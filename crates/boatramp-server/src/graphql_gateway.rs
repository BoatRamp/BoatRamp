//! GraphQL federation executor: run a query plan and stitch the results.
//!
//! The planner (`graphql_plan`) produces an ordered list of fetches; this executor runs
//! each — a root fetch, or a dependent `_entities` fetch whose representations are built
//! from an earlier fetch's data — and merges every fetch's result into one response,
//! joining entities by their `@key`. Dispatching a fetch to its subgraph is abstracted
//! behind [`SubgraphRunner`], so the stitching logic is tested with a mock and reused over
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
pub(crate) trait SubgraphRunner: Sync {
    async fn run(&self, subgraph: &str, query: &str, variables: Value) -> Value;
}

/// Execute `plan` with `runner`, returning the merged `{ "data": … }` response.
pub(crate) async fn execute(plan: &QueryPlan, runner: &dyn SubgraphRunner) -> Value {
    let mut data = json!({});
    for fetch in &plan.fetches {
        match &fetch.requires {
            None => {
                let resp = runner.run(&fetch.subgraph, &fetch.query, json!({})).await;
                merge(&mut data, fetch_data(&resp));
            }
            Some(req) => {
                // Build the entity representations from the already-stitched tree at the
                // provider's response path, run the `_entities` fetch, and stitch the
                // resolved entity fields back in at that path.
                let reprs = representations(&data, &req.path, &req.type_name, &req.key);
                let resp = runner
                    .run(
                        &fetch.subgraph,
                        &fetch.query,
                        json!({ "representations": reprs }),
                    )
                    .await;
                let entities = resp
                    .pointer("/data/_entities")
                    .or_else(|| resp.pointer("/_entities"))
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                stitch(&mut data, &req.path, &entities);
            }
        }
    }
    json!({ "data": data })
}

/// A fetch response's data object (unwrapping a `{ "data": … }` envelope).
fn fetch_data(resp: &Value) -> &Value {
    resp.get("data").unwrap_or(resp)
}

/// Dispatch one fetch to a subgraph **function** over the in-process invoke path (no network
/// hop, no SSRF surface) — the subgraph name is the function name — mapping the result (or a
/// precise error) to a GraphQL response. The gateway is the root of the call chain, so it
/// invokes at depth 0. Used by the [`BackendRouter`]'s function branch.
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
    match invoker.invoke(subgraph, request, 0).await {
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

/// A [`SubgraphRunner`] that dispatches each fetch to the **right backend**: a SQL-backed
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
        }
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
            )
            .await
        }
    }
}

#[async_trait::async_trait]
impl SubgraphRunner for BackendRouter {
    async fn run(&self, subgraph: &str, query: &str, variables: Value) -> Value {
        if let Some((site, config)) = self.sql_subgraphs.get(subgraph) {
            return self.run_sql(subgraph, site, config, query, variables).await;
        }
        invoke_subgraph(
            self.invoker.as_ref(),
            subgraph,
            query,
            variables,
            self.bearer.as_deref(),
        )
        .await
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

    /// A mock runner returning a canned response per subgraph.
    struct Mock(HashMap<&'static str, Value>);

    #[async_trait::async_trait]
    impl SubgraphRunner for Mock {
        async fn run(&self, subgraph: &str, _query: &str, _variables: Value) -> Value {
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
    impl SubgraphRunner for ContractRunner {
        async fn run(&self, subgraph: &str, query: &str, variables: Value) -> Value {
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
    /// target resolves to `NotFound`, so [`InvokeRunner`] must report the
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
        let out = execute(&plan, &mock).await;
        assert_eq!(out["data"]["me"]["name"], json!("Alice"));
        assert_eq!(out["data"]["topReviews"][0]["body"], json!("ok"));
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
        let out = execute(&plan, &mock).await;
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
        let out = execute(&plan, &ContractRunner).await;
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
        let resp = router.run("accounts", "{ me { id } }", json!({})).await;
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
        let root = router.run("orders", "{ me { id } }", json!({})).await;
        assert_eq!(root["data"]["identity"], json!("Bearer t-acme"));
        // ...and so does a dependent `_entities` hydration fetch (same dispatch path).
        let entity = router
            .run(
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
        let resp = router.run("orders", "{ me { id } }", json!({})).await;
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
}
