//! GraphQL federation executor: run a query plan and stitch the results.
//!
//! The planner (`graphql_plan`) produces an ordered list of fetches; this executor runs
//! each — a root fetch, or a dependent `_entities` fetch whose representations are built
//! from an earlier fetch's data — and merges every fetch's result into one response,
//! joining entities by their `@key`. Dispatching a fetch to its subgraph is abstracted
//! behind [`SubgraphRunner`], so the stitching logic is tested with a mock and reused
//! over the real (streaming-invoke) runner in the serving path.
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

/// A [`SubgraphRunner`] that dispatches each fetch to a subgraph **function** over the
/// in-process invoke path (no network hop, no SSRF surface) — the subgraph name is the
/// function name. Buffered (a federation fetch is bounded); the gateway is the root of the
/// call chain, so it invokes at depth 0.
pub(crate) struct InvokeRunner {
    invoker: std::sync::Arc<dyn boatramp_handlers::Invoker>,
}

impl InvokeRunner {
    pub(crate) fn new(invoker: std::sync::Arc<dyn boatramp_handlers::Invoker>) -> Self {
        Self { invoker }
    }
}

#[async_trait::async_trait]
impl SubgraphRunner for InvokeRunner {
    async fn run(&self, subgraph: &str, query: &str, variables: Value) -> Value {
        let body = json!({ "query": query, "variables": variables })
            .to_string()
            .into_bytes();
        let request = boatramp_handlers::InvokeRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: vec![("content-type".to_string(), b"application/json".to_vec())],
            body,
        };
        match self.invoker.invoke(subgraph, request, 0).await {
            Ok(resp) => serde_json::from_slice(&resp.body).unwrap_or_else(|_| {
                json!({ "errors": [{ "message": format!("subgraph `{subgraph}` returned invalid JSON") }] })
            }),
            Err(_) => {
                json!({ "errors": [{ "message": format!("subgraph `{subgraph}` is unavailable") }] })
            }
        }
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

    #[test]
    fn merge_is_a_deep_object_merge() {
        let mut a = json!({ "me": { "name": "x" } });
        merge(&mut a, &json!({ "me": { "age": 3 }, "other": 1 }));
        assert_eq!(a, json!({ "me": { "name": "x", "age": 3 }, "other": 1 }));
    }
}
