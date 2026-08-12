//! The GraphQL subgraph schema registry.
//!
//! Each subgraph publishes its SDL for a project; the registry stores it, recomposes the
//! whole supergraph (see `graphql_federation`), validates it, and **rejects an
//! incompatible change** so a bad publish never corrupts the registry. The composed
//! supergraph model is what the query planner (a later landing) plans against.

use crate::graphql_federation::{compose, CompositionError, Supergraph};
use boatramp_core::config::HandlerGraphqlDataConfig;
use boatramp_core::kv::KvStore;
use std::collections::BTreeMap;

/// The kv prefix under which a project's subgraph SDLs live.
fn subgraph_prefix(project: &str) -> String {
    format!("graphql/{project}/subgraph/")
}

fn subgraph_key(project: &str, name: &str) -> String {
    format!("{}{name}", subgraph_prefix(project))
}

/// The kv prefix under which a project's per-subgraph **backend kinds** live (which runner
/// resolves a subgraph's fetches). Absent ⇒ a wasm function, so pre-existing subgraphs are
/// unaffected.
fn backend_prefix(project: &str) -> String {
    format!("graphql/{project}/subgraph-backend/")
}

/// How a registered subgraph's fetches are resolved: a wasm **function** (the default), or
/// the **SQL** data connector reading a managed database. Persisted as JSON under
/// `graphql/{project}/subgraph-backend/{name}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum SubgraphBackendSpec {
    /// Dispatch fetches to the wasm function of the same name.
    Function,
    /// Resolve fetches by compiling to SQL against `site`'s managed database.
    Sql {
        site: String,
        config: HandlerGraphqlDataConfig,
    },
}

/// Record subgraph `name`'s backend kind for `project`.
pub(crate) async fn put_subgraph_backend(
    kv: &dyn KvStore,
    project: &str,
    name: &str,
    spec: &SubgraphBackendSpec,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(spec).map_err(|e| e.to_string())?;
    kv.put(&backend_key(project, name), bytes)
        .await
        .map_err(|e| e.to_string())
}

fn backend_key(project: &str, name: &str) -> String {
    format!("{}{name}", backend_prefix(project))
}

/// The SQL-backed subgraphs of `project`: `name → (site, data config)`. Function subgraphs
/// (the default) are not included — the gateway routes those to the invoker.
pub(crate) async fn sql_subgraphs(
    kv: &dyn KvStore,
    project: &str,
) -> BTreeMap<String, (String, HandlerGraphqlDataConfig)> {
    let prefix = backend_prefix(project);
    let mut out = BTreeMap::new();
    for key in kv.list_prefix(&prefix).await.unwrap_or_default() {
        let Ok(Some(bytes)) = kv.get(&key).await else {
            continue;
        };
        if let Ok(SubgraphBackendSpec::Sql { site, config }) = serde_json::from_slice(&bytes) {
            let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            out.insert(name, (site, config));
        }
    }
    out
}

/// Why a subgraph publish failed.
#[derive(Debug)]
pub(crate) enum PublishError {
    /// The change does not compose into a valid supergraph (it is not persisted).
    Composition(CompositionError),
    /// The store write failed.
    Store(String),
}

/// Load every stored subgraph for `project` as `(name, sdl)`.
async fn load_subgraphs(kv: &dyn KvStore, project: &str) -> Vec<(String, String)> {
    let prefix = subgraph_prefix(project);
    let mut out = Vec::new();
    for key in kv.list_prefix(&prefix).await.unwrap_or_default() {
        if let Ok(Some(bytes)) = kv.get(&key).await {
            if let Ok(sdl) = String::from_utf8(bytes) {
                let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
                out.push((name, sdl));
            }
        }
    }
    out
}

/// Publish (or replace) subgraph `name`'s SDL: recompose the supergraph with the change,
/// validate it, and persist the SDL **only if** composition succeeds. Returns the
/// recomposed supergraph.
pub(crate) async fn publish(
    kv: &dyn KvStore,
    project: &str,
    name: &str,
    sdl: &str,
) -> Result<Supergraph, PublishError> {
    let mut subgraphs = load_subgraphs(kv, project).await;
    subgraphs.retain(|(n, _)| n != name);
    subgraphs.push((name.to_string(), sdl.to_string()));
    let sg = compose(&subgraphs).map_err(PublishError::Composition)?;
    kv.put(&subgraph_key(project, name), sdl.as_bytes().to_vec())
        .await
        .map_err(|e| PublishError::Store(e.to_string()))?;
    Ok(sg)
}

/// The current composed supergraph for `project` (recomposed from the stored subgraphs).
pub(crate) async fn supergraph(
    kv: &dyn KvStore,
    project: &str,
) -> Result<Supergraph, CompositionError> {
    compose(&load_subgraphs(kv, project).await)
}

/// Whether `name` is a currently-registered subgraph of `project` (an SDL is stored). Used to
/// decide, on a function redeploy, whether to auto-refresh its registered SDL — first
/// registration stays an explicit operator action.
pub(crate) async fn is_subgraph(kv: &dyn KvStore, project: &str, name: &str) -> bool {
    matches!(kv.get(&subgraph_key(project, name)).await, Ok(Some(_)))
}

/// Remove subgraph `name` from `project`'s registry (its SDL + backend record). The escape
/// hatch for a coordinated schema migration: it does **not** recompose or validate the
/// remainder, so an operator can deliberately drop a subgraph that others depend on as one step
/// of a multi-subgraph change (the composed supergraph is recomposed lazily on read). Idempotent.
pub(crate) async fn unpublish(kv: &dyn KvStore, project: &str, name: &str) -> Result<(), String> {
    kv.delete(&subgraph_key(project, name))
        .await
        .map_err(|e| e.to_string())?;
    kv.delete(&backend_key(project, name))
        .await
        .map_err(|e| e.to_string())
}

/// The names of the currently-registered subgraphs for `project`.
pub(crate) async fn subgraph_names(kv: &dyn KvStore, project: &str) -> Vec<String> {
    let prefix = subgraph_prefix(project);
    kv.list_prefix(&prefix)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|k| k.strip_prefix(&prefix).unwrap_or(&k).to_string())
        .collect()
}

/// A JSON summary of a composed supergraph for the control-plane API: its subgraphs, its
/// entities (key + resolving subgraphs), and its root fields (field → owning subgraph).
pub(crate) fn summary_json(sg: &Supergraph, subgraphs: &[String]) -> serde_json::Value {
    let entities: serde_json::Map<String, serde_json::Value> = sg
        .entities
        .iter()
        .map(|(ty, e)| {
            (
                ty.clone(),
                serde_json::json!({ "key": e.key, "subgraphs": e.subgraphs }),
            )
        })
        .collect();
    serde_json::json!({
        "subgraphs": subgraphs,
        "entities": entities,
        "rootQuery": sg.root_query,
        "rootMutation": sg.root_mutation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;

    const ACCOUNTS: &str = r#"
        type Query { me: User }
        type User @key(fields: "id") { id: ID! name: String }
    "#;
    const REVIEWS: &str = r#"
        type Query { topReviews: [Review] }
        type Review { id: ID! body: String author: User }
        extend type User @key(fields: "id") { id: ID! @external reviews: [Review] }
    "#;

    #[tokio::test]
    async fn publish_composes_stores_and_recomposes() {
        let kv = MemoryKv::new();
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        let sg = publish(&kv, "acme", "reviews", REVIEWS).await.unwrap();
        assert!(sg.entities.contains_key("User"));
        // Both roots are present in the recomposed supergraph.
        let current = supergraph(&kv, "acme").await.unwrap();
        assert_eq!(current.root_query.len(), 2);
        assert_eq!(
            subgraph_names(&kv, "acme").await,
            vec!["accounts", "reviews"]
        );
    }

    #[tokio::test]
    async fn an_incompatible_publish_is_rejected_and_not_stored() {
        let kv = MemoryKv::new();
        publish(&kv, "acme", "a", "type Query { x: Int } type T { f: Int }")
            .await
            .unwrap();
        // `b` re-defines `T.f` without @shareable — a conflict.
        let err = publish(&kv, "acme", "b", "type T { f: Int }").await;
        assert!(matches!(err, Err(PublishError::Composition(_))));
        // The rejected subgraph was not persisted.
        assert_eq!(subgraph_names(&kv, "acme").await, vec!["a".to_string()]);
    }

    #[tokio::test]
    async fn projects_are_isolated() {
        let kv = MemoryKv::new();
        publish(&kv, "acme", "s", "type Query { x: Int }")
            .await
            .unwrap();
        assert!(subgraph_names(&kv, "other").await.is_empty());
    }

    #[tokio::test]
    async fn is_subgraph_reflects_registration_and_unpublish_removes_it() {
        let kv = MemoryKv::new();
        assert!(!is_subgraph(&kv, "acme", "accounts").await);
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        put_subgraph_backend(&kv, "acme", "accounts", &SubgraphBackendSpec::Function)
            .await
            .unwrap();
        assert!(is_subgraph(&kv, "acme", "accounts").await);

        unpublish(&kv, "acme", "accounts").await.unwrap();
        assert!(!is_subgraph(&kv, "acme", "accounts").await);
        assert!(subgraph_names(&kv, "acme").await.is_empty());
        // Idempotent: unpublishing a gone subgraph is not an error.
        unpublish(&kv, "acme", "accounts").await.unwrap();
    }
}
