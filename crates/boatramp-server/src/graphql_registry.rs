//! The GraphQL subgraph schema registry.
//!
//! Each subgraph publishes its SDL for a project; the registry stores it, recomposes the
//! whole supergraph (see `graphql_federation`), validates it, and **rejects an
//! incompatible change** so a bad publish never corrupts the registry. The composed
//! supergraph model is what the query planner (a later landing) plans against.

use crate::graphql_federation::{compose, CompositionError, Supergraph};
use boatramp_core::kv::KvStore;

/// The kv prefix under which a project's subgraph SDLs live.
fn subgraph_prefix(project: &str) -> String {
    format!("graphql/{project}/subgraph/")
}

fn subgraph_key(project: &str, name: &str) -> String {
    format!("{}{name}", subgraph_prefix(project))
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
}
