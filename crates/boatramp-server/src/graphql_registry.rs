//! The GraphQL subgraph schema registry.
//!
//! Each subgraph publishes its SDL for a project; the registry stores it, recomposes the
//! whole supergraph (see `graphql_federation`), validates it, and **rejects an
//! incompatible change** so a bad publish never corrupts the registry. The composed
//! supergraph model is what the query planner (a later landing) plans against.

use crate::graphql_federation::{CompositionError, Supergraph, compose};
use boatramp_core::config::HandlerGraphqlDataConfig;
use boatramp_core::kv::{KvStore, WriteOp};
use std::collections::BTreeMap;

/// The kv prefix under which a project's subgraph SDLs live.
fn subgraph_prefix(project: &str) -> String {
    format!("graphql/{project}/subgraph/")
}

/// The key holding a project's **composition version** — a monotonic counter bumped on every
/// registry mutation (subgraph publish/unpublish, backend-kind change). The composed supergraph
/// and query plans are memoized against it (see `graphql_cache`); a bump invalidates the cache.
/// A discrete key (a cheap `get`, cacheable + rideable by the shared-store change poller), not a
/// `list_prefix`, so the per-request version check is cheap and topology-correct.
fn version_key(project: &str) -> String {
    format!("graphql/{project}/version")
}

/// The current composition version for `project` (`0` if never written). Cheap enough to read
/// once per request to key the supergraph/plan caches.
pub(crate) async fn composition_version(kv: &dyn KvStore, project: &str) -> u64 {
    match kv.get(&version_key(project)).await {
        Ok(Some(bytes)) if bytes.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            u64::from_be_bytes(arr)
        }
        _ => 0,
    }
}

/// Bump the composition version, invalidating any `(project, version)`-keyed cache entry. Called
/// after every registry mutation. (A read-modify-write; concurrent same-project registry writes —
/// rare, serialized operator/deploy actions — could lose a bump, briefly serving a stale cache
/// until the next mutation. Acceptable for the write cadence; the read path always version-checks.)
async fn bump_version(kv: &dyn KvStore, project: &str) -> Result<(), String> {
    let next = composition_version(kv, project).await.wrapping_add(1);
    kv.put(&version_key(project), next.to_be_bytes().to_vec())
        .await
        .map_err(|e| e.to_string())
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
        .map_err(|e| e.to_string())?;
    // A backend-kind change alters routing (function ↔ SQL), so it must invalidate the cache.
    bump_version(kv, project).await
}

fn backend_key(project: &str, name: &str) -> String {
    format!("{}{name}", backend_prefix(project))
}

/// The key holding the **component hash** whose introspected SDL is currently published for
/// subgraph `name` (v0.4.x deploy-resilience #4). Lets a function redeploy of an UNCHANGED
/// component skip the expensive `{ _service { sdl } }` introspection + recompose — the published
/// SDL is already current for that hash. Only written by the function-deploy path (a manual/SQL
/// publish leaves it absent, so the next function deploy re-introspects — never a false skip).
fn subgraph_hash_key(project: &str, name: &str) -> String {
    format!("graphql/{project}/subgraph-hash/{name}")
}

/// The component hash whose SDL is currently published for subgraph `name` (`None` if unknown —
/// never published from a function deploy, or published from a manual/SQL source). A deploy whose
/// component hash equals this can skip re-introspection.
pub(crate) async fn subgraph_hash(kv: &dyn KvStore, project: &str, name: &str) -> Option<String> {
    match kv.get(&subgraph_hash_key(project, name)).await {
        Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
        _ => None,
    }
}

/// Record that subgraph `name`'s currently-published SDL was introspected from component `hash`.
/// Best-effort accounting for the skip-if-unchanged optimization; a write failure just means the
/// next deploy re-introspects (correct, only slower), so the caller can ignore the error.
pub(crate) async fn put_subgraph_hash(
    kv: &dyn KvStore,
    project: &str,
    name: &str,
    hash: &str,
) -> Result<(), String> {
    kv.put(&subgraph_hash_key(project, name), hash.as_bytes().to_vec())
        .await
        .map_err(|e| e.to_string())
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
        if let Ok(Some(bytes)) = kv.get(&key).await
            && let Ok(sdl) = String::from_utf8(bytes)
        {
            let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            out.push((name, sdl));
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
    // Persist the SDL, bump the version, and CLEAR the #4 component-hash sidecar — all in one
    // atomic batch. This publish's SDL did not necessarily come from a function-introspected
    // component (this is also the manual and SQL registration path), so any previously-recorded
    // component hash is now stale: leaving it would let a later function redeploy of that exact
    // hash falsely skip re-introspection (#4) and keep serving *this* override's SDL. Clearing it
    // forces the next function deploy to re-introspect; the function-deploy path re-sets the hash
    // itself right after its own `publish`, so it costs that path nothing.
    let next = composition_version(kv, project).await.wrapping_add(1);
    kv.write_batch(vec![
        WriteOp::Put(subgraph_key(project, name), sdl.as_bytes().to_vec()),
        WriteOp::Delete(subgraph_hash_key(project, name)),
        WriteOp::Put(version_key(project), next.to_be_bytes().to_vec()),
    ])
    .await
    .map_err(|e| PublishError::Store(e.to_string()))?;
    Ok(sg)
}

/// The kv prefix for **staged** (pending) subgraph SDLs — the batch-compose area
/// (deploy-resilience #3). A deploy with `?compose=defer` writes here WITHOUT composing; a later
/// `compose_batch` validates the whole set once and promotes them to live in a single version bump.
fn pending_prefix(project: &str) -> String {
    format!("graphql/{project}/pending/")
}

fn pending_key(project: &str, name: &str) -> String {
    format!("{}{name}", pending_prefix(project))
}

fn pending_hash_key(project: &str, name: &str) -> String {
    format!("graphql/{project}/pending-hash/{name}")
}

/// Stage subgraph `name`'s SDL (introspected from component `hash`) for a batched compose WITHOUT
/// composing or bumping the version (#3). The live supergraph is untouched until `compose_batch`.
pub(crate) async fn stage_subgraph(
    kv: &dyn KvStore,
    project: &str,
    name: &str,
    sdl: &str,
    hash: &str,
) -> Result<(), String> {
    kv.put(&pending_key(project, name), sdl.as_bytes().to_vec())
        .await
        .map_err(|e| e.to_string())?;
    kv.put(&pending_hash_key(project, name), hash.as_bytes().to_vec())
        .await
        .map_err(|e| e.to_string())
}

/// Load the staged (pending) subgraphs as `(name, sdl, hash)`.
async fn load_pending(kv: &dyn KvStore, project: &str) -> Vec<(String, String, String)> {
    let prefix = pending_prefix(project);
    let mut out = Vec::new();
    for key in kv.list_prefix(&prefix).await.unwrap_or_default() {
        let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
        if let Ok(Some(bytes)) = kv.get(&key).await
            && let Ok(sdl) = String::from_utf8(bytes)
        {
            let hash = match kv.get(&pending_hash_key(project, &name)).await {
                Ok(Some(h)) => String::from_utf8(h).unwrap_or_default(),
                _ => String::new(),
            };
            out.push((name, sdl, hash));
        }
    }
    out
}

/// Compose the whole set ONCE — live subgraphs overlaid with everything staged (#3) — validate it,
/// and only on success **promote** each pending SDL to live (+ its hash sidecar for #4), clear the
/// pending area, and bump the version a **single** time. On a composition failure NOTHING is
/// promoted and the live supergraph is untouched (invariant #2). The batch analog of `publish`.
pub(crate) async fn compose_batch(
    kv: &dyn KvStore,
    project: &str,
) -> Result<Supergraph, PublishError> {
    let pending = load_pending(kv, project).await;
    if pending.is_empty() {
        // Nothing staged — recompose the live set so the caller still gets a validated supergraph.
        return supergraph(kv, project)
            .await
            .map_err(PublishError::Composition);
    }
    // Live set with pending overlaid (pending wins on name collision), composed once.
    let mut set: BTreeMap<String, String> = load_subgraphs(kv, project).await.into_iter().collect();
    for (name, sdl, _) in &pending {
        set.insert(name.clone(), sdl.clone());
    }
    let subgraphs: Vec<(String, String)> = set.into_iter().collect();
    let sg = compose(&subgraphs).map_err(PublishError::Composition)?;
    // Composed OK → promote every pending SDL to live (+ its #4 hash sidecar), clear the pending
    // area, and bump the version — all in ONE atomic `write_batch` so serving never observes a
    // half-promoted set. A single-key-at-a-time loop could fail mid-promote and leave the live
    // supergraph non-composing (some subgraphs promoted, others not) with the version either
    // bumped-onto-a-broken-set or not; the atomic batch makes it all-or-nothing — either the whole
    // validated set becomes live (with the bump) or the previously-composed set keeps serving.
    let next = composition_version(kv, project).await.wrapping_add(1);
    let mut ops: Vec<WriteOp> = Vec::with_capacity(pending.len() * 4 + 1);
    for (name, sdl, hash) in &pending {
        ops.push(WriteOp::Put(
            subgraph_key(project, name),
            sdl.as_bytes().to_vec(),
        ));
        if !hash.is_empty() {
            ops.push(WriteOp::Put(
                subgraph_hash_key(project, name),
                hash.as_bytes().to_vec(),
            ));
        }
        ops.push(WriteOp::Delete(pending_key(project, name)));
        ops.push(WriteOp::Delete(pending_hash_key(project, name)));
    }
    ops.push(WriteOp::Put(
        version_key(project),
        next.to_be_bytes().to_vec(),
    ));
    kv.write_batch(ops)
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
pub(crate) async fn is_registered_subgraph(kv: &dyn KvStore, project: &str, name: &str) -> bool {
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
        .map_err(|e| e.to_string())?;
    // Clear the deploy-resilience hash sidecar too, so re-registering this subgraph (a function
    // redeploy of the same component hash) does NOT falsely skip introspection (#4).
    kv.delete(&subgraph_hash_key(project, name))
        .await
        .map_err(|e| e.to_string())?;
    bump_version(kv, project).await
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

    // The verbatim `_service { sdl }` a real async-graphql v7 `.enable_federation()` subgraph
    // emits: a federation-v2 document with the `extend schema @link(...)` preamble, block-string
    // descriptions, and built-in directive definitions. This is a *real client artifact*, not a
    // hand-written approximation — the documented, recommended way to author a subgraph. It is
    // the exact SDL shape that once failed to parse (and would have 400'd every real subgraph
    // registration); this dogfoods the documented path through the whole publish→compose→read.
    const ASYNC_GRAPHQL_V2: &str = r#"type Query {
	users: [User!]!
}

type User @key(fields: "id") {
	id: ID!
	name: String!
}

"""
Directs the executor to include this field or fragment only when the `if` argument is true.
"""
directive @include(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
extend schema @link(
	url: "https://specs.apollo.dev/federation/v2.5",
	import: ["@key", "@tag", "@shareable", "@inaccessible", "@override", "@external", "@provides", "@requires", "@composeDirective", "@interfaceObject"]
)
"#;

    #[tokio::test]
    async fn publishes_real_async_graphql_v2_sdl_the_documented_way() {
        let kv = MemoryKv::new();
        // Register a real async-graphql-emitted subgraph SDL — the recommended authoring path.
        let sg = publish(&kv, "acme", "users", ASYNC_GRAPHQL_V2)
            .await
            .unwrap();
        // Its type-system facts survive the whole path (the `@link` preamble is ignored).
        assert_eq!(
            sg.root_query.get("users").map(String::as_str),
            Some("users")
        );
        assert!(sg.entities.contains_key("User"), "User entity registered");
        // And it reads back as the composed supergraph, so the gateway can plan against it.
        let current = supergraph(&kv, "acme").await.unwrap();
        assert!(current.root_query.contains_key("users"));
        assert_eq!(subgraph_names(&kv, "acme").await, vec!["users".to_string()]);
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
    async fn every_registry_mutation_bumps_the_composition_version() {
        let kv = MemoryKv::new();
        assert_eq!(composition_version(&kv, "acme").await, 0);
        // publish bumps...
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        let v1 = composition_version(&kv, "acme").await;
        assert_eq!(v1, 1);
        // a backend-kind change bumps (routing change)...
        put_subgraph_backend(&kv, "acme", "accounts", &SubgraphBackendSpec::Function)
            .await
            .unwrap();
        let v2 = composition_version(&kv, "acme").await;
        assert!(v2 > v1, "backend change bumps the version");
        // unpublish bumps.
        unpublish(&kv, "acme", "accounts").await.unwrap();
        assert!(composition_version(&kv, "acme").await > v2);
        // A different project's version is independent.
        assert_eq!(composition_version(&kv, "other").await, 0);
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
    async fn is_registered_subgraph_reflects_registration_and_unpublish_removes_it() {
        let kv = MemoryKv::new();
        assert!(!is_registered_subgraph(&kv, "acme", "accounts").await);
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        put_subgraph_backend(&kv, "acme", "accounts", &SubgraphBackendSpec::Function)
            .await
            .unwrap();
        assert!(is_registered_subgraph(&kv, "acme", "accounts").await);

        unpublish(&kv, "acme", "accounts").await.unwrap();
        assert!(!is_registered_subgraph(&kv, "acme", "accounts").await);
        assert!(subgraph_names(&kv, "acme").await.is_empty());
        // Idempotent: unpublishing a gone subgraph is not an error.
        unpublish(&kv, "acme", "accounts").await.unwrap();
    }

    // MEDIUM-1: `compose_batch` promotes the whole validated set atomically — every pending SDL
    // goes live (+ its #4 hash), the pending area clears, and the composition version bumps
    // exactly ONCE for the batch.
    #[tokio::test]
    async fn compose_batch_promotes_all_pending_atomically_with_one_version_bump() {
        let kv = MemoryKv::new();
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        let v_before = composition_version(&kv, "acme").await;
        // Staging touches neither the live set nor the version.
        stage_subgraph(&kv, "acme", "reviews", REVIEWS, "hashR")
            .await
            .unwrap();
        assert_eq!(composition_version(&kv, "acme").await, v_before);
        assert_eq!(
            subgraph_names(&kv, "acme").await,
            vec!["accounts".to_string()]
        );
        // Compose the batch: reviews promotes to live, its hash is recorded, pending clears, +1 bump.
        let sg = compose_batch(&kv, "acme").await.unwrap();
        assert!(sg.entities.contains_key("User"));
        assert_eq!(
            subgraph_names(&kv, "acme").await,
            vec!["accounts".to_string(), "reviews".to_string()]
        );
        assert_eq!(
            subgraph_hash(&kv, "acme", "reviews").await.as_deref(),
            Some("hashR")
        );
        assert_eq!(composition_version(&kv, "acme").await, v_before + 1);
        assert!(
            kv.list_prefix(&pending_prefix("acme"))
                .await
                .unwrap()
                .is_empty()
        );
    }

    // MEDIUM-1 (the fail-closed half): a batch that does not compose promotes NOTHING and leaves
    // the previously-composed live set + version untouched (invariant #2).
    #[tokio::test]
    async fn compose_batch_promotes_nothing_when_the_batch_does_not_compose() {
        let kv = MemoryKv::new();
        publish(&kv, "acme", "a", "type Query { x: Int } type T { f: Int }")
            .await
            .unwrap();
        let v_before = composition_version(&kv, "acme").await;
        // `b` re-defines `T.f` without @shareable — the batch cannot compose.
        stage_subgraph(&kv, "acme", "b", "type T { f: Int }", "hashB")
            .await
            .unwrap();
        assert!(matches!(
            compose_batch(&kv, "acme").await,
            Err(PublishError::Composition(_))
        ));
        // Live set, hash sidecars, and version are all untouched; the (fixable) pending stays staged.
        assert_eq!(subgraph_names(&kv, "acme").await, vec!["a".to_string()]);
        assert_eq!(composition_version(&kv, "acme").await, v_before);
        assert!(subgraph_hash(&kv, "acme", "b").await.is_none());
        assert!(
            !kv.list_prefix(&pending_prefix("acme"))
                .await
                .unwrap()
                .is_empty()
        );
    }

    // MEDIUM-2: a manual/SQL `publish` clears the #4 component-hash sidecar, so a later function
    // redeploy of that same hash re-introspects instead of falsely skipping and serving the
    // override's SDL.
    #[tokio::test]
    async fn publish_clears_the_component_hash_sidecar() {
        let kv = MemoryKv::new();
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        // A prior function deploy recorded its component hash for the #4 skip.
        put_subgraph_hash(&kv, "acme", "accounts", "hash1")
            .await
            .unwrap();
        assert_eq!(
            subgraph_hash(&kv, "acme", "accounts").await.as_deref(),
            Some("hash1")
        );
        // A manual publish overwrites the live SDL from a non-function source → the hash is now
        // stale and MUST be cleared (else the next same-hash function deploy would falsely skip).
        publish(&kv, "acme", "accounts", ACCOUNTS).await.unwrap();
        assert!(subgraph_hash(&kv, "acme", "accounts").await.is_none());
    }
}
