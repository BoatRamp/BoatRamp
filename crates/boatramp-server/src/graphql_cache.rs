//! Per-project memoization of the composed supergraph + query plans, so the federation gateway
//! does not re-list, re-parse every subgraph's SDL, and re-plan on **every** request — the
//! dominant avoidable cost on the agent hot path (an agent turn issues N `graphql::run` calls
//! against a graph that changes only on deploy).
//!
//! Invalidation is a **version check**, not an event. The registry bumps a per-project
//! composition version on every mutation ([`crate::graphql_registry::composition_version`]); a
//! cache entry keyed on `(project, version)` is served only while the stored version still
//! matches. This is correct across both KV topologies with no bespoke cross-node cache-bust: a
//! Raft node reads the replicated version from local applied state; a shared-store node's version
//! key rides the existing change poller. Both caches are bounded (LRU), keyed by `project` for
//! multi-tenant isolation, and only **successful** compositions are cached (a composition error
//! is never cached, so an operator's fix takes effect on the very next read).

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock};

use lru::LruCache;

use crate::graphql_federation::{CompositionError, Supergraph};
use crate::graphql_plan::{PlanError, QueryPlan, plan};
use boatramp_core::cache_coherence::AuthzFence;
use boatramp_core::config::HandlerGraphqlDataConfig;
use boatramp_core::kv::KvStore;

/// The edge-visibility dimension of a plan-cache lookup (#495). The plan cache is SHARED by the
/// external `/graphql` edge and the internal `graphql::run` path; those two paths resolve the SAME
/// operation against the SAME supergraph but under **different visibility** — the external path may
/// hide root fields (they plan as `UnknownRootField`), the internal path hides nothing. Keying only
/// on `(project, version, op_hash)` would let one path serve the other's plan — a fail-open trap
/// (an internal plan of a hidden op, primed once, would then be served to the external edge). This
/// discriminates the two so their plans never collide.
#[derive(Clone)]
pub(crate) enum Visibility<'a> {
    /// An internal caller (`graphql::run`, `emit::invoke`): hide nothing (`plan(edge_hidden=None)`).
    Internal,
    /// The external `/graphql` edge: hide the resolved `(root_type, field)` set. The set is the
    /// **canonical resolved** effective-hidden set (manifest entries already resolved against the
    /// supergraph roots, unknowns dropped, unioned with the directive roots) — NOT raw manifest
    /// strings, so two sites that resolve to the same hidden set share a warm plan. An EMPTY set
    /// (a site with no excludes) is still `External` and keys **distinctly** from `Internal`.
    External(&'a BTreeSet<(String, String)>),
}

impl Visibility<'_> {
    /// The visibility component of the plan-cache key: a discriminated, stable string. `Internal`
    /// is a fixed sentinel that can never collide with any external hash; `External` is a
    /// deterministic hash over the CANONICAL RESOLVED hidden set (post-resolution), so it is stable
    /// across nodes and equal iff the resolved hidden sets are equal. Internal and external-empty
    /// are DISTINCT keys (`"i"` vs `"e:<hash-of-empty>"`).
    fn cache_discriminant(&self) -> String {
        match self {
            Visibility::Internal => "i".to_string(),
            Visibility::External(hidden) => format!("e:{}", hidden_hash(hidden)),
        }
    }

    /// The `edge_hidden` argument to thread into [`plan`]: `None` for internal, the resolved set for
    /// external. This is the SAME set the discriminant hashes, so the key and the plan agree.
    fn edge_hidden(&self) -> Option<&BTreeSet<(String, String)>> {
        match self {
            Visibility::Internal => None,
            Visibility::External(hidden) => Some(hidden),
        }
    }
}

/// A stable hex hash over a canonical resolved hidden set. The set is a `BTreeSet`, so iteration is
/// already sorted and deterministic; the `(root_type, field)` pairs are hashed with an unambiguous
/// separator so `("Query","ab")` and `("Query","a"),("Query","b")` can't collide. Uses the same
/// SHA-256 helper the op-hash uses, so the key alphabet stays uniform.
fn hidden_hash(hidden: &BTreeSet<(String, String)>) -> String {
    let mut canonical = String::new();
    for (ty, field) in hidden {
        // Length-prefix each element so no concatenation is ambiguous (a delimiter alone could be
        // forged by a field name containing it; a length prefix cannot).
        canonical.push_str(&format!(
            "{}:{ty}\u{1f}{}:{field}\u{1f}",
            ty.len(),
            field.len()
        ));
    }
    crate::graphql_apq::sha256_hex(&canonical)
}

/// A stable hex hash over a canonical (sorted, deduped) subgraph-NAME set — the `set_hash` key
/// dimension for per-site composed supergraphs (per-site `graphql.subgraphs`). Mirrors
/// [`hidden_hash`]'s length-prefixed canonical form + the shared SHA-256 helper, so two sites with
/// the same resolved include set hash identically (share one composed supergraph) across nodes. The
/// caller passes the names; sorting + deduping here makes the hash order-independent.
pub(crate) fn subgraph_set_hash(names: &[String]) -> String {
    let mut canon: Vec<&str> = names.iter().map(String::as_str).collect();
    canon.sort_unstable();
    canon.dedup();
    let mut canonical = String::new();
    for name in canon {
        canonical.push_str(&format!("{}:{name}\u{1f}", name.len()));
    }
    crate::graphql_apq::sha256_hex(&canonical)
}

/// The SQL-backed subgraph routing table (`name → (site, data config)`), cached alongside the
/// supergraph (it's the *other* uncached `list_prefix` on the hot path, and changes on the same
/// version bump).
type SqlSubgraphs = BTreeMap<String, (String, HandlerGraphqlDataConfig)>;

/// The plan-cache key: `(project, version, op_hash, visibility_discriminant)` (#495). The trailing
/// visibility discriminant separates the external edge's (possibly hidden) plan from the internal
/// path's — see [`Visibility`].
/// `(project, version, graph_id, op_hash, visibility)`. `graph_id` is the per-site composed-supergraph
/// identity: `""` for the full-project supergraph (every existing project — byte-identical to the
/// pre-subset 4-tuple with a constant empty slot), or the [`subgraph_set_hash`] for a per-site subset.
/// Without it two sites at the same registry version but different subgraph subsets would collide and
/// serve each other's plans (a cross-site leak), since the plan is a function of the *subset* supergraph.
type PlanKey = (String, u64, String, String, String);

/// A composed supergraph for a project at a specific composition version. Cheaply cloned (the
/// heavy `Supergraph` + routing table are behind `Arc`s).
#[derive(Clone)]
pub(crate) struct CachedGraph {
    pub version: u64,
    pub supergraph: Arc<Supergraph>,
    pub sql_subgraphs: Arc<SqlSubgraphs>,
    /// The composed PUBLIC type system for introspection synthesis (S3) — the SAME composed set as
    /// `supergraph` (full project, or the per-site subset), so a site's `__schema`/`__type` reflects
    /// exactly its subgraphs. Built + cached alongside the routing model.
    pub schema_types: Arc<crate::graphql_introspect::SchemaTypes>,
}

/// Bounded number of projects' composed supergraphs held at once.
const SUPERGRAPH_CAPACITY: usize = 256;
/// Bounded number of `(project, version, operation)` plans held at once.
const PLAN_CAPACITY: usize = 1024;

/// The per-node GraphQL cache (a field of `HandlerRuntimeInner`, shared by the edge and
/// in-process `graphql::run` paths).
pub(crate) struct GraphqlCache {
    supergraphs: Mutex<LruCache<String, CachedGraph>>,
    /// Per-site subgraph composition: composed supergraphs for a DECLARED SUBSET of a project's
    /// subgraphs, keyed `(project, set_hash)` where `set_hash` is a stable hash of the canonical
    /// (sorted, deduped) include set (see [`subgraph_set_hash`]). Version-filtered like
    /// `supergraphs`, so two sites with the same set share one entry and recomposition still happens
    /// only on a registry-version change. The full-project (`subgraphs` absent) path never touches
    /// this — it stays in `supergraphs`, byte-identical to before.
    subset_supergraphs: Mutex<LruCache<(String, String), CachedGraph>>,
    /// Keyed `(project, version, op_hash, visibility)` (#495): the trailing `visibility` component
    /// discriminates the external edge's (possibly hidden) plan from the internal path's — see
    /// [`Visibility`]. Without it the shared cache would fail open across the two paths.
    plans: Mutex<LruCache<PlanKey, Arc<QueryPlan>>>,
    /// **MF-3 stale-authz fence for the GraphQL registry keyspace** (multi-writer `shared` mode).
    /// Set once at serve bootstrap via [`set_registry_fence`](Self::set_registry_fence); unset in
    /// single-writer / single-node (then the registry read uses the passed cached `kv`, UNCHANGED).
    /// A registry-version change that misses its NOTIFY (an `@edgeHidden` field) would otherwise stay
    /// VISIBLE on a peer until the old backstop fired — the SAME stale-confidentiality hole as a
    /// stale policy; the fence closes it by reading the registry version THROUGH the uncached backing
    /// when it cannot confirm currency within `T`, and failing CLOSED (deny) if the store is
    /// unreachable. Its OWN [`AuthzFence`] instance (not the auth-policy one): confirming one
    /// keyspace's currency cannot soundly vouch for another, so each keyspace is fenced + confirmed
    /// independently — the same primitive + the same `remove_authz_fence` seam, per keyspace.
    registry_fence: OnceLock<RegistryFence>,
}

/// The uncached backing store + the GraphQL-registry [`AuthzFence`] for MF-3 read-through (set in
/// `shared` mode only).
struct RegistryFence {
    backing: Arc<dyn KvStore>,
    fence: Arc<AuthzFence>,
}

impl Default for GraphqlCache {
    fn default() -> Self {
        Self {
            supergraphs: Mutex::new(LruCache::new(
                NonZeroUsize::new(SUPERGRAPH_CAPACITY).expect("nonzero"),
            )),
            subset_supergraphs: Mutex::new(LruCache::new(
                NonZeroUsize::new(SUPERGRAPH_CAPACITY).expect("nonzero"),
            )),
            plans: Mutex::new(LruCache::new(
                NonZeroUsize::new(PLAN_CAPACITY).expect("nonzero"),
            )),
            registry_fence: OnceLock::new(),
        }
    }
}

impl GraphqlCache {
    /// Wire the MF-3 GraphQL-registry fence (multi-writer `shared` mode): `backing` is the UNCACHED
    /// control-plane store the registry read goes THROUGH when the fence cannot confirm currency;
    /// `fence` is this keyspace's own [`AuthzFence`] (shared with the cache poller, which trips it on
    /// an unreachable poll). Call ONCE at serve bootstrap; a no-op if already set. NEVER called for a
    /// single-writer / single-node backend — the registry path then stays byte-for-byte unchanged.
    pub(crate) fn set_registry_fence(&self, backing: Arc<dyn KvStore>, fence: Arc<AuthzFence>) {
        let _ = self.registry_fence.set(RegistryFence { backing, fence });
    }

    /// Resolve which store the registry read uses and whether it is a fence-forced READ-THROUGH.
    /// Single-writer (no fence wired) → the passed cached `kv` (unchanged). Shared mode → the
    /// uncached backing when the fence is not current (cache trust lapsed past `T`, or the poller
    /// tripped it); otherwise the cache. The `remove_authz_fence` mutation forces the cache (so the
    /// registry gate goes RED under the SAME seam as the policy gate).
    fn registry_read_store<'a>(&'a self, kv: &'a dyn KvStore) -> (&'a dyn KvStore, bool) {
        match self.registry_fence.get() {
            Some(rf) if !crate::auth::authz_fence_removed() && !rf.fence.is_current() => {
                (rf.backing.as_ref(), true)
            }
            _ => (kv, false),
        }
    }

    /// Read the current registry composition version for `project` through `read_kv` (the store the
    /// caller resolved via [`registry_read_store`](Self::registry_read_store)). When `via_read_through`
    /// (MF-3 fence can't confirm currency) a successful read re-confirms the fence; an unreachable
    /// store FAILS CLOSED (`RegistryUnreachable`). Shared by the full-project and per-subset caches so
    /// the fence logic lives in one place.
    async fn read_version(
        &self,
        read_kv: &dyn KvStore,
        project: &str,
        via_read_through: bool,
    ) -> Result<u64, CompositionError> {
        if via_read_through {
            match crate::graphql_registry::composition_version_checked(read_kv, project).await {
                Ok(v) => {
                    if let Some(rf) = self.registry_fence.get() {
                        rf.fence.confirm();
                    }
                    Ok(v)
                }
                Err(e) => Err(CompositionError::RegistryUnreachable {
                    message: e.to_string(),
                }),
            }
        } else {
            Ok(crate::graphql_registry::composition_version(read_kv, project).await)
        }
    }

    /// The composed supergraph + SQL routing for `project` at the current registry version,
    /// composing (and caching) on a version miss. A composition error is returned **uncached**.
    pub(crate) async fn supergraph(
        &self,
        kv: &dyn KvStore,
        project: &str,
    ) -> Result<CachedGraph, CompositionError> {
        // MF-3: read the registry version (and, on a miss, recompose) THROUGH the uncached backing
        // when the fence cannot confirm currency — so a peer's `@edgeHidden`/registry change whose
        // NOTIFY was dropped is seen within `T`. A store-unreachable read FAILS CLOSED (deny).
        // `read_kv` is captured ONCE and reused for the version read and the recompose, so both see
        // the same store even if the fence flips mid-call.
        let (read_kv, via_read_through) = self.registry_read_store(kv);
        let version = self
            .read_version(read_kv, project, via_read_through)
            .await?;
        // Fast path: a cached entry still at the current version. Bind the clone in its own
        // statement so the lock is released before we return / recompose.
        let hit = self
            .supergraphs
            .lock()
            .unwrap()
            .get(project)
            .filter(|c| c.version == version)
            .cloned();
        if let Some(hit) = hit {
            return Ok(hit);
        }
        // Miss (never composed, or the registry advanced): recompose + reload the SQL routing at
        // this version, then cache — THROUGH the same `read_kv` as the version read, so a fenced
        // recompose reads the fresh (post-`@edgeHidden`) registry from the backing. Two concurrent
        // misses both recompute the same version and the last write wins — harmless (identical).
        let supergraph = Arc::new(crate::graphql_registry::supergraph(read_kv, project).await?);
        let sql_subgraphs =
            Arc::new(crate::graphql_registry::sql_subgraphs(read_kv, project).await);
        let schema_types = Arc::new(crate::graphql_registry::schema_types(read_kv, project).await);
        let cached = CachedGraph {
            version,
            supergraph,
            sql_subgraphs,
            schema_types,
        };
        self.supergraphs
            .lock()
            .unwrap()
            .put(project.to_string(), cached.clone());
        Ok(cached)
    }

    /// The composed supergraph + SQL routing for `project` restricted to the canonical `subset` of
    /// subgraph names (per-site `graphql.subgraphs`), composing + caching per `(project, set_hash)` on
    /// a version miss. `subset` is the caller's CANONICAL (sorted, deduped) include set and `set_hash`
    /// its [`subgraph_set_hash`]; two sites with the same set share one entry. Used only when a site
    /// declares `subgraphs` — the absent case stays on [`supergraph`](Self::supergraph) (byte-identical
    /// to before). A composition error is returned **uncached**.
    pub(crate) async fn supergraph_subset(
        &self,
        kv: &dyn KvStore,
        project: &str,
        subset: &[String],
        set_hash: &str,
    ) -> Result<CachedGraph, CompositionError> {
        // `read_kv` captured once (same store for version read + recompose), mirroring `supergraph`.
        let (read_kv, via_read_through) = self.registry_read_store(kv);
        let version = self
            .read_version(read_kv, project, via_read_through)
            .await?;
        let key = (project.to_string(), set_hash.to_string());
        let hit = self
            .subset_supergraphs
            .lock()
            .unwrap()
            .get(&key)
            .filter(|c| c.version == version)
            .cloned();
        if let Some(hit) = hit {
            return Ok(hit);
        }
        let supergraph =
            Arc::new(crate::graphql_registry::supergraph_subset(read_kv, project, subset).await?);
        let sql_subgraphs =
            Arc::new(crate::graphql_registry::sql_subgraphs_subset(read_kv, project, subset).await);
        let schema_types =
            Arc::new(crate::graphql_registry::schema_types_subset(read_kv, project, subset).await);
        let cached = CachedGraph {
            version,
            supergraph,
            sql_subgraphs,
            schema_types,
        };
        self.subset_supergraphs
            .lock()
            .unwrap()
            .put(key, cached.clone());
        Ok(cached)
    }

    /// The plan for `query` against `graph`, memoized by `(project, version, graph_id, op_hash,
    /// visibility)`. The planner is a pure function of (operation, supergraph, edge_hidden), so
    /// `version` pins the project's composition version, `graph_id` the per-site subgraph-subset
    /// supergraph (`""` = full project), `op_hash` the operation, and `visibility` the edge-visibility
    /// dimension (#495) — so neither two sites with different subsets, nor the external edge vs the
    /// internal path, ever collide. A plan error is returned **uncached**.
    pub(crate) fn plan(
        &self,
        project: &str,
        version: u64,
        // The composed-supergraph identity: `""` (full project) or a per-site subset's
        // [`subgraph_set_hash`]. Pins the plan to the exact supergraph it was planned against.
        graph_id: &str,
        op_hash: &str,
        query: &str,
        graph: &Supergraph,
        visibility: Visibility<'_>,
    ) -> Result<Arc<QueryPlan>, PlanError> {
        let key = (
            project.to_string(),
            version,
            graph_id.to_string(),
            op_hash.to_string(),
            visibility.cache_discriminant(),
        );
        let hit = self.plans.lock().unwrap().get(&key).cloned();
        if let Some(hit) = hit {
            return Ok(hit);
        }
        // Thread the SAME visibility into the planner that the key hashed, so the cached plan and its
        // key agree (an external hidden op plans as `UnknownRootField`; an internal one plans it).
        let planned = Arc::new(plan(query, graph, visibility.edge_hidden())?);
        self.plans.lock().unwrap().put(key, planned.clone());
        Ok(planned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ACCOUNTS: &str = r#"
        type Query { me: User }
        type User @key(fields: "id") { id: ID! name: String }
    "#;

    /// A `KvStore` that counts `list_prefix` calls, so a cache hit can be asserted as
    /// "no recompute" (not merely "equal result").
    struct CountingKv {
        inner: MemoryKv,
        lists: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl KvStore for CountingKv {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, boatramp_core::kv::KvError> {
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), boatramp_core::kv::KvError> {
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<(), boatramp_core::kv::KvError> {
            self.inner.delete(key).await
        }
        async fn list_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, boatramp_core::kv::KvError> {
            self.lists.fetch_add(1, Ordering::Relaxed);
            self.inner.list_prefix(prefix).await
        }
    }

    #[tokio::test]
    async fn a_cache_hit_does_not_recompose() {
        let kv = CountingKv {
            inner: MemoryKv::new(),
            lists: AtomicUsize::new(0),
        };
        crate::graphql_registry::publish(&kv, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();

        let first = cache.supergraph(&kv, "acme").await.unwrap();
        let after_first = kv.lists.load(Ordering::Relaxed);
        assert!(first.supergraph.root_query.contains_key("me"));

        // Second call at the same version: no further `list_prefix` (served from cache).
        let _second = cache.supergraph(&kv, "acme").await.unwrap();
        assert_eq!(
            kv.lists.load(Ordering::Relaxed),
            after_first,
            "a cache hit must not re-list/recompose"
        );
    }

    #[tokio::test]
    async fn a_registry_mutation_invalidates_the_cache() {
        let kv = MemoryKv::new();
        crate::graphql_registry::publish(&kv, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let v1 = cache.supergraph(&kv, "acme").await.unwrap().version;

        // Publish a second subgraph → version bumps → the next call recomposes at the new version.
        crate::graphql_registry::publish(
            &kv,
            "acme",
            "reviews",
            "type Query { topReviews: [Review] } type Review { id: ID! }",
        )
        .await
        .unwrap();
        let after = cache.supergraph(&kv, "acme").await.unwrap();
        assert!(after.version > v1, "version advanced after a mutation");
        assert!(after.supergraph.root_query.contains_key("topReviews"));
    }

    #[tokio::test]
    async fn plans_are_cached_per_operation_and_projects_are_isolated() {
        let kv = MemoryKv::new();
        crate::graphql_registry::publish(&kv, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let graph = cache.supergraph(&kv, "acme").await.unwrap();

        let p1 = cache
            .plan(
                "acme",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::Internal,
            )
            .unwrap();
        // Same key → the very same Arc (cache hit).
        let p1_again = cache
            .plan(
                "acme",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::Internal,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&p1, &p1_again), "same op → cached plan");

        // A different project with the same op hash must not share the entry (tenant isolation).
        let p_other = cache
            .plan(
                "other",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::Internal,
            )
            .unwrap();
        assert!(
            !Arc::ptr_eq(&p1, &p_other),
            "distinct projects never share a plan"
        );
    }

    #[tokio::test]
    async fn the_visibility_dimension_distinguishes_cache_entries() {
        // #495: the SAME (project, version, op_hash) under different visibility MUST NOT share a
        // plan — a fail-open trap otherwise (an internal plan primed once would serve the edge).
        let kv = MemoryKv::new();
        crate::graphql_registry::publish(&kv, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let graph = cache.supergraph(&kv, "acme").await.unwrap();
        let empty: BTreeSet<(String, String)> = BTreeSet::new();
        let non_empty: BTreeSet<(String, String)> =
            BTreeSet::from([("Query".to_string(), "topReviews".to_string())]);

        // Internal.
        let internal = cache
            .plan(
                "acme",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::Internal,
            )
            .unwrap();
        // External with an EMPTY hidden set — MUST be a distinct entry from Internal (distinct keys).
        let external_empty = cache
            .plan(
                "acme",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::External(&empty),
            )
            .unwrap();
        assert!(
            !Arc::ptr_eq(&internal, &external_empty),
            "Internal and External(empty) must be DISTINCT cache keys (no fail-open)"
        );
        // External with a NON-empty hidden set — distinct again (different resolved-set hash). The
        // op only names `me`, so it still plans (the hidden `topReviews` isn't selected), but under
        // a different key.
        let external_hidden = cache
            .plan(
                "acme",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::External(&non_empty),
            )
            .unwrap();
        assert!(
            !Arc::ptr_eq(&external_empty, &external_hidden),
            "distinct resolved hidden sets ⇒ distinct external cache keys"
        );

        // Re-priming External(empty) with the same set returns the SAME Arc (a warm hit — the hash
        // is stable over the canonical set).
        let external_empty_again = cache
            .plan(
                "acme",
                graph.version,
                "",
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
                Visibility::External(&BTreeSet::new()),
            )
            .unwrap();
        assert!(
            Arc::ptr_eq(&external_empty, &external_empty_again),
            "the same resolved hidden set is a warm cache hit"
        );
    }

    #[test]
    fn subgraph_set_hash_is_order_independent_and_dedups() {
        let ab = subgraph_set_hash(&["a".into(), "b".into()]);
        assert_eq!(
            ab,
            subgraph_set_hash(&["b".into(), "a".into()]),
            "order-independent"
        );
        assert_eq!(
            ab,
            subgraph_set_hash(&["b".into(), "a".into(), "a".into()]),
            "duplicate-independent"
        );
        assert_ne!(
            ab,
            subgraph_set_hash(&["a".into()]),
            "a proper subset hashes distinctly"
        );
    }

    #[tokio::test]
    async fn per_site_subset_composes_only_its_set_and_caches_per_set() {
        // A second, standalone subgraph so a subset can genuinely omit a root.
        const CATALOG: &str = "type Query { products: [String] }";
        let kv = MemoryKv::new();
        crate::graphql_registry::publish(&kv, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        crate::graphql_registry::publish(&kv, "acme", "catalog", CATALOG)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let empty: BTreeSet<(String, String)> = BTreeSet::new();

        // Subset {accounts}: its supergraph has `me` (accounts' root) but NOT `products` (catalog's).
        let only_accounts = vec!["accounts".to_string()];
        let h1 = subgraph_set_hash(&only_accounts);
        let g1 = cache
            .supergraph_subset(&kv, "acme", &only_accounts, &h1)
            .await
            .unwrap();
        assert!(
            cache
                .plan(
                    "acme",
                    g1.version,
                    &h1,
                    "a",
                    "{ me { id } }",
                    &g1.supergraph,
                    Visibility::External(&empty)
                )
                .is_ok(),
            "accounts' root `me` plans in the {{accounts}} subset"
        );
        assert!(
            cache
                .plan(
                    "acme",
                    g1.version,
                    &h1,
                    "b",
                    "{ products }",
                    &g1.supergraph,
                    Visibility::External(&empty)
                )
                .is_err(),
            "catalog's root `products` is ABSENT from the {{accounts}} subset (genuinely unplannable)"
        );

        // Same set again ⇒ the very same composed supergraph Arc (per-set cache de-dupe).
        let g1b = cache
            .supergraph_subset(&kv, "acme", &only_accounts, &h1)
            .await
            .unwrap();
        assert!(
            Arc::ptr_eq(&g1.supergraph, &g1b.supergraph),
            "equal subgraph sets share one composed supergraph"
        );

        // The fuller set {accounts, catalog} (order-independent) composes distinctly + includes both.
        let both = vec!["catalog".to_string(), "accounts".to_string()];
        let h2 = subgraph_set_hash(&both);
        assert_ne!(h1, h2, "distinct sets ⇒ distinct set-hashes");
        let g2 = cache
            .supergraph_subset(&kv, "acme", &both, &h2)
            .await
            .unwrap();
        assert!(
            cache
                .plan(
                    "acme",
                    g2.version,
                    &h2,
                    "b",
                    "{ products }",
                    &g2.supergraph,
                    Visibility::External(&empty)
                )
                .is_ok(),
            "catalog's root plans in the fuller {{accounts, catalog}} subset"
        );
    }

    // The per-set subset cache recomposes on a registry-version change (and only then): a hit at the
    // same version shares the Arc; a publish bumps the version, so the next resolve recomposes.
    #[tokio::test]
    async fn per_site_subset_recomposes_only_on_a_registry_version_change() {
        const CATALOG: &str = "type Query { products: [String] }";
        let kv = MemoryKv::new();
        crate::graphql_registry::publish(&kv, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let set = vec!["accounts".to_string()];
        let h = subgraph_set_hash(&set);

        let g1 = cache
            .supergraph_subset(&kv, "acme", &set, &h)
            .await
            .unwrap();
        let g1b = cache
            .supergraph_subset(&kv, "acme", &set, &h)
            .await
            .unwrap();
        assert!(
            Arc::ptr_eq(&g1.supergraph, &g1b.supergraph),
            "no registry change ⇒ no recompose (same Arc)"
        );

        // A publish bumps the composition version → the next resolve recomposes this set.
        crate::graphql_registry::publish(&kv, "acme", "catalog", CATALOG)
            .await
            .unwrap();
        let g2 = cache
            .supergraph_subset(&kv, "acme", &set, &h)
            .await
            .unwrap();
        assert!(g2.version > g1.version, "the registry version advanced");
        assert!(
            !Arc::ptr_eq(&g1.supergraph, &g2.supergraph),
            "a version change ⇒ a recompose"
        );
        // The set is still {accounts} — the newly-published `catalog` did NOT leak into this site's
        // include set (include-list stability).
        assert!(g2.supergraph.root_query.contains_key("me"));
        assert!(!g2.supergraph.root_query.contains_key("products"));
    }

    // ===== MF-3 (extended): GraphQL registry stale-authz fence =====================================
    //
    // A cross-node registry change (a field becoming `@edgeHidden`) that misses its NOTIFY must not
    // leave that field VISIBLE on a peer — the same stale-confidentiality hole as a stale policy.
    // The GraphQL registry read is fenced through the SAME `AuthzFence` primitive (its own instance),
    // reusing the SAME `remove_authz_fence` seam. Models B's stale local snapshot (`cached`) vs the
    // authoritative shared store (`backing`), mirroring the policy gate.

    /// ACCOUNTS with the root `me` field marked `@edgeHidden` — the "hidden" registry state A writes.
    const ACCOUNTS_HIDDEN: &str = r#"
        type Query { me: User @edgeHidden }
        type User @key(fields: "id") { id: ID! name: String }
    "#;

    /// A `KvStore` whose reads ERROR — the "shared store unreachable" stand-in for the deny-closed
    /// assertion.
    struct FailingKv;
    #[async_trait::async_trait]
    impl KvStore for FailingKv {
        async fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, boatramp_core::kv::KvError> {
            Err(boatramp_core::kv::KvError::backend(
                "registry db unreachable (test)",
            ))
        }
        async fn put(&self, _k: &str, _v: Vec<u8>) -> Result<(), boatramp_core::kv::KvError> {
            Err(boatramp_core::kv::KvError::backend(
                "registry db unreachable (test)",
            ))
        }
        async fn delete(&self, _k: &str) -> Result<(), boatramp_core::kv::KvError> {
            Err(boatramp_core::kv::KvError::backend(
                "registry db unreachable (test)",
            ))
        }
        async fn list_prefix(&self, _p: &str) -> Result<Vec<String>, boatramp_core::kv::KvError> {
            Err(boatramp_core::kv::KvError::backend(
                "registry db unreachable (test)",
            ))
        }
    }

    fn hides_me(graph: &CachedGraph) -> bool {
        graph
            .supergraph
            .edge_hidden_roots
            .contains(&("Query".to_string(), "me".to_string()))
    }

    /// GATE (MF-3, GraphQL registry) — node A hides a root field on the shared store (NOTIFY
    /// suppressed → B's local snapshot + memoized supergraph are stale, field still visible). The
    /// registry fence forces a read-through to the authoritative backing, so node B recomposes at the
    /// new version and the field is now `@edgeHidden` (NOT served) within the bound `T`.
    /// RED under `remove_authz_fence` (B serves its stale, field-visible supergraph).
    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn shared_stale_graphql_registry_hidden_field_not_served_without_notify() {
        // B's stale local snapshot: `me` visible, composition version 1.
        let cached = MemoryKv::new();
        crate::graphql_registry::publish(&cached, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        // The authoritative shared store: A hid `me` (a later publish) → version 2, `me` hidden.
        let backing: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        crate::graphql_registry::publish(backing.as_ref(), "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        crate::graphql_registry::publish(backing.as_ref(), "acme", "accounts", ACCOUNTS_HIDDEN)
            .await
            .unwrap();

        let cache = GraphqlCache::default();
        // Warm B's memo against its stale snapshot (field visible at v1), BEFORE the fence is wired.
        let warm = cache.supergraph(&cached, "acme").await.unwrap();
        assert!(!hides_me(&warm), "B's warmed snapshot still serves `me`");

        // Wire the registry fence (tripped: B cannot confirm currency within T).
        let fence = Arc::new(AuthzFence::new(std::time::Duration::from_secs(30)));
        fence.trip();
        cache.set_registry_fence(backing.clone(), fence);

        // The fence forces a read-through → B sees version 2 → recomposes → `me` is now hidden.
        let fresh = cache.supergraph(&cached, "acme").await.unwrap();
        assert!(
            hides_me(&fresh),
            "the fence read-through enforces the now-hidden field — B does not serve it within T"
        );
    }

    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn mutation_remove_authz_fence_serves_hidden_graphql_field() {
        // SAFETY: single-threaded within this #[serial] test; cleared before returning.
        unsafe { std::env::set_var("BOATRAMP_KVSQL_MUTATION", "remove_authz_fence") };
        let cached = MemoryKv::new();
        crate::graphql_registry::publish(&cached, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let backing: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        crate::graphql_registry::publish(backing.as_ref(), "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        crate::graphql_registry::publish(backing.as_ref(), "acme", "accounts", ACCOUNTS_HIDDEN)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let _warm = cache.supergraph(&cached, "acme").await.unwrap();
        let fence = Arc::new(AuthzFence::new(std::time::Duration::from_secs(30)));
        fence.trip();
        cache.set_registry_fence(backing, fence);
        let served = cache.supergraph(&cached, "acme").await.unwrap();
        let hidden = hides_me(&served);
        unsafe { std::env::remove_var("BOATRAMP_KVSQL_MUTATION") };
        assert!(
            !hidden,
            "mutation: the fence is ignored, the stale (field-visible) supergraph is served → RED"
        );
    }

    /// Deny-closed: with the shared store UNREACHABLE while the fence requires a read-through, the
    /// registry read FAILS CLOSED (a composition error → the edge denies, never serving a possibly
    /// now-hidden field from stale state).
    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn shared_graphql_registry_fails_closed_on_db_unreachable() {
        let cached = MemoryKv::new();
        crate::graphql_registry::publish(&cached, "acme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let _warm = cache.supergraph(&cached, "acme").await.unwrap();
        let fence = Arc::new(AuthzFence::new(std::time::Duration::from_secs(30)));
        fence.trip();
        cache.set_registry_fence(Arc::new(FailingKv), fence);
        match cache.supergraph(&cached, "acme").await {
            Err(CompositionError::RegistryUnreachable { .. }) => {}
            Err(other) => panic!("expected RegistryUnreachable, got {other:?}"),
            Ok(_) => {
                panic!("an unreachable registry read must deny-close (fail CLOSED), not serve")
            }
        }
    }

    /// LIVE-PG twin (like the policy twin) — node A hides a root field on a REAL shared Postgres
    /// (NOTIFY suppressed); node B, whose cache holds the field-visible snapshot, does NOT serve it:
    /// the registry fence read-through to the real primary recomposes at the new version with the
    /// field `@edgeHidden`. Env-gated on `BOATRAMP_TEST_PG_URL`; skips cleanly when unset.
    #[cfg(feature = "sql-postgres")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial(shared_authz_env)]
    async fn pg_shared_stale_graphql_registry_hidden_field_not_served_without_notify() {
        let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
            eprintln!("skip pg graphql-registry fence gate: BOATRAMP_TEST_PG_URL unset");
            return;
        };
        let backing: Arc<dyn KvStore> = Arc::new(
            boatramp_storage::SqlKv::open_postgres(url, Some(8))
                .await
                .expect("open Postgres SqlKv"),
        );
        // Clean slate for this project's registry keys on the shared primary.
        for key in backing.list_prefix("graphql/pgacme/").await.unwrap() {
            backing.delete(&key).await.unwrap();
        }
        // A publishes the visible SDL, then hides `me` (a later publish) → version 2 on the primary.
        crate::graphql_registry::publish(backing.as_ref(), "pgacme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        crate::graphql_registry::publish(backing.as_ref(), "pgacme", "accounts", ACCOUNTS_HIDDEN)
            .await
            .unwrap();

        // B's stale local snapshot (field visible, version 1) + a warmed memo.
        let cached = MemoryKv::new();
        crate::graphql_registry::publish(&cached, "pgacme", "accounts", ACCOUNTS)
            .await
            .unwrap();
        let cache = GraphqlCache::default();
        let warm = cache.supergraph(&cached, "pgacme").await.unwrap();
        assert!(!hides_me(&warm));

        let fence = Arc::new(AuthzFence::new(std::time::Duration::from_secs(30)));
        fence.trip();
        cache.set_registry_fence(backing, fence);
        let fresh = cache.supergraph(&cached, "pgacme").await.unwrap();
        assert!(
            hides_me(&fresh),
            "B hid the field via the fence read-through to the real shared primary (no NOTIFY)"
        );
        println!("SERVER PG GRAPHQL-REGISTRY FENCE OK [postgres]");
    }
}
