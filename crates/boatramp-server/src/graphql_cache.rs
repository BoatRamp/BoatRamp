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

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::graphql_federation::{CompositionError, Supergraph};
use crate::graphql_plan::{plan, PlanError, QueryPlan};
use boatramp_core::config::HandlerGraphqlDataConfig;
use boatramp_core::kv::KvStore;

/// The SQL-backed subgraph routing table (`name → (site, data config)`), cached alongside the
/// supergraph (it's the *other* uncached `list_prefix` on the hot path, and changes on the same
/// version bump).
type SqlSubgraphs = BTreeMap<String, (String, HandlerGraphqlDataConfig)>;

/// A composed supergraph for a project at a specific composition version. Cheaply cloned (the
/// heavy `Supergraph` + routing table are behind `Arc`s).
#[derive(Clone)]
pub(crate) struct CachedGraph {
    pub version: u64,
    pub supergraph: Arc<Supergraph>,
    pub sql_subgraphs: Arc<SqlSubgraphs>,
}

/// Bounded number of projects' composed supergraphs held at once.
const SUPERGRAPH_CAPACITY: usize = 256;
/// Bounded number of `(project, version, operation)` plans held at once.
const PLAN_CAPACITY: usize = 1024;

/// The per-node GraphQL cache (a field of `HandlerRuntimeInner`, shared by the edge and
/// in-process `graphql::run` paths).
pub(crate) struct GraphqlCache {
    supergraphs: Mutex<LruCache<String, CachedGraph>>,
    plans: Mutex<LruCache<(String, u64, String), Arc<QueryPlan>>>,
}

impl Default for GraphqlCache {
    fn default() -> Self {
        Self {
            supergraphs: Mutex::new(LruCache::new(
                NonZeroUsize::new(SUPERGRAPH_CAPACITY).expect("nonzero"),
            )),
            plans: Mutex::new(LruCache::new(
                NonZeroUsize::new(PLAN_CAPACITY).expect("nonzero"),
            )),
        }
    }
}

impl GraphqlCache {
    /// The composed supergraph + SQL routing for `project` at the current registry version,
    /// composing (and caching) on a version miss. A composition error is returned **uncached**.
    pub(crate) async fn supergraph(
        &self,
        kv: &dyn KvStore,
        project: &str,
    ) -> Result<CachedGraph, CompositionError> {
        let version = crate::graphql_registry::composition_version(kv, project).await;
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
        // this version, then cache. Two concurrent misses both recompute the same version and the
        // last write wins — harmless (identical result).
        let supergraph = Arc::new(crate::graphql_registry::supergraph(kv, project).await?);
        let sql_subgraphs = Arc::new(crate::graphql_registry::sql_subgraphs(kv, project).await);
        let cached = CachedGraph {
            version,
            supergraph,
            sql_subgraphs,
        };
        self.supergraphs
            .lock()
            .unwrap()
            .put(project.to_string(), cached.clone());
        Ok(cached)
    }

    /// The plan for `query` against `graph`, memoized by `(project, version, op_hash)`. The
    /// planner is a pure function of (operation, supergraph), so `version` pins the supergraph
    /// dimension and `op_hash` the operation. A plan error is returned **uncached**.
    pub(crate) fn plan(
        &self,
        project: &str,
        version: u64,
        op_hash: &str,
        query: &str,
        graph: &Supergraph,
    ) -> Result<Arc<QueryPlan>, PlanError> {
        let key = (project.to_string(), version, op_hash.to_string());
        let hit = self.plans.lock().unwrap().get(&key).cloned();
        if let Some(hit) = hit {
            return Ok(hit);
        }
        let planned = Arc::new(plan(query, graph)?);
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
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
            )
            .unwrap();
        // Same key → the very same Arc (cache hit).
        let p1_again = cache
            .plan(
                "acme",
                graph.version,
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&p1, &p1_again), "same op → cached plan");

        // A different project with the same op hash must not share the entry (tenant isolation).
        let p_other = cache
            .plan(
                "other",
                graph.version,
                "op-a",
                "{ me { id } }",
                &graph.supergraph,
            )
            .unwrap();
        assert!(
            !Arc::ptr_eq(&p1, &p_other),
            "distinct projects never share a plan"
        );
    }
}
