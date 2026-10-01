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

/// The SQL-backed subgraph routing table (`name → (site, data config)`), cached alongside the
/// supergraph (it's the *other* uncached `list_prefix` on the hot path, and changes on the same
/// version bump).
type SqlSubgraphs = BTreeMap<String, (String, HandlerGraphqlDataConfig)>;

/// The plan-cache key: `(project, version, op_hash, visibility_discriminant)` (#495). The trailing
/// visibility discriminant separates the external edge's (possibly hidden) plan from the internal
/// path's — see [`Visibility`].
type PlanKey = (String, u64, String, String);

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
        let (read_kv, via_read_through) = self.registry_read_store(kv);
        let version = if via_read_through {
            match crate::graphql_registry::composition_version_checked(read_kv, project).await {
                Ok(v) => {
                    // A successful read-through re-confirms this keyspace's fence for the bound `T`.
                    if let Some(rf) = self.registry_fence.get() {
                        rf.fence.confirm();
                    }
                    v
                }
                Err(e) => {
                    return Err(CompositionError::RegistryUnreachable {
                        message: e.to_string(),
                    });
                }
            }
        } else {
            crate::graphql_registry::composition_version(read_kv, project).await
        };
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

    /// The plan for `query` against `graph`, memoized by `(project, version, op_hash, visibility)`.
    /// The planner is a pure function of (operation, supergraph, edge_hidden), so `version` pins the
    /// supergraph dimension, `op_hash` the operation, and `visibility` the edge-visibility dimension
    /// (#495) — the external edge's (possibly hidden) plan never collides with the internal path's.
    /// A plan error is returned **uncached**.
    pub(crate) fn plan(
        &self,
        project: &str,
        version: u64,
        op_hash: &str,
        query: &str,
        graph: &Supergraph,
        visibility: Visibility<'_>,
    ) -> Result<Arc<QueryPlan>, PlanError> {
        let key = (
            project.to_string(),
            version,
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
