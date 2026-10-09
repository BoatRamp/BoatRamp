//! A bounded, process-wide cache of VERIFIED blob container-markers, so a hot serve path does not
//! re-`HEAD` the `.boatramp-container` marker on every request.
//!
//! Every blob container open (`get_container` / `container_exists` / a `copy`-dest) runs the Dim-0
//! tenant-confinement choke (`container_access`, in the `wasi:blobstore` binding) and THEN probes the
//! container marker with a `Storage::head` of `{resolved-prefix}.boatramp-container` — a second serial
//! object-store round-trip on top of the object read. The confinement decision is made ENTIRELY by the
//! binding's `container_access`, BEFORE `head` is ever called; by the time a marker key reaches this
//! decorator it is already the fully-resolved, tenant-confined key `hblob/{site}/{resolved-name}/…`
//! (the tenant is baked into `{resolved-name}` by the host `{tenant}` expansion). So this decorator can
//! only ever cache a marker it was asked about under an already-authorized open — it never sees a guest
//! name and cannot be keyed cross-tenant.
//!
//! Policy (fail-closed):
//! - **Positive-only:** a marker `head` is cached ONLY on `Ok(_)`. A `NotFound` or any backend fault is
//!   NEVER cached (a fault must re-probe next time — preserving the "a 403 is not a silent 404" guard).
//! - **Confined-key-only:** the cache key is the exact key the binding passed (the resolved prefix),
//!   never a derived/guest value — two tenants' markers are distinct keys and never collide.
//! - **Invalidate on destroy:** a `delete`/`put` of a marker key evicts it, so `delete_container`'s
//!   marker delete invalidates (fail-closed) and `create_container`'s marker put refreshes. `clear`
//!   keeps the marker (it is not deleted) so the entry legitimately stays.
//! - Only marker keys (`…/.boatramp-container`) are touched; every other op delegates verbatim. The
//!   reserved `.boatramp*` object-key namespace is rejected upstream (`validate_object_key`), so a guest
//!   object can never masquerade as a marker key here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

/// The container-ownership marker basename — MUST match `MARKER` in the `wasi:blobstore` binding
/// (`boatramp-handlers` `bindings/blobstore.rs`). A marker key is `{resolved-prefix}.boatramp-container`.
const MARKER_SUFFIX: &str = ".boatramp-container";

/// Anti-hollow mutation matrix for the confinement gate (test-only; `None` in every shipped build — the
/// variants are constructed ONLY via [`MarkerHeadCache::with_mutation`]). Each flips ONE load-bearing
/// rule to its insecure form so the gate proves the real rule is doing the work.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[allow(dead_code)] // non-`None` variants are constructed only in the gate test
enum MarkerCacheMutation {
    #[default]
    None,
    /// Cache a synthetic POSITIVE for a marker that was absent/faulted (breaks positive-only).
    CacheNegative,
    /// Skip eviction on a marker delete (breaks invalidate-on-destroy → serves a stale "owned").
    SkipInvalidation,
    /// Key the cache by the marker BASENAME, collapsing distinct confined prefixes (breaks
    /// confined-key-only → one tenant's verified marker would answer another's lookup).
    KeyByBasename,
}

/// A process-wide, positive-only cache of verified container markers fronting a shared [`Storage`].
/// Bounded by entry count (markers are tiny). See the [module docs](self) for the fail-closed policy.
pub struct MarkerHeadCache {
    inner: Arc<dyn Storage>,
    /// `None` ⇒ disabled (pure pass-through); `Some` ⇒ bounded positive cache of verified marker metas.
    cache: Option<Mutex<HashMap<String, ObjectMeta>>>,
    capacity: usize,
    mutation: MarkerCacheMutation,
}

impl MarkerHeadCache {
    /// Wrap `inner`, caching up to `capacity` verified markers. `capacity == 0` disables the cache
    /// (pure pass-through).
    pub fn new(inner: Arc<dyn Storage>, capacity: usize) -> Self {
        let cache = (capacity > 0).then(|| Mutex::new(HashMap::new()));
        Self {
            inner,
            cache,
            capacity,
            mutation: MarkerCacheMutation::None,
        }
    }

    #[cfg(test)]
    fn with_mutation(
        inner: Arc<dyn Storage>,
        capacity: usize,
        mutation: MarkerCacheMutation,
    ) -> Self {
        let mut s = Self::new(inner, capacity);
        s.mutation = mutation;
        s
    }

    fn is_marker(key: &str) -> bool {
        key.ends_with(MARKER_SUFFIX)
    }

    /// The cache key for a marker key — the FULL confined key (secure). The `KeyByBasename` mutation
    /// collapses it to the basename to prove the full key is load-bearing.
    fn cache_key(&self, key: &str) -> String {
        match self.mutation {
            MarkerCacheMutation::KeyByBasename => key.rsplit('/').next().unwrap_or(key).to_string(),
            _ => key.to_string(),
        }
    }

    fn lookup(&self, ck: &str) -> Option<ObjectMeta> {
        let cache = self.cache.as_ref()?;
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(ck)
            .cloned()
    }

    fn store(&self, ck: String, meta: ObjectMeta) {
        if let Some(cache) = &self.cache {
            let mut map = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Coarse bound: markers are tiny and cheap to re-probe, and a node has far fewer than
            // `capacity` live containers in normal operation — on overflow, clear rather than carry an
            // LRU. Clearing only costs a re-probe (never serves stale), so it stays fail-closed.
            if map.len() >= self.capacity && !map.contains_key(&ck) {
                map.clear();
            }
            map.insert(ck, meta);
        }
    }

    fn evict(&self, ck: &str) {
        if let Some(cache) = &self.cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(ck);
        }
    }
}

#[async_trait]
impl Storage for MarkerHeadCache {
    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        if !Self::is_marker(key) {
            return self.inner.head(key).await; // non-marker heads are never cached
        }
        let ck = self.cache_key(key);
        if let Some(meta) = self.lookup(&ck) {
            return Ok(meta); // verified-owned, no round-trip
        }
        let result = self.inner.head(key).await;
        match &result {
            Ok(meta) => self.store(ck, meta.clone()), // POSITIVE-ONLY
            Err(_) if self.mutation == MarkerCacheMutation::CacheNegative => {
                // MUTATION: cache a synthetic positive for an absent/faulted marker.
                self.store(
                    ck,
                    ObjectMeta {
                        key: key.to_string(),
                        size: Some(0),
                        content_type: None,
                        etag: None,
                    },
                );
            }
            Err(_) => {} // SECURE: never cache a NotFound or a fault — re-probe next time.
        }
        result
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        if Self::is_marker(key) {
            self.evict(&self.cache_key(key)); // create_container's marker put refreshes
        }
        self.inner.put(key, body, meta).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        if Self::is_marker(key) && self.mutation != MarkerCacheMutation::SkipInvalidation {
            self.evict(&self.cache_key(key)); // delete_container's marker delete invalidates (fail-closed)
        }
        self.inner.delete(key).await
    }

    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        self.inner.get(key).await
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        self.inner.get_range(key, offset, len).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        self.inner.list(prefix).await
    }

    async fn list_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<boatramp_core::ListPage, StorageError> {
        self.inner.list_page(prefix, after, limit).await
    }

    fn mapped(&self, key: &str) -> Option<bytes::Bytes> {
        self.inner.mapped(key)
    }

    fn local_file(&self, key: &str) -> Option<std::fs::File> {
        self.inner.local_file(key)
    }

    fn allows_prune(&self) -> bool {
        self.inner.allows_prune()
    }

    fn drain_pair(&self) -> Option<boatramp_core::DrainPair> {
        self.inner.drain_pair()
    }

    // Watch / change-notification MUST delegate. This decorator IS the handler runtime's
    // `inner.storage`, and the blob-change-trigger path (FA-5) reads `storage.supports_watch()` /
    // `storage.watch()` directly — inheriting the trait defaults (false / Ok(None)) would SILENTLY
    // disable blob triggers on a watch-capable backend (fs / fallback-over-fs). Delegate verbatim.
    fn supports_watch(&self) -> bool {
        self.inner.supports_watch()
    }

    async fn watch(
        &self,
        prefix: &str,
    ) -> Result<Option<boatramp_core::ChangeStream>, StorageError> {
        self.inner.watch(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn bytes_stream(b: Bytes) -> ByteStream {
        futures::stream::once(async move { Ok(b) }).boxed()
    }

    /// In-memory [`Storage`] that counts `head` calls, so a test proves the cache absorbed a probe.
    #[derive(Default)]
    struct CountingMem {
        data: Mutex<HashMap<String, Bytes>>,
        heads: AtomicUsize,
    }
    impl CountingMem {
        fn head_count(&self) -> usize {
            self.heads.load(Ordering::SeqCst)
        }
        fn put_raw(&self, key: &str, b: &[u8]) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), Bytes::copy_from_slice(b));
        }
        fn remove_raw(&self, key: &str) {
            self.data.lock().unwrap().remove(key);
        }
    }
    #[async_trait]
    impl Storage for CountingMem {
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.heads.fetch_add(1, Ordering::SeqCst);
            let data = self.data.lock().unwrap();
            let b = data
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(b.len() as u64),
                content_type: None,
                etag: None,
            })
        }
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let meta = self.head(key).await?;
            let b = self.data.lock().unwrap().get(key).cloned().unwrap();
            Ok(GetObject {
                meta,
                body: bytes_stream(b),
            })
        }
        async fn get_range(
            &self,
            key: &str,
            _o: u64,
            _l: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            _m: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            let mut body = body;
            while let Some(c) = body.next().await {
                buf.extend_from_slice(&c?);
            }
            let size = buf.len() as u64;
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), Bytes::from(buf));
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                content_type: None,
                etag: None,
            })
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, _p: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(vec![])
        }
        // Watch-capable: proves the decorator delegates `supports_watch`/`watch` (a non-delegating
        // decorator would inherit the trait defaults false / Ok(None) and silently disable FA-5
        // blob-change triggers). `watch` returns a distinguishable sentinel Err to prove delegation.
        fn supports_watch(&self) -> bool {
            true
        }
        async fn watch(
            &self,
            _p: &str,
        ) -> Result<Option<boatramp_core::ChangeStream>, StorageError> {
            Err(StorageError::NotFound("watch-sentinel".into()))
        }
    }

    const MA: &str = "hblob/shop/assets-firm-a/.boatramp-container";
    const MB: &str = "hblob/shop/assets-firm-b/.boatramp-container";

    #[tokio::test]
    async fn verified_marker_is_cached_and_second_head_skips_the_backend() {
        let inner = Arc::new(CountingMem::default());
        inner.put_raw(MA, b"ts");
        let cache = MarkerHeadCache::new(inner.clone(), 64);
        assert!(cache.head(MA).await.is_ok());
        assert!(cache.head(MA).await.is_ok());
        assert_eq!(
            inner.head_count(),
            1,
            "second marker head served from cache"
        );
        // A non-marker head is never cached.
        inner.put_raw("hblob/shop/assets-firm-a/obj", b"x");
        assert!(cache.head("hblob/shop/assets-firm-a/obj").await.is_ok());
        assert!(cache.head("hblob/shop/assets-firm-a/obj").await.is_ok());
        assert_eq!(
            inner.head_count(),
            3,
            "non-marker heads always hit the backend"
        );
    }

    #[tokio::test]
    async fn delegates_supports_watch_and_watch() {
        // REGRESSION: a transparent decorator MUST delegate watch/supports_watch to inner — otherwise
        // it inherits the trait defaults (false / Ok(None)) and SILENTLY disables FA-5 blob-change
        // triggers, since this decorator is the handler runtime's `inner.storage`.
        let inner = Arc::new(CountingMem::default());
        let cache = MarkerHeadCache::new(inner.clone(), 64);
        assert!(
            cache.supports_watch(),
            "supports_watch must delegate to the watch-capable inner (not the false default)"
        );
        assert!(
            matches!(
                cache.watch("hblob/shop/assets-firm-a/").await,
                Err(StorageError::NotFound(_))
            ),
            "watch must delegate to inner (sentinel Err), not return the decorator default Ok(None)"
        );
        // Delegation holds even when the cache is DISABLED (capacity 0).
        assert!(MarkerHeadCache::new(inner, 0).supports_watch());
    }

    #[tokio::test]
    async fn absent_marker_is_not_cached_and_reprobes() {
        let inner = Arc::new(CountingMem::default());
        let cache = MarkerHeadCache::new(inner.clone(), 64);
        assert!(matches!(
            cache.head(MA).await,
            Err(StorageError::NotFound(_))
        ));
        assert!(matches!(
            cache.head(MA).await,
            Err(StorageError::NotFound(_))
        ));
        assert_eq!(
            inner.head_count(),
            2,
            "an absent marker is never cached — re-probes every time"
        );
    }

    #[tokio::test]
    async fn delete_of_marker_invalidates() {
        let inner = Arc::new(CountingMem::default());
        inner.put_raw(MA, b"ts");
        let cache = MarkerHeadCache::new(inner.clone(), 64);
        assert!(cache.head(MA).await.is_ok()); // cached
        inner.remove_raw(MA); // backend loses it
        cache.delete(MA).await.unwrap(); // marker delete → evict
        assert!(
            matches!(cache.head(MA).await, Err(StorageError::NotFound(_))),
            "after a marker delete the cache is evicted — re-probe denies"
        );
    }

    /// GATE (marker-dedup confinement): the three fail-closed rules are each load-bearing. The SECURE
    /// (`None`) run asserts every rule holds; each mutation flips exactly one rule to its insecure form
    /// and the matching assertion then goes the other way — proving the real rule does the work.
    /// Marker `MARKER-DEDUP CONFINEMENT OK`. (Cross-tenant container confinement itself is enforced by
    /// the binding's untouched `container_access`/`blob_tenant_confinement_gate`; this gate proves the
    /// DEDUP can't collapse confined keys, serve a stale-after-delete positive, or cache a negative.)
    #[tokio::test]
    async fn marker_dedup_confinement_gate() {
        // --- confined-key-only: A's verified marker must NOT answer B's lookup ---
        let keyed = |m: MarkerCacheMutation| {
            let inner = Arc::new(CountingMem::default());
            inner.put_raw(MA, b"a"); // size 1
            inner.put_raw(MB, b"bb"); // size 2 — distinguishable from A
            (inner.clone(), MarkerHeadCache::with_mutation(inner, 64, m))
        };
        {
            let (_inner, cache) = keyed(MarkerCacheMutation::None);
            assert_eq!(cache.head(MA).await.unwrap().size, Some(1)); // caches A
            assert_eq!(
                cache.head(MB).await.unwrap().size,
                Some(2),
                "SECURE: B gets its OWN marker"
            );
        }
        {
            let (_inner, cache) = keyed(MarkerCacheMutation::KeyByBasename);
            assert_eq!(cache.head(MA).await.unwrap().size, Some(1)); // caches under collapsed basename
            assert_eq!(
                cache.head(MB).await.unwrap().size,
                Some(1),
                "MUTATION key-by-basename: B wrongly gets A's cached marker (collapsed key)"
            );
        }

        // --- positive-only: an absent marker must never become a cached positive ---
        {
            let inner = Arc::new(CountingMem::default());
            let cache = MarkerHeadCache::new(inner.clone(), 64);
            assert!(matches!(
                cache.head(MA).await,
                Err(StorageError::NotFound(_))
            ));
            assert!(
                matches!(cache.head(MA).await, Err(StorageError::NotFound(_))),
                "SECURE: still absent"
            );
        }
        {
            let inner = Arc::new(CountingMem::default());
            let cache = MarkerHeadCache::with_mutation(
                inner.clone(),
                64,
                MarkerCacheMutation::CacheNegative,
            );
            assert!(matches!(
                cache.head(MA).await,
                Err(StorageError::NotFound(_))
            ));
            assert!(
                cache.head(MA).await.is_ok(),
                "MUTATION cache-negative: an absent marker is wrongly served as owned on re-head"
            );
        }

        // --- invalidate-on-destroy: a deleted marker must re-probe (deny) ---
        {
            let inner = Arc::new(CountingMem::default());
            inner.put_raw(MA, b"a");
            let cache = MarkerHeadCache::new(inner.clone(), 64);
            assert!(cache.head(MA).await.is_ok());
            inner.remove_raw(MA);
            cache.delete(MA).await.unwrap();
            assert!(
                matches!(cache.head(MA).await, Err(StorageError::NotFound(_))),
                "SECURE: evicted on delete"
            );
        }
        {
            let inner = Arc::new(CountingMem::default());
            inner.put_raw(MA, b"a");
            let cache = MarkerHeadCache::with_mutation(
                inner.clone(),
                64,
                MarkerCacheMutation::SkipInvalidation,
            );
            assert!(cache.head(MA).await.is_ok());
            inner.remove_raw(MA);
            cache.delete(MA).await.unwrap();
            assert!(
                cache.head(MA).await.is_ok(),
                "MUTATION skip-invalidation: a deleted container is wrongly served as still-owned"
            );
        }

        // --- disabled (capacity 0) is a pure pass-through ---
        {
            let inner = Arc::new(CountingMem::default());
            inner.put_raw(MA, b"a");
            let cache = MarkerHeadCache::new(inner.clone(), 0);
            assert!(cache.head(MA).await.is_ok());
            assert!(cache.head(MA).await.is_ok());
            assert_eq!(
                inner.head_count(),
                2,
                "capacity 0 disables caching (pass-through)"
            );
        }

        println!("MARKER-DEDUP CONFINEMENT OK");
    }
}
