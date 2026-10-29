//! A bounded, local read-through cache over any [`Storage`].
//!
//! In cluster and Cloudflare modes blobs live in a *shared* object store that
//! every node reads from; a request that lands on a node which has never served
//! a given blob would otherwise pay a full round-trip to the shared store. [`CachedStorage`]
//! fronts the shared backend with a byte-bounded LRU of recently-read object
//! bodies: the first read on a node streams from (and populates) the cache, and
//! subsequent reads on the same node are served from memory.
//!
//! It fronts the three READ ops a blob/image serve actually drives:
//! - `get` — whole-object read; the body is cached when its size is known up front and fits the budget.
//! - `get_range` — the `/img` serve reads a WHOLE object via the `get-data(0, u64::MAX)` sentinel, which
//!   arrives here as `get_range(key, 0, None)`. A **whole-object** range read populates the cache exactly
//!   like `get`; a cached whole body then answers ANY later range by SLICING the exact bytes it holds
//!   (sound — we never serve a range we did not fully read). A genuinely-**partial** range on a miss
//!   (a non-zero offset, or a bounded length that is not the whole-object sentinel) streams straight
//!   through UNCACHED — a partial body is never stored under the key where a whole/other-range read would
//!   later read it back wrong.
//! - `head` — served from a cached whole body's metadata, or from a small bounded positive-only cache of
//!   recently-`head`ed object metas (so the blob-ref serve path's size probe, and the guest
//!   `has-object`/`object-info` probes, skip the round-trip on a warm object).
//!
//! The cache is deliberately conservative:
//! - a body is cached only when its size is known up front *and* fits the byte budget — larger or
//!   unknown-size objects stream through uncached, never buffered;
//! - only a POSITIVE result is cached — a `NotFound`/fault re-probes next time (a fault must not mask a
//!   later success, and an absence must not be served as a stale positive);
//! - `put`/`delete` evict the key (body AND head meta) so a stale body is never served after a write.
//!
//! boatramp's blob keys are content-addressed (immutable), so cache staleness is a non-issue in
//! practice; the evict-on-write rule keeps the wrapper correct as a general [`Storage`] regardless.
//!
//! **Wiring / confinement.** Like [`crate::MarkerHeadCache`], ONE instance is created PER backend
//! (`wrap_blob_backend`), keyed by the EXACT fully-resolved, tenant-confined storage key — never a guest
//! name. The tenant-confinement decision (`container_access`) is made by the `wasi:blobstore` binding
//! BEFORE any `get`/`get_range`/`head` reaches this decorator, so a cached entry can only ever be
//! returned for an already-authorized key, and two tenants' objects are distinct keys that never collide.
//! A process-global/`static`/one-shared-instance cache would be a cross-project confinement bypass — do
//! NOT "optimize" it into one. Transparent accessors (`mapped`/`local_file`/`allows_prune`/`drain_pair`/
//! `supports_watch`/`watch`) delegate to the inner backend so a cache OVER a read-fallback composite
//! (`cache(fallback(primary, secondary))`, the required wiring order) preserves the GC refusal, the
//! drain pair, and blob-change (FA-5) watch capability.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::StreamExt;
use lru::LruCache;

/// A cached whole-object body plus the metadata to reconstruct its [`GetObject`].
struct Entry {
    meta: ObjectMeta,
    body: Bytes,
}

/// LRU of whole-object bodies (byte-bounded) plus a small LRU of recently-`head`ed object metas
/// (count-bounded — metas are tiny), behind one lock.
struct CacheState {
    /// Whole-object bodies; bounded by `bytes <= max_bytes`.
    lru: LruCache<String, Entry>,
    /// Running total of cached body bytes.
    bytes: u64,
    /// Positive-only cache of object metas for keys `head`ed without a body read. Count-bounded (a meta
    /// costs ~0 against the byte budget, so it needs its own bound). A key present in `lru` is served
    /// from there instead, so this never duplicates a body entry's meta.
    heads: LruCache<String, ObjectMeta>,
}

/// Default count bound for the head-meta cache. Metas are tiny; a node serves far fewer than this many
/// distinct objects' heads between evictions in normal operation.
const HEAD_META_ENTRIES: usize = 8192;

/// A read-through cache wrapping a shared [`Storage`] backend.
///
/// Holds at most `max_bytes` of object bodies in a least-recently-used cache, plus a small bounded cache
/// of object metas for `head`. See the [module docs](self) for the caching policy.
pub struct CachedStorage {
    inner: Arc<dyn Storage>,
    state: Mutex<CacheState>,
    max_bytes: u64,
}

impl CachedStorage {
    /// Wrap `inner`, caching up to `max_bytes` of object bodies in memory.
    pub fn new(inner: Arc<dyn Storage>, max_bytes: u64) -> Self {
        Self {
            inner,
            state: Mutex::new(CacheState {
                lru: LruCache::unbounded(),
                bytes: 0,
                heads: LruCache::new(
                    std::num::NonZeroUsize::new(HEAD_META_ENTRIES).expect("non-zero"),
                ),
            }),
            max_bytes,
        }
    }

    /// Whether this is a whole-object range read — the `/img` serve's `get-data(0, u64::MAX)` sentinel
    /// (`len == u64::MAX`) or a to-end-from-start read (`len == None`), both starting at offset 0. Only
    /// these populate the cache on a miss; a cached whole body then slices any range.
    fn is_whole_object(offset: u64, len: Option<u64>) -> bool {
        offset == 0 && matches!(len, None | Some(u64::MAX))
    }

    /// Slice `[offset, offset+len)` (clamped to the body) out of a cached whole body, returning the
    /// range `GetObject`. Sound: the body holds every byte of the object, so a slice is exactly what the
    /// backend's `get_range` would return — `meta.size` becomes the slice length (what a backend reports
    /// as the range's content-length), content-type/etag carried from the cached whole-object meta.
    fn slice_range(meta: &ObjectMeta, body: &Bytes, offset: u64, len: Option<u64>) -> GetObject {
        let total = body.len();
        let start = (offset as usize).min(total);
        let end = match len {
            None | Some(u64::MAX) => total,
            Some(l) => start.saturating_add(l as usize).min(total),
        };
        let slice = body.slice(start..end);
        GetObject {
            meta: ObjectMeta {
                key: meta.key.clone(),
                size: Some(slice.len() as u64),
                content_type: meta.content_type.clone(),
                etag: meta.etag.clone(),
            },
            body: bytes_stream(slice),
        }
    }

    /// Look up a cached whole body, marking it most-recently-used on a hit.
    fn lookup(&self, key: &str) -> Option<(ObjectMeta, Bytes)> {
        let mut state = self.state.lock().expect("cache lock poisoned");
        state
            .lru
            .get(key)
            .map(|entry| (entry.meta.clone(), entry.body.clone()))
    }

    /// Look up a cached object meta (whole body's meta first, else the head-meta cache), marking it MRU.
    fn lookup_meta(&self, key: &str) -> Option<ObjectMeta> {
        let mut state = self.state.lock().expect("cache lock poisoned");
        if let Some(entry) = state.lru.get(key) {
            return Some(entry.meta.clone());
        }
        state.heads.get(key).cloned()
    }

    /// Insert a whole body, evicting least-recently-used entries until it fits the byte budget. Objects
    /// larger than the whole budget are not cached. Also drops any head-only meta for the key (the body
    /// entry now serves `head`).
    fn insert(&self, key: String, meta: ObjectMeta, body: Bytes) {
        let n = body.len() as u64;
        if n > self.max_bytes {
            return;
        }
        let mut state = self.state.lock().expect("cache lock poisoned");
        if let Some(old) = state.lru.pop(&key) {
            state.bytes -= old.body.len() as u64;
        }
        while state.bytes + n > self.max_bytes {
            match state.lru.pop_lru() {
                Some((_, old)) => state.bytes -= old.body.len() as u64,
                None => break,
            }
        }
        state.heads.pop(&key);
        state.lru.put(key, Entry { meta, body });
        state.bytes += n;
    }

    /// Insert a positive object meta into the head-meta cache (count-bounded by the LRU). Skipped if a
    /// whole body for the key is already cached (that entry's meta already answers `head`).
    fn insert_head(&self, key: String, meta: ObjectMeta) {
        let mut state = self.state.lock().expect("cache lock poisoned");
        if state.lru.contains(&key) {
            return;
        }
        state.heads.put(key, meta);
    }

    /// Drop any cached body AND head meta for `key` (after a write or delete).
    fn evict(&self, key: &str) {
        let mut state = self.state.lock().expect("cache lock poisoned");
        if let Some(old) = state.lru.pop(key) {
            state.bytes -= old.body.len() as u64;
        }
        state.heads.pop(key);
    }
}

/// Wrap owned [`Bytes`] as a single-chunk [`ByteStream`].
fn bytes_stream(bytes: Bytes) -> ByteStream {
    futures::stream::once(async move { Ok(bytes) }).boxed()
}

/// Drain a [`ByteStream`] into contiguous [`Bytes`].
async fn collect(mut body: ByteStream) -> Result<Bytes, StorageError> {
    let mut buf = Vec::new();
    while let Some(chunk) = body.next().await {
        buf.extend_from_slice(&chunk?);
    }
    Ok(Bytes::from(buf))
}

#[async_trait]
impl Storage for CachedStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        if let Some((meta, body)) = self.lookup(key) {
            return Ok(GetObject {
                meta,
                body: bytes_stream(body),
            });
        }

        let obj = self.inner.get(key).await?;

        // Only buffer-and-cache when the size is known up front and fits the
        // budget; otherwise stream the body straight through, uncached.
        let eligible = obj.meta.size.is_some_and(|s| s <= self.max_bytes);
        if !eligible {
            return Ok(obj);
        }

        let meta = obj.meta.clone();
        let body = collect(obj.body).await?;
        // A backend that under-reported its size could still overflow the
        // budget once collected — re-check before caching.
        if body.len() as u64 <= self.max_bytes {
            self.insert(key.to_string(), meta.clone(), body.clone());
        }
        Ok(GetObject {
            meta,
            body: bytes_stream(body),
        })
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        // A cached whole body answers ANY range by slicing the exact bytes it holds (sound).
        if let Some((meta, body)) = self.lookup(key) {
            return Ok(Self::slice_range(&meta, &body, offset, len));
        }

        // A WHOLE-object range read (the `/img` `get-data(0, u64::MAX)` sentinel) populates the cache
        // exactly like `get`. A genuinely-partial range streams through UNCACHED — never stored under
        // the key where a later whole/other-range read would read a partial body back wrong.
        if !Self::is_whole_object(offset, len) {
            return self.inner.get_range(key, offset, len).await;
        }

        let obj = self.inner.get_range(key, offset, len).await?;
        let eligible = obj.meta.size.is_some_and(|s| s <= self.max_bytes);
        if !eligible {
            return Ok(obj);
        }
        let meta = obj.meta.clone();
        let body = collect(obj.body).await?;
        if body.len() as u64 <= self.max_bytes {
            self.insert(key.to_string(), meta.clone(), body.clone());
        }
        Ok(GetObject {
            meta,
            body: bytes_stream(body),
        })
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        self.evict(key);
        self.inner.put(key, body, meta).await
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        if let Some(meta) = self.lookup_meta(key) {
            return Ok(meta);
        }
        let meta = self.inner.head(key).await?; // POSITIVE-ONLY: a NotFound/fault re-probes next time
        self.insert_head(key.to_string(), meta.clone());
        Ok(meta)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.evict(key);
        self.inner.delete(key).await
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
        // Delegate so the inner backend's NATIVE single-page pagination is preserved (the default
        // trait body would drain the whole keyspace through the cache — the exact cost this avoids).
        self.inner.list_page(prefix, after, limit).await
    }

    /// Delegate the zero-copy accessors to the wrapped backend — the cache buffers
    /// only small bodies, and large blobs (the ones these serve) are exactly what a
    /// local backend should memory-map / `sendfile`. Not delegating them would
    /// silently disable both fast paths behind the cache.
    fn mapped(&self, key: &str) -> Option<bytes::Bytes> {
        self.inner.mapped(key)
    }

    fn local_file(&self, key: &str) -> Option<std::fs::File> {
        self.inner.local_file(key)
    }

    /// Delegate to the wrapped backend. A cache is a pure read-through decorator —
    /// it does not change what may be pruned — so a cache OVER a read-fallback
    /// composite (`cache(fallback(primary, secondary))`, the required wiring order)
    /// must still report `false`, or the GC refusal would be bypassed by the cache
    /// layer.
    fn allows_prune(&self) -> bool {
        self.inner.allows_prune()
    }

    /// Delegate to the wrapped backend: a cache OVER a read-fallback composite
    /// (`cache(fallback(primary, secondary))`, the required wiring order) must still expose the
    /// drain pair so the daemon-mediated drain reaches the underlying secondary → primary — the
    /// caching layer never introduces or hides a drain of its own.
    fn drain_pair(&self) -> Option<boatramp_core::DrainPair> {
        self.inner.drain_pair()
    }

    /// Delegate watch/change-notification VERBATIM. This decorator sits in the handler runtime's
    /// `inner.storage` stack, and the blob-change-trigger path (FA-5) reads `storage.supports_watch()`
    /// / `storage.watch()` directly — inheriting the trait defaults (`false` / `Ok(None)`) would
    /// SILENTLY disable blob triggers on a watch-capable backend (fs / fallback-over-fs) now that the
    /// cache is wired into the serve path. Delegate, exactly as `MarkerHeadCache` does.
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
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory [`Storage`] double that counts `get`/`get_range`/`head` calls, so a test can
    /// prove the cache absorbed a read instead of hitting the backend.
    #[derive(Default)]
    struct CountingMem {
        data: Mutex<HashMap<String, Bytes>>,
        gets: AtomicUsize,
        ranges: AtomicUsize,
        heads: AtomicUsize,
    }

    impl CountingMem {
        fn get_count(&self) -> usize {
            self.gets.load(Ordering::SeqCst)
        }
        fn range_count(&self) -> usize {
            self.ranges.load(Ordering::SeqCst)
        }
        fn head_count(&self) -> usize {
            self.heads.load(Ordering::SeqCst)
        }

        fn insert(&self, key: &str, bytes: &[u8]) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), Bytes::copy_from_slice(bytes));
        }
    }

    #[async_trait]
    impl Storage for CountingMem {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            let bytes = self
                .data
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(bytes.len() as u64),
                    content_type: None,
                    etag: None,
                },
                body: bytes_stream(bytes),
            })
        }

        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.ranges.fetch_add(1, Ordering::SeqCst);
            let bytes = self
                .data
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let start = (offset as usize).min(bytes.len());
            let end = match len {
                None | Some(u64::MAX) => bytes.len(),
                Some(l) => (start + l as usize).min(bytes.len()),
            };
            let slice = bytes.slice(start..end);
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(slice.len() as u64),
                    content_type: None,
                    etag: None,
                },
                body: bytes_stream(slice),
            })
        }

        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let bytes = collect(body).await?;
            let size = bytes.len() as u64;
            self.data.lock().unwrap().insert(key.to_string(), bytes);
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                content_type: None,
                etag: None,
            })
        }

        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.heads.fetch_add(1, Ordering::SeqCst);
            let data = self.data.lock().unwrap();
            let bytes = data
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(bytes.len() as u64),
                content_type: None,
                etag: None,
            })
        }

        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| ObjectMeta {
                    key: k.clone(),
                    size: Some(v.len() as u64),
                    content_type: None,
                    etag: None,
                })
                .collect())
        }
    }

    async fn read_all(store: &CachedStorage, key: &str) -> Result<Vec<u8>, StorageError> {
        let obj = store.get(key).await?;
        Ok(collect(obj.body).await?.to_vec())
    }

    async fn read_range(
        store: &CachedStorage,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<Vec<u8>, StorageError> {
        let obj = store.get_range(key, offset, len).await?;
        Ok(collect(obj.body).await?.to_vec())
    }

    #[tokio::test]
    async fn second_read_is_served_from_cache() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("current/blog", b"hello cluster");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        assert_eq!(
            read_all(&cache, "current/blog").await.unwrap(),
            b"hello cluster"
        );
        assert_eq!(
            read_all(&cache, "current/blog").await.unwrap(),
            b"hello cluster"
        );
        // Two reads, one backend round-trip — the second was a cache hit.
        assert_eq!(inner.get_count(), 1);
    }

    /// C2 gate: a blob deployed on node A is served by node B, which has no
    /// local copy. Both nodes front the *same* shared object store with their
    /// own cold cache; B's first read goes through to the shared store and is
    /// then cached locally.
    #[tokio::test]
    async fn deploy_on_one_node_served_by_another() {
        let shared = Arc::new(CountingMem::default());
        let node_a = CachedStorage::new(shared.clone(), 1 << 20);
        let node_b = CachedStorage::new(shared.clone(), 1 << 20);

        // Deploy lands on node A (content-addressed key, idempotent write).
        node_a
            .put(
                "ab/sha256-deadbeef",
                bytes_stream(Bytes::from_static(b"<html>deployed on A</html>")),
                PutMeta::default(),
            )
            .await
            .unwrap();

        // Node B, cold cache, serves it by reading through to the shared store.
        assert_eq!(
            read_all(&node_b, "ab/sha256-deadbeef").await.unwrap(),
            b"<html>deployed on A</html>"
        );
        assert_eq!(shared.get_count(), 1, "B read through to the shared store");

        // And B now serves it from its own cache (no further shared-store hit).
        read_all(&node_b, "ab/sha256-deadbeef").await.unwrap();
        assert_eq!(
            shared.get_count(),
            1,
            "B's second read was a local cache hit"
        );
    }

    #[tokio::test]
    async fn delete_evicts_so_next_read_misses() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("blob", b"data");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        read_all(&cache, "blob").await.unwrap();
        assert_eq!(inner.get_count(), 1);

        cache.delete("blob").await.unwrap();
        // Backend now lacks the key and the cache was evicted: a miss surfaces
        // NotFound from the backend (proving the stale body wasn't served).
        // (`GetObject` isn't `Debug`, so match rather than `unwrap_err`.)
        assert!(matches!(
            cache.get("blob").await,
            Err(StorageError::NotFound(_))
        ));
        assert_eq!(inner.get_count(), 2);
    }

    #[tokio::test]
    async fn objects_over_budget_are_not_cached() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("big", b"0123456789"); // 10 bytes
        let cache = CachedStorage::new(inner.clone(), 4); // budget below object size

        read_all(&cache, "big").await.unwrap();
        read_all(&cache, "big").await.unwrap();
        // Never cached (too large), so every read hits the backend.
        assert_eq!(inner.get_count(), 2);
    }

    #[tokio::test]
    async fn lru_evicts_to_stay_within_budget() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("a", b"aaaa"); // 4 bytes
        inner.insert("b", b"bbbb"); // 4 bytes
        let cache = CachedStorage::new(inner.clone(), 6); // room for one 4-byte body

        read_all(&cache, "a").await.unwrap(); // caches a
        read_all(&cache, "b").await.unwrap(); // caches b, evicts a
        read_all(&cache, "a").await.unwrap(); // a was evicted -> backend again
        // a: miss, b: miss, a: miss again => 3 backend gets.
        assert_eq!(inner.get_count(), 3);
    }

    #[tokio::test]
    async fn put_evicts_stale_cached_body() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("k", b"v1");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        assert_eq!(read_all(&cache, "k").await.unwrap(), b"v1");
        cache
            .put(
                "k",
                bytes_stream(Bytes::from_static(b"v2")),
                PutMeta::default(),
            )
            .await
            .unwrap();
        // The write evicted the cached body, so the next read reflects v2.
        assert_eq!(read_all(&cache, "k").await.unwrap(), b"v2");
    }

    /// The `/img` serve path: a WHOLE-object `get_range(0, None)` (the `get-data(0, u64::MAX)` sentinel
    /// the shim passes) caches the body, and the second whole-object range serve is a cache hit.
    #[tokio::test]
    async fn whole_object_range_populates_and_serves_from_cache() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("der/sha/512.webp", b"webp-derivative-bytes");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        assert_eq!(
            read_range(&cache, "der/sha/512.webp", 0, None)
                .await
                .unwrap(),
            b"webp-derivative-bytes"
        );
        assert_eq!(
            read_range(&cache, "der/sha/512.webp", 0, Some(u64::MAX))
                .await
                .unwrap(),
            b"webp-derivative-bytes"
        );
        // One backend range round-trip; the second whole-object read was a cache hit.
        assert_eq!(inner.range_count(), 1);
    }

    /// A cached WHOLE body answers any later sub-range by slicing — the exact bytes, never a wrong range.
    #[tokio::test]
    async fn sub_range_is_served_from_a_cached_whole_body() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("obj", b"0123456789");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        // Warm the whole object.
        assert_eq!(
            read_range(&cache, "obj", 0, None).await.unwrap(),
            b"0123456789"
        );
        assert_eq!(inner.range_count(), 1);

        // Sub-ranges are now sliced from the cached body — correct bytes, no further backend reads.
        assert_eq!(read_range(&cache, "obj", 2, Some(3)).await.unwrap(), b"234");
        assert_eq!(read_range(&cache, "obj", 7, None).await.unwrap(), b"789");
        assert_eq!(read_range(&cache, "obj", 0, Some(1)).await.unwrap(), b"0");
        assert_eq!(
            inner.range_count(),
            1,
            "every sub-range was sliced from the cached whole body"
        );
    }

    /// A GENUINELY-partial range on a MISS streams through UNCACHED — it must never be stored under the
    /// key (a later whole-object read would otherwise read a truncated body back as if it were whole).
    #[tokio::test]
    async fn partial_range_miss_is_not_cached_as_whole() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("obj", b"0123456789");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        // A partial range (offset 2, len 3) on a cold cache: passes through, NOT cached.
        assert_eq!(read_range(&cache, "obj", 2, Some(3)).await.unwrap(), b"234");
        assert_eq!(inner.range_count(), 1);

        // The whole object is still a MISS (the partial was not stored as the whole body) and returns
        // the FULL correct bytes from the backend — never the truncated partial.
        assert_eq!(read_all(&cache, "obj").await.unwrap(), b"0123456789");
        assert_eq!(
            inner.get_count(),
            1,
            "whole-object read went to the backend"
        );
    }

    /// `head` is served from a cached whole body's meta, and from a bounded positive-only head-meta
    /// cache otherwise; a `NotFound` is never cached (re-probes).
    #[tokio::test]
    async fn head_is_cached_positive_only() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("obj", b"0123456789");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        // First head → backend; second → cached meta.
        assert_eq!(cache.head("obj").await.unwrap().size, Some(10));
        assert_eq!(cache.head("obj").await.unwrap().size, Some(10));
        assert_eq!(
            inner.head_count(),
            1,
            "second head served from the meta cache"
        );

        // A whole-object read's meta also answers head with no extra round-trip.
        read_all(&cache, "obj").await.unwrap();
        assert_eq!(cache.head("obj").await.unwrap().size, Some(10));
        assert_eq!(
            inner.head_count(),
            1,
            "head served from the cached body's meta"
        );

        // An ABSENT key is never cached — it re-probes the backend every time.
        assert!(matches!(
            cache.head("missing").await,
            Err(StorageError::NotFound(_))
        ));
        assert!(matches!(
            cache.head("missing").await,
            Err(StorageError::NotFound(_))
        ));
        assert_eq!(
            inner.head_count(),
            3,
            "an absent head is never cached — re-probes each time"
        );
    }

    /// A write/delete evicts the head-meta too, so a stale size is never served after a mutation.
    #[tokio::test]
    async fn write_evicts_head_meta() {
        let inner = Arc::new(CountingMem::default());
        inner.insert("k", b"v1");
        let cache = CachedStorage::new(inner.clone(), 1 << 20);

        assert_eq!(cache.head("k").await.unwrap().size, Some(2)); // caches meta size=2
        cache
            .put(
                "k",
                bytes_stream(Bytes::from_static(b"v2-longer")),
                PutMeta::default(),
            )
            .await
            .unwrap();
        // The write evicted the head meta, so head reflects the new size.
        assert_eq!(cache.head("k").await.unwrap().size, Some(9));
    }
}
