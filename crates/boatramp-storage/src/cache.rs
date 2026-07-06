//! A bounded, local read-through cache over any [`Storage`].
//!
//! In cluster and Cloudflare modes blobs live in a *shared* object store that
//! every node reads from; a request that lands on a node which has never served
//! a given blob would otherwise pay a full round-trip to the shared store. [`CachedStorage`]
//! fronts the shared backend with a byte-bounded LRU of recently-read object
//! bodies: the first read on a node streams from (and populates) the cache, and
//! subsequent reads on the same node are served from memory.
//!
//! The cache is deliberately conservative:
//! - only `get` is cached; ranges, `head`, and `list` pass straight through;
//! - a body is cached only when its size is known up front *and* fits the byte
//!   budget — larger or unknown-size objects stream through uncached, never
//!   buffered;
//! - `put`/`delete` evict the key so a stale body is never served after a write.
//!
//! boatramp's blob keys are content-addressed (immutable), so cache staleness
//! is a non-issue in practice; the evict-on-write rule keeps the wrapper correct
//! as a general [`Storage`] regardless.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::StreamExt;
use lru::LruCache;

/// A cached object body plus the metadata to reconstruct its [`GetObject`].
struct Entry {
    meta: ObjectMeta,
    body: Bytes,
}

/// LRU plus a running total of cached bytes, behind one lock.
struct CacheState {
    lru: LruCache<String, Entry>,
    bytes: u64,
}

/// A read-through cache wrapping a shared [`Storage`] backend.
///
/// Holds at most `max_bytes` of object bodies in a least-recently-used cache.
/// See the [module docs](self) for the caching policy.
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
            }),
            max_bytes,
        }
    }

    /// Look up a cached body, marking it most-recently-used on a hit.
    fn lookup(&self, key: &str) -> Option<(ObjectMeta, Bytes)> {
        let mut state = self.state.lock().expect("cache lock poisoned");
        state
            .lru
            .get(key)
            .map(|entry| (entry.meta.clone(), entry.body.clone()))
    }

    /// Insert a body, evicting least-recently-used entries until it fits the
    /// byte budget. Objects larger than the whole budget are not cached.
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
        state.lru.put(key, Entry { meta, body });
        state.bytes += n;
    }

    /// Drop any cached body for `key` (after a write or delete).
    fn evict(&self, key: &str) {
        let mut state = self.state.lock().expect("cache lock poisoned");
        if let Some(old) = state.lru.pop(key) {
            state.bytes -= old.body.len() as u64;
        }
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
        // Range reads (media seeking) bypass the whole-object cache.
        self.inner.get_range(key, offset, len).await
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
        self.inner.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.evict(key);
        self.inner.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        self.inner.list(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory [`Storage`] double that counts `get` calls, so a test can
    /// prove the cache absorbed a read instead of hitting the backend.
    #[derive(Default)]
    struct CountingMem {
        data: Mutex<HashMap<String, Bytes>>,
        gets: AtomicUsize,
    }

    impl CountingMem {
        fn get_count(&self) -> usize {
            self.gets.load(Ordering::SeqCst)
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
            let full = self.get(key).await?;
            let bytes = collect(full.body).await?;
            let start = offset as usize;
            let end = match len {
                Some(l) => (start + l as usize).min(bytes.len()),
                None => bytes.len(),
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
}
