//! A small, pluggable key/value store for deploy metadata.
//!
//! boatramp keeps two very different kinds of data apart:
//!
//! - **Blobs** — the (potentially huge) file contents — live in a streaming
//!   [`crate::Storage`] backend (filesystem, S3, ...).
//! - **Metadata** — deploy manifests and the per-site "current" pointer — are
//!   small and read on every request, so they live in a [`KvStore`].
//!
//! Separating them means the server never holds a whole file (or a whole site)
//! in memory: blobs stream, and only the small metadata is resident — and even
//! that is bounded by [`CachedKv`]'s LRU. The trait is deliberately tiny so it
//! can be backed by the filesystem, an embedded store, or a remote KV such as
//! Cloudflare KV when boatramp runs on a Workers-style platform.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use lru::LruCache;

pub use crate::error::KvError;

/// A single write within a [`KvStore::write_batch`].
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Set `key` to the given value.
    Put(String, Vec<u8>),
    /// Delete `key`.
    Delete(String),
}

/// A minimal key/value store for small values, with atomic per-key writes.
#[async_trait]
pub trait KvStore: Send + Sync {
    /// Fetch the value for `key`, or `None` if absent.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError>;

    /// Set `key` to `value`, atomically replacing any previous value.
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError>;

    /// Delete `key`. Deleting a missing key is not an error.
    async fn delete(&self, key: &str) -> Result<(), KvError>;

    /// List all keys beginning with `prefix`.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError>;

    /// Durably persist any buffered writes, keeping the store usable. The default
    /// is a no-op (in-memory + write-through backends are already durable on
    /// return); buffered backends (SlateDB, which flushes on a timer) override it
    /// so a **graceful shutdown** can force the final flush rather than racing the
    /// timer — important for the Raft log/state store, whose durability is the
    /// cluster's correctness boundary.
    async fn flush(&self) -> Result<(), KvError> {
        Ok(())
    }

    /// Apply several writes together. The default applies them sequentially
    /// (each atomic per key); backends that support grouped commits (e.g.
    /// SlateDB's `WriteBatch`) override this to commit the whole group in one
    /// durable flush — both fewer round-trips and all-or-nothing atomicity.
    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        for op in ops {
            match op {
                WriteOp::Put(key, value) => self.put(&key, value).await?,
                WriteOp::Delete(key) => self.delete(&key).await?,
            }
        }
        Ok(())
    }

    /// Drop any locally-cached entries, so subsequent reads come from the
    /// backing store. The default is a no-op (uncached stores — and the cluster
    /// `RaftKv`, which reads local applied state — see every committed write
    /// already); [`CachedKv`] clears its LRU.
    ///
    /// This matters for the **non-consensus shared-backend** topology: several
    /// independent processes over one shared KV (SlateDB-on-S3/R2, Cloudflare
    /// KV), each with its own LRU. A write by one process isn't visible to
    /// another until its LRU evicts; `SIGHUP` → `invalidate_cache` forces the
    /// re-read. In a Raft cluster this is unnecessary — replication applies the
    /// write to every node's state machine and `RaftKv` has no LRU in front.
    fn invalidate_cache(&self) {}

    /// Drop just these keys from any local cache (targeted invalidation),
    /// leaving the rest hot. The default is a no-op;
    /// [`CachedKv`] pops each. This is what the shared-mode changelog poller
    /// calls when it learns another process changed those keys, so a config edit
    /// to one site never flushes the whole working set.
    fn invalidate_keys(&self, keys: &[String]) {
        let _ = keys;
    }
}

/// An in-memory [`KvStore`], primarily for tests and ephemeral runs.
#[derive(Debug, Default, Clone)]
pub struct MemoryKv {
    inner: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MemoryKv {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KvStore for MemoryKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.inner.lock().unwrap().get(key).cloned())
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner.lock().unwrap().insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Apply the whole group under one lock: other readers see either all of
        // it or none of it, matching the all-or-nothing semantics of a durable
        // backend's batch.
        let mut map = self.inner.lock().unwrap();
        for op in ops {
            match op {
                WriteOp::Put(key, value) => {
                    map.insert(key, value);
                }
                WriteOp::Delete(key) => {
                    map.remove(&key);
                }
            }
        }
        Ok(())
    }
}

/// Announces locally-made control-plane writes to peer processes (shared-mode
/// cache coherence). [`CachedKv`] calls this after a
/// write so the changelog can record the changed keys for other processes'
/// pollers; the default deployment (single process / Raft) sets none.
#[async_trait]
pub trait ChangePublisher: Send + Sync {
    /// Record that `keys` were just written (best-effort; implementations log
    /// their own failures and must not panic).
    async fn publish(&self, keys: &[String]);
}

/// A write-through LRU cache in front of any [`KvStore`].
///
/// Bounds resident metadata: reads are served from memory when hot, and the
/// cache holds at most `capacity` entries regardless of how many sites or
/// deployments exist.
pub struct CachedKv {
    inner: Arc<dyn KvStore>,
    cache: Mutex<LruCache<String, Vec<u8>>>,
    /// Shared-mode coherence hook: announces local writes to peers. `None` for
    /// single-process / Raft deployments (no peers to notify).
    publisher: Option<Arc<dyn ChangePublisher>>,
}

impl CachedKv {
    /// Wrap `inner`, caching up to `capacity` entries (minimum 1).
    pub fn new(inner: Arc<dyn KvStore>, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner,
            cache: Mutex::new(LruCache::new(capacity)),
            publisher: None,
        }
    }

    /// Attach a [`ChangePublisher`] so local writes are announced to peer
    /// processes (shared-mode coherence). Builder-style; the default is none.
    pub fn with_publisher(mut self, publisher: Arc<dyn ChangePublisher>) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// Announce changed keys to peers, if a publisher is attached.
    async fn announce(&self, keys: Vec<String>) {
        if let Some(publisher) = &self.publisher {
            publisher.publish(&keys).await;
        }
    }
}

#[async_trait]
impl KvStore for CachedKv {
    async fn flush(&self) -> Result<(), KvError> {
        // Forward to the backing store (the LRU holds only reads); without this a
        // graceful-shutdown flush would stop at the cache (SHUT-1).
        self.inner.flush().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(value) = cache.get(key) {
                return Ok(Some(value.clone()));
            }
        }
        let value = self.inner.get(key).await?;
        if let Some(bytes) = &value {
            self.cache
                .lock()
                .unwrap()
                .put(key.to_string(), bytes.clone());
        }
        Ok(value)
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner.put(key, value.clone()).await?;
        self.cache.lock().unwrap().put(key.to_string(), value);
        self.announce(vec![key.to_string()]).await;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.delete(key).await?;
        self.cache.lock().unwrap().pop(key);
        self.announce(vec![key.to_string()]).await;
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        // Listing is not cached; it is only used on administrative paths.
        self.inner.list_prefix(prefix).await
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Commit to the backing store first (its batch is the atomic/durable
        // one); only then mirror each write into the cache so a failed commit
        // never leaves the cache ahead of the store.
        self.inner.write_batch(ops.clone()).await?;
        let mut changed = Vec::with_capacity(ops.len());
        {
            let mut cache = self.cache.lock().unwrap();
            for op in ops {
                match op {
                    WriteOp::Put(key, value) => {
                        changed.push(key.clone());
                        cache.put(key, value);
                    }
                    WriteOp::Delete(key) => {
                        cache.pop(&key);
                        changed.push(key);
                    }
                }
            }
        }
        // One announce for the whole batch (the lock is dropped first).
        self.announce(changed).await;
        Ok(())
    }

    fn invalidate_cache(&self) {
        // Drop every cached entry; the backing store is untouched, so the next
        // read repopulates from it (picking up writes made elsewhere, e.g. by
        // another cluster node via the replicated store).
        self.cache.lock().unwrap().clear();
    }

    fn invalidate_keys(&self, keys: &[String]) {
        // Pop just these keys; the rest of the cache stays hot.
        let mut cache = self.cache.lock().unwrap();
        for key in keys {
            cache.pop(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cached_kv_round_trips_and_caches() {
        let backing = Arc::new(MemoryKv::new());
        let kv = CachedKv::new(backing.clone(), 8);

        assert_eq!(kv.get("a").await.unwrap(), None);
        kv.put("a", b"1".to_vec()).await.unwrap();
        assert_eq!(kv.get("a").await.unwrap(), Some(b"1".to_vec()));

        // A direct change to the backing store is masked by the cache.
        backing.put("a", b"2".to_vec()).await.unwrap();
        assert_eq!(kv.get("a").await.unwrap(), Some(b"1".to_vec()));

        kv.delete("a").await.unwrap();
        assert_eq!(kv.get("a").await.unwrap(), None);
    }

    #[tokio::test]
    async fn invalidate_cache_drops_stale_entries() {
        let backing = Arc::new(MemoryKv::new());
        backing.put("k", b"v1".to_vec()).await.unwrap();
        let kv = CachedKv::new(backing.clone(), 8);
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v1".to_vec())); // caches v1

        // Another writer (e.g. a cluster peer via the shared store) updates it.
        backing.put("k", b"v2".to_vec()).await.unwrap();
        assert_eq!(
            kv.get("k").await.unwrap(),
            Some(b"v1".to_vec()),
            "still cached"
        );

        // SIGHUP-style invalidation → the next read pulls the fresh value.
        kv.invalidate_cache();
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn write_batch_applies_puts_and_deletes() {
        let backing = Arc::new(MemoryKv::new());
        backing.put("old", b"gone".to_vec()).await.unwrap();
        let kv = CachedKv::new(backing.clone(), 8);
        // Warm the cache so we can confirm the batch updates it.
        assert_eq!(kv.get("old").await.unwrap(), Some(b"gone".to_vec()));

        kv.write_batch(vec![
            WriteOp::Put("a".into(), b"1".to_vec()),
            WriteOp::Put("b".into(), b"2".to_vec()),
            WriteOp::Delete("old".into()),
        ])
        .await
        .unwrap();

        assert_eq!(kv.get("a").await.unwrap(), Some(b"1".to_vec()));
        assert_eq!(kv.get("b").await.unwrap(), Some(b"2".to_vec()));
        assert_eq!(kv.get("old").await.unwrap(), None);
        // The backing store reflects the same writes.
        assert_eq!(backing.get("a").await.unwrap(), Some(b"1".to_vec()));
        assert_eq!(backing.get("old").await.unwrap(), None);
    }
}
