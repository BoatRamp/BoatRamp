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
use std::ops::Bound;
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

    /// List up to `limit` keys under `prefix` that sort **strictly after**
    /// `{prefix}{after}` (an empty `after` starts at the beginning), in key order
    /// — a bounded, resumable range scan. The default rebuilds it from
    /// [`list_prefix`](Self::list_prefix) (O(keys-under-prefix)); ordered backends
    /// override it with a native seek so a caller paging forward from a cursor is
    /// O(`limit`), not O(prefix size) — the messaging fan-out claim relies on this.
    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        let start = format!("{prefix}{after}");
        let mut keys: Vec<String> = self
            .list_prefix(prefix)
            .await?
            .into_iter()
            .filter(|k| k.as_str() > start.as_str())
            .collect();
        keys.sort();
        keys.truncate(limit);
        Ok(keys)
    }

    /// Durably persist any buffered writes, keeping the store usable. The default
    /// is a no-op (in-memory + write-through backends are already durable on
    /// return); buffered backends (SlateDB, which flushes on a timer) override it
    /// so a **graceful shutdown** can force the final flush rather than racing the
    /// timer — important for the Raft log/state store, whose durability is the
    /// cluster's correctness boundary.
    async fn flush(&self) -> Result<(), KvError> {
        Ok(())
    }

    /// Whether [`write_batch`](Self::write_batch) is **atomic** — all-or-nothing across the group, so
    /// a crash can never leave a partially-applied batch. The default is `false`: the default
    /// `write_batch` applies each op sequentially (each atomic per KEY, but not across the group), so
    /// a crash between two ops leaves the first applied and the second not. Backends whose batch is a
    /// single durable commit (SlateDB's `WriteBatch`, the in-memory store under one lock, the Raft
    /// state machine's per-entry apply) override this to `true`.
    ///
    /// This is a **hard prerequisite** for event-driven delivery's ready-set fast path (B2): the
    /// ready-set marker must ride the SAME atomic `write_batch` as the message-index write, else a
    /// crash between the (durable) index put and the (separate) ready put strands the message. A
    /// backend that returns `false` here MUST fall back to the full poll — see
    /// [`Messaging::supports_ready_set`](crate::messaging::Messaging::supports_ready_set), which keys
    /// on this. Fail-closed: an unsure backend inherits the default `false` and simply polls.
    fn atomic_write_batch(&self) -> bool {
        false
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

    /// Whether [`compare_and_swap`](Self::compare_and_swap) is a **linearizable** compare-and-set —
    /// the read-of-`expected` and the conditional write happen as ONE atomic step with respect to
    /// every other writer, so two racing swappers of the same key can never both succeed. The default
    /// is `false`: the default `compare_and_swap` is a best-effort read-then-write, which is safe only
    /// where there is a single logical writer (a single-node scheduler serializes its own drains), NOT
    /// across concurrent nodes.
    ///
    /// This is the **hard prerequisite for the async-lane shard's CAS claim (B10)**: with the async
    /// drain sharded, the old and new owner of a function may briefly both run its drain (the
    /// double-owner window), and only a linearizable CAS on the invocation record guarantees at most
    /// one node transitions a `Queued`/expired-`Running` invocation to `Running`. A backend that
    /// returns `false` here MUST keep the async drain leader-gated (owns-all, today's behavior) rather
    /// than shard it — see the server's `async_shard_gate`, which keys the shard fast-path on this.
    /// Fail-closed: an unsure backend inherits the default `false` and simply stays unsharded.
    ///
    /// Backends whose CAS is genuinely atomic override this to `true`: [`MemoryKv`] (under its lock),
    /// SlateDB (a single-writer process serialized by an in-process CAS mutex), and the Raft state
    /// machine (a single leader-serialized apply). A non-transactional remote KV (Cloudflare KV) keeps
    /// the default `false`.
    fn supports_cas(&self) -> bool {
        false
    }

    /// **Compare-and-set** `key`: write `new` IFF the current value equals `expected` (`None` =
    /// "expect the key absent"), returning `true` when the swap happened and `false` when the observed
    /// value did not match (so the caller lost the race / the record moved on).
    ///
    /// The default is a **best-effort** read-then-write: it reads the current value, compares, and
    /// writes if it matches — atomic per key, but the read and the write are two operations, so a
    /// second writer can interleave between them. That is safe ONLY on a single-writer node (the async
    /// drain runs from one scheduler loop, and a single-node deployment has exactly one process
    /// writing invocation records). It is NOT safe across concurrent cluster nodes — which is exactly
    /// why [`supports_cas`](Self::supports_cas) gates the sharded fast-path, and a backend without a
    /// linearizable CAS stays leader-gated (owns-all). See B10.
    ///
    /// Callers compare on the EXACT prior bytes they read (whole-record equality), so any concurrent
    /// mutation — a claim by another node, a settle, a redeploy — changes the bytes and the CAS
    /// correctly fails. `expected: None` is a create-if-absent (used for idempotent first writes).
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        // Best-effort default: read, compare, write-if-matched. Atomic only under a single logical
        // writer (see the method + `supports_cas` docs). A linearizable backend overrides this.
        let current = self.get(key).await?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        self.put(key, new).await?;
        Ok(true)
    }

    /// A **durability-relaxed** grouped write: the same atomic group as
    /// [`write_batch`](Self::write_batch), but the backend MAY acknowledge on an
    /// in-memory buffer insert **before** the write is durably persisted (the flush
    /// follows asynchronously). The default impl is **identical to `write_batch`
    /// (fully durable)** — a backend that cannot (or must not) relax durability
    /// simply inherits the strong path, so this can never silently weaken a store
    /// that doesn't opt in. Only [`SlateKv`](../../boatramp_storage/struct.SlateKv.html)
    /// overrides it (SlateDB `await_durable: false`).
    ///
    /// **SAFETY BOUNDARY — bus publish path ONLY.** The ONLY permitted caller is the
    /// single-node messaging group-commit
    /// ([`LogMessaging::group_commit`](crate::messaging::LogMessaging)), and only when
    /// the operator has opted the node into relaxed messaging durability. Every
    /// control-plane write (deploy/config/domain/auth), every guest `wasi:keyvalue`
    /// write, and every messaging **ack/claim/dead-letter** transition (INCLUDING the
    /// event-driven ready-set removals/re-adds — B3) MUST use the durable
    /// [`write_batch`](Self::write_batch) — a shared `KvStore` backs all of them, so
    /// relaxing any of those would be a control-plane / redelivery hazard.
    ///
    /// The sole-caller property is enforced behaviorally: the `CountingKv` durability tests assert
    /// the relaxed path is taken ONLY on the opted-in publish path (zero relaxed calls under the
    /// strong default, and never for a claim-drain prune or nack re-add — see
    /// `ready_set_removals_and_readds_are_never_relaxed`), and the sole in-tree caller is
    /// [`LogMessaging::commit_group`](crate::messaging::LogMessaging). (This is not a source-scanning
    /// lint — a future caller would have to be caught by these tests or review.)
    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.write_batch(ops).await
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
        // Range-seek to the prefix and walk forward only while keys still match — O(keys-under-prefix)
        // on the sorted map, NOT O(total keys). This matters for the event-driven-delivery ready-set
        // scan (`mqready/…`): an idle fleet with many other keys must not pay to scan them all.
        Ok(self
            .inner
            .lock()
            .unwrap()
            .range(prefix.to_string()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect())
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        // The BTreeMap is already sorted, so seek straight to the cursor and walk
        // forward — O(limit) rather than the default's O(keys-under-prefix).
        let start = format!("{prefix}{after}");
        Ok(self
            .inner
            .lock()
            .unwrap()
            .range((Bound::Excluded(start), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .take(limit)
            .map(|(key, _)| key.clone())
            .collect())
    }

    fn atomic_write_batch(&self) -> bool {
        // The whole group applies under one mutex (below): other readers see all of it or none of
        // it, and there is no crash boundary within an in-memory store — so its batch is atomic and
        // the ready-set fast path (B2) is safe over it.
        true
    }

    fn supports_cas(&self) -> bool {
        // The compare + swap below happen under one mutex, so it is a linearizable CAS: two racing
        // swappers of the same key can never both win. Safe for the async-lane shard's claim (B10).
        true
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        // Compare + conditional insert under ONE lock — no other writer can interleave, so this is a
        // true atomic CAS (unlike the trait default's separate read-then-write).
        let mut map = self.inner.lock().unwrap();
        let current = map.get(key).map(|v| v.as_slice());
        if current != expected {
            return Ok(false);
        }
        map.insert(key.to_string(), new);
        Ok(true)
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

    /// Commit `ops` to the backing store FIRST (its batch is the atomic/durable one — durable via
    /// `write_batch`, or memtable-acked via `write_batch_relaxed` when `relaxed`), then mirror each
    /// write into the cache — so a failed commit never leaves the cache ahead of the store. The
    /// relaxation is purely the inner store's ack timing; the cache ordering is identical.
    async fn commit_then_mirror(&self, ops: Vec<WriteOp>, relaxed: bool) -> Result<(), KvError> {
        if relaxed {
            self.inner.write_batch_relaxed(ops.clone()).await?;
        } else {
            self.inner.write_batch(ops.clone()).await?;
        }
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

    fn atomic_write_batch(&self) -> bool {
        // The cache is a pure read-through mirror; the backing store's batch is the atomic/durable
        // one (`commit_then_mirror` commits it FIRST). So the cache is as atomic as its inner store.
        self.inner.atomic_write_batch()
    }

    fn supports_cas(&self) -> bool {
        // The cache never serves the CAS compare (the override below goes straight to the inner
        // store, whose value is authoritative), so the CAS is as atomic as the inner store's.
        self.inner.supports_cas()
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        // The CAS compare MUST run against the backing store's authoritative value, never the LRU
        // (a stale cached value would make the compare wrong and could double-swap). So forward the
        // whole CAS to the inner store, then mirror the new value into the cache only on success —
        // a lost CAS leaves the cache untouched, and a failed inner call never advances it.
        let swapped = self
            .inner
            .compare_and_swap(key, expected, new.clone())
            .await?;
        if swapped {
            self.cache.lock().unwrap().put(key.to_string(), new);
            self.announce(vec![key.to_string()]).await;
        }
        Ok(swapped)
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.commit_then_mirror(ops, false).await
    }

    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Forward the relaxed path to the inner store (only it can weaken durability), preserving the
        // identical commit-then-mirror ordering so a failed commit never leaves the cache ahead.
        self.commit_then_mirror(ops, true).await
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

    /// A shared **conformance suite** every `KvStore` must satisfy identically. Running the
    /// same assertions against multiple backends is what keeps them from drifting (B7): a
    /// caching or storage layer that got `list_prefix`, overwrite, delete-of-missing, or empty
    /// values subtly wrong fails here rather than in production. New in-process backends
    /// (SlateDB, …) should call this too.
    async fn kv_conformance(store: &dyn KvStore) {
        // Missing key → None; delete of a missing key is a no-op (idempotent).
        assert_eq!(store.get("missing").await.unwrap(), None);
        store.delete("missing").await.unwrap();

        // Put/get round-trip, including an EMPTY value (distinct from absent) and binary bytes.
        store.put("k/1", b"one".to_vec()).await.unwrap();
        store.put("k/empty", Vec::new()).await.unwrap();
        store.put("k/bin", vec![0u8, 159, 146, 150]).await.unwrap();
        assert_eq!(store.get("k/1").await.unwrap(), Some(b"one".to_vec()));
        assert_eq!(store.get("k/empty").await.unwrap(), Some(Vec::new()));
        assert_eq!(
            store.get("k/bin").await.unwrap(),
            Some(vec![0, 159, 146, 150])
        );

        // Overwrite replaces the value.
        store.put("k/1", b"ONE".to_vec()).await.unwrap();
        assert_eq!(store.get("k/1").await.unwrap(), Some(b"ONE".to_vec()));

        // list_prefix returns exactly the matching keys (not others), regardless of order.
        store.put("other/x", b"x".to_vec()).await.unwrap();
        let mut got = store.list_prefix("k/").await.unwrap();
        got.sort();
        assert_eq!(got, vec!["k/1", "k/bin", "k/empty"]);
        assert_eq!(
            store.list_prefix("nope/").await.unwrap(),
            Vec::<String>::new()
        );

        // list_from is a bounded, resumable range scan: only keys strictly after
        // the cursor, in order, capped at `limit` — the messaging fan-out claim
        // relies on this being identical across backends.
        assert_eq!(
            store.list_from("k/", "", 10).await.unwrap(),
            vec!["k/1", "k/bin", "k/empty"],
            "empty cursor starts at the beginning, in key order"
        );
        assert_eq!(
            store.list_from("k/", "", 2).await.unwrap(),
            vec!["k/1", "k/bin"],
            "limit caps the batch"
        );
        assert_eq!(
            store.list_from("k/", "bin", 10).await.unwrap(),
            vec!["k/empty"],
            "resumes strictly after the cursor"
        );
        assert_eq!(
            store.list_from("k/", "empty", 10).await.unwrap(),
            Vec::<String>::new(),
            "past the last key → empty"
        );
        assert_eq!(
            store.list_from("k/", "1", 10).await.unwrap(),
            vec!["k/bin", "k/empty"],
            "the cursor itself is excluded, and other prefixes never leak in"
        );

        // Delete removes just that key; the prefix set shrinks accordingly.
        store.delete("k/1").await.unwrap();
        assert_eq!(store.get("k/1").await.unwrap(), None);
        let mut after = store.list_prefix("k/").await.unwrap();
        after.sort();
        assert_eq!(after, vec!["k/bin", "k/empty"]);

        // write_batch applies puts + deletes together.
        store
            .write_batch(vec![
                WriteOp::Put("k/2".into(), b"two".to_vec()),
                WriteOp::Delete("k/empty".into()),
            ])
            .await
            .unwrap();
        assert_eq!(store.get("k/2").await.unwrap(), Some(b"two".to_vec()));
        assert_eq!(store.get("k/empty").await.unwrap(), None);

        // compare_and_swap (B10) — the same semantics on every backend, atomic or best-effort.
        // Create-if-absent: expected=None swaps only when the key is missing.
        assert!(
            store
                .compare_and_swap("cas/k", None, b"v1".to_vec())
                .await
                .unwrap(),
            "expected-absent CAS on a missing key swaps"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v1".to_vec()));
        assert!(
            !store
                .compare_and_swap("cas/k", None, b"v2".to_vec())
                .await
                .unwrap(),
            "expected-absent CAS on a present key does NOT swap"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v1".to_vec()));
        // Match on the exact prior bytes swaps; a stale expected does not.
        assert!(
            !store
                .compare_and_swap("cas/k", Some(b"WRONG"), b"v3".to_vec())
                .await
                .unwrap(),
            "CAS with a non-matching expected leaves the value"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v1".to_vec()));
        assert!(
            store
                .compare_and_swap("cas/k", Some(b"v1"), b"v4".to_vec())
                .await
                .unwrap(),
            "CAS with the matching expected swaps"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v4".to_vec()));
    }

    /// The atomic-CAS race property (B10): with a linearizable `compare_and_swap`, exactly one of
    /// many racing swappers of the same key from the same observed value wins — the primitive the
    /// async-lane shard claim is built on. Runs only against a backend that advertises
    /// [`KvStore::supports_cas`]; a best-effort backend is exercised by the single-writer suite above.
    async fn cas_race_has_exactly_one_winner(store: Arc<dyn KvStore>) {
        if !store.supports_cas() {
            return;
        }
        store.put("race/k", b"start".to_vec()).await.unwrap();
        // 32 tasks all try to swap start→<their id>; a linearizable CAS admits exactly one.
        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let store = store.clone();
            set.spawn(async move {
                store
                    .compare_and_swap("race/k", Some(b"start"), i.to_le_bytes().to_vec())
                    .await
                    .unwrap()
            });
        }
        let mut wins = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one racing CAS wins");
    }

    #[tokio::test]
    async fn memorykv_cas_race_has_exactly_one_winner() {
        cas_race_has_exactly_one_winner(Arc::new(MemoryKv::new())).await;
    }

    #[tokio::test]
    async fn cachedkv_cas_race_has_exactly_one_winner() {
        cas_race_has_exactly_one_winner(Arc::new(CachedKv::new(Arc::new(MemoryKv::new()), 16)))
            .await;
    }

    #[tokio::test]
    async fn memorykv_satisfies_the_conformance_suite() {
        kv_conformance(&MemoryKv::new()).await;
    }

    #[tokio::test]
    async fn cachedkv_satisfies_the_conformance_suite() {
        // The caching layer must be semantically identical to its backing store on every op.
        let kv = CachedKv::new(Arc::new(MemoryKv::new()), 16);
        kv_conformance(&kv).await;
    }
}
