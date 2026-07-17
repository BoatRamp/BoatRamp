//! Shared-mode cache coherence: a **changelog** in the
//! shared KV store that lets independent processes invalidate just the keys a
//! peer changed, instead of flushing the world (which thunders the store) or
//! living on TTL desync.
//!
//! Only relevant to the **shared-store / no-consensus** topology — N stateless
//! processes over one shared store, each with its own [`CachedKv`] LRU. The Raft
//! topology needs none of this (replication keeps every node's applied state
//! current; `RaftKv` has no LRU). Single-process deployments don't either.
//!
//! Shape: on a control-plane write, [`Changelog::publish`] appends
//! one entry `_inval/{millis}-{writer}-{counter}` listing the changed keys. Each
//! process polls [`Changelog::poll`] for entries after its cursor, pops those
//! keys from its local cache, and advances the cursor; its own entries are
//! skipped. [`Changelog::trim`] drops old entries so the feed stays small, and a
//! periodic full flush (driven by the caller) is the gap backstop. The mechanism
//! is backend-agnostic — the feed is just KV data, so it works over Cloudflare
//! KV or a shared SlateDB equally (they are the `store` here).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::kv::{ChangePublisher, KvStore};

/// Reserved key prefix for changelog entries. Never a control-plane key, so the
/// feed and the data never collide. The poller scans this prefix.
pub const INVAL_PREFIX: &str = "_inval/";

/// One changelog entry: who wrote it and which keys changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    /// The writer that produced this entry (so a process skips its own).
    writer: String,
    /// The control-plane keys changed in this write/batch.
    keys: Vec<String>,
}

/// A changelog over a shared [`KvStore`]. Construct one per process; the
/// `writer` id is random so a process can skip its own entries when polling.
pub struct Changelog {
    /// The **shared** store (the uncached backend — Cloudflare KV / shared
    /// SlateDB), so peers see each other's entries.
    store: Arc<dyn KvStore>,
    /// This process's id (random hex), tagged into every entry it writes.
    writer: String,
    /// Per-process monotonic counter, to disambiguate entries within one millis.
    counter: AtomicU64,
    /// Drop feed entries older than this many seconds on [`trim`](Self::trim).
    retention_secs: u64,
}

impl Changelog {
    /// Build a changelog over `store`, keeping feed entries for `retention_secs`.
    /// Pick a retention comfortably larger than the poll interval so a poller
    /// can't miss entries between polls.
    pub fn new(store: Arc<dyn KvStore>, retention_secs: u64) -> Self {
        Self {
            store,
            writer: random_writer_id(),
            counter: AtomicU64::new(0),
            retention_secs: retention_secs.max(1),
        }
    }

    /// This process's writer id.
    pub fn writer_id(&self) -> &str {
        &self.writer
    }

    /// The largest existing entry key, or `""` if the feed is empty — the cursor
    /// a freshly-started poller should begin from (it has an empty cache, so it
    /// must not replay history).
    pub async fn current_cursor(&self) -> String {
        self.list_entry_keys()
            .await
            .into_iter()
            .max()
            .unwrap_or_default()
    }

    /// Append one entry recording that `keys` changed. Best-effort: a failure is
    /// logged, not propagated — the data write already succeeded, and the gap
    /// backstop (periodic full flush) bounds the worst case.
    pub async fn publish(&self, keys: &[String]) {
        // Don't record changes to the feed's own keyspace (defensive; the feed
        // is written here, never through a cache).
        let keys: Vec<String> = keys
            .iter()
            .filter(|k| !k.starts_with(INVAL_PREFIX))
            .cloned()
            .collect();
        if keys.is_empty() {
            return;
        }
        let entry = Entry {
            writer: self.writer.clone(),
            keys,
        };
        // Best-effort (per the doc): if serialization or the write fails, the
        // data write already succeeded and the periodic full-flush backstop
        // bounds the worst case, so we don't propagate. (core stays
        // tracing-free; the poller side, in the server, logs operationally.)
        if let Ok(value) = serde_json::to_vec(&entry) {
            let key = self.entry_key();
            let _ = self.store.put(&key, value).await;
        }
    }

    /// Read entries strictly after `*cursor`, returning the keys changed by
    /// **other** writers, and advance `*cursor` past everything seen. Order is
    /// irrelevant: popping is idempotent and the next read re-fetches the value.
    pub async fn poll(&self, cursor: &mut String) -> Vec<String> {
        let mut entry_keys: Vec<String> = self
            .list_entry_keys()
            .await
            .into_iter()
            .filter(|k| *k > *cursor)
            .collect();
        entry_keys.sort();
        let mut changed = Vec::new();
        for entry_key in &entry_keys {
            if let Ok(Some(bytes)) = self.store.get(entry_key).await {
                if let Ok(entry) = serde_json::from_slice::<Entry>(&bytes) {
                    if entry.writer != self.writer {
                        changed.extend(entry.keys);
                    }
                }
            }
        }
        if let Some(max) = entry_keys.into_iter().max() {
            *cursor = max;
        }
        changed
    }

    /// Delete feed entries older than the retention window. Run periodically
    /// (e.g. from the poller) so the feed — and thus each poll's scan — stays
    /// bounded regardless of how long the deployment runs.
    pub async fn trim(&self) {
        let cutoff = now_millis().saturating_sub(self.retention_secs * 1000);
        for key in self.list_entry_keys().await {
            if entry_millis(&key).is_some_and(|ms| ms < cutoff) {
                let _ = self.store.delete(&key).await;
            }
        }
    }

    async fn list_entry_keys(&self) -> Vec<String> {
        self.store
            .list_prefix(INVAL_PREFIX)
            .await
            .unwrap_or_default()
    }

    fn entry_key(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        // Zero-padded millis keep the keys lexicographically time-ordered.
        format!(
            "{INVAL_PREFIX}{:013}-{}-{:020}",
            now_millis(),
            self.writer,
            n
        )
    }
}

#[async_trait]
impl ChangePublisher for Changelog {
    async fn publish(&self, keys: &[String]) {
        Self::publish(self, keys).await;
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse the leading millis out of an entry key `_inval/{millis}-…`.
fn entry_millis(key: &str) -> Option<u64> {
    key.strip_prefix(INVAL_PREFIX)?
        .split('-')
        .next()?
        .parse()
        .ok()
}

fn random_writer_id() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("system RNG");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::{CachedKv, MemoryKv};

    /// Two processes (A and B) share one backing store; each fronts it with its
    /// own cache, and each cache publishes to a per-process changelog over the
    /// shared store. This is the shared-mode topology in miniature.
    #[tokio::test]
    async fn peer_write_invalidates_only_the_changed_key() {
        let shared: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        shared.put("site/a/config", b"v1".to_vec()).await.unwrap();
        shared.put("site/b/config", b"b1".to_vec()).await.unwrap();

        // Process A: cache + changelog over the shared store.
        let log_a = Arc::new(Changelog::new(shared.clone(), 60));
        let cache_a: Arc<dyn KvStore> =
            Arc::new(CachedKv::new(shared.clone(), 64).with_publisher(log_a.clone()));
        // Process B: its own changelog; we poll *B's* view of A's writes.
        let log_b = Arc::new(Changelog::new(shared.clone(), 60));
        let cache_b: Arc<dyn KvStore> =
            Arc::new(CachedKv::new(shared.clone(), 64).with_publisher(log_b.clone()));
        let mut cursor_b = log_b.current_cursor().await;

        // B warms both keys into its cache.
        assert_eq!(
            cache_b.get("site/a/config").await.unwrap(),
            Some(b"v1".to_vec())
        );
        assert_eq!(
            cache_b.get("site/b/config").await.unwrap(),
            Some(b"b1".to_vec())
        );

        // A updates one key — writes through to the shared store + publishes.
        cache_a.put("site/a/config", b"v2".to_vec()).await.unwrap();

        // Until B polls, its cache still serves the stale value.
        assert_eq!(
            cache_b.get("site/a/config").await.unwrap(),
            Some(b"v1".to_vec())
        );

        // B polls the changelog and pops just the changed key.
        let changed = log_b.poll(&mut cursor_b).await;
        assert_eq!(changed, vec!["site/a/config".to_string()]);
        cache_b.invalidate_keys(&changed);

        // Now B re-reads the fresh value for the changed key…
        assert_eq!(
            cache_b.get("site/a/config").await.unwrap(),
            Some(b"v2".to_vec())
        );
        // …and the *other* site stayed hot (not flushed) — still its cached value
        // even though the shared store is unchanged for it.
        assert_eq!(
            cache_b.get("site/b/config").await.unwrap(),
            Some(b"b1".to_vec())
        );
    }

    #[tokio::test]
    async fn poll_skips_own_writes() {
        let shared: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let log = Arc::new(Changelog::new(shared.clone(), 60));
        let cache: Arc<dyn KvStore> =
            Arc::new(CachedKv::new(shared.clone(), 64).with_publisher(log.clone()));
        let mut cursor = log.current_cursor().await;

        cache.put("k", b"v".to_vec()).await.unwrap();
        // A process never needs to invalidate its own writes (already cached).
        assert!(log.poll(&mut cursor).await.is_empty());
    }

    #[tokio::test]
    async fn batch_publishes_one_entry_with_all_keys() {
        let shared: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let writer = Arc::new(Changelog::new(shared.clone(), 60));
        let cache: Arc<dyn KvStore> =
            Arc::new(CachedKv::new(shared.clone(), 64).with_publisher(writer.clone()));
        // A reader changelog (distinct writer id) sees the writer's batch.
        let reader = Arc::new(Changelog::new(shared.clone(), 60));
        let mut cursor = reader.current_cursor().await;

        cache
            .write_batch(vec![
                crate::kv::WriteOp::Put("current/x".into(), b"id".to_vec()),
                crate::kv::WriteOp::Put("site/x/config".into(), b"c".to_vec()),
            ])
            .await
            .unwrap();

        let mut changed = reader.poll(&mut cursor).await;
        changed.sort();
        assert_eq!(
            changed,
            vec!["current/x".to_string(), "site/x/config".to_string()]
        );
        // Exactly one feed entry for the batch.
        assert_eq!(shared.list_prefix(INVAL_PREFIX).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn trim_drops_entries_outside_retention() {
        let shared: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        // Retention 0 → everything is "old" → trim clears the feed.
        let log = Changelog::new(shared.clone(), 1);
        log.publish(&["k".to_string()]).await;
        assert_eq!(shared.list_prefix(INVAL_PREFIX).await.unwrap().len(), 1);

        // A hand-inserted ancient entry is trimmed; a fresh one survives.
        shared
            .put(
                &format!("{INVAL_PREFIX}0000000000001-old-0"),
                b"{\"writer\":\"x\",\"keys\":[]}".to_vec(),
            )
            .await
            .unwrap();
        log.trim().await;
        let remaining = shared.list_prefix(INVAL_PREFIX).await.unwrap();
        assert!(
            remaining.iter().all(|k| !k.contains("-old-")),
            "ancient entry trimmed"
        );
    }
}
