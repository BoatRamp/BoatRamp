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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::kv::{ChangePublisher, KvError, KvStore};
use crate::time::now_unix_ms;

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
    ///
    /// Best-effort: a store error is swallowed (empty result, cursor unchanged) so a transient
    /// blip never crashes the poller. The shared-mode poller uses [`poll_checked`](Self::poll_checked)
    /// instead, because it MUST distinguish a genuinely-empty poll from an unreachable store (the
    /// latter trips the MF-3 [`AuthzFence`]).
    pub async fn poll(&self, cursor: &mut String) -> Vec<String> {
        self.poll_checked(cursor).await.unwrap_or_default()
    }

    /// Like [`poll`](Self::poll), but PROPAGATES a store error instead of swallowing it — so the
    /// shared-mode cache poller can tell a successful (possibly empty) poll from an unreachable
    /// store. The MF-3 fence turns on that distinction: a poll that cannot reach the store leaves
    /// the node unable to confirm currency, so it must stop trusting the cached authz keyspace
    /// (trip the [`AuthzFence`]) rather than silently treat "no entries" as "nothing changed".
    pub async fn poll_checked(&self, cursor: &mut String) -> Result<Vec<String>, KvError> {
        let mut entry_keys: Vec<String> = self
            .store
            .list_prefix(INVAL_PREFIX)
            .await?
            .into_iter()
            .filter(|k| *k > *cursor)
            .collect();
        entry_keys.sort();
        let mut changed = Vec::new();
        for entry_key in &entry_keys {
            if let Ok(Some(bytes)) = self.store.get(entry_key).await
                && let Ok(entry) = serde_json::from_slice::<Entry>(&bytes)
                && entry.writer != self.writer
            {
                changed.extend(entry.keys);
            }
        }
        if let Some(max) = entry_keys.into_iter().max() {
            *cursor = max;
        }
        Ok(changed)
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

/// The MF-3 **stale-authz fence** — the cross-node correctness FLOOR (NO-SHIP must-fix for
/// multi-writer `shared` mode) that bounds how long a node will serve the *cached* authz keyspace
/// (`authz/policy` and the GraphQL registry — the authz state that is a cached `Some` value, hence
/// stale-vulnerable) without re-confirming it against the authoritative store.
///
/// ## Why it exists, and why it is INDEPENDENT of NOTIFY
/// Cross-node invalidation in `shared` mode is best-effort: the [`Changelog`]/`_inval` NOTIFY feed
/// (and its 1s poll) is the *fast path*, but a NOTIFY can be MISSED on a dropped connection, and the
/// old 300s full-flush backstop meant a dropped invalidation could let a node honor a *revoked grant
/// / loosened policy* for up to five minutes. The fence replaces that 300s backstop **for the
/// authz/crown-jewel keyspace only** with a small bound `T`: a node may serve the cached authz state
/// only while it has CONFIRMED (within `T`) that the cache is current; otherwise it must force a
/// read-through of the authz keyspace, and if the store is unreachable it SHEDS (deny / 503) rather
/// than serve stale. The fence does NOT consult the (suppressible) NOTIFY feed to decide currency —
/// it is a hard max-age on cache trust, so a *silently dropped* invalidation is bounded to `T`.
///
/// ## Lifecycle (who stamps it)
/// - Constructed **tripped** (`confirmed_until = 0`): a fresh node never trusts the authz cache until
///   it has positively revalidated once (fail-safe default).
/// - [`confirm`](Self::confirm) is called by the authorizer after a SUCCESSFUL read-through of the
///   authz keyspace against the authoritative (uncached) store — the only thing that can vouch for
///   currency independent of the best-effort feed. It extends trust for `T`.
/// - [`trip`](Self::trip) is called by the cache poller when a poll CANNOT reach the store (a
///   [`poll_checked`](Changelog::poll_checked) error): the node can no longer confirm currency, so it
///   drops cache trust at once (shed sooner, rather than wait out the `T` max-age).
///
/// The key embeds `millis` ([`Changelog::current_cursor`]), so [`lag_ms`](Self::lag_ms) exposes the
/// staleness beyond the fence for `kv-status` / metrics (UX-C6). The fence is pure, lock-free state
/// (an atomic deadline) shared by `Arc` between the poller and the authorizer; it holds no store
/// handle and no authz knowledge, so it works identically over `MemoryKv` (tests) and a real
/// multi-writer `SqlKv`. It is built ONLY in `shared` (multi-writer) mode; single-writer / Raft
/// deployments never construct one and their authz path is UNCHANGED.
pub struct AuthzFence {
    /// Wall-clock millis until which the cached authz keyspace may be trusted. `0` ⇒ tripped (force
    /// read-through). Set to `now + bound` by [`confirm`](Self::confirm) on a successful revalidation.
    confirmed_until_ms: AtomicU64,
    /// The bound `T` in millis — how long one confirmation vouches for the cache.
    bound_ms: u64,
}

impl AuthzFence {
    /// Build a fence with cache-trust bound `T`. Starts **tripped** (not current) — a node must
    /// revalidate the authz keyspace once before it will serve it from cache. `bound` is clamped to
    /// ≥ 1ms so a misconfigured zero still behaves (every read then reads through).
    pub fn new(bound: Duration) -> Self {
        Self {
            confirmed_until_ms: AtomicU64::new(0),
            bound_ms: (bound.as_millis() as u64).max(1),
        }
    }

    /// The configured cache-trust bound `T`.
    pub fn bound(&self) -> Duration {
        Duration::from_millis(self.bound_ms)
    }

    /// Whether the cached authz keyspace may be trusted RIGHT NOW — i.e. a confirmation is still
    /// within its `T` window. Cheap, lock-free; callable from the authorize hot path.
    pub fn is_current(&self) -> bool {
        now_unix_ms() < self.confirmed_until_ms.load(Ordering::Acquire)
    }

    /// Record a successful revalidation of the authz keyspace against the authoritative store:
    /// the cache may now be trusted for another `T`. Called by the authorizer after a read-through
    /// `Ok`.
    pub fn confirm(&self) {
        self.confirmed_until_ms.store(
            now_unix_ms().saturating_add(self.bound_ms),
            Ordering::Release,
        );
    }

    /// Drop cache trust immediately (force read-through on the next authz read). Called by the
    /// poller when it cannot reach the store, so a partitioned node stops trusting the cached authz
    /// state at once instead of waiting out the `T` max-age.
    pub fn trip(&self) {
        self.confirmed_until_ms.store(0, Ordering::Release);
    }

    /// Millis elapsed PAST the fence deadline — the authz-cache staleness beyond `T`, for
    /// `kv-status.staleness` / the `kv_coherence_lag_seconds` metric (UX-C6). `0` while the fence is
    /// current OR freshly tripped-with-no-prior-confirm (use [`is_current`](Self::is_current) to tell
    /// "current" from "tripped"); a positive value is "stale by this long past `T`".
    pub fn lag_ms(&self) -> u64 {
        let until = self.confirmed_until_ms.load(Ordering::Acquire);
        let now = now_unix_ms();
        if until == 0 || now < until {
            0
        } else {
            now - until
        }
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

    /// The MF-3 fence: starts tripped (a fresh node never trusts the authz cache), `confirm` makes
    /// it current for the bound, and `trip` drops trust at once.
    #[tokio::test]
    async fn authz_fence_confirm_and_trip() {
        let fence = AuthzFence::new(Duration::from_secs(30));
        assert!(
            !fence.is_current(),
            "a fresh fence is tripped — no cache trust until revalidated"
        );
        fence.confirm();
        assert!(
            fence.is_current(),
            "a confirmation grants trust for the bound"
        );
        assert_eq!(fence.lag_ms(), 0, "current ⇒ no lag");
        fence.trip();
        assert!(
            !fence.is_current(),
            "trip drops trust immediately (poll could not reach the store)"
        );
    }

    /// A zero bound is clamped to ≥ 1ms so a misconfigured zero never panics (the fence just lapses
    /// almost immediately, forcing a read-through on the next authz read).
    #[tokio::test]
    async fn authz_fence_zero_bound_is_clamped() {
        let fence = AuthzFence::new(Duration::ZERO);
        assert_eq!(
            fence.bound(),
            Duration::from_millis(1),
            "zero bound clamps to 1ms"
        );
    }

    /// MF-6 (custody) — the NOTIFY / changelog payload carries the changed KEY ONLY, never any value
    /// bytes. A secret write announces the key name; the entry serialized to the shared feed must
    /// contain the key but NONE of the (sealed) value bytes. RED if the feed ever starts carrying
    /// values.
    #[tokio::test]
    async fn change_log_payload_carries_no_value_bytes() {
        let shared: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let log = Arc::new(Changelog::new(shared.clone(), 60));
        let cache: Arc<dyn KvStore> =
            Arc::new(CachedKv::new(shared.clone(), 64).with_publisher(log.clone()));

        // A "sealed secret" write: a distinctive value that must NOT appear in the feed.
        let sealed_value = b"SEALED-SECRET-CIPHERTEXT-0xDEADBEEF".to_vec();
        cache
            .put("secret/default/api-key", sealed_value.clone())
            .await
            .unwrap();

        // The one feed entry the write published.
        let entry_keys = shared.list_prefix(INVAL_PREFIX).await.unwrap();
        assert_eq!(entry_keys.len(), 1, "one feed entry for the write");
        let raw = shared.get(&entry_keys[0]).await.unwrap().unwrap();

        // The payload names the key…
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(
            text.contains("secret/default/api-key"),
            "the payload carries the changed key"
        );
        // …and carries NONE of the value bytes (key + version only — custody MF-6).
        assert!(
            !contains_subslice(&raw, &sealed_value),
            "the change-log/NOTIFY payload must NEVER carry value bytes"
        );
        // The parsed entry has exactly the key, no value field.
        let entry: Entry = serde_json::from_slice(&raw).unwrap();
        assert_eq!(entry.keys, vec!["secret/default/api-key".to_string()]);
    }

    /// Whether `haystack` contains `needle` as a contiguous byte subslice (test helper for the
    /// no-value-bytes custody assertion).
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
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
