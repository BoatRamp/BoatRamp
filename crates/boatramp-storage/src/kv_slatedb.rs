//! [`KvStore`] backed by [SlateDB](https://slatedb.io): a transactional LSM-tree
//! store whose storage layer is an `object_store` backend — local filesystem,
//! S3/R2, GCS, Azure, etc. The same KV runs over any of them, which suits
//! object-store deployments (and the clustering/Cloudflare direction).
//!
//! Durability is the object-store write completing (not a local fsync); writes
//! are object-store-latency-bound. SlateDB is single-writer (manifest fencing).
//!
//! ## Flush interval and the two roles boatramp gives SlateDB
//!
//! A `put` is acknowledged only after the next WAL flush, so a single awaited
//! write costs roughly one `flush_interval`. SlateDB's default (≈100 ms)
//! favours throughput: many concurrent writes coalesce into one flush. boatramp
//! uses SlateDB for two jobs with opposite needs:
//!
//! - **Control plane** (deploy manifests, the per-site "current" pointer):
//!   writes are few, serialized, and a human is waiting — so we open it with a
//!   *low* flush interval ([`SlateKv::open_local_with_flush`]) and group
//!   related writes into one [`KvStore::write_batch`] (a single SlateDB
//!   `WriteBatch` → one flush, all-or-nothing).
//! - **Handler `wasi:keyvalue`** store: request-driven, high-concurrency — it
//!   keeps the throughput-oriented default ([`SlateKv::open_local`]).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::kv::{KvError, KvStore, WriteOp};
use slatedb::object_store::local::LocalFileSystem;
use slatedb::object_store::ObjectStore;
use slatedb::{Db, DbReader, DbReaderBuilder, Settings, WriteBatch};

/// A SlateDB-backed key/value store — either the single **writer** or a
/// read-only **reader replica**. SlateDB is
/// single-writer (manifest fencing); the shared-store topology is therefore one
/// writer process plus read replicas that poll the manifest for new data. A
/// reader serves `get`/`list_prefix`; writes on it error (control-plane writes
/// go to the writer process, and the changelog keeps replicas' caches coherent).
#[derive(Clone)]
pub struct SlateKv {
    backend: Backend,
    /// Serializes [`compare_and_swap`](KvStore::compare_and_swap) within this writer process (B10):
    /// SlateDB has no read-conditional-write primitive, but it is single-writer (manifest fencing),
    /// so the only concurrent CAS racers are tasks in THIS process. Holding this async mutex across
    /// the get→compare→write makes the CAS linearizable within the writer — the property the
    /// async-lane shard claim needs. Cheap (contended only by the drain's claims, off the hot path).
    cas_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
enum Backend {
    Writer(Arc<Db>),
    Reader(Arc<DbReader>),
}

fn backend<E: std::fmt::Display>(err: E) -> KvError {
    KvError::backend(err.to_string())
}

/// SlateDB [`Settings`] with `flush_interval` overridden, everything else left
/// at its default.
fn settings_with_flush(flush_interval: Duration) -> Settings {
    Settings {
        flush_interval: Some(flush_interval),
        ..Settings::default()
    }
}

/// How to reach an S3-compatible object store (e.g. Cloudflare R2) for a
/// [`SlateKv::open_s3_with_flush`]. Credentials are read from the ambient AWS
/// environment, so only the addressing lives here.
#[derive(Debug, Clone)]
pub struct S3StoreConfig {
    /// The bucket the SlateDB store lives in.
    pub bucket: String,
    /// Custom endpoint (R2: `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: Option<String>,
    /// Region (R2 uses `auto`).
    pub region: Option<String>,
    /// Use path-style addressing (R2 accepts it).
    pub path_style: bool,
}

/// Build an `object_store` S3 backend from [`S3StoreConfig`] + ambient AWS
/// credentials. SlateDB fences its manifest with conditional puts, so the store
/// is built with ETag-based conditional put (which R2 supports).
fn build_s3_object_store(cfg: &S3StoreConfig) -> Result<Arc<dyn ObjectStore>, KvError> {
    use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
    let mut builder = AmazonS3Builder::from_env()
        .with_bucket_name(&cfg.bucket)
        .with_region(cfg.region.clone().unwrap_or_else(|| "auto".into()))
        .with_conditional_put(S3ConditionalPut::ETagMatch);
    if let Some(endpoint) = &cfg.endpoint {
        builder = builder.with_endpoint(endpoint);
    }
    if cfg.path_style {
        builder = builder.with_virtual_hosted_style_request(false);
    }
    Ok(Arc::new(builder.build().map_err(backend)?))
}

impl SlateKv {
    /// Open a store over an arbitrary `object_store` backend (rooted at `path`)
    /// using SlateDB's default settings — the throughput-oriented profile for
    /// the high-concurrency handler store.
    pub async fn open(store: Arc<dyn ObjectStore>, path: &str) -> Result<Self, KvError> {
        Self::open_with(store, path, Settings::default()).await
    }

    /// Open like [`SlateKv::open`] but with an explicit `flush_interval`. A low
    /// value (a few milliseconds) trades coalescing for the per-write latency
    /// the control plane wants.
    pub async fn open_with_flush(
        store: Arc<dyn ObjectStore>,
        path: &str,
        flush_interval: Duration,
    ) -> Result<Self, KvError> {
        Self::open_with(store, path, settings_with_flush(flush_interval)).await
    }

    /// Open a control-plane store over an S3-compatible object store (e.g.
    /// Cloudflare R2), rooted at the key prefix `path`, with the low
    /// control-plane flush interval. Credentials come from the ambient AWS
    /// environment (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), matching the
    /// S3 blob backend, so a container needs only R2 credentials — no Cloudflare
    /// token. SlateDB's single-writer manifest fencing suits the DO-singleton
    /// container; durable state then survives a scale-to-zero stop.
    pub async fn open_s3_with_flush(
        cfg: &S3StoreConfig,
        path: &str,
        flush_interval: Duration,
    ) -> Result<Self, KvError> {
        Self::open_with_flush(build_s3_object_store(cfg)?, path, flush_interval).await
    }

    async fn open_with(
        store: Arc<dyn ObjectStore>,
        path: &str,
        settings: Settings,
    ) -> Result<Self, KvError> {
        let db = Db::builder(path.to_string(), store)
            .with_settings(settings)
            .build()
            .await
            .map_err(backend)?;
        Ok(Self {
            backend: Backend::Writer(Arc::new(db)),
            cas_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Open a **read-only replica** over an `object_store` backend that some
    /// other process is the writer for. It serves
    /// reads from the committed manifest/L0 and polls for the writer's new data;
    /// writes error. Pair with the shared-mode changelog (`--shared-cache-
    /// coherence`) so a replica's config cache is invalidated on peer writes.
    pub async fn open_reader(store: Arc<dyn ObjectStore>, path: &str) -> Result<Self, KvError> {
        let reader = DbReaderBuilder::new(path.to_string(), store)
            .build()
            .await
            .map_err(backend)?;
        Ok(Self {
            backend: Backend::Reader(Arc::new(reader)),
            cas_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Open a read-only replica over a local directory (mainly for tests; real
    /// replicas share an object store with the writer).
    pub async fn open_local_reader(dir: impl AsRef<Path>) -> Result<Self, KvError> {
        let fs = LocalFileSystem::new_with_prefix(dir.as_ref()).map_err(backend)?;
        Self::open_reader(Arc::new(fs), "kv").await
    }

    /// Open a store over a local directory (an `object_store` `LocalFileSystem`)
    /// with SlateDB's default settings.
    pub async fn open_local(dir: impl AsRef<Path>) -> Result<Self, KvError> {
        Self::open_local_settings(dir, Settings::default()).await
    }

    /// Open a local-directory store with a low `flush_interval` for the
    /// latency-sensitive control plane.
    pub async fn open_local_with_flush(
        dir: impl AsRef<Path>,
        flush_interval: Duration,
    ) -> Result<Self, KvError> {
        Self::open_local_settings(dir, settings_with_flush(flush_interval)).await
    }

    async fn open_local_settings(
        dir: impl AsRef<Path>,
        settings: Settings,
    ) -> Result<Self, KvError> {
        std::fs::create_dir_all(&dir)?;
        let fs = LocalFileSystem::new_with_prefix(dir.as_ref()).map_err(backend)?;
        Self::open_with(Arc::new(fs), "kv", settings).await
    }

    /// Flush and cleanly close the database (call before dropping for
    /// durability). A no-op for a read replica.
    pub async fn close(&self) -> Result<(), KvError> {
        match &self.backend {
            Backend::Writer(db) => db.close().await.map_err(backend),
            Backend::Reader(_) => Ok(()),
        }
    }

    fn writer(&self) -> Result<&Db, KvError> {
        match &self.backend {
            Backend::Writer(db) => Ok(db),
            Backend::Reader(_) => Err(KvError::backend(
                "this SlateDB handle is a read-only replica; writes go to the writer process",
            )),
        }
    }
}

#[async_trait]
impl KvStore for SlateKv {
    async fn flush(&self) -> Result<(), KvError> {
        match &self.backend {
            // Force SlateDB's WAL/memtable to durable storage now (it otherwise
            // flushes on the configured timer), so a graceful shutdown loses no
            // committed writes. No-op for a read replica.
            Backend::Writer(db) => db.flush().await.map_err(backend),
            Backend::Reader(_) => Ok(()),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        let value = match &self.backend {
            Backend::Writer(db) => db.get(key.as_bytes()).await.map_err(backend)?,
            Backend::Reader(reader) => reader.get(key.as_bytes()).await.map_err(backend)?,
        };
        Ok(value.map(|bytes| bytes.to_vec()))
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        // slatedb 0.16: `put`/`write` return a `WriteHandle` after the in-memory WAL/memtable update
        // and are NOT durable until `await_durable()` (a semantics change from 0.13, where an awaited
        // put was durable). The control plane needs durable writes — a deploy manifest / current
        // pointer must survive a crash — so we await durability here, preserving 0.13's awaited-put
        // behavior. (`write_batch_relaxed` deliberately does NOT await, for the bus fast path.)
        self.writer()?
            .put(key.as_bytes(), &value)
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.writer()?
            .delete(key.as_bytes())
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        // Scan the ordered keyspace from the prefix and stop once keys no longer
        // share it. Both writer and reader expose the same `scan`/`DbIterator`.
        let mut iter = match &self.backend {
            Backend::Writer(db) => db
                .scan(prefix.as_bytes().to_vec()..)
                .await
                .map_err(backend)?,
            Backend::Reader(reader) => reader
                .scan(prefix.as_bytes().to_vec()..)
                .await
                .map_err(backend)?,
        };
        let mut out = Vec::new();
        while let Some(kv) = iter.next().await.map_err(backend)? {
            let key = String::from_utf8_lossy(kv.key.as_ref());
            if !key.starts_with(prefix) {
                break;
            }
            out.push(key.into_owned());
        }
        Ok(out)
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        // Seek straight to the cursor in the ordered keyspace and walk forward,
        // capped at `limit` — O(limit), not O(keys-under-prefix) like the default.
        let start = format!("{prefix}{after}").into_bytes();
        let range = (
            std::ops::Bound::Excluded(start),
            std::ops::Bound::<Vec<u8>>::Unbounded,
        );
        let mut iter = match &self.backend {
            Backend::Writer(db) => db.scan(range).await.map_err(backend)?,
            Backend::Reader(reader) => reader.scan(range).await.map_err(backend)?,
        };
        let mut out = Vec::new();
        while out.len() < limit {
            let Some(kv) = iter.next().await.map_err(backend)? else {
                break;
            };
            let key = String::from_utf8_lossy(kv.key.as_ref());
            if !key.starts_with(prefix) {
                break;
            }
            out.push(key.into_owned());
        }
        Ok(out)
    }

    fn atomic_write_batch(&self) -> bool {
        // One SlateDB `WriteBatch` = a single atomic, durable commit (below), so the ready-set
        // fast path (B2) is safe over SlateKv: the ready marker rides the same batch as the index.
        true
    }

    fn supports_cas(&self) -> bool {
        // SlateDB is single-writer (manifest fencing), and the CAS below holds `cas_lock` across the
        // get→compare→write — so it is linearizable within this writer process (the only place a CAS
        // racer can be). Safe for the async-lane shard claim (B10) on a single-node SlateDB deploy.
        matches!(self.backend, Backend::Writer(_))
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        value: Vec<u8>,
    ) -> Result<bool, KvError> {
        // Hold the process-local CAS lock across read→compare→write so no other task in THIS writer
        // interleaves. SlateDB is single-writer, so no other process writes this store — making this
        // a linearizable compare-and-set. A durable `put` (awaited flush) commits the swap.
        let _guard = self.cas_lock.lock().await;
        let db = self.writer()?;
        let current = db.get(key.as_bytes()).await.map_err(backend)?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        // Durable put (slatedb 0.16 await_durable, as in `put` above): the CAS swap must survive a crash.
        db.put(key.as_bytes(), &value)
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        Ok(true)
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Collect the whole group into one SlateDB WriteBatch: a single atomic,
        // durable commit (one flush) rather than one per key.
        let mut batch = WriteBatch::new();
        for op in ops {
            match op {
                WriteOp::Put(key, value) => batch.put(key.as_bytes(), &value),
                WriteOp::Delete(key) => batch.delete(key.as_bytes()),
            }
        }
        self.writer()?
            .write(batch)
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        Ok(())
    }

    /// Durability-relaxed grouped write (see [`KvStore::write_batch_relaxed`]): commit the group to
    /// the in-memory memtable/WAL buffer and return WITHOUT awaiting the object-store flush (SlateDB
    /// `WriteOptions { await_durable: false }`). The buffered entries are flushed on the store's
    /// configured `flush_interval` — OR sooner when a later durable [`write_batch`](Self::write_batch)
    /// (the messaging checkpoint) forces the WAL buffer out. The batch is still atomic; only the
    /// *ack timing* changes. On a process crash before the next flush, entries acked here are lost —
    /// which is why only the bus publish path may call it, bounded to N un-durable messages by the
    /// caller's checkpoint (see `LogMessaging`).
    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        let mut batch = WriteBatch::new();
        for op in ops {
            match op {
                WriteOp::Put(key, value) => batch.put(key.as_bytes(), &value),
                WriteOp::Delete(key) => batch.delete(key.as_bytes()),
            }
        }
        // slatedb 0.16: `write` returns after the in-memory WAL/memtable update and is durable only
        // once `await_durable()` is called on the handle. We deliberately DROP the handle without
        // awaiting it — the relaxed (non-durable) semantics the bus fast path wants (equivalent to
        // 0.13's `WriteOptions { await_durable: false }`). The entries flush on the store's
        // `flush_interval` or when a later durable `write_batch` forces the WAL buffer out.
        self.writer()?.write(batch).await.map_err(backend)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SlateDB settings for tests: the background **compactor and GC tasks are
    /// disabled** (`None`), so `close()` has nothing to drain. Those two task
    /// shutdowns — `close()` awaits `shutdown_task(COMPACTOR)` then
    /// `shutdown_task(GC)` — were the source of the intermittent close/reopen
    /// stall on a loaded CI host. The durability path these tests exercise (WAL
    /// flush → L0 → reopen) is unaffected; production keeps both enabled (it
    /// wants compaction + space reclamation over the store's lifetime).
    ///
    /// `flush_interval: None` keeps SlateDB's default flush timer (mirrors
    /// [`SlateKv::open_local`]); `Some(d)` overrides it (mirrors
    /// [`SlateKv::open_local_with_flush`]).
    fn test_settings(flush_interval: Option<Duration>) -> Settings {
        let mut settings = Settings::default();
        if let Some(interval) = flush_interval {
            settings.flush_interval = Some(interval);
        }
        settings.compactor_options = None;
        settings.garbage_collector_options = None;
        settings
    }

    /// Run a SlateDB test `body` under a timeout guard, retrying on a **fresh**
    /// directory. With the background compactor + GC disabled ([`test_settings`])
    /// the close/reopen stall this used to paper over is gone, so this is now a
    /// cheap backstop only: `#[serial]` (below) removes intra-binary concurrency,
    /// and should any future hang appear it fails **fast** (≈100s) rather than
    /// stalling the job for hours.
    async fn with_fresh_slatedb_dir<F, Fut>(name: &str, body: F)
    where
        F: Fn(std::path::PathBuf) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        for attempt in 0..4u32 {
            let dir = std::env::temp_dir().join(format!(
                "boatramp-slatedb-{name}-{}-{attempt}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            match tokio::time::timeout(std::time::Duration::from_secs(25), body(dir.clone())).await
            {
                Ok(()) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return;
                }
                Err(_) => eprintln!(
                    "slatedb test `{name}` attempt {attempt} exceeded 25s (SlateDB \
                     close/reopen stalled); retrying on a fresh dir"
                ),
            }
        }
        panic!("slatedb test `{name}` stalled on every attempt");
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn slatedb_round_trips() {
        with_fresh_slatedb_dir("roundtrip", |dir| async move {
            let kv = SlateKv::open_local_settings(&dir, test_settings(None))
                .await
                .unwrap();

            kv.put("alias/blog/staging", b"id-1".to_vec())
                .await
                .unwrap();
            kv.put("alias/blog/prod", b"id-2".to_vec()).await.unwrap();
            kv.put("other/x", b"z".to_vec()).await.unwrap();
            assert_eq!(
                kv.get("alias/blog/staging").await.unwrap(),
                Some(b"id-1".to_vec())
            );
            assert_eq!(kv.get("missing").await.unwrap(), None);

            let mut keys = kv.list_prefix("alias/blog/").await.unwrap();
            keys.sort();
            assert_eq!(keys, vec!["alias/blog/prod", "alias/blog/staging"]);

            // Native bounded range scan: ordered, cursor-exclusive, limited, and
            // it never leaks the `other/x` key that sorts just past the prefix.
            assert_eq!(
                kv.list_from("alias/blog/", "", 10).await.unwrap(),
                vec!["alias/blog/prod", "alias/blog/staging"],
            );
            assert_eq!(
                kv.list_from("alias/blog/", "", 1).await.unwrap(),
                vec!["alias/blog/prod"],
                "limit caps the batch",
            );
            assert_eq!(
                kv.list_from("alias/blog/", "prod", 10).await.unwrap(),
                vec!["alias/blog/staging"],
                "resumes strictly after the cursor",
            );
            assert_eq!(
                kv.list_from("alias/blog/", "staging", 10).await.unwrap(),
                Vec::<String>::new(),
                "past the last key → empty (no other-prefix leak)",
            );

            kv.delete("alias/blog/staging").await.unwrap();
            assert_eq!(kv.get("alias/blog/staging").await.unwrap(), None);

            kv.close().await.unwrap();
        })
        .await;
    }

    /// SlateKv's compare-and-swap (B10): the single-writer `cas_lock` makes it a linearizable CAS
    /// within the writer process — expected-absent create, exact-bytes match, stale-expected refusal,
    /// and a concurrent-racer set with exactly one winner (the property the async-lane claim needs).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn slatedb_compare_and_swap_is_linearizable() {
        with_fresh_slatedb_dir("cas", |dir| async move {
            let kv = Arc::new(
                SlateKv::open_local_settings(&dir, test_settings(None))
                    .await
                    .unwrap(),
            );
            assert!(
                kv.supports_cas(),
                "the writer advertises a linearizable CAS"
            );

            // Expected-absent creates; expected-absent on a present key does not swap.
            assert!(kv
                .compare_and_swap("inv/1", None, b"queued".to_vec())
                .await
                .unwrap());
            assert_eq!(kv.get("inv/1").await.unwrap(), Some(b"queued".to_vec()));
            assert!(!kv
                .compare_and_swap("inv/1", None, b"x".to_vec())
                .await
                .unwrap());
            // A stale expected does not swap; the exact prior bytes do.
            assert!(!kv
                .compare_and_swap("inv/1", Some(b"WRONG"), b"x".to_vec())
                .await
                .unwrap());
            assert_eq!(kv.get("inv/1").await.unwrap(), Some(b"queued".to_vec()));
            assert!(kv
                .compare_and_swap("inv/1", Some(b"queued"), b"running".to_vec())
                .await
                .unwrap());
            assert_eq!(kv.get("inv/1").await.unwrap(), Some(b"running".to_vec()));

            // Race: many tasks in this single writer process try queued→<id>; exactly one wins.
            kv.put("inv/2", b"queued".to_vec()).await.unwrap();
            let mut set = tokio::task::JoinSet::new();
            for i in 0..16u32 {
                let kv = kv.clone();
                set.spawn(async move {
                    kv.compare_and_swap("inv/2", Some(b"queued"), i.to_le_bytes().to_vec())
                        .await
                        .unwrap()
                });
            }
            let mut wins = 0;
            while let Some(r) = set.join_next().await {
                if r.unwrap() {
                    wins += 1;
                }
            }
            assert_eq!(
                wins, 1,
                "exactly one racing CAS wins on the single-writer store"
            );

            Arc::try_unwrap(kv).ok().unwrap().close().await.unwrap();
        })
        .await;
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_persists_then_reopens() {
        // Durability is a property of the object store, not the local disk: SlateDB
        // writes the WAL / L0 SSTs / manifest to the `ObjectStore`, and a reopen replays
        // them from it. So this exercises the exact flush → close (memtable → L0) →
        // reopen-replay path against a **shared in-memory** store (the same instance for
        // both opens, so the reopen reads exactly what close persisted) — with ZERO disk
        // I/O. That removes this test's historical flake: `close()` flushes memtables to
        // L0 and the reopen replays, and on the contended shared musl CI runner that
        // real `LocalFileSystem` I/O occasionally stalled past the timeout (it was the
        // only test that reopened). In-memory it is deterministic and needs no timeout
        // harness. `slatedb_round_trips` keeps the on-disk `LocalFileSystem` path.
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        // A low flush interval (slatedb 0.16: a durable `put` awaits `await_durable()`, which waits for
        // the timer-driven WAL flush — so a long interval would hang; 5 ms keeps the awaited write fast,
        // matching the production control-plane store). Then an explicit `flush()`, close (memtable →
        // L0), and reopen-replay — the durability + reopen contract this test exists to exercise.
        let kv = SlateKv::open_with(
            store.clone(),
            "kv",
            test_settings(Some(std::time::Duration::from_millis(5))),
        )
        .await
        .unwrap();
        kv.put("k", b"v".to_vec()).await.unwrap(); // durable (awaits durability before returning)
        kv.flush().await.unwrap(); // exercise the explicit flush() path too
        kv.close().await.unwrap();

        let reopened = SlateKv::open_with(store.clone(), "kv", test_settings(None))
            .await
            .unwrap();
        assert_eq!(reopened.get("k").await.unwrap(), Some(b"v".to_vec()));
        reopened.close().await.unwrap();
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn read_replica_sees_writer_and_refuses_writes() {
        with_fresh_slatedb_dir("replica", |dir| async move {
            // The writer process commits config, then flushes/closes so the manifest
            // reflects it (a real replica polls the manifest; here we close to make
            // the committed state visible to a freshly-opened reader).
            let writer =
                SlateKv::open_local_settings(&dir, test_settings(Some(Duration::from_millis(5))))
                    .await
                    .unwrap();
            writer.put("site/blog", b"hash-1".to_vec()).await.unwrap();
            writer
                .write_batch(vec![
                    WriteOp::Put("siteconfig/hash-1".into(), b"{}".to_vec()),
                    WriteOp::Put("current/blog".into(), b"dep-1".to_vec()),
                ])
                .await
                .unwrap();
            writer.close().await.unwrap();

            // A read replica over the same store serves the writer's data…
            let replica = SlateKv::open_local_reader(&dir).await.unwrap();
            assert_eq!(
                replica.get("site/blog").await.unwrap(),
                Some(b"hash-1".to_vec())
            );
            let mut keys = replica.list_prefix("siteconfig/").await.unwrap();
            keys.sort();
            assert_eq!(keys, vec!["siteconfig/hash-1"]);

            // …and refuses writes (control-plane writes go to the writer process).
            assert!(replica.put("x", b"y".to_vec()).await.is_err());
            assert!(replica
                .write_batch(vec![WriteOp::Delete("site/blog".into())])
                .await
                .is_err());
        })
        .await;
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn slatedb_write_batch_commits_group() {
        with_fresh_slatedb_dir("batch", |dir| async move {
            let kv =
                SlateKv::open_local_settings(&dir, test_settings(Some(Duration::from_millis(5))))
                    .await
                    .unwrap();

            kv.put("manifests/dep-1", b"old".to_vec()).await.unwrap();
            kv.write_batch(vec![
                WriteOp::Put("manifests/dep-2".into(), b"new".to_vec()),
                WriteOp::Put("current/blog".into(), b"dep-2".to_vec()),
                WriteOp::Delete("manifests/dep-1".into()),
            ])
            .await
            .unwrap();

            assert_eq!(
                kv.get("manifests/dep-2").await.unwrap(),
                Some(b"new".to_vec())
            );
            assert_eq!(
                kv.get("current/blog").await.unwrap(),
                Some(b"dep-2".to_vec())
            );
            assert_eq!(kv.get("manifests/dep-1").await.unwrap(), None);

            kv.close().await.unwrap();
        })
        .await;
    }

    /// Incident regression (v0.5.5 — the `slatedb` 0.13.1 → 0.16.0 upgrade): a control-plane store whose
    /// **tail WAL object was frozen at 0 bytes** — a crash, or a crash-consistent fly volume snapshot of
    /// a *live* store, freezing a just-opened WAL object before its data blocks reached the device — must
    /// still **open**, skipping only that never-durable empty tail, instead of failing fatally with
    /// `Data error: empty SSTable` on *every* cold open (the production-down incident). Every committed
    /// key (projects/sites/**sealed secrets**) must survive. SlateDB 0.16 tolerates it natively (an
    /// object ≤ the SST footer is a fence marker with zero committed entries, so replay skips it); 0.13.1
    /// (as v0.5.4 shipped) did NOT — this test fails against 0.13.1 and passes on 0.16.
    ///
    /// Setup uses `test_settings` (compactor + GC OFF) so the WAL objects linger on disk after close,
    /// letting us inject a realistic empty tail object at `max_id + 1`. The injected object is > the
    /// manifest's `replay_after_wal_id`, so it lands in the reopen's WAL replay range — exactly where a
    /// frozen tail object sits. The reopen therefore reads the empty object during replay; only the
    /// upstream tolerance makes it non-fatal.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen stalls under the static-musl test harness (see test-orm-tenancy); \
                the CI `test (slatedb WAL recovery)` job runs it unignored on the host toolchain"]
    async fn empty_tail_wal_object_is_tolerated_and_data_survives() {
        with_fresh_slatedb_dir("emptytail", |dir| async move {
            // 1. A few durable control-plane writes, then a clean flush + close.
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.write_batch(vec![
                    WriteOp::Put("project/acme".into(), b"seed".to_vec()),
                    WriteOp::Put("secret/acme/idp".into(), b"sealed".to_vec()),
                ])
                .await
                .unwrap();
                kv.put("current/console", b"deploy-7".to_vec())
                    .await
                    .unwrap();
                kv.flush().await.unwrap();
                kv.close().await.unwrap();
            }

            // 2. Inject the frozen tail: a 0-byte WAL object at (highest existing WAL id) + 1.
            let wal_dir = dir.join("kv").join("wal");
            let mut ids: Vec<u64> = std::fs::read_dir(&wal_dir)
                .expect("wal/ dir should exist after writes")
                .filter_map(Result::ok)
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<u64>().ok())
                })
                .collect();
            ids.sort_unstable();
            let max_id = *ids
                .last()
                .expect("expected WAL objects on disk (compactor/GC are off in test_settings)");
            let empty = wal_dir.join(format!("{:020}.sst", max_id + 1));
            std::fs::write(&empty, b"").unwrap();
            assert_eq!(
                std::fs::metadata(&empty).unwrap().len(),
                0,
                "the injected tail WAL object must be 0 bytes"
            );

            // 3. Reopen: the empty tail is tolerated and every committed key survives.
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .expect(
                    "EMPTY WAL TAIL: reopen must tolerate the frozen 0-byte tail WAL object, not \
                     fail with `empty SSTable`",
                );
                assert_eq!(
                    kv.get("current/console").await.unwrap(),
                    Some(b"deploy-7".to_vec())
                );
                assert_eq!(
                    kv.get("project/acme").await.unwrap(),
                    Some(b"seed".to_vec())
                );
                assert_eq!(
                    kv.get("secret/acme/idp").await.unwrap(),
                    Some(b"sealed".to_vec()),
                    "the sealed secret must survive the recovery"
                );
                kv.close().await.unwrap();
            }
            eprintln!("EMPTY WAL TAIL RECOVERED OK");
        })
        .await;
    }

    /// **Live** (ignored): open a control-plane SlateKv over Cloudflare R2, write,
    /// then close and reopen a fresh handle over the same R2 path and confirm the
    /// data survived — the durability contract a scale-to-zero container relies
    /// on. Needs `BR_R2_TEST_BUCKET` + `BR_R2_TEST_ENDPOINT` and ambient
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
    #[tokio::test]
    #[ignore = "needs live R2 credentials (BR_R2_TEST_BUCKET/ENDPOINT + AWS creds)"]
    async fn slatedb_over_r2_survives_reopen() {
        let Ok(bucket) = std::env::var("BR_R2_TEST_BUCKET") else {
            eprintln!("skipping: BR_R2_TEST_BUCKET not set");
            return;
        };
        let cfg = S3StoreConfig {
            bucket,
            endpoint: std::env::var("BR_R2_TEST_ENDPOINT").ok(),
            region: std::env::var("BR_R2_TEST_REGION").ok(),
            path_style: true,
        };
        let path = "boatramp-kv-livetest";
        let flush = Duration::from_millis(5);
        {
            let kv = SlateKv::open_s3_with_flush(&cfg, path, flush)
                .await
                .unwrap();
            kv.put("current/site", b"deploy-42".to_vec()).await.unwrap();
            assert_eq!(
                kv.get("current/site").await.unwrap(),
                Some(b"deploy-42".to_vec())
            );
            kv.close().await.unwrap();
        }
        // A fresh handle over the same R2 path must observe the persisted write.
        let kv = SlateKv::open_s3_with_flush(&cfg, path, flush)
            .await
            .unwrap();
        assert_eq!(
            kv.get("current/site").await.unwrap(),
            Some(b"deploy-42".to_vec())
        );
        kv.close().await.unwrap();
    }
}
