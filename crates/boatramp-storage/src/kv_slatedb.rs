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
        self.writer()?
            .put(key.as_bytes(), &value)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.writer()?
            .delete(key.as_bytes())
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

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_persists_then_reopens() {
        with_fresh_slatedb_dir("flush", |dir| async move {
            // A long flush interval so the periodic timer won't auto-persist; the
            // explicit `flush()` (SHUT-1) must be what makes the write durable.
            let kv = SlateKv::open_local_settings(
                &dir,
                test_settings(Some(std::time::Duration::from_secs(3600))),
            )
            .await
            .unwrap();
            kv.put("k", b"v".to_vec()).await.unwrap();
            kv.flush().await.unwrap(); // force durability now, not on the timer
            kv.close().await.unwrap();

            let reopened = SlateKv::open_local_settings(&dir, test_settings(None))
                .await
                .unwrap();
            assert_eq!(reopened.get("k").await.unwrap(), Some(b"v".to_vec()));
            reopened.close().await.unwrap();
        })
        .await;
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
}
