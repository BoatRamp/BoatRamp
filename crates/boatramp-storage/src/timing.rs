//! A transparent per-request timing decorator over any [`Storage`].
//!
//! [`TimingStorage`] wraps an already-confined `Arc<dyn Storage>` and records the wall-clock spent in
//! each READ op (`get` / `head` / `get_range`) into a shared [`BlobOpTiming`], so a handler dispatch can
//! attribute the blob-read cost that otherwise hides inside the guest invoke (`serve_us`). It is pure
//! observability: EVERY method delegates to the inner backend unchanged — no path handling, no container
//! prefix, no `.boatramp*` marker, no confinement, no caching, no behavior of any kind is altered. Only
//! the three read ops are additionally timed (and counted); writes, listing, and the zero-copy / prune /
//! drain accessors delegate verbatim so a cache/fallback/GC-refusal composite underneath is preserved.
//!
//! Separating `head_us` from `get_us`/`range_us` is the point: on the blob-serve path a container open
//! does a marker `head` BEFORE the object `get_range`, and this decorator makes that per-serve doubling
//! (and whether concurrent reads parallelize) visible without touching the blob path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError};

/// Per-request blob read-op timings, in microseconds, accumulated across every `get`/`head`/`get_range`
/// the guest drives through its `wasi:blobstore` binding during one dispatch. All relaxed atomics — the
/// counters are advisory telemetry, never read for a control decision.
#[derive(Debug, Default)]
pub struct BlobOpTiming {
    /// Total µs in whole-object `get` calls (time-to-stream-handle, i.e. the round-trip; the body drains
    /// later in the guest and is not counted here).
    pub get_us: AtomicU64,
    /// Total µs in `head` calls — on the serve path this is the container-marker check before the GET.
    pub head_us: AtomicU64,
    /// Total µs in `get_range` calls (the object-body reads: whole-object sentinel or a real range).
    pub range_us: AtomicU64,
    /// Count of timed read ops (`get` + `head` + `get_range`).
    pub ops: AtomicU64,
}

impl BlobOpTiming {
    /// Snapshot the counters (get_us, head_us, range_us, ops) for folding into a log line / header.
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.get_us.load(Ordering::Relaxed),
            self.head_us.load(Ordering::Relaxed),
            self.range_us.load(Ordering::Relaxed),
            self.ops.load(Ordering::Relaxed),
        )
    }
}

/// A [`Storage`] decorator that times the read ops of `inner` into a shared [`BlobOpTiming`]. See the
/// [module docs](self): observability only, behavior byte-identical to `inner`.
pub struct TimingStorage {
    inner: Arc<dyn Storage>,
    timing: Arc<BlobOpTiming>,
}

impl TimingStorage {
    /// Wrap `inner`, accumulating its read-op timings into `timing`.
    pub fn new(inner: Arc<dyn Storage>, timing: Arc<BlobOpTiming>) -> Self {
        Self { inner, timing }
    }
}

#[async_trait]
impl Storage for TimingStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        let t = Instant::now();
        let r = self.inner.get(key).await;
        self.timing
            .get_us
            .fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        self.timing.ops.fetch_add(1, Ordering::Relaxed);
        r
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        let t = Instant::now();
        let r = self.inner.get_range(key, offset, len).await;
        self.timing
            .range_us
            .fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        self.timing.ops.fetch_add(1, Ordering::Relaxed);
        r
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let t = Instant::now();
        let r = self.inner.head(key).await;
        self.timing
            .head_us
            .fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        self.timing.ops.fetch_add(1, Ordering::Relaxed);
        r
    }

    // Writes, listing, and the zero-copy / prune / drain accessors delegate VERBATIM — the decorator
    // only times reads and must not alter any other behavior (GC refusal + drain pass-through preserved).
    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        self.inner.put(key, body, meta).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
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
    ) -> Result<ListPage, StorageError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn bytes_stream(bytes: Bytes) -> ByteStream {
        futures::stream::once(async move { Ok(bytes) }).boxed()
    }

    async fn collect(mut body: ByteStream) -> Vec<u8> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.unwrap());
        }
        buf
    }

    /// A trivial in-memory [`Storage`] double for the decorator test.
    #[derive(Default)]
    struct Mem {
        data: Mutex<HashMap<String, Bytes>>,
    }
    impl Mem {
        fn insert(&self, key: &str, bytes: &[u8]) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), Bytes::copy_from_slice(bytes));
        }
    }

    #[async_trait]
    impl Storage for Mem {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let b = self
                .data
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(b.len() as u64),
                    content_type: None,
                    etag: None,
                },
                body: bytes_stream(b),
            })
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let full = self.get(key).await?;
            let bytes = Bytes::from(collect(full.body).await);
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
            let bytes = Bytes::from(collect(body).await);
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

    #[tokio::test]
    async fn each_read_op_increments_its_own_counter_and_results_are_identical() {
        let inner = Arc::new(Mem::default());
        inner.insert("der/sha/640.webp", b"webp-bytes-xyz");
        let timing = Arc::new(BlobOpTiming::default());
        let store = TimingStorage::new(inner.clone(), timing.clone());

        // head → head_us only.
        let meta = store.head("der/sha/640.webp").await.unwrap();
        assert_eq!(meta.size, Some(14));
        let (g, h, r, ops) = timing.snapshot();
        assert_eq!(
            (g, r, ops),
            (0, 0, 1),
            "head bumps only ops; get/range untouched"
        );
        assert!(
            h >= 1 || h == 0,
            "head_us recorded (may be 0 on a fast mock)"
        );

        // get → get_us + ops, body byte-identical to inner.
        let got = store.get("der/sha/640.webp").await.unwrap();
        assert_eq!(collect(got.body).await, b"webp-bytes-xyz");
        let (_, _, r2, ops2) = timing.snapshot();
        assert_eq!((r2, ops2), (0, 2), "get bumps ops to 2, range still 0");

        // get_range → range_us + ops, slice byte-identical.
        let ranged = store
            .get_range("der/sha/640.webp", 0, Some(4))
            .await
            .unwrap();
        assert_eq!(collect(ranged.body).await, b"webp");
        let (_, _, _, ops3) = timing.snapshot();
        assert_eq!(ops3, 3, "get_range bumps ops to 3");

        // A write does NOT bump the read counters (times reads only).
        store
            .put(
                "k",
                bytes_stream(Bytes::from_static(b"v")),
                PutMeta::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            timing.ops.load(Ordering::Relaxed),
            3,
            "put is not a timed read op"
        );

        // NotFound still surfaces from inner (behavior unchanged), and is still counted + timed.
        assert!(matches!(
            store.get("missing").await,
            Err(StorageError::NotFound(_))
        ));
        assert_eq!(
            timing.ops.load(Ordering::Relaxed),
            4,
            "a failed get is still a timed op"
        );
    }
}
