//! Hedged-read blob wrapper — cut the serve-path fetch tail by racing a second read against a slow
//! first one.
//!
//! On an external object store the blob-fetch latency is bimodal: a warm, connection-reused GET is p50
//! ≈ tens of ms, but a p99 is hundreds of ms — a slow-to-establish new connection or the store's own
//! tail — while the node's CPU sits idle (measured: `blob_range` p50 16ms, p99 727ms, with sub-ms
//! CPU-side phases). A single serve can't make one GET faster, but it can **race a second GET** once the
//! first is visibly slow and take whichever response arrives first. Blob reads are idempotent, so a
//! hedge is always safe; the loser's in-flight request is dropped (cancelled) the moment the winner
//! lands. This trades spare CPU/IO for a much tighter tail — exactly the resource balance the serve path
//! leaves on the table.
//!
//! A [`Semaphore`] caps concurrent hedges so a store-wide brown-out (when *every* request is slow) can't
//! turn hedging into a request-amplifying storm: over the cap, a read simply falls back to a single
//! un-hedged request. Only the two body-reading ops (`get`, `get_range`) hedge — `head` is already
//! deduped by [`crate::MarkerHeadCache`] and writes/list/delete pass straight through. This is a
//! backend-agnostic decorator over `Arc<dyn Storage>`, so it covers S3/Tigris, GCS and Azure uniformly
//! (the local filesystem backend needs no hedging and should not be wrapped).

use async_trait::async_trait;
use boatramp_core::{
    ByteStream, ChangeStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Wraps any [`Storage`], hedging `get`/`get_range` after `delay`. See the module docs.
pub struct HedgedStorage {
    inner: Arc<dyn Storage>,
    /// `Duration::ZERO` ⇒ hedging disabled (pure pass-through).
    delay: Duration,
    /// Budget of concurrent in-flight hedges (not total reads). Guards against a hedge storm when the
    /// backend is uniformly slow.
    hedges: Arc<Semaphore>,
}

/// Default concurrent-hedge budget when hedging is enabled but no explicit cap is given.
const DEFAULT_MAX_INFLIGHT_HEDGES: usize = 16;

impl HedgedStorage {
    /// Wrap `inner`. `delay == 0` disables hedging (pure pass-through). `max_inflight == 0` ⇒
    /// [`DEFAULT_MAX_INFLIGHT_HEDGES`].
    pub fn new(inner: Arc<dyn Storage>, delay: Duration, max_inflight: usize) -> Self {
        let cap = if max_inflight == 0 {
            DEFAULT_MAX_INFLIGHT_HEDGES
        } else {
            max_inflight
        };
        Self {
            inner,
            delay,
            hedges: Arc::new(Semaphore::new(cap)),
        }
    }

    fn enabled(&self) -> bool {
        !self.delay.is_zero()
    }

    /// Race `make()` against a delayed second `make()`. Returns whichever finishes first; the loser is
    /// dropped. When disabled, or when the first call finishes within `delay`, or when the hedge budget
    /// is saturated, this is exactly one call — no amplification. `make` must be callable twice and
    /// produce independent, idempotent read futures.
    async fn hedged<F, Fut>(&self, make: F) -> Result<GetObject, StorageError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<GetObject, StorageError>> + Send,
    {
        if !self.enabled() {
            return make().await;
        }
        let primary = make();
        tokio::pin!(primary);
        // The first call gets `delay` to finish on its own. If it does (fast path / an error that
        // arrives quickly, e.g. a 404), return it — hedge only on latency, never to paper over errors
        // (the backend's own retry handles transient failures).
        tokio::select! {
            r = &mut primary => return r,
            _ = tokio::time::sleep(self.delay) => {}
        }
        // The primary is slow. Fire a hedge if there is budget; otherwise keep waiting on the primary
        // alone so a uniformly-slow backend is not hammered with doubled load.
        let _permit = match Arc::clone(&self.hedges).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return primary.await,
        };
        let hedge = make();
        tokio::pin!(hedge);
        tokio::select! {
            r = &mut primary => r,
            r = &mut hedge => r,
        }
    }
}

#[async_trait]
impl Storage for HedgedStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        self.hedged(|| self.inner.get(key)).await
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        self.hedged(|| self.inner.get_range(key, offset, len)).await
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        self.inner.put(key, body, meta).await
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        self.inner.head(key).await
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

    fn supports_watch(&self) -> bool {
        self.inner.supports_watch()
    }

    async fn watch(&self, prefix: &str) -> Result<Option<ChangeStream>, StorageError> {
        self.inner.watch(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::GetObject;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    /// A backend whose `get_range` sleeps `slow` on the FIRST call and `fast` on every later call, so a
    /// hedge (the 2nd call) returns quickly while the primary is still asleep — letting the test assert
    /// the hedge won and bounded the latency.
    struct SlowFirst {
        calls: AtomicUsize,
        slow: Duration,
        fast: Duration,
    }

    #[async_trait]
    impl Storage for SlowFirst {
        async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
            unimplemented!()
        }
        async fn get_range(
            &self,
            key: &str,
            _offset: u64,
            _len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(if n == 0 { self.slow } else { self.fast }).await;
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(0),
                    content_type: None,
                    etag: None,
                },
                body: Box::pin(futures::stream::empty()),
            })
        }
        async fn put(
            &self,
            _key: &str,
            _body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            unimplemented!()
        }
        async fn head(&self, _key: &str) -> Result<ObjectMeta, StorageError> {
            unimplemented!()
        }
        async fn delete(&self, _key: &str) -> Result<(), StorageError> {
            unimplemented!()
        }
        async fn list(&self, _prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn hedge_wins_when_primary_is_slow() {
        let backend = Arc::new(SlowFirst {
            calls: AtomicUsize::new(0),
            slow: Duration::from_millis(500),
            fast: Duration::from_millis(5),
        });
        let hedged = HedgedStorage::new(backend.clone(), Duration::from_millis(30), 8);
        let t0 = Instant::now();
        hedged.get_range("k", 0, None).await.expect("ok");
        let elapsed = t0.elapsed();
        // Primary sleeps 500ms; the hedge fires at 30ms and returns ~5ms later. Without hedging this
        // would take ~500ms — assert it came back far sooner, and that a 2nd (hedge) call was made.
        assert!(
            elapsed < Duration::from_millis(250),
            "hedge should have bounded the tail, took {elapsed:?}"
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 2, "a hedge fired");
    }

    #[tokio::test]
    async fn disabled_is_single_call() {
        let backend = Arc::new(SlowFirst {
            calls: AtomicUsize::new(0),
            slow: Duration::from_millis(5),
            fast: Duration::from_millis(5),
        });
        let hedged = HedgedStorage::new(backend.clone(), Duration::ZERO, 8);
        hedged.get_range("k", 0, None).await.expect("ok");
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            1,
            "disabled ⇒ exactly one call"
        );
    }

    #[tokio::test]
    async fn fast_primary_does_not_hedge() {
        let backend = Arc::new(SlowFirst {
            calls: AtomicUsize::new(0),
            slow: Duration::from_millis(5), // first call is already fast ⇒ finishes within the delay
            fast: Duration::from_millis(5),
        });
        let hedged = HedgedStorage::new(backend.clone(), Duration::from_millis(50), 8);
        hedged.get_range("k", 0, None).await.expect("ok");
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            1,
            "a fast primary must not trigger a hedge"
        );
    }
}
