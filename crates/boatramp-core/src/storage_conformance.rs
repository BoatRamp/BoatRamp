//! Shared **[`Storage`] conformance** suite, so every blob backend's test suite runs the
//! IDENTICAL assertions rather than a hand-copied variant — the anti-drift property, the direct
//! analogue of [`kv::conformance`](crate::kv::conformance) for the object-storage trait. A caching,
//! fallback, or cloud backend that got streaming round-trips, ranged reads, delete-of-missing,
//! prefix listing, or resumable pagination subtly wrong fails HERE rather than in production.
//!
//! Compiled only for this crate's own tests (`cfg(test)`) or when a downstream crate's test build
//! enables the `storage-conformance` feature (e.g. `boatramp-storage`'s `FsStorage` suite) — never
//! in a shipped library. `#[doc(hidden)]`: a test-support surface, not public API.

use bytes::Bytes;
use futures::StreamExt;

use crate::{ByteStream, PutMeta, Storage, StorageError};

/// Collect a streaming body fully into memory (test-only — the production paths never buffer a
/// whole object, but a conformance assertion must compare the exact bytes).
async fn drain(body: ByteStream) -> Vec<u8> {
    let mut body = body;
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.expect("body chunk is readable"));
    }
    out
}

/// A one-chunk [`ByteStream`] over owned bytes, for feeding [`Storage::put`].
fn stream_of(bytes: Vec<u8>) -> ByteStream {
    futures::stream::once(async move { Ok(Bytes::from(bytes)) }).boxed()
}

/// A shared **conformance suite** every [`Storage`] backend must satisfy identically. Running the
/// same assertions against multiple backends is what keeps them from drifting: the fs/S3/GCS/Azure
/// stores, the caching/fallback/translating wrappers, and any future backend all run this. Covers
/// the universal data-plane contract — streaming put/get round-trips (incl. empty + binary bodies),
/// ranged reads, `NotFound` on a missing key, idempotent delete, overwrite, prefix listing, and the
/// resumable [`Storage::list_page`] pagination invariant. Metadata whose type is `Option` (notably
/// `size`) is asserted correct **when the backend reports it**, never forced — a cloud backend may
/// legitimately leave it `None`, but must never report a wrong value.
pub async fn storage_conformance(store: &dyn Storage) {
    // ---- Missing key: get + head → NotFound; delete of a missing key is a no-op (idempotent). ----
    assert!(
        matches!(
            store.get("conf/missing").await,
            Err(StorageError::NotFound(_))
        ),
        "get of a missing key is NotFound"
    );
    assert!(
        matches!(
            store.head("conf/missing").await,
            Err(StorageError::NotFound(_))
        ),
        "head of a missing key is NotFound"
    );
    store
        .delete("conf/missing")
        .await
        .expect("delete of a missing key is a no-op");

    // ---- put/get round-trip: a normal value, an EMPTY body (distinct from absent), binary bytes. ----
    let put_meta = store
        .put("conf/a", stream_of(b"one".to_vec()), PutMeta::default())
        .await
        .expect("put a normal body");
    if let Some(size) = put_meta.size {
        assert_eq!(size, 3, "put reports the number of bytes written");
    }
    store
        .put("conf/empty", stream_of(Vec::new()), PutMeta::default())
        .await
        .expect("put an empty body");
    store
        .put(
            "conf/bin",
            stream_of(vec![0u8, 159, 146, 150]),
            PutMeta::default(),
        )
        .await
        .expect("put binary bytes");

    let got = store.get("conf/a").await.expect("get a present key");
    assert_eq!(got.meta.key, "conf/a", "get echoes the requested key");
    if let Some(size) = got.meta.size {
        assert_eq!(size, 3);
    }
    assert_eq!(
        drain(got.body).await,
        b"one".to_vec(),
        "get streams the exact bytes"
    );
    assert_eq!(
        drain(store.get("conf/empty").await.unwrap().body).await,
        Vec::<u8>::new(),
        "an empty object round-trips as zero bytes (not absent)"
    );
    assert_eq!(
        drain(store.get("conf/bin").await.unwrap().body).await,
        vec![0, 159, 146, 150],
        "binary bytes round-trip unmangled"
    );

    // head reports metadata without reading the body.
    let head = store.head("conf/a").await.expect("head a present key");
    assert_eq!(head.key, "conf/a");
    if let Some(size) = head.size {
        assert_eq!(size, 3, "head reports the stored size");
    }

    // ---- get_range: a bounded middle slice, an open-ended tail (len = None), and the full object. ----
    store
        .put(
            "conf/range",
            stream_of(b"0123456789".to_vec()),
            PutMeta::default(),
        )
        .await
        .expect("put the range fixture");
    assert_eq!(
        drain(
            store
                .get_range("conf/range", 2, Some(3))
                .await
                .unwrap()
                .body
        )
        .await,
        b"234".to_vec(),
        "a bounded range returns exactly [offset, offset+len)"
    );
    assert_eq!(
        drain(store.get_range("conf/range", 7, None).await.unwrap().body).await,
        b"789".to_vec(),
        "len = None streams from the offset to the end"
    );
    assert_eq!(
        drain(store.get_range("conf/range", 0, None).await.unwrap().body).await,
        b"0123456789".to_vec(),
        "offset 0, len None is the whole object"
    );

    // ---- Overwrite replaces the value (idempotent key, new bytes). ----
    store
        .put(
            "conf/a",
            stream_of(b"ONE-LONGER".to_vec()),
            PutMeta::default(),
        )
        .await
        .expect("overwrite");
    assert_eq!(
        drain(store.get("conf/a").await.unwrap().body).await,
        b"ONE-LONGER".to_vec(),
        "a second put to the same key replaces the bytes"
    );

    // ---- list returns exactly the keys under the prefix, never others. ----
    store
        .put("other/x", stream_of(b"x".to_vec()), PutMeta::default())
        .await
        .expect("put an out-of-prefix key");
    let mut keys = list_keys(store, "conf/").await;
    keys.sort();
    assert_eq!(
        keys,
        vec!["conf/a", "conf/bin", "conf/empty", "conf/range"],
        "list is scoped to the prefix and excludes other prefixes"
    );
    assert!(
        store.list("conf/nope/").await.unwrap().is_empty(),
        "a prefix with no objects lists nothing"
    );

    // ---- delete removes just that key; the prefix set shrinks; a re-get is NotFound. ----
    store.delete("conf/range").await.expect("delete one key");
    assert!(
        matches!(
            store.get("conf/range").await,
            Err(StorageError::NotFound(_))
        ),
        "a deleted key is gone"
    );
    let mut after = list_keys(store, "conf/").await;
    after.sort();
    assert_eq!(
        after,
        vec!["conf/a", "conf/bin", "conf/empty"],
        "the prefix listing shrinks by exactly the deleted key"
    );

    // ---- list_page paginates EXACTLY: every key once, in key order, no dup/skip across pages, the
    //      limit is respected, and the final page's cursor is None (exhausted). ----
    for i in 0..5u8 {
        store
            .put(&format!("page/{i}"), stream_of(vec![i]), PutMeta::default())
            .await
            .expect("put a pagination fixture");
    }
    let mut collected: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut iterations = 0;
    loop {
        iterations += 1;
        assert!(
            iterations <= 50,
            "list_page must terminate (cursor → None when exhausted)"
        );
        let page = store
            .list_page("page/", cursor.as_deref(), 2)
            .await
            .expect("a page lists");
        assert!(page.metas.len() <= 2, "a page never exceeds the limit");
        collected.extend(page.metas.iter().map(|m| m.key.clone()));
        match page.cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(
        collected,
        vec!["page/0", "page/1", "page/2", "page/3", "page/4"],
        "pagination yields every key exactly once, in key order"
    );
}

/// The keys under `prefix`, via [`Storage::list`] (metadata → key).
async fn list_keys(store: &dyn Storage, prefix: &str) -> Vec<String> {
    store
        .list(prefix)
        .await
        .expect("list a prefix")
        .into_iter()
        .map(|m| m.key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GetObject, ObjectMeta};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A minimal, correct in-memory [`Storage`] — just enough to validate the conformance suite
    /// itself (the way `kv::conformance` runs against the shipped `MemoryKv`). Implements only the
    /// required methods and inherits the default [`Storage::list_page`], so the suite also exercises
    /// that default pagination body.
    #[derive(Default)]
    struct MemStorage {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let bytes = self
                .objects
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
                body: stream_of(bytes),
            })
        }

        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let bytes = self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let start = (offset as usize).min(bytes.len());
            let end = match len {
                Some(l) => start.saturating_add(l as usize).min(bytes.len()),
                None => bytes.len(),
            };
            let slice = bytes[start..end].to_vec();
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(slice.len() as u64),
                    content_type: None,
                    etag: None,
                },
                body: stream_of(slice),
            })
        }

        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let bytes = drain(body).await;
            let size = bytes.len() as u64;
            self.objects.lock().unwrap().insert(key.to_string(), bytes);
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                content_type: None,
                etag: None,
            })
        }

        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let objects = self.objects.lock().unwrap();
            let bytes = objects
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
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .objects
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

    /// The reference in-memory backend satisfies the conformance suite — proving the suite's own
    /// assertions are coherent (the analogue of `memorykv_satisfies_the_conformance_suite`).
    #[tokio::test]
    async fn mem_storage_satisfies_the_conformance_suite() {
        storage_conformance(&MemStorage::default()).await;
    }
}
