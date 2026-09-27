//! A read-fallback composite over two [`Storage`] backends — the zero-downtime
//! blob-backend switch (blob-backend migration Part 2).
//!
//! Switching the node blob backend (`--blobs fs|s3|gcs|azure`, or provider→provider,
//! or region→region) points serving at an EMPTY store, so every site 404s until each
//! project is re-applied (or `boatramp blob migrate` finishes copying). [`FallbackStorage`]
//! bridges that window: it serves the NEW (primary) backend first, and on a definitive
//! **miss** falls through to the OLD (secondary) backend, so a read is answered from
//! wherever the object still lives during the transition. Writes go to the primary ONLY —
//! the secondary is strictly read-only — so the store converges onto the new backend
//! with each write while `boatramp blob migrate` drains the rest.
//!
//! It is a **bounded transition aid**, not a steady state (see the converged panel
//! decisions in `PLAN-blob-migrate.md`): the operator drains the secondary into the
//! primary, verifies, then removes `[serve].blob_fallback` and restarts. The node logs a
//! prominent startup WARNING while it is active.
//!
//! ## Read policy (exact, fail-closed)
//! - `get`/`get_range`/`head` call the primary. The result is matched EXACTLY:
//!   - `Err(NotFound)` **and** the key is fallback-eligible ⇒ try the secondary (bounded
//!     by `secondary_timeout`). The secondary is a best-effort drain source: a secondary
//!     hit is served, and a secondary miss, a secondary error of ANY kind, or a timeout
//!     all collapse back to the primary's `NotFound` — a wedged/failing secondary must
//!     never hang the serve path nor turn a primary-authoritative miss into a 500.
//!   - any OTHER primary error (`Io`/`Backend`/`Unsupported`/`InvalidKey`) ⇒ PROPAGATE.
//!     A transient primary error is never a definitive miss, so the secondary is not
//!     consulted (else a blip would serve a stale/absent object).
//!   - `NotFound` but the key is NOT fallback-eligible ⇒ return the primary `NotFound`.
//!   - primary miss + secondary miss ⇒ `NotFound`.
//! - The key is forwarded **byte-identical** to both backends — no normalize/prefix/
//!   case-fold. Tenant isolation is enforced ABOVE `Storage` by the key scheme, so
//!   identity-forwarding is the cross-tenant backstop.
//! - `fallback_when` is a **supplied predicate**, keeping this crate generic — the app
//!   (`boatramp-node`) supplies the boatramp allowlist (content-addressed blob keys or
//!   the `hblob/`/`mqgp/` prefixes). A non-eligible key is primary-only, so a stray
//!   non-boatramp object on the secondary can never silently resurrect.
//!
//! ## Write policy
//! - `put`/`delete` touch the PRIMARY ONLY. The secondary is never written or deleted.
//!
//! ## `list`
//! - Union: primary entries plus secondary entries whose key is absent from the primary
//!   (primary metadata wins on a duplicate). `list` is NOT prefix-gated — a mid-transition
//!   guest `wasi:blobstore` list and a `boatramp blob migrate` enumeration must both see
//!   every object regardless of which backend still holds it.
//!
//! ## Zero-copy + watch
//! - `mapped`/`local_file` are PRIMARY ONLY — a primary `None` is ambiguous (missing vs
//!   remote-opaque), and falling back could hand out STALE zero-copy bytes for a mutable
//!   `hblob/` key when the primary is a remote store. The caller already streams via `get`
//!   on a `None`, which DOES fall back correctly.
//! - `supports_watch`/`watch` are the primary's.
//!
//! ## GC
//! - [`allows_prune`](Storage::allows_prune) returns `false`: the union `list` over a
//!   primary-only `delete` would let GC report a secondary-only orphan reclaimed while a
//!   read resurrects it. `DeployStore::collect_garbage` refuses a prune while this is
//!   attached (drain-then-drop).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::{
    ByteStream, ChangeStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError,
};

/// A predicate deciding whether a primary-miss on `key` may fall through to the secondary.
///
/// Supplied by the caller so this crate stays generic (no hardcoded app prefixes); the
/// boatramp node supplies its own allowlist (content-addressed blob keys or the
/// `hblob/`/`mqgp/` prefixes).
pub type FallbackWhen = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// A read-fallback composite: serve `primary` first, fall through to `secondary` only on
/// a definitive, fallback-eligible primary miss. Writes are primary-only. See the
/// [module docs](self) for the full policy.
pub struct FallbackStorage {
    primary: Arc<dyn Storage>,
    secondary: Arc<dyn Storage>,
    fallback_when: FallbackWhen,
    secondary_timeout: Duration,
}

impl FallbackStorage {
    /// Wrap `primary` (the new, authoritative backend — reads first, all writes) over
    /// `secondary` (the old backend — read-only fallback). `fallback_when(key)` gates the
    /// fall-through on a primary miss; `secondary_timeout` bounds each secondary read so a
    /// wedged secondary degrades a miss to `NotFound` instead of hanging the serve path.
    pub fn new(
        primary: Arc<dyn Storage>,
        secondary: Arc<dyn Storage>,
        fallback_when: FallbackWhen,
        secondary_timeout: Duration,
    ) -> Self {
        Self {
            primary,
            secondary,
            fallback_when,
            secondary_timeout,
        }
    }

    /// Whether a primary miss on `key` may fall through to the secondary.
    fn eligible(&self, key: &str) -> bool {
        (self.fallback_when)(key)
    }

    /// Run `fut` (a secondary read) under the bounded [`Self::secondary_timeout`]. This is reached
    /// ONLY after the primary has authoritatively MISSED (`NotFound`), so the secondary is a
    /// best-effort drain source: a secondary hit is returned, and a secondary MISS, a secondary
    /// ERROR of any kind, OR a timeout all collapse to `NotFound(key)` — a wedged/failing secondary
    /// must never hang the serve path or turn a primary-authoritative miss into a 500 during the
    /// transition window. Callers pass the primary's `NotFound` key so the surfaced key is
    /// byte-identical.
    async fn timed_secondary(
        &self,
        key: &str,
        fut: impl std::future::Future<Output = Result<GetObject, StorageError>>,
    ) -> Result<GetObject, StorageError> {
        match tokio::time::timeout(self.secondary_timeout, fut).await {
            Ok(Ok(obj)) => Ok(obj),
            // Secondary miss/error, or a timeout (the outer `Err`): degrade to the primary's
            // authoritative miss.
            Ok(Err(_)) | Err(_) => Err(StorageError::NotFound(key.to_string())),
        }
    }
}

#[async_trait]
impl Storage for FallbackStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        match self.primary.get(key).await {
            Ok(obj) => Ok(obj),
            // Definitive miss + eligible ⇒ consult the secondary (bounded; miss/error/timeout all
            // collapse back to the primary's `NotFound`).
            Err(StorageError::NotFound(_)) if self.eligible(key) => {
                self.timed_secondary(key, self.secondary.get(key)).await
            }
            // Miss but NOT eligible ⇒ the primary's NotFound (no fallback).
            Err(e @ StorageError::NotFound(_)) => Err(e),
            // Any other primary error ⇒ PROPAGATE (never consult the secondary on an error).
            Err(e) => Err(e),
        }
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        match self.primary.get_range(key, offset, len).await {
            Ok(obj) => Ok(obj),
            Err(StorageError::NotFound(_)) if self.eligible(key) => {
                // Forward the SAME (offset, len) to the secondary (bounded; miss/error/timeout all
                // collapse back to the primary's `NotFound`).
                self.timed_secondary(key, self.secondary.get_range(key, offset, len))
                    .await
            }
            Err(e @ StorageError::NotFound(_)) => Err(e),
            Err(e) => Err(e),
        }
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        // Primary only — the secondary is strictly read-only.
        self.primary.put(key, body, meta).await
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        match self.primary.head(key).await {
            Ok(meta) => Ok(meta),
            Err(StorageError::NotFound(k)) if self.eligible(key) => {
                // `head` returns metadata, not a body — bound it with the same timeout inline. A
                // secondary miss/error/timeout all collapse to the primary's `NotFound` key (the same
                // best-effort read-through semantic as `get`/`get_range`).
                match tokio::time::timeout(self.secondary_timeout, self.secondary.head(key)).await {
                    Ok(Ok(meta)) => Ok(meta),
                    Ok(Err(_)) | Err(_) => Err(StorageError::NotFound(k)),
                }
            }
            Err(e @ StorageError::NotFound(_)) => Err(e),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        // Primary only — the secondary is strictly read-only.
        self.primary.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        // Union — primary entries plus secondary entries absent from the primary (primary
        // metadata wins on a duplicate). NOT prefix-gated: a mid-transition enumeration
        // (guest `wasi:blobstore` list, `boatramp blob migrate`) must see every object.
        let primary = self.primary.list(prefix).await?;
        let secondary = self.secondary.list(prefix).await?;

        let mut seen: HashSet<String> = HashSet::with_capacity(primary.len());
        let mut out = Vec::with_capacity(primary.len() + secondary.len());
        for meta in primary {
            seen.insert(meta.key.clone());
            out.push(meta);
        }
        for meta in secondary {
            if !seen.contains(&meta.key) {
                out.push(meta);
            }
        }
        Ok(out)
    }

    /// Primary ONLY — a primary `None` is ambiguous (missing vs remote-opaque), and
    /// falling back could serve STALE zero-copy bytes for a mutable key when the primary
    /// is a remote store. The caller streams via `get` on a `None`, which falls back.
    fn mapped(&self, key: &str) -> Option<bytes::Bytes> {
        self.primary.mapped(key)
    }

    /// Primary ONLY — same reasoning as [`mapped`](Self::mapped).
    fn local_file(&self, key: &str) -> Option<std::fs::File> {
        self.primary.local_file(key)
    }

    /// Watching is the primary's capability — the secondary is a read-only drain source,
    /// not a live-change source.
    fn supports_watch(&self) -> bool {
        self.primary.supports_watch()
    }

    async fn watch(&self, prefix: &str) -> Result<Option<ChangeStream>, StorageError> {
        self.primary.watch(prefix).await
    }

    /// `false` — a read-fallback composite is never safe to prune: the union `list` over a
    /// primary-only `delete` would report a secondary-only orphan reclaimed while a read
    /// resurrects it. `DeployStore::collect_garbage` refuses a prune while this is
    /// attached (drain-then-drop; overrides the trait default of `true`).
    fn allows_prune(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Wrap owned [`Bytes`] as a single-chunk [`ByteStream`].
    fn bytes_stream(bytes: Bytes) -> ByteStream {
        futures::stream::once(async move { Ok(bytes) }).boxed()
    }

    /// Drain a [`ByteStream`] into contiguous bytes.
    async fn collect(mut body: ByteStream) -> Vec<u8> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.expect("chunk"));
        }
        buf
    }

    /// A tiny in-memory [`Storage`] double: records writes/deletes and counts reads, so a
    /// test can prove write-isolation and read precedence.
    #[derive(Default)]
    struct Mem {
        data: Mutex<HashMap<String, Bytes>>,
        gets: AtomicUsize,
    }

    impl Mem {
        fn seed(&self, key: &str, bytes: &[u8]) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), Bytes::copy_from_slice(bytes));
        }
        fn keys(&self) -> Vec<String> {
            let mut ks: Vec<String> = self.data.lock().unwrap().keys().cloned().collect();
            ks.sort();
            ks
        }
        fn get_count(&self) -> usize {
            self.gets.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Storage for Mem {
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
            let bytes = Bytes::from(collect(full.body).await);
            let start = (offset as usize).min(bytes.len());
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

    /// A [`Storage`] whose `get`/`get_range`/`head` always return a chosen non-NotFound
    /// error — to prove a primary error PROPAGATES and never consults the secondary.
    struct FaultyPrimary;
    #[async_trait]
    impl Storage for FaultyPrimary {
        async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
            Err(StorageError::backend("primary transient failure"))
        }
        async fn get_range(
            &self,
            _key: &str,
            _offset: u64,
            _len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            Err(StorageError::backend("primary transient failure"))
        }
        async fn put(
            &self,
            key: &str,
            _body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(0),
                content_type: None,
                etag: None,
            })
        }
        async fn head(&self, _key: &str) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::backend("primary transient failure"))
        }
        async fn delete(&self, _key: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(Vec::new())
        }
    }

    /// The boatramp allowlist predicate, mirrored here for the unit tests (the real one is
    /// supplied by `boatramp-node`).
    fn hblob_only() -> FallbackWhen {
        Arc::new(|k: &str| k.starts_with("hblob/"))
    }

    fn fallback(primary: Arc<dyn Storage>, secondary: Arc<dyn Storage>) -> FallbackStorage {
        FallbackStorage::new(primary, secondary, hblob_only(), Duration::from_secs(5))
    }

    #[tokio::test]
    async fn primary_miss_reads_from_secondary() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        secondary.seed("hblob/site/c/obj", b"from-secondary");
        let fb = fallback(primary.clone(), secondary.clone());

        let obj = fb.get("hblob/site/c/obj").await.expect("fallback hit");
        assert_eq!(collect(obj.body).await, b"from-secondary");
    }

    #[tokio::test]
    async fn primary_hit_wins_over_divergent_secondary() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        primary.seed("hblob/site/c/obj", b"PRIMARY");
        secondary.seed("hblob/site/c/obj", b"secondary");
        let fb = fallback(primary.clone(), secondary.clone());

        let obj = fb.get("hblob/site/c/obj").await.expect("primary hit");
        assert_eq!(collect(obj.body).await, b"PRIMARY");
        // The secondary was never consulted (primary hit).
        assert_eq!(secondary.get_count(), 0);
    }

    #[tokio::test]
    async fn put_and_delete_are_primary_only() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        secondary.seed("hblob/site/c/obj", b"secondary");
        let fb = fallback(primary.clone(), secondary.clone());

        fb.put(
            "hblob/site/c/new",
            bytes_stream(Bytes::from_static(b"x")),
            PutMeta::default(),
        )
        .await
        .unwrap();
        fb.delete("hblob/site/c/obj").await.unwrap();

        // The write landed on the primary; the delete did NOT touch the read-only secondary.
        assert_eq!(primary.keys(), vec!["hblob/site/c/new".to_string()]);
        assert_eq!(secondary.keys(), vec!["hblob/site/c/obj".to_string()]);
    }

    #[tokio::test]
    async fn primary_error_propagates_without_consulting_secondary() {
        let primary = Arc::new(FaultyPrimary);
        let secondary = Arc::new(Mem::default());
        secondary.seed("hblob/site/c/obj", b"secondary");
        let fb = fallback(primary, secondary.clone());

        let err = fb.get("hblob/site/c/obj").await;
        assert!(
            matches!(err, Err(StorageError::Backend(_))),
            "a non-NotFound primary error must propagate"
        );
        assert_eq!(
            secondary.get_count(),
            0,
            "the secondary must not be consulted on an error"
        );
    }

    #[tokio::test]
    async fn non_eligible_key_is_primary_only() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        // A config-shaped key present ONLY on the secondary — the allowlist excludes it.
        secondary.seed("config/x", b"stale-config");
        let fb = fallback(primary, secondary.clone());

        assert!(
            matches!(fb.get("config/x").await, Err(StorageError::NotFound(_))),
            "a non-eligible key must not fall back to the secondary"
        );
        assert_eq!(secondary.get_count(), 0);
    }

    #[tokio::test]
    async fn list_unions_and_dedups_primary_wins() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        primary.seed("hblob/site/c/a", b"PA"); // primary-only
        primary.seed("hblob/site/c/dup", b"P-dup-bytes"); // dup, primary wins
        secondary.seed("hblob/site/c/b", b"SB"); // secondary-only
        secondary.seed("hblob/site/c/dup", b"S"); // dup, must be masked by primary
        let fb = fallback(primary, secondary);

        let mut list = fb.list("").await.unwrap();
        list.sort_by(|a, b| a.key.cmp(&b.key));
        let keys: Vec<&str> = list.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["hblob/site/c/a", "hblob/site/c/b", "hblob/site/c/dup"]
        );
        // Primary meta wins on the dup (its size, not the secondary's 1-byte value).
        let dup = list.iter().find(|m| m.key == "hblob/site/c/dup").unwrap();
        assert_eq!(dup.size, Some("P-dup-bytes".len() as u64));
    }

    #[tokio::test]
    async fn both_miss_is_not_found() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        let fb = fallback(primary, secondary);
        assert!(matches!(
            fb.get("hblob/site/c/nope").await,
            Err(StorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn allows_prune_is_false() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        let fb = fallback(primary, secondary);
        assert!(!fb.allows_prune());
    }

    #[tokio::test]
    async fn get_range_forwards_offset_len_to_secondary() {
        let primary = Arc::new(Mem::default());
        let secondary = Arc::new(Mem::default());
        secondary.seed("hblob/site/c/obj", b"0123456789");
        let fb = fallback(primary, secondary);

        let obj = fb.get_range("hblob/site/c/obj", 3, Some(4)).await.unwrap();
        assert_eq!(collect(obj.body).await, b"3456");
    }
}
