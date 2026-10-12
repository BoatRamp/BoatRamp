//! A **translating** read-fallback over ONE [`Storage`] backend — the zero-downtime blob half of
//! the v0.31.0 default-scope re-home (Finding 8).
//!
//! The ordinary [`FallbackStorage`](crate::FallbackStorage) bridges a backend→backend switch by
//! forwarding each key **byte-identically** to a second backend. The default-scope re-home is a
//! different shape: the object does not move to another backend, it is re-homed to a different
//! **key prefix** on the SAME backend (`hblob/{site}/…` → `hblob/default/{site}/…`, and likewise
//! `mqp/…`/`mqgp/…`). After [`ProjectRef::qualified`](boatramp_core::project::ProjectRef::qualified)
//! is flipped, the runtime composes the NEW (`…/default/…`) key; the object still lives at the OLD
//! (bare) key until the background drain copies it. This composite bridges that window:
//!
//! - `get`/`get_range`/`head` call the backend at the NEW key. On a definitive, translatable miss
//!   (`NotFound` and `to_old(key)` yields a different old key) it retries the backend at the OLD
//!   key, serves it, and **spawns an idempotent background copy** OLD→NEW (head-skip if already
//!   present; NEVER deletes the old key). A translated miss/error/timeout collapses to the NEW
//!   key's `NotFound`.
//! - `put`/`delete` touch the NEW key only (no translation): writes land at the post-flip spelling,
//!   so the store converges onto the new scope with each write.
//! - `list(prefix)` unions the NEW-prefix listing with the OLD-prefix listing mapped back to the
//!   new spelling (via `to_new`), so a mid-soak guest `wasi:blobstore` list sees every object
//!   regardless of which spelling still holds it. The NEW spelling wins a duplicate.
//! - `allows_prune` is `false` — a read resurrects an old key, so GC must not prune during the soak
//!   (drain-then-finalize, exactly like [`FallbackStorage`]).
//!
//! The translation is **purely syntactic** (strip / insert the `default/` segment after a known
//! family prefix) and is supplied by the caller as two closures, so this crate stays generic:
//! `boatramp-node` supplies the boatramp `hblob/`/`mqp/`/`mqgp/` translators. A key that is not a
//! re-homed default-scope key (`to_old` returns `None`) is backend-only — a named project's
//! `hblob/{project}/…` key never falls back, so no cross-scope resurrection is possible.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::{
    ByteStream, ChangeStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError,
};

/// Map a key between the two spellings of a re-homed default scope. Returns `Some(other)` for a
/// translatable key (a different spelling to try / map to), `None` for a key this composite must
/// leave alone (not a boatramp data-family key, or already the target spelling).
pub type KeyTranslate = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The gate-mutation seams for the `DEFAULT-SCOPE DISJOINT OK` battery's read-fallback half.
/// Compiled ONLY under the `default-scope-gate-mutation` feature (the CI gate lane); each
/// `BOATRAMP_DEFAULTSCOPE_MUTATE_*` env var makes the composite behave like a specific broken
/// implementation so the gate proves the invariant is load-bearing. Mirrors the
/// `blob_migrate::gate_mutation` seam exactly.
#[cfg(feature = "default-scope-gate-mutation")]
pub(crate) mod gate_mutation {
    /// Whether a mutation env var is set (non-empty and not `0`).
    pub(crate) fn env_on(name: &str) -> bool {
        std::env::var(name)
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    }
}

/// A translating read-fallback over a single backend (see the [module docs](self)).
pub struct TranslatingFallbackStorage {
    inner: Arc<dyn Storage>,
    /// NEW key → OLD key (the bare pre-flip spelling to fall back to); `None` ⇒ not eligible.
    to_old: KeyTranslate,
    /// OLD key → NEW key (used to map an old-prefix `list` entry back to the new spelling).
    to_new: KeyTranslate,
    /// Bounds each translated secondary read so a wedged backend degrades a miss to `NotFound`.
    timeout: Duration,
}

impl TranslatingFallbackStorage {
    /// Wrap `inner`. `to_old(new_key)` names the old (bare) key to retry on a translatable miss;
    /// `to_new(old_key)` maps an old-prefix list entry to its new spelling for the `list` union;
    /// `timeout` bounds each fallback read.
    pub fn new(
        inner: Arc<dyn Storage>,
        to_old: KeyTranslate,
        to_new: KeyTranslate,
        timeout: Duration,
    ) -> Self {
        Self {
            inner,
            to_old,
            to_new,
            timeout,
        }
    }

    /// The old (bare) key to fall back to for a NEW-spelling `key`, or `None` when the key is not a
    /// re-homed default-scope key or the fallback is disabled by the gate mutation.
    fn old_key(&self, key: &str) -> Option<String> {
        // GATE MUTATION SEAM (read-fallback): disable the fallback entirely, so a datum that lives
        // only at the old key is NOT served at the new key ⇒ the gate's "fallback serves the old
        // datum" assertion goes RED.
        #[cfg(feature = "default-scope-gate-mutation")]
        if gate_mutation::env_on("BOATRAMP_DEFAULTSCOPE_MUTATE_DISABLE_FALLBACK") {
            return None;
        }
        match (self.to_old)(key) {
            Some(old) if old != key => Some(old),
            _ => None,
        }
    }

    /// Spawn an idempotent, read-only-on-source background copy OLD→NEW: head-skip when the new key
    /// already exists, stream the old body into the new key, and NEVER delete the old key. A failed
    /// copy simply leaves the fallback to serve (and re-attempt) again.
    fn spawn_background_copy(&self, old: String, new: String) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            if inner.head(&new).await.is_ok() {
                return; // already drained
            }
            // A transient/absent source is ignored — the next read falls back and re-attempts.
            if let Ok(obj) = inner.get(&old).await {
                let ct = obj.meta.content_type;
                let _ = inner
                    .put(&new, obj.body, PutMeta { content_type: ct })
                    .await;
            }
        });
    }

    /// Run `fut` (a translated backend read at the old key) under [`Self::timeout`], collapsing a
    /// miss/error/timeout to the new key's authoritative `NotFound`.
    async fn timed(
        &self,
        new_key: &str,
        fut: impl std::future::Future<Output = Result<GetObject, StorageError>>,
    ) -> Result<GetObject, StorageError> {
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(obj)) => Ok(obj),
            Ok(Err(_)) | Err(_) => Err(StorageError::NotFound(new_key.to_string())),
        }
    }
}

#[async_trait]
impl Storage for TranslatingFallbackStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        match self.inner.get(key).await {
            Ok(obj) => Ok(obj),
            Err(StorageError::NotFound(_)) => {
                let Some(old) = self.old_key(key) else {
                    return Err(StorageError::NotFound(key.to_string()));
                };
                let served = self.timed(key, self.inner.get(&old)).await;
                if served.is_ok() {
                    self.spawn_background_copy(old, key.to_string());
                }
                served
            }
            Err(e) => Err(e),
        }
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        match self.inner.get_range(key, offset, len).await {
            Ok(obj) => Ok(obj),
            Err(StorageError::NotFound(_)) => {
                let Some(old) = self.old_key(key) else {
                    return Err(StorageError::NotFound(key.to_string()));
                };
                let served = self
                    .timed(key, self.inner.get_range(&old, offset, len))
                    .await;
                if served.is_ok() {
                    // The full-object copy re-homes the whole key (not just the served range).
                    self.spawn_background_copy(old, key.to_string());
                }
                served
            }
            Err(e) => Err(e),
        }
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        // NEW key only — writes land at the post-flip spelling, converging the store.
        self.inner.put(key, body, meta).await
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        match self.inner.head(key).await {
            Ok(meta) => Ok(meta),
            Err(StorageError::NotFound(k)) => {
                let Some(old) = self.old_key(key) else {
                    return Err(StorageError::NotFound(k));
                };
                match tokio::time::timeout(self.timeout, self.inner.head(&old)).await {
                    Ok(Ok(meta)) => {
                        self.spawn_background_copy(old, key.to_string());
                        // Report the NEW key (the caller's spelling), size/ct from the old object.
                        Ok(ObjectMeta {
                            key: key.to_string(),
                            ..meta
                        })
                    }
                    Ok(Err(_)) | Err(_) => Err(StorageError::NotFound(k)),
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        // NEW key only — the old spelling is retired by the `blob_rehome` finalize pass, never here.
        self.inner.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = self.inner.list(prefix).await?;
        // Union in the OLD-prefix listing (mapped to the new spelling), so a mid-soak scoped list
        // sees objects still at the old spelling. The new spelling wins a duplicate.
        if let Some(old_prefix) = (self.to_old)(prefix)
            && old_prefix != prefix
        {
            let seen: std::collections::HashSet<String> =
                out.iter().map(|m| m.key.clone()).collect();
            for meta in self.inner.list(&old_prefix).await? {
                if let Some(new_key) = (self.to_new)(&meta.key)
                    && !seen.contains(&new_key)
                {
                    out.push(ObjectMeta {
                        key: new_key,
                        ..meta
                    });
                }
            }
        }
        Ok(out)
    }

    /// NEW key only — a translated zero-copy could hand out STALE bytes for a mutable key; the
    /// caller streams via `get` on a `None`, which DOES translate (same rule as `FallbackStorage`).
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

    /// `false` during the soak — a read resurrects the old key, so GC must not prune until the
    /// re-home drain has run and the operator removes the fallback (drain-then-finalize).
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

    /// A tiny in-memory backend.
    #[derive(Default)]
    struct Mem {
        data: Mutex<HashMap<String, Bytes>>,
    }
    impl Mem {
        fn seed(&self, key: &str, bytes: &[u8]) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), Bytes::copy_from_slice(bytes));
        }
    }
    fn stream(b: Bytes) -> ByteStream {
        futures::stream::once(async move { Ok(b) }).boxed()
    }
    async fn collect(mut body: ByteStream) -> Vec<u8> {
        let mut buf = Vec::new();
        while let Some(c) = body.next().await {
            buf.extend_from_slice(&c.unwrap());
        }
        buf
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
                body: stream(b),
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
                body: stream(slice),
            })
        }
        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let b = Bytes::from(collect(body).await);
            let size = b.len() as u64;
            self.data.lock().unwrap().insert(key.to_string(), b);
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                content_type: None,
                etag: None,
            })
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let d = self.data.lock().unwrap();
            let b = d
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

    /// The boatramp default-scope translators for `hblob/` (new→old strips `default/`, old→new
    /// inserts it), mirrored here for the unit tests.
    fn hblob_translators() -> (KeyTranslate, KeyTranslate) {
        let fam = "hblob/";
        let to_old: KeyTranslate = Arc::new(move |k: &str| {
            let rest = k.strip_prefix(fam)?;
            let suffix = rest.strip_prefix("default/")?;
            Some(format!("{fam}{suffix}"))
        });
        let to_new: KeyTranslate = Arc::new(move |k: &str| {
            let rest = k.strip_prefix(fam)?;
            let first = rest.split('/').next().unwrap_or("");
            if first.is_empty() || first == "default" {
                return None;
            }
            Some(format!("{fam}default/{rest}"))
        });
        (to_old, to_new)
    }

    fn fb(inner: Arc<dyn Storage>) -> TranslatingFallbackStorage {
        let (to_old, to_new) = hblob_translators();
        TranslatingFallbackStorage::new(inner, to_old, to_new, Duration::from_secs(5))
    }

    #[tokio::test]
    async fn new_key_miss_falls_back_to_old_and_background_copies() {
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/blog/c/obj", b"from-old");
        let s = fb(mem.clone());

        // The runtime now asks for the NEW spelling; the datum lives at the OLD key → served.
        let obj = s
            .get("hblob/default/blog/c/obj")
            .await
            .expect("fallback hit");
        assert_eq!(collect(obj.body).await, b"from-old");

        // The background copy eventually re-homes it to the new key (idempotent; poll briefly).
        let mut copied = false;
        for _ in 0..50 {
            if mem
                .data
                .lock()
                .unwrap()
                .contains_key("hblob/default/blog/c/obj")
            {
                copied = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(copied, "background copy should re-home old→new");
        // The OLD key is NEVER deleted by the fallback.
        assert!(mem.data.lock().unwrap().contains_key("hblob/blog/c/obj"));
    }

    #[tokio::test]
    async fn new_key_hit_does_not_fall_back() {
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/default/blog/c/obj", b"NEW");
        mem.seed("hblob/blog/c/obj", b"old");
        let s = fb(mem.clone());
        let obj = s.get("hblob/default/blog/c/obj").await.unwrap();
        assert_eq!(collect(obj.body).await, b"NEW");
    }

    #[tokio::test]
    async fn named_project_key_never_falls_back() {
        // A named project's key (`hblob/acme/…`, not `hblob/default/…`) is not translatable → a
        // miss stays a miss; a stray old datum is never resurrected across scopes.
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/acme", b"should-never-be-served");
        let s = fb(mem.clone());
        assert!(matches!(
            s.get("hblob/acme/site/c/obj").await,
            Err(StorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn writes_and_deletes_hit_the_new_key_only() {
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/blog/c/old", b"old");
        let s = fb(mem.clone());
        s.put(
            "hblob/default/blog/c/new",
            stream(Bytes::from_static(b"x")),
            PutMeta::default(),
        )
        .await
        .unwrap();
        s.delete("hblob/default/blog/c/new").await.unwrap();
        // The old key is untouched by writes/deletes at the new spelling.
        assert!(mem.data.lock().unwrap().contains_key("hblob/blog/c/old"));
    }

    #[tokio::test]
    async fn scoped_list_unions_old_and_new_spellings() {
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/default/blog/c/a", b"A"); // already re-homed
        mem.seed("hblob/blog/c/b", b"B"); // still at old spelling
        let s = fb(mem.clone());
        let mut keys: Vec<String> = s
            .list("hblob/default/blog/c/")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["hblob/default/blog/c/a", "hblob/default/blog/c/b"]
        );
    }

    #[tokio::test]
    async fn allows_prune_is_false() {
        let mem = Arc::new(Mem::default());
        assert!(!fb(mem).allows_prune());
    }
}
