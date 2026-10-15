//! A **pure key-translating** decorator over one [`Storage`] backend — the blob half of the
//! un-migrated-store backward-read-compat (the Finding-8 migration-safety rewrite).
//!
//! Unlike [`TranslatingFallbackStorage`](crate::TranslatingFallbackStorage) — a READ-ONLY fallback
//! used during the `dual` soak, which writes the NEW spelling and only *reads* the old one — this
//! decorator rewrites the key new→old on **every** operation (read AND write), so an un-migrated store
//! operates entirely on the one canonical OLD key the backend physically holds. That read+write
//! symmetry is the point: a guest write/delete lands on the single old key (no second spelling to
//! resurrect a delete or strand a write), and a rollback to the prior binary reads exactly what this
//! binary wrote. It is installed ONLY while the control-plane store is below the default-scope re-home
//! version (see `boatramp_node::blobs::default_scope_blob_fallback`); a staged/`dual` store uses the
//! read-fallback instead, and a finalized/fresh store is undecorated.
//!
//! Translation is purely syntactic and family-scoped, supplied by the caller as two closures
//! ([`KeyTranslate`]):
//! - `to_old` (new→old): strip the `default/` scope segment after a known family prefix. A key it
//!   does not recognise (a content-addressed CAS blob, a named project's `hblob/{project}/…`, any
//!   non-family key) yields `None` and is passed through **unchanged** — so a global CAS blob and a
//!   tenant's objects are never wrongly addressed.
//! - `to_new` (old→new, project-aware): map an old-prefix `list` entry back to the new spelling the
//!   runtime expects, leaving a named project's key alone.
//!
//! `allows_prune` is `false`: a store serving its old layout is mid-transition, so blob GC must not
//! prune until `boatramp migrate` + the blob re-home drain run (drain-then-finalize), exactly like the
//! soak fallback.

use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::{
    ByteStream, ChangeStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError,
};

use crate::translating_fallback::KeyTranslate;

/// A pure new→old key-translating decorator over a single backend (see the [module docs](self)).
pub struct TranslatingStorage {
    inner: Arc<dyn Storage>,
    /// NEW key → OLD key. `None` ⇒ pass the key through unchanged (CAS blob, named project, non-family).
    to_old: KeyTranslate,
    /// OLD key → NEW key, for mapping `list` entries back to the runtime's spelling.
    to_new: KeyTranslate,
}

impl TranslatingStorage {
    /// Wrap `inner`, translating every operation's key new→old via `to_old` (and `list` results
    /// old→new via `to_new`).
    pub fn new(inner: Arc<dyn Storage>, to_old: KeyTranslate, to_new: KeyTranslate) -> Self {
        Self {
            inner,
            to_old,
            to_new,
        }
    }

    /// new→old for an input key: the old key to operate on, or the key unchanged when it is not a
    /// re-homed default-scope key (CAS, named project, control-plane).
    fn down<'a>(&self, key: &'a str) -> std::borrow::Cow<'a, str> {
        match (self.to_old)(key) {
            Some(old) => std::borrow::Cow::Owned(old),
            None => std::borrow::Cow::Borrowed(key),
        }
    }
}

#[async_trait]
impl Storage for TranslatingStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        self.inner.get(&self.down(key)).await
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        self.inner.get_range(&self.down(key), offset, len).await
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        // Report the NEW (caller's) key spelling; the object is stored at the old key.
        let stored = self.inner.put(&self.down(key), body, meta).await?;
        Ok(ObjectMeta {
            key: key.to_string(),
            ..stored
        })
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let meta = self.inner.head(&self.down(key)).await?;
        Ok(ObjectMeta {
            key: key.to_string(),
            ..meta
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.inner.delete(&self.down(key)).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let listed = self.inner.list(&self.down(prefix)).await?;
        Ok(listed
            .into_iter()
            .map(|meta| match (self.to_new)(&meta.key) {
                Some(new_key) => ObjectMeta {
                    key: new_key,
                    ..meta
                },
                None => meta,
            })
            .collect())
    }

    fn mapped(&self, key: &str) -> Option<bytes::Bytes> {
        self.inner.mapped(&self.down(key))
    }

    fn local_file(&self, key: &str) -> Option<std::fs::File> {
        self.inner.local_file(&self.down(key))
    }

    fn supports_watch(&self) -> bool {
        self.inner.supports_watch()
    }

    async fn watch(&self, prefix: &str) -> Result<Option<ChangeStream>, StorageError> {
        self.inner.watch(&self.down(prefix)).await
    }

    /// `false` — an un-migrated store is mid-transition; GC must not prune until `boatramp migrate` +
    /// the blob re-home drain have run (drain-then-finalize).
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
        fn has(&self, key: &str) -> bool {
            self.data.lock().unwrap().contains_key(key)
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
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let full = self.get(key).await?;
            let bytes = Bytes::from(collect(full.body).await);
            let start = (offset as usize).min(bytes.len());
            let end = len
                .map(|l| (start + l as usize).min(bytes.len()))
                .unwrap_or(bytes.len());
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

    /// `hblob/` default-scope translators (new→old strips `default/`; old→new inserts it, leaving a
    /// named project / already-`default/` key alone) — the boatramp-node `blobs` translators, mirrored.
    fn hblob_translators() -> (KeyTranslate, KeyTranslate) {
        let to_old: KeyTranslate = Arc::new(|k: &str| {
            let rest = k.strip_prefix("hblob/")?;
            let suffix = rest.strip_prefix("default/")?;
            Some(format!("hblob/{suffix}"))
        });
        let to_new: KeyTranslate = Arc::new(|k: &str| {
            let rest = k.strip_prefix("hblob/")?;
            let first = rest.split('/').next().unwrap_or("");
            if first.is_empty() || first == "default" || first == "acme" {
                return None; // already new, or a named project (`acme`)
            }
            Some(format!("hblob/default/{rest}"))
        });
        (to_old, to_new)
    }
    fn wrap(inner: Arc<dyn Storage>) -> TranslatingStorage {
        let (to_old, to_new) = hblob_translators();
        TranslatingStorage::new(inner, to_old, to_new)
    }

    #[tokio::test]
    async fn new_spelling_reads_writes_and_deletes_hit_the_old_key() {
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/blog/obj", b"from-old");
        let s = wrap(mem.clone());
        // READ new spelling → served from the old bare key.
        let got = s.get("hblob/default/blog/obj").await.unwrap();
        assert_eq!(collect(got.body).await, b"from-old");
        // WRITE new spelling → lands on the OLD key (not the new one).
        s.put(
            "hblob/default/blog/new",
            stream(Bytes::from_static(b"x")),
            PutMeta::default(),
        )
        .await
        .unwrap();
        assert!(
            mem.has("hblob/blog/new"),
            "write must land on the bare old key"
        );
        assert!(
            !mem.has("hblob/default/blog/new"),
            "write must NOT create a new-spelling key"
        );
        // DELETE new spelling → removes the old key.
        s.delete("hblob/default/blog/new").await.unwrap();
        assert!(!mem.has("hblob/blog/new"));
    }

    #[tokio::test]
    async fn cas_and_named_project_keys_pass_through_untranslated() {
        let mem = Arc::new(Mem::default());
        mem.seed("ab/deadbeef", b"component-wasm"); // content-addressed CAS (global, not re-homed)
        mem.seed("hblob/acme/shop/logo", b"tenant"); // named tenant project
        let s = wrap(mem.clone());
        // CAS: to_old returns None → key untouched → served from the same global key.
        assert_eq!(
            collect(s.get("ab/deadbeef").await.unwrap().body).await,
            b"component-wasm"
        );
        s.put(
            "cd/feedface",
            stream(Bytes::from_static(b"c2")),
            PutMeta::default(),
        )
        .await
        .unwrap();
        assert!(mem.has("cd/feedface"), "a CAS write is not translated");
        // Named tenant key: not `default/` → passes through unchanged (never wrongly stripped).
        assert_eq!(
            collect(s.get("hblob/acme/shop/logo").await.unwrap().body).await,
            b"tenant"
        );
    }

    #[tokio::test]
    async fn scoped_list_maps_old_keys_back_to_new_and_leaves_the_tenant() {
        let mem = Arc::new(Mem::default());
        mem.seed("hblob/blog/a", b"A");
        mem.seed("hblob/acme/shop/b", b"B"); // tenant
        let s = wrap(mem.clone());
        // Scoped list of the default's objects → new spelling.
        let keys: Vec<String> = s
            .list("hblob/default/blog/")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect();
        assert_eq!(keys, vec!["hblob/default/blog/a".to_string()]);
        // Family-wide list: default mapped up, tenant left verbatim.
        let mut all: Vec<String> = s
            .list("hblob/")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect();
        all.sort();
        assert_eq!(
            all,
            vec![
                "hblob/acme/shop/b".to_string(),
                "hblob/default/blog/a".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn prune_is_disabled_during_the_transition() {
        assert!(!wrap(Arc::new(Mem::default())).allows_prune());
    }
}
