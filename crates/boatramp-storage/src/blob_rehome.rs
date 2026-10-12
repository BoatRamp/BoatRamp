//! **Default-scope blob re-home** — the proactive drain + retire that moves the bare
//! default-scoped blob objects (`hblob/{site}/…`, `mqp/{topic}/…`, `mqgp/{topic}/…`) to their
//! two-segment `…/default/…` spelling on the SAME backend (v0.31.0 Finding 8, the blob substrate's
//! analogue of the `boatramp migrate` KV re-key).
//!
//! It is `blob_migrate`-style — enumerate (`list`) + `put` new + `head`-verify + idempotent-skip —
//! but it re-homes to a TRANSLATED key (old→new) within one backend rather than copying byte-identical
//! keys between two backends, and it never deletes the source until a separate **retire** pass runs
//! AFTER the copy verifies. The split mirrors the KV migration's forward (non-destructive copy) /
//! finalize (verify-then-delete):
//!
//! - [`drain`] — copy every re-homeable old key to its new key, `head`-verify, skip a new key already
//!   present at matching size, and **NEVER delete** the source. Safe to re-run (idempotent).
//! - [`retire`] — delete each old key ONLY after confirming its new key is `head`-present at matching
//!   size. Refuses to delete an old key whose new key is absent/short — so a partial drain never
//!   loses data. This is the destructive finalize, run after the soak + a verified drain.
//!
//! The `to_new` translator (old→new) is supplied by the caller (`boatramp-node`) and is
//! project-aware: it returns `Some(new)` only for a BARE default scope (a key whose scope segment is
//! not a known project), and `None` for a named project's key or an already-re-homed `…/default/…`
//! key — so named projects are never touched and a re-run is a no-op.

use std::sync::Arc;

use boatramp_core::{PutMeta, Storage, StorageError};

use crate::translating_fallback::KeyTranslate;
#[cfg(feature = "default-scope-gate-mutation")]
use crate::translating_fallback::gate_mutation;

/// Options for a [`drain`]/[`retire`] pass.
#[derive(Clone)]
pub struct RehomeOptions {
    /// The family prefixes to enumerate (e.g. `["hblob/", "mqp/", "mqgp/"]`).
    pub prefixes: Vec<String>,
    /// Old→new key translator (project-aware); `None` ⇒ leave the key alone.
    pub to_new: KeyTranslate,
    /// Classify/would-copy only; write + delete nothing.
    pub dry_run: bool,
}

/// A summary of a [`drain`]/[`retire`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RehomeReport {
    /// Re-homeable old keys enumerated.
    pub total: u64,
    /// Objects copied old→new (drain) — or that WOULD be (dry-run).
    pub copied: u64,
    /// Objects skipped because the new key was already present at matching size.
    pub skipped: u64,
    /// Old keys deleted (retire) — or that WOULD be (dry-run).
    pub deleted: u64,
}

/// A failure running a re-home pass.
#[derive(Debug, thiserror::Error)]
pub enum RehomeError {
    /// A storage op failed.
    #[error("blob re-home storage: {0}")]
    Storage(#[from] StorageError),
    /// A copied object failed its post-copy `head` verification (missing or short at the new key).
    #[error("verification FAILED: new key {new:?} absent/short after copying from {old:?}")]
    Verify {
        /// The source (old) key.
        old: String,
        /// The destination (new) key that did not verify.
        new: String,
    },
}

/// Every re-homeable `(old, new)` pair under `opts.prefixes` on `storage`, newest-key-last.
async fn pairs(
    storage: &Arc<dyn Storage>,
    opts: &RehomeOptions,
) -> Result<Vec<(String, String, u64)>, RehomeError> {
    let mut out = Vec::new();
    for prefix in &opts.prefixes {
        for meta in storage.list(prefix).await? {
            if let Some(new) = (opts.to_new)(&meta.key)
                && new != meta.key
            {
                out.push((meta.key, new, meta.size.unwrap_or(0)));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// **Drain** (non-destructive): copy every re-homeable old key to its new key, `head`-verify, skip a
/// new key already present at matching size. NEVER deletes the source. Idempotent/resumable.
pub async fn drain(
    storage: Arc<dyn Storage>,
    opts: &RehomeOptions,
) -> Result<RehomeReport, RehomeError> {
    let mut report = RehomeReport::default();
    for (old, new, old_size) in pairs(&storage, opts).await? {
        report.total += 1;
        // Idempotent skip: new already present at matching size.
        if let Ok(meta) = storage.head(&new).await
            && meta.size == Some(old_size)
        {
            report.skipped += 1;
            continue;
        }
        if opts.dry_run {
            report.copied += 1;
            continue;
        }
        let got = storage.get(&old).await?;
        let ct = got.meta.content_type.clone();
        storage
            .put(&new, got.body, PutMeta { content_type: ct })
            .await?;
        // Post-copy verify: the new key must now be head-present at the source size.
        match storage.head(&new).await {
            Ok(meta) if meta.size == Some(old_size) => {}
            _ => return Err(RehomeError::Verify { old, new }),
        }
        report.copied += 1;
    }
    Ok(report)
}

/// **Retire** (destructive finalize): delete each old key ONLY after confirming its new key is
/// `head`-present at matching size. Refuses to delete an old key whose new key is absent/short.
pub async fn retire(
    storage: Arc<dyn Storage>,
    opts: &RehomeOptions,
) -> Result<RehomeReport, RehomeError> {
    let mut report = RehomeReport::default();
    for (old, new, old_size) in pairs(&storage, opts).await? {
        report.total += 1;

        // GATE MUTATION SEAM: delete the source WITHOUT first verifying the new key is present at
        // matching size — the exact "delete before verify" regression. The gate seeds a case where
        // the new key is absent and asserts the old key SURVIVES retire; under this mutation it is
        // deleted ⇒ the gate goes RED.
        #[cfg(feature = "default-scope-gate-mutation")]
        if gate_mutation::env_on("BOATRAMP_DEFAULTSCOPE_MUTATE_RETIRE_BEFORE_VERIFY") {
            if !opts.dry_run {
                storage.delete(&old).await?;
            }
            report.deleted += 1;
            continue;
        }

        // Verify the new key is present at matching size BEFORE deleting the old one.
        let verified = matches!(storage.head(&new).await, Ok(meta) if meta.size == Some(old_size));
        if !verified {
            return Err(RehomeError::Verify { old, new });
        }
        if opts.dry_run {
            report.deleted += 1;
            continue;
        }
        storage.delete(&old).await?;
        report.deleted += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translating_fallback::TranslatingFallbackStorage;
    use boatramp_core::ByteStream;
    use bytes::Bytes;
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct Mem {
        data: Mutex<HashMap<String, Bytes>>,
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
    #[async_trait::async_trait]
    impl Storage for Mem {
        async fn get(&self, key: &str) -> Result<boatramp_core::GetObject, StorageError> {
            let b = self
                .data
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(boatramp_core::GetObject {
                meta: boatramp_core::ObjectMeta {
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
            _o: u64,
            _l: Option<u64>,
        ) -> Result<boatramp_core::GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            _m: PutMeta,
        ) -> Result<boatramp_core::ObjectMeta, StorageError> {
            let b = Bytes::from(collect(body).await);
            let size = b.len() as u64;
            self.data.lock().unwrap().insert(key.to_string(), b);
            Ok(boatramp_core::ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                content_type: None,
                etag: None,
            })
        }
        async fn head(&self, key: &str) -> Result<boatramp_core::ObjectMeta, StorageError> {
            let d = self.data.lock().unwrap();
            let b = d
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(boatramp_core::ObjectMeta {
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
        async fn list(&self, prefix: &str) -> Result<Vec<boatramp_core::ObjectMeta>, StorageError> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| boatramp_core::ObjectMeta {
                    key: k.clone(),
                    size: Some(v.len() as u64),
                    content_type: None,
                    etag: None,
                })
                .collect())
        }
    }

    /// Project-aware old→new for `hblob/` with named projects `{acme}` known.
    fn to_new_hblob() -> KeyTranslate {
        Arc::new(|k: &str| {
            let rest = k.strip_prefix("hblob/")?;
            let first = rest.split('/').next().unwrap_or("");
            // Known projects (+ default) are left alone; `acme` is a named project in the fixtures.
            if first.is_empty() || first == "default" || first == "acme" {
                return None;
            }
            Some(format!("hblob/default/{rest}"))
        })
    }
    fn opts() -> RehomeOptions {
        RehomeOptions {
            prefixes: vec!["hblob/".into()],
            to_new: to_new_hblob(),
            dry_run: false,
        }
    }
    fn seed(mem: &Arc<Mem>, k: &str, v: &[u8]) {
        mem.data
            .lock()
            .unwrap()
            .insert(k.to_string(), Bytes::copy_from_slice(v));
    }
    fn has(mem: &Arc<Mem>, k: &str) -> bool {
        mem.data.lock().unwrap().contains_key(k)
    }

    #[tokio::test]
    async fn drain_copies_and_never_deletes_source() {
        let mem = Arc::new(Mem::default());
        seed(&mem, "hblob/blog/c/obj", b"data");
        seed(&mem, "hblob/acme/site/c/x", b"named"); // named project — untouched
        let storage: Arc<dyn Storage> = mem.clone();
        let r = drain(storage, &opts()).await.unwrap();
        assert_eq!(r.copied, 1);
        assert!(has(&mem, "hblob/default/blog/c/obj"), "new key written");
        assert!(
            has(&mem, "hblob/blog/c/obj"),
            "old key NEVER deleted by drain"
        );
        // Named project untouched.
        assert!(!has(&mem, "hblob/default/acme/site/c/x"));
        assert!(has(&mem, "hblob/acme/site/c/x"));
        // Idempotent re-run: already present at matching size ⇒ skipped.
        let r2 = drain(mem.clone() as Arc<dyn Storage>, &opts())
            .await
            .unwrap();
        assert_eq!(r2.copied, 0);
        assert_eq!(r2.skipped, 1);
    }

    #[tokio::test]
    async fn retire_deletes_old_only_after_new_verifies() {
        let mem = Arc::new(Mem::default());
        seed(&mem, "hblob/blog/c/obj", b"data");
        let storage: Arc<dyn Storage> = mem.clone();
        drain(storage.clone(), &opts()).await.unwrap();
        // New verified present → retire deletes old.
        let r = retire(storage, &opts()).await.unwrap();
        assert_eq!(r.deleted, 1);
        assert!(!has(&mem, "hblob/blog/c/obj"), "old deleted after verify");
        assert!(has(&mem, "hblob/default/blog/c/obj"), "new retained");
    }

    #[tokio::test]
    async fn retire_refuses_when_new_is_absent() {
        // No drain ran — the new key is absent; retire must REFUSE (never delete the source).
        let mem = Arc::new(Mem::default());
        seed(&mem, "hblob/blog/c/obj", b"data");
        let err = retire(mem.clone() as Arc<dyn Storage>, &opts()).await;
        assert!(matches!(err, Err(RehomeError::Verify { .. })));
        assert!(
            has(&mem, "hblob/blog/c/obj"),
            "source survives a failed verify"
        );
    }

    #[tokio::test]
    async fn fallback_then_drain_then_retire_round_trip() {
        // End-to-end: datum at the OLD key, the translating fallback serves it at the NEW spelling,
        // the drain re-homes it, and retire deletes the old key.
        let mem = Arc::new(Mem::default());
        seed(&mem, "hblob/blog/c/obj", b"roundtrip");
        let to_old: KeyTranslate = Arc::new(|k: &str| {
            let rest = k.strip_prefix("hblob/")?;
            let suffix = rest.strip_prefix("default/")?;
            Some(format!("hblob/{suffix}"))
        });
        let fb = TranslatingFallbackStorage::new(
            mem.clone(),
            to_old,
            to_new_hblob(),
            Duration::from_secs(5),
        );
        let obj = fb.get("hblob/default/blog/c/obj").await.expect("fallback");
        assert_eq!(collect(obj.body).await, b"roundtrip");

        drain(mem.clone() as Arc<dyn Storage>, &opts())
            .await
            .unwrap();
        retire(mem.clone() as Arc<dyn Storage>, &opts())
            .await
            .unwrap();
        assert!(has(&mem, "hblob/default/blog/c/obj"));
        assert!(!has(&mem, "hblob/blog/c/obj"));
    }
}

// ================================================================================================
// The `DEFAULT-SCOPE FALLBACK OK` mutation-verified gate battery (anti-hollow).
//
// One `#[tokio::test]` proves, fs→fs in a tempdir: (1) the translating read-fallback serves an
// object that lives only at the OLD bare key when the runtime asks for the NEW `…/default/…`
// spelling; and (2) `retire` deletes an OLD key ONLY after its NEW key verifies present (copy
// -before-delete). Compiled ONLY under the `default-scope-gate-mutation` feature; each
// `BOATRAMP_DEFAULTSCOPE_MUTATE_*` env var neuters exactly ONE invariant so a clean run reaches the
// marker while every mutation PANICS before it. Mirrors the blob_migrate gate structure.
// ================================================================================================
#[cfg(all(test, feature = "default-scope-gate-mutation"))]
mod gate {
    use super::*;
    use crate::FsStorage;
    use crate::translating_fallback::TranslatingFallbackStorage;
    use boatramp_core::ByteStream;
    use bytes::Bytes;
    use futures::StreamExt;
    use std::time::Duration;

    fn to_old() -> KeyTranslate {
        Arc::new(|k: &str| {
            let rest = k.strip_prefix("hblob/")?;
            let suffix = rest.strip_prefix("default/")?;
            Some(format!("hblob/{suffix}"))
        })
    }
    fn to_new() -> KeyTranslate {
        Arc::new(|k: &str| {
            let rest = k.strip_prefix("hblob/")?;
            let first = rest.split('/').next().unwrap_or("");
            if first.is_empty() || first == "default" {
                return None;
            }
            Some(format!("hblob/default/{rest}"))
        })
    }
    async fn put(store: &Arc<dyn Storage>, key: &str, bytes: &[u8]) {
        let owned = bytes.to_vec();
        let body: ByteStream = futures::stream::once(async move { Ok(Bytes::from(owned)) }).boxed();
        store.put(key, body, PutMeta::default()).await.expect("put");
    }
    async fn collect(mut body: ByteStream) -> Vec<u8> {
        let mut buf = Vec::new();
        while let Some(c) = body.next().await {
            buf.extend_from_slice(&c.unwrap());
        }
        buf
    }

    #[tokio::test]
    async fn default_scope_fallback_gate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let opts = RehomeOptions {
            prefixes: vec!["hblob/".into()],
            to_new: to_new(),
            dry_run: false,
        };

        // (b.1) Read-fallback — on its OWN backend so the fallback's async background copy can never
        // race the (b.2) copy-before-delete check below. The datum exists ONLY at the OLD bare key
        // (pre-flip spelling); the runtime (post-flip) asks for the NEW spelling; the fallback must
        // serve the old datum. DISABLE_FALLBACK makes this miss ⇒ the `expect` panics ⇒ marker absent.
        let read_backend: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("read")));
        put(&read_backend, "hblob/blog/c/obj", b"old-datum").await;
        let fb = TranslatingFallbackStorage::new(
            read_backend.clone(),
            to_old(),
            to_new(),
            Duration::from_secs(5),
        );
        let served = fb
            .get("hblob/default/blog/c/obj")
            .await
            .expect("read-fallback must serve the old datum at the new spelling");
        assert_eq!(
            collect(served.body).await,
            b"old-datum",
            "fallback served wrong bytes"
        );

        // (b.2) Copy-before-delete — on a FRESH backend (no fallback, so nothing pre-populates the
        // new key). With NO drain yet the new key is absent, so retire must REFUSE to delete the old
        // key. RETIRE_BEFORE_VERIFY deletes it anyway ⇒ the asserts below fire.
        let backend: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("retire")));
        put(&backend, "hblob/blog/c/obj", b"old-datum").await;
        let retire_result = retire(backend.clone(), &opts).await;
        assert!(
            backend.head("hblob/blog/c/obj").await.is_ok(),
            "retire deleted the OLD key before the NEW key verified (copy-before-delete violated)"
        );
        assert!(
            retire_result.is_err(),
            "retire must refuse (Verify error) when the new key is absent"
        );

        // Now a real drain re-homes it, and retire deletes the old key only after verify.
        drain(backend.clone(), &opts).await.expect("drain");
        assert!(
            backend.head("hblob/default/blog/c/obj").await.is_ok(),
            "drain must copy old→new"
        );
        assert!(
            backend.head("hblob/blog/c/obj").await.is_ok(),
            "drain must NOT delete the source"
        );
        retire(backend.clone(), &opts)
            .await
            .expect("retire after drain");
        assert!(
            backend.head("hblob/blog/c/obj").await.is_err(),
            "retire must delete the old key after the new key verifies"
        );

        println!(
            "DEFAULT-SCOPE FALLBACK OK: the translating blob read-fallback serves a bare \
             default-scoped object at its new default/ spelling and the re-home retire deletes the \
             old key only after the new key verifies (copy-before-delete). Mutation-verified: \
             BOATRAMP_DEFAULTSCOPE_MUTATE_DISABLE_FALLBACK=1 and \
             BOATRAMP_DEFAULTSCOPE_MUTATE_RETIRE_BEFORE_VERIFY=1 each FAIL this gate."
        );
    }
}
