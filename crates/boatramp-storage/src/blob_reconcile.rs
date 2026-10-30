//! **Guarded blob reconcile + targeted legacy-derivative purge** (PLAN-clone-robustness #4 + #5) —
//! the two opinionated repair engines over the guest blob keyspace (`hblob/…`), both gated by the
//! ONE shared integrity boundary [`boatramp_core::blob_class`].
//!
//! Both repair a backend whose index↔object agreement drifted (the stale/truncated-derivative shape
//! that fail-closes a streaming clone). The load-bearing security property — the one a Security
//! review checks — is that NEITHER engine blesses or deletes LOAD-BEARING data by default:
//!
//! - [`reconcile`] "blesses" whatever is stored, by recomputing an object's declared size from the
//!   bytes actually readable and re-writing it so the backend's metadata agrees with its body. That
//!   is SAFE for a re-generable `der/` derivative (it self-heals / regenerates on next access) but
//!   DANGEROUS for a baseline / primary object (it would make the index agree with a truncation).
//!   So reconcile is DEFAULT-scoped to `der/` derivatives; a baseline/primary object is skipped
//!   unless the explicit, audited [`ReconcileOptions::include_primary`] opt-in is set (and even then
//!   it warns). Dry-run by default (report-then-confirm); `apply` writes.
//! - [`purge_legacy_derivatives`] deletes stale derivatives of a SUPERSEDED image format (the
//!   pre-WEBP `.jpg` leftovers). It deletes ONLY objects [`is_superseded_derivative`] accepts — a
//!   `der/` object whose extension is the named superseded one — so a referenced baseline/primary,
//!   and a current-format derivative, are NEVER touched, whatever their extension. Dry-run by
//!   default; `apply` deletes.
//!
//! Neither engine ever reaches a non-blob (DB/KV) store — they operate purely on a [`Storage`]
//! backend, scoped by a key `prefix` (e.g. `hblob/<project>/`), with the classifier as the inner
//! guard. The scope decisions live in pure helpers on [`boatramp_core::blob_class`], unit-tested
//! exhaustively there; these engines are tested here against a fault-injecting fake backend that
//! proves the der-vs-primary boundary is load-bearing (flip the class, flip the outcome).

use std::sync::Arc;

use boatramp_core::blob_class::{BlobClass, classify_blob_key, is_superseded_derivative};
use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use futures::StreamExt;

/// An error running a reconcile / legacy-purge pass — a storage failure enumerating or writing.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// An underlying storage error (list/head/get/put/delete).
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Options for a [`reconcile`] run.
#[derive(Debug, Clone)]
pub struct ReconcileOptions {
    /// Restrict the scan to objects under this key prefix (e.g. `hblob/<project>/`). Empty = the
    /// whole backend keyspace.
    pub prefix: String,
    /// Actually re-write the drifted objects (default: dry-run — report what WOULD be reconciled,
    /// write nothing).
    pub apply: bool,
    /// DANGEROUS, audited opt-in: ALSO reconcile baseline / primary objects, not just re-generable
    /// `der/` derivatives. Off by default — a primary-blob reconcile blesses a truncation on
    /// load-bearing data, so it needs an explicit decision. Even on, every such object is warned.
    pub include_primary: bool,
    /// Never buffer an object larger than this many bytes (a safety ceiling — a derivative is
    /// small; this guards an `include_primary` run from reading a huge primary into memory). An
    /// object over the ceiling is counted `skipped_too_large` and left untouched.
    pub max_object_bytes: u64,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            apply: false,
            include_primary: false,
            max_object_bytes: 64 * 1024 * 1024,
        }
    }
}

/// The outcome of a [`reconcile`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Objects IN SCOPE examined (der/ always; baseline/primary only under `include_primary`).
    pub considered: u64,
    /// In-scope objects whose readable byte count disagreed with their declared metadata size.
    pub drifted: u64,
    /// Drifted objects actually re-written to bless the stored bytes (`apply`).
    pub reconciled: u64,
    /// Drifted objects that WOULD be reconciled (dry-run — nothing written).
    pub would_reconcile: u64,
    /// Baseline/primary objects SKIPPED because they are out of the default `der/` scope (and
    /// `include_primary` was not set) — the integrity guard, surfaced so the operator sees it.
    pub skipped_out_of_scope: u64,
    /// Objects skipped because they exceed `max_object_bytes` (not buffered).
    pub skipped_too_large: u64,
    /// Objects skipped because their body could not be read (a `get` error) — reconcile cannot
    /// bless bytes it cannot read.
    pub skipped_unreadable: u64,
    /// Total stored bytes re-written (`apply`).
    pub bytes_reconciled: u64,
}

/// Reconcile the declared size of each in-scope object under `opts.prefix` to the bytes actually
/// readable from it — "bless the store". For each object:
/// - classify it ([`boatramp_core::blob_class`]). A baseline/primary object is SKIPPED
///   (`skipped_out_of_scope`) unless `opts.include_primary`; a `der/` derivative is always in scope.
/// - read its body (bounded by `max_object_bytes`) and compare the actual byte count to the
///   backend's declared `head` size. On a drift, re-`put` the read bytes (`apply`) so the metadata
///   agrees with the body, else count `would_reconcile`.
///
/// Read-only on an object whose metadata already matches its body (no needless re-write). Returns a
/// [`ReconcileReport`]; a storage error ENUMERATING the keyspace aborts (returns `Err`), while a
/// per-object read error is fail-soft (`skipped_unreadable`, the pass continues).
pub async fn reconcile(
    storage: Arc<dyn Storage>,
    opts: &ReconcileOptions,
) -> Result<ReconcileReport, ReconcileError> {
    let mut report = ReconcileReport::default();
    let metas = storage.list(&opts.prefix).await?;
    for meta in metas {
        let key = meta.key;
        let class = classify_blob_key(&key);
        let in_scope = class == BlobClass::Derivative || opts.include_primary;
        if !in_scope {
            report.skipped_out_of_scope += 1;
            continue;
        }
        if class != BlobClass::Derivative {
            // include_primary is set — loudly record each load-bearing object we are about to bless.
            tracing::warn!(
                blob = %key, class = class.label(),
                "blob reconcile: blessing a NON-derivative (baseline/primary) object under \
                 --include-primary — this makes the index agree with the stored bytes even if they \
                 are truncated/corrupt"
            );
        }

        // The declared (metadata) size the backend reports via `head`.
        let declared = storage.head(&key).await?.size;

        // Read the body, bounded by the ceiling, counting the ACTUAL bytes.
        let (actual, buffered) = match read_bounded(&storage, &key, opts.max_object_bytes).await {
            Ok(Some(b)) => (b.len() as u64, b),
            Ok(None) => {
                report.skipped_too_large += 1;
                continue;
            }
            Err(_) => {
                report.skipped_unreadable += 1;
                continue;
            }
        };
        report.considered += 1;

        // A drift is "the backend's declared size disagrees with the readable bytes". A backend
        // that reports no declared size (`None`) can't be confirmed in agreement, so a reconcile
        // still normalises it (re-put stamps a known size) — treat `None` as a drift to repair.
        let drifted = declared != Some(actual);
        if !drifted {
            continue;
        }
        report.drifted += 1;
        if opts.apply {
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(buffered)) }).boxed();
            storage
                .put(&key, body, PutMeta::default())
                .await
                .map_err(ReconcileError::Storage)?;
            report.reconciled += 1;
            report.bytes_reconciled += actual;
        } else {
            report.would_reconcile += 1;
        }
    }
    Ok(report)
}

/// Read an object's body fully into memory, counting bytes, but ABORT (returning `Ok(None)`) if it
/// exceeds `max_bytes` — so a reconcile never buffers an unexpectedly large object. A `get` /
/// stream error is an `Err`.
async fn read_bounded(
    storage: &Arc<dyn Storage>,
    key: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, StorageError> {
    let obj = storage.get(key).await?;
    let mut body = obj.body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if buf.len() as u64 + chunk.len() as u64 > max_bytes {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf))
}

/// Options for a [`purge_legacy_derivatives`] run.
#[derive(Debug, Clone)]
pub struct LegacyPurgeOptions {
    /// Restrict the scan to objects under this key prefix (e.g. `hblob/<project>/`). Empty = all.
    pub prefix: String,
    /// Actually delete (default: dry-run — report what WOULD be purged, delete nothing).
    pub apply: bool,
    /// The SUPERSEDED image extension to purge (e.g. `jpg`), lower-cased; a leading dot is
    /// tolerated. ONLY `der/` objects with this extension are deleted — never a baseline/primary,
    /// never the current format.
    pub superseded_ext: String,
}

/// The outcome of a [`purge_legacy_derivatives`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyPurgeReport {
    /// Objects examined under the prefix.
    pub considered: u64,
    /// Superseded-format `der/` objects deleted (`apply`).
    pub purged: u64,
    /// Superseded-format `der/` objects that WOULD be deleted (dry-run).
    pub would_purge: u64,
    /// Objects left untouched because they are NOT a superseded-format derivative (a baseline, a
    /// primary, or a current-format derivative) — the structural guard, surfaced.
    pub skipped_not_superseded: u64,
    /// Bytes deleted (`apply`).
    pub bytes_purged: u64,
}

/// Delete stale derivatives of a SUPERSEDED image format under `opts.prefix` — the targeted
/// legacy-`.jpg` cleanup. For each object, [`is_superseded_derivative`] decides: ONLY a `der/`
/// object whose extension is `opts.superseded_ext` is deletable; everything else (a baseline, a
/// primary/original, or a current-format derivative) is kept (`skipped_not_superseded`), whatever
/// its extension. Deletes self-heal — a dropped derivative is regenerated on next access.
///
/// Dry-run unless `opts.apply`. Returns a [`LegacyPurgeReport`]; a storage error enumerating or
/// deleting returns `Err`.
pub async fn purge_legacy_derivatives(
    storage: Arc<dyn Storage>,
    opts: &LegacyPurgeOptions,
) -> Result<LegacyPurgeReport, ReconcileError> {
    let mut report = LegacyPurgeReport::default();
    let metas = storage.list(&opts.prefix).await?;
    for meta in metas {
        let key = meta.key;
        report.considered += 1;
        if !is_superseded_derivative(&key, &opts.superseded_ext) {
            report.skipped_not_superseded += 1;
            continue;
        }
        let size = meta.size.or(storage.head(&key).await.ok().and_then(|m| m.size));
        if opts.apply {
            storage.delete(&key).await?;
            report.purged += 1;
            report.bytes_purged += size.unwrap_or(0);
        } else {
            report.would_purge += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::{GetObject, ListPage, ObjectMeta};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A fault-injecting in-memory backend: each object carries an optional DECLARED-size override
    /// so a test can create the declared≠stored drift (`head` returns the override; `get` returns
    /// the real bytes). A `put` writes the real bytes and CLEARS the override (declared == stored
    /// again — the reconcile fix), a `delete` removes it.
    /// key -> (declared-size override, bytes). A `Some` override is the fault injection that makes
    /// `head` report a size different from the real body `get` returns (the declared≠stored drift).
    type FakeObj = (Option<u64>, Vec<u8>);

    #[derive(Default)]
    struct FakeBlobs {
        objs: Mutex<HashMap<String, FakeObj>>,
    }
    impl FakeBlobs {
        fn insert(&self, key: &str, declared: Option<u64>, bytes: &[u8]) {
            self.objs
                .lock()
                .unwrap()
                .insert(key.to_string(), (declared, bytes.to_vec()));
        }
        fn has(&self, key: &str) -> bool {
            self.objs.lock().unwrap().contains_key(key)
        }
        fn head_size(&self, key: &str) -> Option<u64> {
            let m = self.objs.lock().unwrap();
            m.get(key).map(|(d, b)| d.unwrap_or(b.len() as u64))
        }
    }

    #[async_trait::async_trait]
    impl Storage for FakeBlobs {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let bytes = self
                .objs
                .lock()
                .unwrap()
                .get(key)
                .map(|(_, b)| b.clone())
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let size = bytes.len() as u64;
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(size),
                    ..Default::default()
                },
                body,
            })
        }
        async fn get_range(
            &self,
            key: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            let size = buf.len() as u64;
            // A put normalises: declared size is cleared, so head == body afterwards.
            self.objs
                .lock()
                .unwrap()
                .insert(key.to_string(), (None, buf));
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                ..Default::default()
            })
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let size = self
                .head_size(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                ..Default::default()
            })
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.objs.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            let m = self.objs.lock().unwrap();
            let mut v: Vec<ObjectMeta> = m
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, (d, b))| ObjectMeta {
                    key: k.clone(),
                    size: Some(d.unwrap_or(b.len() as u64)),
                    ..Default::default()
                })
                .collect();
            v.sort_by(|a, b| a.key.cmp(&b.key));
            Ok(v)
        }
        async fn list_page(
            &self,
            prefix: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ListPage, StorageError> {
            Ok(ListPage {
                metas: self.list(prefix).await?,
                cursor: None,
            })
        }
    }

    const DER: &str = "hblob/acme/blog/img/der/abc/512.jpg";
    const BASE: &str = "hblob/acme/blog/img/base/abc.jpg";

    /// THE mutation-verified reconcile boundary: a DRIFTED `der/` object is reconciled under the
    /// default scope, but a DRIFTED `base/` (baseline) object is NOT — it is skipped out of scope.
    /// Flip the class, flip the outcome.
    #[tokio::test]
    async fn reconcile_blesses_a_der_drift_but_skips_a_baseline_by_default() {
        let fake = Arc::new(FakeBlobs::default());
        // Both DRIFTED: head declares 26599 but only 9 bytes are stored.
        fake.insert(DER, Some(26599), b"truncated");
        fake.insert(BASE, Some(26599), b"truncated");

        let opts = ReconcileOptions {
            prefix: "hblob/".into(),
            apply: true,
            include_primary: false,
            ..Default::default()
        };
        let rep = reconcile(fake.clone(), &opts).await.unwrap();
        assert_eq!(rep.considered, 1, "only the der/ object is in scope");
        assert_eq!(rep.drifted, 1);
        assert_eq!(rep.reconciled, 1, "the der/ drift is blessed");
        assert_eq!(rep.skipped_out_of_scope, 1, "the baseline is skipped by default");
        // The der/ object's declared size now matches its body (9), the baseline still drifts (26599).
        assert_eq!(fake.head_size(DER), Some(9), "der/ declared size blessed to the stored 9 bytes");
        assert_eq!(
            fake.head_size(BASE),
            Some(26599),
            "the baseline is UNTOUCHED — its index drift is preserved, not silently blessed"
        );
    }

    /// MUTATION FLIP: the audited `include_primary` opt-in DOES reconcile the baseline too — proving
    /// the default scope (not some unrelated condition) is what spared it above.
    #[tokio::test]
    async fn reconcile_include_primary_also_blesses_a_baseline() {
        let fake = Arc::new(FakeBlobs::default());
        fake.insert(BASE, Some(26599), b"truncated");
        let opts = ReconcileOptions {
            prefix: "hblob/".into(),
            apply: true,
            include_primary: true,
            ..Default::default()
        };
        let rep = reconcile(fake.clone(), &opts).await.unwrap();
        assert_eq!(rep.considered, 1);
        assert_eq!(rep.reconciled, 1, "include_primary reconciles the baseline");
        assert_eq!(rep.skipped_out_of_scope, 0);
        assert_eq!(fake.head_size(BASE), Some(9));
    }

    /// A dry-run never writes: a der/ drift is counted `would_reconcile`, the object is unchanged.
    #[tokio::test]
    async fn reconcile_dry_run_writes_nothing() {
        let fake = Arc::new(FakeBlobs::default());
        fake.insert(DER, Some(26599), b"truncated");
        let opts = ReconcileOptions {
            prefix: "hblob/".into(),
            apply: false,
            ..Default::default()
        };
        let rep = reconcile(fake.clone(), &opts).await.unwrap();
        assert_eq!(rep.drifted, 1);
        assert_eq!(rep.would_reconcile, 1);
        assert_eq!(rep.reconciled, 0);
        assert_eq!(fake.head_size(DER), Some(26599), "dry-run left the drift in place");
    }

    /// An object whose declared size already matches its body is not re-written.
    #[tokio::test]
    async fn reconcile_leaves_a_consistent_object_alone() {
        let fake = Arc::new(FakeBlobs::default());
        fake.insert(DER, None, b"consistent"); // declared == body
        let opts = ReconcileOptions {
            prefix: "hblob/".into(),
            apply: true,
            ..Default::default()
        };
        let rep = reconcile(fake, &opts).await.unwrap();
        assert_eq!(rep.considered, 1);
        assert_eq!(rep.drifted, 0);
        assert_eq!(rep.reconciled, 0);
    }

    /// THE mutation-verified legacy-purge boundary: a superseded-format `der/.jpg` is deleted, but a
    /// `base/.jpg` (same extension!) and a current-format `der/.webp` are NEVER deleted.
    #[tokio::test]
    async fn legacy_purge_drops_only_superseded_der_objects() {
        let fake = Arc::new(FakeBlobs::default());
        let der_jpg = "hblob/acme/blog/img/der/abc/512.jpg";
        let der_webp = "hblob/acme/blog/img/der/abc/512.webp";
        let base_jpg = "hblob/acme/blog/img/base/abc.jpg";
        let primary_jpg = "hblob/acme/blog/photo.jpg";
        fake.insert(der_jpg, None, b"stale-jpg");
        fake.insert(der_webp, None, b"current-webp");
        fake.insert(base_jpg, None, b"baseline-jpg");
        fake.insert(primary_jpg, None, b"primary-jpg");

        let opts = LegacyPurgeOptions {
            prefix: "hblob/".into(),
            apply: true,
            superseded_ext: "jpg".into(),
        };
        let rep = purge_legacy_derivatives(fake.clone(), &opts).await.unwrap();
        assert_eq!(rep.considered, 4);
        assert_eq!(rep.purged, 1, "only the der/.jpg is purged");
        assert_eq!(rep.skipped_not_superseded, 3);
        assert!(!fake.has(der_jpg), "the superseded der/.jpg is gone");
        // The load-bearing guard: a baseline with the SAME extension, a primary, and the current
        // derivative are ALL preserved.
        assert!(fake.has(der_webp), "the current-format derivative survives");
        assert!(fake.has(base_jpg), "the baseline survives despite the matching .jpg extension");
        assert!(fake.has(primary_jpg), "the primary object survives");
    }

    /// Legacy-purge dry-run deletes nothing.
    #[tokio::test]
    async fn legacy_purge_dry_run_deletes_nothing() {
        let fake = Arc::new(FakeBlobs::default());
        let der_jpg = "hblob/acme/blog/img/der/abc/512.jpg";
        fake.insert(der_jpg, None, b"stale-jpg");
        let opts = LegacyPurgeOptions {
            prefix: "hblob/".into(),
            apply: false,
            superseded_ext: ".JPG".into(), // leading-dot + case normalised
        };
        let rep = purge_legacy_derivatives(fake.clone(), &opts).await.unwrap();
        assert_eq!(rep.would_purge, 1);
        assert_eq!(rep.purged, 0);
        assert!(fake.has(der_jpg), "dry-run kept the object");
    }
}
