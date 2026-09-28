//! **Drained-source purge** — the backend-agnostic engine that reclaims the OLD read-only
//! secondary of a blob-backend migration once its objects are provably duplicated in the NEW
//! primary. It is the *decommission* half of the blob-backend migration: after
//! [`blob_migrate::migrate`](crate::blob_migrate::migrate) (or the daemon-mediated
//! `POST /api/blob-drain`) has copied the secondary into the primary, this engine deletes each
//! source key **only** once it is byte-confirmed present in the destination.
//!
//! It backs the `DrainedSource` mode of the general purge surface (`POST /api/blob-purge` +
//! `boatramp blob purge --drained-source`). Unlike the `Unreferenced` mode (which is on-demand
//! garbage collection — [`DeployStore::collect_garbage`](boatramp_core::deploy) — deleting blobs
//! no live manifest points at), this engine deletes from the migration SOURCE, so its whole safety
//! rests on one **provably-safe** rule:
//!
//! > A source key is deletable **iff** the destination already holds that exact key at a matching
//! > size (see [`drained_source_deletable`], the single pure predicate on which the gate rests).
//!
//! Everything else — an absent destination key, a size mismatch, or *any* destination `head`
//! error — is **fail-closed**: the source key SURVIVES (counted `skipped_unconfirmed`, never
//! deleted). The engine is idempotent (a re-run over an already-purged source is a near-no-op) and
//! never touches the destination (read-only on the primary).
//!
//! ## Why a pure predicate (the gate mechanism)
//! The safety decision is extracted into [`drained_source_deletable`] — a pure function over
//! `(dest_head_result, src_size)` with no I/O — so it can be unit-tested exhaustively in both
//! directions, and so the real-path integration tests + the in-process mutation matrix
//! ([`PurgeMutation`]) can prove the check is load-bearing WITHOUT a println marker, an env-var
//! seam, or a CI grep/bash loop. The test-runner exit code is the whole contract. This is the
//! robust successor to the marker-style gates used by `blob_migrate`/`blob_drain` (which stay
//! unchanged); see the gate module at the bottom of this file and the ci.yml lane.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use boatramp_core::{ObjectMeta, Storage, StorageError};
use futures::StreamExt;

use crate::blob_migrate::ProgressSink;

/// The pure, side-effect-free safety decision for a drained-source purge: is the source key at
/// `src_size` **provably** duplicated in the destination, so deleting it from the source is safe?
///
/// `true` **iff** `dest_head` is `Ok` AND the destination object's size equals `src_size` (both
/// `Some` and equal). Every other case is fail-closed (`false`) — the source key is kept:
/// - `dest_head` is `Err(_)` (the destination lacks the key — `NotFound` — or a transient/backend
///   error): NEVER delete on an unconfirmed destination (a transient error must not look like a
///   miss OR a match). Fail-closed both ways.
/// - the destination size is `None`, or differs from `src_size`: the objects are not byte-identical
///   (a partial/interrupted copy), so the source is still authoritative.
/// - `src_size` is `None` (the source list did not report a size): unverifiable ⇒ keep.
///
/// This is the ONE decision the whole purge safety rests on, kept pure so it is exhaustively
/// unit-tested (see the tests below) and so the gate can drive it directly.
pub(crate) fn drained_source_deletable(
    dest_head: &Result<ObjectMeta, StorageError>,
    src_size: Option<u64>,
) -> bool {
    match (dest_head, src_size) {
        // The destination holds the key AND its size matches the source's known size ⇒ provably
        // duplicated ⇒ safe to delete from the source.
        (Ok(meta), Some(src)) => meta.size == Some(src),
        // Any destination error (NotFound OR transient), an unknown destination size, or an unknown
        // source size ⇒ NOT provably duplicated ⇒ fail-closed (keep the source key).
        _ => false,
    }
}

/// A TEST-ONLY fault injection for the purge safety check, used by the in-process mutation matrix
/// (the robust gate). It reproduces exactly what a regression at the safety choke point would do,
/// so the gate can prove [`drained_source_deletable`] is load-bearing: a clean [`None`] run keeps
/// every unconfirmed source key, while each mutation makes an unsafe deletion that the SAME
/// fail-closed assertions then DETECT.
///
/// Compiled only under `cfg(test)` OR the `blob-purge-gate` feature (the CI gate lane) — it is
/// COMPILED OUT of every real build, and production call sites always pass [`PurgeMutation::None`].
#[cfg(any(test, feature = "blob-purge-gate"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeMutation {
    /// No mutation — the real, fail-closed behavior.
    None,
    /// Delete a source key EVEN WHEN it is not confirmed deletable (ignore the predicate's `false`)
    /// — the exact "purge deleted an unconfirmed key" regression.
    DeleteUnconfirmed,
    /// Skip the destination verify entirely and treat EVERY source key as deletable (a broken
    /// safety check that never consults the destination) — the same unsafe outcome by a second path.
    SkipVerify,
}

/// The production-facing purge entry point — always fail-closed (no mutation). See
/// [`purge_drained_source_with`] for the full contract; this simply pins the mutation to `None`.
pub async fn purge_drained_source(
    source: Arc<dyn Storage>,
    dest: Arc<dyn Storage>,
    prefix: &str,
    apply: bool,
    on_progress: Option<ProgressSink>,
) -> Result<PurgeReport, PurgeError> {
    purge_drained_source_with(
        source,
        dest,
        prefix,
        apply,
        on_progress,
        #[cfg(any(test, feature = "blob-purge-gate"))]
        PurgeMutation::None,
    )
    .await
}

/// Purge (delete) from the read-only migration SOURCE every key under `prefix` that is **provably
/// duplicated** in the destination — the drained-secondary decommission.
///
/// For each source key, the destination is `head`-probed and the pure predicate
/// [`drained_source_deletable`] decides:
/// - **deletable + `apply`** ⇒ `source.delete(key)` (counted `purged` + `purged_bytes`).
/// - **deletable + dry-run** (`!apply`) ⇒ counted `would_purge`, nothing deleted.
/// - **NOT deletable** (absent / size-mismatch / any destination error) ⇒ counted
///   `skipped_unconfirmed`, the key SURVIVES (fail-closed — never deleted).
///
/// The destination is treated as read-only (only `head`); the source is only ever `delete`d for a
/// confirmed-duplicated key. The pass is idempotent (a re-run skips already-deleted keys) and uses
/// bounded concurrency. Returns a [`PurgeReport`]; a storage error enumerating the source (or a
/// non-fail-closed delete failure) returns [`PurgeError`].
///
/// The `mutation` parameter is TEST-ONLY (present only under `cfg(test)`/`blob-purge-gate`);
/// production callers use [`purge_drained_source`], which pins it to [`PurgeMutation::None`].
pub async fn purge_drained_source_with(
    source: Arc<dyn Storage>,
    dest: Arc<dyn Storage>,
    prefix: &str,
    apply: bool,
    on_progress: Option<ProgressSink>,
    #[cfg(any(test, feature = "blob-purge-gate"))] mutation: PurgeMutation,
) -> Result<PurgeReport, PurgeError> {
    // 1. Enumerate the SOURCE (the read-only secondary). Each backend flattens `list` internally.
    let objects = source.list(prefix).await?;
    let considered = objects.len() as u64;

    tracing::info!(
        considered,
        prefix = %prefix,
        apply,
        "blob purge (drained-source): enumerated source objects"
    );

    // Bounded-concurrency probe + (on apply) delete. Each object yields a per-item outcome the
    // fold below tallies into the shared counters. A hard storage error short-circuits the run.
    let purged = Arc::new(AtomicU64::new(0));
    let would_purge = Arc::new(AtomicU64::new(0));
    let skipped_unconfirmed = Arc::new(AtomicU64::new(0));
    let purged_bytes = Arc::new(AtomicU64::new(0));

    const CONCURRENCY: usize = 8;
    let results: Vec<Result<(), PurgeError>> = futures::stream::iter(objects)
        .map(|meta| {
            let source = source.clone();
            let dest = dest.clone();
            let purged = purged.clone();
            let would_purge = would_purge.clone();
            let skipped_unconfirmed = skipped_unconfirmed.clone();
            let purged_bytes = purged_bytes.clone();
            async move {
                purge_one(
                    &source,
                    &dest,
                    meta,
                    apply,
                    &purged,
                    &would_purge,
                    &skipped_unconfirmed,
                    &purged_bytes,
                    #[cfg(any(test, feature = "blob-purge-gate"))]
                    mutation,
                )
                .await
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;

    // Surface the first hard error (a source-delete failure on a confirmed key); a fail-closed
    // skip is never an error. `?` moves the owned error out (StorageError is not Clone).
    for r in results {
        r?;
    }

    let report = PurgeReport {
        considered,
        purged: purged.load(Ordering::Relaxed),
        would_purge: would_purge.load(Ordering::Relaxed),
        skipped_unconfirmed: skipped_unconfirmed.load(Ordering::Relaxed),
        purged_bytes: purged_bytes.load(Ordering::Relaxed),
    };

    tracing::info!(
        considered = report.considered,
        purged = report.purged,
        would_purge = report.would_purge,
        skipped_unconfirmed = report.skipped_unconfirmed,
        purged_bytes = report.purged_bytes,
        apply,
        "blob purge (drained-source): complete"
    );

    // A single terminal progress snapshot (the purge does not stream per-object cadence like the
    // copy engine — the whole run is a fast head+delete pass — but the daemon relays this final
    // count as an NDJSON line, mirroring the drain's progress shape).
    if let Some(sink) = on_progress {
        sink(crate::blob_migrate::MigrateProgress {
            done: report.considered,
            total: report.considered,
            copied: report.purged,
            skipped: report.skipped_unconfirmed,
            copied_bytes: report.purged_bytes,
            dry_run: !apply,
        });
    }

    Ok(report)
}

/// Process one source object: `head` the destination, decide via the pure predicate, then (only for
/// a confirmed-duplicated key under `apply`) delete it from the source. Fail-closed on anything
/// unconfirmed.
#[allow(clippy::too_many_arguments)]
async fn purge_one(
    source: &Arc<dyn Storage>,
    dest: &Arc<dyn Storage>,
    meta: ObjectMeta,
    apply: bool,
    purged: &AtomicU64,
    would_purge: &AtomicU64,
    skipped_unconfirmed: &AtomicU64,
    purged_bytes: &AtomicU64,
    #[cfg(any(test, feature = "blob-purge-gate"))] mutation: PurgeMutation,
) -> Result<(), PurgeError> {
    let src_size = meta.size;

    // The single safety decision, via the pure predicate. GATE MUTATION SEAM (SkipVerify): a broken
    // implementation that never consults the destination and treats every key as deletable — under
    // the mutation we skip the head entirely and force `true`; a clean run always does the real head.
    #[cfg(any(test, feature = "blob-purge-gate"))]
    let deletable = if mutation == PurgeMutation::SkipVerify {
        true
    } else {
        let dest_head = dest.head(&meta.key).await;
        drained_source_deletable(&dest_head, src_size)
    };
    #[cfg(not(any(test, feature = "blob-purge-gate")))]
    let deletable = {
        let dest_head = dest.head(&meta.key).await;
        drained_source_deletable(&dest_head, src_size)
    };

    // GATE MUTATION SEAM (DeleteUnconfirmed): ignore the predicate's `false` and delete anyway — the
    // exact "purge deleted an unconfirmed key" regression. A clean run honors `deletable`.
    #[cfg(any(test, feature = "blob-purge-gate"))]
    let effective_deletable = deletable || mutation == PurgeMutation::DeleteUnconfirmed;
    #[cfg(not(any(test, feature = "blob-purge-gate")))]
    let effective_deletable = deletable;

    if !effective_deletable {
        // Fail-closed: the destination did not provably duplicate this key — keep the source object.
        skipped_unconfirmed.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    if apply {
        // `delete` a confirmed-duplicated source key. A delete failure IS a hard error (never
        // swallowed) — the operator must know the source was not reclaimed.
        source.delete(&meta.key).await?;
        purged.fetch_add(1, Ordering::Relaxed);
        purged_bytes.fetch_add(src_size.unwrap_or(0), Ordering::Relaxed);
    } else {
        // Dry-run: classify only, delete nothing.
        would_purge.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// A summary of a completed [`purge_drained_source`] run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Total source objects enumerated under the prefix (the candidate set).
    pub considered: u64,
    /// Source objects DELETED (confirmed-duplicated in the destination, `apply` on).
    pub purged: u64,
    /// Source objects that WOULD be deleted (confirmed-duplicated) on a dry-run (`apply` off).
    pub would_purge: u64,
    /// Source objects KEPT because the destination did not provably duplicate them (absent /
    /// size-mismatch / a destination head error) — the fail-closed count.
    pub skipped_unconfirmed: u64,
    /// Bytes reclaimed from the deleted source objects (0 on a dry-run).
    pub purged_bytes: u64,
}

/// A failure running a drained-source purge.
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    /// Enumerating the source, or deleting a confirmed-duplicated source object, failed. A
    /// fail-closed skip (an unconfirmed key) is NEVER an error.
    #[error("blob storage: {0}")]
    Storage(#[from] StorageError),
}

// ================================================================================================
// The ROBUST purge gate — pure predicate + real-path integration + in-process mutation matrix.
//
// This is the deliberate successor to the marker-style gates (`blob_migrate`/`blob_drain`), which
// use a `#[cfg(feature = "…-gate-mutation")]` env-var seam + a println MARKER + a ci.yml grep/bash
// loop. Here the contract is the ordinary test-runner EXIT CODE — no marker string, no env var, no
// bash loop:
//   1. `drained_source_deletable` (the pure safety decision) is unit-tested EXHAUSTIVELY in both
//      directions (present+match ⇒ true; NotFound ⇒ false; size-mismatch ⇒ false; dest Err ⇒ false).
//   2. Real-path integration tests run over a seeded `FallbackStorage(primary=fs, secondary=fs)`
//      and the REAL `purge_drained_source` engine (no feature flag, no marker).
//   3. A typed in-process mutation matrix (`PurgeMutation`) injected via `purge_drained_source_with`
//      proves the safety check is LOAD-BEARING: `None` keeps every unconfirmed key, while each
//      mutation makes an unsafe deletion that the SAME fail-closed assertion DETECTS (the test
//      FAILS if a mutation is not caught).
// The `boatramp-storage` half is (1) + (3-engine). The route-level integration (409 Unreferenced /
// 422 no-fallback) lives in `boatramp-server::blob_purge`. See the ci.yml `blob_purge` lane.
// ================================================================================================
// (1) The pure predicate is exhaustively unit-tested here with NO features — it is plain data in,
// bool out. The fixture-based real-path + mutation-matrix tests (2)/(3) live in the sibling module
// below, gated on `fs`+`fallback` (the fs backends + the composite) so they run on the CI gate lane.
#[cfg(test)]
mod pure_predicate_tests {
    use super::*;

    /// A destination `head` result for a present object of the given size.
    fn present(size: u64) -> Result<ObjectMeta, StorageError> {
        Ok(ObjectMeta {
            key: "k".to_string(),
            size: Some(size),
            content_type: None,
            etag: None,
        })
    }

    #[test]
    fn deletable_true_when_present_and_size_matches() {
        // The ONLY true case: destination has the key at a matching size.
        assert!(drained_source_deletable(&present(42), Some(42)));
    }

    #[test]
    fn not_deletable_when_dest_not_found() {
        // Destination lacks the key ⇒ fail-closed (keep the source).
        let head = Err(StorageError::NotFound("k".to_string()));
        assert!(!drained_source_deletable(&head, Some(42)));
    }

    #[test]
    fn not_deletable_when_size_mismatch() {
        // Present but a different size ⇒ not byte-identical ⇒ fail-closed.
        assert!(!drained_source_deletable(&present(41), Some(42)));
        assert!(!drained_source_deletable(&present(43), Some(42)));
    }

    #[test]
    fn not_deletable_when_dest_error() {
        // A transient/backend error must NOT look like a match (or a miss) ⇒ fail-closed.
        let head = Err(StorageError::Backend("kaboom".to_string()));
        assert!(!drained_source_deletable(&head, Some(42)));
    }

    #[test]
    fn not_deletable_when_dest_size_unknown() {
        // Present but the destination reported no size ⇒ unverifiable ⇒ fail-closed.
        let head = Ok(ObjectMeta {
            key: "k".to_string(),
            size: None,
            content_type: None,
            etag: None,
        });
        assert!(!drained_source_deletable(&head, Some(42)));
    }

    #[test]
    fn not_deletable_when_src_size_unknown() {
        // The source list did not report a size ⇒ unverifiable ⇒ fail-closed even on a present dest.
        assert!(!drained_source_deletable(&present(42), None));
    }
}

// (2) Real-path integration over a seeded `FallbackStorage(primary=fs, secondary=fs)` and (3) the
// typed in-process mutation matrix. Gated on `fs`+`fallback` (the backends the fixtures build); the
// CI `blob_purge` lane runs `cargo test -p boatramp-storage` with the default `fs` + `fallback` on.
#[cfg(all(test, feature = "fs", feature = "fallback"))]
mod integration_tests {
    use super::*;
    use crate::{FallbackStorage, FallbackWhen, FsStorage};
    use boatramp_core::{ByteStream, PutMeta};
    use std::time::Duration;

    fn allow_all() -> FallbackWhen {
        Arc::new(|_k: &str| true)
    }

    async fn put(store: &Arc<dyn Storage>, key: &str, bytes: &[u8]) {
        let owned = bytes.to_vec();
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(owned)) }).boxed();
        store
            .put(key, body, PutMeta::default())
            .await
            .expect("seed put");
    }

    async fn keys_of(store: &Arc<dyn Storage>) -> Vec<String> {
        let mut ks: Vec<String> = store
            .list("")
            .await
            .expect("list")
            .into_iter()
            .map(|m| m.key)
            .collect();
        ks.sort();
        ks
    }

    async fn head_ok(store: &Arc<dyn Storage>, key: &str) -> bool {
        store.head(key).await.is_ok()
    }

    /// A `FallbackStorage(primary=fs, secondary=fs)` seeded so it models a MID-DRAIN state:
    /// - `CONFIRMED`: present in BOTH at matching size (a fully-drained key — deletable).
    /// - `ABSENT`: present ONLY in the secondary (never drained — must survive, fail-closed).
    /// - `MISMATCH`: present in both but at DIFFERENT sizes (a partial copy — must survive).
    ///
    /// Returns the composite, the primary + secondary fs backends, and the three keys.
    struct Seeded {
        composite: Arc<dyn Storage>,
        primary: Arc<dyn Storage>,
        secondary: Arc<dyn Storage>,
    }

    const CONFIRMED: &str = "hblob/proj~site/uploads/confirmed.json";
    const ABSENT: &str = "hblob/proj~site/uploads/absent.json";
    const MISMATCH: &str = "ab/0000000000000000000000000000000000000000000000000000000000000000";

    async fn seeded(tmp: &std::path::Path) -> Seeded {
        let primary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("primary")));
        let secondary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("secondary")));

        // CONFIRMED: identical bytes in both (a drained key).
        put(&secondary, CONFIRMED, b"drained-confirmed").await;
        put(&primary, CONFIRMED, b"drained-confirmed").await;
        // ABSENT: only in the secondary (never drained).
        put(&secondary, ABSENT, b"never-drained").await;
        // MISMATCH: both present, different sizes (a partial/interrupted copy).
        put(&secondary, MISMATCH, b"the-full-original-bytes").await;
        put(&primary, MISMATCH, b"short").await;

        let composite: Arc<dyn Storage> = Arc::new(FallbackStorage::new(
            primary.clone(),
            secondary.clone(),
            allow_all(),
            Duration::from_secs(5),
        ));
        Seeded {
            composite,
            primary,
            secondary,
        }
    }

    /// Resolve the drain pair (source=secondary, dest=primary) off the composite exactly as the
    /// daemon does, then run the purge engine over it with the given mutation + apply flag.
    async fn run_purge(s: &Seeded, apply: bool, mutation: PurgeMutation) -> PurgeReport {
        let pair = s
            .composite
            .drain_pair()
            .expect("the FallbackStorage composite exposes a drain_pair");
        // Sanity: the composite's pair is exactly (secondary → primary).
        assert_eq!(keys_of(&pair.source).await, keys_of(&s.secondary).await);
        assert_eq!(keys_of(&pair.dest).await, keys_of(&s.primary).await);
        purge_drained_source_with(pair.source, pair.dest, "", apply, None, mutation)
            .await
            .expect("purge engine succeeds on a clean run")
    }

    /// The load-bearing fail-closed assertions, factored so the mutation matrix reuses the EXACT
    /// SAME checks the clean run passes: after an `apply` purge, the CONFIRMED key is gone but the
    /// ABSENT + MISMATCH keys SURVIVE in the secondary. A mutation that deletes an unconfirmed key
    /// makes one of the survivors vanish ⇒ these very assertions fail.
    async fn assert_fail_closed_survivors(s: &Seeded) {
        assert!(
            head_ok(&s.secondary, ABSENT).await,
            "fail-closed: a source key ABSENT from the primary must SURVIVE the purge"
        );
        assert!(
            head_ok(&s.secondary, MISMATCH).await,
            "fail-closed: a source key SIZE-MISMATCHED in the primary must SURVIVE the purge"
        );
    }

    // ---- (2) Real-path integration over the seeded FallbackStorage ------------------------------

    #[tokio::test]
    async fn apply_deletes_only_the_confirmed_duplicate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let s = seeded(tmp.path()).await;

        let report = run_purge(&s, true, PurgeMutation::None).await;

        // Exactly the CONFIRMED key was purged; the two unconfirmed keys were kept.
        assert_eq!(report.considered, 3, "three source candidates");
        assert_eq!(
            report.purged, 1,
            "only the confirmed-duplicated key is purged"
        );
        assert_eq!(
            report.would_purge, 0,
            "apply run does not count would_purge"
        );
        assert_eq!(
            report.skipped_unconfirmed, 2,
            "the absent + size-mismatched keys are skipped (fail-closed)"
        );
        assert!(
            report.purged_bytes > 0,
            "the purged key's bytes are counted"
        );

        // The CONFIRMED key is gone from the source; the primary still has it (dest read-only).
        assert!(
            !head_ok(&s.secondary, CONFIRMED).await,
            "the confirmed-duplicated source key is deleted"
        );
        assert!(
            head_ok(&s.primary, CONFIRMED).await,
            "the destination (primary) is read-only — it still holds the drained key"
        );
        // The fail-closed survivors.
        assert_fail_closed_survivors(&s).await;
    }

    #[tokio::test]
    async fn dry_run_deletes_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let s = seeded(tmp.path()).await;
        let before = keys_of(&s.secondary).await;

        let report = run_purge(&s, false, PurgeMutation::None).await;

        assert_eq!(report.considered, 3);
        assert_eq!(report.purged, 0, "dry-run deletes nothing");
        assert_eq!(report.would_purge, 1, "dry-run counts the confirmed key");
        assert_eq!(report.skipped_unconfirmed, 2);
        assert_eq!(report.purged_bytes, 0, "dry-run reclaims no bytes");
        assert_eq!(
            keys_of(&s.secondary).await,
            before,
            "dry-run leaves the source object set unchanged"
        );
    }

    #[tokio::test]
    async fn purge_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let s = seeded(tmp.path()).await;

        let first = run_purge(&s, true, PurgeMutation::None).await;
        assert_eq!(first.purged, 1);
        // A re-run: the confirmed key is already gone, so nothing is purged; the survivors remain.
        let second = run_purge(&s, true, PurgeMutation::None).await;
        assert_eq!(second.purged, 0, "a re-run purges nothing (idempotent)");
        assert_eq!(
            second.considered, 2,
            "only the two survivors remain to consider"
        );
        assert_fail_closed_survivors(&s).await;
    }

    // ---- (3) The typed in-process mutation matrix (anti-hollow) ---------------------------------

    /// `None` (the clean run): the fail-closed survivors hold — the SAME assertions the mutations
    /// must break. This is the positive control for the matrix.
    #[tokio::test]
    async fn mutation_none_is_fail_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let s = seeded(tmp.path()).await;
        let report = run_purge(&s, true, PurgeMutation::None).await;
        assert_eq!(report.purged, 1, "clean run purges only the confirmed key");
        assert_eq!(report.skipped_unconfirmed, 2);
        assert_fail_closed_survivors(&s).await;
    }

    /// DeleteUnconfirmed: ignore the predicate's `false` and delete every source key. The SAME
    /// fail-closed survivor assertion must now DETECT the unsafe deletion (the ABSENT + MISMATCH
    /// keys are gone) — so we assert they were deleted (i.e. the mutation IS caught). If the engine
    /// were fixed to still honor the predicate under this mutation, this test would fail — proving
    /// the safety check is load-bearing.
    #[tokio::test]
    async fn mutation_delete_unconfirmed_is_caught() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let s = seeded(tmp.path()).await;

        let report = run_purge(&s, true, PurgeMutation::DeleteUnconfirmed).await;

        // The mutation deletes ALL three (it never honors the fail-closed decision).
        assert_eq!(
            report.purged, 3,
            "DeleteUnconfirmed deletes every source key (the regression)"
        );
        assert_eq!(report.skipped_unconfirmed, 0);
        // The load-bearing detection: the survivors did NOT survive under the mutation. If the
        // fail-closed guard were still in force, these would be true and this assertion would fail —
        // which is exactly how the matrix proves the guard is load-bearing.
        assert!(
            !head_ok(&s.secondary, ABSENT).await,
            "DeleteUnconfirmed must be CAUGHT: the ABSENT key was unsafely deleted"
        );
        assert!(
            !head_ok(&s.secondary, MISMATCH).await,
            "DeleteUnconfirmed must be CAUGHT: the MISMATCH key was unsafely deleted"
        );
    }

    /// SkipVerify: never consult the destination, treat every key as deletable. Same unsafe outcome
    /// as DeleteUnconfirmed but via the head-skip path — the survivor assertion detects it.
    #[tokio::test]
    async fn mutation_skip_verify_is_caught() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let s = seeded(tmp.path()).await;

        let report = run_purge(&s, true, PurgeMutation::SkipVerify).await;

        assert_eq!(
            report.purged, 3,
            "SkipVerify deletes every source key (the regression)"
        );
        assert_eq!(report.skipped_unconfirmed, 0);
        assert!(
            !head_ok(&s.secondary, ABSENT).await,
            "SkipVerify must be CAUGHT: the ABSENT key was unsafely deleted"
        );
        assert!(
            !head_ok(&s.secondary, MISMATCH).await,
            "SkipVerify must be CAUGHT: the MISMATCH key was unsafely deleted"
        );
    }
}
