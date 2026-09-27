//! **Blob-backend migration** — the backend-agnostic copy engine that moves every
//! object from a SOURCE [`Storage`] to a DESTINATION [`Storage`], skipping any already
//! present at matching size and (by default) verifying completeness afterward.
//!
//! It lives in `boatramp-storage` (over the `Storage` trait + `futures` only, no app deps)
//! so it can be driven from BOTH:
//! - the **offline, node-local** CLI (`boatramp blob migrate --from <config> --to <config>`,
//!   Part 1 of the blob-backend-migration feature — re-exported as `boatramp_node::blob_migrate`),
//!   which builds both backends in-process from two node config files and copies between them; and
//! - the **daemon-mediated** control-plane drain (v0.6.3, `POST /api/blob-drain` +
//!   `boatramp blob drain --server <url>`), where the running server copies its OWN configured
//!   `[serve.blob_fallback]` secondary → primary — reachable on a managed node with no local/SSH
//!   access. That path wires [`MigrateOptions::on_progress`] to stream progress to the client.
//!
//! Switching the node blob backend (`--blobs fs|s3|gcs|azure`, or provider→provider,
//! or region→region) points serving at an EMPTY store, so every site on the node 404s
//! until each project is re-applied. This engine copies the existing objects from a
//! source backend to a destination backend so the switch has no re-upload step.
//!
//! It operates over the existing [`Storage`] trait primitives — `list`/`head`/`get`/`put`
//! — so it works uniformly across every backend (fs, S3, GCS, Azure). The offline CLI builds
//! the two backends from two node config files via `boatramp_node::blobs::build_blobs`
//! and calls [`migrate`]; the daemon hands it the two halves of its own
//! [`FallbackStorage`](crate::FallbackStorage) `drain_pair`. The engine itself is
//! backend-agnostic (it takes two `Arc<dyn Storage>`), which is exactly what lets the mutation
//! gate drive it fs→fs.
//!
//! ## Guarantees
//! - **Read-only on the source.** The engine NEVER deletes (or writes) the source. The
//!   operator flips `--blobs`/config after verifying and retires the old store separately.
//! - **Key fidelity.** A destination key is byte-for-byte the source key (no prefix
//!   mangling that could collapse a tenant/`hblob` boundary). The `content_type` is
//!   preserved from the source metadata.
//! - **Idempotent / resumable.** A `head`-present destination object of matching size is
//!   skipped, so a re-run after an interruption is a near-no-op.
//! - **Completeness (verified).** With `--verify` (default on) every source key is
//!   confirmed `head`-present in the destination after the copy; any missing key is a
//!   hard error (non-zero exit).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use futures::StreamExt;

/// The gate-mutation seams for the Part-1 `BLOB MIGRATE COMPLETE OK` battery. Compiled ONLY
/// under the `blob-migrate-gate-mutation` feature (the CI gate lane). Each
/// `BOATRAMP_BLOBMIG_MUTATE_*` env var makes the engine behave like a specific broken
/// implementation, so the CI gate proves each invariant is load-bearing (every mutation MUST
/// fail the gate). Mirrors the #505 `s3_credential::gate_mutation` seam exactly.
#[cfg(feature = "blob-migrate-gate-mutation")]
pub(crate) mod gate_mutation {
    /// Whether a mutation env var is set (non-empty and not `0`).
    pub(crate) fn env_on(name: &str) -> bool {
        std::env::var(name)
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    }
}

/// A snapshot of migration progress, delivered to a [`ProgressSink`] at the same cadence as
/// the internal periodic tracing line (see [`Progress::maybe_log`]). It carries the running
/// totals so a caller (the daemon's NDJSON stream) can relay live per-object progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrateProgress {
    /// Objects processed so far (copied + skipped).
    pub done: u64,
    /// Total source objects enumerated under the prefix.
    pub total: u64,
    /// Objects copied source→dest so far (or WOULD be, on a dry-run).
    pub copied: u64,
    /// Objects skipped (already present at matching size) so far.
    pub skipped: u64,
    /// Bytes copied so far (0 on a dry-run).
    pub copied_bytes: u64,
    /// Whether this is a dry-run (nothing is actually written).
    pub dry_run: bool,
}

/// A caller-supplied progress callback, invoked at the periodic-log cadence with a
/// [`MigrateProgress`] snapshot (in ADDITION to the internal `tracing` line). `None`
/// (the offline CLI) = the current behavior (tracing only, no callback).
///
/// It must be cheap + non-blocking (the copy loop calls it while holding the progress
/// lock); the daemon's sink just does a non-blocking `mpsc::try_send`.
pub type ProgressSink = Arc<dyn Fn(MigrateProgress) + Send + Sync>;

/// Options controlling a [`migrate`] run.
#[derive(Clone)]
pub struct MigrateOptions {
    /// Bounded worker concurrency for the copy loop (≥ 1; clamped up to 1).
    pub concurrency: usize,
    /// Verify (default on) that every source object is `head`-present in the destination
    /// after the copy; any missing key is an error.
    pub verify: bool,
    /// Enumerate + classify (would-copy / would-skip) but copy nothing.
    pub dry_run: bool,
    /// Restrict the enumeration to keys under this prefix (default `""` = all).
    pub prefix: String,
    /// Optional streaming progress callback, invoked at the same cadence as the internal
    /// periodic tracing line (in addition to it). `None` = tracing only (the offline CLI).
    pub on_progress: Option<ProgressSink>,
}

impl std::fmt::Debug for MigrateOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `on_progress` is a boxed closure with no `Debug`; render its presence only.
        f.debug_struct("MigrateOptions")
            .field("concurrency", &self.concurrency)
            .field("verify", &self.verify)
            .field("dry_run", &self.dry_run)
            .field("prefix", &self.prefix)
            .field("on_progress", &self.on_progress.is_some())
            .finish()
    }
}

impl Default for MigrateOptions {
    fn default() -> Self {
        Self {
            concurrency: 8,
            verify: true,
            dry_run: false,
            prefix: String::new(),
            on_progress: None,
        }
    }
}

/// A summary of a completed [`migrate`] run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrateReport {
    /// Total source objects enumerated under the prefix.
    pub total_objects: u64,
    /// Objects copied source→dest (or, on `--dry-run`, that WOULD be copied).
    pub copied_objects: u64,
    /// Objects skipped because the destination already had the key at matching size
    /// (or, on `--dry-run`, that WOULD be skipped).
    pub skipped_objects: u64,
    /// Total bytes copied (0 on `--dry-run`; sums the source-reported sizes on a real copy).
    pub copied_bytes: u64,
    /// Whether verification ran (`opts.verify` and not a dry-run).
    pub verified: bool,
}

/// A failure running the migration.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// Enumerating / reading / writing an object failed.
    #[error("blob storage: {0}")]
    Storage(#[from] StorageError),
    /// Post-copy verification found source objects absent from the destination. The list is
    /// capped ([`VERIFY_REPORT_CAP`]) so a large miss set does not flood the terminal.
    #[error(
        "verification FAILED: {missing} source object(s) absent from the destination \
         (first {shown} shown): {keys:?}"
    )]
    VerifyMissing {
        /// How many source keys were found missing in the destination.
        missing: usize,
        /// How many of them are listed in `keys` (capped).
        shown: usize,
        /// The (capped) list of missing keys.
        keys: Vec<String>,
    },
}

/// How many missing keys a [`MigrateError::VerifyMissing`] lists before truncating.
pub const VERIFY_REPORT_CAP: usize = 50;

/// One classified object after the destination `head` check.
enum PlanItem {
    /// The destination lacks the key (or has it at a different size) — it must be copied.
    Copy {
        key: String,
        size: u64,
        content_type: Option<String>,
    },
    /// The destination already has the key at matching size — skip (idempotent/resumable).
    Skip,
}

/// The outcome of processing one source object.
struct ItemOutcome {
    copied: bool,
    bytes: u64,
}

/// Copy every object under `opts.prefix` from `source` to `dest`, skipping any already
/// present at matching size, then (when `opts.verify`) confirm every source key is present
/// in the destination.
///
/// The source is treated as read-only — the engine never deletes or writes it. On success
/// it returns a [`MigrateReport`]; a storage error or a failed verification returns
/// [`MigrateError`] (the CLI maps this to a non-zero exit).
pub async fn migrate(
    source: Arc<dyn Storage>,
    dest: Arc<dyn Storage>,
    opts: &MigrateOptions,
) -> Result<MigrateReport, MigrateError> {
    let concurrency = opts.concurrency.max(1);

    // 1. Enumerate the source. `list` is not paginated at the trait — each backend flattens
    //    internally (fs = recursive read_dir; s3/gcs/azure = native paged ListObjects loop).
    // `mut` is consumed only by the DROP_LAST gate seam below; a non-gate build never mutates it.
    #[cfg_attr(not(feature = "blob-migrate-gate-mutation"), allow(unused_mut))]
    let mut objects = source.list(&opts.prefix).await?;
    // The reported total counts the FULL source enumeration — even under the DROP_LAST mutation,
    // so `total_objects` still reflects the true source set (verification re-enumerates the source
    // independently and finds the dropped object absent in the dest).
    let total_objects = objects.len() as u64;

    // GATE MUTATION SEAM (I1 completeness): drop the LAST source object from the COPY set so it is
    // never written to the destination. Verification independently re-enumerates the source and
    // `head`s every key in the dest, so the dropped key is found absent ⇒ I1 FAIL.
    #[cfg(feature = "blob-migrate-gate-mutation")]
    if gate_mutation::env_on("BOATRAMP_BLOBMIG_MUTATE_DROP_LAST") {
        // A deterministic "last" — sort so the dropped key is stable regardless of list order.
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        objects.pop();
    }
    tracing::info!(
        total = total_objects,
        prefix = %opts.prefix,
        dry_run = opts.dry_run,
        concurrency,
        "blob migrate: enumerated source objects"
    );

    // Shared progress counters (updated from the concurrent workers).
    let copied_objects = Arc::new(AtomicU64::new(0));
    let skipped_objects = Arc::new(AtomicU64::new(0));
    let copied_bytes = Arc::new(AtomicU64::new(0));
    let done_objects = Arc::new(AtomicU64::new(0));
    let progress = Arc::new(std::sync::Mutex::new(Progress::new(
        total_objects,
        opts.on_progress.clone(),
    )));

    // 2. Bounded-concurrency copy. `buffer_unordered(N)` runs at most `N` per-object futures
    //    at once, and yields each `Result` so a storage error short-circuits the whole run.
    let results: Vec<Result<ItemOutcome, MigrateError>> = futures::stream::iter(objects)
        .map(|meta| {
            let source = source.clone();
            let dest = dest.clone();
            let dry_run = opts.dry_run;
            async move { copy_one(&source, &dest, meta, dry_run).await }
        })
        .buffer_unordered(concurrency)
        .map(|outcome| {
            // Fold each completed object into the shared counters + periodic progress line.
            if let Ok(ref o) = outcome {
                if o.copied {
                    copied_objects.fetch_add(1, Ordering::Relaxed);
                    copied_bytes.fetch_add(o.bytes, Ordering::Relaxed);
                } else {
                    skipped_objects.fetch_add(1, Ordering::Relaxed);
                }
            }
            let done = done_objects.fetch_add(1, Ordering::Relaxed) + 1;
            let (c, s, b) = (
                copied_objects.load(Ordering::Relaxed),
                skipped_objects.load(Ordering::Relaxed),
                copied_bytes.load(Ordering::Relaxed),
            );
            if let Ok(mut p) = progress.lock() {
                p.maybe_log(done, c, s, b, opts.dry_run);
            }
            outcome
        })
        .collect()
        .await;

    // Surface the first storage error (if any) — a copy failure aborts before verification.
    for r in results {
        r?;
    }

    let copied_objects = copied_objects.load(Ordering::Relaxed);
    let skipped_objects = skipped_objects.load(Ordering::Relaxed);
    let copied_bytes = copied_bytes.load(Ordering::Relaxed);

    // A final summary line (always), independent of the periodic cadence.
    tracing::info!(
        total = total_objects,
        copied = copied_objects,
        skipped = skipped_objects,
        copied_bytes,
        dry_run = opts.dry_run,
        "blob migrate: copy phase complete"
    );

    // 3. Verify (default on; skipped on a dry-run — nothing was written to confirm). Re-enumerate
    //    the SOURCE and `head` each key in the DESTINATION; collect any that are absent. This is
    //    the completeness invariant (I1) + the key-fidelity invariant (I3, since a mangled dest
    //    key would leave the true source key absent).
    let mut verified = false;
    if opts.verify && !opts.dry_run {
        let missing = verify(&source, &dest, &opts.prefix, concurrency).await?;
        if !missing.is_empty() {
            let shown = missing.len().min(VERIFY_REPORT_CAP);
            return Err(MigrateError::VerifyMissing {
                missing: missing.len(),
                shown,
                keys: missing.into_iter().take(VERIFY_REPORT_CAP).collect(),
            });
        }
        verified = true;
        tracing::info!(
            objects = total_objects,
            "VERIFY OK: all source objects present in destination"
        );
    }

    Ok(MigrateReport {
        total_objects,
        copied_objects,
        skipped_objects,
        copied_bytes,
        verified,
    })
}

/// `head` the destination for `key`; classify whether it must be copied. Under the
/// `SKIP_ALWAYS` mutation, unconditionally report "skip" (a broken head-check that would leave
/// a not-present key missing — breaks I1/I2).
async fn plan_one(
    dest: &Arc<dyn Storage>,
    key: &str,
    source_size: u64,
    content_type: Option<String>,
) -> Result<PlanItem, MigrateError> {
    // GATE MUTATION SEAM (I2 head-skip soundness): skip unconditionally, even when the dest does
    // NOT have the key. The gate then finds that key absent in verification ⇒ I1 FAIL.
    #[cfg(feature = "blob-migrate-gate-mutation")]
    if gate_mutation::env_on("BOATRAMP_BLOBMIG_MUTATE_SKIP_ALWAYS") {
        return Ok(PlanItem::Skip);
    }

    match dest.head(key).await {
        // Present at matching size ⇒ idempotent skip.
        Ok(meta) if meta.size == Some(source_size) => Ok(PlanItem::Skip),
        // Present at a different size, or absent ⇒ (re)copy.
        Ok(_) => Ok(PlanItem::Copy {
            key: key.to_string(),
            size: source_size,
            content_type,
        }),
        Err(StorageError::NotFound(_)) => Ok(PlanItem::Copy {
            key: key.to_string(),
            size: source_size,
            content_type,
        }),
        // A transient/backend error is NOT a miss — propagate it (never a silent copy-or-skip).
        Err(e) => Err(MigrateError::Storage(e)),
    }
}

/// Process one source object: head-check the destination, then (unless dry-run or skipped)
/// stream the source body into the destination preserving the key + content_type.
async fn copy_one(
    source: &Arc<dyn Storage>,
    dest: &Arc<dyn Storage>,
    meta: boatramp_core::ObjectMeta,
    dry_run: bool,
) -> Result<ItemOutcome, MigrateError> {
    let source_size = meta.size.unwrap_or(0);
    let plan = plan_one(dest, &meta.key, source_size, meta.content_type.clone()).await?;
    match plan {
        PlanItem::Skip => Ok(ItemOutcome {
            copied: false,
            bytes: 0,
        }),
        PlanItem::Copy {
            key,
            size,
            content_type,
        } => {
            if dry_run {
                // Classify only — never get/put on a dry-run.
                return Ok(ItemOutcome {
                    copied: true,
                    bytes: 0,
                });
            }
            // Stream the source body straight into the destination — no full-object buffering.
            // The source `get` yields the authoritative content_type; fall back to the list meta.
            let got = source.get(&key).await?;
            let ct = got.meta.content_type.or(content_type);
            let dest_key = dest_key_for(&key);
            let body: ByteStream = got.body;
            let written = dest
                .put(&dest_key, body, PutMeta { content_type: ct })
                .await?;

            // GATE MUTATION SEAM (I4 source read-only): delete from the SOURCE after copying — the
            // exact "never delete from source" regression. The gate asserts the source object set is
            // unchanged, so this must fail it.
            #[cfg(feature = "blob-migrate-gate-mutation")]
            if gate_mutation::env_on("BOATRAMP_BLOBMIG_MUTATE_DELETE_SOURCE") {
                source.delete(&key).await?;
            }

            Ok(ItemOutcome {
                copied: true,
                bytes: written.size.unwrap_or(size),
            })
        }
    }
}

/// The destination key for a source key. Identity — a destination key is byte-for-byte the
/// source key (I3 key fidelity). Under the `REWRITE_KEY` mutation, prepend a mangled segment so
/// the true source key is never written to the destination (verification then finds it absent).
fn dest_key_for(source_key: &str) -> String {
    // GATE MUTATION SEAM (I3 key fidelity): mangle the destination key. Verification `head`s the
    // ORIGINAL source key in the destination and finds it absent ⇒ FAIL. In a real build this is a
    // straight identity copy.
    #[cfg(feature = "blob-migrate-gate-mutation")]
    if gate_mutation::env_on("BOATRAMP_BLOBMIG_MUTATE_REWRITE_KEY") {
        return format!("MANGLED/{source_key}");
    }
    source_key.to_string()
}

/// Confirm every source key under `prefix` is `head`-present in the destination; return the keys
/// that are absent (empty ⇒ complete). Bounded-concurrency `head` probes.
async fn verify(
    source: &Arc<dyn Storage>,
    dest: &Arc<dyn Storage>,
    prefix: &str,
    concurrency: usize,
) -> Result<Vec<String>, MigrateError> {
    // Re-enumerate the SOURCE independently of the copy set. This is what makes the DROP_LAST
    // mutation observable: the copy loop dropped a key, but verification still lists it here and
    // finds it absent in the destination.
    let source_keys = source.list(prefix).await?;

    let checks: Vec<Result<Option<String>, MigrateError>> = futures::stream::iter(source_keys)
        .map(|meta| {
            let dest = dest.clone();
            async move {
                match dest.head(&meta.key).await {
                    Ok(_) => Ok(None),
                    Err(StorageError::NotFound(_)) => Ok(Some(meta.key)),
                    Err(e) => Err(MigrateError::Storage(e)),
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut missing = Vec::new();
    for c in checks {
        if let Some(key) = c? {
            missing.push(key);
        }
    }
    missing.sort();
    Ok(missing)
}

/// Periodic progress reporter — a `tracing` line (and, when supplied, a [`ProgressSink`]
/// callback) roughly every [`PROGRESS_INTERVAL`] or every [`PROGRESS_EVERY_N`] objects,
/// whichever comes first.
struct Progress {
    total: u64,
    last: Instant,
    /// The optional streaming callback (the daemon's NDJSON mpsc sink); `None` for the CLI.
    sink: Option<ProgressSink>,
}

const PROGRESS_INTERVAL: Duration = Duration::from_secs(2);
const PROGRESS_EVERY_N: u64 = 500;

impl Progress {
    fn new(total: u64, sink: Option<ProgressSink>) -> Self {
        Self {
            total,
            last: Instant::now(),
            sink,
        }
    }

    fn maybe_log(&mut self, done: u64, copied: u64, skipped: u64, bytes: u64, dry_run: bool) {
        let elapsed = self.last.elapsed();
        if elapsed >= PROGRESS_INTERVAL
            || done.is_multiple_of(PROGRESS_EVERY_N)
            || done == self.total
        {
            self.last = Instant::now();
            tracing::info!(
                done,
                total = self.total,
                copied,
                skipped,
                copied_bytes = bytes,
                dry_run,
                "blob migrate: progress"
            );
            // The streaming sink fires at the SAME cadence, in ADDITION to the tracing line.
            if let Some(sink) = &self.sink {
                sink(MigrateProgress {
                    done,
                    total: self.total,
                    copied,
                    skipped,
                    copied_bytes: bytes,
                    dry_run,
                });
            }
        }
    }
}

// ================================================================================================
// The Part-1 mutation-verified gate battery: `BLOB MIGRATE COMPLETE OK`.
//
// One `#[tokio::test]` runs every invariant fs→fs in a tempdir (no cloud), then prints the marker.
// Compiled ONLY under the `blob-migrate-gate-mutation` feature (the CI gate lane); each
// `BOATRAMP_BLOBMIG_MUTATE_*` env var neuters exactly ONE invariant (via the seams above), so a
// clean run reaches the marker while every mutation PANICS before it — proving each check is
// load-bearing. Mirrors the #505 `s3_credential::gate` structure exactly. See the ci.yml gate step.
// ================================================================================================
#[cfg(all(test, feature = "blob-migrate-gate-mutation"))]
mod gate {
    use super::*;
    use crate::FsStorage;

    /// A representative slice of the ONE node blob keyspace: an immutable content-addressed deploy
    /// blob (`{2hex}/{64hex}`), a mutable control-plane manifest record, and a mutable guest object
    /// (`hblob/{qualified-site}/{container}/{key}`). Migrating must move all three faithfully.
    fn seed_keys() -> Vec<(&'static str, &'static [u8])> {
        vec![
            (
                "ab/0000000000000000000000000000000000000000000000000000000000000000",
                b"content-addressed-immutable-blob",
            ),
            ("manifests/site-alpha", b"{\"deployment\":\"d1\"}"),
            ("hblob/proj~site/uploads/report.json", b"{\"ok\":true}"),
        ]
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

    /// Build a fresh fs source backend seeded with the representative keyspace, plus an empty fs
    /// destination. Two distinct tempdir roots so source + dest never alias.
    async fn seeded_backends(
        tmp: &std::path::Path,
    ) -> (Arc<dyn Storage>, Arc<dyn Storage>, Vec<String>) {
        let source: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("src")));
        let dest: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("dst")));
        let mut keys = Vec::new();
        for (k, v) in seed_keys() {
            put(&source, k, v).await;
            keys.push(k.to_string());
        }
        keys.sort();
        (source, dest, keys)
    }

    /// The sorted set of keys currently present in a backend (list `""`).
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

    /// Invariant 1 (completeness): after migrate, EVERY source key is `head`-present in the dest.
    async fn invariant_1_completeness(dest: &Arc<dyn Storage>, source_keys: &[String]) {
        for key in source_keys {
            dest.head(key).await.unwrap_or_else(|_| {
                panic!("I1 completeness: source key {key:?} is absent from the destination")
            });
        }
    }

    /// Invariant 2 (head-skip soundness): a skip only happens when the dest already holds the key at
    /// matching size. We assert it by proving a SECOND run (dest now fully populated) copies nothing
    /// AND still leaves every key present — i.e. the skip decision never dropped a key. The
    /// SKIP_ALWAYS mutation makes the FIRST run skip a not-present key, which I1 catches.
    async fn invariant_2_head_skip_sound(
        source: &Arc<dyn Storage>,
        dest: &Arc<dyn Storage>,
        source_keys: &[String],
    ) {
        let report = migrate(source.clone(), dest.clone(), &MigrateOptions::default())
            .await
            .expect("second migrate (idempotent) succeeds");
        assert_eq!(
            report.copied_objects, 0,
            "I2: a re-run over a fully-populated destination must copy nothing (all head-skipped)"
        );
        assert_eq!(
            report.skipped_objects,
            source_keys.len() as u64,
            "I2: every object must be head-skipped on the idempotent re-run"
        );
        // And the skip must not have dropped anything.
        invariant_1_completeness(dest, source_keys).await;
    }

    /// Invariant 3 (key fidelity): the dest key set equals the source key set, byte-exact. The
    /// REWRITE_KEY mutation prepends `MANGLED/`, so the dest keys diverge from the source keys.
    async fn invariant_3_key_fidelity(source: &Arc<dyn Storage>, dest: &Arc<dyn Storage>) {
        let src = keys_of(source).await;
        let dst = keys_of(dest).await;
        assert_eq!(
            src, dst,
            "I3 key fidelity: destination keys must equal source keys byte-exact (no mangling)"
        );
    }

    /// Invariant 4 (source read-only): the source key set is unchanged after migrate. The
    /// DELETE_SOURCE mutation deletes each copied object from the source.
    async fn invariant_4_source_read_only(source: &Arc<dyn Storage>, before: &[String]) {
        let after = keys_of(source).await;
        assert_eq!(
            before,
            after.as_slice(),
            "I4 source read-only: the source object set must be unchanged after migrate"
        );
    }

    #[tokio::test]
    async fn blob_migrate_complete_gate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (source, dest, source_keys) = seeded_backends(tmp.path()).await;
        let before_source = keys_of(&source).await;
        assert_eq!(before_source, source_keys, "sanity: seeded source keys");

        // The real migration under test (verify ON) — a mutation makes it break an invariant below.
        let report = migrate(source.clone(), dest.clone(), &MigrateOptions::default())
            .await
            .expect("migrate succeeds on a clean run");
        assert_eq!(report.total_objects, source_keys.len() as u64);
        assert!(report.verified, "verify must have run + passed");

        invariant_1_completeness(&dest, &source_keys).await;
        // I4 before I3: DELETE_SOURCE empties the source, so check "source unchanged" against its own
        // invariant before the source-vs-dest key-set comparison (both catch it — panic ⇒ marker
        // absent — but this attributes it to the load-bearing check).
        invariant_4_source_read_only(&source, &before_source).await;
        invariant_3_key_fidelity(&source, &dest).await;
        invariant_2_head_skip_sound(&source, &dest, &source_keys).await;

        // Reached only on a clean, fully-passing run — a mutation env var panics one invariant above
        // (DROP_LAST/SKIP_ALWAYS/REWRITE_KEY via I1/I3; DELETE_SOURCE via I4).
        println!(
            "BLOB MIGRATE COMPLETE OK: the offline blob-backend migration copies every source \
             object to the destination (completeness), skips only a matching-size head-present key \
             (idempotent/resumable), preserves keys byte-exact (no tenant/hblob-boundary collapse), \
             and never mutates the source (read-only). Mutation-verified: \
             BOATRAMP_BLOBMIG_MUTATE_{{DROP_LAST,SKIP_ALWAYS,REWRITE_KEY,DELETE_SOURCE}}=1 each FAIL \
             this gate."
        );
    }
}
