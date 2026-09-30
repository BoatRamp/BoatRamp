//! [`KvStore`] backed by [SlateDB](https://slatedb.io): a transactional LSM-tree
//! store whose storage layer is an `object_store` backend — local filesystem,
//! S3/R2, GCS, Azure, etc. The same KV runs over any of them, which suits
//! object-store deployments (and the clustering/Cloudflare direction).
//!
//! Durability is the object-store write completing (not a local fsync); writes
//! are object-store-latency-bound. SlateDB is single-writer (manifest fencing).
//!
//! ## Flush interval and the two roles boatramp gives SlateDB
//!
//! A `put` is acknowledged only after the next WAL flush, so a single awaited
//! write costs roughly one `flush_interval`. SlateDB's default (≈100 ms)
//! favours throughput: many concurrent writes coalesce into one flush. boatramp
//! uses SlateDB for two jobs with opposite needs:
//!
//! - **Control plane** (deploy manifests, the per-site "current" pointer):
//!   writes are few, serialized, and a human is waiting — so we open it with a
//!   *low* flush interval ([`SlateKv::open_local_with_flush`]) and group
//!   related writes into one [`KvStore::write_batch`] (a single SlateDB
//!   `WriteBatch` → one flush, all-or-nothing).
//! - **Handler `wasi:keyvalue`** store: request-driven, high-concurrency — it
//!   keeps the throughput-oriented default ([`SlateKv::open_local`]).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::kv::{DegradedMarker, KvError, KvStore, WriteOp};
use slatedb::config::{FlushOptions, FlushType};
use slatedb::object_store::local::LocalFileSystem;
use slatedb::object_store::path::Path as ObjPath;
use slatedb::object_store::{ObjectStore, ObjectStoreExt};
use slatedb::{Db, DbReader, DbReaderBuilder, Settings, WriteBatch};

pub use crate::wal_repair::{RepairMode, RepairReport, WalRepairError};
// The cold-open recovery policy lives in `boatramp-core` (available without the `slatedb` feature,
// which `boatramp-node::build_kv` needs); re-exported here for the storage-facing openers.
pub use boatramp_core::kv::KvOpenPolicy;

/// A SlateDB-backed key/value store — either the single **writer** or a
/// read-only **reader replica**. SlateDB is
/// single-writer (manifest fencing); the shared-store topology is therefore one
/// writer process plus read replicas that poll the manifest for new data. A
/// reader serves `get`/`list_prefix`; writes on it error (control-plane writes
/// go to the writer process, and the changelog keeps replicas' caches coherent).
#[derive(Clone)]
pub struct SlateKv {
    backend: Backend,
    /// Serializes [`compare_and_swap`](KvStore::compare_and_swap) within this writer process (B10):
    /// SlateDB has no read-conditional-write primitive, but it is single-writer (manifest fencing),
    /// so the only concurrent CAS racers are tasks in THIS process. Holding this async mutex across
    /// the get→compare→write makes the CAS linearizable within the writer — the property the
    /// async-lane shard claim needs. Cheap (contended only by the drain's claims, off the hot path).
    cas_lock: Arc<tokio::sync::Mutex<()>>,
    /// **Checkpoint dirty flag** (v0.9.0 KV-recovery, C1): set by every write, cleared by
    /// [`checkpoint`](KvStore::checkpoint). The periodic cadence task's `checkpoint()` skips the
    /// memtable-freeze (and the manifest PUT it entails) when this is `false`, so an IDLE store does
    /// not churn a new empty L0 SST on every tick. A crown-jewel write sets it, then its own
    /// `checkpoint()` observes it and freezes — so the frontier advances past the write before it
    /// acks. Shared across clones (all clones front the same `Db`).
    dirty: Arc<AtomicBool>,
}

#[derive(Clone)]
enum Backend {
    Writer(Arc<Db>),
    Reader(Arc<DbReader>),
}

fn backend<E: std::fmt::Display>(err: E) -> KvError {
    KvError::backend(err.to_string())
}

/// Map a SlateDB open/build error into a [`KvError`], and — when it looks like a **torn WAL
/// tail** (the P0 failure mode: a partial trailing WAL object with a bad version word, or the
/// empty-SSTable symptom) — extend the message to name the OPT-IN repair. The default cold open
/// stays FAIL-LOUD (SAFETY: quarantining acked-into-WAL data is an operator decision, never
/// automatic), so this only makes the loud failure *actionable*, it does not repair anything.
/// Whether a SlateDB open/build error Display looks like a **torn / unbootable STORE** — a corruption
/// the self-heal-on-open (or `kv recover`) targets — as opposed to a concurrent-writer / lifecycle
/// error (a fence or a closed store), which recover must NOT be pointed at. Shared by
/// [`map_open_error`] (message shape) and the self-heal decision in [`SlateKv::open_self_heal`]
/// (whether a failed plain open is even a candidate for self-heal). See C4.
fn open_error_looks_torn(raw: &str) -> bool {
    // Concurrent-writer fence / closed store: NOT a torn store — exclude first.
    if raw.contains("detected newer DB client")
        || raw.contains("Fenced")
        || raw.contains("db is closed")
    {
        return false;
    }
    // The torn-SST signatures slatedb surfaces on replay of a partial object: the >10-byte partial
    // (`InvalidVersion { actual_version: 0 }`) and the empty-SSTable symptom. Matched on the message
    // (slatedb exposes no stable typed variant for these across versions). slatedb's ACTUAL `Display`
    // for the version error is `"unsupported {format} format version. supported_versions=…,
    // actual_version=…"` — it does NOT contain the Debug name `"InvalidVersion"`, and only
    // incidentally contains `"actual_version"`. C4 BROADENS to EVERY unbootable-store shape: a
    // truncated edge → `ChecksumMismatch` / `WalTruncated`, a torn block → "wal data error" /
    // "invalid sst" / "empty block", a missing object → the wrapped object-store not-found.
    raw.contains("InvalidVersion")
        || raw.contains("actual_version")
        || (raw.contains("unsupported") && raw.contains("format version"))
        || raw.contains("empty SSTable")
        || raw.contains("EmptySSTable")
        || raw.contains("checksum mismatch")
        || raw.contains("ChecksumMismatch")
        || raw.contains("wal truncated")
        || raw.contains("WalTruncated")
        || raw.contains("wal data error")
        || raw.contains("invalid sst")
        || raw.contains("empty block")
        || raw.contains("empty manifest")
        || raw.contains("invalid DB state")
}

/// Map a SlateDB open/build error into a [`KvError`], and — when it looks like a **torn/unbootable
/// store** — extend the message to name the recovery paths. The default cold open (strict) stays
/// FAIL-LOUD; this only makes the loud failure *actionable*. Under the v0.9.0 self-heal-on-open
/// default a torn TRAILING tail is auto-quarantined instead, so this loud message is reached only in
/// strict mode or for an unsafe shape.
fn map_open_error(err: slatedb::Error) -> KvError {
    let raw = err.to_string();
    // `map_open_error` is only ever called on an open FAILURE, so the recover pointer is correct for
    // the whole torn set. `Fenced`/closed (a lifecycle problem) is carved out by `open_error_looks_torn`.
    let looks_torn = open_error_looks_torn(&raw);
    let is_lifecycle = raw.contains("detected newer DB client")
        || raw.contains("Fenced")
        || raw.contains("db is closed");
    if looks_torn {
        KvError::backend(format!(
            "control-plane SlateDB store failed to open: the store is torn/corrupt ({raw}). \
             This is the crash/snapshot partial-tail (or truncated-edge) case. To recover, run \
             `boatramp kv recover` (dry-run) — the daemon-mediated/boot-time SUPERSET that \
             diagnoses the WHOLE store (the WAL tail AND the compacted/L0 SSTs), repairs a safe \
             trailing tail in place, and can adopt a clean volume snapshot for an unsafe shape — \
             or, for an offline tail-only quarantine, `boatramp kv repair` (a DRY-RUN diagnoses \
             and NAMES any torn object it cannot auto-repair; then `--apply`). You may also \
             redeploy with the env `BOATRAMP_KV_REPAIR=1` (equivalently `boatramp serve \
             --repair-wal`) — now the DEFAULT self-heal, so the env is redundant. Repair \
             quarantines only a torn TRAILING WAL tail; a torn compacted/L0 SST is reported (not \
             auto-removed — it needs `kv recover --adopt-volume`). A hard-crash repair may lose \
             the most-recent acked-into-WAL-but-not-yet-L0 writes; a graceful shutdown is lossless."
        ))
    } else if is_lifecycle {
        // A concurrent-writer fence or a closed store — do NOT point at recover (wrong tool).
        KvError::backend(format!(
            "control-plane SlateDB store failed to open ({raw}). This looks like a concurrent \
             writer / lifecycle error (another process holds the single-writer fence, or the store \
             was closed), NOT a torn store — resolve the writer conflict rather than running \
             `kv recover`."
        ))
    } else {
        // Any OTHER open failure is still unbootable — append the recover pointer (C4), hedged.
        KvError::backend(format!(
            "control-plane SlateDB store failed to open ({raw}). If this is a crash/snapshot \
             corruption, run `boatramp kv recover` (dry-run) to diagnose the whole store; an \
             offline tail-only quarantine is `boatramp kv repair`. `BOATRAMP_KV_REPAIR=1` / \
             `serve --repair-wal` (now the default self-heal) repairs a safe trailing tail on open."
        ))
    }
}

/// A one-line human summary of a [`RepairReport`] for the dry-run surface.
fn describe_report(report: &RepairReport) -> String {
    let classes: Vec<String> = report
        .candidates
        .iter()
        .map(|c| format!("{:020}[{} bytes, {:?}]", c.id, c.size, c.class))
        .collect();
    // Surface the out-of-scope torn objects (torn compacted/L0 SSTs + torn non-trailing WAL
    // objects) so the compacted-SST case is unmistakable: these are DETECTION-ONLY (never
    // auto-removed) and REQUIRE MANIFEST-AWARE RECOVERY — repair will NOT open the store while any
    // remain. Named explicitly so a dry-run doesn't read as "nothing to do" when it isn't.
    let out_of_scope = if report.out_of_scope_torn.is_empty() {
        String::new()
    } else {
        let paths: Vec<String> = report
            .out_of_scope_torn
            .iter()
            .map(|t| format!("{} ({:?}, {} bytes)", t.path, t.kind, t.size))
            .collect();
        format!(
            " OUT-OF-SCOPE torn SST(s) this tool will NOT auto-remove (requires manifest-aware \
             recovery; escalate): [{}].",
            paths.join(", ")
        )
    };
    format!(
        "durable frontier (replay_after_wal_id) = {}; WAL candidates beyond it (highest first): \
         [{}]; would quarantine {:?} (trailing torn tail).{} Re-run with `--apply` to perform it.",
        report.frontier,
        classes.join(", "),
        report.quarantined,
        out_of_scope,
    )
}

/// SlateDB [`Settings`] with `flush_interval` overridden, everything else left
/// at its default.
fn settings_with_flush(flush_interval: Duration) -> Settings {
    Settings {
        flush_interval: Some(flush_interval),
        ..Settings::default()
    }
}

/// The durable degraded-state breadcrumb object path (v0.9.0 KV-recovery, C6): `{root}/DEGRADED.json`,
/// an object-store file alongside `wal/` / `compacted/` / `manifest/` so it is readable WITHOUT the
/// LSM store being bootable (the recovery-mode `GET /api/kv-status` + `boatramp kv status` read it).
fn degraded_marker_path(root: &str) -> ObjPath {
    ObjPath::from(format!("{root}/DEGRADED.json"))
}

/// Write the [`DegradedMarker`] breadcrumb after a non-empty self-heal (C6). Best-effort: the store
/// is already open and serving, so a marker-write failure is LOGGED, not fatal (it only costs the
/// operator the breadcrumb, never availability). Returns the stamp for the log line.
pub async fn write_degraded_marker(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    report: &RepairReport,
) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let loss_window = match (
        report.quarantined.iter().min(),
        report.quarantined.iter().max(),
    ) {
        (Some(&lo), Some(&hi)) => format!(
            "WAL ids {lo:020}..={hi:020} beyond the durable frontier {:020} were quarantined; these \
             bytes are preserved for FORENSICS ONLY (no supported recovery of acked pairs)",
            report.frontier
        ),
        _ => format!("frontier {:020}; no ids quarantined", report.frontier),
    };
    let marker = DegradedMarker {
        stamp,
        quarantined_ids: report.quarantined.clone(),
        loss_window,
        quarantine_dir: report.quarantine_dir.clone().unwrap_or_default(),
    };
    let path = degraded_marker_path(root);
    if let Err(e) = store.put(&path, marker.to_json_bytes().into()).await {
        tracing::warn!(error = %e, path = %path, "failed to write the KV DEGRADED.json breadcrumb (self-heal still succeeded)");
    }
    format!("{stamp:020}")
}

/// Read the [`DegradedMarker`] breadcrumb, if any, for `GET /api/kv-status` + `boatramp kv status`.
/// `Ok(None)` when no marker is present (a clean store, or a zero-loss self-heal). Reads through the
/// object store, so it works even when the LSM store itself will not open.
pub async fn read_degraded_marker(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<Option<DegradedMarker>, KvError> {
    let path = degraded_marker_path(root);
    match store.get(&path).await {
        Ok(get) => {
            let bytes = get.bytes().await.map_err(backend)?;
            Ok(DegradedMarker::from_json_bytes(&bytes))
        }
        // Absent ⇒ no degraded state. Any object-store NotFound maps here.
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(backend(e)),
    }
}

/// Clear the [`DegradedMarker`] breadcrumb (`boatramp kv status --ack`). Returns whether a marker was
/// present (so `--ack` can report "acknowledged" vs "nothing to acknowledge"). Deleting an absent
/// marker is not an error (idempotent).
pub async fn clear_degraded_marker(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<bool, KvError> {
    let existed = read_degraded_marker(store, root).await?.is_some();
    let path = degraded_marker_path(root);
    match store.delete(&path).await {
        Ok(()) => Ok(existed),
        Err(object_store::Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(backend(e)),
    }
}

/// How to reach an S3-compatible object store (e.g. Cloudflare R2) for a
/// [`SlateKv::open_s3_with_flush`]. Credentials are read from the ambient AWS
/// environment, so only the addressing lives here.
#[derive(Debug, Clone)]
pub struct S3StoreConfig {
    /// The bucket the SlateDB store lives in.
    pub bucket: String,
    /// Custom endpoint (R2: `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: Option<String>,
    /// Region (R2 uses `auto`).
    pub region: Option<String>,
    /// Use path-style addressing (R2 accepts it).
    pub path_style: bool,
}

/// Build an `object_store` S3 backend from [`S3StoreConfig`] + ambient AWS
/// credentials. SlateDB fences its manifest with conditional puts, so the store
/// is built with ETag-based conditional put (which R2 supports).
/// Build the `LocalFileSystem` object store rooted at `dir` exactly as the local control-plane
/// opener does (`open_local_settings`). Exposed so the `boatramp kv repair` CLI can build the
/// SAME store the opener would, and run the repair against it (root `"kv"`).
pub fn local_object_store(dir: &Path) -> Result<LocalFileSystem, KvError> {
    LocalFileSystem::new_with_prefix(dir).map_err(backend)
}

/// Build the S3/R2 object store from an [`S3StoreConfig`] (ambient AWS creds), exactly as the
/// S3 control-plane opener does. Exposed so the `boatramp kv repair` CLI can build the SAME
/// store the opener would and run the repair against it (root = the configured prefix).
pub fn s3_object_store(cfg: &S3StoreConfig) -> Result<Arc<dyn ObjectStore>, KvError> {
    build_s3_object_store(cfg)
}

pub(crate) fn build_s3_object_store(cfg: &S3StoreConfig) -> Result<Arc<dyn ObjectStore>, KvError> {
    use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
    let mut builder = AmazonS3Builder::from_env()
        .with_bucket_name(&cfg.bucket)
        .with_region(cfg.region.clone().unwrap_or_else(|| "auto".into()))
        .with_conditional_put(S3ConditionalPut::ETagMatch);
    if let Some(endpoint) = &cfg.endpoint {
        builder = builder.with_endpoint(endpoint);
    }
    if cfg.path_style {
        builder = builder.with_virtual_hosted_style_request(false);
    }
    Ok(Arc::new(builder.build().map_err(backend)?))
}

impl SlateKv {
    /// Open a store over an arbitrary `object_store` backend (rooted at `path`)
    /// using SlateDB's default settings — the throughput-oriented profile for
    /// the high-concurrency handler store.
    pub async fn open(store: Arc<dyn ObjectStore>, path: &str) -> Result<Self, KvError> {
        Self::open_with(store, path, Settings::default()).await
    }

    /// Open like [`SlateKv::open`] but with an explicit `flush_interval`. A low
    /// value (a few milliseconds) trades coalescing for the per-write latency
    /// the control plane wants.
    pub async fn open_with_flush(
        store: Arc<dyn ObjectStore>,
        path: &str,
        flush_interval: Duration,
    ) -> Result<Self, KvError> {
        Self::open_with(store, path, settings_with_flush(flush_interval)).await
    }

    /// Open a control-plane store over an S3-compatible object store (e.g.
    /// Cloudflare R2), rooted at the key prefix `path`, with the low
    /// control-plane flush interval. Credentials come from the ambient AWS
    /// environment (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), matching the
    /// S3 blob backend, so a container needs only R2 credentials — no Cloudflare
    /// token. SlateDB's single-writer manifest fencing suits the DO-singleton
    /// container; durable state then survives a scale-to-zero stop.
    pub async fn open_s3_with_flush(
        cfg: &S3StoreConfig,
        path: &str,
        flush_interval: Duration,
    ) -> Result<Self, KvError> {
        Self::open_with_flush(build_s3_object_store(cfg)?, path, flush_interval).await
    }

    /// Like [`SlateKv::open_with_flush`] but, when `repair` is set, first runs the opt-in
    /// [WAL tail repair](crate::wal_repair::repair_wal_tail) over the SAME `store` + `path`
    /// BEFORE opening — so a store whose cold open would otherwise fail on a torn trailing
    /// WAL tail (a hard-crash / snapshot partial) is repaired in place, then opened. `None`
    /// is the default cold open (unchanged; still fails LOUD on a torn tail). The repair
    /// enforces its own data-loss guard (trailing-only + beyond-frontier + refuse-on-mid-gap
    /// + refuse-on-unreadable-manifest) and refuses rather than dropping acked data.
    pub async fn open_with_flush_repair(
        store: Arc<dyn ObjectStore>,
        path: &str,
        flush_interval: Duration,
        repair: Option<RepairMode>,
    ) -> Result<Self, KvError> {
        Self::open_with_repair(store, path, settings_with_flush(flush_interval), repair).await
    }

    /// Like [`SlateKv::open_s3_with_flush`] but with the opt-in WAL repair (see
    /// [`SlateKv::open_with_flush_repair`]).
    pub async fn open_s3_with_flush_repair(
        cfg: &S3StoreConfig,
        path: &str,
        flush_interval: Duration,
        repair: Option<RepairMode>,
    ) -> Result<Self, KvError> {
        Self::open_with_flush_repair(build_s3_object_store(cfg)?, path, flush_interval, repair)
            .await
    }

    async fn open_with(
        store: Arc<dyn ObjectStore>,
        path: &str,
        settings: Settings,
    ) -> Result<Self, KvError> {
        Self::open_with_repair(store, path, settings, None).await
    }

    /// The single open choke point. When `repair` is `Some`, the WAL tail repair runs FIRST
    /// (against the same `store` + `path`), before `Db::builder().build()`. On a plain cold
    /// open (`None`) a torn-tail build error is mapped to a LOUD, actionable message that
    /// names the opt-in repair — the default MUST still fail loud (SAFETY: an operator, not
    /// an automatic open, decides to quarantine acked-into-WAL data).
    async fn open_with_repair(
        store: Arc<dyn ObjectStore>,
        path: &str,
        settings: Settings,
        repair: Option<RepairMode>,
    ) -> Result<Self, KvError> {
        if let Some(mode) = repair {
            let report = crate::wal_repair::repair_wal_tail(&store, path, mode)
                .await
                .map_err(|e| KvError::backend(e.to_string()))?;
            match mode {
                RepairMode::DryRun => {
                    // A dry-run must NOT open the store — it only reports the plan. Surface the
                    // plan as an error so a `--dry-run` caller never silently proceeds to serve.
                    return Err(KvError::backend(format!(
                        "WAL repair dry-run (no mutation performed): {}",
                        describe_report(&report)
                    )));
                }
                RepairMode::Apply => {
                    if report.applied {
                        tracing::warn!(
                            frontier = report.frontier,
                            quarantined = ?report.quarantined,
                            dir = report.quarantine_dir.as_deref().unwrap_or(""),
                            "control-plane WAL tail repaired: quarantined a torn trailing tail \
                             beyond the durable frontier. NOTE: a hard-crash repair may have lost \
                             the most-recent acked-into-WAL-but-not-yet-L0 writes (the graceful \
                             shutdown path is lossless)."
                        );
                    } else {
                        tracing::info!(
                            frontier = report.frontier,
                            "control-plane WAL repair: no torn trailing tail found; opening normally"
                        );
                    }
                }
            }
        }
        let db = match Db::builder(path.to_string(), store)
            .with_settings(settings)
            .build()
            .await
        {
            Ok(db) => db,
            Err(err) => return Err(map_open_error(err)),
        };
        Ok(Self::from_writer(db))
    }

    /// Wrap an opened SlateDB writer `Db` as a control-plane [`SlateKv`] (fresh CAS lock + a clean
    /// checkpoint dirty flag). The single writer-handle constructor, shared by every open path.
    fn from_writer(db: Db) -> Self {
        Self {
            backend: Backend::Writer(Arc::new(db)),
            cas_lock: Arc::new(tokio::sync::Mutex::new(())),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Open a local control-plane store under `dir` with the given [`KvOpenPolicy`] (v0.9.0
    /// KV-recovery, C3/C7/C8/C11). Builds the SAME `LocalFileSystem`-over-`"kv"` store the plain
    /// opener uses, so the self-heal sees exactly the objects the open would replay.
    pub async fn open_local_with_flush_policy(
        dir: impl AsRef<Path>,
        flush_interval: Duration,
        policy: KvOpenPolicy,
    ) -> Result<Self, KvError> {
        std::fs::create_dir_all(&dir)?;
        let fs = local_object_store(dir.as_ref())?;
        Self::open_with_policy(
            Arc::new(fs),
            "kv",
            settings_with_flush(flush_interval),
            policy,
        )
        .await
    }

    /// Open an S3/R2 control-plane store with the given [`KvOpenPolicy`] (see
    /// [`open_local_with_flush_policy`](Self::open_local_with_flush_policy)).
    pub async fn open_s3_with_flush_policy(
        cfg: &S3StoreConfig,
        path: &str,
        flush_interval: Duration,
        policy: KvOpenPolicy,
    ) -> Result<Self, KvError> {
        Self::open_with_policy(
            build_s3_object_store(cfg)?,
            path,
            settings_with_flush(flush_interval),
            policy,
        )
        .await
    }

    /// Open with a [`KvOpenPolicy`]: [`Strict`](KvOpenPolicy::Strict) is the plain cold open (a torn
    /// store fails LOUD, unchanged); [`SelfHeal`](KvOpenPolicy::SelfHeal) auto-recovers a
    /// provably-safe trailing torn WAL tail and fails LOUD on any unsafe shape (C3/C7).
    async fn open_with_policy(
        store: Arc<dyn ObjectStore>,
        path: &str,
        settings: Settings,
        policy: KvOpenPolicy,
    ) -> Result<Self, KvError> {
        match policy {
            KvOpenPolicy::Strict => Self::open_with_repair(store, path, settings, None).await,
            KvOpenPolicy::SelfHeal => Self::open_self_heal(store, path, settings).await,
        }
    }

    /// The self-heal-on-open path (v0.9.0 KV-recovery, C3/C7). Runs pre-open in the fenced,
    /// single-writer context (no concurrent writer), so the frontier the self-heal reads is exactly
    /// the one the open replays.
    ///
    /// 1. FAST PATH: try a plain open. A clean store (the overwhelming common case) opens with ZERO
    ///    repair-scan overhead. A non-torn failure (a concurrent-writer fence, a closed store) fails
    ///    LOUD unchanged — self-heal is NEVER attempted for those (`open_error_looks_torn`).
    /// 2. C3 — DRY-RUN FIRST: on a torn/unbootable open, scan the WHOLE store WITHOUT mutating. Any
    ///    refusal (mid-range gap/hole, unreadable manifest) propagates LOUD; any out-of-scope torn
    ///    object (a torn compacted/L0 SST, a torn non-trailing WAL object) is an UNSAFE shape ⇒ fail
    ///    LOUD, mutate NOTHING (fixes the ordering bug where a naive apply would quarantine the WAL
    ///    tail then still die on a torn compacted SST). Only a SOLE safe-trailing-torn-tail proceeds.
    /// 3. APPLY: quarantine the safe tail (copy → manifest → delete → REAL-open verify, C4). A
    ///    verification failure fails LOUD (never claim success). Then write the durable
    ///    `{root}/DEGRADED.json` breadcrumb (C6) + a structured WARN, and open the serving writer.
    /// 4. A refusal at ANY step is FATAL (C7): return `Err` — NEVER boot-anyway. The caller turns a
    ///    fatal open into a recovery-mode listener (C5), not an `exit(1)` crash-loop.
    async fn open_self_heal(
        store: Arc<dyn ObjectStore>,
        path: &str,
        settings: Settings,
    ) -> Result<Self, KvError> {
        // 1. Fast path — a clean store opens directly.
        match Db::builder(path.to_string(), store.clone())
            .with_settings(settings.clone())
            .build()
            .await
        {
            Ok(db) => {
                tracing::info!(
                    "control-plane KV opened cleanly (self-heal armed; nothing to repair)"
                );
                return Ok(Self::from_writer(db));
            }
            Err(err) => {
                let raw = err.to_string();
                if !open_error_looks_torn(&raw) {
                    // A concurrent-writer fence / closed store / other non-torn failure: fail LOUD,
                    // NEVER self-heal (recover is the wrong tool — see `map_open_error`).
                    return Err(map_open_error(err));
                }
                tracing::warn!(
                    error = %raw,
                    "control-plane KV cold open failed with a torn/unbootable signature; running \
                     self-heal (dry-run first, C3)"
                );
            }
        }

        // 2. C3 — dry-run the WHOLE store first; a refusal (mid-range gap/hole, unreadable manifest)
        //    propagates LOUD, mutating nothing.
        let dry = crate::wal_repair::repair_wal_tail(&store, path, RepairMode::DryRun)
            .await
            .map_err(|e| KvError::backend(e.to_string()))?;
        if !dry.out_of_scope_torn.is_empty() {
            // UNSAFE shape — a torn compacted/L0 SST (or torn non-trailing WAL object) the self-heal
            // must NOT touch. Fail LOUD naming it; mutate NOTHING (C3/C7).
            let objects: Vec<String> = dry
                .out_of_scope_torn
                .iter()
                .map(|t| format!("{} ({:?})", t.path, t.kind))
                .collect();
            return Err(KvError::backend(format!(
                "control-plane KV self-heal REFUSED: the store at `{path}` holds a torn SST OUTSIDE \
                 the safe trailing-WAL-tail scope that auto-heal must NOT remove (a compacted/L0 SST \
                 is manifest-referenced; removing it would drop acked data). Torn out-of-scope \
                 object(s): [{}]. This is beyond auto-heal AND beyond `kv repair` (tail-only). \
                 Recover with `boatramp kv recover --adopt-volume <mounted-path>` (attach a clean \
                 volume snapshot). Nothing was mutated.",
                objects.join(", ")
            )));
        }
        if dry.quarantined.is_empty() {
            // Torn open but NOTHING safe to quarantine (a truncated edge the probe cannot localize,
            // or a corruption inside a readable-looking object). Cannot self-heal ⇒ fail LOUD.
            return Err(KvError::backend(format!(
                "control-plane KV self-heal could not localize a safe trailing torn WAL tail at \
                 `{path}` (the store is torn but no auto-healable tail was found — e.g. a truncated \
                 edge or a torn readable object). Recover with `boatramp kv recover`. Nothing was \
                 mutated."
            )));
        }

        // 3. APPLY — quarantine the sole safe trailing torn tail (+ C4 real-open verify inside).
        let report = crate::wal_repair::repair_wal_tail(&store, path, RepairMode::Apply)
            .await
            .map_err(|e| KvError::backend(e.to_string()))?;
        // C6 — a non-empty self-heal writes the durable degraded breadcrumb + a structured WARN.
        if !report.quarantined.is_empty() {
            let stamp = write_degraded_marker(&store, path, &report).await;
            tracing::warn!(
                target: "kv_self_healed",
                frontier = report.frontier,
                quarantined_ids = ?report.quarantined,
                quarantine_dir = report.quarantine_dir.as_deref().unwrap_or(""),
                degraded_marker = %stamp,
                "control-plane KV SELF-HEALED on open: quarantined a torn trailing WAL tail beyond \
                 the durable frontier and opened. A hard-crash tail MAY have held acked-into-WAL- \
                 but-not-yet-L0 writes; those bytes are preserved for FORENSICS ONLY (no supported \
                 recovery of acked pairs from a torn version-0 SST). Ack with `boatramp kv status \
                 --ack` once reviewed."
            );
        }

        // 4. Open the serving writer over the now-clean store (the Apply's verify used a throwaway).
        let db = Db::builder(path.to_string(), store)
            .with_settings(settings)
            .build()
            .await
            .map_err(map_open_error)?;
        Ok(Self::from_writer(db))
    }

    /// Open a **read-only replica** over an `object_store` backend that some
    /// other process is the writer for. It serves
    /// reads from the committed manifest/L0 and polls for the writer's new data;
    /// writes error. Pair with the shared-mode changelog (`--shared-cache-
    /// coherence`) so a replica's config cache is invalidated on peer writes.
    pub async fn open_reader(store: Arc<dyn ObjectStore>, path: &str) -> Result<Self, KvError> {
        let reader = DbReaderBuilder::new(path.to_string(), store)
            .build()
            .await
            .map_err(backend)?;
        Ok(Self {
            backend: Backend::Reader(Arc::new(reader)),
            cas_lock: Arc::new(tokio::sync::Mutex::new(())),
            dirty: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Open a read-only replica over a local directory (mainly for tests; real
    /// replicas share an object store with the writer).
    pub async fn open_local_reader(dir: impl AsRef<Path>) -> Result<Self, KvError> {
        let fs = LocalFileSystem::new_with_prefix(dir.as_ref()).map_err(backend)?;
        Self::open_reader(Arc::new(fs), "kv").await
    }

    /// Open a store over a local directory (an `object_store` `LocalFileSystem`)
    /// with SlateDB's default settings.
    pub async fn open_local(dir: impl AsRef<Path>) -> Result<Self, KvError> {
        Self::open_local_settings(dir, Settings::default()).await
    }

    /// Open a local-directory store with a low `flush_interval` for the
    /// latency-sensitive control plane.
    pub async fn open_local_with_flush(
        dir: impl AsRef<Path>,
        flush_interval: Duration,
    ) -> Result<Self, KvError> {
        Self::open_local_settings(dir, settings_with_flush(flush_interval)).await
    }

    /// Open a local control-plane store with the opt-in WAL repair (see
    /// [`SlateKv::open_with_flush_repair`]). Builds the SAME `LocalFileSystem` object store +
    /// `"kv"` root the plain [`open_local_with_flush`](Self::open_local_with_flush) uses, so the
    /// repair sees exactly the objects the open would replay.
    pub async fn open_local_with_flush_repair(
        dir: impl AsRef<Path>,
        flush_interval: Duration,
        repair: Option<RepairMode>,
    ) -> Result<Self, KvError> {
        std::fs::create_dir_all(&dir)?;
        let fs = local_object_store(dir.as_ref())?;
        Self::open_with_flush_repair(Arc::new(fs), "kv", flush_interval, repair).await
    }

    async fn open_local_settings(
        dir: impl AsRef<Path>,
        settings: Settings,
    ) -> Result<Self, KvError> {
        std::fs::create_dir_all(&dir)?;
        let fs = local_object_store(dir.as_ref())?;
        Self::open_with(Arc::new(fs), "kv", settings).await
    }

    /// Flush and cleanly close the database (call before dropping for
    /// durability). A no-op for a read replica.
    pub async fn close(&self) -> Result<(), KvError> {
        match &self.backend {
            Backend::Writer(db) => db.close().await.map_err(backend),
            Backend::Reader(_) => Ok(()),
        }
    }

    fn writer(&self) -> Result<&Db, KvError> {
        match &self.backend {
            Backend::Writer(db) => Ok(db),
            Backend::Reader(_) => Err(KvError::backend(
                "this SlateDB handle is a read-only replica; writes go to the writer process",
            )),
        }
    }

    /// Record that a write happened since the last checkpoint, so the next
    /// [`checkpoint`](KvStore::checkpoint) actually freezes the memtable (and an idle store's
    /// cadence checkpoint stays a cheap no-op). Called by every write path.
    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }
}

#[async_trait]
impl KvStore for SlateKv {
    async fn flush(&self) -> Result<(), KvError> {
        match &self.backend {
            // Force SlateDB's WAL/memtable to durable storage now (it otherwise
            // flushes on the configured timer), so a graceful shutdown loses no
            // committed writes. No-op for a read replica.
            Backend::Writer(db) => db.flush().await.map_err(backend),
            Backend::Reader(_) => Ok(()),
        }
    }

    async fn close(&self) -> Result<(), KvError> {
        // The real SlateDB `close()`: freeze memtables to L0, advance the durable frontier
        // (`replay_after_wal_id`), and shut down the writer/flusher/compactor tasks — so a
        // subsequent cold open has an empty WAL replay range (no torn tail). Unlike `flush()`
        // (WAL only), this is what makes the graceful shutdown lossless. The caller MUST have
        // quiesced every writer first: `Db::close()` marks the store closed then flushes, so a
        // late write errors `Closed` or forces a new WAL segment. No-op on a read replica.
        //
        // Delegates to the inherent [`SlateKv::close`] so both entry points share one impl.
        // Named `SlateKv::close` (NOT `Self::close`) deliberately: inside this trait `close` impl,
        // `Self::close` would resolve to THIS trait method — an infinite recursion — whereas
        // `SlateKv::close` names the inherent method. `allow(clippy::use_self)` keeps that explicit.
        #[allow(clippy::use_self)]
        SlateKv::close(self).await
    }

    async fn checkpoint(&self) -> Result<(), KvError> {
        // Advance the durable frontier WITHOUT closing: freeze the active memtable → L0 so every
        // acked write so far is past `replay_after_wal_id` (verified in slatedb 0.16 `db.rs:1816`
        // `flush_with_options` + `config.rs:474` `FlushType::MemTable`: it "freezes the active
        // memtable and writes all immutable memtable entries to the object store", advancing the
        // frontier exactly as `close()` does, minus the shutdown). This is the C1/C2 primitive that
        // makes the self-heal-on-open default lossless-for-acked.
        //
        // DIRTY-GATED (C1): skip the freeze — and the manifest PUT + empty L0 SST it would emit —
        // when nothing has been written since the last checkpoint, so an idle store's periodic
        // cadence tick is free. `swap(false)` claims the dirty state atomically; on a flush error we
        // RE-ARM the flag so the next checkpoint retries (never silently drop a pending freeze). A
        // crown-jewel write set the flag just before calling this, so the freeze here captures it.
        match &self.backend {
            Backend::Writer(db) => {
                // Claim the dirty state atomically; only then freeze. On a flush error, RE-ARM the
                // flag so the next checkpoint retries (never silently drop a pending freeze).
                if self.dirty.swap(false, Ordering::AcqRel)
                    && let Err(err) = db
                        .flush_with_options(FlushOptions {
                            flush_type: FlushType::MemTable,
                        })
                        .await
                {
                    self.dirty.store(true, Ordering::Release);
                    return Err(backend(err));
                }
                Ok(())
            }
            // A read replica has no memtable/frontier of its own (it polls the writer's manifest).
            Backend::Reader(_) => Ok(()),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        let value = match &self.backend {
            Backend::Writer(db) => db.get(key.as_bytes()).await.map_err(backend)?,
            Backend::Reader(reader) => reader.get(key.as_bytes()).await.map_err(backend)?,
        };
        Ok(value.map(|bytes| bytes.to_vec()))
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        // slatedb 0.16: `put`/`write` return a `WriteHandle` after the in-memory WAL/memtable update
        // and are NOT durable until `await_durable()` (a semantics change from 0.13, where an awaited
        // put was durable). The control plane needs durable writes — a deploy manifest / current
        // pointer must survive a crash — so we await durability here, preserving 0.13's awaited-put
        // behavior. (`write_batch_relaxed` deliberately does NOT await, for the bus fast path.)
        self.writer()?
            .put(key.as_bytes(), &value)
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        self.mark_dirty();
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.writer()?
            .delete(key.as_bytes())
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        self.mark_dirty();
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        // Scan the ordered keyspace from the prefix and stop once keys no longer
        // share it. Both writer and reader expose the same `scan`/`DbIterator`.
        let mut iter = match &self.backend {
            Backend::Writer(db) => db
                .scan(prefix.as_bytes().to_vec()..)
                .await
                .map_err(backend)?,
            Backend::Reader(reader) => reader
                .scan(prefix.as_bytes().to_vec()..)
                .await
                .map_err(backend)?,
        };
        let mut out = Vec::new();
        while let Some(kv) = iter.next().await.map_err(backend)? {
            let key = String::from_utf8_lossy(kv.key.as_ref());
            if !key.starts_with(prefix) {
                break;
            }
            out.push(key.into_owned());
        }
        Ok(out)
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        // Seek straight to the cursor in the ordered keyspace and walk forward,
        // capped at `limit` — O(limit), not O(keys-under-prefix) like the default.
        let start = format!("{prefix}{after}").into_bytes();
        let range = (
            std::ops::Bound::Excluded(start),
            std::ops::Bound::<Vec<u8>>::Unbounded,
        );
        let mut iter = match &self.backend {
            Backend::Writer(db) => db.scan(range).await.map_err(backend)?,
            Backend::Reader(reader) => reader.scan(range).await.map_err(backend)?,
        };
        let mut out = Vec::new();
        while out.len() < limit {
            let Some(kv) = iter.next().await.map_err(backend)? else {
                break;
            };
            let key = String::from_utf8_lossy(kv.key.as_ref());
            if !key.starts_with(prefix) {
                break;
            }
            out.push(key.into_owned());
        }
        Ok(out)
    }

    fn atomic_write_batch(&self) -> bool {
        // One SlateDB `WriteBatch` = a single atomic, durable commit (below), so the ready-set
        // fast path (B2) is safe over SlateKv: the ready marker rides the same batch as the index.
        true
    }

    fn supports_cas(&self) -> bool {
        // SlateDB is single-writer (manifest fencing), and the CAS below holds `cas_lock` across the
        // get→compare→write — so it is linearizable within this writer process (the only place a CAS
        // racer can be). Safe for the async-lane shard claim (B10) on a single-node SlateDB deploy.
        matches!(self.backend, Backend::Writer(_))
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        value: Vec<u8>,
    ) -> Result<bool, KvError> {
        // Hold the process-local CAS lock across read→compare→write so no other task in THIS writer
        // interleaves. SlateDB is single-writer, so no other process writes this store — making this
        // a linearizable compare-and-set. A durable `put` (awaited flush) commits the swap.
        let _guard = self.cas_lock.lock().await;
        let db = self.writer()?;
        let current = db.get(key.as_bytes()).await.map_err(backend)?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        // Durable put (slatedb 0.16 await_durable, as in `put` above): the CAS swap must survive a crash.
        db.put(key.as_bytes(), &value)
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        self.mark_dirty();
        Ok(true)
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Collect the whole group into one SlateDB WriteBatch: a single atomic,
        // durable commit (one flush) rather than one per key.
        let mut batch = WriteBatch::new();
        for op in ops {
            match op {
                WriteOp::Put(key, value) => batch.put(key.as_bytes(), &value),
                WriteOp::Delete(key) => batch.delete(key.as_bytes()),
            }
        }
        self.writer()?
            .write(batch)
            .await
            .map_err(backend)?
            .await_durable()
            .await
            .map_err(backend)?;
        self.mark_dirty();
        Ok(())
    }

    /// Durability-relaxed grouped write (see [`KvStore::write_batch_relaxed`]): commit the group to
    /// the in-memory memtable/WAL buffer and return WITHOUT awaiting the object-store flush (SlateDB
    /// `WriteOptions { await_durable: false }`). The buffered entries are flushed on the store's
    /// configured `flush_interval` — OR sooner when a later durable [`write_batch`](Self::write_batch)
    /// (the messaging checkpoint) forces the WAL buffer out. The batch is still atomic; only the
    /// *ack timing* changes. On a process crash before the next flush, entries acked here are lost —
    /// which is why only the bus publish path may call it, bounded to N un-durable messages by the
    /// caller's checkpoint (see `LogMessaging`).
    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        let mut batch = WriteBatch::new();
        for op in ops {
            match op {
                WriteOp::Put(key, value) => batch.put(key.as_bytes(), &value),
                WriteOp::Delete(key) => batch.delete(key.as_bytes()),
            }
        }
        // slatedb 0.16: `write` returns after the in-memory WAL/memtable update and is durable only
        // once `await_durable()` is called on the handle. We deliberately DROP the handle without
        // awaiting it — the relaxed (non-durable) semantics the bus fast path wants (equivalent to
        // 0.13's `WriteOptions { await_durable: false }`). The entries flush on the store's
        // `flush_interval` or when a later durable `write_batch` forces the WAL buffer out.
        self.writer()?.write(batch).await.map_err(backend)?;
        // Mark dirty so the periodic cadence checkpoint (or a later durable write's checkpoint)
        // freezes these buffered entries to L0 too — bounding the relaxed path's loss window as a
        // side benefit. The ack timing the bus wants is unchanged (this does NOT force a flush now).
        self.mark_dirty();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SlateDB settings for tests: the background **compactor and GC tasks are
    /// disabled** (`None`), so `close()` has nothing to drain. Those two task
    /// shutdowns — `close()` awaits `shutdown_task(COMPACTOR)` then
    /// `shutdown_task(GC)` — were the source of the intermittent close/reopen
    /// stall on a loaded CI host. The durability path these tests exercise (WAL
    /// flush → L0 → reopen) is unaffected; production keeps both enabled (it
    /// wants compaction + space reclamation over the store's lifetime).
    ///
    /// `flush_interval: None` keeps SlateDB's default flush timer (mirrors
    /// [`SlateKv::open_local`]); `Some(d)` overrides it (mirrors
    /// [`SlateKv::open_local_with_flush`]).
    fn test_settings(flush_interval: Option<Duration>) -> Settings {
        let mut settings = Settings::default();
        if let Some(interval) = flush_interval {
            settings.flush_interval = Some(interval);
        }
        settings.compactor_options = None;
        settings.garbage_collector_options = None;
        settings
    }

    /// Run a SlateDB test `body` under a timeout guard, retrying on a **fresh**
    /// directory. With the background compactor + GC disabled ([`test_settings`])
    /// the close/reopen stall this used to paper over is gone, so this is now a
    /// cheap backstop only: `#[serial]` (below) removes intra-binary concurrency,
    /// and should any future hang appear it fails **fast** (≈100s) rather than
    /// stalling the job for hours.
    async fn with_fresh_slatedb_dir<F, Fut>(name: &str, body: F)
    where
        F: Fn(std::path::PathBuf) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        for attempt in 0..4u32 {
            let dir = std::env::temp_dir().join(format!(
                "boatramp-slatedb-{name}-{}-{attempt}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            match tokio::time::timeout(std::time::Duration::from_secs(25), body(dir.clone())).await
            {
                Ok(()) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return;
                }
                Err(_) => eprintln!(
                    "slatedb test `{name}` attempt {attempt} exceeded 25s (SlateDB \
                     close/reopen stalled); retrying on a fresh dir"
                ),
            }
        }
        panic!("slatedb test `{name}` stalled on every attempt");
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn slatedb_round_trips() {
        with_fresh_slatedb_dir("roundtrip", |dir| async move {
            let kv = SlateKv::open_local_settings(&dir, test_settings(None))
                .await
                .unwrap();

            kv.put("alias/blog/staging", b"id-1".to_vec())
                .await
                .unwrap();
            kv.put("alias/blog/prod", b"id-2".to_vec()).await.unwrap();
            kv.put("other/x", b"z".to_vec()).await.unwrap();
            assert_eq!(
                kv.get("alias/blog/staging").await.unwrap(),
                Some(b"id-1".to_vec())
            );
            assert_eq!(kv.get("missing").await.unwrap(), None);

            let mut keys = kv.list_prefix("alias/blog/").await.unwrap();
            keys.sort();
            assert_eq!(keys, vec!["alias/blog/prod", "alias/blog/staging"]);

            // Native bounded range scan: ordered, cursor-exclusive, limited, and
            // it never leaks the `other/x` key that sorts just past the prefix.
            assert_eq!(
                kv.list_from("alias/blog/", "", 10).await.unwrap(),
                vec!["alias/blog/prod", "alias/blog/staging"],
            );
            assert_eq!(
                kv.list_from("alias/blog/", "", 1).await.unwrap(),
                vec!["alias/blog/prod"],
                "limit caps the batch",
            );
            assert_eq!(
                kv.list_from("alias/blog/", "prod", 10).await.unwrap(),
                vec!["alias/blog/staging"],
                "resumes strictly after the cursor",
            );
            assert_eq!(
                kv.list_from("alias/blog/", "staging", 10).await.unwrap(),
                Vec::<String>::new(),
                "past the last key → empty (no other-prefix leak)",
            );

            kv.delete("alias/blog/staging").await.unwrap();
            assert_eq!(kv.get("alias/blog/staging").await.unwrap(), None);

            kv.close().await.unwrap();
        })
        .await;
    }

    /// SlateKv's compare-and-swap (B10): the single-writer `cas_lock` makes it a linearizable CAS
    /// within the writer process — expected-absent create, exact-bytes match, stale-expected refusal,
    /// and a concurrent-racer set with exactly one winner (the property the async-lane claim needs).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn slatedb_compare_and_swap_is_linearizable() {
        with_fresh_slatedb_dir("cas", |dir| async move {
            let kv = Arc::new(
                SlateKv::open_local_settings(&dir, test_settings(None))
                    .await
                    .unwrap(),
            );
            assert!(
                kv.supports_cas(),
                "the writer advertises a linearizable CAS"
            );

            // Expected-absent creates; expected-absent on a present key does not swap.
            assert!(
                kv.compare_and_swap("inv/1", None, b"queued".to_vec())
                    .await
                    .unwrap()
            );
            assert_eq!(kv.get("inv/1").await.unwrap(), Some(b"queued".to_vec()));
            assert!(
                !kv.compare_and_swap("inv/1", None, b"x".to_vec())
                    .await
                    .unwrap()
            );
            // A stale expected does not swap; the exact prior bytes do.
            assert!(
                !kv.compare_and_swap("inv/1", Some(b"WRONG"), b"x".to_vec())
                    .await
                    .unwrap()
            );
            assert_eq!(kv.get("inv/1").await.unwrap(), Some(b"queued".to_vec()));
            assert!(
                kv.compare_and_swap("inv/1", Some(b"queued"), b"running".to_vec())
                    .await
                    .unwrap()
            );
            assert_eq!(kv.get("inv/1").await.unwrap(), Some(b"running".to_vec()));

            // Race: many tasks in this single writer process try queued→<id>; exactly one wins.
            kv.put("inv/2", b"queued".to_vec()).await.unwrap();
            let mut set = tokio::task::JoinSet::new();
            for i in 0..16u32 {
                let kv = kv.clone();
                set.spawn(async move {
                    kv.compare_and_swap("inv/2", Some(b"queued"), i.to_le_bytes().to_vec())
                        .await
                        .unwrap()
                });
            }
            let mut wins = 0;
            while let Some(r) = set.join_next().await {
                if r.unwrap() {
                    wins += 1;
                }
            }
            assert_eq!(
                wins, 1,
                "exactly one racing CAS wins on the single-writer store"
            );

            Arc::try_unwrap(kv).ok().unwrap().close().await.unwrap();
        })
        .await;
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_persists_then_reopens() {
        // Durability is a property of the object store, not the local disk: SlateDB
        // writes the WAL / L0 SSTs / manifest to the `ObjectStore`, and a reopen replays
        // them from it. So this exercises the exact flush → close (memtable → L0) →
        // reopen-replay path against a **shared in-memory** store (the same instance for
        // both opens, so the reopen reads exactly what close persisted) — with ZERO disk
        // I/O. That removes this test's historical flake: `close()` flushes memtables to
        // L0 and the reopen replays, and on the contended shared musl CI runner that
        // real `LocalFileSystem` I/O occasionally stalled past the timeout (it was the
        // only test that reopened). In-memory it is deterministic and needs no timeout
        // harness. `slatedb_round_trips` keeps the on-disk `LocalFileSystem` path.
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        // A low flush interval (slatedb 0.16: a durable `put` awaits `await_durable()`, which waits for
        // the timer-driven WAL flush — so a long interval would hang; 5 ms keeps the awaited write fast,
        // matching the production control-plane store). Then an explicit `flush()`, close (memtable →
        // L0), and reopen-replay — the durability + reopen contract this test exists to exercise.
        let kv = SlateKv::open_with(
            store.clone(),
            "kv",
            test_settings(Some(std::time::Duration::from_millis(5))),
        )
        .await
        .unwrap();
        kv.put("k", b"v".to_vec()).await.unwrap(); // durable (awaits durability before returning)
        kv.flush().await.unwrap(); // exercise the explicit flush() path too
        kv.close().await.unwrap();

        let reopened = SlateKv::open_with(store.clone(), "kv", test_settings(None))
            .await
            .unwrap();
        assert_eq!(reopened.get("k").await.unwrap(), Some(b"v".to_vec()));
        reopened.close().await.unwrap();
    }

    /// **C1 GATE** — a mid-life `checkpoint()` (a MemTable freeze, NO close) advances the durable
    /// frontier (`replay_after_wal_id`) past the prior acked writes: the write moves from the WAL
    /// into L0, so a subsequent crash's WAL replay range no longer holds it. This is the primitive
    /// the crown-jewel per-write frontier-sync and the periodic cadence are built on. Runs over a
    /// shared `InMemory` store (deterministic, non-stalling — no close/reopen), reading the frontier
    /// via the read-only `Admin` path `repair_wal_tail` uses.
    ///
    /// Mutation this guards: make `checkpoint()` a no-op (drop the `flush_with_options(MemTable)`).
    /// Then the frontier never advances on a checkpoint and this `f1 > f0` assertion fails RED —
    /// which is exactly why the self-heal-on-open default would then be able to drop an acked write.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn checkpoint_advances_the_durable_frontier_without_close() {
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let kv = SlateKv::open_with(
            store.clone(),
            "kv",
            test_settings(Some(Duration::from_millis(5))),
        )
        .await
        .unwrap();
        // A durable crown-jewel-shaped write (sealed secret). Durable ≠ frontier-advanced: it lives
        // in the WAL until a memtable freeze.
        kv.put("secret/acme/idp", b"sealed".to_vec()).await.unwrap();
        let f0 = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;

        // Checkpoint: freeze the memtable → L0, advancing the frontier — WITHOUT closing the store.
        kv.checkpoint().await.unwrap();
        let f1 = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;
        assert!(
            f1 > f0,
            "checkpoint() must advance the durable frontier (was {f0}, now {f1}) — the crown-jewel \
             frontier-sync invariant"
        );
        // The write is still readable, and a SECOND checkpoint on the now-idle store is a cheap
        // dirty-gated no-op (the frontier does not move again).
        assert_eq!(
            kv.get("secret/acme/idp").await.unwrap(),
            Some(b"sealed".to_vec())
        );
        kv.checkpoint().await.unwrap();
        let f2 = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;
        assert_eq!(
            f2, f1,
            "an idle checkpoint is a dirty-gated no-op (frontier unchanged)"
        );
        kv.close().await.unwrap();
    }

    // ===================================================================================
    // Self-heal-on-open gates (v0.9.0 KV-recovery, C3/C7). InMemory (non-stalling): seed a real
    // store, inject a torn shape, then open via `open_with_policy` and assert the flip's behavior.
    // ===================================================================================

    /// Seed a real store over `store`: one durable write + a clean close (frontier past the write).
    /// Returns the durable frontier so a test can inject strictly beyond it.
    async fn seed_and_frontier(store: &Arc<dyn ObjectStore>, root: &str) -> u64 {
        {
            let kv = SlateKv::open_with(
                store.clone(),
                root,
                test_settings(Some(Duration::from_millis(5))),
            )
            .await
            .unwrap();
            kv.put("secret/acme/idp", b"sealed-oauth".to_vec())
                .await
                .unwrap();
            kv.close().await.unwrap();
        }
        crate::wal_repair::repair_wal_tail(store, root, RepairMode::DryRun)
            .await
            .unwrap()
            .frontier
    }

    /// Put a crafted >10-byte version-0 torn WAL object at `{root}/wal/{id:020}.sst`.
    async fn put_torn_wal(store: &Arc<dyn ObjectStore>, root: &str, id: u64) {
        let mut body = vec![0xABu8; 64];
        let n = body.len();
        body[n - 2..n].copy_from_slice(&0u16.to_be_bytes());
        store
            .put(
                &ObjPath::from(format!("{root}/wal/{id:020}.sst")),
                body.into(),
            )
            .await
            .unwrap();
    }

    /// The highest `{root}/wal/{id:020}.sst` id currently present (the object the most-recent,
    /// not-yet-L0-frozen write lives in). Used by the linchpin to tear the secret's OWN WAL object
    /// in the mutation (no-checkpoint) case, modelling a crash that interrupts that very write.
    async fn highest_wal_id(store: &Arc<dyn ObjectStore>, root: &str) -> u64 {
        use futures::StreamExt;
        let prefix = ObjPath::from(format!("{root}/wal"));
        let mut stream = store.list(Some(&prefix));
        let mut max = 0u64;
        while let Some(item) = stream.next().await {
            if let Some(id) = item
                .ok()
                .and_then(|m| m.location.filename().map(str::to_string))
                .and_then(|n| n.strip_suffix(".sst").and_then(|s| s.parse::<u64>().ok()))
            {
                max = max.max(id);
            }
        }
        max
    }

    /// **LINCHPIN GATE (C1+C2)** — the single proof the self-heal-on-open DEFAULT cannot drop an
    /// ACKED crown-jewel write. A sealed-secret write goes through the frontier-syncing (checkpointed)
    /// path, so it is frozen to L0 *past the durable frontier before ack*; a subsequent hard crash
    /// leaves a torn trailing WAL object, self-heal quarantines it, and the secret — already in L0 —
    /// SURVIVES. The assertion is FIXED (the secret survives).
    ///
    /// Anti-hollow (env-driven, NO production seam): under
    /// `BOATRAMP_LINCHPIN_MUTATION=no_frontier_sync` the crown-jewel write SKIPS the checkpoint —
    /// modelling a crown-jewel write left frontier-async (the C2 miss Security caught in daemon-config)
    /// — so the secret stays in the WAL object the crash tears, self-heal quarantines THAT object, and
    /// the secret is LOST (or the open refuses): the fixed survival assertion then FAILS RED. That red
    /// is the proof the checkpoint on the crown-jewel write path is load-bearing. The injection tears
    /// the secret's own WAL object only in the mutation case because that is where the un-checkpointed
    /// secret actually lives; with the checkpoint it has moved to L0 and the crash tears a fresh object.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn crown_jewel_write_survives_torn_tail_self_heal_linchpin() {
        use slatedb::object_store::memory::InMemory;
        let skip_checkpoint =
            std::env::var("BOATRAMP_LINCHPIN_MUTATION").unwrap_or_default() == "no_frontier_sync";

        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let kv = SlateKv::open_with(
            store.clone(),
            "kv",
            test_settings(Some(Duration::from_millis(5))),
        )
        .await
        .unwrap();

        // The acked crown-jewel write. In prod this is the CheckpointKv-wrapped / `*_checkpointed`
        // path: put (await_durable) THEN checkpoint (freeze the memtable → L0, advancing the frontier
        // PAST this write). The mutation skips the checkpoint (the frontier-async C2 miss).
        kv.put("secret/acme/idp", b"sealed-crown-jewel".to_vec())
            .await
            .unwrap();
        if !skip_checkpoint {
            kv.checkpoint().await.unwrap();
        }

        // Model a hard crash: a torn in-flight WAL object, and NO clean close.
        let frontier = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;
        if skip_checkpoint {
            // No checkpoint ⇒ the secret is still in its WAL object, beyond the un-advanced frontier.
            // Tearing THAT object = the crash interrupted the secret's own write ⇒ self-heal drops it.
            put_torn_wal(&store, "kv", highest_wal_id(&store, "kv").await).await;
        } else {
            // Checkpoint advanced the frontier past the secret (now in L0). The crash tears a FRESH
            // in-flight object beyond the frontier; self-heal quarantines it, the L0 secret survives.
            put_torn_wal(&store, "kv", frontier + 1).await;
        }
        drop(kv); // a hard crash, NOT a graceful close

        // Self-heal reopen (the DEFAULT). FIXED assertion: the acked secret survives.
        let opened = SlateKv::open_with_policy(
            store.clone(),
            "kv",
            test_settings(Some(Duration::from_millis(5))),
            KvOpenPolicy::SelfHeal,
        )
        .await
        .expect(
            "LINCHPIN: self-heal must OPEN past a torn tail (a refusal here under the mutation is \
             also RED for the survival guarantee)",
        );
        assert_eq!(
            opened.get("secret/acme/idp").await.unwrap(),
            Some(b"sealed-crown-jewel".to_vec()),
            "LINCHPIN: an ACKED crown-jewel write MUST survive a torn-tail self-heal — it is \
             frontier-synced to L0 before ack, so the quarantined torn tail never held it"
        );
        opened.close().await.unwrap();
    }

    /// **C3/C7 GATE** — SelfHeal recovers a sole safe trailing torn WAL tail: it quarantines +
    /// OPENS, every committed key (incl. the sealed secret) survives, and a durable DEGRADED.json
    /// breadcrumb is written naming the quarantined id.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn self_heal_opens_after_quarantining_a_safe_torn_tail() {
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let frontier = seed_and_frontier(&store, "kv").await;
        let torn_id = frontier + 1;
        put_torn_wal(&store, "kv", torn_id).await;

        let kv = SlateKv::open_with_policy(
            store.clone(),
            "kv",
            test_settings(Some(Duration::from_millis(5))),
            KvOpenPolicy::SelfHeal,
        )
        .await
        .expect("SelfHeal must recover a sole safe trailing torn tail and OPEN");
        assert_eq!(
            kv.get("secret/acme/idp").await.unwrap(),
            Some(b"sealed-oauth".to_vec()),
            "the sealed secret (below the frontier) MUST survive the self-heal"
        );
        // C6: a non-empty self-heal wrote the durable breadcrumb naming the quarantined id.
        let marker = read_degraded_marker(&store, "kv")
            .await
            .unwrap()
            .expect("a non-empty self-heal must write DEGRADED.json");
        assert_eq!(marker.quarantined_ids, vec![torn_id]);
        assert!(!marker.loss_window.is_empty());
        kv.close().await.unwrap();
    }

    /// **C11 GATE** — Strict does NOT self-heal the same safe tail: it fails LOUD (the opt-out
    /// restores today's behavior) and mutates nothing (no DEGRADED.json).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn strict_policy_fails_loud_on_a_safe_torn_tail() {
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let frontier = seed_and_frontier(&store, "kv").await;
        put_torn_wal(&store, "kv", frontier + 1).await;

        let opened = SlateKv::open_with_policy(
            store.clone(),
            "kv",
            test_settings(Some(Duration::from_millis(5))),
            KvOpenPolicy::Strict,
        )
        .await;
        let Err(err) = opened else {
            panic!("Strict must FAIL LOUD on a torn tail (never self-heal)");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("kv recover") || msg.contains("kv repair"),
            "the strict loud error must name a recovery path: {msg}"
        );
        assert!(
            read_degraded_marker(&store, "kv").await.unwrap().is_none(),
            "Strict must mutate nothing (no DEGRADED.json)"
        );
    }

    /// **C3/C7 GATE** — an UNSAFE shape (a torn COMPACTED/L0 SST, manifest-referenced) makes SelfHeal
    /// FAIL LOUD (naming the object) and mutate NOTHING under the DEFAULT — never quarantine the WAL
    /// tail then die, never remove the compacted SST. This is the ordering-bug fix + the data-loss guard.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn self_heal_refuses_and_preserves_on_an_unsafe_compacted_tear() {
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let frontier = seed_and_frontier(&store, "kv").await;
        put_torn_wal(&store, "kv", frontier + 1).await; // a safe trailing tail…
        // …AND an out-of-scope torn compacted/L0 SST (version 0) — the unsafe shape.
        let mut body = vec![0xCDu8; 128];
        let n = body.len();
        body[n - 2..n].copy_from_slice(&0u16.to_be_bytes());
        let torn_compacted = ObjPath::from("kv/compacted/01J79C21YKR31J2BS1EFXJZ7MZ.sst");
        store.put(&torn_compacted, body.into()).await.unwrap();

        let opened = SlateKv::open_with_policy(
            store.clone(),
            "kv",
            test_settings(Some(Duration::from_millis(5))),
            KvOpenPolicy::SelfHeal,
        )
        .await;
        let Err(err) = opened else {
            panic!("SelfHeal must FAIL LOUD on an out-of-scope torn compacted SST");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("REFUSED") && msg.contains(&torn_compacted.to_string()),
            "the refusal must name the torn compacted SST: {msg}"
        );
        // Data-loss guard: the compacted SST was NEVER removed, and the safe WAL tail was NOT
        // quarantined either (C3 dry-run-first: an unsafe shape mutates NOTHING).
        assert!(
            store.head(&torn_compacted).await.is_ok(),
            "the torn compacted SST must NOT be mutated"
        );
        assert!(
            store
                .head(&ObjPath::from(format!("kv/wal/{:020}.sst", frontier + 1)))
                .await
                .is_ok(),
            "C3: an unsafe shape must NOT quarantine the safe WAL tail either (dry-run-first, mutate nothing)"
        );
        assert!(
            read_degraded_marker(&store, "kv").await.unwrap().is_none(),
            "a refused self-heal writes no DEGRADED.json"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn read_replica_sees_writer_and_refuses_writes() {
        with_fresh_slatedb_dir("replica", |dir| async move {
            // The writer process commits config, then flushes/closes so the manifest
            // reflects it (a real replica polls the manifest; here we close to make
            // the committed state visible to a freshly-opened reader).
            let writer =
                SlateKv::open_local_settings(&dir, test_settings(Some(Duration::from_millis(5))))
                    .await
                    .unwrap();
            writer.put("site/blog", b"hash-1".to_vec()).await.unwrap();
            writer
                .write_batch(vec![
                    WriteOp::Put("siteconfig/hash-1".into(), b"{}".to_vec()),
                    WriteOp::Put("current/blog".into(), b"dep-1".to_vec()),
                ])
                .await
                .unwrap();
            writer.close().await.unwrap();

            // A read replica over the same store serves the writer's data…
            let replica = SlateKv::open_local_reader(&dir).await.unwrap();
            assert_eq!(
                replica.get("site/blog").await.unwrap(),
                Some(b"hash-1".to_vec())
            );
            let mut keys = replica.list_prefix("siteconfig/").await.unwrap();
            keys.sort();
            assert_eq!(keys, vec!["siteconfig/hash-1"]);

            // …and refuses writes (control-plane writes go to the writer process).
            assert!(replica.put("x", b"y".to_vec()).await.is_err());
            assert!(
                replica
                    .write_batch(vec![WriteOp::Delete("site/blog".into())])
                    .await
                    .is_err()
            );
        })
        .await;
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn slatedb_write_batch_commits_group() {
        with_fresh_slatedb_dir("batch", |dir| async move {
            let kv =
                SlateKv::open_local_settings(&dir, test_settings(Some(Duration::from_millis(5))))
                    .await
                    .unwrap();

            kv.put("manifests/dep-1", b"old".to_vec()).await.unwrap();
            kv.write_batch(vec![
                WriteOp::Put("manifests/dep-2".into(), b"new".to_vec()),
                WriteOp::Put("current/blog".into(), b"dep-2".to_vec()),
                WriteOp::Delete("manifests/dep-1".into()),
            ])
            .await
            .unwrap();

            assert_eq!(
                kv.get("manifests/dep-2").await.unwrap(),
                Some(b"new".to_vec())
            );
            assert_eq!(
                kv.get("current/blog").await.unwrap(),
                Some(b"dep-2".to_vec())
            );
            assert_eq!(kv.get("manifests/dep-1").await.unwrap(), None);

            kv.close().await.unwrap();
        })
        .await;
    }

    /// Incident regression (v0.5.5 — the `slatedb` 0.13.1 → 0.16.0 upgrade): a control-plane store whose
    /// **tail WAL object was frozen at 0 bytes** — a crash, or a crash-consistent fly volume snapshot of
    /// a *live* store, freezing a just-opened WAL object before its data blocks reached the device — must
    /// still **open**, skipping only that never-durable empty tail, instead of failing fatally with
    /// `Data error: empty SSTable` on *every* cold open (the production-down incident). Every committed
    /// key (projects/sites/**sealed secrets**) must survive. SlateDB 0.16 tolerates it natively (an
    /// object ≤ the SST footer is a fence marker with zero committed entries, so replay skips it); 0.13.1
    /// (as v0.5.4 shipped) did NOT — this test fails against 0.13.1 and passes on 0.16.
    ///
    /// Setup uses `test_settings` (compactor + GC OFF) so the WAL objects linger on disk after close,
    /// letting us inject a realistic empty tail object at `max_id + 1`. The injected object is > the
    /// manifest's `replay_after_wal_id`, so it lands in the reopen's WAL replay range — exactly where a
    /// frozen tail object sits. The reopen therefore reads the empty object during replay; only the
    /// upstream tolerance makes it non-fatal.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen stalls under the static-musl test harness (see test-orm-tenancy); \
                the CI `test (slatedb WAL recovery)` job runs it unignored on the host toolchain"]
    async fn empty_tail_wal_object_is_tolerated_and_data_survives() {
        with_fresh_slatedb_dir("emptytail", |dir| async move {
            // 1. A few durable control-plane writes, then a clean flush + close.
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.write_batch(vec![
                    WriteOp::Put("project/acme".into(), b"seed".to_vec()),
                    WriteOp::Put("secret/acme/idp".into(), b"sealed".to_vec()),
                ])
                .await
                .unwrap();
                kv.put("current/console", b"deploy-7".to_vec())
                    .await
                    .unwrap();
                kv.flush().await.unwrap();
                kv.close().await.unwrap();
            }

            // 2. Inject the frozen tail: a 0-byte WAL object at (highest existing WAL id) + 1.
            let wal_dir = dir.join("kv").join("wal");
            let mut ids: Vec<u64> = std::fs::read_dir(&wal_dir)
                .expect("wal/ dir should exist after writes")
                .filter_map(Result::ok)
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<u64>().ok())
                })
                .collect();
            ids.sort_unstable();
            let max_id = *ids
                .last()
                .expect("expected WAL objects on disk (compactor/GC are off in test_settings)");
            let empty = wal_dir.join(format!("{:020}.sst", max_id + 1));
            std::fs::write(&empty, b"").unwrap();
            assert_eq!(
                std::fs::metadata(&empty).unwrap().len(),
                0,
                "the injected tail WAL object must be 0 bytes"
            );

            // 3. Reopen: the empty tail is tolerated and every committed key survives.
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .expect(
                    "EMPTY WAL TAIL: reopen must tolerate the frozen 0-byte tail WAL object, not \
                     fail with `empty SSTable`",
                );
                assert_eq!(
                    kv.get("current/console").await.unwrap(),
                    Some(b"deploy-7".to_vec())
                );
                assert_eq!(
                    kv.get("project/acme").await.unwrap(),
                    Some(b"seed".to_vec())
                );
                assert_eq!(
                    kv.get("secret/acme/idp").await.unwrap(),
                    Some(b"sealed".to_vec()),
                    "the sealed secret must survive the recovery"
                );
                kv.close().await.unwrap();
            }
            eprintln!("EMPTY WAL TAIL RECOVERED OK");
        })
        .await;
    }

    // ===================================================================================
    // WAL-repair gate battery (Part A close-not-flush + Part B store-backed gates).
    //
    // These open a REAL SlateDB store over `LocalFileSystem` and close/reopen it, so — like
    // `empty_tail_wal_object_is_tolerated_and_data_survives` above — they are `#[ignore]`d for
    // the static-musl harness (close→reopen stalls there) and run UNIGNORED on the host toolchain
    // via the CI `test (slatedb WAL recovery)` job. Each is WALL-CLOCK bound by
    // `with_fresh_slatedb_dir`'s timeout (per the #499/#500 lesson), not iteration-count.
    // ===================================================================================

    /// Discover the highest WAL SST id currently on disk under `dir/kv/wal/`.
    fn max_wal_id(dir: &std::path::Path) -> u64 {
        let wal_dir = dir.join("kv").join("wal");
        std::fs::read_dir(&wal_dir)
            .expect("wal/ dir should exist after writes")
            .filter_map(Result::ok)
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .max()
            .expect("expected WAL objects on disk (compactor/GC are off in test_settings)")
    }

    /// Inject a **>10-byte torn** WAL object (version word 0 — the production `InvalidVersion`
    /// signature) at `dir/kv/wal/{id:020}.sst`. Distinct from the existing `empty_tail` test,
    /// which injects a 0-byte object (the ALREADY-tolerated fence case): this is the >10-byte
    /// partial that HARD-FAILS a default cold open (the coverage gap B1 closes).
    fn inject_torn_tail(dir: &std::path::Path, id: u64) {
        let wal_dir = dir.join("kv").join("wal");
        // 64 bytes of filler ending in an 8-byte offset + a 2-byte BE version word of 0.
        let mut body = vec![0xABu8; 64];
        let n = body.len();
        body[n - 2..n].copy_from_slice(&0u16.to_be_bytes());
        std::fs::write(wal_dir.join(format!("{id:020}.sst")), &body).unwrap();
    }

    /// Build the same `LocalFileSystem`-over-`kv` store the opener uses, as an
    /// `Arc<dyn ObjectStore>` the repair takes.
    fn fs_store(dir: &std::path::Path) -> Arc<dyn ObjectStore> {
        Arc::new(local_object_store(dir).unwrap())
    }

    /// **A1** — close-not-flush advances the durable frontier: after a graceful `close()`, the
    /// reopen's WAL replay range is EMPTY (all acked data is in L0, not the WAL), and every key
    /// survives. The mutation this guards: reverting `close()` to `flush()` on shutdown leaves the
    /// frontier un-advanced, so the WAL objects for the writes stay beyond the frontier — this
    /// asserts ZERO candidates beyond the frontier after close, which a flush-only shutdown fails.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn a1_close_advances_frontier_empty_wal_replay() {
        with_fresh_slatedb_dir("a1-close-frontier", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.write_batch(vec![
                    WriteOp::Put("project/acme".into(), b"seed".to_vec()),
                    WriteOp::Put("secret/acme/idp".into(), b"sealed".to_vec()),
                    WriteOp::Put("current/console".into(), b"deploy-9".to_vec()),
                ])
                .await
                .unwrap();
                // The graceful shutdown primitive under test: `close()` (freeze memtables → L0,
                // advance the durable frontier), NOT the old bare `flush()`.
                KvStore::close(&kv).await.unwrap();
            }

            // After close, NO WAL object should sit beyond the durable frontier — a dry-run repair
            // reports the frontier + candidates; the candidate list beyond it must be empty.
            let store = fs_store(&dir);
            let report = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
                .await
                .unwrap();
            assert!(
                report.candidates.is_empty(),
                "A1: after close() the durable frontier (replay_after_wal_id={}) must cover every \
                 WAL object — a flush-only shutdown would leave the write WAL objects beyond it; \
                 got candidates {:?}",
                report.frontier,
                report.candidates,
            );

            // And the reopen still sees every key (close was lossless).
            let kv = SlateKv::open_local_settings(&dir, test_settings(None))
                .await
                .unwrap();
            assert_eq!(
                kv.get("project/acme").await.unwrap(),
                Some(b"seed".to_vec())
            );
            assert_eq!(
                kv.get("secret/acme/idp").await.unwrap(),
                Some(b"sealed".to_vec())
            );
            assert_eq!(
                kv.get("current/console").await.unwrap(),
                Some(b"deploy-9".to_vec())
            );
            KvStore::close(&kv).await.unwrap();
            eprintln!("A1 CLOSE-ADVANCES-FRONTIER OK");
        })
        .await;
    }

    /// **B1** — the DEFAULT cold open stays LOUD on the >10-byte version-0 torn tail (the
    /// coverage gap: the existing empty-tail test only injects a 0-byte tail), and the error names
    /// the repair. Mutation guarded: silently tolerating the torn tail on the default open would
    /// make this `Ok(...)`, failing the `is_err()` assertion.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b1_default_open_is_loud_on_torn_version0_tail() {
        with_fresh_slatedb_dir("b1-loud", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.put("project/acme", b"seed".to_vec()).await.unwrap();
                kv.flush().await.unwrap(); // WAL durable, frontier NOT advanced (no close)
            }
            // Inject a >10-byte version-0 torn object at max_id+1 — beyond the frontier, so it
            // lands in the reopen's WAL replay range and fails the default open.
            inject_torn_tail(&dir, max_wal_id(&dir) + 1);

            // DEFAULT open (no repair) must FAIL LOUD and name the repair.
            let msg = match SlateKv::open_local_with_flush(&dir, Duration::from_millis(5)).await {
                Ok(_) => panic!("B1: default cold open MUST fail loud on a torn version-0 tail"),
                Err(err) => err.to_string(),
            };
            assert!(
                msg.contains("boatramp kv repair") && msg.contains("BOATRAMP_KV_REPAIR"),
                "B1: the loud error must name the opt-in repair; got: {msg}"
            );
            eprintln!("B1 DEFAULT-LOUD-ON-TORN-TAIL OK");
        })
        .await;
    }

    /// **B2** — the repair recovers the store AND every committed key (projects / sites / **sealed
    /// secrets** / current pointers) survives. This is the load-bearing gate.
    ///
    /// Anti-hollow mutation: the guard is that the reopen after `--apply` returns the exact bytes
    /// for EVERY key, incl. the sealed secret. If the repair over-quarantined (dropped a readable
    /// WAL object holding an acked write) the reopen would miss a key and the assert fails; if it
    /// under-quarantined (left the torn tail) the reopen would fail to open at all.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b2_repair_recovers_and_all_keys_survive() {
        with_fresh_slatedb_dir("b2-recover", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(&dir, test_settings(Some(Duration::from_millis(5))))
                    .await
                    .unwrap();
                kv.write_batch(vec![
                    WriteOp::Put("project/acme".into(), b"seed".to_vec()),
                    WriteOp::Put("site/blog".into(), b"hash-1".to_vec()),
                    WriteOp::Put("secret/acme/idp".into(), b"sealed-oauth".to_vec()),
                    WriteOp::Put("current/console".into(), b"deploy-11".to_vec()),
                ])
                .await
                .unwrap();
                kv.flush().await.unwrap(); // real WAL objects, durable; frontier NOT advanced
            }
            // A torn version-0 tail beyond the readable WAL objects (the trailing tear).
            inject_torn_tail(&dir, max_wal_id(&dir) + 1);

            // Repair-then-open (the `serve --repair-wal` path).
            let kv = SlateKv::open_local_with_flush_repair(
                &dir,
                Duration::from_millis(5),
                Some(RepairMode::Apply),
            )
            .await
            .expect("B2: repair-then-open must succeed after quarantining the torn trailing tail");

            // EVERY committed key must survive — especially the sealed secret.
            assert_eq!(kv.get("project/acme").await.unwrap(), Some(b"seed".to_vec()));
            assert_eq!(kv.get("site/blog").await.unwrap(), Some(b"hash-1".to_vec()));
            assert_eq!(
                kv.get("secret/acme/idp").await.unwrap(),
                Some(b"sealed-oauth".to_vec()),
                "B2: the sealed secret MUST survive the repair (the repair only touched the torn tail)"
            );
            assert_eq!(kv.get("current/console").await.unwrap(), Some(b"deploy-11".to_vec()));
            KvStore::close(&kv).await.unwrap();
            eprintln!("B2 REPAIR-RECOVERS-ALL-KEYS OK");
        })
        .await;
    }

    /// **B4 (beyond-frontier half)** — the repair NEVER quarantines a WAL object at or below the
    /// durable frontier. After a clean `close()` (frontier advanced past every WAL object), even
    /// injecting a torn object AT an at-or-below-frontier id leaves the dry-run with nothing to do
    /// beyond the frontier — the beyond-frontier filter excludes it. (The unreadable-manifest half
    /// of B4 is `wal_repair::tests::repair_refuses_when_the_manifest_is_unreadable`.)
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b4_repair_never_touches_at_or_below_frontier() {
        with_fresh_slatedb_dir("b4-frontier", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.write_batch(vec![
                    WriteOp::Put("project/acme".into(), b"seed".to_vec()),
                    WriteOp::Put("secret/acme/idp".into(), b"sealed".to_vec()),
                ])
                .await
                .unwrap();
                KvStore::close(&kv).await.unwrap(); // advances the frontier past every WAL object
            }
            let store = fs_store(&dir);
            let report = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
                .await
                .unwrap();
            // The frontier now covers every WAL object, so the candidate set (strictly beyond it)
            // is empty and nothing is quarantined — the repair cannot touch acked-into-L0 data.
            assert!(
                report.candidates.is_empty() && report.quarantined.is_empty(),
                "B4: nothing at or below the durable frontier ({}) may be considered/quarantined; \
                 got candidates {:?}, quarantined {:?}",
                report.frontier,
                report.candidates,
                report.quarantined,
            );
            eprintln!("B4 BEYOND-FRONTIER-ONLY OK");
        })
        .await;
    }

    /// **B5** — quarantined bytes are preserved: the offending object is byte-identical under
    /// `wal-quarantine/{stamp}/` and ABSENT from `wal/` after `--apply`.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b5_quarantined_bytes_preserved_and_removed_from_wal() {
        with_fresh_slatedb_dir("b5-bytes", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.put("project/acme", b"seed".to_vec()).await.unwrap();
                kv.flush().await.unwrap();
            }
            let torn_id = max_wal_id(&dir) + 1;
            inject_torn_tail(&dir, torn_id);
            let torn_path = dir
                .join("kv")
                .join("wal")
                .join(format!("{torn_id:020}.sst"));
            let original_bytes = std::fs::read(&torn_path).unwrap();

            let store = fs_store(&dir);
            let report = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::Apply)
                .await
                .unwrap();
            assert!(report.applied && report.quarantined == vec![torn_id]);

            // The original is gone from wal/.
            assert!(
                !torn_path.exists(),
                "B5: the quarantined object must be removed from wal/"
            );
            // A byte-identical copy exists under wal-quarantine/<stamp>/.
            let qdir = dir.join("kv").join("wal-quarantine");
            let mut found = None;
            for stamp_entry in std::fs::read_dir(&qdir).unwrap().filter_map(Result::ok) {
                let candidate = stamp_entry.path().join(format!("{torn_id:020}.sst"));
                if candidate.exists() {
                    found = Some(candidate);
                }
            }
            let quarantined_path = found.expect("B5: a quarantine copy must exist");
            assert_eq!(
                std::fs::read(&quarantined_path).unwrap(),
                original_bytes,
                "B5: the quarantined object must be byte-identical to the original"
            );
            eprintln!("B5 QUARANTINED-BYTES-PRESERVED OK");
        })
        .await;
    }

    /// **B6** — dry-run purity: a `DryRun` mutates NOTHING (the torn object stays in `wal/`, no
    /// `wal-quarantine/` dir is created). Mutation guarded: a repair that copied/deleted under
    /// `DryRun` would leave the object gone from `wal/` and this asserts it is still there.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b6_dry_run_mutates_nothing() {
        with_fresh_slatedb_dir("b6-dryrun", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.put("project/acme", b"seed".to_vec()).await.unwrap();
                kv.flush().await.unwrap();
            }
            let torn_id = max_wal_id(&dir) + 1;
            inject_torn_tail(&dir, torn_id);
            let torn_path = dir
                .join("kv")
                .join("wal")
                .join(format!("{torn_id:020}.sst"));

            let store = fs_store(&dir);
            let report = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::DryRun)
                .await
                .unwrap();
            // The plan identifies the tail…
            assert_eq!(
                report.quarantined,
                vec![torn_id],
                "B6: the dry-run still plans the tail"
            );
            assert!(!report.applied, "B6: a dry-run must report applied=false");
            // …but mutates NOTHING.
            assert!(
                torn_path.exists(),
                "B6: the torn object must still be in wal/ after a dry-run"
            );
            assert!(
                !dir.join("kv").join("wal-quarantine").exists(),
                "B6: a dry-run must not create the wal-quarantine/ dir"
            );
            eprintln!("B6 DRY-RUN-PURITY OK");
        })
        .await;
    }

    /// **B3 (store-backed)** — the trailing-only refusal over a REAL store: a torn object with a
    /// READABLE WAL object at a higher id (a mid-range gap) makes the repair REFUSE + fail loud,
    /// mutating nothing. This complements the pure-logic `plan_refuses_torn_below_readable_mid_range_gap`
    /// with an end-to-end store fixture. Anti-hollow mutation (in `plan_trailing_tail`): relaxing to
    /// "quarantine any torn" turns this refusal into a silent quarantine of the mid object → the acked
    /// data in the higher readable object is dropped, and this `MidRangeGap` assertion fails.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b3_refuses_mid_range_gap_over_real_store() {
        with_fresh_slatedb_dir("b3-midgap", |dir| async move {
            {
                let kv = SlateKv::open_local_settings(
                    &dir,
                    test_settings(Some(Duration::from_millis(5))),
                )
                .await
                .unwrap();
                kv.put("project/acme", b"seed".to_vec()).await.unwrap();
                kv.flush().await.unwrap();
            }
            // Inject a torn object at max+1, THEN a readable-looking object at max+2 (a higher id).
            // The torn object is now MID-range (a readable object sits above it) → REFUSE.
            let top = max_wal_id(&dir);
            inject_torn_tail(&dir, top + 1);
            // A well-formed (version-1) object at the higher id — the "later acked data" that must
            // not be gapped. Footer bytes[0..8] = a valid metadata offset (<= size-10) so it passes
            // the C4 offset-sanity probe and reads Readable; bytes[8..10] = version 1 BE.
            let wal_dir = dir.join("kv").join("wal");
            let mut readable = vec![0xCDu8; 64];
            let n = readable.len();
            let meta_offset = (64u64 - 10) / 2;
            readable[n - 10..n - 2].copy_from_slice(&meta_offset.to_be_bytes());
            readable[n - 2..n].copy_from_slice(&1u16.to_be_bytes());
            std::fs::write(wal_dir.join(format!("{:020}.sst", top + 2)), &readable).unwrap();

            let store = fs_store(&dir);
            let err = crate::wal_repair::repair_wal_tail(&store, "kv", RepairMode::Apply)
                .await
                .expect_err("B3: a torn object below a readable one must REFUSE (mid-range gap)");
            assert!(
                matches!(err, crate::wal_repair::WalRepairError::MidRangeGap { .. }),
                "B3: got {err:?}"
            );
            // And it mutated nothing (the torn object is still in wal/, no quarantine dir).
            assert!(
                wal_dir.join(format!("{:020}.sst", top + 1)).exists(),
                "B3: a refused repair must not delete the torn object"
            );
            assert!(
                !dir.join("kv").join("wal-quarantine").exists(),
                "B3: a refused repair must not create a quarantine dir"
            );
            eprintln!("B3 MID-RANGE-GAP-REFUSAL OK");
        })
        .await;
    }

    /// **B7** — `await_durable` characterization guardrail: a durable `put` (the control-plane
    /// path awaits `await_durable()`) is genuinely durable — it survives a reopen with NO explicit
    /// `flush()` and NO `close()` between the write and the reopen. The whole repair's safety rests
    /// on this "await_durable = the write is in the WAL/durable" contract; a future slatedb bump
    /// that changed durable-seq semantics (making an awaited put non-durable, or advancing the
    /// frontier differently) trips this guardrail. Uses a SHARED `InMemory` store across both opens
    /// (so the reopen reads exactly what the first handle persisted) — deterministic, no timeout.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "on-disk close→reopen; the CI `test (slatedb WAL recovery)` job runs it unignored"]
    async fn b7_await_durable_write_survives_reopen_without_flush_or_close() {
        use slatedb::object_store::memory::InMemory;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        {
            let kv = SlateKv::open_with(
                store.clone(),
                "kv",
                test_settings(Some(Duration::from_millis(5))),
            )
            .await
            .unwrap();
            // A durable `put` — the KvStore impl awaits `await_durable()` before returning. We then
            // DROP the handle with NO flush() and NO close(): only the await_durable contract makes
            // the write survive.
            kv.put("current/console", b"deploy-durable".to_vec())
                .await
                .unwrap();
            drop(kv);
        }
        // Reopen a fresh handle over the SAME store: the awaited write must be present.
        let reopened = SlateKv::open_with(store.clone(), "kv", test_settings(None))
            .await
            .expect("B7: reopen of a store with a durable-but-unclosed write must succeed");
        assert_eq!(
            reopened.get("current/console").await.unwrap(),
            Some(b"deploy-durable".to_vec()),
            "B7: an `await_durable` put MUST survive a reopen with no flush/close — if this fails, \
             a slatedb bump changed the durable-seq semantics the WAL repair relies on"
        );
        KvStore::close(&reopened).await.unwrap();
        eprintln!("B7 AWAIT-DURABLE-CHARACTERIZATION OK");
    }

    /// **Live** (ignored): open a control-plane SlateKv over Cloudflare R2, write,
    /// then close and reopen a fresh handle over the same R2 path and confirm the
    /// data survived — the durability contract a scale-to-zero container relies
    /// on. Needs `BR_R2_TEST_BUCKET` + `BR_R2_TEST_ENDPOINT` and ambient
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
    #[tokio::test]
    #[ignore = "needs live R2 credentials (BR_R2_TEST_BUCKET/ENDPOINT + AWS creds)"]
    async fn slatedb_over_r2_survives_reopen() {
        let Ok(bucket) = std::env::var("BR_R2_TEST_BUCKET") else {
            eprintln!("skipping: BR_R2_TEST_BUCKET not set");
            return;
        };
        let cfg = S3StoreConfig {
            bucket,
            endpoint: std::env::var("BR_R2_TEST_ENDPOINT").ok(),
            region: std::env::var("BR_R2_TEST_REGION").ok(),
            path_style: true,
        };
        let path = "boatramp-kv-livetest";
        let flush = Duration::from_millis(5);
        {
            let kv = SlateKv::open_s3_with_flush(&cfg, path, flush)
                .await
                .unwrap();
            kv.put("current/site", b"deploy-42".to_vec()).await.unwrap();
            assert_eq!(
                kv.get("current/site").await.unwrap(),
                Some(b"deploy-42".to_vec())
            );
            kv.close().await.unwrap();
        }
        // A fresh handle over the same R2 path must observe the persisted write.
        let kv = SlateKv::open_s3_with_flush(&cfg, path, flush)
            .await
            .unwrap();
        assert_eq!(
            kv.get("current/site").await.unwrap(),
            Some(b"deploy-42".to_vec())
        );
        kv.close().await.unwrap();
    }
}
