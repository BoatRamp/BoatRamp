//! Opt-in **WAL tail repair** for the SlateDB control-plane store (P0, v0.7.2).
//!
//! ## Why this exists
//!
//! A graceful shutdown now [quiesces then `close()`s](crate::kv_slatedb::SlateKv::close)
//! the store (Part A), which advances the durable frontier and produces no torn
//! tail. But a *hard* crash — or a crash-consistent volume snapshot that freezes a
//! just-renamed WAL object whose data blocks / dir-entry had not yet fsync'd, or an
//! R2 partial multipart — can leave a **partial trailing WAL object**: the footer is
//! present but the version word is 0 (`InvalidVersion { actual_version: 0 }`), which
//! SlateDB's replay rejects fatally on *every* cold open. The store is then unbootable.
//! The pre-existing v0.5.5 tolerance covers only the ≤10-byte (0-byte) fence case;
//! this >10-byte partial is not covered, so cold open fails loud (by design) and the
//! operator opts into this repair.
//!
//! ## Safety contract (load-bearing — data-loss guard)
//!
//! An acked control-plane write lives only in the WAL until the next L0 flush, so a
//! torn WAL object CAN hold acked-into-WAL data. Quarantining is therefore permitted
//! ONLY for an object that is ALL of:
//!
//! 1. **Beyond the durable frontier** — strictly `> replay_after_wal_id`, the frontier
//!    read from the manifest. If the manifest is UNREADABLE we cannot establish a
//!    frontier, so we **REFUSE** (never quarantine blind).
//! 2. **Physically torn** — fails the same footer/version probe SlateDB's SST reader
//!    uses (`format/sst.rs`): len > 10, last-10-byte footer, version word ∈ {1, 2}.
//!    A ≤10-byte object is the already-tolerated fence case and is LEFT in place.
//! 3. **Strictly trailing** — NO readable WAL object exists at a higher id. If a
//!    readable object sits above a torn one (a mid-range gap), quarantining the torn
//!    object would drop the acked WAL data in the later readable objects, so we
//!    **REFUSE + fail loud** rather than cause silent data loss.
//!
//! On a hard crash this repair may lose the most-recent acked-into-WAL-but-not-yet-L0
//! writes — a bounded, honest loss-window that the caller's success message states.
//! Part A (graceful quiesce-then-close) makes the *graceful* case lossless.
//!
//! ## Whole-store awareness (v0.8.x — never silently no-op)
//!
//! SlateDB stores more than WAL objects: compacted / L0 SSTs live under
//! `{root}/compacted/` (slatedb `paths.rs` `COMPACTED_PATH`) and the manifest under
//! `{root}/manifest/`. A torn version-0 SST can therefore land in `compacted/` too (a
//! partial L0 flush / snapshot / R2 partial multipart), and that object is INVISIBLE to a
//! WAL-only scan — so an earlier repair could find no WAL candidate and return a no-op
//! "nothing to repair" while the store still refused to open. That silent no-op was the
//! "repair didn't work" incident.
//!
//! This repair now scans the WHOLE store (`wal/` **and** `compacted/`) with the same
//! format-agnostic footer probe and REPORTS every torn object it finds. Crucially:
//!
//! **A compacted/L0 SST (and the manifest) is DETECTION-ONLY — this tool NEVER quarantines,
//! copies, renames, or deletes it.** A compacted SST is referenced by the manifest; removing
//! one without a manifest rollback would drop acked data. So anything outside the safe
//! WAL-tail scope (a torn compacted SST, or a torn WAL object that is not part of the safe
//! trailing tail) is surfaced in [`RepairReport::out_of_scope_torn`] and, on
//! [`RepairMode::Apply`], makes the repair **fail loud** with
//! [`WalRepairError::UnrepairableTornObject`] naming the exact path(s) — rather than report
//! success while the store still holds a torn SST that will fail open. Manifest-aware recovery
//! for a torn compacted SST is an escalation, not something this tool performs.
//!
//! The **invariant**: an [`RepairMode::Apply`] `Ok` result means the store is now free of ALL
//! torn SSTs (the safe trailing WAL tail was quarantined, and nothing else torn remains);
//! otherwise it returns an `Err` naming exactly what still remains.
//!
//! ## Mechanic
//!
//! [`RepairMode::DryRun`] mutates NOTHING — it only computes and returns the plan.
//! [`RepairMode::Apply`] **copies** (never renames) each offending trailing-torn
//! object to `{root}/wal-quarantine/{stamp}/{:020}.sst`, writes a
//! `MANIFEST.json` describing the action, THEN deletes the original, and finally
//! verifies the store by an **actual open attempt** (a throwaway
//! [`slatedb::Db`] build with repair disabled — see [`verify_opens`]) before
//! returning. A footer re-scan alone cannot see every corruption (a truncated
//! edge whose last two bytes read as a valid version word, a torn block below the
//! footer); the definitive post-repair check is that the store genuinely opens.
//! Success ⇒ genuinely fixed; a failed open ⇒ fail loud
//! ([`WalRepairError::OpenVerificationFailed`]), never a false success. The
//! caller then proceeds to open the (now-verified) store.

use std::sync::Arc;
use std::time::Duration;

use slatedb::admin::Admin;
// `ObjectStore` for `list`; `ObjectStoreExt` for the `get_range`/`put`/`copy`/`delete`
// convenience methods (an extension trait in object_store 0.14).
use slatedb::object_store::path::Path as ObjPath;
use slatedb::object_store::{ObjectStore, ObjectStoreExt};
use slatedb::{Db, Settings};

/// The SST footer is the last 10 bytes: 8-byte metadata offset + 2-byte version word.
/// Mirrors slatedb `format/sst.rs` `NUM_FOOTER_BYTES` (an object at or below this size
/// carries no committed entries — the fence/empty case slatedb tolerates natively).
const NUM_FOOTER_BYTES: u64 = 10;
/// The SST format versions slatedb accepts (`SST_FORMAT_VERSION` / `_V2`). A footer
/// whose version word is anything else (notably `0`, the production torn-tail signature)
/// is a torn/partial object.
const SUPPORTED_SST_VERSIONS: [u16; 2] = [1, 2];

/// What a repair pass is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairMode {
    /// Compute and return the plan; mutate NOTHING (no copy, no delete, no manifest write).
    DryRun,
    /// Perform the quarantine (copy → manifest → delete → re-verify).
    Apply,
}

/// How a single WAL candidate object was classified by the footer probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalClass {
    /// A well-formed SST footer with a supported version — holds committed data, LEAVE it.
    Readable,
    /// ≤ the footer size (the 0-byte / fence case slatedb already tolerates) — LEAVE it.
    Fence,
    /// A footer whose version word is unsupported (e.g. `0`) — physically torn.
    Torn,
}

/// One WAL object considered by the repair (strictly beyond the durable frontier).
#[derive(Debug, Clone)]
pub struct WalCandidate {
    /// The parsed `{:020}.sst` WAL id.
    pub id: u64,
    /// The object size in bytes (as reported by the store `list`).
    pub size: u64,
    /// The footer-probe classification.
    pub class: WalClass,
}

/// Which out-of-scope area a torn object detected by the whole-store scan lives in — the reason
/// the safe WAL-tail quarantine cannot (and must not) touch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TornKind {
    /// A torn SST under `{root}/compacted/` (a compacted / L0 SST). **DETECTION-ONLY**: it is
    /// referenced by the manifest, so removing it without a manifest rollback would drop acked
    /// data — this tool never quarantines/copies/renames/deletes it. Needs manifest-aware recovery.
    CompactedSst,
    /// A WAL object that is torn but NOT part of the safe trailing tail — e.g. a torn WAL object
    /// at or below the durable frontier (below slatedb's replay boundary; SAFETY step 2 forbids
    /// touching anything at/below the frontier), reported for completeness rather than quarantined.
    WalNonTrailing,
}

/// A torn SST object detected OUTSIDE the safe WAL-tail quarantine scope. **DETECTION-ONLY**: the
/// repair never mutates any object described here (see [`TornKind`]); it is surfaced so a dry-run
/// shows the complete picture and an apply fails loud instead of silently succeeding.
#[derive(Debug, Clone)]
pub struct TornObject {
    /// The full object path (e.g. `kv/compacted/01J79C21YKR31J2BS1EFXJZ7MR.sst`).
    pub path: String,
    /// The object size in bytes (as reported by the store `list`).
    pub size: u64,
    /// The footer-probe classification (always [`WalClass::Torn`] for this list).
    pub class: WalClass,
    /// Which out-of-scope area / reason it falls under.
    pub kind: TornKind,
}

/// The outcome of a repair pass (dry-run or applied).
#[derive(Debug, Clone)]
pub struct RepairReport {
    /// The durable frontier read from the manifest (`replay_after_wal_id`): only ids
    /// strictly greater than this were considered.
    pub frontier: u64,
    /// Every WAL candidate beyond the frontier, highest id first, with its class.
    pub candidates: Vec<WalCandidate>,
    /// The ids that were (or, in dry-run, would be) quarantined — the trailing torn tail.
    pub quarantined: Vec<u64>,
    /// The quarantine directory the objects were (or would be) copied under, when any.
    pub quarantine_dir: Option<String>,
    /// Whether the pass actually mutated the store (`false` for a dry-run or a no-op).
    pub applied: bool,
    /// Torn SST objects found OUTSIDE the safe WAL-tail quarantine scope (from the WHOLE-store
    /// scan): every torn compacted / L0 SST under `{root}/compacted/`, plus any torn WAL object
    /// not in the quarantine plan (torn at/below the frontier). **DETECTION-ONLY** — the repair
    /// NEVER quarantines/copies/renames/deletes anything listed here (a compacted SST is
    /// referenced by the manifest; removing it without a manifest rollback would drop acked data).
    /// A non-empty list means the store still holds a torn SST this tool will not auto-repair: a
    /// dry-run reports it, and an [`RepairMode::Apply`] fails loud with
    /// [`WalRepairError::UnrepairableTornObject`] (after any safe WAL-tail quarantine).
    pub out_of_scope_torn: Vec<TornObject>,
}

impl RepairReport {
    /// A pass that found nothing to repair (no torn trailing tail beyond the frontier AND no
    /// out-of-scope torn object anywhere in the store). Both must be empty for the store to open.
    pub fn is_noop(&self) -> bool {
        self.quarantined.is_empty() && self.out_of_scope_torn.is_empty()
    }
}

/// Why a repair refused or failed. Every refusal is fail-LOUD: the caller must not
/// proceed to open, because opening would either lose acked data or still fail.
#[derive(Debug, thiserror::Error)]
pub enum WalRepairError {
    /// The manifest could not be read (absent or corrupt), so no durable frontier can be
    /// established. Refuse rather than quarantine blind (SAFETY step 1).
    #[error(
        "control-plane WAL repair refused: the SlateDB manifest at `{root}` is unreadable \
         ({detail}), so the durable frontier cannot be established — refusing to quarantine \
         any WAL object without a frontier (would risk dropping acked data)"
    )]
    UnreadableManifest {
        /// The store root the manifest lives under.
        root: String,
        /// The underlying reason the manifest read failed.
        detail: String,
    },

    /// A torn object has a readable WAL object at a HIGHER id (a mid-range gap).
    /// Quarantining the torn object would gap the acked data in the later readable
    /// objects, so refuse + fail loud (SAFETY step 4).
    #[error(
        "control-plane WAL repair refused: WAL object {torn_id:020} is torn but a READABLE \
         WAL object ({readable_id:020}) sits at a higher id — quarantining the torn object \
         would drop the acked data in the later object(s). Refusing (this is not a trailing \
         tear). Inspect `{root}/wal/` manually"
    )]
    MidRangeGap {
        /// The store root.
        root: String,
        /// The torn object's id.
        torn_id: u64,
        /// The readable object's id that sits above it.
        readable_id: u64,
    },

    /// An internal invariant tripped: a candidate slated for quarantine was not strictly
    /// beyond the frontier (SAFETY step 5). Should be unreachable — a defensive fail-closed.
    #[error(
        "control-plane WAL repair aborted: candidate {id:020} is not strictly beyond the \
         durable frontier ({frontier:020}) — refusing to quarantine at or below the frontier"
    )]
    NotBeyondFrontier {
        /// The offending candidate id.
        id: u64,
        /// The durable frontier.
        frontier: u64,
    },

    /// A WAL id is MISSING from the surviving objects BELOW a readable (data-bearing) object — a
    /// hole in the replay range that quarantining the trailing tail did not (and cannot) fix. WAL
    /// replay cannot bridge a hole: the readable object above the gap holds acked data that cannot
    /// be reached without the missing id's entries, so opening would be lossy/inconsistent, and the
    /// repair fails loud (SAFETY: an unfixed hole beyond the frontier is real data loss the repair
    /// must never paper over). Distinct from [`MidRangeGap`](Self::MidRangeGap) (a torn object below
    /// a readable one): in a `WalIdHole` the id is entirely ABSENT, not present-but-torn.
    #[error(
        "control-plane WAL repair refused: WAL id {missing_id:020} is MISSING but a readable WAL \
         object ({above_readable_id:020}) sits above the gap at `{root}` — a trailing-tail \
         quarantine cannot fix a mid-range hole (replay cannot bridge a gap). Refusing (an absent \
         WAL id below acked data is unfixed data loss). Run `boatramp kv recover` to diagnose"
    )]
    WalIdHole {
        /// The store root.
        root: String,
        /// The first absent WAL id in the surviving replay range.
        missing_id: u64,
        /// The highest readable (data-bearing) surviving object that sits above the gap.
        above_readable_id: u64,
    },

    /// After the safe WAL-tail quarantine, a REAL open attempt of the store STILL failed. The
    /// footer probe cannot detect every corruption (a truncated edge whose last bytes read as a
    /// valid version word, a torn block below the footer offset), so the definitive post-repair
    /// verification is an actual [`slatedb::Db`] open (repair disabled). A failure here means the
    /// store is NOT genuinely repaired — refuse to claim success (SAFETY: never return `Ok` for a
    /// store the server's own cold open would then die on).
    #[error(
        "control-plane WAL repair: the safe trailing WAL tail was handled, but a REAL open of the \
         store at `{root}` STILL failed ({detail}) — the tear is beyond a trailing-tail quarantine \
         (e.g. a truncated edge or a torn block the footer probe cannot see). Refusing to report \
         success. Run `boatramp kv recover` to diagnose / adopt a clean volume snapshot"
    )]
    OpenVerificationFailed {
        /// The store root.
        root: String,
        /// The underlying open failure.
        detail: String,
    },

    /// The store holds torn SST object(s) OUTSIDE the safe WAL-tail scope that this tool will
    /// NOT auto-remove — a torn compacted / L0 SST (referenced by the manifest, so removing it
    /// without a manifest rollback would drop acked data), or a torn non-trailing WAL object.
    /// On an apply this is returned AFTER any safe WAL-tail quarantine, so the repair never
    /// reports success while the store still holds a torn SST that will fail its cold open —
    /// the core "stop silently not-working" guarantee. Recovery needs manifest-aware handling /
    /// escalation, not this tool.
    #[error(
        "control-plane WAL repair: the store at `{root}` still holds torn SST object(s) OUTSIDE \
         the safe WAL-tail scope that this tool will NOT auto-remove — a compacted/L0 SST is \
         referenced by the manifest, so removing it without a manifest rollback would drop acked \
         data. {detail} Torn out-of-scope object(s): {}",
        .objects.join(", ")
    )]
    UnrepairableTornObject {
        /// The store root.
        root: String,
        /// The exact path(s) of the torn out-of-scope object(s) still present.
        objects: Vec<String>,
        /// Whether the safe WAL-tail quarantine was applied first, and the escalation note.
        detail: String,
    },

    /// **F2 (v0.11.0)** — the LATEST manifest is empty/torn/absent AND no manifest generation present
    /// on the store decodes, so there is no last-good generation to roll back to. Recovery from here is
    /// WAL-from-0 reconstruction, which is LOSSY (acked-into-L0 data lives only in manifest-referenced
    /// SSTs; slatedb has no rebuild-from-WAL API) — so it is opt-in/loud ONLY, NEVER automatic. Fail
    /// loud → the recovery-mode listener / operator escalation.
    #[error(
        "control-plane manifest recovery refused: the latest manifest at `{root}` is empty/torn and \
         NONE of the {listed} manifest generation(s) present decode — there is no last-good generation \
         to roll back to. Automatic WAL-from-0 reconstruction is LOSSY and is never performed silently. \
         Recover from a clean volume snapshot (`boatramp kv recover --adopt-volume <mounted-path>`) or \
         restore the object store from a backup"
    )]
    NoDecodableManifest {
        /// The store root.
        root: String,
        /// How many manifest generation objects were present but undecodable (or absent).
        listed: usize,
    },

    /// **MF2 (v0.11.0)** — rolling back to the last-good generation G (durable frontier F) would need a
    /// WAL replay range `(F, …]` that is NOT intact: a WAL id is ABSENT below the highest surviving WAL
    /// object. WAL-GC advanced off a non-durable generation (the fsync silent-loss window this release
    /// closes: a torn manifest N that was page-cache-readable let a GC pass collect the `(F, F_N]`
    /// replay range) and the acked writes in the hole are unrecoverable, so the rollback would SILENTLY
    /// drop acked state → REFUSE. Complements [`WalIdHole`](Self::WalIdHole) (a hole below a readable
    /// survivor within a single-generation repair); this is the leading/interior gap a manifest
    /// ROLLBACK to an older, lower frontier exposes — the blind spot `check_survivor_contiguity` leaves
    /// (it returns Ok when the whole tail is gone; `verify_opens` proves BOOT, not RETENTION).
    #[error(
        "control-plane manifest recovery refused: rolling back to a generation with durable frontier \
         {rolled_back_frontier} would replay WAL from {}..={highest_wal_id}, but WAL id \
         {missing_wal_id:020} is MISSING at `{root}` — a GC hole in the replay range (replay cannot \
         bridge an absent id). Refusing (an absent WAL id below the surviving tail is unrecoverable \
         acked loss). Recover from a clean volume snapshot",
        rolled_back_frontier + 1
    )]
    ManifestRollbackGcHole {
        /// The store root.
        root: String,
        /// The durable frontier F of the generation being rolled back to (replay starts at F+1).
        rolled_back_frontier: u64,
        /// The first ABSENT WAL id in the replay range (F, highest].
        missing_wal_id: u64,
        /// The highest surviving WAL object id (the top of the range that must be intact).
        highest_wal_id: u64,
    },

    /// **MF2 (v0.11.0)** — the highest decodable manifest generation G is BELOW the manifest GC
    /// boundary (`{root}/gc/manifest.boundary`): GC has swept past it, so adopting it could reference
    /// deleted objects. Defensive fail-closed (never adopt a generation below the GC boundary).
    #[error(
        "control-plane manifest recovery refused: the highest decodable manifest generation \
         {generation} at `{root}` is BELOW the manifest GC boundary {boundary} — GC has swept past it, \
         so it may reference deleted objects. Refusing to adopt a generation below the GC boundary"
    )]
    BelowGcBoundary {
        /// The store root.
        root: String,
        /// The highest decodable generation id.
        generation: u64,
        /// The manifest GC boundary read from `{root}/gc/manifest.boundary` (default 0 when absent).
        boundary: u64,
    },

    /// An underlying object-store operation failed (list/get/copy/delete/put).
    #[error("control-plane WAL repair: object-store operation failed: {0}")]
    Store(String),
}

/// Read the durable frontier `replay_after_wal_id` from the store's latest manifest via
/// slatedb's public [`Admin`] API. `Ok(None)` (no manifest) and `Err` are both treated as
/// UNREADABLE by the caller — we never proceed without a frontier.
async fn read_frontier(store: &Arc<dyn ObjectStore>, root: &str) -> Result<u64, WalRepairError> {
    let admin = Admin::builder(root.to_string(), store.clone()).build();
    match admin.read_manifest(None).await {
        Ok(Some(manifest)) => Ok(manifest.replay_after_wal_id()),
        Ok(None) => Err(WalRepairError::UnreadableManifest {
            root: root.to_string(),
            detail: "no manifest found (an uninitialized or wrong store root?)".to_string(),
        }),
        Err(err) => Err(WalRepairError::UnreadableManifest {
            root: root.to_string(),
            detail: err.to_string(),
        }),
    }
}

/// Parse a `{:020}.sst` WAL filename into its numeric id (mirrors slatedb `paths.rs`).
/// Returns `None` for any object under `wal/` that is not a zero-padded `.sst` (defensive).
fn parse_wal_id(location: &ObjPath) -> Option<u64> {
    let name = location.filename()?;
    let stem = name.strip_suffix(".sst")?;
    stem.parse::<u64>().ok()
}

/// Probe an object's footer the way slatedb's SST reader does (`format/sst.rs`):
/// - `len <= 10` ⇒ [`WalClass::Fence`] (the already-tolerated empty/fence object; LEAVE),
/// - else read the last 10 bytes; the version word is the last 2 bytes (big-endian u16)
///   at footer offset 8. Version ∈ {1, 2} ⇒ [`WalClass::Readable`]; anything else (0, …)
///   ⇒ [`WalClass::Torn`].
///
/// This never decodes the SST body — it is a pure structural probe, so a torn/partial
/// object is classified without SlateDB's fatal replay error.
async fn classify(
    store: &Arc<dyn ObjectStore>,
    location: &ObjPath,
    size: u64,
) -> Result<WalClass, WalRepairError> {
    if size <= NUM_FOOTER_BYTES {
        // Matches slatedb's `obj_len <= NUM_FOOTER_BYTES_LONG` fence/empty branch: no
        // committed entries, tolerated by replay. Leave it for the native skip.
        return Ok(WalClass::Fence);
    }
    let footer = store
        .get_range(location, (size - NUM_FOOTER_BYTES)..size)
        .await
        .map_err(|e| WalRepairError::Store(e.to_string()))?;
    if footer.len() != NUM_FOOTER_BYTES as usize {
        // A short read of the tail range is itself a sign of a torn object.
        return Ok(WalClass::Torn);
    }
    // Metadata-offset sanity (C4 — the truncated-edge blind spot). Footer bytes[0..8] are the
    // big-endian u64 offset of the SST metadata block, which MUST lie strictly before the footer
    // itself (i.e. within `[0, size - NUM_FOOTER_BYTES]`). An offset past that boundary is garbage:
    // a torn / truncated object even when the 2-byte version word below happens to read as a
    // supported value (the exact case a version-only probe misclassifies as `Readable`, only for
    // the real open to then die with `ChecksumMismatch`). `size > NUM_FOOTER_BYTES` here (the fence
    // branch returned above), so `size - NUM_FOOTER_BYTES` cannot underflow.
    let meta_offset = u64::from_be_bytes([
        footer[0], footer[1], footer[2], footer[3], footer[4], footer[5], footer[6], footer[7],
    ]);
    if meta_offset > size - NUM_FOOTER_BYTES {
        return Ok(WalClass::Torn);
    }
    // Version word = the last 2 bytes (footer bytes 8..10), big-endian — the same slice
    // slatedb's `read_length_and_metadata_offset_and_version` reads with `get_u16`.
    let version = u16::from_be_bytes([footer[8], footer[9]]);
    if SUPPORTED_SST_VERSIONS.contains(&version) {
        Ok(WalClass::Readable)
    } else {
        Ok(WalClass::Torn)
    }
}

/// List every `wal/{:020}.sst` object under `root` that is strictly beyond `frontier`,
/// classify each, and return them sorted **descending** by id (highest first — the walk
/// order the trailing-only rule needs).
async fn scan_candidates(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    frontier: u64,
) -> Result<Vec<WalCandidate>, WalRepairError> {
    use futures::StreamExt;
    let wal_prefix = ObjPath::from(format!("{root}/wal"));
    let mut stream = store.list(Some(&wal_prefix));
    let mut candidates = Vec::new();
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        let Some(id) = parse_wal_id(&meta.location) else {
            continue; // not a WAL SST object (defensive)
        };
        // Candidates are strictly beyond the durable frontier: objects at or below it are
        // already reflected in L0 / the manifest and must never be touched (SAFETY step 2).
        if id <= frontier {
            continue;
        }
        let class = classify(store, &meta.location, meta.size).await?;
        candidates.push(WalCandidate {
            id,
            size: meta.size,
            class,
        });
    }
    // Highest id first — the trailing-tear walk goes from the top down.
    candidates.sort_by_key(|c| std::cmp::Reverse(c.id));
    Ok(candidates)
}

/// Scan the WHOLE store for torn SST objects that fall OUTSIDE the safe WAL-tail quarantine
/// scope, so the repair can REPORT them (dry-run) and FAIL LOUD (apply) instead of silently
/// no-op'ing while the store still won't open. Two sources, neither ever mutated:
///
/// 1. **`{root}/compacted/` SSTs** — compacted / L0 SSTs (`SsTableId::Compacted(ulid)`, so a ULID
///    filename, NOT a `{:020}.sst` WAL id — we list the prefix and classify every `.sst` by path,
///    not via `parse_wal_id`). The footer probe is format-agnostic (last 10 bytes only), so it
///    classifies a compacted SST unchanged. Any [`WalClass::Torn`] one is a
///    [`TornKind::CompactedSst`] — **DETECTION-ONLY** (referenced by the manifest; never removed).
/// 2. **`{root}/wal/` objects at or below the frontier** — a torn WAL object at/below the durable
///    frontier is below slatedb's replay boundary (so it doesn't block THIS open) and SAFETY step 2
///    forbids touching anything at/below the frontier, so it is reported as [`TornKind::WalNonTrailing`]
///    rather than quarantined. (Torn WAL objects strictly beyond the frontier are the quarantine
///    plan's domain — a trailing run is quarantined, a mid-range gap is a hard `MidRangeGap` refusal.)
///
/// Returns the torn objects sorted by path for a stable report. Never copies/renames/deletes.
async fn scan_out_of_scope_torn(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    frontier: u64,
) -> Result<Vec<TornObject>, WalRepairError> {
    use futures::StreamExt;
    let mut out = Vec::new();

    // 1. Compacted / L0 SSTs under `{root}/compacted/`.
    let compacted_prefix = ObjPath::from(format!("{root}/compacted"));
    let mut stream = store.list(Some(&compacted_prefix));
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        // Classify only `.sst` objects (skip any incidental non-SST under the prefix, defensively).
        let Some(name) = meta.location.filename() else {
            continue;
        };
        if !name.ends_with(".sst") {
            continue;
        }
        if classify(store, &meta.location, meta.size).await? == WalClass::Torn {
            out.push(TornObject {
                path: meta.location.to_string(),
                size: meta.size,
                class: WalClass::Torn,
                kind: TornKind::CompactedSst,
            });
        }
    }

    // 2. Torn WAL objects at or below the durable frontier (non-trailing; the plan owns > frontier).
    let wal_prefix = ObjPath::from(format!("{root}/wal"));
    let mut stream = store.list(Some(&wal_prefix));
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        let Some(id) = parse_wal_id(&meta.location) else {
            continue;
        };
        if id > frontier {
            continue; // strictly beyond the frontier — the quarantine plan's domain, not here
        }
        if classify(store, &meta.location, meta.size).await? == WalClass::Torn {
            out.push(TornObject {
                path: meta.location.to_string(),
                size: meta.size,
                class: WalClass::Torn,
                kind: TornKind::WalNonTrailing,
            });
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Decide the fail-loud refusal for out-of-scope torn objects on an APPLY. Pure (no I/O), so the
/// refusal shape/message is unit-testable without a live slatedb manifest: given the whole-store
/// out-of-scope torn list and the WAL-tail ids that were (or would be) quarantined, return
/// `Some(UnrepairableTornObject)` naming every out-of-scope path when the list is non-empty, else
/// `None`. The message states whether the safe WAL-tail quarantine ran first (progress), so the
/// operator sees exactly what was done and what remains.
fn out_of_scope_refusal(
    root: &str,
    out_of_scope_torn: &[TornObject],
    quarantined: &[u64],
) -> Option<WalRepairError> {
    if out_of_scope_torn.is_empty() {
        return None;
    }
    let objects: Vec<String> = out_of_scope_torn.iter().map(|t| t.path.clone()).collect();
    let quarantine_note = if quarantined.is_empty() {
        "No safe trailing WAL tail was present to quarantine (this apply mutated nothing)."
            .to_string()
    } else {
        let ids: Vec<String> = quarantined.iter().map(|id| format!("{id:020}")).collect();
        format!(
            "The safe trailing WAL tail [{}] WAS quarantined first, but the store still holds the \
             torn object(s) below.",
            ids.join(", ")
        )
    };
    let detail = format!(
        "{quarantine_note} This needs manifest-aware recovery / escalation — a compacted SST must \
         be dropped via a manifest rollback, never by removing the object out from under the manifest."
    );
    Some(WalRepairError::UnrepairableTornObject {
        root: root.to_string(),
        objects,
        detail,
    })
}

/// Decide the trailing torn tail to quarantine from the descending candidate list, enforcing
/// the **trailing-only** + **mid-range-gap refusal** rules (SAFETY steps 3 & 4).
///
/// Walking highest → lowest: collect a contiguous run of `Torn` objects from the top. The
/// moment a `Readable` object is seen, the tail is closed — any `Torn` object BELOW a
/// readable one is a mid-range gap ⇒ **refuse**. `Fence` objects (≤10 bytes) are transparent:
/// they are left in place and do not break the trailing run (slatedb skips them on replay),
/// but they also do not, by themselves, make a lower torn object "trailing".
fn plan_trailing_tail(candidates: &[WalCandidate], root: &str) -> Result<Vec<u64>, WalRepairError> {
    let mut quarantine = Vec::new();
    // The highest readable id seen so far while walking down; once set, any torn object
    // below it is a mid-range gap.
    let mut readable_above: Option<u64> = None;
    for c in candidates {
        match c.class {
            WalClass::Readable => {
                // Close the trailing run: nothing below a readable object is a trailing tear.
                readable_above.get_or_insert(c.id);
            }
            WalClass::Fence => {
                // A fence/empty object is tolerated by replay and left in place. It is neither
                // torn (nothing to quarantine) nor readable-data (does not close the tail on its
                // own); we simply pass over it.
            }
            WalClass::Torn => {
                if let Some(readable_id) = readable_above {
                    // A torn object sits BELOW a readable one → mid-range gap. Quarantining it
                    // would drop the acked data in the readable object(s) above. Refuse loud.
                    return Err(WalRepairError::MidRangeGap {
                        root: root.to_string(),
                        torn_id: c.id,
                        readable_id,
                    });
                }
                quarantine.push(c.id);
            }
        }
    }
    Ok(quarantine)
}

/// **WAL-id contiguity guard (C4).** After the trailing-torn tail is planned for quarantine, the
/// objects that SURVIVE (everything beyond the frontier that is not quarantined) must form a
/// contiguous replay range with no absent id below the highest readable (data-bearing) survivor.
///
/// The danger this catches — distinct from [`plan_trailing_tail`]'s [`WalRepairError::MidRangeGap`]
/// (a torn object present below a readable one) — is a WAL id that is ENTIRELY ABSENT below acked
/// data: e.g. frontier=5, readable at 6 and 8, torn trailing at 9. Quarantining 9 leaves survivors
/// {6, 8} — id 7 is missing, so the acked data in object 8 sits above an unbridgeable hole. WAL
/// replay cannot skip a hole, so this is unfixed data loss ⇒ fail loud rather than open.
///
/// Fence objects (≤10 bytes) occupy an id and count as PRESENT (slatedb tolerates them on replay),
/// so a benign fence does not read as a hole. Only ids from `frontier + 1` up to the highest
/// readable survivor are required to be present; absent ids ABOVE the highest data survivor are
/// harmless (nothing acked sits above them). Runs in BOTH modes so a dry-run also reports the hole.
fn check_survivor_contiguity(
    candidates: &[WalCandidate],
    quarantined: &[u64],
    frontier: u64,
    root: &str,
) -> Result<(), WalRepairError> {
    // The highest readable (data-bearing) survivor — a hole matters only below real acked data.
    let Some(max_readable) = candidates
        .iter()
        .filter(|c| c.class == WalClass::Readable && !quarantined.contains(&c.id))
        .map(|c| c.id)
        .max()
    else {
        // No surviving data object beyond the frontier ⇒ nothing acked can be stranded by a gap.
        return Ok(());
    };
    // Every id from frontier+1 up to that data survivor must be present among the survivors.
    let present: std::collections::BTreeSet<u64> = candidates
        .iter()
        .map(|c| c.id)
        .filter(|id| !quarantined.contains(id))
        .collect();
    for id in (frontier + 1)..=max_readable {
        if !present.contains(&id) {
            return Err(WalRepairError::WalIdHole {
                root: root.to_string(),
                missing_id: id,
                above_readable_id: max_readable,
            });
        }
    }
    Ok(())
}

/// **Real-open verification (C4).** Attempt an ACTUAL [`slatedb::Db`] open of the store at `root`
/// over `store`, with repair DISABLED — the definitive check that the store the repair just
/// produced genuinely boots (a footer re-scan shares the classifier's blind spot; only a real
/// replay proves the WAL/L0/manifest are consistent). Builds a throwaway writer with the
/// background compactor + GC disabled (nothing to drain, so the close is fast and cannot stall),
/// then closes it. `Ok(())` ⇒ the store opened and closed cleanly; `Err` ⇒ it is NOT repaired.
///
/// Runs in the fenced, single-writer repair context (no concurrent writer), so briefly claiming
/// the writer here and releasing it before the caller's real open is safe. The close advances the
/// durable frontier (memtable → L0), leaving the store checkpointed for the caller's cold open.
async fn verify_opens(store: &Arc<dyn ObjectStore>, root: &str) -> Result<(), WalRepairError> {
    #[allow(clippy::field_reassign_with_default)]
    let settings = {
        // `Settings` is a foreign `#[non_exhaustive]` struct — field reassignment after
        // `default()` is the only way to build it (mirrors `kv_slatedb`'s `test_settings`).
        let mut settings = Settings::default();
        settings.flush_interval = Some(Duration::from_millis(5));
        settings.compactor_options = None;
        settings.garbage_collector_options = None;
        settings
    };
    let db = Db::builder(root.to_string(), store.clone())
        .with_settings(settings)
        .build()
        .await
        .map_err(|e| WalRepairError::OpenVerificationFailed {
            root: root.to_string(),
            detail: e.to_string(),
        })?;
    // Close the throwaway writer (freeze memtable → L0, advance the frontier, release the fence).
    db.close()
        .await
        .map_err(|e| WalRepairError::OpenVerificationFailed {
            root: root.to_string(),
            detail: format!("store opened but failed to close cleanly: {e}"),
        })?;
    Ok(())
}

/// The zero-padded `{:020}.sst` WAL object path under `{root}/wal/` for `id`.
fn wal_object_path(root: &str, id: u64) -> ObjPath {
    ObjPath::from(format!("{root}/wal/{id:020}.sst"))
}

/// The quarantine copy path `{root}/wal-quarantine/{stamp}/{:020}.sst`.
fn quarantine_object_path(root: &str, stamp: &str, id: u64) -> ObjPath {
    ObjPath::from(format!("{root}/wal-quarantine/{stamp}/{id:020}.sst"))
}

/// Perform the quarantine for the planned trailing-torn ids: for each, **copy** (never rename)
/// the object to the quarantine dir, then delete the original; finally write the quarantine
/// `MANIFEST.json`. Copy-then-delete (not `rename`) means a crash mid-repair never loses the
/// bytes — the quarantine copy lands first.
async fn apply_quarantine(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    frontier: u64,
    candidates: &[WalCandidate],
    ids: &[u64],
    stamp: &str,
) -> Result<(), WalRepairError> {
    // Copy each object to the quarantine dir first (bytes safe), THEN delete the original.
    for &id in ids {
        // SAFETY step 5: never quarantine at or below the durable frontier.
        if id <= frontier {
            return Err(WalRepairError::NotBeyondFrontier { id, frontier });
        }
        let src = wal_object_path(root, id);
        let dst = quarantine_object_path(root, stamp, id);
        store
            .copy(&src, &dst)
            .await
            .map_err(|e| WalRepairError::Store(e.to_string()))?;
    }
    // Write the quarantine manifest describing exactly what was moved (before the deletes are
    // observed complete, so a reader always finds the record for a copied object).
    let manifest = build_quarantine_manifest(frontier, candidates, ids, stamp);
    let manifest_path = ObjPath::from(format!("{root}/wal-quarantine/{stamp}/MANIFEST.json"));
    store
        .put(&manifest_path, manifest.into_bytes().into())
        .await
        .map_err(|e| WalRepairError::Store(e.to_string()))?;
    // Now delete the originals — the quarantine copies (and the manifest) are already durable.
    for &id in ids {
        let src = wal_object_path(root, id);
        store
            .delete(&src)
            .await
            .map_err(|e| WalRepairError::Store(e.to_string()))?;
    }
    Ok(())
}

/// Build the quarantine `MANIFEST.json` body (ids, sizes, observed frontier, reason, timestamp).
fn build_quarantine_manifest(
    frontier: u64,
    candidates: &[WalCandidate],
    ids: &[u64],
    stamp: &str,
) -> String {
    let size_of = |id: u64| candidates.iter().find(|c| c.id == id).map(|c| c.size);
    let objects: Vec<String> = ids
        .iter()
        .map(|&id| {
            format!(
                "    {{ \"id\": {id}, \"file\": \"{id:020}.sst\", \"size\": {} }}",
                size_of(id).unwrap_or(0)
            )
        })
        .collect();
    format!(
        "{{\n  \"reason\": \"trailing torn WAL tail beyond the durable frontier (partial \
         crash/snapshot tail); quarantined by boatramp kv repair\",\n  \"stamp\": \"{stamp}\",\n  \
         \"observed_frontier_replay_after_wal_id\": {frontier},\n  \"quarantined\": [\n{}\n  ]\n}}\n",
        objects.join(",\n"),
    )
}

/// A monotonic-ish quarantine stamp: seconds since the epoch. Distinct per repair invocation
/// (an operator would not run two in the same second), and lexicographically sortable.
fn quarantine_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs:020}")
}

/// Repair a torn trailing WAL tail on the SlateDB store rooted at `root` over `store`, per the
/// module's safety contract, and DIAGNOSE the whole store (`wal/` + `compacted/`). Returns the
/// plan/outcome as a [`RepairReport`]; refuses (fails loud) on an unreadable manifest, a mid-range
/// gap, a mid-range WAL-id hole, an out-of-scope torn SST it must not remove, or a store that
/// STILL fails a real open after the quarantine.
///
/// - [`RepairMode::DryRun`] computes the plan, populates [`RepairReport::out_of_scope_torn`] with
///   every torn compacted SST (and torn non-trailing WAL object), and mutates NOTHING — so the
///   operator sees the complete picture (what WOULD be quarantined AND what is torn-but-out-of-scope).
///   The mid-range-gap and WAL-id-hole refusals also fire in dry-run (they are properties of the
///   plan, not the mutation).
/// - [`RepairMode::Apply`] quarantines the safe trailing WAL tail first (copy → manifest → delete),
///   THEN — if any out-of-scope torn object remains — FAILS LOUD with
///   [`WalRepairError::UnrepairableTornObject`] naming the exact path(s), and finally verifies the
///   store by an ACTUAL open ([`verify_opens`], C4). An `Ok` therefore means the store is free of
///   ALL torn SSTs AND genuinely boots; anything torn this tool won't touch, or a store that still
///   won't open, is an `Err`. Compacted / L0 SSTs are DETECTION-ONLY (never quarantined/deleted).
///
/// `store` + `root` MUST be exactly the store/root the opener uses (so the repair sees the same
/// objects the open will replay).
pub async fn repair_wal_tail(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    mode: RepairMode,
) -> Result<RepairReport, WalRepairError> {
    // 1. Establish the durable frontier — REFUSE if the manifest is unreadable (SAFETY step 1).
    let frontier = read_frontier(store, root).await?;
    repair_wal_tail_at_frontier(store, root, frontier, mode).await
}

/// Steps 2–8 of [`repair_wal_tail`] over an **explicit** durable frontier — factored out so the
/// last-good-generation manifest recovery (F2, [`recover_last_good_manifest`]) can run the WAL-tail
/// self-heal at the frontier of a ROLLED-BACK generation G (`replay_after_wal_id(G)`) WITHOUT
/// re-reading the LATEST manifest (which, on the empty/torn-manifest shape, is still unreadable until
/// its torn suffix is quarantined). `repair_wal_tail` is exactly [`read_frontier`] then this. Every
/// existing safety guard (trailing-only, mid-range gap, WAL-id hole, out-of-scope torn, real-open
/// verify) is preserved unchanged — only the frontier SOURCE differs.
async fn repair_wal_tail_at_frontier(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    frontier: u64,
    mode: RepairMode,
) -> Result<RepairReport, WalRepairError> {
    // 2. List + classify every WAL object strictly beyond the frontier, highest id first.
    let candidates = scan_candidates(store, root, frontier).await?;

    // 3+4. Decide the trailing torn tail, refusing on a mid-range gap (torn below readable).
    let ids = plan_trailing_tail(&candidates, root)?;

    // 4b. Contiguity guard (C4): the survivors must have no ABSENT WAL id below the highest readable
    //     survivor — a hole is unfixed data loss replay cannot bridge. Runs in both modes.
    check_survivor_contiguity(&candidates, &ids, frontier, root)?;

    // 5. WHOLE-STORE scan: torn compacted/L0 SSTs (never mutated) + torn non-trailing WAL objects.
    //    Computed for both modes — a dry-run reports it, an apply fails loud on it after quarantine.
    let out_of_scope_torn = scan_out_of_scope_torn(store, root, frontier).await?;

    if mode == RepairMode::DryRun {
        // Dry-run: return the FULL plan (WAL-tail quarantine plan + out-of-scope torn) — mutate NOTHING.
        return Ok(RepairReport {
            frontier,
            candidates,
            quarantined: ids.clone(),
            quarantine_dir: (!ids.is_empty())
                .then(|| format!("{root}/wal-quarantine/<stamp>/ (dry-run: not created)")),
            applied: false,
            out_of_scope_torn,
        });
    }

    // 6. Apply the safe WAL-tail quarantine FIRST (make progress). An empty plan mutates nothing;
    //    a non-empty one copies → writes the quarantine manifest → deletes the originals.
    let quarantine_dir = if ids.is_empty() {
        None
    } else {
        let stamp = quarantine_stamp();
        apply_quarantine(store, root, frontier, &candidates, &ids, &stamp).await?;
        Some(format!("{root}/wal-quarantine/{stamp}"))
    };

    // 7. FAIL LOUD if the store still holds a torn SST OUTSIDE the safe WAL-tail scope (a torn
    //    compacted/L0 SST this tool must not remove, or a torn non-trailing WAL object). This is
    //    the "never silently no-op / never claim success while torn" guarantee. Ordering: the safe
    //    WAL tail (if any) was already quarantined above; the compacted SSTs are DETECTION-ONLY.
    //    This runs BEFORE the real-open verify so the specific `UnrepairableTornObject` message
    //    (naming the manifest-referenced object) wins over a generic open failure.
    if let Some(err) = out_of_scope_refusal(root, &out_of_scope_torn, &ids) {
        return Err(err);
    }

    // 8. REAL-OPEN VERIFICATION (C4) — the definitive post-repair check. A footer re-scan shares
    //    the classifier's blind spot; only an actual `Db` open proves the store the caller is about
    //    to serve genuinely boots. A failure here (e.g. a truncated edge or a torn block the probe
    //    could not see) fails loud — NEVER claim success for a store the cold open would die on.
    verify_opens(store, root).await?;

    Ok(RepairReport {
        frontier,
        candidates,
        quarantined: ids,
        applied: quarantine_dir.is_some(),
        quarantine_dir,
        out_of_scope_torn,
    })
}

// ===================================================================================================
// F2 — last-good-generation cold-open recovery from an empty/torn LATEST manifest (v0.11.0).
//
// A hard VM stop / crash-consistent snapshot mid manifest-PUT (with fsync off — F1 closes the window
// going forward) can leave a 0-byte "empty manifest" at its final name. slatedb's cold open reads ONLY
// the highest manifest and does NOT fall back on a decode failure, so the store is unbootable and even
// `kv recover` (which needs the manifest first) hit a dead end.
//
// The decisive facts (investigation): a last-good generation N-1 essentially ALWAYS survives (each
// manifest id is written once; a torn N never became current; slatedb GC runs only inside an open Db,
// which is down). "Roll back to N-1 + replay WAL forward" is a LOSSLESS-for-acked recovery — exactly a
// normal open: WAL objects `>= F(N-1)` are GC-protected, the frontier F(N-1) gates replay (no dup), and
// the failed close's L0 SST(s) referenced only by torn N are orphaned (a reclaimable space leak, never
// double-counted). WAL-from-0 (no manifest at all) is LOSSY ⇒ last resort only, loud/opt-in, never auto.
// ===================================================================================================

/// The outcome of an F2 last-good-generation recovery attempt.
#[derive(Debug, Clone)]
pub enum ManifestRecovery {
    /// The LATEST manifest is READABLE — this is NOT the empty/torn-manifest shape, and NOTHING was
    /// done. The caller should use the ordinary WAL-tail path ([`repair_wal_tail`]). Carries the
    /// latest frontier so the caller can surface it.
    LatestReadable {
        /// `replay_after_wal_id` of the (readable) latest manifest.
        frontier: u64,
    },
    /// The latest manifest was empty/torn/absent; recovery rolled back to the highest decodable
    /// generation G (on [`RepairMode::Apply`]) — or, on [`RepairMode::DryRun`], computed the plan it
    /// WOULD apply. See [`ManifestRecoveryReport`].
    RolledBack(ManifestRecoveryReport),
}

/// The plan/outcome of a last-good-generation rollback (F2).
#[derive(Debug, Clone)]
pub struct ManifestRecoveryReport {
    /// The highest decodable manifest generation G the store was (or would be) rolled back to.
    pub rolled_back_to_generation: u64,
    /// G's durable frontier `F = replay_after_wal_id(G)` — the replay boundary (replay starts at F+1).
    pub frontier: u64,
    /// The torn manifest suffix (every PRESENT-but-undecodable `manifest/{:020}.manifest` with id > G)
    /// that was (or, in dry-run, would be) quarantined so G becomes the latest.
    pub quarantined_manifest_ids: Vec<u64>,
    /// The `{root}/manifest-quarantine/{stamp}/` dir the torn manifests were (or would be) copied to.
    pub manifest_quarantine_dir: Option<String>,
    /// The WAL-tail self-heal run at F (may be a no-op for the pure-N-1 case, or quarantine a torn WAL
    /// tail beyond F for a crash that tore BOTH the manifest and a later WAL object).
    pub wal_repair: RepairReport,
    /// **Informational / reclaimable, NEVER loss** (UX C11): L0 SST object(s) referenced only by a
    /// discarded torn generation are orphaned by the rollback — a space leak the reopened store's own
    /// GC reclaims. Surfaced as a DISTINCT field so it is never conflated with acked loss. (Best-effort;
    /// populated only when cheaply derivable — see the note in [`recover_last_good_manifest`].)
    pub orphaned_nonacked_objects: Vec<String>,
    /// Whether the pass mutated the store (`false` for a dry-run).
    pub applied: bool,
}

/// The `{root}/manifest/{:020}.manifest` object path for generation `id` (slatedb's manifest layout).
fn manifest_object_path(root: &str, id: u64) -> ObjPath {
    ObjPath::from(format!("{root}/manifest/{id:020}.manifest"))
}

/// Parse a `{:020}.manifest` filename into its numeric generation id (mirrors [`parse_wal_id`]).
fn parse_manifest_id(location: &ObjPath) -> Option<u64> {
    location
        .filename()?
        .strip_suffix(".manifest")?
        .parse::<u64>()
        .ok()
}

/// List every `{root}/manifest/{:020}.manifest` generation id present on the store, **descending**
/// (highest first — the walk order F2 needs). We enumerate object-store keys ourselves rather than use
/// `Admin::list_manifests`, which fails WHOLESALE on any corrupt-but-present manifest (it `?`-propagates
/// a decode error) and so cannot hand us the good older generations past a torn one.
async fn list_manifest_ids(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<Vec<u64>, WalRepairError> {
    use futures::StreamExt;
    let prefix = ObjPath::from(format!("{root}/manifest"));
    let mut stream = store.list(Some(&prefix));
    let mut ids = Vec::new();
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        if let Some(id) = parse_manifest_id(&meta.location) {
            ids.push(id);
        }
    }
    ids.sort_unstable_by(|a, b| b.cmp(a)); // descending (highest generation first)
    Ok(ids)
}

/// The set of every `{root}/wal/{:020}.sst` id present on the store — for the MF2 replay-range
/// contiguity check ([`check_manifest_rollback_wal_contiguity`]).
async fn list_wal_ids(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<std::collections::BTreeSet<u64>, WalRepairError> {
    use futures::StreamExt;
    let prefix = ObjPath::from(format!("{root}/wal"));
    let mut stream = store.list(Some(&prefix));
    let mut ids = std::collections::BTreeSet::new();
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        if let Some(id) = parse_wal_id(&meta.location) {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// Read the manifest GC boundary (`{root}/gc/manifest.boundary`, a single ASCII `u64` — slatedb's
/// `slatedb-txn-obj` boundary object). It records the id BELOW which manifests are treated as deleted.
/// Absent / unreadable / unparsable ⇒ `0` (slatedb's own default), i.e. no boundary. Best-effort: this
/// is a defensive input to an MF2 guard, so any read failure degrades to the safe `0` boundary.
async fn read_manifest_gc_boundary(store: &Arc<dyn ObjectStore>, root: &str) -> u64 {
    let path = ObjPath::from(format!("{root}/gc/manifest.boundary"));
    match store.get(&path).await {
        Ok(get) => match get.bytes().await {
            Ok(bytes) => std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0),
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

/// **MF2 structural GC-hole guard for a manifest rollback (v0.11.0).** After F2 picks the last-good
/// generation G (frontier F = `replay_after_wal_id(G)`), the WAL replay range is `(F, ∞)`. Every WAL id
/// from F+1 up to the highest PRESENT WAL id MUST be present on the store — a LEADING gap (F+1 absent
/// while a higher id survives) or ANY interior gap means WAL-GC advanced off a non-durable generation
/// (the fsync silent-loss window) and the acked writes in the hole are unrecoverable → FAIL LOUD rather
/// than open a store missing acked crown-jewel state.
///
/// This COMPLEMENTS [`check_survivor_contiguity`] (which the subsequent WAL-tail self-heal also runs):
/// that guard returns `Ok` when the WHOLE tail is gone (no readable survivor) — exactly the blind spot
/// here, where rolling back to an OLDER, LOWER frontier F needs a replay range a later GC pass may have
/// erased. A torn TRAILING WAL object is still PRESENT (an object at that id) and is handled by the
/// WAL-tail self-heal; this guard is about ABSENT ids (an unbridgeable hole), never torn-but-present.
fn check_manifest_rollback_wal_contiguity(
    wal_ids_present: &std::collections::BTreeSet<u64>,
    frontier: u64,
    root: &str,
) -> Result<(), WalRepairError> {
    let Some(&highest) = wal_ids_present.iter().max() else {
        return Ok(()); // no WAL objects at all → nothing to replay, nothing to lose
    };
    if highest <= frontier {
        return Ok(()); // every WAL object is already covered by G's frontier (all in L0)
    }
    // Some WAL objects sit beyond F → the entire (F, highest] range must be intact (no absent id).
    for id in (frontier + 1)..=highest {
        if !wal_ids_present.contains(&id) {
            return Err(WalRepairError::ManifestRollbackGcHole {
                root: root.to_string(),
                rolled_back_frontier: frontier,
                missing_wal_id: id,
                highest_wal_id: highest,
            });
        }
    }
    Ok(())
}

/// Quarantine the torn manifest suffix (MF4): for each undecodable `manifest/{:020}.manifest` with
/// id > G, **copy** it to `{root}/manifest-quarantine/{stamp}/` (OUTSIDE `{root}/manifest/` — Arch C2:
/// a copy left inside would be re-listed as the max generation and re-break the store), write a
/// `MANIFEST.json` record, THEN delete the original. Copy → record → delete is the crash-safe order
/// (mirrors [`apply_quarantine`]): a crash mid-op never loses the bytes, and the record always names a
/// copied object. Deletion is MANDATORY (not tidiness): a surviving torn manifest makes the reopened
/// store's next manifest PUT fail `AlreadyExists` via id-reuse.
async fn quarantine_manifest_suffix(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    generation: u64,
    ids: &[u64],
    stamp: &str,
) -> Result<(), WalRepairError> {
    for &id in ids {
        // Defensive: NEVER quarantine a manifest at or below the adopted last-good generation G.
        if id <= generation {
            return Err(WalRepairError::Store(format!(
                "internal invariant: refusing to quarantine manifest {id:020} at/below the adopted \
                 last-good generation {generation:020}"
            )));
        }
        let src = manifest_object_path(root, id);
        let dst = ObjPath::from(format!(
            "{root}/manifest-quarantine/{stamp}/{id:020}.manifest"
        ));
        store
            .copy(&src, &dst)
            .await
            .map_err(|e| WalRepairError::Store(e.to_string()))?;
    }
    // Record BEFORE the deletes are observed complete (a reader always finds the record for a copy).
    let record = build_manifest_quarantine_record(generation, ids, stamp);
    let record_path = ObjPath::from(format!("{root}/manifest-quarantine/{stamp}/MANIFEST.json"));
    store
        .put(&record_path, record.into_bytes().into())
        .await
        .map_err(|e| WalRepairError::Store(e.to_string()))?;
    // Now delete the originals — the quarantine copies + record are already durable.
    for &id in ids {
        store
            .delete(&manifest_object_path(root, id))
            .await
            .map_err(|e| WalRepairError::Store(e.to_string()))?;
    }
    Ok(())
}

/// Build the `manifest-quarantine/{stamp}/MANIFEST.json` record body (the rolled-back generation + the
/// quarantined torn generation ids). No secrets — only generation ids and the stamp (MF6).
fn build_manifest_quarantine_record(generation: u64, ids: &[u64], stamp: &str) -> String {
    let objects: Vec<String> = ids
        .iter()
        .map(|&id| format!("    {{ \"id\": {id}, \"file\": \"{id:020}.manifest\" }}"))
        .collect();
    format!(
        "{{\n  \"reason\": \"torn/empty manifest generation(s) beyond the last-good generation (partial \
         crash/snapshot manifest PUT); quarantined by boatramp v0.11.0 last-good-generation cold-open \
         recovery\",\n  \"stamp\": \"{stamp}\",\n  \"rolled_back_to_generation\": {generation},\n  \
         \"quarantined_manifests\": [\n{}\n  ]\n}}\n",
        objects.join(",\n"),
    )
}

/// After the torn manifest suffix is quarantined, ASSERT no `manifest/{:020}.manifest` with id > G
/// remains (MF4 / Arch C2) — a survivor would be re-listed as the latest and re-break the reopened
/// store. Runs before the real-open verify.
async fn assert_no_torn_manifest_remains(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    generation: u64,
) -> Result<(), WalRepairError> {
    let remaining: Vec<u64> = list_manifest_ids(store, root)
        .await?
        .into_iter()
        .filter(|&id| id > generation)
        .collect();
    if !remaining.is_empty() {
        return Err(WalRepairError::Store(format!(
            "internal invariant: after the manifest-suffix quarantine, manifest id(s) {remaining:?} \
             still remain above the adopted generation {generation:020} in `{root}/manifest/` — \
             refusing to verify (a survivor is re-listed as the latest and re-breaks the store)"
        )));
    }
    Ok(())
}

/// **F2 — last-good-generation cold-open recovery.** When the LATEST manifest is empty/torn/absent,
/// walk the manifest generations highest → lowest, pick the highest that DECODES = G (frontier
/// F = `replay_after_wal_id(G)`), quarantine the torn suffix (id > G) so G becomes the latest, then run
/// the existing WAL-tail self-heal at F and (on Apply) a real-open verify with a FRESH handle. Returns
/// [`ManifestRecovery::LatestReadable`] (no-op) when the latest manifest is actually readable — so the
/// caller can fall through to the ordinary [`repair_wal_tail`] WAL-tail path.
///
/// Control flow (Apply): read_frontier(latest) fails → list generations desc → pick G (fail loud
/// [`NoDecodableManifest`] if none decode) → MF2 guards (GC boundary + no leading/interior WAL GC hole,
/// fail loud [`BelowGcBoundary`] / [`ManifestRollbackGcHole`]) → quarantine the torn manifest suffix
/// OUTSIDE `manifest/` (copy → record → delete) → assert none remain → WAL-tail self-heal at F +
/// fresh-handle `verify_opens`. A refusal at ANY step fails loud (mutating nothing beyond a
/// crash-safe quarantine), never a lossy WAL-from-0.
///
/// `orphaned_nonacked_objects` is a best-effort informational field: after G becomes the latest, the L0
/// SST(s) that only torn N referenced are unreferenced. Identifying them precisely needs G's SST list
/// mapped to object paths; slatedb's reopened store GC reclaims them regardless, so this is left empty
/// (documented) rather than risk mislabelling a live SST as orphaned. Space reclamation, never loss.
pub async fn recover_last_good_manifest(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    mode: RepairMode,
) -> Result<ManifestRecovery, WalRepairError> {
    // 0. Shape gate: if the LATEST manifest is readable, this is NOT the empty/torn-manifest shape.
    if let Ok(frontier) = read_frontier(store, root).await {
        return Ok(ManifestRecovery::LatestReadable { frontier });
    }

    // 1. Enumerate manifest generation ids present on the store (descending).
    let manifest_ids = list_manifest_ids(store, root).await?;
    if manifest_ids.is_empty() {
        return Err(WalRepairError::NoDecodableManifest {
            root: root.to_string(),
            listed: 0,
        });
    }

    // 2. Walk highest → lowest; the first that DECODES is the last-good generation G (frontier F). Every
    //    id above G is non-decodable (else we'd have adopted it), so the torn suffix to quarantine is
    //    exactly the PRESENT manifest FILES with id > G (derived from the listing, not the walk's
    //    `Err`/`Ok(None)` split — a 0-byte torn manifest is a PRESENT file that must be removed for G to
    //    become the clean latest, even if `read_manifest` reports it `Ok(None)`).
    let admin = Admin::builder(root.to_string(), store.clone()).build();
    let mut good: Option<(u64, u64)> = None; // (generation G, frontier F)
    for &id in &manifest_ids {
        if let Ok(Some(vm)) = admin.read_manifest(Some(id)).await {
            good = Some((id, vm.replay_after_wal_id()));
            break;
        }
        // Undecodable (`Err`) or reported-absent (`Ok(None)`) — keep walking down.
    }
    let Some((generation, frontier)) = good else {
        return Err(WalRepairError::NoDecodableManifest {
            root: root.to_string(),
            listed: manifest_ids.len(),
        });
    };
    // The torn suffix = every present manifest file strictly above the adopted generation G.
    let torn_suffix: Vec<u64> = manifest_ids
        .iter()
        .copied()
        .filter(|&id| id > generation)
        .collect();

    // 3. MF2 GUARDS — never adopt a generation that would drop acked data.
    //    (a) never adopt a generation below the manifest GC boundary.
    let boundary = read_manifest_gc_boundary(store, root).await;
    if generation < boundary {
        return Err(WalRepairError::BelowGcBoundary {
            root: root.to_string(),
            generation,
            boundary,
        });
    }
    //    (b) the WAL replay range (F, …] must have NO leading/interior GC hole.
    let wal_ids = list_wal_ids(store, root).await?;
    check_manifest_rollback_wal_contiguity(&wal_ids, frontier, root)?;

    // Informational only (UX C11 / MF6): reclaimable orphans, never loss. Left empty (see the doc).
    let orphaned_nonacked_objects: Vec<String> = Vec::new();

    match mode {
        RepairMode::DryRun => {
            // Compute the WAL-tail plan at F WITHOUT reading the (still-torn) latest manifest, and
            // mutate NOTHING (the torn manifest suffix is retained).
            let wal_repair =
                repair_wal_tail_at_frontier(store, root, frontier, RepairMode::DryRun).await?;
            let manifest_quarantine_dir = (!torn_suffix.is_empty())
                .then(|| format!("{root}/manifest-quarantine/<stamp>/ (dry-run: not created)"));
            Ok(ManifestRecovery::RolledBack(ManifestRecoveryReport {
                rolled_back_to_generation: generation,
                frontier,
                quarantined_manifest_ids: torn_suffix,
                manifest_quarantine_dir,
                wal_repair,
                orphaned_nonacked_objects,
                applied: false,
            }))
        }
        RepairMode::Apply => {
            // (a) quarantine the torn manifest suffix so G becomes the latest (copy → record → delete).
            let manifest_quarantine_dir = if torn_suffix.is_empty() {
                None
            } else {
                let stamp = quarantine_stamp();
                quarantine_manifest_suffix(store, root, generation, &torn_suffix, &stamp).await?;
                Some(format!("{root}/manifest-quarantine/{stamp}"))
            };
            // (b) ASSERT no torn manifest > G remains before verify (Arch C2 / MF4).
            assert_no_torn_manifest_remains(store, root, generation).await?;
            // (c) WAL-tail self-heal at F over the now-G-latest store: quarantine a torn WAL tail
            //     beyond F (if any), then `verify_opens` with a FRESH slatedb handle (Arch C6).
            let wal_repair =
                repair_wal_tail_at_frontier(store, root, frontier, RepairMode::Apply).await?;
            Ok(ManifestRecovery::RolledBack(ManifestRecoveryReport {
                rolled_back_to_generation: generation,
                frontier,
                quarantined_manifest_ids: torn_suffix,
                manifest_quarantine_dir,
                wal_repair,
                orphaned_nonacked_objects,
                applied: true,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    //! WAL-repair gate battery (Part B): the pure-logic gates (frontier / trailing-only /
    //! mid-range-gap refusal / classification) run on ANY toolchain — they exercise
    //! [`plan_trailing_tail`] + [`scan_candidates`] + [`classify`] over crafted object-store
    //! fixtures, never decoding an SST body. The full round-trip gates that open a REAL SlateDB
    //! store and reopen it (B2, B5 over a live store) live in `kv_slatedb::tests` and are gated
    //! to the host toolchain (the static-musl harness stalls on close→reopen).
    //!
    //! The whole-store-awareness gates (torn compacted/L0 SST DETECTED + never mutated; apply
    //! REFUSES with `UnrepairableTornObject`) DO build a real slatedb manifest, but over a
    //! **shared `InMemory`** store — the same deterministic, non-stalling path
    //! `kv_slatedb::tests::flush_persists_then_reopens` uses (only the on-disk `LocalFileSystem`
    //! path stalls under musl, so these need no `#[ignore]`), with the background compactor + GC
    //! disabled so `close()` has nothing to drain.
    //!
    //! Each gate is mutation-verified: the doc on B3/B4 names the exact relaxation that breaks it.

    use super::*;
    use slatedb::object_store::memory::InMemory;
    use slatedb::{Db, Settings};

    /// A well-formed SST-footer object of `size` bytes: filler + a 10-byte footer whose bytes[0..8]
    /// are a SANE metadata offset (`<= size - 10`, so it passes the C4 offset-sanity probe) and
    /// bytes[8..10] are a 2-byte BE version word. The repair probe reads ONLY the last 10 bytes, so
    /// a crafted object is byte-faithful to what `classify` inspects without a real SST body.
    /// `version ∈ {1,2}` ⇒ Readable; anything else (notably 0, the production torn signature) ⇒ Torn.
    fn footer_object(size: usize, version: u16) -> bytes::Bytes {
        assert!(
            size >= NUM_FOOTER_BYTES as usize,
            "must fit a 10-byte footer"
        );
        let mut buf = vec![0xABu8; size];
        let n = buf.len();
        // Footer bytes[0..8] = a valid metadata offset (<= size-10) so a version-1/2 object reads
        // Readable; bytes[8..10] = version BE. A half-of-the-body offset is always in range.
        let meta_offset = (size as u64 - NUM_FOOTER_BYTES) / 2;
        buf[n - 10..n - 2].copy_from_slice(&meta_offset.to_be_bytes());
        buf[n - 2..n].copy_from_slice(&version.to_be_bytes());
        bytes::Bytes::from(buf)
    }

    /// A crafted footer object with a GOOD version word but a metadata offset PAST the footer start
    /// (`> size - 10`) — the truncated-edge blind spot the C4 offset-sanity probe catches. A
    /// version-only classifier would misread this as `Readable`, only for the real open to die.
    fn footer_object_bad_offset(size: usize, version: u16) -> bytes::Bytes {
        assert!(
            size >= NUM_FOOTER_BYTES as usize,
            "must fit a 10-byte footer"
        );
        let mut buf = vec![0xABu8; size];
        let n = buf.len();
        let bad_offset = size as u64; // strictly > size - NUM_FOOTER_BYTES
        buf[n - 10..n - 2].copy_from_slice(&bad_offset.to_be_bytes());
        buf[n - 2..n].copy_from_slice(&version.to_be_bytes());
        bytes::Bytes::from(buf)
    }

    /// Put a crafted WAL object at `{root}/wal/{id:020}.sst`.
    async fn put_wal(store: &Arc<dyn ObjectStore>, root: &str, id: u64, body: bytes::Bytes) {
        let path = wal_object_path(root, id);
        store.put(&path, body.into()).await.unwrap();
    }

    /// Build an `InMemory` store as an `Arc<dyn ObjectStore>` (the type the repair takes).
    fn mem_store() -> Arc<dyn ObjectStore> {
        Arc::new(InMemory::new())
    }

    // --- Pure classification: the >10-byte version-0 tail is Torn; the ≤10-byte tail is Fence. ---

    #[tokio::test]
    async fn classify_distinguishes_readable_torn_and_fence() {
        let store = mem_store();
        let root = "kv";
        // A readable object (version 1), a torn object (version 0, >10 bytes), and a fence (0-byte).
        put_wal(&store, root, 5, footer_object(64, 1)).await;
        put_wal(&store, root, 6, footer_object(64, 0)).await;
        put_wal(&store, root, 7, bytes::Bytes::new()).await; // 0-byte fence

        let readable = wal_object_path(root, 5);
        let torn = wal_object_path(root, 6);
        assert_eq!(
            classify(&store, &readable, 64).await.unwrap(),
            WalClass::Readable
        );
        assert_eq!(classify(&store, &torn, 64).await.unwrap(), WalClass::Torn);
        // The fence branch is purely size-driven (≤10 bytes), matching slatedb's tolerated case.
        let fence = wal_object_path(root, 7);
        assert_eq!(classify(&store, &fence, 0).await.unwrap(), WalClass::Fence);
    }

    // --- C4: metadata-offset sanity — a GOOD version word but an out-of-range offset ⇒ Torn. ---
    //
    // MUTATION this gate catches: drop the `meta_offset > size - NUM_FOOTER_BYTES` check in
    // `classify`. Then a truncated edge whose last 2 bytes happen to read as version 1/2 would be
    // misclassified `Readable`, left in place by `plan_trailing_tail`, and only caught (if at all)
    // by the real open — this test asserts the probe itself flags it Torn on the offset alone.
    #[tokio::test]
    async fn classify_flags_bad_metadata_offset_as_torn_even_with_valid_version() {
        let store = mem_store();
        let root = "kv";
        // A valid version word (1) but an offset past the footer start — a truncated/torn object.
        put_wal(&store, root, 5, footer_object_bad_offset(64, 1)).await;
        let torn = wal_object_path(root, 5);
        assert_eq!(
            classify(&store, &torn, 64).await.unwrap(),
            WalClass::Torn,
            "an out-of-range metadata offset ⇒ Torn regardless of a valid version word (C4)"
        );
    }

    // --- C4: WAL-id contiguity guard — an ABSENT id below a readable survivor ⇒ WalIdHole. ---
    //
    // MUTATION this gate catches: remove `check_survivor_contiguity`. Then a store missing a WAL id
    // below acked data would be reported as repairable (the trailing-tail plan looks fine), and the
    // real open would die on the hole; this asserts the pre-open loud refusal instead.
    #[test]
    fn contiguity_guard_refuses_an_absent_id_below_a_readable_survivor() {
        // frontier=5; survivors after planning: readable at 6 and 8, id 7 ABSENT. (The trailing
        // torn tail, if any, is already excluded via `quarantined`.) Highest readable survivor = 8,
        // so ids 6 and 7 must be present — 7 is missing ⇒ hole ⇒ refuse.
        let candidates = vec![
            WalCandidate {
                id: 8,
                size: 64,
                class: WalClass::Readable,
            },
            WalCandidate {
                id: 6,
                size: 64,
                class: WalClass::Readable,
            },
        ];
        let err = check_survivor_contiguity(&candidates, &[], 5, "kv").unwrap_err();
        match err {
            WalRepairError::WalIdHole {
                missing_id,
                above_readable_id,
                ..
            } => {
                assert_eq!(missing_id, 7, "the first absent id in the replay range");
                assert_eq!(above_readable_id, 8, "the readable survivor above the hole");
            }
            other => panic!("expected a WalIdHole refusal, got {other:?}"),
        }
    }

    #[test]
    fn contiguity_guard_allows_a_contiguous_survivor_run_and_a_trailing_fence_gap() {
        // frontier=5; readable at 6,7,8 (contiguous from frontier+1) plus an ABSENT id 10 ABOVE the
        // highest data survivor (8) — harmless (nothing acked sits above it). Must pass.
        let candidates = vec![
            WalCandidate {
                id: 8,
                size: 64,
                class: WalClass::Readable,
            },
            WalCandidate {
                id: 7,
                size: 64,
                class: WalClass::Readable,
            },
            WalCandidate {
                id: 6,
                size: 64,
                class: WalClass::Readable,
            },
        ];
        assert!(
            check_survivor_contiguity(&candidates, &[], 5, "kv").is_ok(),
            "a contiguous run from frontier+1 with no hole below the top data object is fine"
        );
        // And with no surviving data object at all (only the tail, all quarantined) it is a no-op.
        assert!(check_survivor_contiguity(&[], &[], 5, "kv").is_ok());
    }

    // --- B3: trailing-only + mid-range-gap REFUSAL (the load-bearing data-loss guard). ---
    //
    // MUTATION that this gate catches: relax `plan_trailing_tail` to "quarantine ANY torn object"
    // (drop the `readable_above` mid-gap check). Then the torn id below a readable id would be
    // quarantined, dropping the acked data in the higher readable object — this test asserts the
    // REFUSAL, so the relaxed version returns `Ok([...])` and the `MidRangeGap` assertion fails.

    #[test]
    fn plan_refuses_torn_below_readable_mid_range_gap() {
        // Candidates highest→lowest (as `scan_candidates` returns them): a readable object at id 9
        // sits ABOVE a torn object at id 8 → a mid-range gap → REFUSE (quarantining 8 would gap 9).
        let candidates = vec![
            WalCandidate {
                id: 9,
                size: 64,
                class: WalClass::Readable,
            },
            WalCandidate {
                id: 8,
                size: 64,
                class: WalClass::Torn,
            },
        ];
        let err = plan_trailing_tail(&candidates, "kv").unwrap_err();
        match err {
            WalRepairError::MidRangeGap {
                torn_id,
                readable_id,
                ..
            } => {
                assert_eq!(torn_id, 8, "the torn object below the readable one");
                assert_eq!(
                    readable_id, 9,
                    "the readable object that must not be gapped"
                );
            }
            other => panic!("expected a mid-range-gap refusal, got {other:?}"),
        }
    }

    #[test]
    fn plan_quarantines_only_the_contiguous_trailing_torn_run() {
        // Highest→lowest: two torn objects at the very top (10, 9), then a readable one (8). Only
        // the contiguous trailing torn run [10, 9] is quarantinable; 8 is readable and left.
        let candidates = vec![
            WalCandidate {
                id: 10,
                size: 64,
                class: WalClass::Torn,
            },
            WalCandidate {
                id: 9,
                size: 64,
                class: WalClass::Torn,
            },
            WalCandidate {
                id: 8,
                size: 64,
                class: WalClass::Readable,
            },
        ];
        let ids = plan_trailing_tail(&candidates, "kv").unwrap();
        assert_eq!(
            ids,
            vec![10, 9],
            "only the trailing torn tail, highest first"
        );
    }

    #[test]
    fn plan_leaves_a_fence_object_untouched_and_does_not_break_the_trailing_run() {
        // A 0-byte fence at the very top (11), then a torn tail (10), then a readable (9). The
        // fence is transparent (left in place, slatedb skips it); the torn 10 is still trailing.
        let candidates = vec![
            WalCandidate {
                id: 11,
                size: 0,
                class: WalClass::Fence,
            },
            WalCandidate {
                id: 10,
                size: 64,
                class: WalClass::Torn,
            },
            WalCandidate {
                id: 9,
                size: 64,
                class: WalClass::Readable,
            },
        ];
        let ids = plan_trailing_tail(&candidates, "kv").unwrap();
        assert_eq!(
            ids,
            vec![10],
            "the fence is left; the trailing torn 10 is quarantined; 9 kept"
        );
    }

    #[test]
    fn plan_is_noop_when_all_candidates_are_readable() {
        let candidates = vec![
            WalCandidate {
                id: 9,
                size: 64,
                class: WalClass::Readable,
            },
            WalCandidate {
                id: 8,
                size: 64,
                class: WalClass::Readable,
            },
        ];
        assert!(plan_trailing_tail(&candidates, "kv").unwrap().is_empty());
    }

    // --- B4 (half): the UNREADABLE-MANIFEST refusal (no frontier ⇒ never quarantine blind). ---
    //
    // MUTATION that this gate catches: default the frontier to 0 on a manifest read miss instead of
    // refusing. Then a store with no manifest would treat every WAL object as "beyond frontier" and
    // could quarantine acked data. This test asserts the `UnreadableManifest` refusal.

    #[tokio::test]
    async fn repair_refuses_when_the_manifest_is_unreadable() {
        // A store with WAL objects but NO manifest at all: the frontier cannot be established.
        let store = mem_store();
        let root = "kv";
        put_wal(&store, root, 1, footer_object(64, 0)).await; // a torn object, tempting to quarantine
        let err = repair_wal_tail(&store, root, RepairMode::DryRun)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WalRepairError::UnreadableManifest { .. }),
            "no manifest ⇒ REFUSE (never quarantine without a durable frontier), got {err:?}"
        );
    }

    // ===== Whole-store awareness: compacted/L0 SSTs are DETECTED, never mutated =====

    /// A well-formed ULID-shaped compacted-SST object path `{root}/compacted/<ulid>.sst` (slatedb
    /// stores L0 / compacted SSTs as `SsTableId::Compacted(ulid)`, NOT the `{:020}.sst` WAL id).
    fn compacted_object_path(root: &str, ulid: &str) -> ObjPath {
        ObjPath::from(format!("{root}/compacted/{ulid}.sst"))
    }

    /// Seed a REAL slatedb store over `store` at `root`: one durable write, then a clean `close()`
    /// (freezes the memtable → an L0 SST under `compacted/`, advances the durable frontier, writes
    /// the manifest). Compactor + GC OFF so `close()` has nothing to drain — the deterministic,
    /// non-stalling InMemory path (mirrors `kv_slatedb::tests::test_settings`). After this the store
    /// has a readable manifest (so `repair_wal_tail` gets past the frontier check) and a readable
    /// compacted SST — a clean baseline into which a test injects a torn object.
    async fn seed_real_store(store: &Arc<dyn ObjectStore>, root: &str) {
        // slatedb `Settings` is a foreign `#[non_exhaustive]` struct, so field reassignment after
        // `default()` is the only way to build it (no struct-literal `..Default::default()`) — same
        // shape as `kv_slatedb::tests::test_settings`.
        #[allow(clippy::field_reassign_with_default)]
        let settings = {
            let mut settings = Settings::default();
            settings.flush_interval = Some(std::time::Duration::from_millis(5));
            settings.compactor_options = None;
            settings.garbage_collector_options = None;
            settings
        };
        let db = Db::builder(root.to_string(), store.clone())
            .with_settings(settings)
            .build()
            .await
            .unwrap();
        db.put(b"seed-key", b"seed-val").await.unwrap();
        db.close().await.unwrap(); // memtable → L0 (compacted/), frontier advanced, manifest written
    }

    /// The whole-store scan DETECTS a torn compacted/L0 SST (pure — no manifest needed) and marks it
    /// [`TornKind::CompactedSst`], and the scan itself mutates NOTHING (the object survives). This is
    /// the DETECTION half of the data-loss-safe invariant, decoupled from the frontier/manifest.
    #[tokio::test]
    async fn scan_detects_torn_compacted_sst_and_never_mutates_it() {
        let store = mem_store();
        let root = "kv";
        // A readable compacted SST (version 1) and a torn one (version 0, >10 bytes) side by side.
        let readable = compacted_object_path(root, "01J79C21YKR31J2BS1EFXJZ7MR");
        let torn = compacted_object_path(root, "01J79C21YKR31J2BS1EFXJZ7MS");
        store
            .put(&readable, footer_object(128, 1).into())
            .await
            .unwrap();
        store
            .put(&torn, footer_object(128, 0).into())
            .await
            .unwrap();

        // frontier is irrelevant to the compacted scan; pass 0.
        let found = scan_out_of_scope_torn(&store, root, 0).await.unwrap();
        assert_eq!(
            found.len(),
            1,
            "only the torn compacted SST is reported: {found:?}"
        );
        assert_eq!(found[0].path, torn.to_string());
        assert_eq!(found[0].kind, TornKind::CompactedSst);
        assert_eq!(found[0].class, WalClass::Torn);
        // DETECTION-ONLY: the scan copies/renames/deletes NOTHING — both objects still exist.
        assert!(
            store.head(&torn).await.is_ok(),
            "the torn compacted SST must not be removed"
        );
        assert!(
            store.head(&readable).await.is_ok(),
            "the readable compacted SST is untouched"
        );
    }

    /// The pure refusal decision: a non-empty out-of-scope list yields an `UnrepairableTornObject`
    /// naming every path; an empty list yields `None`. The message notes whether a safe WAL tail was
    /// quarantined first. Pure (no I/O), so the refusal shape is gated without a live manifest.
    #[test]
    fn out_of_scope_refusal_names_paths_and_notes_the_quarantine() {
        let torn = vec![
            TornObject {
                path: "kv/compacted/01J79C21YKR31J2BS1EFXJZ7MS.sst".to_string(),
                size: 128,
                class: WalClass::Torn,
                kind: TornKind::CompactedSst,
            },
            TornObject {
                path: "kv/wal/00000000000000000003.sst".to_string(),
                size: 64,
                class: WalClass::Torn,
                kind: TornKind::WalNonTrailing,
            },
        ];
        // Empty ⇒ no refusal.
        assert!(out_of_scope_refusal("kv", &[], &[]).is_none());
        // Non-empty ⇒ UnrepairableTornObject naming BOTH paths.
        let err = out_of_scope_refusal("kv", &torn, &[9]).expect("a refusal");
        match err {
            WalRepairError::UnrepairableTornObject {
                objects,
                detail,
                root,
            } => {
                assert_eq!(root, "kv");
                assert!(
                    objects.contains(&torn[0].path),
                    "names the compacted SST: {objects:?}"
                );
                assert!(
                    objects.contains(&torn[1].path),
                    "names the non-trailing WAL: {objects:?}"
                );
                assert!(
                    detail.contains("WAS quarantined"),
                    "the note records the WAL tail [9] was quarantined first: {detail}"
                );
            }
            other => panic!("expected UnrepairableTornObject, got {other:?}"),
        }
        // With no safe tail quarantined, the note says nothing was mutated.
        let err = out_of_scope_refusal("kv", &torn, &[]).expect("a refusal");
        assert!(
            format!("{err}").contains("mutated nothing"),
            "with no WAL tail, the message states nothing was mutated: {err}"
        );
    }

    /// GATE — a torn COMPACTED SST is DETECTED (dry-run) and an APPLY REFUSES (`UnrepairableTornObject`)
    /// naming it, and NEVER quarantines/deletes it (it still exists after the apply). This is the core
    /// data-loss-safety invariant: a compacted SST referenced by the manifest is DETECTION-ONLY.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_refuses_and_never_mutates_a_torn_compacted_sst() {
        let store = mem_store();
        let root = "kv";
        seed_real_store(&store, root).await; // real manifest + frontier + a readable L0 SST
        // Inject a torn (version-0, >10-byte) COMPACTED/L0 SST — the production torn-compacted case.
        let torn = compacted_object_path(root, "01J79C21YKR31J2BS1EFXJZ7MS");
        store
            .put(&torn, footer_object(128, 0).into())
            .await
            .unwrap();

        // DRY-RUN detects it in out_of_scope_torn (mutating nothing).
        let dry = repair_wal_tail(&store, root, RepairMode::DryRun)
            .await
            .unwrap();
        assert!(
            dry.out_of_scope_torn
                .iter()
                .any(|t| t.kind == TornKind::CompactedSst
                    && t.path == torn.to_string()
                    && t.class == WalClass::Torn),
            "dry-run must DETECT the torn compacted SST: {:?}",
            dry.out_of_scope_torn
        );

        // APPLY REFUSES, naming the compacted path.
        let err = repair_wal_tail(&store, root, RepairMode::Apply)
            .await
            .unwrap_err();
        match err {
            WalRepairError::UnrepairableTornObject { objects, .. } => assert!(
                objects.iter().any(|p| p == &torn.to_string()),
                "the refusal must name the torn compacted SST: {objects:?}"
            ),
            other => panic!("expected UnrepairableTornObject, got {other:?}"),
        }
        // DETECTION-ONLY: the compacted SST was NEVER quarantined/copied/deleted — it still exists.
        assert!(
            store.head(&torn).await.is_ok(),
            "the torn compacted SST must NOT be mutated by repair (manifest-referenced; data-loss guard)"
        );
    }

    /// GATE — a torn TRAILING WAL tail with NO compacted tear still quarantines and the apply SUCCEEDS
    /// (the existing WAL-tail behavior is unchanged by whole-store awareness).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_quarantines_a_torn_wal_tail_when_no_compacted_tear() {
        let store = mem_store();
        let root = "kv";
        seed_real_store(&store, root).await;
        // Inject a torn WAL object strictly beyond the durable frontier (a trailing tear).
        let frontier = repair_wal_tail(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;
        let torn_id = frontier + 1;
        put_wal(&store, root, torn_id, footer_object(64, 0)).await;

        let report = repair_wal_tail(&store, root, RepairMode::Apply)
            .await
            .unwrap();
        assert!(
            report.applied,
            "the WAL-tail quarantine must have been applied: {report:?}"
        );
        assert_eq!(
            report.quarantined,
            vec![torn_id],
            "the trailing torn tail is quarantined"
        );
        assert!(
            report.out_of_scope_torn.is_empty(),
            "no compacted tear ⇒ no out-of-scope torn objects: {:?}",
            report.out_of_scope_torn
        );
        // The torn bytes were preserved under wal-quarantine/ before the delete (forensic-safe),
        // and — because `repair_wal_tail(Apply)` now ends with a REAL open verification (C4) that
        // SUCCEEDED (the `.unwrap()` above) — the store is genuinely bootable again. (We do NOT
        // assert `wal/{torn_id}` is absent: the verify open claims the next WAL slot, which is that
        // same id, so slatedb re-creates a fresh — non-torn — object there; the point is the store
        // OPENS, which the successful verify proves.)
        let qdir = report.quarantine_dir.expect("a quarantine dir");
        let qcopy = ObjPath::from(format!("{qdir}/{torn_id:020}.sst"));
        assert!(
            store.head(&qcopy).await.is_ok(),
            "the torn bytes must be preserved under wal-quarantine/ (forensic-safe copy)"
        );
        // And an independent real open confirms the repaired store is bootable.
        assert!(
            verify_opens(&store, root).await.is_ok(),
            "the repaired store must open cleanly after the repair"
        );
    }

    /// GATE (C4) — the real-open verification is the DEFINITIVE post-repair check: a torn WAL object
    /// left in the replay range (simulating a classifier miss the footer probe could not catch)
    /// makes `verify_opens` FAIL LOUD with `OpenVerificationFailed`, never a false success. This is
    /// what backs the invariant that `repair_wal_tail(Apply)` returning `Ok` means the store genuinely
    /// boots — the footer re-scan it replaces shares the classifier's blind spot; a real open does not.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_opens_fails_loud_on_a_torn_wal_object_in_the_replay_range() {
        let store = mem_store();
        let root = "kv";
        seed_real_store(&store, root).await;
        let frontier = repair_wal_tail(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;
        // A torn version-0 WAL object in the replay range that a (hypothetically relaxed) quarantine
        // left behind — the real open replays it and dies. `verify_opens` must surface that failure.
        put_wal(&store, root, frontier + 1, footer_object(64, 0)).await;
        let err = verify_opens(&store, root)
            .await
            .expect_err("a torn WAL object in the replay range must fail the real open");
        assert!(
            matches!(err, WalRepairError::OpenVerificationFailed { .. }),
            "the real open must fail loud (never claim success): got {err:?}"
        );
    }

    /// GATE — BOTH a safe WAL tail AND a torn compacted SST: the apply quarantines the WAL tail FIRST
    /// (progress), then REFUSES with `UnrepairableTornObject` naming the compacted path — and the
    /// compacted SST still exists (never mutated). Proves the quarantine-then-fail-loud ordering.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_quarantines_wal_tail_then_refuses_on_torn_compacted() {
        let store = mem_store();
        let root = "kv";
        seed_real_store(&store, root).await;
        let frontier = repair_wal_tail(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
            .frontier;
        let torn_id = frontier + 1;
        put_wal(&store, root, torn_id, footer_object(64, 0)).await; // safe trailing WAL tear
        let torn_compacted = compacted_object_path(root, "01J79C21YKR31J2BS1EFXJZ7MT");
        store
            .put(&torn_compacted, footer_object(128, 0).into())
            .await
            .unwrap(); // out-of-scope tear

        let err = repair_wal_tail(&store, root, RepairMode::Apply)
            .await
            .unwrap_err();
        match err {
            WalRepairError::UnrepairableTornObject { objects, .. } => assert!(
                objects.iter().any(|p| p == &torn_compacted.to_string()),
                "the refusal must name the torn compacted SST: {objects:?}"
            ),
            other => panic!("expected UnrepairableTornObject, got {other:?}"),
        }
        // The safe WAL tail WAS quarantined first (progress made before the fail-loud).
        assert!(
            store.head(&wal_object_path(root, torn_id)).await.is_err(),
            "the safe trailing WAL tail must have been quarantined before the refusal"
        );
        // But the compacted SST was NEVER touched (DETECTION-ONLY, data-loss guard).
        assert!(
            store.head(&torn_compacted).await.is_ok(),
            "the torn compacted SST must never be quarantined/deleted by repair"
        );
    }

    // ===================================================================================
    // F2 — last-good-generation cold-open recovery from an empty/torn LATEST manifest (v0.11.0).
    // Over a shared `InMemory` store (deterministic, non-stalling — the same path the whole-store
    // gates use), so these run UNIGNORED on every toolchain.
    // ===================================================================================

    /// Seed a REAL slatedb store with a crown-jewel write frozen to L0 under a good generation, then a
    /// clean `close()` (memtable → L0, frontier advanced, manifest written). Compactor + GC OFF so the
    /// manifest generations linger for the tear.
    async fn seed_real_store_with_secret(store: &Arc<dyn ObjectStore>, root: &str) {
        #[allow(clippy::field_reassign_with_default)]
        let settings = {
            let mut settings = Settings::default();
            settings.flush_interval = Some(Duration::from_millis(5));
            settings.compactor_options = None;
            settings.garbage_collector_options = None;
            settings
        };
        let db = Db::builder(root.to_string(), store.clone())
            .with_settings(settings)
            .build()
            .await
            .unwrap();
        db.put(b"secret/acme/idp", b"sealed-crown-jewel")
            .await
            .unwrap();
        db.close().await.unwrap();
    }

    /// Inject a torn (0-byte) manifest at `{root}/manifest/{id:020}.manifest` — the production
    /// empty-manifest signature (a hard stop / snapshot froze a just-hard-linked manifest before its
    /// data blocks were durable).
    async fn inject_torn_manifest(store: &Arc<dyn ObjectStore>, root: &str, id: u64) {
        store
            .put(&manifest_object_path(root, id), bytes::Bytes::new().into())
            .await
            .unwrap();
    }

    /// The highest manifest generation id present on the store.
    async fn highest_manifest_id(store: &Arc<dyn ObjectStore>, root: &str) -> u64 {
        *list_manifest_ids(store, root)
            .await
            .unwrap()
            .first()
            .expect("a seeded store has at least one manifest")
    }

    /// Open a fresh throwaway `Db` over the store and read `key` (proves the recovered store boots AND
    /// retains the value byte-equal).
    async fn read_key_via_fresh_db(
        store: &Arc<dyn ObjectStore>,
        root: &str,
        key: &[u8],
    ) -> Option<Vec<u8>> {
        #[allow(clippy::field_reassign_with_default)]
        let settings = {
            let mut settings = Settings::default();
            settings.flush_interval = Some(Duration::from_millis(5));
            settings.compactor_options = None;
            settings.garbage_collector_options = None;
            settings
        };
        let db = Db::builder(root.to_string(), store.clone())
            .with_settings(settings)
            .build()
            .await
            .expect("the recovered store must open");
        let val = db.get(key).await.unwrap().map(|b| b.to_vec());
        db.close().await.unwrap();
        val
    }

    // --- MF2 pure guard: the WAL replay-range contiguity check. ---

    /// MUTATION this catches: drop the leading-edge requirement (start the loop at `min_present` rather
    /// than `frontier+1`). Then a GC'd (F, min_present) range would pass and the rollback would SILENTLY
    /// lose the acked writes that lived there.
    #[test]
    fn mf2_contiguity_refuses_a_leading_gc_hole() {
        // Rolled back to frontier F=5; surviving WAL ids {8,9} — 6,7 GC'd away (a LEADING hole). Replay
        // must start at 6 but 6 is absent while 8,9 sit above it → REFUSE.
        let wal: std::collections::BTreeSet<u64> = [8u64, 9].into_iter().collect();
        let err = check_manifest_rollback_wal_contiguity(&wal, 5, "kv").unwrap_err();
        match err {
            WalRepairError::ManifestRollbackGcHole {
                rolled_back_frontier,
                missing_wal_id,
                highest_wal_id,
                ..
            } => {
                assert_eq!(rolled_back_frontier, 5);
                assert_eq!(missing_wal_id, 6, "the first absent id in the replay range");
                assert_eq!(highest_wal_id, 9);
            }
            other => panic!("expected a ManifestRollbackGcHole, got {other:?}"),
        }
    }

    #[test]
    fn mf2_contiguity_refuses_an_interior_hole() {
        // F=5; {6,7,9} present, 8 absent → an interior hole below acked data at 9.
        let wal: std::collections::BTreeSet<u64> = [6u64, 7, 9].into_iter().collect();
        let err = check_manifest_rollback_wal_contiguity(&wal, 5, "kv").unwrap_err();
        assert!(
            matches!(
                err,
                WalRepairError::ManifestRollbackGcHole {
                    missing_wal_id: 8,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn mf2_contiguity_allows_contiguous_and_empty_cases() {
        // Contiguous from F+1 → OK.
        let wal: std::collections::BTreeSet<u64> = [6u64, 7, 8].into_iter().collect();
        assert!(check_manifest_rollback_wal_contiguity(&wal, 5, "kv").is_ok());
        // No WAL objects at all → nothing to replay.
        assert!(
            check_manifest_rollback_wal_contiguity(&std::collections::BTreeSet::new(), 5, "kv")
                .is_ok()
        );
        // Every WAL object already covered by the frontier (all <= F) → OK.
        let below: std::collections::BTreeSet<u64> = [1u64, 2, 3].into_iter().collect();
        assert!(check_manifest_rollback_wal_contiguity(&below, 5, "kv").is_ok());
    }

    // --- End-to-end over a real InMemory slatedb store. ---

    /// **F2 GATE** — a torn LATEST manifest + a valid last-good generation G: DRY-RUN plans the rollback
    /// (mutating nothing), APPLY rolls back to G, quarantines the torn manifest OUTSIDE `manifest/`, and
    /// the recovered store OPENS with the crown-jewel byte-equal. Anti-hollow: the crown-jewel round-trip
    /// is the guard — a rollback to the wrong generation (or a failure to quarantine the torn suffix)
    /// makes the reopen miss the key or fail to open.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_rolls_back_to_last_good_generation_and_crown_jewel_survives() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await;
        let good = highest_manifest_id(&store, root).await;
        // Inject a torn (0-byte) manifest at good+1 — the empty-manifest outage (torn N > G).
        inject_torn_manifest(&store, root, good + 1).await;
        assert!(
            read_frontier(&store, root).await.is_err(),
            "the torn latest manifest must be unreadable (the F2 trigger)"
        );

        // DRY-RUN: plans the rollback to G, mutates NOTHING (the torn manifest is retained).
        match recover_last_good_manifest(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
        {
            ManifestRecovery::RolledBack(r) => {
                assert_eq!(r.rolled_back_to_generation, good);
                assert_eq!(r.quarantined_manifest_ids, vec![good + 1]);
                assert!(!r.applied);
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
        assert!(
            store
                .head(&manifest_object_path(root, good + 1))
                .await
                .is_ok(),
            "DRY-RUN must retain the torn manifest (mutate nothing)"
        );

        // APPLY: rolls back to G, quarantines the torn manifest, verify_opens succeeds.
        let report = match recover_last_good_manifest(&store, root, RepairMode::Apply)
            .await
            .unwrap()
        {
            ManifestRecovery::RolledBack(r) => r,
            other => panic!("expected RolledBack, got {other:?}"),
        };
        assert!(report.applied);
        assert_eq!(report.rolled_back_to_generation, good);
        // The torn 0-byte manifest's BYTES are gone from manifest/. The Apply's `verify_opens` close
        // re-creates a FRESH, VALID manifest at the reused id (slatedb tracks next-manifest-id), so the
        // invariant is that the TORN 0-byte bytes are no longer at the path (preserved only under
        // manifest-quarantine/) — not that the path is absent. `assert_no_torn_manifest_remains` proved
        // no torn manifest survived BEFORE verify re-wrote a valid one.
        if let Ok(now) = store.get(&manifest_object_path(root, good + 1)).await {
            let bytes = now.bytes().await.unwrap();
            assert!(
                !bytes.is_empty(),
                "a fresh valid manifest at the reused id is fine; the torn 0-byte bytes must be gone"
            );
        }
        let qdir = report
            .manifest_quarantine_dir
            .expect("a manifest-quarantine dir");
        let qcopy = ObjPath::from(format!("{qdir}/{:020}.manifest", good + 1));
        assert!(
            store.head(&qcopy).await.is_ok(),
            "the torn manifest bytes must be preserved under manifest-quarantine/ (forensic-safe copy)"
        );

        // The recovered store OPENS and the crown-jewel survives byte-equal.
        assert_eq!(
            read_key_via_fresh_db(&store, root, b"secret/acme/idp").await,
            Some(b"sealed-crown-jewel".to_vec()),
            "F2: the acked crown-jewel MUST survive the last-good-generation rollback byte-equal"
        );
    }

    /// **F2 GATE** — NO manifest generation decodes ⇒ REFUSE loud ([`WalRepairError::NoDecodableManifest`]),
    /// NEVER a silent WAL-from-0. Mutation this catches: defaulting to WAL-from-0 on no-decodable would
    /// return `Ok` instead of the loud refusal.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_refuses_loud_when_no_generation_decodes() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await;
        // Tear EVERY manifest generation (0-byte) — no last-good generation remains.
        for id in list_manifest_ids(&store, root).await.unwrap() {
            inject_torn_manifest(&store, root, id).await;
        }
        let err = recover_last_good_manifest(&store, root, RepairMode::DryRun)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WalRepairError::NoDecodableManifest { .. }),
            "no decodable generation ⇒ REFUSE loud (never silent WAL-from-0), got {err:?}"
        );
    }

    /// **MF2 GATE (end-to-end)** — a WAL GC hole below the rollback frontier ⇒ REFUSE
    /// ([`WalRepairError::ManifestRollbackGcHole`]), never a lossy rollback. A readable WAL object at
    /// F+2 with F+1 ABSENT is the leading GC hole the fsync silent-loss window would produce.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_refuses_a_wal_gc_hole_below_the_rollback_frontier() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await;
        let good = highest_manifest_id(&store, root).await;
        // Read the good frontier F BEFORE tearing the latest (afterwards read_frontier fails).
        let frontier = read_frontier(&store, root).await.unwrap();
        inject_torn_manifest(&store, root, good + 1).await;
        // Model WAL-GC that advanced off a non-durable generation (the fsync silent-loss window): a
        // surviving readable WAL object ABOVE the frontier with the F+1 replay slot ABSENT — a leading
        // GC hole the rollback cannot bridge. Add a higher survivor, then clear the F+1 slot.
        put_wal(&store, root, frontier + 3, footer_object(64, 1)).await;
        store
            .delete(&wal_object_path(root, frontier + 1))
            .await
            .ok(); // clear the F+1 slot (no-op if it was already absent)
        let err = recover_last_good_manifest(&store, root, RepairMode::DryRun)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WalRepairError::ManifestRollbackGcHole { .. }),
            "a WAL GC hole below the rollback frontier ⇒ REFUSE, got {err:?}"
        );
    }

    /// **F2 GATE** — a READABLE latest manifest is NOT the manifest shape: recovery is a no-op
    /// ([`ManifestRecovery::LatestReadable`]) so the caller falls through to the WAL-tail path.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_is_a_noop_when_the_latest_manifest_is_readable() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await;
        match recover_last_good_manifest(&store, root, RepairMode::Apply)
            .await
            .unwrap()
        {
            ManifestRecovery::LatestReadable { .. } => {}
            other => panic!("a readable latest manifest must be a no-op, got {other:?}"),
        }
    }
}
