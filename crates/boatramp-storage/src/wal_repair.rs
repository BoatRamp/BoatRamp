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

    /// **v0.11.1** — one or more manifest generations DECODE, but NONE of them OPENS CLEAN: every
    /// decodable generation references a removed/torn compacted SST (the mid-compaction unclean-exit
    /// `Invalid error: invalid compaction` shape) or otherwise fails a real open+scan. There is no
    /// last-good generation to adopt WITHOUT dropping acked data, so recovery REFUSES rather than
    /// adopt an unopenable generation (that was the v0.11.0 bug: self-heal rolled back to the newest
    /// generation that merely *decoded*, which then failed `Db::open` with `invalid compaction`, and
    /// `kv recover` reported "should open normally" because it decoded). The heavier fallback —
    /// rebuilding the LSM from the WAL + surviving SSTs while discarding the bad compaction record
    /// (construens ask #2) — is DEFERRED and NOT performed here; recover from a clean volume snapshot
    /// or the object-store backup instead.
    #[error(
        "control-plane manifest recovery refused: {examined} manifest generation(s) at `{root}` \
         DECODE, but NONE opens clean — the newest decodable generation ({newest_generation}) fails \
         a real open with the `invalid compaction` / missing-referenced-SST shape (an earlier \
         mid-compaction unclean exit), and every older decodable generation is likewise unopenable. \
         Refusing to adopt an unopenable generation (it would still fail `Db::open` and could drop \
         acked data). Recover from a clean volume snapshot \
         (`boatramp kv recover --adopt-volume <mounted-path>`) or restore the object store from a \
         backup; rebuilding the LSM from the WAL + surviving SSTs (discarding the bad compaction \
         record) is not yet automated"
    )]
    NoOpenableManifest {
        /// The store root.
        root: String,
        /// How many decodable manifest generations were examined (and all found unopenable).
        examined: usize,
        /// The newest decodable generation (the one v0.11.0 would have wrongly adopted).
        newest_generation: u64,
    },

    /// **MF2 (v0.11.0)** — rolling back to the last-good generation G (durable frontier F) would need a
    /// WAL replay range `(F, …]` that is NOT intact: a WAL id is ABSENT below the highest surviving WAL
    /// object. WAL-GC advanced off a non-durable generation (the fsync silent-loss window this release
    /// closes: a torn manifest N that was page-cache-readable let a GC pass collect the `(F, F_N]`
    /// replay range) and the acked writes in the hole are unrecoverable, so the rollback would SILENTLY
    /// drop acked state → REFUSE. Complements [`WalIdHole`](Self::WalIdHole) (a hole below a readable
    /// survivor within a single-generation repair); this is the leading/interior gap a manifest
    /// ROLLBACK to an older, lower frontier exposes. It fires precisely when a surviving WAL id sits
    /// beyond the rollback frontier with a hole below it; the complementary "whole replay range gone"
    /// case is prevented upstream by slatedb's WAL-GC *retaining the frontier object*
    /// (`Bound::Included(replay_after_wal_id)`), which turns a genuinely-advanced-then-GC'd store into
    /// exactly this detectable leading-hole shape — see [`check_manifest_rollback_wal_contiguity`] and
    /// its F1b invariant-pin test (`verify_opens` proves BOOT, not RETENTION).
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

    /// **v0.11.1** — after the corrupt-`.compactions` reset (quarantine the `.compactions` objects +
    /// remove the compactions GC boundary), the compactor-state verify STILL failed: either
    /// `Admin::read_compactions` did not come back clean (a corrupt `.compactions` object still decodes
    /// with `InvalidCompaction`) or the compactions GC boundary is still present (it would reject the
    /// fresh id-1 `.compactions` the compactor-ON reopen creates, with `ObjectVersionExists`). Refuse to
    /// claim success — the store would still fail its compactor-ON open.
    #[error(
        "control-plane compactions reset: after quarantining the corrupt `.compactions` object(s) at \
         `{root}`, the compactor-state verify STILL failed ({detail}) — refusing to report success (a \
         compactor-ON reopen would still fail). Run `boatramp kv recover` to diagnose / adopt a clean \
         volume snapshot"
    )]
    CompactionsResetVerifyFailed {
        /// The store root.
        root: String,
        /// Why the post-reset verify failed (corrupt object still decodes, or the boundary remains).
        detail: String,
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

/// **Real-open + full-scan verification (C4, extended v0.11.1).** Attempt an ACTUAL [`slatedb::Db`]
/// open of the store at `root` over `store`, with repair DISABLED, THEN drive a FULL range scan of
/// every key before closing — the definitive check that the store the repair just produced genuinely
/// boots AND can SERVE its data.
///
/// ## Why a scan, not just open+close (v0.11.1 — the invalid-compaction / missing-SST gap)
///
/// `Db::builder().build()` + `close()` proves WAL replay + manifest load + a checkpoint, but it does
/// **not** read the manifest's referenced L0 / sorted-run SSTs — those are loaded LAZILY on a query.
/// A manifest generation whose db_state references a **removed or torn compacted SST** (an earlier
/// mid-compaction unclean exit — the production `Invalid error: invalid compaction` shape) therefore
/// `build()`s and `close()`s cleanly, only for the real serving `get`/`scan` to die later. A bare
/// open+close would green-light such a generation. A full range scan forces slatedb to read every
/// referenced SST block, so a missing/torn referenced SST surfaces HERE as an
/// [`WalRepairError::OpenVerificationFailed`] rather than at first serve — this is what makes the
/// last-good-generation walk ([`recover_last_good_manifest`]) adopt a generation that OPENS CLEAN
/// (serve-able), not merely one that decodes. (Confirmed empirically: deleting a manifest-referenced
/// L0 SST leaves open+close `Ok`, but the scan errors `object store ... not found`.)
///
/// Builds a throwaway writer with the background compactor + GC disabled (nothing to drain, so the
/// close is fast and cannot stall), scans, then closes it. `Ok(())` ⇒ the store opened, every
/// referenced SST read, and it closed cleanly; `Err` ⇒ it is NOT serve-able.
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
    // FULL SCAN — force a read of every referenced L0 / sorted-run SST (a missing/torn compacted SST
    // is otherwise invisible to a lazy open; see the doc above). On any scan error, close the throwaway
    // writer (best-effort) and fail loud so a won't-serve generation is never reported openable.
    let scan_result: Result<(), WalRepairError> = async {
        let mut iter = db
            .scan(..)
            .await
            .map_err(|e| WalRepairError::OpenVerificationFailed {
                root: root.to_string(),
                detail: format!("store opened but a verification scan could not start: {e}"),
            })?;
        loop {
            match iter.next().await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    return Err(WalRepairError::OpenVerificationFailed {
                        root: root.to_string(),
                        detail: format!(
                            "store opened but a verification scan failed (a referenced SST is \
                             missing/torn — invalid-compaction shape): {e}"
                        ),
                    });
                }
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = scan_result {
        // Best-effort close of the throwaway writer before surfacing the scan failure.
        let _ = db.close().await;
        return Err(e);
    }
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

/// The outcome of an F2/v0.11.1 last-good-generation recovery attempt.
#[derive(Debug, Clone)]
pub enum ManifestRecovery {
    /// The LATEST manifest is READABLE **and opens clean** (decodes AND every referenced SST is
    /// present/intact) — this is NOT the empty/torn-manifest nor the invalid-compaction shape, and
    /// NOTHING was done. The caller should use the ordinary WAL-tail path ([`repair_wal_tail`]).
    /// Carries the latest frontier so the caller can surface it. **v0.11.1:** the gate is now
    /// OPEN-ability (serve-able), not mere decode-ability — a latest that decodes but references a
    /// removed/torn compacted SST (the `invalid compaction` shape) does NOT short-circuit here; it
    /// falls through to the generation walk and returns [`RolledBack`](Self::RolledBack).
    LatestReadable {
        /// `replay_after_wal_id` of the (readable, openable) latest manifest.
        frontier: u64,
    },
    /// The latest manifest was empty/torn/absent OR decodes-but-won't-open (invalid compaction); the
    /// recovery walk adopted the newest generation G that OPENS CLEAN (on [`RepairMode::Apply`]) — or,
    /// on [`RepairMode::DryRun`], computed the plan it WOULD apply. See [`ManifestRecoveryReport`].
    /// Boxed so this (large) variant does not bloat the common [`LatestReadable`](Self::LatestReadable)
    /// no-op variant (clippy `large_enum_variant`).
    RolledBack(Box<ManifestRecoveryReport>),
}

/// One rung of the generation-walk ladder (v0.11.1): a manifest generation present on the store and
/// what the recovery walk determined about it. Surfaced in [`ManifestRecoveryReport::candidate_ladder`]
/// so `boatramp kv recover` can print the exact ladder (which generations were skipped as unopenable,
/// and which one is adopted) instead of a bare "should open normally".
#[derive(Debug, Clone)]
pub struct ManifestCandidate {
    /// The manifest generation id.
    pub generation: u64,
    /// `replay_after_wal_id` of this generation, when it decoded (`None` for an undecodable/torn one).
    pub frontier: Option<u64>,
    /// A one-line human status: `adopted (opens clean)`, `skipped: <reason>` (decodes but won't open),
    /// or `undecodable (torn/empty manifest)`.
    pub status: String,
}

/// The plan/outcome of a last-good-generation rollback (F2 / v0.11.1 invalid-compaction walk).
#[derive(Debug, Clone)]
pub struct ManifestRecoveryReport {
    /// The newest manifest generation G that OPENS CLEAN (v0.11.1: decodes AND is serve-able — every
    /// referenced SST present/intact), which the store was (or would be) rolled back to. Earlier
    /// (v0.11.0) this was merely the newest generation that DECODED, which is the bug this release fixes.
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
    /// **v0.11.1** — the full generation-walk ladder (highest generation first): every manifest
    /// generation present on the store with its openability verdict (adopted / skipped-unopenable /
    /// undecodable). Lets `boatramp kv recover` print the candidate ladder + the generation it expects
    /// to adopt, so a decodes-but-won't-open latest is classified RECOVERABLE (never "should open
    /// normally"). The adopted generation equals [`Self::rolled_back_to_generation`].
    pub candidate_ladder: Vec<ManifestCandidate>,
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
/// that guard returns `Ok` when the WHOLE tail is gone (no readable survivor), where rolling back to an
/// OLDER, LOWER frontier F needs a replay range a later GC pass may have erased. A torn TRAILING WAL
/// object is still PRESENT (an object at that id) and is handled by the WAL-tail self-heal; this guard
/// is about ABSENT ids (an unbridgeable hole), never torn-but-present.
///
/// **Load-bearing external invariant (F1a — read before trusting the empty-range branch).** This guard
/// does NOT itself detect a true "whole replay range gone": it returns `Ok` when `highest <= frontier`
/// (no WAL object beyond F). That branch is safe ONLY because slatedb's WAL-GC *retains the WAL object
/// AT the frontier*: the latest manifest's referenced range is `WalFileRange(Bound::Included(
/// replay_after_wal_id), Bound::Unbounded)` (slatedb `garbage_collector/wal_gc.rs` `referenced_wal_ranges`,
/// "Keep the current compaction boundary and everything after it"). So the WAL object at the DURABLE
/// frontier is never GC'd. Consequence for a rollback: if the store had ever advanced to a frontier
/// F_N > F_G (under the torn generation we discard), WAL-GC running off that generation retained the
/// boundary object at F_N — which, after we roll back to G (frontier F_G), is a surviving WAL id > F_G,
/// so `highest > frontier` and the loop below runs and catches the leading hole in `(F_G, F_N)`. In
/// other words, the retention invariant is what guarantees a genuinely-advanced-then-GC'd store can
/// never reach the `highest <= frontier` escape with acked data missing — the guard's own code does not
/// catch that case; slatedb's GC-retention does. [`slatedb_wal_gc_retains_the_frontier_object_INVARIANT`]
/// (F1b) pins this invariant so a future slatedb change (e.g. `Bound::Included`→`Excluded`) that would
/// silently reopen the crown-jewel-loss window fails RED here. (A deferred belt-and-suspenders —
/// Security F1c — is an orphaned-L0 cross-check in the empty-range branch; the F1b test-pin is the
/// primary safeguard, so it is intentionally NOT built.)
fn check_manifest_rollback_wal_contiguity(
    wal_ids_present: &std::collections::BTreeSet<u64>,
    frontier: u64,
    root: &str,
) -> Result<(), WalRepairError> {
    let Some(&highest) = wal_ids_present.iter().max() else {
        return Ok(()); // no WAL objects at all → nothing to replay, nothing to lose
    };
    if highest <= frontier {
        // Empty replay range. SAFE only via the external WAL-GC retention invariant documented above
        // (the retained boundary object at a genuinely-advanced frontier would make highest > frontier);
        // F1b pins it. The deferred orphaned-L0 cross-check (F1c) is intentionally not built here.
        return Ok(());
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

/// List `{root}/compacted/` once, returning each `.sst` object's filename → size. The non-mutating
/// structural openability check ([`generation_structurally_openable`]) tests a manifest generation's
/// referenced compacted SSTs against this set (existence) and re-probes present ones for a torn footer.
async fn list_compacted_sizes(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<std::collections::BTreeMap<String, u64>, WalRepairError> {
    use futures::StreamExt;
    let prefix = ObjPath::from(format!("{root}/compacted"));
    let mut stream = store.list(Some(&prefix));
    let mut out = std::collections::BTreeMap::new();
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        if let Some(name) = meta.location.filename()
            && name.ends_with(".sst")
        {
            out.insert(name.to_string(), meta.size);
        }
    }
    Ok(out)
}

/// **Non-mutating structural openability prediction (v0.11.1).** Given a DECODED manifest generation,
/// predict whether a real open + full scan ([`verify_opens`]) would succeed — WITHOUT opening the store
/// (a writer open fences and writes a manifest; it cannot be used in a dry-run). The prediction mirrors
/// the exact failure the invalid-compaction shape causes: a referenced compacted SST that is REMOVED
/// (an earlier mid-compaction unclean exit, the production `invalid compaction`) or TORN. It enumerates
/// the generation's referenced L0 + sorted-run SSTs (every one a `SsTableId::Compacted(ulid)` →
/// `{root}/compacted/{ulid}.sst`) and checks each is present (via `compacted`) and not torn (re-probing
/// the footer with [`classify`]).
///
/// Returns `Ok(None)` = predicted serve-able; `Ok(Some(reason))` = predicted UNOPENABLE (names the first
/// missing/torn SST); `Err` for a shape this predictor does not model — a store with **external DBs** or
/// a **segment extractor** (non-standard SST paths). Control-plane KV uses neither (no external_dbs, no
/// segments — verified at seed), so the `Err` path is a defensive fail-loud, never hit in production.
///
/// This is the DRY-RUN authority; [`verify_opens`] (a real open + scan) is the APPLY authority and the
/// final word (so a failure mode this structural check cannot see still fails loud on apply, never a
/// false success).
async fn generation_structurally_openable(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    vm: &slatedb::VersionedManifest,
    compacted: &std::collections::BTreeMap<String, u64>,
) -> Result<Option<String>, WalRepairError> {
    use slatedb::object_store_tag::SstType;

    // Defensive: this predictor derives `{root}/compacted/{ulid}.sst` paths, which only hold for a
    // plain (non-external, non-segmented) store. Control-plane KV is always plain; anything else is a
    // shape we refuse to predict rather than mispredict.
    if !vm.external_dbs().is_empty() || !vm.segments().is_empty() {
        return Err(WalRepairError::Store(format!(
            "structural openability prediction unsupported at `{root}`: the manifest references \
             external DBs ({}) or segment extractor(s) ({}) with non-standard SST paths",
            vm.external_dbs().len(),
            vm.segments().len()
        )));
    }

    // Collect every referenced compacted SST filename `{ulid}.sst` (L0 views + each sorted run's
    // views). L0 and sorted-run SSTs are ALWAYS `Compacted` (WAL SSTs never appear here); the `SstType`
    // guard makes `unwrap_compacted_id()` panic-proof regardless. The ULID's `Display` is used directly
    // (the `ulid` type lives in slatedb's private module and need not be named here).
    let mut referenced_filenames: Vec<String> = Vec::new();
    for view in vm.l0() {
        if SstType::from(&view.sst.id) == SstType::Compacted {
            referenced_filenames.push(format!("{}.sst", view.sst.id.unwrap_compacted_id()));
        }
    }
    for sr in vm.compacted() {
        for view in sr.sst_views() {
            if SstType::from(&view.sst.id) == SstType::Compacted {
                referenced_filenames.push(format!("{}.sst", view.sst.id.unwrap_compacted_id()));
            }
        }
    }

    for filename in referenced_filenames {
        match compacted.get(&filename) {
            None => {
                return Ok(Some(format!(
                    "references a REMOVED compacted SST `{root}/compacted/{filename}` (invalid \
                     compaction — an earlier mid-compaction unclean exit left the manifest pointing \
                     at an object that no longer exists)"
                )));
            }
            Some(&size) => {
                // Present — re-probe the footer: a torn (version-0 / truncated) compacted SST decodes
                // in the manifest but fails the real open+scan just as a missing one does.
                let path = ObjPath::from(format!("{root}/compacted/{filename}"));
                if classify(store, &path, size).await? == WalClass::Torn {
                    return Ok(Some(format!(
                        "references a TORN compacted SST `{root}/compacted/{filename}` (a bad footer \
                         version — invalid-compaction/partial-write shape)"
                    )));
                }
            }
        }
    }
    Ok(None)
}

/// **Mutation seam (CI host-lane).** Returns `false` in the shipped code: the generation walk adopts
/// the newest generation that OPENS CLEAN (decodes AND is structurally serve-able). The CI mutation loop
/// flips this to `true` to reproduce the **v0.11.0 bug** — adopt the newest generation that merely
/// DECODES, SKIPPING the openability check — under which
/// `recover_adopts_newest_openable_generation_and_crown_jewel_survives` goes RED (the adopted
/// invalid-compaction generation then fails the real open + scan verify). A function (not a `const`) so
/// the shipped `false` is a runtime value, not a clippy constant-condition lint.
#[inline]
fn stop_at_first_decodable() -> bool {
    // Mutation seam, compiled out of shipped binaries (cfg(test) only — never a production env
    // backdoor): under `cargo test` with BOATRAMP_KVMANIFEST_MUTATION=stop_at_first_decodable the walk
    // reverts to v0.11.0's "adopt the newest DECODABLE generation" (skipping the openability check), so
    // the CI mutation loop can confirm `recover_adopts_newest_openable_generation_and_crown_jewel_survives`
    // + `self_heal_walk_skips_a_decodable_but_unopenable_generation` go RED. Shipped: always false.
    #[cfg(test)]
    {
        if std::env::var("BOATRAMP_KVMANIFEST_MUTATION").as_deref() == Ok("stop_at_first_decodable")
        {
            return true;
        }
    }
    false
}

/// The adopted generation + the quarantine plan computed by the NON-MUTATING generation walk.
struct GenerationWalkPlan {
    /// The newest generation that OPENS CLEAN (decodes AND structurally serve-able).
    adopted_generation: u64,
    /// The adopted generation's durable frontier `F = replay_after_wal_id`.
    adopted_frontier: u64,
    /// Every PRESENT `manifest/{:020}.manifest` id strictly above the adopted generation — the suffix
    /// to quarantine so the adopted generation becomes the latest (undecodable torn ids AND decodable-
    /// but-unopenable ids the walk skipped).
    quarantine_ids: Vec<u64>,
    /// The full candidate ladder (highest generation first) for the report / `kv recover` print.
    candidate_ladder: Vec<ManifestCandidate>,
}

/// **The generation walk (v0.11.1), NON-MUTATING.** Walk the manifest generations highest → lowest and
/// find the newest that OPENS CLEAN — decodes AND is structurally serve-able (every referenced SST
/// present/intact), re-running the MF2 GC-boundary + WAL-contiguity guards at EACH candidate's frontier.
/// This is the authority for both the DRY-RUN plan AND the generation the APPLY path targets before it
/// mutates anything (so a store with no openable generation fails loud WITHOUT gutting `manifest/`).
///
/// Why structural (not a real open) here: a real writer open FENCES and writes a manifest, so it cannot
/// run in a dry-run and would mutate even a healthy store; and `verify_opens` opens the LATEST, so
/// testing an older candidate by real open would require quarantining the suffix above it first (a
/// mutation). The structural check ([`generation_structurally_openable`]) predicts the exact
/// invalid-compaction / missing-SST failure non-mutatingly; [`verify_opens`] is the apply-time final word.
///
/// Walking DOWN adopts a LOWER frontier = a LONGER WAL replay range, which stays lossless ONLY if
/// contiguous — so MF2 is re-checked at each candidate. An MF2 failure (hole / below GC boundary) at a
/// candidate fails LOUD and stops: a lower candidate has an even longer range (a superset), so its range
/// contains the same hole — continuing cannot help and adopting it would silently drop acked data.
///
/// Returns the adopted plan, or fails loud: [`WalRepairError::NoDecodableManifest`] (nothing decodes),
/// [`WalRepairError::NoOpenableManifest`] (some decode but none opens clean — never adopt an unopenable
/// generation), [`WalRepairError::ManifestRollbackGcHole`] / [`WalRepairError::BelowGcBoundary`] (MF2).
async fn plan_generation_walk(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<GenerationWalkPlan, WalRepairError> {
    // 1. Enumerate manifest generation ids present on the store (descending).
    let manifest_ids = list_manifest_ids(store, root).await?;
    if manifest_ids.is_empty() {
        return Err(WalRepairError::NoDecodableManifest {
            root: root.to_string(),
            listed: 0,
        });
    }

    // Read-only inputs gathered once for the whole walk.
    let admin = Admin::builder(root.to_string(), store.clone()).build();
    let compacted = list_compacted_sizes(store, root).await?;
    let wal_ids = list_wal_ids(store, root).await?;
    let boundary = read_manifest_gc_boundary(store, root).await;

    let mut ladder: Vec<ManifestCandidate> = Vec::new();
    let mut examined_decodable = 0usize;
    let mut newest_decodable: Option<u64> = None;

    for &id in &manifest_ids {
        // Decode the generation. Undecodable / reported-absent ⇒ a torn-suffix rung; keep walking down.
        let vm = match admin.read_manifest(Some(id)).await {
            Ok(Some(vm)) => vm,
            Ok(None) | Err(_) => {
                ladder.push(ManifestCandidate {
                    generation: id,
                    frontier: None,
                    status: "undecodable (torn/empty manifest)".to_string(),
                });
                continue;
            }
        };
        let frontier = vm.replay_after_wal_id();
        examined_decodable += 1;
        newest_decodable.get_or_insert(id);

        // MF2 (a) — never adopt a generation below the manifest GC boundary. A lower candidate is even
        // further below, so this is terminal for the walk (fail loud).
        if id < boundary {
            return Err(WalRepairError::BelowGcBoundary {
                root: root.to_string(),
                generation: id,
                boundary,
            });
        }
        // MF2 (b) — the WAL replay range (F, …] must have NO leading/interior GC hole. A lower
        // candidate's range is a superset, so a hole here is a hole for every lower candidate too —
        // fail loud (continuing cannot reach a safe lower generation).
        check_manifest_rollback_wal_contiguity(&wal_ids, frontier, root)?;

        // Openability: the first decodable generation that is structurally serve-able is adopted.
        // (Mutation seam: `stop_at_first_decodable()` → treat the first decodable generation as openable,
        // reproducing the v0.11.0 bug for the mutation-verified gate.)
        let openability = if stop_at_first_decodable() {
            None
        } else {
            generation_structurally_openable(store, root, &vm, &compacted).await?
        };
        match openability {
            None => {
                ladder.push(ManifestCandidate {
                    generation: id,
                    frontier: Some(frontier),
                    status: "adopted (opens clean)".to_string(),
                });
                let quarantine_ids: Vec<u64> =
                    manifest_ids.iter().copied().filter(|&m| m > id).collect();
                return Ok(GenerationWalkPlan {
                    adopted_generation: id,
                    adopted_frontier: frontier,
                    quarantine_ids,
                    candidate_ladder: ladder,
                });
            }
            Some(reason) => {
                ladder.push(ManifestCandidate {
                    generation: id,
                    frontier: Some(frontier),
                    status: format!("skipped: {reason}"),
                });
                // Decodes but won't open — keep walking down to an older, serve-able generation.
            }
        }
    }

    // No generation opened clean.
    if examined_decodable == 0 {
        Err(WalRepairError::NoDecodableManifest {
            root: root.to_string(),
            listed: manifest_ids.len(),
        })
    } else {
        Err(WalRepairError::NoOpenableManifest {
            root: root.to_string(),
            examined: examined_decodable,
            newest_generation: newest_decodable.expect("examined_decodable > 0 implies a newest"),
        })
    }
}

/// **F2 / v0.11.1 — last-good-generation cold-open recovery (adopt the newest generation that OPENS
/// CLEAN).** When the LATEST manifest is empty/torn/absent OR decodes-but-won't-open (the invalid-
/// compaction / missing-referenced-SST shape), walk the manifest generations highest → lowest and adopt
/// the newest that OPENS CLEAN — decodes AND is serve-able (every referenced SST present/intact) — then
/// quarantine the suffix above it (torn AND decodable-but-unopenable generations) so it becomes the
/// latest, run the WAL-tail self-heal at its frontier F, and (on Apply) a real open **+ full scan**
/// verify ([`verify_opens`]) with a FRESH handle. Returns [`ManifestRecovery::LatestReadable`] (no-op)
/// when the latest manifest both decodes AND is serve-able — so the caller falls through to the ordinary
/// [`repair_wal_tail`] WAL-tail path.
///
/// ## v0.11.0 → v0.11.1: OPEN-ability, not decode-ability
/// v0.11.0 adopted the newest generation that merely DECODED. A generation can decode yet fail
/// `Db::open` — the production store rolled back to a generation that then died with `Invalid error:
/// invalid compaction` (an earlier mid-compaction unclean exit left the manifest referencing a removed
/// compacted SST), and `kv recover` reported "should open normally" because it decoded. The health
/// criterion is now OPEN-ability: the shape-gate and the walk use [`generation_structurally_openable`]
/// (dry-run) / [`verify_opens`] (apply, a real open + full scan) so a decodes-but-won't-open generation
/// is SKIPPED, never adopted. If NO decodable generation opens clean, recovery fails loud with
/// [`WalRepairError::NoOpenableManifest`] (pointing to a snapshot / backup; the heavier LSM-rebuild-from-
/// WAL fallback is deferred) — NEVER adopt an unopenable generation.
///
/// ## Control flow
/// Shape-gate: the latest decodes AND is structurally serve-able ⇒ `LatestReadable`. Otherwise plan the
/// walk ([`plan_generation_walk`], non-mutating: fail loud [`NoDecodableManifest`] / [`NoOpenableManifest`]
/// / MF2 [`BelowGcBoundary`] / [`ManifestRollbackGcHole`]). DryRun returns the plan (mutating nothing).
/// Apply quarantines the suffix above the adopted generation OUTSIDE `manifest/` (copy → record →
/// delete) → asserts none remain → WAL-tail self-heal at F + fresh-handle `verify_opens`. A refusal at
/// ANY step fails loud (mutating nothing beyond a crash-safe quarantine), never a lossy WAL-from-0.
///
/// `orphaned_nonacked_objects` is a best-effort informational field: after G becomes the latest, the L0
/// SST(s) that only a discarded generation referenced are unreferenced. Identifying them precisely needs
/// G's SST list mapped to object paths; slatedb's reopened store GC reclaims them regardless, so this is
/// left empty (documented) rather than risk mislabelling a live SST as orphaned. Space reclamation,
/// never loss.
pub async fn recover_last_good_manifest(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    mode: RepairMode,
) -> Result<ManifestRecovery, WalRepairError> {
    // 0. Shape gate (v0.11.1): the latest manifest is "healthy" only if it DECODES *and* OPENS CLEAN.
    //    A decodes-but-won't-open latest (invalid compaction / missing-referenced-SST) must NOT
    //    short-circuit to `LatestReadable` — it falls through to the generation walk below.
    let admin = Admin::builder(root.to_string(), store.clone()).build();
    if let Ok(Some(latest_vm)) = admin.read_manifest(None).await {
        // The latest decodes. Is it structurally serve-able (every referenced SST present/intact)?
        let compacted = list_compacted_sizes(store, root).await?;
        if generation_structurally_openable(store, root, &latest_vm, &compacted)
            .await?
            .is_none()
        {
            // Decodes AND opens clean ⇒ NOT the manifest/invalid-compaction shape. Any open failure the
            // caller saw is a WAL-tail (or out-of-scope torn) issue — defer to the WAL-tail path.
            return Ok(ManifestRecovery::LatestReadable {
                frontier: latest_vm.replay_after_wal_id(),
            });
        }
        // Decodes but references a removed/torn SST — fall through to the walk (the invalid-compaction
        // shape v0.11.0 missed). (We don't early-return `RolledBack` here: the walk re-derives the plan
        // uniformly whether the latest is torn-unreadable OR decodable-but-unopenable.)
    }

    // 1+2. Plan the generation walk (non-mutating): the newest generation that OPENS CLEAN, with MF2
    //       re-checked at each candidate's frontier. Fails loud rather than adopt an unopenable one.
    let plan = plan_generation_walk(store, root).await?;
    let GenerationWalkPlan {
        adopted_generation: generation,
        adopted_frontier: frontier,
        quarantine_ids: torn_suffix,
        candidate_ladder,
    } = plan;

    // Informational only (UX C11 / MF6): reclaimable orphans, never loss. Left empty (see the doc).
    let orphaned_nonacked_objects: Vec<String> = Vec::new();

    match mode {
        RepairMode::DryRun => {
            // Compute the WAL-tail plan at F WITHOUT reading the (still-torn) latest manifest, and
            // mutate NOTHING (the quarantine suffix is retained).
            let wal_repair =
                repair_wal_tail_at_frontier(store, root, frontier, RepairMode::DryRun).await?;
            let manifest_quarantine_dir = (!torn_suffix.is_empty())
                .then(|| format!("{root}/manifest-quarantine/<stamp>/ (dry-run: not created)"));
            Ok(ManifestRecovery::RolledBack(Box::new(
                ManifestRecoveryReport {
                    rolled_back_to_generation: generation,
                    frontier,
                    quarantined_manifest_ids: torn_suffix,
                    manifest_quarantine_dir,
                    wal_repair,
                    orphaned_nonacked_objects,
                    candidate_ladder,
                    applied: false,
                },
            )))
        }
        RepairMode::Apply => {
            // (a) quarantine the suffix above the adopted generation so it becomes the latest
            //     (copy → record → delete). The suffix includes torn generations AND the decodable-but-
            //     unopenable generations the walk skipped.
            let manifest_quarantine_dir = if torn_suffix.is_empty() {
                None
            } else {
                let stamp = quarantine_stamp();
                quarantine_manifest_suffix(store, root, generation, &torn_suffix, &stamp).await?;
                Some(format!("{root}/manifest-quarantine/{stamp}"))
            };
            // (b) ASSERT no manifest > G remains before verify (Arch C2 / MF4).
            assert_no_torn_manifest_remains(store, root, generation).await?;
            // (c) WAL-tail self-heal at F over the now-G-latest store: quarantine a torn WAL tail
            //     beyond F (if any), then `verify_opens` (real open + full scan, the APPLY authority)
            //     with a FRESH slatedb handle (Arch C6). If the adopted generation still fails the real
            //     open+scan (a failure mode the structural predictor could not see), this fails loud —
            //     never a false success.
            let wal_repair =
                repair_wal_tail_at_frontier(store, root, frontier, RepairMode::Apply).await?;
            Ok(ManifestRecovery::RolledBack(Box::new(
                ManifestRecoveryReport {
                    rolled_back_to_generation: generation,
                    frontier,
                    quarantined_manifest_ids: torn_suffix,
                    manifest_quarantine_dir,
                    wal_repair,
                    orphaned_nonacked_objects,
                    candidate_ladder,
                    applied: true,
                },
            )))
        }
    }
}

// ===================================================================================================
// v0.11.1 — corrupt-`.compactions` reset recovery.
//
// The production `Invalid error: invalid compaction` at `Db::open` is NOT a manifest/SST problem: the
// manifest decodes and its referenced SSTs are present (so [`recover_last_good_manifest`] returns
// `LatestReadable`). It is a corrupt slatedb `.compactions` object — the compactor-bookkeeping sequence
// at `{root}/compactions/{:020}.compactions` (pending/in-progress/recent compactions + the compactor
// epoch), decoded ONLY on a compactor-ON open (`CompactorStateWriter::new` → `StoredCompactions::try_load`
// → `decode_compactions`, which raises `InvalidCompaction`). This bookkeeping holds NO acked-data
// liveness — the durable authority is the manifest + WAL + SST files, and slatedb's GC derives the live
// set from the MANIFEST only, never `.compactions`. So resetting `.compactions` cannot lose committed
// data: a compactor-ON open with `.compactions` ABSENT fresh-starts ("creating new compactions file
// [compactor_epoch=0]"), re-epochs to the manifest's epoch, and re-plans compactions from the manifest's
// current SST set (manifest-first writes + additive outputs; GC reclaims any orphan output SSTs). It is
// INDEPENDENT of the manifest generation, so no manifest-generation rollback can fix it.
//
// Non-obvious: the compactions GC boundary at `{root}/gc/compactions.boundary` (an ASCII u64, distinct
// from `{root}/gc/manifest.boundary`) must ALSO be removed. slatedb's sequenced-object CAS rejects any
// id `<= boundary` with `ObjectVersionExists` (slatedb-txn-obj `check_boundary`); after we delete all
// `.compactions` versions the compactor-ON reopen creates a FRESH id-1 object, which a stale boundary
// `>= 1` would reject — so the reset would silently fail at reopen. Removing the boundary floors it to 0
// (a missing boundary reads as 0), so the fresh create succeeds. It does NOT touch `manifest.boundary`.
// ===================================================================================================

/// The outcome of a corrupt-`.compactions` reset attempt.
#[derive(Debug, Clone)]
pub enum CompactionsRecovery {
    /// The `.compactions` bookkeeping is NOT corrupt (it decodes, or is absent) — NOTHING to do. The
    /// caller proceeds with its normal open / other recovery paths.
    NotCorrupt,
    /// The `.compactions` object was corrupt; the reset quarantined + removed it (+ the GC boundary) on
    /// [`RepairMode::Apply`], or computed the plan it WOULD apply on [`RepairMode::DryRun`].
    Reset(CompactionsResetReport),
}

/// The plan/outcome of a corrupt-`.compactions` reset (v0.11.1).
#[derive(Debug, Clone)]
pub struct CompactionsResetReport {
    /// The `{root}/compactions/{:020}.compactions` ids that were (or, in dry-run, would be) quarantined
    /// and removed so a compactor-ON reopen fresh-starts the compactor bookkeeping.
    pub quarantined_compactions_ids: Vec<u64>,
    /// The `{root}/compactions-quarantine/{stamp}/` dir the objects were (or would be) copied to.
    pub quarantine_dir: Option<String>,
    /// Whether the compactions GC boundary (`{root}/gc/compactions.boundary`) was present and removed
    /// (or, in dry-run, would be) — required so the fresh id-1 create is not rejected.
    pub boundary_removed: bool,
    /// Whether the pass mutated the store (`false` for a dry-run).
    pub applied: bool,
}

/// Mutation seam (CI host-lane, test-only): when `BOATRAMP_KVMANIFEST_MUTATION=skip_compactions_reset`
/// the reset does NOT quarantine/remove the corrupt `.compactions` object(s) — modeling "the reset was
/// not applied". The post-reset verify then still sees the corrupt object → fails loud → the gate goes
/// RED. Non-test builds compile to `false`.
#[cfg(test)]
fn skip_compactions_reset() -> bool {
    std::env::var("BOATRAMP_KVMANIFEST_MUTATION")
        .map(|v| v == "skip_compactions_reset")
        .unwrap_or(false)
}
#[cfg(not(test))]
#[inline]
fn skip_compactions_reset() -> bool {
    false
}

/// Mutation seam (CI host-lane, test-only): when `BOATRAMP_KVMANIFEST_MUTATION=keep_compactions_boundary`
/// the reset quarantines/removes the `.compactions` object(s) but LEAVES the compactions GC boundary in
/// place — modeling the non-obvious bug where a stale boundary rejects the fresh id-1 create. The
/// post-reset verify then sees the boundary still present → fails loud → the gate goes RED. Non-test
/// builds compile to `false`.
#[cfg(test)]
fn keep_compactions_boundary() -> bool {
    std::env::var("BOATRAMP_KVMANIFEST_MUTATION")
        .map(|v| v == "keep_compactions_boundary")
        .unwrap_or(false)
}
#[cfg(not(test))]
#[inline]
fn keep_compactions_boundary() -> bool {
    false
}

/// The `{root}/compactions/{:020}.compactions` object path for id (slatedb-txn-obj layout:
/// subdir `compactions`, suffix `compactions`).
fn compactions_object_path(root: &str, id: u64) -> ObjPath {
    ObjPath::from(format!("{root}/compactions/{id:020}.compactions"))
}

/// Parse a `{:020}.compactions` filename into its numeric id.
fn parse_compactions_id(location: &ObjPath) -> Option<u64> {
    location
        .filename()?
        .strip_suffix(".compactions")?
        .parse::<u64>()
        .ok()
}

/// The compactions GC boundary object path (`{root}/gc/compactions.boundary`) — DISTINCT from
/// `{root}/gc/manifest.boundary`. A missing boundary reads as 0 (slatedb-txn-obj default).
fn compactions_gc_boundary_path(root: &str) -> ObjPath {
    ObjPath::from(format!("{root}/gc/compactions.boundary"))
}

/// List every `{root}/compactions/{:020}.compactions` id present on the store, ascending.
async fn list_compactions_ids(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<Vec<u64>, WalRepairError> {
    use futures::StreamExt;
    let prefix = ObjPath::from(format!("{root}/compactions"));
    let mut stream = store.list(Some(&prefix));
    let mut ids = Vec::new();
    while let Some(item) = stream.next().await {
        let meta = item.map_err(|e| WalRepairError::Store(e.to_string()))?;
        if let Some(id) = parse_compactions_id(&meta.location) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Whether a `slatedb::Error` Display from [`Admin::read_compactions`] is a DECODE failure of the
/// `.compactions` object — the corrupt-bookkeeping signature we reset — as opposed to a transient
/// object-store error (which must NOT trigger a destructive reset). Matches the `decode_compactions`
/// errors: `InvalidCompaction` (`"Invalid error: invalid compaction"`) and the compactions
/// `InvalidVersion` (`"unsupported compactions format version…"`).
fn compactions_decode_error_is_corrupt(raw: &str) -> bool {
    raw.contains("invalid compaction")
        || raw.contains("InvalidCompaction")
        || (raw.contains("unsupported") && raw.contains("compactions") && raw.contains("version"))
}

/// Probe whether the store's `.compactions` bookkeeping is CORRUPT — the compactor-ON open failure
/// `Invalid error: invalid compaction` — WITHOUT a compactor-ON `Db` open (no lifecycle to drain, no
/// close-drain stall). Uses [`Admin::read_compactions`] (decodes the latest `.compactions` object):
/// `Err` with a decode signature ([`compactions_decode_error_is_corrupt`]) ⇒ corrupt; `Ok(_)` (decodes,
/// or absent) ⇒ not corrupt; a non-decode `Err` (a transient store error) ⇒ NOT corrupt (conservative —
/// never reset on a transient error). This reflects compactor-ON semantics: it decodes exactly the object
/// the compactor's `StoredCompactions::try_load` decodes at build.
async fn detect_corrupt_compactions(
    store: &Arc<dyn ObjectStore>,
    root: &str,
) -> Result<bool, WalRepairError> {
    let admin = Admin::builder(root.to_string(), store.clone()).build();
    match admin.read_compactions(None).await {
        Ok(_) => Ok(false),
        Err(e) => Ok(compactions_decode_error_is_corrupt(&e.to_string())),
    }
}

/// Build the `compactions-quarantine/{stamp}/MANIFEST.json` record body (the quarantined ids + whether
/// the boundary was removed). No secrets — only ids + the stamp.
fn build_compactions_quarantine_record(ids: &[u64], boundary_removed: bool, stamp: &str) -> String {
    let objects: Vec<String> = ids
        .iter()
        .map(|&id| format!("    {{ \"id\": {id}, \"file\": \"{id:020}.compactions\" }}"))
        .collect();
    format!(
        "{{\n  \"reason\": \"corrupt slatedb .compactions bookkeeping object (decode failed with \
         InvalidCompaction on a compactor-ON open); reset by boatramp v0.11.1 compactions-reset \
         recovery. .compactions holds no acked-data liveness, so this is lossless-for-acked.\",\n  \
         \"stamp\": \"{stamp}\",\n  \"compactions_gc_boundary_removed\": {boundary_removed},\n  \
         \"quarantined_compactions\": [\n{}\n  ]\n}}\n",
        objects.join(",\n"),
    )
}

/// **v0.11.1 — corrupt-`.compactions` reset recovery.** When the manifest + SSTs are intact but a
/// compactor-ON open fails `InvalidCompaction`, the `.compactions` bookkeeping is corrupt. Reset it:
/// quarantine (copy → record → delete) every `{root}/compactions/{:020}.compactions`, remove the
/// compactions GC boundary (`{root}/gc/compactions.boundary`), then VERIFY compactor-state cleanliness
/// WITHOUT a compactor-ON `Db` open (no close-drain stall): `Admin::read_compactions(None)` must come
/// back clean (`Ok(None)` — the corrupt object is gone, so a compactor-ON open fresh-starts) AND the
/// boundary must be gone (else the fresh id-1 create is rejected). Returns [`CompactionsRecovery::NotCorrupt`]
/// (no-op) when `.compactions` is fine — so the caller proceeds normally.
///
/// - [`RepairMode::DryRun`] computes the plan and mutates NOTHING.
/// - [`RepairMode::Apply`] performs the reset + verify. Fails loud ([`WalRepairError::CompactionsResetVerifyFailed`])
///   if the post-reset verify is not clean — never a false success.
///
/// SelfHeal-only; the caller (strict / cluster node-local) must gate this to fail loud with zero mutation.
/// Lossless-for-acked: `.compactions` holds only compactor bookkeeping (verified against slatedb 0.16.0).
pub async fn recover_corrupt_compactions(
    store: &Arc<dyn ObjectStore>,
    root: &str,
    mode: RepairMode,
) -> Result<CompactionsRecovery, WalRepairError> {
    // Detection: compactor-state decode, no compactor lifecycle. Not corrupt ⇒ nothing to do.
    if !detect_corrupt_compactions(store, root).await? {
        return Ok(CompactionsRecovery::NotCorrupt);
    }

    let ids = list_compactions_ids(store, root).await?;
    let boundary_present = store
        .head(&compactions_gc_boundary_path(root))
        .await
        .is_ok();

    if mode == RepairMode::DryRun {
        return Ok(CompactionsRecovery::Reset(CompactionsResetReport {
            quarantined_compactions_ids: ids,
            quarantine_dir: Some(format!(
                "{root}/compactions-quarantine/<stamp>/ (dry-run: not created)"
            )),
            boundary_removed: boundary_present,
            applied: false,
        }));
    }

    // Apply. The `skip_compactions_reset` mutation models "reset not applied" (quarantine nothing);
    // the `keep_compactions_boundary` mutation models leaving the stale boundary in place. Each makes
    // the verify below fail loud → the gate goes RED.
    let stamp = quarantine_stamp();
    let mut quarantine_dir = None;
    let mut boundary_removed = false;
    if !skip_compactions_reset() {
        // Copy each `.compactions` object to the quarantine dir (bytes safe), THEN delete the original.
        for &id in &ids {
            let src = compactions_object_path(root, id);
            let dst = ObjPath::from(format!(
                "{root}/compactions-quarantine/{stamp}/{id:020}.compactions"
            ));
            store
                .copy(&src, &dst)
                .await
                .map_err(|e| WalRepairError::Store(e.to_string()))?;
        }
        // Record BEFORE the deletes are observed complete (a reader always finds the record for a copy).
        let boundary_will_remove = boundary_present && !keep_compactions_boundary();
        let record = build_compactions_quarantine_record(&ids, boundary_will_remove, &stamp);
        let record_path = ObjPath::from(format!(
            "{root}/compactions-quarantine/{stamp}/MANIFEST.json"
        ));
        store
            .put(&record_path, record.into_bytes().into())
            .await
            .map_err(|e| WalRepairError::Store(e.to_string()))?;
        // Delete the originals (copies + record are durable).
        for &id in &ids {
            store
                .delete(&compactions_object_path(root, id))
                .await
                .map_err(|e| WalRepairError::Store(e.to_string()))?;
        }
        quarantine_dir = Some(format!("{root}/compactions-quarantine/{stamp}"));
        // Remove the compactions GC boundary so the fresh id-1 create is not rejected (non-obvious;
        // see the module note). NotFound is fine (absent boundary already reads as 0).
        if !keep_compactions_boundary() {
            match store.delete(&compactions_gc_boundary_path(root)).await {
                Ok(()) => boundary_removed = true,
                Err(object_store::Error::NotFound { .. }) => boundary_removed = false,
                Err(e) => return Err(WalRepairError::Store(e.to_string())),
            }
        }
    }

    // VERIFY (compactor-state, stall-free, compactor-ON-faithful):
    //  (1) `read_compactions(None)` must be clean — `Ok(None)` after a full reset (the corrupt object is
    //      gone, so a compactor-ON `StoredCompactions::try_load` sees None → fresh-start). A still-corrupt
    //      object decodes `InvalidCompaction` here → fail loud.
    //  (2) the compactions GC boundary must be gone — else the compactor-ON reopen's fresh id-1 create is
    //      rejected `ObjectVersionExists`.
    match detect_corrupt_compactions(store, root).await {
        Ok(false) => {}
        Ok(true) => {
            return Err(WalRepairError::CompactionsResetVerifyFailed {
                root: root.to_string(),
                detail:
                    "a corrupt `.compactions` object still decodes with InvalidCompaction after \
                         the reset (the quarantine did not remove it)"
                        .to_string(),
            });
        }
        Err(e) => return Err(e),
    }
    if store
        .head(&compactions_gc_boundary_path(root))
        .await
        .is_ok()
    {
        return Err(WalRepairError::CompactionsResetVerifyFailed {
            root: root.to_string(),
            detail: "the compactions GC boundary `gc/compactions.boundary` is still present — a \
                     compactor-ON reopen's fresh id-1 `.compactions` create would be rejected \
                     (ObjectVersionExists)"
                .to_string(),
        });
    }

    Ok(CompactionsRecovery::Reset(CompactionsResetReport {
        quarantined_compactions_ids: ids,
        quarantine_dir,
        boundary_removed,
        applied: true,
    }))
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

    /// **F2a — isolate MF2's UNIQUE contribution.** The SAME shape — frontier F=5, the only object
    /// beyond F a NON-readable (Torn) one at id 8, with 6,7 ABSENT — is MISSED by
    /// [`check_survivor_contiguity`] (it keys on the highest READABLE survivor; there is none, so it
    /// returns Ok — the whole-tail-gone blind spot) but CAUGHT by
    /// [`check_manifest_rollback_wal_contiguity`] (it keys on ALL present ids). Proves MF2 is the SOLE
    /// guard for a leading GC hole whose only anchor above it is non-readable — exactly the shape a
    /// torn-generation GC pass leaves for a manifest rollback.
    #[test]
    fn mf2_catches_a_hole_under_a_non_readable_anchor_that_survivor_contiguity_misses() {
        // check_survivor_contiguity: no readable survivor above the hole ⇒ Ok (misses it).
        let candidates = vec![WalCandidate {
            id: 8,
            size: 64,
            class: WalClass::Torn,
        }];
        assert!(
            check_survivor_contiguity(&candidates, &[], 5, "kv").is_ok(),
            "check_survivor_contiguity misses a hole whose only anchor above it is non-readable \
             (no readable survivor ⇒ whole-tail-gone branch ⇒ Ok) — the blind spot MF2 covers"
        );
        // check_manifest_rollback_wal_contiguity: all present ids ⇒ 6 absent below the surviving 8 ⇒ hole.
        let wal: std::collections::BTreeSet<u64> = [8u64].into_iter().collect();
        let err = check_manifest_rollback_wal_contiguity(&wal, 5, "kv").unwrap_err();
        assert!(
            matches!(
                err,
                WalRepairError::ManifestRollbackGcHole {
                    missing_wal_id: 6,
                    highest_wal_id: 8,
                    ..
                }
            ),
            "MF2 must catch the leading hole under a non-readable anchor, got {err:?}"
        );
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

    /// **F2a (e2e, MF2 isolated)** — a WAL GC hole whose ONLY anchor above it is a NON-readable (torn)
    /// WAL object. The WAL-tail self-heal's `check_survivor_contiguity` would MISS it (no readable
    /// survivor ⇒ whole-tail-gone ⇒ Ok, and `plan_trailing_tail` would just quarantine the torn tail —
    /// silently lossy), so ONLY `check_manifest_rollback_wal_contiguity` catches it ⇒
    /// `ManifestRollbackGcHole`. This isolates MF2's unique contribution end-to-end.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_refuses_a_gc_hole_under_a_torn_anchor_mf2_isolated() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await;
        let good = highest_manifest_id(&store, root).await;
        let frontier = read_frontier(&store, root).await.unwrap();
        inject_torn_manifest(&store, root, good + 1).await;
        // A TORN (non-readable) WAL object above the frontier, with the F+1 slot ABSENT: no readable
        // survivor sits above the hole, so only the all-ids MF2 guard can catch it.
        put_wal(&store, root, frontier + 3, footer_object(64, 0)).await; // version 0 ⇒ Torn
        store
            .delete(&wal_object_path(root, frontier + 1))
            .await
            .ok();
        let err = recover_last_good_manifest(&store, root, RepairMode::DryRun)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WalRepairError::ManifestRollbackGcHole { .. }),
            "MF2 must catch a leading GC hole under a non-readable anchor (survivor-contiguity misses \
             it), got {err:?}"
        );
    }

    /// **F2b — direct lossless POST-G WAL-replay gate.** An acked write in the replay range `(F, highest]`
    /// that was NOT frozen into G's L0 (it lives only in a WAL object beyond G's frontier) is REPLAYED
    /// and recovered byte-equal by the rollback. Distinct from the L0-under-G survival gate: here a
    /// base key is checkpointed into G's L0 (advancing the frontier to F), then the crown-jewel is an
    /// acked WAL-only write at an id > F — so its recovery proves the rollback's WAL replay, not the
    /// pre-G L0 state.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_replays_an_acked_wal_write_beyond_g_frontier_byte_equal() {
        use slatedb::config::{FlushOptions, FlushType};
        let store = mem_store();
        let root = "kv";
        // Seed: a base key checkpointed into L0 (advancing the durable frontier to F), then the
        // crown-jewel as an acked WAL-only write BEYOND F (durable in WAL, NOT frozen to L0).
        {
            #[allow(clippy::field_reassign_with_default)]
            let settings = {
                let mut s = Settings::default();
                s.flush_interval = Some(Duration::from_millis(5));
                s.compactor_options = None;
                s.garbage_collector_options = None;
                s
            };
            let db = Db::builder(root.to_string(), store.clone())
                .with_settings(settings)
                .build()
                .await
                .unwrap();
            db.put(b"project/acme", b"base")
                .await
                .unwrap()
                .await_durable()
                .await
                .unwrap();
            // Checkpoint: freeze `base` → L0, advance the durable frontier to F (G's frontier).
            db.flush_with_options(FlushOptions {
                flush_type: FlushType::MemTable,
            })
            .await
            .unwrap();
            // The crown-jewel: an acked WAL write BEYOND F, NOT checkpointed (lives only in the WAL).
            db.put(b"secret/acme/idp", b"sealed-wal-only")
                .await
                .unwrap()
                .await_durable()
                .await
                .unwrap();
            drop(db); // a hard crash, NOT a clean close — the crown-jewel stays in the WAL beyond F
        }
        let good = highest_manifest_id(&store, root).await;
        let frontier = read_frontier(&store, root).await.unwrap();
        inject_torn_manifest(&store, root, good + 1).await;

        // Recover: roll back to G (frontier F) and replay the WAL forward.
        let report = match recover_last_good_manifest(&store, root, RepairMode::Apply)
            .await
            .unwrap()
        {
            ManifestRecovery::RolledBack(r) => r,
            other => panic!("expected RolledBack, got {other:?}"),
        };
        assert_eq!(report.rolled_back_to_generation, good);
        assert_eq!(report.frontier, frontier);
        // The base key (in G's L0) AND the crown-jewel (WAL-only, beyond F) both survive byte-equal —
        // the crown-jewel's survival proves the rollback REPLAYED the WAL range (F, highest], not just
        // G's L0 state.
        assert_eq!(
            read_key_via_fresh_db(&store, root, b"project/acme").await,
            Some(b"base".to_vec()),
            "the checkpointed base key (G's L0) survives"
        );
        assert_eq!(
            read_key_via_fresh_db(&store, root, b"secret/acme/idp").await,
            Some(b"sealed-wal-only".to_vec()),
            "F2b: an acked WAL write BEYOND G's frontier MUST be replayed + recovered byte-equal"
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

    // ===================================================================================
    // v0.11.1 — the INVALID-COMPACTION walk: adopt the newest generation that OPENS CLEAN,
    // not merely one that DECODES. Over a shared `InMemory` store (deterministic, non-stalling).
    // ===================================================================================

    /// Seed the invalid-compaction fixture: a crown-jewel write checkpointed into L0 under an OLDER
    /// generation (the one that must be adopted), then a JUNK write checkpointed into a SECOND L0 SST
    /// under the LATEST generation — then DELETE that second L0 SST. The latest generation now DECODES
    /// but references a REMOVED compacted SST (the production `invalid compaction` / mid-compaction
    /// unclean-exit shape), while the older crown generation references only the surviving crown SST.
    ///
    /// Returns `(highest_decodable_gen, deleted_junk_sst_filename)`. Compactor + GC OFF so no real
    /// compaction runs and no WAL is GC'd (the junk WAL survives, so the rollback replays it losslessly).
    async fn seed_invalid_compaction_fixture(
        store: &Arc<dyn ObjectStore>,
        root: &str,
    ) -> (u64, String) {
        use slatedb::config::{FlushOptions, FlushType};
        #[allow(clippy::field_reassign_with_default)]
        let settings = {
            let mut s = Settings::default();
            s.flush_interval = Some(Duration::from_millis(5));
            s.compactor_options = None;
            s.garbage_collector_options = None;
            s
        };
        let db = Db::builder(root.to_string(), store.clone())
            .with_settings(settings)
            .build()
            .await
            .unwrap();
        // Crown jewel → L0 #1 (the crown generation).
        db.put(b"secret/acme/idp", b"sealed-crown-jewel")
            .await
            .unwrap()
            .await_durable()
            .await
            .unwrap();
        db.flush_with_options(FlushOptions {
            flush_type: FlushType::MemTable,
        })
        .await
        .unwrap();
        let s1: std::collections::BTreeSet<String> = list_compacted_sizes(store, root)
            .await
            .unwrap()
            .into_keys()
            .collect();
        // Junk → L0 #2 (the latest generation references BOTH L0 SSTs).
        db.put(b"zzz/junk", b"junk-value")
            .await
            .unwrap()
            .await_durable()
            .await
            .unwrap();
        db.flush_with_options(FlushOptions {
            flush_type: FlushType::MemTable,
        })
        .await
        .unwrap();
        db.close().await.unwrap();
        let s2: std::collections::BTreeSet<String> = list_compacted_sizes(store, root)
            .await
            .unwrap()
            .into_keys()
            .collect();
        // The SECOND-flush L0 SST = exactly the one present now but not after the first flush.
        let junk: Vec<String> = s2.difference(&s1).cloned().collect();
        assert_eq!(
            junk.len(),
            1,
            "fixture must add exactly one L0 SST on the second flush: s1={s1:?} s2={s2:?}"
        );
        let junk_sst = junk.into_iter().next().unwrap();
        // DELETE it → the latest generation now references a REMOVED compacted SST (invalid compaction).
        store
            .delete(&ObjPath::from(format!("{root}/compacted/{junk_sst}")))
            .await
            .unwrap();
        let highest = highest_manifest_id(store, root).await;
        (highest, junk_sst)
    }

    /// **v0.11.1 GATE (mutation-verified) — adopt the newest generation that OPENS CLEAN.** The latest
    /// manifest DECODES but references a REMOVED compacted SST (invalid compaction). DRY-RUN classifies
    /// it RECOVERABLE and plans the walk; APPLY adopts an OLDER generation that opens clean and the
    /// crown-jewel survives byte-equal (reopen via a FRESH Db).
    ///
    /// MUTATION `stop_at_first_decodable()` (the v0.11.0 behavior — adopt the newest DECODABLE
    /// generation, skipping the openability check): the adopted latest generation references the removed
    /// SST, so the real open + full-scan verify ([`verify_opens`]) FAILS → `recover_last_good_manifest`
    /// returns `Err` → the `.unwrap()` below panics → RED. The fix (adopt the newest that OPENS CLEAN)
    /// walks past the unopenable generation(s) to the crown generation → GREEN.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_adopts_newest_openable_generation_and_crown_jewel_survives() {
        let store = mem_store();
        let root = "kv";
        let (highest_decodable, junk_sst) = seed_invalid_compaction_fixture(&store, root).await;

        // The latest manifest DECODES (so v0.11.0 reported "should open normally")...
        assert!(
            read_frontier(&store, root).await.is_ok(),
            "the latest manifest must DECODE (the invalid-compaction trigger: decodes but won't open)"
        );

        // DRY-RUN: classifies RECOVERABLE, plans the walk to an OLDER generation, mutates NOTHING.
        let dry = match recover_last_good_manifest(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
        {
            ManifestRecovery::RolledBack(r) => r,
            other => panic!("a decodes-but-won't-open latest must be RolledBack, got {other:?}"),
        };
        assert!(!dry.applied, "dry-run must not mutate");
        assert!(
            dry.rolled_back_to_generation < highest_decodable,
            "the walk must adopt an OLDER generation ({}) than the highest decodable latest ({highest_decodable})",
            dry.rolled_back_to_generation
        );
        assert!(
            dry.candidate_ladder
                .iter()
                .any(|c| c.status.starts_with("skipped:") && c.status.contains(&junk_sst)),
            "the ladder must SKIP the decodes-but-won't-open latest naming the removed SST: {:?}",
            dry.candidate_ladder
        );
        assert!(
            dry.candidate_ladder
                .iter()
                .any(|c| c.generation == dry.rolled_back_to_generation
                    && c.status == "adopted (opens clean)"),
            "the ladder must mark the adopted generation: {:?}",
            dry.candidate_ladder
        );
        // Dry-run mutated nothing: the decodable-but-unopenable latest manifest is still present.
        assert!(
            store
                .head(&manifest_object_path(root, highest_decodable))
                .await
                .is_ok(),
            "dry-run must retain the latest (unopenable) manifest generation"
        );

        // APPLY: adopts the older openable generation; `verify_opens` (open + full scan) proves it serves.
        let report = match recover_last_good_manifest(&store, root, RepairMode::Apply)
            .await
            .unwrap()
        {
            ManifestRecovery::RolledBack(r) => r,
            other => panic!("expected RolledBack, got {other:?}"),
        };
        assert!(report.applied);
        assert!(
            report.rolled_back_to_generation < highest_decodable,
            "APPLY must adopt an OLDER openable generation"
        );
        assert_eq!(
            report.rolled_back_to_generation, dry.rolled_back_to_generation,
            "APPLY must adopt the SAME generation the dry-run predicted"
        );

        // The recovered store OPENS and the crown-jewel survives BYTE-EQUAL (anti-hollow: a rollback to
        // the wrong generation, or adopting the unopenable latest, would miss the key or fail to open).
        assert_eq!(
            read_key_via_fresh_db(&store, root, b"secret/acme/idp").await,
            Some(b"sealed-crown-jewel".to_vec()),
            "the acked crown-jewel MUST survive the invalid-compaction generation walk byte-equal"
        );
        // Lossless: the junk write (checkpointed into the DELETED SST) is recovered from the surviving
        // WAL by the lower-frontier replay — nothing acked is dropped.
        assert_eq!(
            read_key_via_fresh_db(&store, root, b"zzz/junk").await,
            Some(b"junk-value".to_vec()),
            "the acked junk write MUST be replayed from the WAL (lossless-for-acked rollback)"
        );
    }

    /// **v0.11.1** — the non-mutating structural openability predictor flags a REMOVED and a TORN
    /// referenced compacted SST (the dry-run authority), and passes a clean generation. Mutation-free
    /// unit coverage of the predictor the walk and shape-gate rely on.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn generation_structurally_openable_flags_missing_and_torn_referenced_sst() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await; // crown in L0, clean
        let admin = Admin::builder(root.to_string(), store.clone()).build();
        let vm = admin.read_manifest(None).await.unwrap().unwrap();

        // Clean store ⇒ predicted openable.
        let compacted = list_compacted_sizes(&store, root).await.unwrap();
        assert!(
            generation_structurally_openable(&store, root, &vm, &compacted)
                .await
                .unwrap()
                .is_none(),
            "a clean generation (all referenced SSTs present/intact) is predicted openable"
        );

        // Pick a referenced L0 SST filename from the compacted dir.
        let sst = compacted
            .keys()
            .next()
            .cloned()
            .expect("the seeded store has at least one L0 SST");

        // TORN the referenced SST (version-0 footer) ⇒ predicted UNOPENABLE naming it.
        store
            .put(
                &ObjPath::from(format!("{root}/compacted/{sst}")),
                footer_object(128, 0).into(),
            )
            .await
            .unwrap();
        let compacted_torn = list_compacted_sizes(&store, root).await.unwrap();
        let torn_reason = generation_structurally_openable(&store, root, &vm, &compacted_torn)
            .await
            .unwrap();
        assert!(
            torn_reason
                .as_deref()
                .is_some_and(|r| r.contains(&sst) && r.contains("TORN")),
            "a torn referenced SST ⇒ predicted unopenable naming it: {torn_reason:?}"
        );

        // REMOVE the referenced SST ⇒ predicted UNOPENABLE (REMOVED).
        store
            .delete(&ObjPath::from(format!("{root}/compacted/{sst}")))
            .await
            .unwrap();
        let compacted_gone = list_compacted_sizes(&store, root).await.unwrap();
        let gone_reason = generation_structurally_openable(&store, root, &vm, &compacted_gone)
            .await
            .unwrap();
        assert!(
            gone_reason
                .as_deref()
                .is_some_and(|r| r.contains(&sst) && r.contains("REMOVED")),
            "a removed referenced SST ⇒ predicted unopenable (REMOVED) naming it: {gone_reason:?}"
        );
    }

    /// **v0.11.1** — the terminal [`WalRepairError::NoOpenableManifest`] names the invalid-compaction
    /// shape and points at the snapshot/rebuild fallback (never a silent adopt-anyway). Message-shape
    /// unit test (the e2e terminal is impractical: the empty initial generation replays the whole WAL
    /// and is itself openable whenever the WAL is contiguous, so a real store rarely exhausts the walk).
    #[test]
    fn no_openable_manifest_error_names_the_invalid_compaction_shape() {
        let err = WalRepairError::NoOpenableManifest {
            root: "kv".to_string(),
            examined: 3,
            newest_generation: 2869,
        };
        let msg = format!("{err}");
        assert!(msg.contains("NONE opens clean"), "msg: {msg}");
        assert!(msg.contains("invalid compaction"), "msg: {msg}");
        assert!(
            msg.contains("2869"),
            "names the newest decodable generation: {msg}"
        );
        assert!(
            msg.contains("volume snapshot") || msg.contains("backup"),
            "points at the snapshot/backup fallback: {msg}"
        );
    }

    // ===================================================================================
    // v0.11.1 — corrupt-`.compactions` RESET (the real production invalid-compaction fix).
    // ===================================================================================

    /// Open a compactor-ON `Db` (the production profile — `Settings::default()` enables the compactor +
    /// GC, which is what decodes `.compactions` at build and creates a fresh one when absent), read
    /// `key`, close. Short flush interval; no compactor options overridden. For a small InMemory store
    /// this open+close is fast and does not stall (the close-drain stall is the on-disk/musl path).
    async fn read_key_via_compactor_on_db(
        store: &Arc<dyn ObjectStore>,
        root: &str,
        key: &[u8],
    ) -> Option<Vec<u8>> {
        #[allow(clippy::field_reassign_with_default)]
        let settings = {
            let mut s = Settings::default();
            s.flush_interval = Some(Duration::from_millis(5));
            s
        };
        let db = Db::builder(root.to_string(), store.clone())
            .with_settings(settings)
            .build()
            .await
            .expect("the reset store must open compactor-ON (fresh-start .compactions)");
        let val = db.get(key).await.unwrap().map(|b| b.to_vec());
        db.close().await.unwrap();
        val
    }

    /// Inject a CORRUPT `.compactions` object (1 byte ⇒ `decode_compactions` len<2 ⇒ `InvalidCompaction`)
    /// at id 1 plus a STALE compactions GC boundary (`>= 1`, so leaving it rejects the fresh id-1 create),
    /// over an otherwise-intact store. Returns the corrupt id.
    async fn inject_corrupt_compactions(store: &Arc<dyn ObjectStore>, root: &str) -> u64 {
        let corrupt_id = 1u64;
        store
            .put(
                &compactions_object_path(root, corrupt_id),
                bytes::Bytes::from_static(&[0x00]).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &compactions_gc_boundary_path(root),
                bytes::Bytes::from_static(b"1").into(),
            )
            .await
            .unwrap();
        corrupt_id
    }

    /// **v0.11.1 GATE (mutation-verified) — reset a corrupt `.compactions` bookkeeping object.** The
    /// manifest + SSTs are intact (so the manifest-rollback walk is a no-op / `LatestReadable`) but a
    /// compactor-ON open would fail `InvalidCompaction`. Detection fires (not misclassified as healthy),
    /// the reset quarantines `.compactions` + removes the compactions GC boundary, and a compactor-ON
    /// reopen SERVES, the crown-jewel survives byte-equal, and `.compactions` decodes again.
    ///
    /// MUTATIONS (cfg(test) env `BOATRAMP_KVMANIFEST_MUTATION`, the CI host-lane loop sets them):
    /// `skip_compactions_reset` (don't quarantine) ⇒ the post-reset verify still sees the corrupt object
    /// ⇒ `recover_corrupt_compactions(Apply)` returns `Err` ⇒ the `.unwrap()` below is RED;
    /// `keep_compactions_boundary` (quarantine the files but leave the boundary) ⇒ the verify sees the
    /// stale boundary (which would reject the fresh id-1 create) ⇒ `Err` ⇒ RED.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn recover_resets_a_corrupt_compactions_object_and_crown_jewel_survives() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await; // crown in L0; manifest + SST intact; no .compactions
        let corrupt_id = inject_corrupt_compactions(&store, root).await;

        // DETECTION: the `.compactions` is corrupt (compactor-state decode, no compactor lifecycle)...
        assert!(
            detect_corrupt_compactions(&store, root).await.unwrap(),
            "must detect the corrupt `.compactions` object"
        );
        // ...but the manifest + SSTs are intact ⇒ the manifest walk is a NO-OP (LatestReadable), NOT a
        // misclassified rollback (the whole point: this is NOT a manifest/SST shape).
        match recover_last_good_manifest(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
        {
            ManifestRecovery::LatestReadable { .. } => {}
            other => {
                panic!("a corrupt `.compactions` must NOT trigger a manifest rollback: {other:?}")
            }
        }

        // DRY-RUN: plans the reset, mutates NOTHING.
        match recover_corrupt_compactions(&store, root, RepairMode::DryRun)
            .await
            .unwrap()
        {
            CompactionsRecovery::Reset(r) => {
                assert_eq!(r.quarantined_compactions_ids, vec![corrupt_id]);
                assert!(r.boundary_removed, "the stale boundary is in the plan");
                assert!(!r.applied);
            }
            other => panic!("expected Reset, got {other:?}"),
        }
        assert!(
            store
                .head(&compactions_object_path(root, corrupt_id))
                .await
                .is_ok(),
            "dry-run must retain the corrupt `.compactions`"
        );

        // APPLY: reset + verify. (Under the mutations this `.unwrap()` is RED.)
        let report = match recover_corrupt_compactions(&store, root, RepairMode::Apply)
            .await
            .unwrap()
        {
            CompactionsRecovery::Reset(r) => r,
            other => panic!("expected Reset, got {other:?}"),
        };
        assert!(report.applied);
        assert!(report.boundary_removed);
        // The corrupt object is gone; a forensic copy survives; the boundary is gone.
        assert!(
            store
                .head(&compactions_object_path(root, corrupt_id))
                .await
                .is_err(),
            "the corrupt `.compactions` must be removed"
        );
        let qdir = report.quarantine_dir.expect("a quarantine dir");
        assert!(
            store
                .head(&ObjPath::from(format!(
                    "{qdir}/{corrupt_id:020}.compactions"
                )))
                .await
                .is_ok(),
            "the corrupt bytes must be preserved under compactions-quarantine/ (forensic-safe copy)"
        );
        assert!(
            store
                .head(&compactions_gc_boundary_path(root))
                .await
                .is_err(),
            "the compactions GC boundary must be removed (else the fresh id-1 create is rejected)"
        );

        // Compactor-state verify: `.compactions` is now absent ⇒ a compactor-ON open fresh-starts.
        let admin = Admin::builder(root.to_string(), store.clone()).build();
        assert!(
            admin.read_compactions(None).await.unwrap().is_none(),
            "`.compactions` is absent after the reset (compactor-ON open will fresh-start)"
        );

        // REOPEN compactor-ON: SERVES, crown survives byte-equal (anti-hollow), `.compactions` decodes
        // again (fresh-created by the compactor-ON open, which the stale boundary would otherwise block).
        assert_eq!(
            read_key_via_compactor_on_db(&store, root, b"secret/acme/idp").await,
            Some(b"sealed-crown-jewel".to_vec()),
            "the crown-jewel MUST survive the `.compactions` reset byte-equal (compactor-ON reopen)"
        );
        assert!(
            admin.read_compactions(None).await.unwrap().is_some(),
            "`.compactions` decodes again after a compactor-ON reopen (fresh-created at id 1)"
        );
    }

    /// **v0.11.1** — `detect_corrupt_compactions` distinguishes the three states: a corrupt `.compactions`
    /// (⇒ true), an ABSENT one (a never-compacted store ⇒ false, never a spurious reset), and `recover_
    /// corrupt_compactions` is a NO-OP (`NotCorrupt`) when there is nothing corrupt. Guards against a
    /// destructive reset of a healthy/absent compactions store.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    async fn compactions_reset_is_a_noop_when_not_corrupt() {
        let store = mem_store();
        let root = "kv";
        seed_real_store_with_secret(&store, root).await; // no `.compactions` at all (compactor off)
        assert!(
            !detect_corrupt_compactions(&store, root).await.unwrap(),
            "an ABSENT `.compactions` is NOT corrupt (never reset a never-compacted store)"
        );
        match recover_corrupt_compactions(&store, root, RepairMode::Apply)
            .await
            .unwrap()
        {
            CompactionsRecovery::NotCorrupt => {}
            other => panic!("an absent `.compactions` must be a no-op, got {other:?}"),
        }
    }

    /// **F1b INVARIANT PIN (MF2 / Security — the single blind spot the mutation suite was missing).**
    /// slatedb's WAL-GC RETAINS the WAL object AT the durable frontier
    /// (`WalFileRange(Bound::Included(replay_after_wal_id), Unbounded)`, slatedb
    /// `garbage_collector/wal_gc.rs`). MF2's empty-range safety
    /// ([`check_manifest_rollback_wal_contiguity`] returning `Ok` when `highest <= frontier`) is
    /// LOAD-BEARING on this: a genuinely-advanced-then-GC'd store keeps the boundary object, so a
    /// rollback to an older generation sees `highest > frontier` and catches the leading hole instead of
    /// silently reaching the empty-range escape with acked data gone. If a future slatedb stops
    /// retaining the frontier object (e.g. `Bound::Included`→`Excluded`), this gate goes RED — which is
    /// exactly the signal that would otherwise silently reopen the crown-jewel-loss window.
    ///
    /// Confirms a REAL WAL-GC pass (min_age 0 ⇒ fresh below-frontier objects ARE deleted), not a no-op.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread")]
    #[allow(non_snake_case)]
    async fn slatedb_wal_gc_retains_the_frontier_object_INVARIANT() {
        use slatedb::config::{
            FlushOptions, FlushType, GarbageCollectorDirectoryOptions, GarbageCollectorOptions,
        };
        let store = mem_store();
        let root = "kv";
        // Seed a WAL history and advance the durable frontier: several checkpointed writes, each made
        // durable in the WAL then frozen to L0 (advancing `replay_after_wal_id`), so WAL objects exist
        // BOTH below and at the final frontier.
        {
            #[allow(clippy::field_reassign_with_default)]
            let settings = {
                let mut s = Settings::default();
                s.flush_interval = Some(Duration::from_millis(5));
                s.compactor_options = None;
                s.garbage_collector_options = None;
                s
            };
            let db = Db::builder(root.to_string(), store.clone())
                .with_settings(settings)
                .build()
                .await
                .unwrap();
            for i in 0..6u32 {
                db.put(format!("k{i}").as_bytes(), format!("v{i}").as_bytes())
                    .await
                    .unwrap()
                    .await_durable()
                    .await
                    .unwrap();
                db.flush_with_options(FlushOptions {
                    flush_type: FlushType::MemTable,
                })
                .await
                .unwrap();
            }
            db.close().await.unwrap();
        }

        let frontier = read_frontier(&store, root).await.unwrap();
        let before = list_wal_ids(&store, root).await.unwrap();
        assert!(
            before.iter().any(|&id| id < frontier),
            "F1b fixture must leave at least one WAL object BELOW the frontier {frontier} so the GC pass \
             has something to delete (proving a non-no-op); got {before:?}"
        );
        assert!(
            before.contains(&frontier),
            "F1b fixture must have a WAL object AT the frontier {frontier} (the boundary object the \
             retention invariant protects); got {before:?}"
        );

        // Run a REAL one-shot WAL-GC pass with min_age 0 so the fresh below-frontier objects ARE
        // eligible for deletion (default min_age is 5 min — that would be a no-op).
        let admin = Admin::builder(root.to_string(), store.clone()).build();
        let gc_opts = GarbageCollectorOptions {
            wal_options: Some(GarbageCollectorDirectoryOptions {
                interval: None,
                min_age: Duration::ZERO,
                dry_run: false,
            }),
            ..Default::default()
        };
        admin
            .run_gc_once(gc_opts)
            .await
            .expect("one-shot WAL GC must run");

        let after = list_wal_ids(&store, root).await.unwrap();
        // NON-NO-OP: the GC pass actually deleted below-frontier WAL objects.
        assert!(
            after.len() < before.len(),
            "F1b: the WAL-GC pass must have DELETED below-frontier objects (not a no-op): before \
             {before:?}, after {after:?} (frontier {frontier})"
        );
        // THE INVARIANT: the WAL object AT the durable frontier is RETAINED.
        assert!(
            after.contains(&frontier),
            "F1b INVARIANT VIOLATED: WAL-GC deleted the frontier object {frontier} — slatedb no longer \
             retains `Bound::Included(replay_after_wal_id)`. MF2's empty-range safety is broken and the \
             crown-jewel-loss window is reopened. after={after:?}"
        );
    }
}
