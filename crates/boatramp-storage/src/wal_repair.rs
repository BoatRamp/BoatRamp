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
//! ## Mechanic
//!
//! [`RepairMode::DryRun`] mutates NOTHING — it only computes and returns the plan.
//! [`RepairMode::Apply`] **copies** (never renames) each offending trailing-torn
//! object to `{root}/wal-quarantine/{stamp}/{:020}.sst`, writes a
//! `MANIFEST.json` describing the action, THEN deletes the original, and finally
//! re-verifies that zero torn candidates remain before returning. The caller then
//! proceeds to open the (now-clean) store.

use std::sync::Arc;

use slatedb::admin::Admin;
// `ObjectStore` for `list`; `ObjectStoreExt` for the `get_range`/`put`/`copy`/`delete`
// convenience methods (an extension trait in object_store 0.14).
use slatedb::object_store::path::Path as ObjPath;
use slatedb::object_store::{ObjectStore, ObjectStoreExt};

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
}

impl RepairReport {
    /// A pass that found nothing to repair (no torn trailing tail beyond the frontier).
    pub fn is_noop(&self) -> bool {
        self.quarantined.is_empty()
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

    /// After applying the quarantine, a torn candidate still remained (a concurrent
    /// writer, or a store-consistency failure). Refuse to claim success.
    #[error(
        "control-plane WAL repair failed: after quarantine, torn WAL object(s) still remain \
         beyond the frontier at `{root}` — refusing to report success"
    )]
    VerificationFailed {
        /// The store root.
        root: String,
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
/// module's safety contract. Returns the plan/outcome as a [`RepairReport`]; refuses (fails
/// loud) on an unreadable manifest, a mid-range gap, or a post-apply verification miss.
///
/// - [`RepairMode::DryRun`] computes the plan and mutates NOTHING.
/// - [`RepairMode::Apply`] copies → writes the quarantine manifest → deletes → re-verifies.
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

    // 2. List + classify every WAL object strictly beyond the frontier, highest id first.
    let candidates = scan_candidates(store, root, frontier).await?;

    // 3+4. Decide the trailing torn tail, refusing on a mid-range gap.
    let ids = plan_trailing_tail(&candidates, root)?;

    if ids.is_empty() || mode == RepairMode::DryRun {
        // Nothing to do, or a dry-run: return the plan without mutating anything.
        return Ok(RepairReport {
            frontier,
            candidates,
            quarantined: ids.clone(),
            quarantine_dir: (!ids.is_empty())
                .then(|| format!("{root}/wal-quarantine/<stamp>/ (dry-run: not created)")),
            applied: false,
        });
    }

    // 5. Apply: copy → manifest → delete (each candidate re-asserted strictly beyond frontier).
    let stamp = quarantine_stamp();
    apply_quarantine(store, root, frontier, &candidates, &ids, &stamp).await?;

    // 6. Re-verify: scan again and confirm zero torn candidates remain beyond the frontier.
    let after = scan_candidates(store, root, frontier).await?;
    if after.iter().any(|c| c.class == WalClass::Torn) {
        return Err(WalRepairError::VerificationFailed {
            root: root.to_string(),
        });
    }

    Ok(RepairReport {
        frontier,
        candidates,
        quarantined: ids,
        quarantine_dir: Some(format!("{root}/wal-quarantine/{stamp}")),
        applied: true,
    })
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
    //! Each gate is mutation-verified: the doc on B3/B4 names the exact relaxation that breaks it.

    use super::*;
    use slatedb::object_store::memory::InMemory;

    /// A well-formed SST-footer object of `size` bytes: `size-2` filler + a 2-byte BE version
    /// word `version`. The repair probe reads ONLY the last 10 bytes (offset + version), so a
    /// crafted object is byte-faithful to what `classify` inspects without a real SST body.
    /// `version ∈ {1,2}` ⇒ Readable; anything else (notably 0, the production torn signature) ⇒ Torn.
    fn footer_object(size: usize, version: u16) -> bytes::Bytes {
        assert!(
            size >= NUM_FOOTER_BYTES as usize,
            "must fit a 10-byte footer"
        );
        let mut buf = vec![0xABu8; size];
        // Footer = last 10 bytes: bytes[..8] = metadata offset (arbitrary here), bytes[8..10] = version BE.
        let n = buf.len();
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
}
