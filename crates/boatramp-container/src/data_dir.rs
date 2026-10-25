//! Data-dir-ownership scanning — the **pure, cross-platform** detection half of the
//! managed-database data-dir health signal (`boatramp db status`).
//!
//! A managed database runs rootless inside its container (Postgres/MySQL as uid:gid
//! `999:999`), so its launch pre-chowns the volume's data directory to the guest process's
//! mapped host owner ([`crate::backend`]'s `stage_volumes` → `chown_tree_to`). When a data
//! directory instead carries **foreign-owned** files — a volume restored/cloned from an
//! env-export, carried over from a different user-namespace base, or a custom image whose
//! real uid differs from the assumed default — the database process gets `EPERM` reading
//! its own cluster files, never answers, and the replica is stuck starting.
//!
//! [`scan_data_dir_ownership`] is the **read-only** counterpart of that launch-time
//! `chown_tree_to`: it walks the same tree and reports a fault WITHOUT changing anything.
//! It lives in this cross-platform module (not the `target_os = "linux"`-gated backend) so
//! the detection logic is unit-tested on every host; the backend's `ComputeBackend`
//! implementation wires it to a workload's volumes and the expected guest owner.

use std::path::Path;

/// How many foreign-owned entries [`scan_data_dir_ownership`] counts before stopping early
/// — enough to warn and sample without walking a large tree once the fault is established.
pub(crate) const OWNERSHIP_SCAN_BUDGET: u64 = 64;

/// How many entries [`scan_consistent_owner`] stats before accepting a uniform consensus. Set
/// high enough to cover a real database data directory (a fresh Postgres cluster is a few
/// thousand files) so a MIXED-ownership (partial-corruption) data dir is caught as a clean,
/// actionable launch REFUSAL rather than deferred to a runtime DB `FATAL`. Still bounded, so a
/// pathologically huge, consistent tree can't stall the launch (a derived base from a tree
/// that's uniform across this many entries is as confined as any other — a conflict beyond it
/// can't make the mapping more permissive, only degrade to the safe runtime-FATAL path).
pub(crate) const CONSISTENT_OWNER_SCAN_BUDGET: u64 = 65_536;

/// The result of a read-only data-dir-ownership scan — the counts a repair
/// (`chown_tree_to`) would act on, gathered without changing anything.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnershipScan {
    /// Entries stat'd (the root itself + each descendant visited before the early stop).
    pub scanned: u64,
    /// Entries NOT owned by the expected uid:gid, counted up to the caller's budget.
    pub foreign: u64,
    /// The first foreign entry: `(path relative to the scanned root, its uid, its gid)`.
    pub sample: Option<(String, u32, u32)>,
}

/// Walk `dir` (and every descendant, not following symlinks) READ-ONLY, counting entries
/// not owned by `(uid, gid)` up to `budget` and capturing the first such entry as a sample.
///
/// It reports a data-dir-ownership fault (foreign-owned files that `EPERM` a rootless
/// database reading its own cluster files) WITHOUT changing anything — the read-only
/// counterpart of the backend's launch-time `chown_tree_to`. Stops early once `budget`
/// foreign entries are seen, so a faulty directory returns fast; a clean one costs one
/// `lstat` per entry (bounded by the data directory — and the reconcile only calls this
/// while a replica is stuck). The sample path is relative to `dir`, so no host-absolute
/// path escapes into the status surface. Blocking; symlinks are stat'd by themselves and
/// never followed (a symlink in the volume can't redirect the scan outside it).
pub(crate) fn scan_data_dir_ownership(
    dir: &Path,
    uid: u32,
    gid: u32,
    budget: u64,
) -> std::io::Result<OwnershipScan> {
    use std::os::unix::fs::MetadataExt;
    let mut scan = OwnershipScan::default();
    let consider = |path: &Path, meta: &std::fs::Metadata, scan: &mut OwnershipScan| {
        scan.scanned += 1;
        if meta.uid() != uid || meta.gid() != gid {
            scan.foreign += 1;
            if scan.sample.is_none() {
                let rel = path.strip_prefix(dir).unwrap_or(path);
                let shown = if rel.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    rel
                };
                scan.sample = Some((shown.display().to_string(), meta.uid(), meta.gid()));
            }
        }
    };
    consider(dir, &std::fs::symlink_metadata(dir)?, &mut scan);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if scan.foreign >= budget {
            break;
        }
        // A directory that vanished mid-walk (concurrent removal) is skipped, not an
        // error — the scan is best-effort diagnostics, not a correctness invariant.
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            consider(&path, &meta, &mut scan);
            if meta.file_type().is_dir() {
                stack.push(path);
            }
            if scan.foreign >= budget {
                break;
            }
        }
    }
    Ok(scan)
}

/// The uniform-ownership consensus of a persistent volume's data directory — the input to
/// the **derive-the-userns-base** repair (`crate::backend`'s `resolve_volume_mapping`).
///
/// When the launcher canNOT chown a reused volume into the guest's mapped-owner range, it
/// derives the workload's user-namespace base from the data dir's EXISTING owner so the files
/// are readable with no chown. That is only sound when the data dir has a SINGLE, consistent
/// `(uid, gid)` owner across every entry (the root and all descendants): a mixed-ownership
/// tree has no single base that makes it all readable, so the launch must fail closed rather
/// than guess. This scan is the read-only detector of that consensus; it changes nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OwnerConsensus {
    /// The directory does not exist, or exists but holds no entries below its root — a fresh
    /// volume with nothing to derive from.
    Empty,
    /// Every entry (the root dir and all descendants) is owned by this single `(uid, gid)`.
    Uniform { uid: u32, gid: u32, entries: u64 },
    /// Entries disagree on their owner. Carries the first owner seen (the root's) and the
    /// first entry that differs from it, for a fail-closed, actionable error.
    Mixed {
        first_uid: u32,
        first_gid: u32,
        /// Path (relative to the scanned root) of the first conflicting entry.
        conflict_path: String,
        conflict_uid: u32,
        conflict_gid: u32,
    },
}

/// Walk `dir` (and every descendant, not following symlinks) READ-ONLY and report whether it
/// has a single consistent `(uid, gid)` owner ([`OwnerConsensus`]). Symlinks are stat'd by
/// themselves and never followed, so a symlink inside the volume can't redirect the scan
/// outside it. Returns on the FIRST conflicting entry (a faulty tree is cheap). `budget` bounds
/// the number of entries stat'd so a huge, consistent tree can't stall the launch (DoS): once
/// `budget` entries agree, the consensus is accepted as [`OwnerConsensus::Uniform`] without
/// walking the rest — the caller only derives a base from this, which a later conflicting entry
/// could not make MORE permissive (the derived mapping is confined regardless). A missing
/// directory, or one with only its (existing) root and no contents, is [`OwnerConsensus::Empty`]
/// — a fresh volume the caller does not derive from.
pub(crate) fn scan_consistent_owner(dir: &Path, budget: u64) -> std::io::Result<OwnerConsensus> {
    use std::os::unix::fs::MetadataExt;
    let root_meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(OwnerConsensus::Empty),
        Err(e) => return Err(e),
    };
    let (first_uid, first_gid) = (root_meta.uid(), root_meta.gid());
    let mut entries: u64 = 1; // the root itself
    let mut children: u64 = 0;
    let mut stack = vec![dir.to_path_buf()];
    'walk: while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            entries += 1;
            children += 1;
            if meta.uid() != first_uid || meta.gid() != first_gid {
                let rel = path.strip_prefix(dir).unwrap_or(&path);
                return Ok(OwnerConsensus::Mixed {
                    first_uid,
                    first_gid,
                    conflict_path: rel.display().to_string(),
                    conflict_uid: meta.uid(),
                    conflict_gid: meta.gid(),
                });
            }
            if meta.file_type().is_dir() {
                stack.push(path);
            }
            if entries >= budget {
                // Budget reached with no conflict: accept the consensus established so far.
                break 'walk;
            }
        }
    }
    if children == 0 {
        // Only the (existing) root dir, no contents: a fresh/empty volume — don't derive.
        return Ok(OwnerConsensus::Empty);
    }
    Ok(OwnerConsensus::Uniform {
        uid: first_uid,
        gid: first_gid,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_foreign_entries_and_clears_when_all_correct() {
        // Build a Postgres-data-dir-shaped nested tree. The detection logic is the owner
        // COMPARISON + the full-tree walk; we exercise it WITHOUT root by scanning against
        // the current owner (clean) vs. a deliberately-wrong owner (every entry foreign) —
        // the same root-free technique the backend's `chown_tree_to` test uses.
        use std::os::unix::fs::MetadataExt;
        let tmp = std::env::temp_dir().join(format!("brscan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("global")).unwrap();
        std::fs::write(tmp.join("global").join("pg_filenode.map"), b"x").unwrap();
        std::fs::write(tmp.join("PG_VERSION"), b"16").unwrap();
        std::fs::create_dir_all(tmp.join("base").join("1")).unwrap();
        std::fs::write(tmp.join("base").join("1").join("1259"), b"y").unwrap();
        let me = std::fs::symlink_metadata(&tmp).unwrap();

        // 1) Scanned against the ACTUAL owner: the walk visits every entry and finds no
        //    foreign file → clean (foreign == 0, no sample). Proves the clean path reaches
        //    the nested cluster file (root + global/ + map + PG_VERSION + base/ + 1/ + 1259).
        let clean = scan_data_dir_ownership(&tmp, me.uid(), me.gid(), OWNERSHIP_SCAN_BUDGET)
            .expect("scan the tree");
        assert_eq!(clean.foreign, 0, "every entry is owned by the current user");
        assert!(clean.sample.is_none(), "no sample when clean");
        assert!(
            clean.scanned >= 7,
            "walk reached every nested entry, got {}",
            clean.scanned
        );

        // 2) Scanned against a WRONG owner (uid + 1): every entry is foreign → the fault is
        //    reported with a sample naming a RELATIVE path + the entry's ACTUAL owner, the
        //    data an operator needs to see the mismatch. This is the data-dir-ownership
        //    EPERM shape (a volume whose files were written under a different uid).
        let fault = scan_data_dir_ownership(&tmp, me.uid() + 1, me.gid(), OWNERSHIP_SCAN_BUDGET)
            .expect("scan the tree");
        assert!(fault.foreign > 0, "every entry mismatches the wrong uid");
        let (path, uid, gid) = fault.sample.expect("a sample foreign entry");
        assert_eq!(uid, me.uid(), "sample reports the entry's actual owner uid");
        assert_eq!(gid, me.gid(), "sample reports the entry's actual owner gid");
        assert!(
            !Path::new(&path).is_absolute() && !path.contains(&tmp.display().to_string()),
            "sample path is relative to the volume root, not host-absolute: {path:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stops_at_the_budget() {
        // A badly-owned directory with many entries must not force a full walk: the scan
        // stops once `budget` foreign entries are counted (a fast, bounded warning).
        use std::os::unix::fs::MetadataExt;
        let tmp = std::env::temp_dir().join(format!("brscanbudget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        for i in 0..32u32 {
            std::fs::write(tmp.join(format!("f{i}")), b"z").unwrap();
        }
        let me = std::fs::symlink_metadata(&tmp).unwrap();
        // Everything is owned by `me`; scan against a wrong uid with a tiny budget: the
        // reported `foreign` count is capped at the budget (early stop), not the full 33.
        let budget = 4;
        let scan = scan_data_dir_ownership(&tmp, me.uid() + 1, me.gid(), budget).expect("scan");
        assert_eq!(
            scan.foreign, budget,
            "scan stopped once the budget was reached"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn consistent_owner_uniform_empty_and_missing() {
        use std::os::unix::fs::MetadataExt;
        // Missing dir ⇒ nothing to derive from.
        let missing = std::env::temp_dir().join(format!("brco-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        assert_eq!(
            scan_consistent_owner(&missing, OWNERSHIP_SCAN_BUDGET).expect("missing is Empty"),
            OwnerConsensus::Empty
        );

        // An existing but childless dir ⇒ Empty (a fresh volume, not yet populated).
        let empty = std::env::temp_dir().join(format!("brco-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(
            scan_consistent_owner(&empty, OWNERSHIP_SCAN_BUDGET).expect("childless is Empty"),
            OwnerConsensus::Empty
        );

        // A populated, Postgres-shaped tree, entirely owned by the current user (we can't
        // chown to a foreign uid without root), is Uniform at that owner — the input the
        // backend turns into a derived base. The `entries` count proves the FULL walk (root
        // + global/ + map + PG_VERSION + base/ + 1/ + 1259 = 7).
        let tree = std::env::temp_dir().join(format!("brco-uniform-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tree);
        std::fs::create_dir_all(tree.join("global")).unwrap();
        std::fs::write(tree.join("global").join("pg_filenode.map"), b"x").unwrap();
        std::fs::write(tree.join("PG_VERSION"), b"16").unwrap();
        std::fs::create_dir_all(tree.join("base").join("1")).unwrap();
        std::fs::write(tree.join("base").join("1").join("1259"), b"y").unwrap();
        let me = std::fs::symlink_metadata(&tree).unwrap();
        match scan_consistent_owner(&tree, OWNERSHIP_SCAN_BUDGET).expect("uniform scan") {
            OwnerConsensus::Uniform { uid, gid, entries } => {
                assert_eq!((uid, gid), (me.uid(), me.gid()));
                assert!(entries >= 7, "walked every nested entry, got {entries}");
            }
            other => panic!("expected Uniform, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&missing);
        let _ = std::fs::remove_dir_all(&empty);
        let _ = std::fs::remove_dir_all(&tree);
    }
}
