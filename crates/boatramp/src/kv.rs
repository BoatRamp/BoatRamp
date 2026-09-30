//! `boatramp kv` — offline maintenance of the control-plane SlateDB store (v0.9.0 KV-recovery).
//!
//! - **`repair`** — the one-shot WAL-tail quarantine: DRY-RUN by default (prints the plan), quarantines
//!   a torn TRAILING tail on `--apply`. The OFFLINE tail-only tool.
//! - **`recover`** — the SUPERSET of `repair` (C9/C10): DRY-RUN diagnoses the WHOLE store; `--apply`
//!   repairs a recoverable shape in place; for an UNSAFE shape (a torn compacted/L0 SST) beyond
//!   auto-heal, `--adopt-volume <mounted-path>` validates + adopts an operator-attached CLEAN volume
//!   snapshot (verify-open → swap, retaining the crashed copy).
//! - **`checkpoint`** — flush the store to a consistent, GUARANTEED-BOOTABLE on-disk state (drain
//!   WAL→L0) so a volume snapshot is reliably bootable. OFFLINE (open + close); the LIVE forms are the
//!   automatic `[serve.kv] checkpoint_interval` cadence + on-demand `POST /api/kv-checkpoint`.
//! - **`status`** — show the durable degraded-state breadcrumb (`{root}/DEGRADED.json`) a self-heal
//!   wrote; `--ack` clears it. Reads WITHOUT opening the store, so it works even when the store won't boot.
//!
//! The data-loss guard lives entirely in the core: it quarantines ONLY a physically-torn object
//! that is strictly trailing AND strictly beyond the durable frontier, and REFUSES (fails loud)
//! on a mid-range gap, a WAL-id hole, or an unreadable manifest. See [`boatramp_storage::wal_repair`].
//! The self-heal-on-open default (`boatramp serve`) is the automatic boot-time counterpart; a stale
//! `BOATRAMP_KV_REPAIR=1` is now a no-op (self-heal is the default).

use std::path::PathBuf;
use std::sync::Arc;

use boatramp_storage::kv_slatedb::{
    RepairMode, RepairReport, clear_degraded_marker, read_degraded_marker,
};
use boatramp_storage::object_store::ObjectStore;
use boatramp_storage::wal_repair::{WalRepairError, repair_wal_tail};
use clap::{Args, Subcommand};

/// `boatramp kv` command group.
#[derive(Debug, Args)]
pub struct KvArgs {
    #[command(subcommand)]
    command: KvCommand,
}

#[derive(Debug, Subcommand)]
enum KvCommand {
    /// Repair a torn TRAILING WAL tail on the control-plane SlateDB store so it opens again
    /// (crash / snapshot partial-tail recovery). DRY-RUN by default (prints the plan); pass
    /// `--apply` to quarantine the torn tail. Refuses on a mid-range gap or unreadable manifest.
    /// This is the OFFLINE tail-only quarantine; `boatramp kv recover` is the daemon-mediated
    /// superset (in-place robust repair, else adopt a clean volume).
    Repair(RepairArgs),
    /// Show the control-plane KV degraded state (v0.9.0 KV-recovery, C6): whether a self-heal-on-open
    /// quarantined a torn WAL tail (from the durable `{root}/DEGRADED.json` breadcrumb). `--ack`
    /// clears the breadcrumb once the loss window has been reviewed. Reads the breadcrumb WITHOUT
    /// opening the store, so it works even when the store will not boot.
    Status(StatusArgs),
    /// Flush the control-plane store to a consistent, GUARANTEED-BOOTABLE on-disk state (drain
    /// WAL→L0, advance the durable frontier), so an operator can snapshot the volume safely. OFFLINE
    /// (the daemon must be stopped — SlateDB is single-writer). A live daemon checkpoints
    /// continuously on the `[serve.kv] checkpoint_interval` cadence, and on demand via
    /// `POST /api/kv-checkpoint`. Fails loud if the store is torn (run `kv recover` first).
    Checkpoint(StoreAddr),
    /// Recover an unbootable control-plane store (v0.9.0 KV-recovery, C9/C10) — the SUPERSET of
    /// `kv repair`. DRY-RUN by default (diagnose the WHOLE store + print the plan). `--apply`
    /// repairs a recoverable shape IN PLACE (quarantine a safe trailing torn tail, retaining the
    /// torn bytes for forensics). For an UNSAFE shape (a torn compacted/L0 SST), attach a clean
    /// volume snapshot and pass `--adopt-volume <mounted-path>`: it validates the attached store
    /// opens clean + zero-torn BEFORE adopting, prints the discard-delta, and (with `--apply`)
    /// adopts it via verify-open-then-swap, RETAINING the crashed copy until the adopt is verified.
    Recover(RecoverArgs),
}

/// The store-addressing flags shared by every `boatramp kv` subcommand — they build EXACTLY the
/// object store + root the opener uses (R2/S3 rooted at the prefix, or the local fs rooted at `kv`),
/// so an offline command sees the same objects the serving open would.
#[derive(Debug, Args)]
struct StoreAddr {
    /// The server data directory (as passed to `boatramp serve --data-dir`). The local SlateDB
    /// control-plane store lives under `<data-dir>/kv-slate` (root `kv`). Defaults to `./data`.
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// Target the R2/S3-backed store instead of the local disk store (matches `serve --kv-s3`).
    /// Uses the ambient AWS credentials; addressing comes from the `--s3-*` flags below.
    #[arg(long, env = "BOATRAMP_KV_S3")]
    kv_s3: bool,

    /// S3/R2 bucket for `--kv-s3`.
    #[arg(long, env = "BOATRAMP_S3_BUCKET")]
    s3_bucket: Option<String>,

    /// S3/R2 endpoint for `--kv-s3` (R2: `https://<account>.r2.cloudflarestorage.com`).
    #[arg(long, env = "BOATRAMP_S3_ENDPOINT")]
    s3_endpoint: Option<String>,

    /// S3/R2 region for `--kv-s3` (R2 uses `auto`).
    #[arg(long, env = "BOATRAMP_S3_REGION")]
    s3_region: Option<String>,

    /// Path-style addressing for `--kv-s3` (R2 accepts it).
    #[arg(long, env = "BOATRAMP_S3_PATH_STYLE")]
    s3_path_style: bool,

    /// Key prefix (root) of the `--kv-s3` store within the bucket (matches `serve --kv-s3-prefix`).
    #[arg(long, env = "BOATRAMP_KV_S3_PREFIX", default_value = "_kv")]
    kv_s3_prefix: String,
}

impl StoreAddr {
    /// Open the control-plane SlateDB store this addressing points at, with `policy` (offline —
    /// the daemon MUST be down, since SlateDB is single-writer). Used by `kv checkpoint`
    /// (open + close = drain WAL→L0) and by `kv recover --adopt-volume` (verify a volume opens).
    async fn open_store(
        &self,
        policy: boatramp_storage::kv_slatedb::KvOpenPolicy,
    ) -> Result<boatramp_storage::SlateKv, Error> {
        let flush = boatramp_node::backends::CONTROL_PLANE_FLUSH;
        if self.kv_s3 {
            let cfg = boatramp_storage::S3StoreConfig {
                bucket: self.s3_bucket.clone().unwrap_or_default(),
                endpoint: self.s3_endpoint.clone(),
                region: self.s3_region.clone(),
                path_style: self.s3_path_style,
            };
            boatramp_storage::SlateKv::open_s3_with_flush_policy(
                &cfg,
                &self.kv_s3_prefix,
                flush,
                policy,
            )
            .await
            .map_err(|e| Error::Store(e.to_string()))
        } else {
            boatramp_storage::SlateKv::open_local_with_flush_policy(
                self.data_dir.join("kv-slate"),
                flush,
                policy,
            )
            .await
            .map_err(|e| Error::Store(e.to_string()))
        }
    }

    /// Build the `(object store, root)` the opener uses.
    fn build(&self) -> Result<(Arc<dyn ObjectStore>, String), Error> {
        if self.kv_s3 {
            let cfg = boatramp_storage::S3StoreConfig {
                bucket: self.s3_bucket.clone().unwrap_or_default(),
                endpoint: self.s3_endpoint.clone(),
                region: self.s3_region.clone(),
                path_style: self.s3_path_style,
            };
            let store = boatramp_storage::kv_slatedb::s3_object_store(&cfg)
                .map_err(|e| Error::Store(e.to_string()))?;
            Ok((store, self.kv_s3_prefix.clone()))
        } else {
            let dir = self.data_dir.join("kv-slate");
            let fs = boatramp_storage::kv_slatedb::local_object_store(&dir)
                .map_err(|e| Error::Store(e.to_string()))?;
            Ok((Arc::new(fs), "kv".to_string()))
        }
    }
}

#[derive(Debug, Args)]
struct RepairArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Perform the quarantine. Without this the command is a DRY-RUN: it prints the plan and
    /// mutates NOTHING.
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Acknowledge + CLEAR the DEGRADED breadcrumb (after reviewing the loss window). Idempotent —
    /// clearing an absent breadcrumb is a no-op.
    #[arg(long)]
    ack: bool,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Perform the recovery (in-place repair, or adopt the attached volume). Without this the
    /// command is a DRY-RUN: it diagnoses + prints the plan and mutates NOTHING.
    #[arg(long)]
    apply: bool,

    /// Adopt an operator-attached CLEAN volume snapshot mounted at this path (expects its
    /// `kv-slate` store underneath) INSTEAD of an in-place repair — for a shape beyond auto-heal
    /// (a torn compacted/L0 SST). The attached store is validated (opens clean + zero-torn) BEFORE
    /// adopting; `--apply` swaps it in, RETAINING the crashed copy until the adopt is verified.
    /// boatramp does NOT create/destroy fly volumes — attach the snapshot volume with the fly CLI
    /// first (`fly volumes create` from a snapshot, then mount it). Local-disk / fly-volume only.
    #[arg(long, value_name = "MOUNTED_PATH")]
    adopt_volume: Option<PathBuf>,
}

/// Errors surfaced by `boatramp kv`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Building the object store to operate on (bad `--kv-s3` addressing / local dir).
    #[error("kv: could not build the store: {0}")]
    Store(String),
    /// The repair itself refused or failed (loud — the caller must not proceed to serve).
    #[error(transparent)]
    Repair(#[from] WalRepairError),
}

/// Dispatch `boatramp kv <subcommand>`.
pub async fn run(args: KvArgs) -> Result<(), Error> {
    match args.command {
        KvCommand::Repair(repair) => run_repair(repair).await,
        KvCommand::Status(status) => run_status(status).await,
        KvCommand::Checkpoint(addr) => run_checkpoint(addr).await,
        KvCommand::Recover(recover) => run_recover(recover).await,
    }
}

async fn run_repair(args: RepairArgs) -> Result<(), Error> {
    let (store, root) = args.addr.build()?;
    let mode = if args.apply {
        RepairMode::Apply
    } else {
        RepairMode::DryRun
    };
    let report = repair_wal_tail(&store, &root, mode).await?;
    print_report(&report, args.apply);
    Ok(())
}

async fn run_status(args: StatusArgs) -> Result<(), Error> {
    let (store, root) = args.addr.build()?;
    if args.ack {
        let existed = clear_degraded_marker(&store, &root)
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        if existed {
            println!("kv status: CLEARED the DEGRADED breadcrumb (acknowledged).");
        } else {
            println!("kv status: no DEGRADED breadcrumb to acknowledge.");
        }
        return Ok(());
    }
    match read_degraded_marker(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?
    {
        Some(m) => {
            println!("kv status: DEGRADED (a self-heal-on-open quarantined a torn WAL tail)");
            println!("  self-healed at (unix): {}", m.stamp);
            println!("  quarantined WAL ids:   {:?}", m.quarantined_ids);
            println!("  loss window:           {}", m.loss_window);
            println!("  quarantine dir:        {}", m.quarantine_dir);
            println!(
                "  NOTE: the quarantined torn tail preserves raw bytes for FORENSICS ONLY — there \
                 is no supported recovery of acked KV pairs from a torn version-0 SST."
            );
            println!("  Acknowledge with `boatramp kv status --ack` once reviewed.");
        }
        None => println!(
            "kv status: OK — no DEGRADED breadcrumb (the store opened cleanly, a self-heal was \
             zero-loss, or a prior degraded state was acked). If the store will not open, run \
             `boatramp kv recover` (dry-run) to diagnose."
        ),
    }
    Ok(())
}

async fn run_checkpoint(addr: StoreAddr) -> Result<(), Error> {
    // Open STRICT (a torn store must be RECOVERED first, never checkpointed) then CLOSE: the close
    // drains the memtable → L0 and advances the durable frontier (slatedb `CloseOptions` default
    // `FlushType::MemTable` — the same primitive as the periodic checkpoint), leaving a consistent,
    // bootable on-disk state. OFFLINE only (single-writer fencing — the daemon must be stopped).
    let kv = addr
        .open_store(boatramp_storage::kv_slatedb::KvOpenPolicy::Strict)
        .await?;
    boatramp_core::kv::KvStore::close(&kv)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    println!(
        "kv checkpoint: WAL drained to L0 and the durable frontier advanced — the on-disk store is \
         now a consistent, bootable snapshot point. Snapshot the volume now (a block snapshot of a \
         LIVE un-checkpointed store is not reliably bootable; that is the recurring root cause)."
    );
    Ok(())
}

async fn run_recover(args: RecoverArgs) -> Result<(), Error> {
    if let Some(volume) = args.adopt_volume.clone() {
        return run_recover_adopt_volume(&args.addr, &volume, args.apply).await;
    }
    // In-place path: the SUPERSET of `kv repair` — the same #5-hardened whole-store repair core,
    // with the shape-split escalation to `--adopt-volume` (C10).
    let (store, root) = args.addr.build()?;
    let mode = if args.apply {
        RepairMode::Apply
    } else {
        RepairMode::DryRun
    };
    match repair_wal_tail(&store, &root, mode).await {
        Ok(report) => {
            print_report(&report, args.apply);
            if !args.apply && !report.quarantined.is_empty() {
                println!(
                    "\nRe-run `boatramp kv recover --apply` to quarantine the safe trailing tail in \
                     place (the crashed torn bytes are retained under `wal-quarantine/` for forensics)."
                );
            }
            if !report.out_of_scope_torn.is_empty() {
                print_adopt_volume_guidance();
            }
            Ok(())
        }
        Err(e) => {
            // C10 shape-split: name the exact refusal, then point at the snapshot-restore path.
            eprintln!("kv recover: in-place repair cannot proceed — {e}");
            print_adopt_volume_guidance();
            Err(e.into())
        }
    }
}

/// The `--adopt-volume` escalation guidance (C10): a shape beyond auto-heal AND beyond `kv repair`
/// (tail-only) is recovered by adopting a clean volume snapshot. boatramp validates + adopts the
/// volume the operator attaches; it never drives the fly volume lifecycle.
fn print_adopt_volume_guidance() {
    eprintln!(
        "\nUNSAFE SHAPE — beyond auto-heal and beyond `kv repair` (tail-only). Recover by adopting a \
         CLEAN volume snapshot:\n  \
         1. fly volumes create <name> --snapshot-id <snap>   (or restore/clone a known-good volume)\n  \
         2. mount it on a machine (e.g. a second mount, or a maintenance machine)\n  \
         3. boatramp kv recover --adopt-volume <mounted-path>            (dry-run: validate + delta)\n  \
         4. boatramp kv recover --adopt-volume <mounted-path> --apply    (verify → swap; crashed copy retained)\n\
         boatramp validates + adopts the volume you attach; it does NOT create/destroy fly volumes."
    );
}

/// `kv recover --adopt-volume <mounted-path>`: validate an operator-attached CLEAN volume snapshot
/// and (with `--apply`) adopt it in place of the crashed local store, RETAINING the crashed copy
/// until the adopt is verified (C9). Local-disk / fly-volume only (a snapshot is a mounted path).
async fn run_recover_adopt_volume(
    target: &StoreAddr,
    volume: &std::path::Path,
    apply: bool,
) -> Result<(), Error> {
    if target.kv_s3 {
        return Err(Error::Store(
            "--adopt-volume is a local-disk / fly-volume flow (a mounted snapshot path); it does \
             not apply to an --kv-s3 store. Recover an S3/R2 store via its own object-store \
             versioning/restore, then `kv recover` (in-place) or redeploy."
                .to_string(),
        ));
    }
    let target_dir = target.data_dir.join("kv-slate");
    // The attached volume's control-plane store (its own `kv-slate`, mirroring the live layout).
    let volume_dir = volume.join("kv-slate");
    if !volume_dir.is_dir() {
        return Err(Error::Store(format!(
            "the attached volume at `{}` has no `kv-slate` store (expected `{}`). Mount the volume \
             whose `kv-slate` is the clean snapshot.",
            volume.display(),
            volume_dir.display()
        )));
    }

    // 1. VALIDATE the attached volume BEFORE adopting: zero torn AND it really opens clean.
    let vol_obj: Arc<dyn ObjectStore> = Arc::new(
        boatramp_storage::kv_slatedb::local_object_store(&volume_dir)
            .map_err(|e| Error::Store(e.to_string()))?,
    );
    let vol_dry = repair_wal_tail(&vol_obj, "kv", RepairMode::DryRun).await?;
    if !vol_dry.is_noop() {
        return Err(Error::Store(format!(
            "REFUSING to adopt: the attached volume at `{}` is ITSELF torn/dirty (would need \
             recovery too) — trailing torn tail {:?}, out-of-scope torn objects: {}. Attach a \
             genuinely clean snapshot.",
            volume.display(),
            vol_dry.quarantined,
            vol_dry.out_of_scope_torn.len()
        )));
    }
    // A real open (Strict) is the definitive clean check (a footer probe cannot see everything).
    {
        let vk = boatramp_storage::SlateKv::open_local_with_flush_policy(
            &volume_dir,
            boatramp_node::backends::CONTROL_PLANE_FLUSH,
            boatramp_storage::kv_slatedb::KvOpenPolicy::Strict,
        )
        .await
        .map_err(|e| {
            Error::Store(format!(
                "REFUSING to adopt: the attached volume at `{}` did not open cleanly: {e}",
                volume.display()
            ))
        })?;
        boatramp_core::kv::KvStore::close(&vk)
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
    }

    // 2. Discard-delta: adopting the snapshot DISCARDS the crashed store's post-snapshot writes.
    println!(
        "adopt-volume: the attached store at `{}` opens CLEAN (zero torn).\n  \
         Adopting REPLACES the crashed store at `{}` with the snapshot.\n  \
         DISCARD-DELTA: every write in the crashed store made AFTER the snapshot's point-in-time is \
         LOST (a snapshot is a point-in-time copy; boatramp cannot merge the crashed WAL into it).\n  \
         The crashed copy is RETAINED (renamed aside) until the adopt is verified serving.",
        volume_dir.display(),
        target_dir.display()
    );
    if !apply {
        println!(
            "\nDRY-RUN: re-run with `--apply` to adopt (verify-open → swap, retaining the crashed copy)."
        );
        return Ok(());
    }

    // 3. --apply: retain the crashed copy, copy the validated snapshot into place, verify it opens;
    //    roll back on any failure so a botched adopt never leaves an unbootable/empty store.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let retained = target
        .data_dir
        .join(format!("kv-slate.crashed-{stamp:020}"));
    if target_dir.exists() {
        std::fs::rename(&target_dir, &retained).map_err(|e| {
            Error::Store(format!(
                "could not retain the crashed store `{}` → `{}`: {e}",
                target_dir.display(),
                retained.display()
            ))
        })?;
    }
    // Copy (never move) the operator's mounted snapshot into the live store dir.
    if let Err(e) = copy_dir_all(&volume_dir, &target_dir) {
        // Roll back: remove the partial copy, restore the crashed copy.
        let _ = std::fs::remove_dir_all(&target_dir);
        if retained.exists() {
            let _ = std::fs::rename(&retained, &target_dir);
        }
        return Err(Error::Store(format!(
            "adopt FAILED copying the snapshot into place (rolled back — the crashed store is \
             restored): {e}"
        )));
    }
    // Verify the adopted store opens clean; roll back if not.
    match boatramp_storage::SlateKv::open_local_with_flush_policy(
        &target_dir,
        boatramp_node::backends::CONTROL_PLANE_FLUSH,
        boatramp_storage::kv_slatedb::KvOpenPolicy::Strict,
    )
    .await
    {
        Ok(vk) => {
            let _ = boatramp_core::kv::KvStore::close(&vk).await;
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&target_dir);
            if retained.exists() {
                let _ = std::fs::rename(&retained, &target_dir);
            }
            return Err(Error::Store(format!(
                "adopt FAILED: the adopted store did not open after the swap (rolled back — the \
                 crashed store is restored): {e}"
            )));
        }
    }
    println!(
        "kv recover: ADOPTED the clean snapshot into `{}`. The crashed store is RETAINED at `{}` \
         (delete it once the node is confirmed serving). Start the daemon.",
        target_dir.display(),
        retained.display()
    );
    Ok(())
}

/// Recursively copy a directory tree (`src` → `dst`) — the snapshot adopt copies the mounted volume
/// into the live store dir rather than moving it (the operator's snapshot volume stays intact).
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Print the repair plan / outcome to stdout.
fn print_report(report: &RepairReport, applied_mode: bool) {
    println!(
        "control-plane WAL repair {}",
        if applied_mode {
            "(APPLY)"
        } else {
            "(DRY-RUN — no mutation)"
        }
    );
    println!(
        "  durable frontier (replay_after_wal_id): {}",
        report.frontier
    );
    println!("  WAL candidates beyond the frontier (highest id first):");
    if report.candidates.is_empty() {
        println!("    (none)");
    } else {
        for c in &report.candidates {
            println!("    {:020}.sst  {:>10} bytes  {:?}", c.id, c.size, c.class);
        }
    }
    // Out-of-scope torn SSTs (torn compacted/L0 SSTs + torn non-trailing WAL objects). These are
    // DETECTION-ONLY: the repair NEVER quarantines/removes them (a compacted SST is referenced by
    // the manifest — removing it without a manifest rollback would drop acked data). Print them
    // LOUDLY before the "should open normally" line so the compacted-SST case is unmistakable and
    // an apply's `UnrepairableTornObject` failure is explained.
    if !report.out_of_scope_torn.is_empty() {
        println!(
            "  OUT-OF-SCOPE torn SST(s) this tool will NOT auto-remove \
             (requires manifest-aware recovery; escalate):"
        );
        for t in &report.out_of_scope_torn {
            println!(
                "    {}  {:>10} bytes  {:?}  [{:?}]",
                t.path, t.size, t.class, t.kind
            );
        }
        println!(
            "  A torn compacted/L0 SST cannot be quarantined safely (it is referenced by the \
             manifest); dropping it needs a manifest rollback. `--apply` will quarantine any safe \
             trailing WAL tail, then FAIL LOUD naming the object(s) above — the store will not open \
             until they are resolved out of band."
        );
    }
    if report.is_noop() {
        println!("  no torn SST found (WAL tail or compacted) — the store should open normally.");
        return;
    }
    let ids: Vec<String> = report
        .quarantined
        .iter()
        .map(|id| format!("{id:020}"))
        .collect();
    if report.applied {
        println!(
            "  QUARANTINED the trailing torn tail [{}] to `{}`.",
            ids.join(", "),
            report.quarantine_dir.as_deref().unwrap_or("<unknown>")
        );
        println!(
            "  The store should now open. NOTE (honest loss-window): a HARD-CRASH repair may have \
             lost the most-recent acked-into-WAL-but-not-yet-L0 writes — the graceful shutdown \
             path (quiesce-then-close) is lossless; only an abrupt crash/snapshot can lose the tail."
        );
    } else {
        println!(
            "  WOULD quarantine the trailing torn tail [{}]. Re-run with `--apply` to perform it.",
            ids.join(", ")
        );
        println!(
            "  NOTE (honest loss-window): applying on a HARD-CRASH store may lose the most-recent \
             acked-into-WAL-but-not-yet-L0 writes; a graceful shutdown is lossless."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `copy_dir_all` (used by `kv recover --adopt-volume`) copies a nested tree faithfully.
    #[test]
    fn copy_dir_all_copies_a_nested_tree() {
        let tmp = std::env::temp_dir().join(format!("br-kv-copy-{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"b").unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(dst.join("sub/b.txt")).unwrap(), b"b");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn local_addr(data_dir: PathBuf) -> StoreAddr {
        StoreAddr {
            data_dir,
            kv_s3: false,
            s3_bucket: None,
            s3_endpoint: None,
            s3_region: None,
            s3_path_style: false,
            kv_s3_prefix: "_kv".to_string(),
        }
    }

    /// `kv recover --adopt-volume` REFUSES a mounted path with no `kv-slate` store (never mutates the
    /// target) — the guard before any validate/swap.
    #[tokio::test]
    async fn adopt_volume_refuses_a_volume_without_a_kv_slate_store() {
        let tmp = std::env::temp_dir().join(format!("br-kv-adopt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let addr = local_addr(tmp.join("data"));
        let err = run_recover_adopt_volume(&addr, &tmp.join("emptyvol"), false)
            .await
            .expect_err("adopt must refuse a volume with no kv-slate store");
        assert!(matches!(err, Error::Store(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `--adopt-volume` is refused for an `--kv-s3` target (it is a local-disk / fly-volume flow).
    #[tokio::test]
    async fn adopt_volume_refuses_an_s3_target() {
        let mut addr = local_addr(std::path::PathBuf::from("./data"));
        addr.kv_s3 = true;
        let err = run_recover_adopt_volume(&addr, std::path::Path::new("/mnt/snap"), true)
            .await
            .expect_err("adopt must refuse an --kv-s3 target");
        assert!(matches!(err, Error::Store(_)), "got {err:?}");
    }
}
