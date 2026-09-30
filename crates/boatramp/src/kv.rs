//! `boatramp kv` — offline maintenance of the control-plane SlateDB store.
//!
//! Today this is the **WAL tail repair** (`boatramp kv repair`): the one-shot, operator-driven
//! recovery for a store whose cold open fails on a torn TRAILING WAL object (a hard-crash /
//! crash-consistent-snapshot partial tail). It is DRY-RUN by default — it prints the plan
//! (candidate ids, sizes, computed durable frontier, classification) and mutates nothing — and
//! only quarantines when `--apply` is passed. The same [`repair_wal_tail`] core also backs the
//! in-process `boatramp serve --repair-wal` / `BOATRAMP_KV_REPAIR=1` repair-then-open path.
//!
//! The data-loss guard lives entirely in the core: it quarantines ONLY a physically-torn object
//! that is strictly trailing AND strictly beyond the durable frontier, and REFUSES (fails loud)
//! on a mid-range gap or an unreadable manifest. See [`boatramp_storage::wal_repair`].

use std::path::PathBuf;
use std::sync::Arc;

use boatramp_storage::kv_slatedb::{RepairMode, RepairReport};
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
    Repair(RepairArgs),
}

#[derive(Debug, Args)]
struct RepairArgs {
    /// The server data directory (as passed to `boatramp serve --data-dir`). The local SlateDB
    /// control-plane store lives under `<data-dir>/kv-slate` (root `kv`). Defaults to `./data`.
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// Repair the R2/S3-backed store instead of the local disk store (matches `serve --kv-s3`).
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

    /// Perform the quarantine. Without this the command is a DRY-RUN: it prints the plan and
    /// mutates NOTHING.
    #[arg(long)]
    apply: bool,
}

/// Errors surfaced by `boatramp kv`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Building the object store to repair (bad `--kv-s3` addressing / local dir).
    #[error("kv repair: could not build the store: {0}")]
    Store(String),
    /// The repair itself refused or failed (loud — the caller must not proceed to serve).
    #[error(transparent)]
    Repair(#[from] WalRepairError),
}

/// Dispatch `boatramp kv <subcommand>`.
pub async fn run(args: KvArgs) -> Result<(), Error> {
    match args.command {
        KvCommand::Repair(repair) => run_repair(repair).await,
    }
}

async fn run_repair(args: RepairArgs) -> Result<(), Error> {
    // Build EXACTLY the store + root the opener would, so the repair sees the same objects the
    // open would replay: R2/S3 rooted at the configured prefix, or the local fs rooted at `kv`.
    let (store, root): (Arc<dyn ObjectStore>, String) = if args.kv_s3 {
        let cfg = boatramp_storage::S3StoreConfig {
            bucket: args.s3_bucket.clone().unwrap_or_default(),
            endpoint: args.s3_endpoint.clone(),
            region: args.s3_region.clone(),
            path_style: args.s3_path_style,
        };
        let store = boatramp_storage::kv_slatedb::s3_object_store(&cfg)
            .map_err(|e| Error::Store(e.to_string()))?;
        (store, args.kv_s3_prefix.clone())
    } else {
        let dir = args.data_dir.join("kv-slate");
        let fs = boatramp_storage::kv_slatedb::local_object_store(&dir)
            .map_err(|e| Error::Store(e.to_string()))?;
        (Arc::new(fs), "kv".to_string())
    };

    let mode = if args.apply {
        RepairMode::Apply
    } else {
        RepairMode::DryRun
    };
    let report = repair_wal_tail(&store, &root, mode).await?;
    print_report(&report, args.apply);
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
