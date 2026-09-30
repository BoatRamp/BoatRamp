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
use boatramp_storage::wal_repair::{
    ManifestRecovery, ManifestRecoveryReport, WalRepairError, recover_last_good_manifest,
    repair_wal_tail,
};
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
    /// by default (the daemon must be stopped — SlateDB is single-writer). Pass `--live` to checkpoint
    /// a RUNNING daemon over `POST /api/kv-checkpoint` (System·Admin) WITHOUT stopping it — the client
    /// verb for the on-demand live checkpoint (the automatic form is the `[serve.kv]
    /// checkpoint_interval` cadence). The offline form fails loud if the store is torn (run `kv
    /// recover` first). NOTE (fsync): a snapshot is bootable only after a checkpoint drained WAL→L0;
    /// v0.11.0 fsync makes even a mid-close hard stop non-corrupting, but a checkpoint before the
    /// snapshot is still the reliable point-in-time.
    Checkpoint(CheckpointArgs),
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

/// Arguments for `boatramp kv checkpoint`.
#[derive(Debug, Args)]
struct CheckpointArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Checkpoint a RUNNING daemon over `POST /api/kv-checkpoint` (System·Admin) instead of the offline
    /// open+close. The live form advances the durable frontier WITHOUT stopping the writer, so a
    /// snapshot of the running node is guaranteed-bootable. Requires `--server`/`--remote` (or a
    /// configured `[deploy].server`).
    #[arg(long)]
    live: bool,

    /// The running daemon URL for `--live` (else the configured `[deploy].server`/`BOATRAMP_SERVER`).
    #[arg(long, value_name = "URL")]
    server: Option<String>,
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
    /// A `--live` control-plane request failed (no server, auth, or a server-side refusal).
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// Dispatch `boatramp kv <subcommand>`.
pub async fn run(args: KvArgs) -> Result<(), Error> {
    match args.command {
        KvCommand::Repair(repair) => run_repair(repair).await,
        KvCommand::Status(status) => run_status(status).await,
        KvCommand::Checkpoint(checkpoint) => run_checkpoint(checkpoint).await,
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
        Some(m) if m.rolled_back_to_generation.is_some() => {
            // v0.11.0 F2 manifest-rollback shape (UX C2): LEAD with the lossless verdict and SUPPRESS
            // the version-0-SST "no recovery of acked pairs" NOTE unless a real WAL-tail drop occurred.
            let generation = m.rolled_back_to_generation.unwrap_or_default();
            let wal_tail_dropped = !m.quarantined_ids.is_empty();
            if wal_tail_dropped {
                println!(
                    "kv status: RECOVERED — auto-rolled-back to manifest gen {generation}; a torn WAL \
                     tail beyond the frontier was ALSO quarantined (a bounded, forensic-only loss)."
                );
            } else {
                println!(
                    "kv status: RECOVERED (lossless) — auto-rolled-back to manifest gen {generation}; \
                     zero acked loss (N-1 + WAL replay = a normal open)."
                );
            }
            println!("  recovered at (unix):        {}", m.stamp);
            println!("  frontier_source:            {}", m.frontier_source);
            println!("  last_durable_seq:           {}", m.frontier);
            println!("  rolled back to generation:  {generation}");
            println!(
                "  quarantined manifest ids:   {:?}",
                m.quarantined_manifest_ids
            );
            println!("  manifest-quarantine dir:    {}", m.quarantine_dir);
            if !m.orphaned_nonacked_objects.is_empty() {
                println!(
                    "  reclaimable orphaned SST(s): {:?} (SPACE only, NOT loss — the reopened store's \
                     GC reclaims them)",
                    m.orphaned_nonacked_objects
                );
            }
            if wal_tail_dropped {
                println!("  quarantined WAL ids:        {:?}", m.quarantined_ids);
                println!("  loss window:                {}", m.loss_window);
                println!(
                    "  NOTE: the ADDITIONALLY quarantined torn WAL tail preserves raw bytes for \
                     FORENSICS ONLY — no supported recovery of acked pairs from a torn version-0 SST."
                );
            }
            println!("  Acknowledge with `boatramp kv status --ack` once reviewed.");
        }
        Some(m) => {
            println!("kv status: DEGRADED (a self-heal-on-open quarantined a torn WAL tail)");
            println!("  self-healed at (unix): {}", m.stamp);
            println!("  frontier_source:       {}", m.frontier_source);
            println!("  last_durable_seq:      {}", m.frontier);
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

async fn run_checkpoint(args: CheckpointArgs) -> Result<(), Error> {
    if args.live {
        return run_checkpoint_live(&args).await;
    }
    run_checkpoint_offline(args.addr).await
}

/// `kv checkpoint --live` (UX C6) — the client verb over `POST /api/kv-checkpoint` (System·Admin):
/// advance the RUNNING daemon's durable frontier WITHOUT stopping it, then the operator can snapshot a
/// bootable volume of the live node. The URL comes from `--server`, else `[deploy].server` /
/// `BOATRAMP_SERVER`; the control-plane token comes from the config / `BOATRAMP_TOKEN`.
async fn run_checkpoint_live(args: &CheckpointArgs) -> Result<(), Error> {
    use crate::client;
    // `kv` runs before the project config is loaded (a store needing repair may predate a valid
    // config), so load `project.cfg` here best-effort — a missing file is the default, and an explicit
    // `--server` + `BOATRAMP_TOKEN` still work without a config file.
    let config = crate::config::ProjectConfig::load(std::path::Path::new("project.cfg"), None)
        .unwrap_or_default();
    let server = client::resolve_server(args.server.clone(), &config)?;
    let cp = client::ControlPlane::new(
        server.clone(),
        client::http_client(client::token(&config).as_deref()),
        client::resolve_project(&config),
    );
    let msg = cp.kv_checkpoint().await?;
    print!("kv checkpoint --live (server {server}): {msg}");
    if !msg.ends_with('\n') {
        println!();
    }
    Ok(())
}

async fn run_checkpoint_offline(addr: StoreAddr) -> Result<(), Error> {
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
    // MF3 (v0.11.0) — the in-place recovery must REFUSE on a cluster node-local Raft store, mirroring
    // the `serve --repair-wal` cluster refusal (serve.rs). `kv recover` addresses `<data-dir>/kv-slate`,
    // never `<data-dir>/raft`; a co-located cluster deployment (a `raft/`/`mesh/` store beside the
    // target) marks this as a cluster node, and a cluster node recovers by failing loud then REJOINING
    // peers (which re-replicate the authoritative log), NOT by auto-quarantining/manifest-recovering its
    // node-local store (which could regress below the committed index → double-vote / log↔SM desync).
    if !args.addr.kv_s3 && is_cluster_node_data_dir(&args.addr.data_dir) {
        return Err(Error::Store(format!(
            "REFUSING in-place recovery: `{}` looks like a CLUSTER node data dir (a `raft/`/`mesh/` \
             store is present). A cluster node NEVER self-recovers its node-local Raft store — that \
             could regress below the committed index (double-vote / log↔state-machine desync). Recover \
             by wiping this node's store and REJOINING peers (which re-replicate the authoritative \
             log): stop the node, remove its data dir, and restart with `--cluster-join <ticket>`.",
            args.addr.data_dir.display()
        )));
    }
    let (store, root) = args.addr.build()?;
    let mode = if args.apply {
        RepairMode::Apply
    } else {
        RepairMode::DryRun
    };
    // Shape detection (UX C4/C5): the empty/torn LATEST manifest shape (v0.11.0 F2) vs the WAL-tail
    // shape. `recover_last_good_manifest` returns `LatestReadable` (a no-op) when the manifest is
    // readable, so we fall through to the ordinary WAL-tail `kv repair` superset; `RolledBack` when the
    // latest manifest is empty/torn and it (would, dry-run) roll back to the last-good generation.
    match recover_last_good_manifest(&store, &root, mode).await {
        Ok(ManifestRecovery::LatestReadable { .. }) => {
            // The latest manifest is readable — the ordinary in-place WAL-tail path (unchanged): the
            // SUPERSET of `kv repair`, with the shape-split escalation to `--adopt-volume` (C10).
            match repair_wal_tail(&store, &root, mode).await {
                Ok(report) => {
                    print_report(&report, args.apply);
                    if !args.apply && !report.quarantined.is_empty() {
                        println!(
                            "\nRe-run `boatramp kv recover --apply` to quarantine the safe trailing \
                             tail in place (the crashed torn bytes are retained under `wal-quarantine/` \
                             for forensics)."
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
        Ok(ManifestRecovery::RolledBack(report)) => {
            // The empty/torn LATEST manifest shape (UX C5): the dry-run WORKS (prints the fallback
            // plan) and `--apply` rolls back to the last-good generation in place, non-destructively
            // (the torn manifest bytes are retained under `manifest-quarantine/` until verify).
            print_manifest_recovery(&report, args.apply);
            if !args.apply {
                println!(
                    "\nRe-run `boatramp kv recover --apply` to roll back to the last-good manifest \
                     generation in place (lossless-for-acked; the torn manifest bytes are retained \
                     under `manifest-quarantine/` for forensics)."
                );
            }
            Ok(())
        }
        Err(e) => {
            // A manifest shape F2 REFUSED (no decodable generation, a WAL GC hole, below the GC
            // boundary). Name the refusal, then point at the clean-snapshot escalation (UX C4).
            eprintln!("kv recover: manifest recovery cannot proceed — {e}");
            print_adopt_volume_guidance();
            Err(e.into())
        }
    }
}

/// Whether `data_dir` belongs to a CLUSTER node — a `raft/` node-local durable store or a `mesh/`
/// identity dir sits beside the control-plane target (see `serve::run_cluster`). Used by
/// [`run_recover`] to refuse an in-place recovery on a cluster node (MF3): a cluster recovers by
/// rejoining peers, never by self-recovering its node-local Raft store.
fn is_cluster_node_data_dir(data_dir: &std::path::Path) -> bool {
    data_dir.join("raft").is_dir() || data_dir.join("mesh").is_dir()
}

/// Print the last-good-generation manifest-recovery plan / outcome (v0.11.0 F2).
fn print_manifest_recovery(report: &ManifestRecoveryReport, applied: bool) {
    println!(
        "control-plane MANIFEST recovery {}",
        if applied {
            "(APPLY)"
        } else {
            "(DRY-RUN — no mutation)"
        }
    );
    println!(
        "  the LATEST manifest is empty/torn — rolling back to the last-good manifest generation."
    );
    println!(
        "  fall back to manifest generation: {}",
        report.rolled_back_to_generation
    );
    println!(
        "  durable frontier (replay_after_wal_id) at that generation: {}",
        report.frontier
    );
    if report.quarantined_manifest_ids.is_empty() {
        println!("  torn manifest generation(s) to quarantine: (none)");
    } else {
        let ids: Vec<String> = report
            .quarantined_manifest_ids
            .iter()
            .map(|id| format!("{id:020}"))
            .collect();
        println!(
            "  torn manifest generation(s) to quarantine (retained under manifest-quarantine/): [{}]",
            ids.join(", ")
        );
    }
    // The embedded WAL-tail sub-plan at F: for the pure last-good-generation rollback this is empty
    // (discard = none, lossless-for-acked); a crash that ALSO tore a WAL tail beyond F shows it here.
    if report.wal_repair.quarantined.is_empty() {
        println!(
            "  WAL tail beyond the frontier to discard: none (discard = none — lossless-for-acked)."
        );
    } else {
        let ids: Vec<String> = report
            .wal_repair
            .quarantined
            .iter()
            .map(|id| format!("{id:020}"))
            .collect();
        println!(
            "  ADDITIONALLY a torn WAL tail beyond the frontier would be quarantined [{}] — those \
             bytes are FORENSIC-ONLY (no supported recovery of acked pairs from a torn version-0 SST).",
            ids.join(", ")
        );
    }
    if !report.orphaned_nonacked_objects.is_empty() {
        println!(
            "  reclaimable orphaned L0 SST(s) (SPACE only, NOT loss): {:?}",
            report.orphaned_nonacked_objects
        );
    }
    if applied {
        println!(
            "  RECOVERED (lossless): rolled back to generation {} and replayed the WAL forward — the \
             store now opens with zero acked loss (N-1 + WAL replay = a normal open). The torn manifest \
             bytes are retained under `{}` for forensics.",
            report.rolled_back_to_generation,
            report
                .manifest_quarantine_dir
                .as_deref()
                .unwrap_or("<none>")
        );
    } else {
        println!(
            "  WOULD roll back to generation {} (lossless-for-acked; discard = none).",
            report.rolled_back_to_generation
        );
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

    // 1. VALIDATE the attached volume BEFORE adopting — WITHOUT mutating it (Security L3): the
    //    operator's snapshot must stay byte-pristine. So the source is only ever READ here: a
    //    read-only whole-store torn scan (`repair_wal_tail` DryRun = list + get_range only, never a
    //    write). We deliberately do NOT open the source as a writer (a `Db` open takes the writer
    //    fence + writes a manifest) NOR as a `DbReader` (which `write_checkpoint`s a reader
    //    checkpoint into the manifest on open) — both would mutate the pristine snapshot. The
    //    DEFINITIVE real-open bootability verify runs later on the COPY (never the source), so a
    //    truncated edge the footer probe misses is still caught (and rolled back) at `--apply`.
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

    // 2. Discard-delta: adopting the snapshot DISCARDS the crashed store's post-snapshot writes.
    println!(
        "adopt-volume: the attached store at `{}` passes the whole-store torn scan (ZERO torn) — \
         validated READ-ONLY, the snapshot is left byte-pristine.\n  \
         Adopting REPLACES the crashed store at `{}` with a COPY of the snapshot (a definitive \
         real-open bootability verify then runs on the copy, never the source).\n  \
         DISCARD-DELTA: every write in the crashed store made AFTER the snapshot's point-in-time is \
         LOST (a snapshot is a point-in-time copy; boatramp cannot merge the crashed WAL into it).\n  \
         The crashed copy is RETAINED (renamed aside) until the adopt is verified serving.",
        volume_dir.display(),
        target_dir.display()
    );
    if !apply {
        println!(
            "\nDRY-RUN: re-run with `--apply` to adopt (copy → verify-open the COPY → swap, retaining \
             the crashed copy). The source snapshot is never mutated."
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
