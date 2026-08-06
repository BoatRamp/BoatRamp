//! The `boatramp migrate` command: re-key a pre-0.2.0 (layout 1) control-plane store
//! to the project-scoped (0.2.0) layout, **offline** — the server refuses to serve an
//! unmigrated store (see the serve-startup guard), so this is the explicit,
//! operator-run step that unblocks it.
//!
//! The engine lives in [`boatramp_core::migrate`]; this wires it to the same KV store
//! `serve` opens (`--kv` / `--data-dir` must match). Supports a `--dry-run` audit, a
//! `--stage` copy-only pass (leaving the old keys for a soak/rollback window), and a
//! `--finalize` pass that deletes the staged old keys.

use std::path::PathBuf;

use boatramp_core::migrate::{self, MigrateOptions, MigrationReport, Status};

use crate::config::ServerConfig;
use crate::serve::build_control_plane_kv;
use boatramp_node::backends::KvBackend;

/// Errors from the `migrate` command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Opening the control-plane KV store failed (delegated to the serve backend
    /// builder, so the same `--kv`/feature guidance applies).
    #[error(transparent)]
    Store(#[from] Box<crate::serve::Error>),
    /// The migration engine failed.
    #[error(transparent)]
    Migrate(#[from] boatramp_core::migrate::MigrateError),
    /// Flushing the migrated store to durable storage failed.
    #[error("flushing the migrated store failed: {0}")]
    Flush(String),
}

/// `boatramp migrate` arguments.
#[derive(Debug, clap::Args)]
pub struct MigrateArgs {
    /// Data directory (flag/env > `[serve].data_dir` > `./data`). Must match `serve`.
    #[arg(long, env = "BOATRAMP_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Metadata (KV) backend. Must match `serve`.
    #[arg(long, value_enum, default_value_t = KvBackend::Slatedb)]
    kv: KvBackend,

    /// Report what the migration would change, writing nothing.
    #[arg(long)]
    dry_run: bool,

    /// Copy + verify + rewrite domain values, but keep the old-layout keys for a
    /// soak/rollback window (the `2-dual` state). A later `--finalize` deletes them.
    /// Without this the migration is one-shot (copy then delete).
    #[arg(long, conflicts_with_all = ["dry_run", "finalize"])]
    stage: bool,

    /// Delete the old-layout keys left by an earlier `--stage` run, completing the
    /// migration to layout 2.
    #[arg(long, conflicts_with = "dry_run")]
    finalize: bool,
}

/// Run the `migrate` command.
pub async fn run(args: MigrateArgs, config: &ServerConfig) -> Result<(), Error> {
    let data_dir = args
        .data_dir
        .clone()
        .or_else(|| config.serve.as_ref().and_then(|s| s.data_dir.clone()))
        .unwrap_or_else(|| PathBuf::from("./data"));

    let kv = build_control_plane_kv(args.kv, &data_dir)
        .await
        .map_err(|e| Box::new(crate::serve::Error::from(e)))?;

    println!(
        "control-plane store ({:?} at {}): {}",
        args.kv,
        data_dir.display(),
        describe(migrate::status(kv.as_ref()).await?)
    );

    let report = if args.finalize {
        migrate::finalize(kv.as_ref()).await?
    } else {
        migrate::migrate(
            kv.as_ref(),
            MigrateOptions {
                dry_run: args.dry_run,
                finalize: !args.stage,
            },
        )
        .await?
    };

    print_report(&report, args.dry_run);

    // Force the migration durable (SlateDB flushes on a timer otherwise) before we
    // exit, so a `serve` started right after sees the completed layout.
    if !args.dry_run {
        kv.flush().await.map_err(|e| Error::Flush(e.to_string()))?;
    }
    Ok(())
}

/// A one-line description of a store's layout status.
fn describe(status: Status) -> &'static str {
    match status {
        Status::Ready => "ready (empty or already at the current schema version)",
        Status::NeedsMigration => "below the current schema version — needs migration",
        Status::Dual => "dual soak (migrated; old keys awaiting `--finalize`)",
    }
}

/// Print a human-readable summary of a migration pass.
fn print_report(report: &MigrationReport, dry_run: bool) {
    if report.already_migrated {
        println!("nothing to do: the store is already fully migrated.");
        return;
    }
    let verb = if dry_run { "would re-key" } else { "re-keyed" };
    if report.rekeyed.is_empty() && report.values_rewritten.is_empty() {
        println!("no layout-1 records found.");
    }
    for (family, n) in &report.rekeyed {
        println!("  {verb} {n} key(s) under {family}");
    }
    for (family, n) in &report.values_rewritten {
        let v = if dry_run { "would rewrite" } else { "rewrote" };
        println!("  {v} {n} {family} index value(s) to the (project, site) form");
    }
    if report.created_default_project {
        let v = if dry_run { "would create" } else { "created" };
        println!("  {v} the `default` project");
    }
    if report.owner_entries > 0 {
        println!(
            "  built {} owner reverse-index entries",
            report.owner_entries
        );
    }
    if dry_run {
        println!("(dry run — nothing was written)");
    } else if report.dual {
        println!(
            "staged to 2-dual — old keys kept; run `boatramp migrate --finalize` to reclaim them."
        );
    } else {
        println!("migration complete: store is at the project-scoped layout.");
    }
}
