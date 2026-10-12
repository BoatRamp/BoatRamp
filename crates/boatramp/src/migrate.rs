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
    /// Loading the `--node-config` for the `--finalize` substrate gate failed.
    #[error(transparent)]
    Config(#[from] boatramp_node::config::ConfigError),
    /// A control-plane KV read failed during the `--finalize` substrate gate.
    #[error(transparent)]
    Kv(#[from] boatramp_core::kv::KvError),
    /// `--finalize` is blocked (v0.31.0 Finding 8, HIGH-2c): clearing the KV dual soak would
    /// disengage the runtime blob read-fallback, so the blob + libsql substrates must be re-homed
    /// first. Reports which remains.
    #[error(
        "refusing `--finalize`: the default-scope re-home is not substrate-complete — {reason}. \
         Clearing the KV dual soak now would disengage the blob read-fallback and strand data. \
         Complete `boatramp blob rehome --finalize` + `boatramp sql rehome-default`, then re-run. \
         See docs/default-scope-migration.md."
    )]
    FinalizeNotSubstrateComplete {
        /// What is still outstanding (libsql bare DBs and/or the blob-retired marker).
        reason: String,
    },
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

    /// Copy + verify, keeping the old-layout keys for a soak/rollback window (the `dual` state).
    /// v0.31.0: this is now the DEFAULT behavior (the default-scope re-home MUST soak so the
    /// translating blob read-fallback engages), so the flag is accepted for clarity/compat but the
    /// forward pass always stages — a later `--finalize` reclaims the old keys.
    #[arg(long, conflicts_with_all = ["dry_run", "finalize"])]
    stage: bool,

    /// Delete the old-layout keys left by the staged forward pass, completing the migration. For the
    /// default-scope re-home (v0.31.0 Finding 8) this REFUSES until the blob + libsql substrates are
    /// re-homed (it reads `--node-config` to check), because clearing the dual soak disengages the
    /// blob read-fallback.
    #[arg(long, conflicts_with = "dry_run")]
    finalize: bool,

    /// Override the fail-closed pre-migration conflict guard (a default-project resource named
    /// `default`, or like a known project): proceed with the re-home anyway — that resource's
    /// default-scoped data will NOT be re-homed. Only set this if you understand the consequence.
    #[arg(long)]
    allow_default_named_resource: bool,

    /// Node config (`boatramp.cfg` shape) used by `--finalize` to locate the libsql dir (+ the blob
    /// retired marker) for the substrate-complete gate. Defaults to `boatramp.cfg`.
    #[arg(long, default_value = "boatramp.cfg")]
    node_config: PathBuf,
}

/// Run the `migrate` command.
pub async fn run(args: MigrateArgs, config: &ServerConfig) -> Result<(), Error> {
    let data_dir = args
        .data_dir
        .clone()
        .or_else(|| config.serve.as_ref().and_then(|s| s.data_dir.clone()))
        .unwrap_or_else(|| PathBuf::from("./data"));

    // The pre-0.2.0 → project-scoped re-key is a local-store migration (a fresh
    // remote-state deploy has no layout-1 store), so open the local SlateDB. Open STRICT here
    // (v0.9.0 KV-recovery): a migration is a re-key, not a crash recovery — a torn tail must fail
    // loud so the operator recovers the store FIRST (`boatramp kv recover`), never auto-quarantine
    // mid-migration.
    let kv = build_control_plane_kv(
        args.kv,
        &data_dir,
        None,
        boatramp_core::kv::KvOpenPolicy::Strict,
        // `migrate` is a SlateDB-store re-key, not a SQL target — no `[serve.kv.sql]` config.
        None,
    )
    .await
    .map_err(|e| Box::new(crate::serve::Error::from(e)))?;

    println!(
        "control-plane store ({:?} at {}): {}",
        args.kv,
        data_dir.display(),
        describe(migrate::status(kv.as_ref()).await?)
    );

    let report = if args.finalize {
        // Substrate-complete gate (Finding 8, HIGH-2c): clearing the KV dual soak disengages the
        // runtime blob read-fallback, so refuse until blob (the marker `blob rehome --finalize` sets)
        // AND libsql (a cheap on-disk scan) are re-homed.
        finalize_substrate_gate(kv.as_ref(), &args.node_config, &data_dir).await?;
        migrate::finalize(kv.as_ref()).await?
    } else {
        // FORCE STAGE (Finding 8, HIGH-2a): the default-scope re-home MUST enter the dual soak so the
        // translating blob read-fallback engages (a one-shot would strand cold default blobs). So the
        // forward pass never inline-finalizes; `--finalize` (gated above) reclaims the old keys.
        migrate::migrate(
            kv.as_ref(),
            MigrateOptions {
                dry_run: args.dry_run,
                finalize: false,
                allow_default_named_resource: args.allow_default_named_resource,
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

/// The substrate-complete gate for `--finalize` (v0.31.0 Finding 8, HIGH-2c): clearing the KV dual
/// soak disengages the runtime blob read-fallback, so refuse until BOTH the blob substrate is retired
/// (the marker `boatramp blob rehome --finalize` sets) AND the default-project libsql is re-homed (no
/// bare `{dir}/*.db`). A remote sqld libsql binding (no local dir) is a documented operator step and
/// is not gated here. Reports every outstanding substrate at once.
async fn finalize_substrate_gate(
    kv: &dyn boatramp_core::kv::KvStore,
    node_config: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<(), Error> {
    let node_cfg = boatramp_node::config::ServerConfig::load(node_config, None)?;
    let mut outstanding: Vec<String> = Vec::new();

    // libsql: a cheap on-disk scan of the node's libsql dir (local bindings only). Use the SAME
    // run-level `data_dir` the serve guard + `assemble` use (honoring `--data-dir`), NOT
    // `node_cfg.serve.data_dir` — a `--data-dir`-overridden node keeps its DBs under the override.
    if let Some(dir) = boatramp_node::default_scope::libsql_dir_for(&node_cfg, data_dir) {
        let projects = boatramp_node::default_scope::known_projects(kv).await?;
        let bare = boatramp_node::default_scope::libsql_bare_default_idents(&dir, &projects);
        if !bare.is_empty() {
            outstanding.push(format!(
                "libsql not re-homed ({bare:?}) — run `boatramp sql rehome-default --site <site>`"
            ));
        }
    }
    // blob: require the marker `blob rehome --finalize` sets once the blob substrate is verified
    // retired (a node with no blob data still sets it by running that command once — a 0-object pass).
    if kv
        .get(boatramp_node::default_scope::BLOB_RETIRED_MARKER)
        .await?
        .is_none()
    {
        outstanding.push(
            "blob not verified-retired — run `boatramp blob rehome` (drain) then `boatramp blob \
             rehome --finalize` (retire)"
                .to_string(),
        );
    }

    if outstanding.is_empty() {
        Ok(())
    } else {
        Err(Error::FinalizeNotSubstrateComplete {
            reason: outstanding.join("; "),
        })
    }
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
