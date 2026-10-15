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
    /// Reading the operator's input during an interactive migration failed.
    #[error("interactive migration: {0}")]
    Interactive(String),
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

    /// Abort a staged (dual-soak) migration, rolling the store back to its exact pre-forward bytes —
    /// the reverse of a `stage`. OFFLINE (run with the node stopped). Fail-closed: refuses, deleting
    /// nothing, if any staged key received a write during the soak (that write would be lost); finalize
    /// forward instead, or reconcile manually. (libsql: abort removes the re-homed COPY; the retained
    /// bare DB is the rollback target — see docs/default-scope-migration.md.)
    #[arg(long, conflicts_with_all = ["dry_run", "stage", "finalize"])]
    abort: bool,

    /// Interactive (question-driven) migration: show the plan, PROMPT at each decision point (a
    /// name collision → rename / skip / abort), then stage honoring your answers. The guided CLI flow
    /// over the same `plan` + apply engine the console wizard uses. OFFLINE (node stopped).
    #[arg(long, short = 'i', conflicts_with_all = ["dry_run", "stage", "finalize", "abort"])]
    interactive: bool,

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

    // ABORT: roll a staged (dual-soak) migration back to the pre-migration layout. Prints what it did,
    // flushes, and re-prints the resulting status.
    if args.abort {
        migrate::abort(kv.as_ref()).await?;
        println!(
            "aborted the staged migration — the store is rolled back to its pre-migration layout \
             (old keys only); a prior binary can serve it, and `boatramp migrate` can re-stage it."
        );
        kv.flush().await.map_err(|e| Error::Flush(e.to_string()))?;
        println!("now: {}", describe(migrate::status(kv.as_ref()).await?));
        return Ok(());
    }

    // INTERACTIVE: the question-driven flow (plan → prompt decisions → stage honoring the answers).
    if args.interactive {
        interactive_migrate(kv.as_ref()).await?;
        kv.flush().await.map_err(|e| Error::Flush(e.to_string()))?;
        return Ok(());
    }

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

/// The interactive (question-driven) migration flow: show the plan, prompt the operator at each
/// decision (a name collision → rename / skip / abort), and stage honoring the answers. The CLI half
/// of the interactive migration — it drives the SAME `migrate::plan` + `migrate_with_answers` engine
/// the console wizard uses, so the two surfaces can never diverge. Thin stdin/stdout glue; the engine
/// logic (skip/abort/refuse) is unit-tested in `boatramp-core`.
async fn interactive_migrate(kv: &dyn boatramp_core::kv::KvStore) -> Result<(), Error> {
    let plan = migrate::plan(kv).await?;
    match plan.status {
        Status::Ready => {
            println!("nothing to do: the store is already at the current layout.");
            return Ok(());
        }
        Status::Dual => {
            println!(
                "the store is already staged (dual soak). Re-home the blob + libsql substrates, then \
                 `boatramp migrate --finalize` to complete it — or `boatramp migrate --abort` to roll \
                 it back."
            );
            return Ok(());
        }
        Status::NeedsMigration => {}
    }

    println!("\nPlan — re-home the default project to the project-scoped layout:");
    for line in &plan.summary {
        println!("  • {line}");
    }

    // Collect a route per decision.
    let mut answers = migrate::MigrationAnswers::default();
    let mut pending_renames: Vec<String> = Vec::new();
    for d in &plan.decisions {
        println!("\n{}", d.question);
        for (i, r) in d.routes.iter().enumerate() {
            println!("  {}) {}", i + 1, r.label);
            if let Some(note) = &r.note {
                println!("     ({note})");
            }
        }
        let chosen = prompt_route(d)?;
        match chosen.key.as_str() {
            "abort" => {
                println!("\naborting the migration — nothing was changed.");
                return Ok(());
            }
            "skip" => answers.skip_collisions.push(d.id.clone()),
            "rename" => {
                let prompt = chosen
                    .input
                    .as_ref()
                    .map(|i| i.prompt.as_str())
                    .unwrap_or("new name");
                let new_name = prompt_line(&format!("  {prompt}: "))?;
                let resource = d.id.strip_prefix("collision:").unwrap_or(&d.id);
                pending_renames.push(format!(
                    "{resource}: re-create it as `{new_name}` via the normal deploy flow (e.g. \
                     redeploy the site under the new name), then delete the old `{resource}`"
                ));
            }
            other => {
                return Err(Error::Interactive(format!("unexpected route `{other}`")));
            }
        }
    }

    // Any rename must be done externally (through the proven deploy path) BEFORE staging — print the
    // guidance and stop; the operator re-runs once the collisions are gone.
    if !pending_renames.is_empty() {
        println!(
            "\nResolve these renames first, then re-run `boatramp migrate --interactive` (the \
             collision clears once the resource no longer shares a name):"
        );
        for step in &pending_renames {
            println!("  • {step}");
        }
        return Ok(());
    }

    if !prompt_yes(
        "\nProceed to STAGE the re-home now (non-destructive; reversible with --abort)?",
    )? {
        println!("cancelled.");
        return Ok(());
    }

    match migrate::migrate_with_answers(kv, &answers).await? {
        migrate::InteractiveOutcome::Aborted => println!("aborted — nothing was changed."),
        migrate::InteractiveOutcome::Staged(report) => {
            print_report(&report, false);
            println!(
                "\nStaged into the dual soak. NEXT:\n  \
                 1. RESTART the node so it adopts the new layout (a running daemon keeps serving the \
                 OLD layout until restarted).\n  \
                 2. Re-home the other substrates: `boatramp sql rehome-default` + `boatramp blob \
                 rehome`.\n  \
                 3. `boatramp migrate --finalize` to reclaim the old keys (gated until step 2).\n  \
                 Reversible until finalize: `boatramp migrate --abort`."
            );
        }
    }
    Ok(())
}

/// Prompt the operator to choose one of a decision's routes (by number or by key); re-prompts on an
/// invalid entry. EOF/`q` is treated as a cancel (maps to the `abort` route if present, else errors).
fn prompt_route(d: &migrate::MigrationDecision) -> Result<&migrate::DecisionRoute, Error> {
    loop {
        let line = prompt_line("  choose [number or name]: ")?;
        let line = line.trim();
        if let Ok(n) = line.parse::<usize>()
            && n >= 1
            && n <= d.routes.len()
        {
            return Ok(&d.routes[n - 1]);
        }
        if let Some(r) = d.routes.iter().find(|r| r.key.eq_ignore_ascii_case(line)) {
            return Ok(r);
        }
        println!("  (please enter 1–{} or a route name)", d.routes.len());
    }
}

/// Read one line from stdin after printing `prompt`.
fn prompt_line(prompt: &str) -> Result<String, Error> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout()
        .flush()
        .map_err(|e| Error::Interactive(e.to_string()))?;
    let mut line = String::new();
    let n = std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::Interactive(e.to_string()))?;
    if n == 0 {
        return Err(Error::Interactive("unexpected end of input".to_string()));
    }
    Ok(line)
}

/// A yes/no confirmation (default NO).
fn prompt_yes(question: &str) -> Result<bool, Error> {
    let line = prompt_line(&format!("{question} [y/N] "))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
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
