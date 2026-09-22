//! `boatramp project migrate` — a client for the owner-gated schema-migration API
//! (`/api/{project-seg}/migrate/{db}/{apply,dry-run,baseline,status}`, added server-side in
//! 0.4.x). Migrations run server-side as the project's non-superuser OWNER role; the mutating
//! verbs (`apply` / `dry-run` / `baseline`) need a **`Project·Admin`** token, `status` only
//! `Project·Read`. It is deliberately *not* the top-level `boatramp migrate` (that re-keys a
//! pre-0.2.0 control-plane store) — schema migrations are a project-scoped admin operation, so
//! they live under `project`.
//!
//! Upload-then-trigger: the step-set **manifest** — a JSON document `{ "steps": [ … ] }`, each
//! step declaring exactly one of a `function` (a wasm component doing DDL as the owner role),
//! raw `sql`, or an allowlisted `extension` — is uploaded as a content-addressed blob and then
//! referenced by hash, so a large/binary step-set never rides the request body.

use std::path::PathBuf;

use clap::Subcommand;

use crate::client::ControlPlane;

/// A failure in `boatramp project migrate`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Uploading the bundle or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Rendering the `--json` output failed.
    #[error("rendering the migration result failed: {0}")]
    Render(#[source] serde_json::Error),
    /// A migration step failed server-side (the prefix before it stays applied). The full
    /// report was already printed; this makes the process exit non-zero so scripts can gate.
    #[error("migration step `{id}` failed: {error}")]
    StepFailed {
        /// The failing step's id.
        id: String,
        /// The sanitized failure reason from the server.
        error: String,
    },
}

/// `project_migrate` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp project migrate`.
#[derive(Debug, clap::Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    command: MigrateCommand,
}

#[derive(Debug, Subcommand)]
enum MigrateCommand {
    /// Apply every pending step in a manifest, in order (`Project·Admin`). Already-recorded
    /// steps are skipped (idempotent); application halts at the first failure, leaving the
    /// prefix before it applied.
    Apply {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        /// The step-set manifest: a JSON document `{ "steps": [ { "id": "…", … } ] }`.
        #[arg(long, short = 'f')]
        file: PathBuf,
        /// Emit the raw `MigrationReport` JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
    /// Preview which steps a manifest WOULD apply, running nothing (`Project·Admin`).
    DryRun {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        /// The step-set manifest (see `apply`).
        #[arg(long, short = 'f')]
        file: PathBuf,
        /// Emit the raw `MigrationReport` JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
    /// Record a manifest's prefix as already-applied WITHOUT running it — adopt a
    /// pre-existing / populated database (`Project·Admin`). `--up-to <id>` records through that
    /// id inclusive; omitted baselines the entire set.
    Baseline {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        /// The step-set manifest (see `apply`).
        #[arg(long, short = 'f')]
        file: PathBuf,
        /// Baseline the prefix through (and including) this step id; omit for the whole set.
        #[arg(long)]
        up_to: Option<String>,
        /// Emit the raw `MigrationReport` JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
    /// Show the applied-migration ledger, in order (`Project·Read`).
    Status {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        /// Emit the raw `MigrationStatus` JSON instead of a human table.
        #[arg(long)]
        json: bool,
    },
}

/// Entry point for `boatramp project migrate`, driven off the already-connected
/// [`ControlPlane`] (the parent `project` command resolves `--server`, the token, and the
/// active `--project`, whose segment selects the target project's migrate surface).
pub async fn run(args: MigrateArgs, cp: &ControlPlane) -> Result<()> {
    match args.command {
        MigrateCommand::Apply { db, file, json } => {
            let bundle = cp.put_file_blob(&file).await?;
            let report = cp.migrate_trigger(&db, "apply", &bundle, None).await?;
            render_report(&report, json)?;
            fail_if_step_failed(report)?;
        }
        MigrateCommand::DryRun { db, file, json } => {
            let bundle = cp.put_file_blob(&file).await?;
            let report = cp.migrate_trigger(&db, "dry-run", &bundle, None).await?;
            render_report(&report, json)?;
            // A dry-run never fails a pending step, but a bundle-level failure still surfaces.
            fail_if_step_failed(report)?;
        }
        MigrateCommand::Baseline {
            db,
            file,
            up_to,
            json,
        } => {
            let bundle = cp.put_file_blob(&file).await?;
            let report = cp
                .migrate_trigger(&db, "baseline", &bundle, up_to.as_deref())
                .await?;
            render_report(&report, json)?;
            fail_if_step_failed(report)?;
        }
        MigrateCommand::Status { db, json } => {
            let status = cp.migrate_status(&db).await?;
            render_status(&status, json)?;
        }
    }
    Ok(())
}

/// Render a [`MigrationReport`](boatramp_core::sql::MigrationReport): pretty JSON under
/// `--json`, else a compact per-bucket human summary with each id's `kind`.
fn render_report(report: &boatramp_core::sql::MigrationReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).map_err(Error::Render)?
        );
        return Ok(());
    }
    print_ids("applied", &report.newly_applied, &report.kinds);
    print_ids("already applied", &report.already_applied, &report.kinds);
    print_ids("pending", &report.pending, &report.kinds);
    if let Some(failure) = &report.failed {
        let kind = report
            .kinds
            .get(&failure.id)
            .map(String::as_str)
            .unwrap_or("?");
        println!("FAILED at `{}` [{kind}]: {}", failure.id, failure.error);
    }
    if report.newly_applied.is_empty()
        && report.already_applied.is_empty()
        && report.pending.is_empty()
        && report.failed.is_none()
    {
        println!("nothing to do");
    }
    Ok(())
}

/// Print one labelled bucket of migration ids (each annotated with its `kind`), skipping an
/// empty bucket so the summary stays terse.
fn print_ids(label: &str, ids: &[String], kinds: &std::collections::BTreeMap<String, String>) {
    if ids.is_empty() {
        return;
    }
    println!("{label} ({}):", ids.len());
    for id in ids {
        let kind = kinds.get(id).map(String::as_str).unwrap_or("?");
        println!("  {id} [{kind}]");
    }
}

/// Render a [`MigrationStatus`](boatramp_core::sql::MigrationStatus): pretty JSON under
/// `--json`, else an ordinal-ordered table (`# id kind origin applied_at`).
fn render_status(status: &boatramp_core::sql::MigrationStatus, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(status).map_err(Error::Render)?
        );
        return Ok(());
    }
    if status.applied.is_empty() {
        println!("no migrations applied");
        return Ok(());
    }
    println!(
        "{:<4} {:<28} {:<10} {:<9} applied_at",
        "#", "id", "kind", "origin"
    );
    for m in &status.applied {
        println!(
            "{:<4} {:<28} {:<10} {:<9} {}",
            m.ordinal, m.id, m.kind, m.origin, m.applied_at
        );
    }
    Ok(())
}

/// Turn a report whose `failed` step is set into a non-zero exit (the report was already
/// rendered), so `apply` in a deploy script halts the pipeline on a failed migration.
fn fail_if_step_failed(report: boatramp_core::sql::MigrationReport) -> Result<()> {
    if let Some(failure) = report.failed {
        return Err(Error::StepFailed {
            id: failure.id,
            error: failure.error,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::sql::{
        AppliedMigration, MigrationFailure, MigrationReport, MigrationStatus,
    };
    use clap::Parser;

    /// A minimal top-level parser mirroring `main`'s `project migrate` nesting, so the flag
    /// surface can be arg-parsed in isolation.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Migrate(MigrateArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<MigrateCommand, clap::Error> {
        let cli = Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))?;
        let Cmd::Migrate(args) = cli.cmd;
        Ok(args.command)
    }

    #[test]
    fn apply_and_baseline_flags_parse() {
        // `apply -f file` with the default db + no --json.
        match parse(&["migrate", "apply", "-f", "m.json"]) {
            Ok(MigrateCommand::Apply { db, file, json }) => {
                assert_eq!(db, "");
                assert_eq!(file, PathBuf::from("m.json"));
                assert!(!json);
            }
            other => panic!("expected apply, got {other:?}"),
        }
        // `dry-run` is the kebab-cased `DryRun` variant.
        assert!(matches!(
            parse(&["migrate", "dry-run", "--db", "main", "-f", "m.json", "--json"]),
            Ok(MigrateCommand::DryRun { .. })
        ));
        // `baseline --up-to` carries the id.
        match parse(&[
            "migrate",
            "baseline",
            "-f",
            "m.json",
            "--up-to",
            "0003_seed",
        ]) {
            Ok(MigrateCommand::Baseline { up_to, .. }) => {
                assert_eq!(up_to.as_deref(), Some("0003_seed"));
            }
            other => panic!("expected baseline, got {other:?}"),
        }
        // `status --db main`.
        match parse(&["migrate", "status", "--db", "main"]) {
            Ok(MigrateCommand::Status { db, json }) => {
                assert_eq!(db, "main");
                assert!(!json);
            }
            other => panic!("expected status, got {other:?}"),
        }
        // `apply` requires the manifest file.
        assert!(parse(&["migrate", "apply"]).is_err());
    }

    #[test]
    fn a_failed_step_is_a_non_zero_exit() {
        let clean = MigrationReport {
            newly_applied: vec!["0001_init".into()],
            ..MigrationReport::default()
        };
        assert!(fail_if_step_failed(clean).is_ok());

        let failed = MigrationReport {
            newly_applied: vec!["0001_init".into()],
            failed: Some(MigrationFailure {
                id: "0002_add_col".into(),
                error: "relation already exists".into(),
            }),
            ..MigrationReport::default()
        };
        match fail_if_step_failed(failed) {
            Err(Error::StepFailed { id, error }) => {
                assert_eq!(id, "0002_add_col");
                assert!(error.contains("already exists"));
            }
            other => panic!("expected StepFailed, got {other:?}"),
        }
    }

    #[test]
    fn renderers_are_infallible_on_representative_payloads() {
        // Exercise the human + JSON paths so a formatting panic would be caught.
        let report = MigrationReport {
            newly_applied: vec!["0001_init".into()],
            already_applied: vec!["0000_base".into()],
            pending: vec![],
            failed: None,
            kinds: [
                ("0001_init".to_string(), "sql".to_string()),
                ("0000_base".to_string(), "function".to_string()),
            ]
            .into_iter()
            .collect(),
        };
        render_report(&report, false).unwrap();
        render_report(&report, true).unwrap();
        render_report(&MigrationReport::default(), false).unwrap();

        let status = MigrationStatus {
            applied: vec![AppliedMigration {
                id: "0001_init".into(),
                ordinal: 0,
                content_hash: "abc".into(),
                kind: "sql".into(),
                applied_at: "2026-09-22T00:00:00Z".into(),
                origin: "apply".into(),
            }],
        };
        render_status(&status, false).unwrap();
        render_status(&status, true).unwrap();
        render_status(&MigrationStatus::default(), false).unwrap();
    }
}
