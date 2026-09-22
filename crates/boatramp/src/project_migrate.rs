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
//!
//! You give the step set one of two ways: `--file <manifest.json>` (a pre-authored canonical
//! bundle), or `--dir <migrations/>` — a **migrations directory** the CLI assembles into the
//! bundle. In a directory each file is one step; the `id` is its name minus the kind suffix, and
//! steps apply in **lexicographic filename order** (zero-pad your prefixes). The suffix picks the
//! kind, so nothing is silently miscategorized:
//!
//! | file                         | step                                                       |
//! |------------------------------|------------------------------------------------------------|
//! | `0001_init.sql`              | `sql` (file body is the script)                            |
//! | `0002_orders_idx.notx.sql`   | `sql` with `no_transaction` (e.g. `CREATE INDEX CONCURRENTLY`) |
//! | `0003_pgcrypto.ext`          | `extension` (file body is the extension name)              |
//! | `0004_backfill.fn.json`      | `function` (file body is `{ "name", "version"?, "args"? }`)|
//!
//! A file with any other suffix is a hard error (never skipped — a mistyped migration must not
//! vanish). An `extension` step can only be an `.ext` file, because a raw `sql` step may not
//! `CREATE EXTENSION` (the server refuses it).

use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::{Deserialize, Serialize};

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
    /// Neither (or both) of `--file` / `--dir` was given — exactly one bundle source is required.
    #[error("pass exactly one of --file <manifest.json> or --dir <migrations/>")]
    BundleSource,
    /// Reading the migrations directory or one of its step files failed.
    #[error("reading {path}: {source}")]
    Read {
        /// The path that failed.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A file in the migrations directory has no recognized migration suffix.
    #[error("`{name}`: unrecognized migration file — expected .sql, .notx.sql, .ext, or .fn.json")]
    UnknownStep {
        /// The offending file name.
        name: String,
    },
    /// Two step files resolved to the same `id`.
    #[error("duplicate migration id `{id}` (files `{a}` and `{b}`)")]
    DuplicateId {
        /// The colliding id.
        id: String,
        /// The first file.
        a: String,
        /// The second file.
        b: String,
    },
    /// A `.fn.json` function step did not parse as `{ "name", "version"?, "args"? }`.
    #[error("parsing function step `{name}`: {source}")]
    FunctionStepParse {
        /// The step file name.
        name: String,
        /// The parse error.
        #[source]
        source: serde_json::Error,
    },
    /// Serializing the assembled bundle failed.
    #[error("serializing the assembled bundle: {0}")]
    Assemble(#[source] serde_json::Error),
}

/// `project_migrate` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp project migrate`.
#[derive(Debug, clap::Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    command: MigrateCommand,
}

/// Where the step set comes from: a pre-authored canonical manifest (`--file`) or a migrations
/// directory the CLI assembles (`--dir`). Exactly one is required (clap enforces mutual exclusion;
/// [`resolve_bundle`] enforces at-least-one).
#[derive(Debug, clap::Args)]
struct BundleSource {
    /// A pre-authored canonical bundle: a JSON `{ "steps": [ { "id": "…", … } ] }` document.
    #[arg(long, short = 'f', conflicts_with = "dir")]
    file: Option<PathBuf>,
    /// A migrations directory the CLI assembles into the bundle (see the naming convention in
    /// the command help). One file per step; applied in lexicographic filename order.
    #[arg(long, short = 'd', conflicts_with = "file")]
    dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum MigrateCommand {
    /// Apply every pending step, in order (`Project·Admin`). Already-recorded steps are skipped
    /// (idempotent); application halts at the first failure, leaving the prefix before it applied.
    Apply {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        #[command(flatten)]
        source: BundleSource,
        /// Emit the raw `MigrationReport` JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
    /// Preview which steps WOULD apply, running nothing (`Project·Admin`).
    DryRun {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        #[command(flatten)]
        source: BundleSource,
        /// Emit the raw `MigrationReport` JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
    /// Record a prefix as already-applied WITHOUT running it — adopt a pre-existing / populated
    /// database (`Project·Admin`). `--up-to <id>` records through that id inclusive; omitted
    /// baselines the entire set.
    Baseline {
        /// The managed-database binding name (empty = the project's default database).
        #[arg(long, default_value = "")]
        db: String,
        #[command(flatten)]
        source: BundleSource,
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
        MigrateCommand::Apply { db, source, json } => {
            let bundle = resolve_bundle(cp, &source).await?;
            let report = cp.migrate_trigger(&db, "apply", &bundle, None).await?;
            render_report(&report, json)?;
            fail_if_step_failed(report)?;
        }
        MigrateCommand::DryRun { db, source, json } => {
            let bundle = resolve_bundle(cp, &source).await?;
            let report = cp.migrate_trigger(&db, "dry-run", &bundle, None).await?;
            render_report(&report, json)?;
            // A dry-run never fails a pending step, but a bundle-level failure still surfaces.
            fail_if_step_failed(report)?;
        }
        MigrateCommand::Baseline {
            db,
            source,
            up_to,
            json,
        } => {
            let bundle = resolve_bundle(cp, &source).await?;
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

/// A resolved bundle source: exactly one of the two mutually-exclusive flags.
#[derive(Debug, PartialEq)]
enum PickedSource<'a> {
    /// `--file`: a pre-authored canonical manifest, uploaded as-is.
    File(&'a Path),
    /// `--dir`: a migrations directory, assembled then uploaded.
    Dir(&'a Path),
}

/// Pick the single bundle source (pure, so the neither/both rule is unit-testable). clap's
/// `conflicts_with` already rules out both-set; this enforces at-least-one.
fn pick_source(source: &BundleSource) -> Result<PickedSource<'_>> {
    match (&source.file, &source.dir) {
        (Some(file), None) => Ok(PickedSource::File(file)),
        (None, Some(dir)) => Ok(PickedSource::Dir(dir)),
        _ => Err(Error::BundleSource),
    }
}

/// Resolve a [`BundleSource`] to an uploaded bundle's content-address: `--file` uploads the file
/// as-is; `--dir` assembles the directory into a canonical bundle and uploads that.
async fn resolve_bundle(cp: &ControlPlane, source: &BundleSource) -> Result<String> {
    match pick_source(source)? {
        PickedSource::File(file) => Ok(cp.put_file_blob(file).await?),
        PickedSource::Dir(dir) => Ok(cp.put_bytes_blob(assemble_dir(dir)?).await?),
    }
}

/// One assembled migration step — serialized into the canonical bundle. Exactly one of `sql` /
/// `extension` / `function` is `Some`; the omitted ones are dropped from the JSON, and
/// `no_transaction` is emitted only when set (matching the server's `#[serde(default)]` shape).
#[derive(Debug, Serialize, PartialEq)]
struct Step {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    no_transaction: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<FunctionStep>,
}

/// A `function` step body (from a `.fn.json` file): the project function to invoke, an optional
/// pinned version (defaults to active), and an opaque `args` string handed to the function.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct FunctionStep {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args: Option<String>,
}

/// The assembled bundle wrapper (`{ "steps": [ … ] }`).
#[derive(Debug, Serialize, PartialEq)]
struct Bundle {
    steps: Vec<Step>,
}

/// Assemble a migrations directory into the canonical bundle bytes. Each file is one step, keyed
/// by the suffix→kind convention (see the module docs); steps are ordered by filename. Fails
/// closed on an unrecognized file or a duplicate id (a mistyped migration must not be silently
/// dropped or reordered).
fn assemble_dir(dir: &Path) -> Result<Vec<u8>> {
    let read = |p: &Path| -> Result<Vec<std::fs::DirEntry>> {
        let mut entries: Vec<_> = std::fs::read_dir(p)
            .map_err(|source| Error::Read {
                path: p.display().to_string(),
                source,
            })?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|source| Error::Read {
                path: p.display().to_string(),
                source,
            })?;
        // Deterministic, lexicographic filename order — the migration application order.
        entries.sort_by_key(std::fs::DirEntry::file_name);
        Ok(entries)
    };

    let slurp = |path: &Path| -> Result<String> {
        std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })
    };

    let mut steps: Vec<Step> = Vec::new();
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for entry in read(dir)? {
        let path = entry.path();
        // Skip subdirectories and dotfiles (e.g. a `.gitkeep`); everything else must be a step.
        if path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }

        let (id, step) = classify_step(&name, &path, &slurp)?;
        if let Some(prev) = seen.insert(id.clone(), name.clone()) {
            return Err(Error::DuplicateId {
                id,
                a: prev,
                b: name,
            });
        }
        steps.push(step);
    }

    serde_json::to_vec(&Bundle { steps }).map_err(Error::Assemble)
}

/// Map one migration file name to its `(id, Step)` by suffix. `slurp` reads the file body (a
/// closure so the pure name→kind logic stays unit-testable without a filesystem).
fn classify_step(
    name: &str,
    path: &Path,
    slurp: &dyn Fn(&Path) -> Result<String>,
) -> Result<(String, Step)> {
    // Order matters: `.notx.sql` is more specific than `.sql`.
    if let Some(id) = name.strip_suffix(".notx.sql") {
        return Ok((
            id.to_string(),
            Step {
                id: id.to_string(),
                sql: Some(slurp(path)?),
                no_transaction: true,
                extension: None,
                function: None,
            },
        ));
    }
    if let Some(id) = name.strip_suffix(".sql") {
        return Ok((
            id.to_string(),
            Step {
                id: id.to_string(),
                sql: Some(slurp(path)?),
                no_transaction: false,
                extension: None,
                function: None,
            },
        ));
    }
    if let Some(id) = name.strip_suffix(".ext") {
        return Ok((
            id.to_string(),
            Step {
                id: id.to_string(),
                sql: None,
                no_transaction: false,
                extension: Some(slurp(path)?.trim().to_string()),
                function: None,
            },
        ));
    }
    if let Some(id) = name.strip_suffix(".fn.json") {
        let body = slurp(path)?;
        let function: FunctionStep =
            serde_json::from_str(&body).map_err(|source| Error::FunctionStepParse {
                name: name.to_string(),
                source,
            })?;
        return Ok((
            id.to_string(),
            Step {
                id: id.to_string(),
                sql: None,
                no_transaction: false,
                extension: None,
                function: Some(function),
            },
        ));
    }
    Err(Error::UnknownStep {
        name: name.to_string(),
    })
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
            Ok(MigrateCommand::Apply { db, source, json }) => {
                assert_eq!(db, "");
                assert_eq!(source.file, Some(PathBuf::from("m.json")));
                assert_eq!(source.dir, None);
                assert!(!json);
            }
            other => panic!("expected apply, got {other:?}"),
        }
        // `apply -d migrations/` takes the directory source.
        match parse(&["migrate", "apply", "-d", "migrations"]) {
            Ok(MigrateCommand::Apply { source, .. }) => {
                assert_eq!(source.dir, Some(PathBuf::from("migrations")));
                assert_eq!(source.file, None);
            }
            other => panic!("expected apply -d, got {other:?}"),
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
        // `--file` and `--dir` are mutually exclusive (clap rejects both).
        assert!(parse(&["migrate", "apply", "-f", "m.json", "-d", "migrations"]).is_err());
    }

    #[test]
    fn bundle_source_requires_exactly_one() {
        // Neither set — parses, but resolves to a BundleSource error at runtime.
        let neither = BundleSource {
            file: None,
            dir: None,
        };
        assert!(matches!(pick_source(&neither), Err(Error::BundleSource)));
        // File wins when only it is set.
        let file = BundleSource {
            file: Some(PathBuf::from("m.json")),
            dir: None,
        };
        assert!(matches!(pick_source(&file), Ok(PickedSource::File(_))));
        // Dir wins when only it is set.
        let dir = BundleSource {
            file: None,
            dir: Some(PathBuf::from("migrations")),
        };
        assert!(matches!(pick_source(&dir), Ok(PickedSource::Dir(_))));
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

    // A `slurp` that returns the file name as its body, so `classify_step` can be tested without
    // touching the filesystem.
    fn name_as_body(p: &Path) -> Result<String> {
        Ok(p.file_name().unwrap().to_string_lossy().into_owned())
    }

    #[test]
    fn classify_step_maps_suffix_to_kind() {
        let go = |name: &str| classify_step(name, Path::new(name), &name_as_body);

        // `.notx.sql` is matched before `.sql`, and sets no_transaction.
        let (id, step) = go("0003_idx.notx.sql").unwrap();
        assert_eq!(id, "0003_idx");
        assert!(step.no_transaction);
        assert_eq!(step.sql.as_deref(), Some("0003_idx.notx.sql"));
        assert!(step.extension.is_none() && step.function.is_none());

        // plain `.sql`.
        let (id, step) = go("0001_init.sql").unwrap();
        assert_eq!(id, "0001_init");
        assert!(!step.no_transaction);
        assert!(step.sql.is_some());

        // `.ext` → extension, body trimmed.
        let (id, step) = go("0002_pgcrypto.ext").unwrap();
        assert_eq!(id, "0002_pgcrypto");
        assert_eq!(step.extension.as_deref(), Some("0002_pgcrypto.ext"));

        // unknown suffix is a hard error (never silently skipped).
        assert!(matches!(go("README.md"), Err(Error::UnknownStep { .. })));
    }

    #[test]
    fn classify_fn_step_parses_json_body() {
        let body =
            |_: &Path| Ok(r#"{"name":"backfill","version":"v3","args":"{\"n\":5}"}"#.to_string());
        let (id, step) = classify_step("0004_backfill.fn.json", Path::new("x"), &body).unwrap();
        assert_eq!(id, "0004_backfill");
        assert_eq!(
            step.function,
            Some(FunctionStep {
                name: "backfill".into(),
                version: Some("v3".into()),
                args: Some("{\"n\":5}".into()),
            })
        );

        // A malformed function body is a typed parse error, not a panic.
        let bad = |_: &Path| Ok("not json".to_string());
        assert!(matches!(
            classify_step("0005_x.fn.json", Path::new("x"), &bad),
            Err(Error::FunctionStepParse { .. })
        ));
    }

    #[test]
    fn assemble_dir_orders_by_filename_and_rejects_dupe_ids() {
        // Hermetic temp dir (unique per process; cleaned at the end).
        let root = std::env::temp_dir().join(format!("br-migrate-asm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Intentionally create out of order; assembly must sort by filename.
        std::fs::write(root.join("0002_pgcrypto.ext"), "pgcrypto\n").unwrap();
        std::fs::write(root.join("0001_init.sql"), "CREATE TABLE t (id int);").unwrap();
        std::fs::write(root.join("0003_backfill.fn.json"), r#"{"name":"backfill"}"#).unwrap();
        std::fs::write(root.join(".gitkeep"), "").unwrap(); // dotfile: skipped

        let bytes = assemble_dir(&root).unwrap();
        let bundle: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let steps = bundle["steps"].as_array().unwrap();
        let ids: Vec<&str> = steps.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["0001_init", "0002_pgcrypto", "0003_backfill"]);
        // Kinds landed on the right fields; the extension body is trimmed.
        assert!(steps[0].get("sql").is_some());
        assert_eq!(steps[1]["extension"], "pgcrypto");
        assert_eq!(steps[2]["function"]["name"], "backfill");
        // A false `no_transaction` is omitted (matches the server's serde(default)).
        assert!(steps[0].get("no_transaction").is_none());

        // A second file resolving to an existing id is refused.
        std::fs::write(root.join("0001_init.ext"), "dup").unwrap();
        assert!(matches!(
            assemble_dir(&root),
            Err(Error::DuplicateId { id, .. }) if id == "0001_init"
        ));

        let _ = std::fs::remove_dir_all(&root);
    }
}
