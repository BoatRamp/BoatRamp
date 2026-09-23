//! `boatramp project repair` — a client for the owner-gated provisioning **drift-repair**
//! API (`/api/{project-seg}/repair/{db}` + `/dry-run`, added server-side in v0.5.0).
//!
//! Repair converges a managed shared-Postgres tenant's provisioning against spec — the
//! owner-model retrofit: create + seal the per-project non-superuser **owner role**, re-own
//! the database, its objects, and the migration ledger to it — so `boatramp project migrate`
//! (which connects as that sealed owner role) can run. It **fixes provisioning so migrate can
//! run; it never touches schema or data** (only roles / ownership / grants / credentials /
//! ledger scaffolding — never a `DROP`/`TRUNCATE`/`DELETE`/`UPDATE` of tenant rows).
//!
//! # Dry-run by default
//!
//! Unlike `migrate` (whose subcommands each mutate), `repair` **defaults to a dry-run**: it
//! reports the drift it finds and the DDL it WOULD run, changing nothing. `--apply` is the
//! deliberate, explicit opt-in that runs the host-derived privileged provisioning DDL
//! (role creation, `ALTER DATABASE OWNER`, `REASSIGN OWNED`). `--dry-run` is accepted as an
//! explicit, redundant no-op for symmetry/scripts. Both surfaces are `Project·Admin`.
//!
//! # Exit codes
//!
//! - `0` — no drift, or every drift repaired (a clean run).
//! - `1` — any check errored (convergence was PARTIAL / a probe or converge failed).
//! - `2` — a dry-run FOUND drift, but ONLY under the opt-in `--exit-nonzero-on-drift`
//!   (so CI can gate on "is this tenant in spec?"); by default a dry-run finding drift is `0`.

use crate::client::ControlPlane;

/// A failure in `boatramp project repair`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Rendering the `--json` output failed.
    #[error("rendering the repair result failed: {0}")]
    Render(#[source] serde_json::Error),
    /// A repair check errored (the full report was already printed; this makes the process exit
    /// non-zero so scripts can gate). Names the first errored check, mirroring migrate's
    /// `FAILED at [step]`.
    #[error("provisioning repair PARTIAL: convergence FAILED at check `{check}`")]
    CheckErrored {
        /// The first errored check's slug.
        check: String,
    },
    /// The `--db` name is not a safe URL path segment (validated client-side before the request
    /// URL is built), so a malformed name fails fast rather than an opaque server error.
    #[error("{0}")]
    InvalidDb(String),
}

/// `project_repair` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Validate a `--db` name through the one canonical resource-identifier validator
/// (`kind = "database"`) before it is threaded into the repair URL — the same rule the server,
/// config load, and `boatramp project migrate` enforce. The empty-name case (the common v0.5.0
/// upgrade snag) carries the one-line cure pointing at the new `default` name.
fn validate_db(db: &str) -> Result<()> {
    boatramp_core::project::validate_resource_name("database", db).map_err(|err| {
        if db.is_empty() {
            Error::InvalidDb(format!(
                "{err}; {}",
                boatramp_core::project::EMPTY_DB_NAME_CURE
            ))
        } else {
            Error::InvalidDb(err.to_string())
        }
    })
}

/// Arguments for `boatramp project repair` — the flags sit directly on the verb (no nested
/// subcommand), matching the spec `boatramp project repair --db <name> [--apply] [--json]`.
///
/// Diffs a managed tenant's provisioning against spec and (with `--apply`) converges the delta — the
/// owner-model retrofit that unblocks `project migrate`. DEFAULT is a dry-run (reports the drift and
/// the DDL it would run, changing nothing). Fixes provisioning so migrate can run; NEVER touches
/// schema or data. `Project·Admin`.
#[derive(Debug, clap::Args)]
pub struct RepairArgs {
    /// The managed-database binding name (`default` = the project's default database).
    #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
    db: String,
    /// Converge the drift (run the host-derived provisioning DDL). The deliberate, explicit opt-in —
    /// without it, `repair` only reports (a documented divergence from `migrate`, whose verbs each
    /// mutate).
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
    /// Explicitly request a dry-run (the default). A redundant no-op for symmetry/scripts; mutually
    /// exclusive with `--apply`.
    #[arg(long)]
    dry_run: bool,
    /// Make a dry-run that FINDS drift exit `2` (for CI gating on "is this tenant in spec?"). Off by
    /// default (a dry-run finding drift exits `0`). No effect under `--apply`.
    #[arg(long)]
    exit_nonzero_on_drift: bool,
    /// Emit the raw `RepairReport` JSON instead of a human table.
    #[arg(long)]
    json: bool,
}

/// Entry point for `boatramp project repair`, driven off the already-connected [`ControlPlane`].
pub async fn run(args: RepairArgs, cp: &ControlPlane) -> Result<()> {
    let RepairArgs {
        db,
        apply,
        dry_run: _,
        exit_nonzero_on_drift,
        json,
    } = args;
    validate_db(&db)?;
    if apply {
        // Echo the plan before mutating (no interactive prompt — the `--apply` flag IS the consent),
        // so an operator sees what's about to run.
        println!("running: boatramp project repair --db {db} --apply");
    }
    let report = cp.repair_trigger(&db, apply).await?;
    render_report(&report, json)?;
    // Exit-code policy: any errored check ⇒ 1 (return Err). Else a dry-run that found drift ⇒ 2 ONLY
    // under the opt-in flag; otherwise 0.
    if let Some(check) = report.first_error().map(str::to_string) {
        return Err(Error::CheckErrored { check });
    }
    if !apply && exit_nonzero_on_drift && report.found_drift() {
        // A deliberate, documented custom exit code the binary `main` (0/1) can't express; the report
        // was already printed, so exit cleanly with 2.
        std::process::exit(2);
    }
    Ok(())
}

/// Render a [`RepairReport`](boatramp_core::sql::RepairReport): pretty JSON under `--json`, else a
/// human per-check table with the DDL broken out below and a partial/no-op summary.
fn render_report(report: &boatramp_core::sql::RepairReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).map_err(Error::Render)?
        );
        return Ok(());
    }

    // Mandatory backend + mode header.
    println!("tenant:  {}", report.tenant);
    println!("backend: {}", report.backend);
    println!("mode:    {}", report.mode);
    println!();

    // Per-check table: CHECK / STATUS / DETAIL.
    let (h_check, h_status, h_detail) = ("CHECK", "STATUS", "DETAIL");
    println!("{h_check:<24} {h_status:<9} {h_detail}");
    for c in &report.checks {
        println!("{:<24} {:<9} {}", c.check, c.status.as_str(), c.detail);
    }

    // DDL broken out below, tagged by the check slug (a credential seal has no SQL and is shown
    // only as the check's detail parenthetical — never fake SQL here).
    let with_ddl: Vec<&boatramp_core::sql::RepairCheck> =
        report.checks.iter().filter(|c| c.ddl.is_some()).collect();
    if !with_ddl.is_empty() {
        let verb = if report.mode == "apply" {
            "DDL executed"
        } else {
            "DDL that WOULD run"
        };
        println!("\n{verb}:");
        for c in with_ddl {
            if let Some(ddl) = &c.ddl {
                println!("  [{}]", c.check);
                for line in ddl.lines() {
                    println!("    {line}");
                }
            }
        }
    }

    // Summary sentinels.
    println!();
    if let Some(check) = report.first_error() {
        println!("convergence PARTIAL: FAILED at [{check}]");
    } else if report.found_drift() {
        if report.mode == "apply" {
            println!("repaired: all drift converged");
        } else {
            println!("drift found (dry-run: nothing changed) — re-run with --apply to converge");
        }
    } else {
        // The literal no-op sentinel.
        println!("nothing to repair");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::sql::{RepairCheck, RepairReport, RepairStatus};
    use clap::{Parser, Subcommand};

    /// A minimal top-level parser mirroring `main`'s `project repair` nesting.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Repair(RepairArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<RepairArgs, clap::Error> {
        let cli = Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))?;
        let Cmd::Repair(args) = cli.cmd;
        Ok(args)
    }

    #[test]
    fn repair_flags_parse_and_default_to_dry_run() {
        // Bare `repair` defaults to the reserved default db, dry-run (apply=false).
        let a = parse(&["repair"]).unwrap();
        assert_eq!(a.db, boatramp_core::project::DEFAULT_DB_NAME);
        assert!(!a.apply, "repair must DEFAULT to a dry-run (apply=false)");
        assert!(!a.dry_run);
        assert!(!a.exit_nonzero_on_drift);
        assert!(!a.json);

        // `--apply --db main --json`.
        let a = parse(&["repair", "--db", "main", "--apply", "--json"]).unwrap();
        assert_eq!(a.db, "main");
        assert!(a.apply);
        assert!(a.json);

        // `--dry-run` is an accepted explicit no-op.
        assert!(parse(&["repair", "--dry-run"]).unwrap().dry_run);

        // `--apply` and `--dry-run` are mutually exclusive.
        assert!(parse(&["repair", "--apply", "--dry-run"]).is_err());

        // The opt-in drift-exit flag parses.
        assert!(
            parse(&["repair", "--exit-nonzero-on-drift"])
                .unwrap()
                .exit_nonzero_on_drift
        );
    }

    #[test]
    fn validate_db_gates_unsafe_names_client_side() {
        assert!(validate_db(boatramp_core::project::DEFAULT_DB_NAME).is_ok());
        assert!(validate_db("main").is_ok());
        for bad in ["", "a/b", "..", "a b"] {
            assert!(validate_db(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn empty_db_name_rejection_carries_the_cure() {
        let Err(Error::InvalidDb(msg)) = validate_db("") else {
            panic!("empty --db must be rejected");
        };
        assert!(
            msg.contains(boatramp_core::project::EMPTY_DB_NAME_CURE),
            "empty-name error must carry the cure, got: {msg}"
        );
    }

    /// A representative report renders (human + JSON) without panicking, and the no-op / partial
    /// summary sentinels fire on the right shapes.
    #[test]
    fn renderers_are_infallible() {
        let ok = RepairReport {
            tenant: "appdb_acme".into(),
            backend: "shared-postgres".into(),
            mode: "dry-run".into(),
            checks: vec![RepairCheck {
                check: "owner-role-exists".into(),
                status: RepairStatus::Ok,
                detail: "owner role exists".into(),
                ddl: None,
            }],
        };
        render_report(&ok, false).unwrap();
        render_report(&ok, true).unwrap();
        assert!(!ok.found_drift());
        assert!(ok.first_error().is_none());

        let drift = RepairReport {
            mode: "dry-run".into(),
            checks: vec![RepairCheck {
                check: "db-owner".into(),
                status: RepairStatus::Drift,
                detail: "db owned by runtime".into(),
                ddl: Some("ALTER DATABASE \"appdb_acme\" OWNER TO \"appdb_acme_owner\";".into()),
            }],
            ..ok.clone()
        };
        render_report(&drift, false).unwrap();
        assert!(drift.found_drift());

        let errored = RepairReport {
            checks: vec![RepairCheck {
                check: "object-ownership".into(),
                status: RepairStatus::Error,
                detail: "requires a superuser maintenance connection".into(),
                ddl: None,
            }],
            ..ok.clone()
        };
        render_report(&errored, false).unwrap();
        assert_eq!(errored.first_error(), Some("object-ownership"));
    }
}
