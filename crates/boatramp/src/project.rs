//! The `project` subcommand (0.2.0): manage **projects** — the owning Workspace above
//! sites/functions/compute. `create` / `ls` / `show` / `rm` over the control-plane
//! `/api/projects` surface. Scoping *other* commands to a project is the global
//! `--project` flag (resolved in `main`), not here.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `project` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Serializing the create request failed.
    #[error("serializing the project request failed: {0}")]
    Serde(#[from] serde_json::Error),
    /// Reading/writing the confirmation prompt failed.
    #[error("prompt I/O failed: {0}")]
    Io(std::io::Error),
    /// The operator aborted (or could not be prompted for) a destructive delete.
    #[error("{0}")]
    Aborted(String),
    /// A `project migrate` subcommand failure.
    #[error(transparent)]
    Migrate(#[from] crate::project_migrate::Error),
    /// A `project repair` subcommand failure.
    #[error(transparent)]
    Repair(#[from] crate::project_repair::Error),
    /// A `project tenant-secrets` subcommand failure.
    #[error(transparent)]
    TenantSecrets(#[from] crate::project_tenant_secrets::Error),
}

/// `project` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp project`.
#[derive(Debug, clap::Args)]
pub struct ProjectArgs {
    /// boatramp server base URL (overrides `[deploy].server`).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Create a new project.
    Create {
        /// The project slug (unique, no `/`).
        name: String,
        /// Human display name (defaults to the slug).
        #[arg(long)]
        display: Option<String>,
        /// Free-text description.
        #[arg(long)]
        description: Option<String>,
        /// Default region for the project's compute/replicas.
        #[arg(long)]
        region: Option<String>,
    },
    /// List all projects.
    Ls,
    /// Show one project's full record.
    Show {
        /// The project slug.
        name: String,
    },
    /// Scan for resource identifiers that the v0.7.0 strict slug allowlist no longer
    /// accepts (`Project·Read`, read-only). Lists each non-conforming name, why it
    /// fails, what it AFFECTS, and a copy-pasteable SUGGESTED FIX. Exits non-zero if any
    /// are found — a CI preflight for the breaking cutover.
    Doctor,
    /// Delete a project. Refused while it owns resources (unless `--force`) or if it
    /// is the reserved `default`.
    ///
    /// Escape-hatch: a NON-CONFORMING legacy name (rejected by the v0.7.0 slug rule)
    /// may be passed here as an opaque teardown key — the only surface that accepts one,
    /// so a skip-upgrader can delete a bad name on v0.7.0. It is used ONLY as a
    /// KV/blob lookup key and is never re-emitted into a new sink.
    Rm {
        /// The project slug.
        name: String,
        /// Cascade: tear down **everything** the project owns (sites, functions,
        /// compute + their volumes, secrets, GraphQL registry) and remove the project.
        /// Destructive and irreversible.
        #[arg(long)]
        force: bool,
        /// Preview what a delete would remove and exit — mutate nothing.
        #[arg(long)]
        dry_run: bool,
        /// Skip the interactive confirmation prompt (required to `--force` when stdin
        /// is not a TTY).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Drive this project's owner-gated schema migrations for a managed database
    /// (`migrate apply|dry-run|baseline|status`). The mutating verbs run as the project's
    /// non-superuser owner role and need a `Project·Admin` token; `status` needs `Project·Read`.
    Migrate(crate::project_migrate::MigrateArgs),
    /// Repair a managed tenant's provisioning drift (the owner-model retrofit that unblocks
    /// `project migrate`). Defaults to a dry-run; `--apply` converges. Fixes provisioning so
    /// migrate can run; never touches schema or data. `Project·Admin`.
    Repair(crate::project_repair::RepairArgs),
    /// Manage this project's PER-TENANT sealed secrets (task #493): each firm's own third-party
    /// credential (e.g. an OAuth `client_secret`), sealed server-side under `(tenant, name)`.
    /// `set`/`rotate`/`ls`/`rm`, each `--tenant <t>`. Distinct from the per-project `boatramp
    /// secrets` env store. Mutating verbs need `Secrets·Write`; `ls` needs `Secrets·Read`.
    #[command(name = "tenant-secrets")]
    TenantSecrets(crate::project_tenant_secrets::TenantSecretsArgs),
    /// Export a project's data (managed DB dumps + the control-plane KV slice + blobs)
    /// to a portable BRPROJ bundle, streamed from the RUNNING node (`Project·Admin` on the project).
    Export {
        /// The project to export.
        name: String,
        /// Write the bundle to this file (the streamed default). Mutually exclusive with
        /// `--resumable`; exactly one is required.
        #[arg(long, required_unless_present = "resumable")]
        out: Option<std::path::PathBuf>,
        /// RESUMABLE export: write a member-object directory of this NAME on the NODE (under
        /// the node's configured `[serve] resumable_export_dir` base) instead of streaming a
        /// file — an interrupted run RESUMES instead of restarting. The directory is
        /// node-local (that is what lets it resume); the name is relative and host-confined.
        #[arg(long, value_name = "DIR_NAME", conflicts_with = "out")]
        resumable: Option<String>,
        /// DELTA export: `differential` (vs a fixed base) or `incremental` (vs the parent,
        /// forming a chain). Only with `--resumable`; requires `--base`. Ships only what changed
        /// since the base (KV + blob true-deltas today; SQL falls back to a full dump within the
        /// delta bundle). Default: a full (non-delta) export.
        #[arg(long, value_parser = ["differential", "incremental"], requires = "base")]
        mode: Option<String>,
        /// The base (differential) / parent (incremental) resumable-dir NAME to chain the delta
        /// onto (a prior `--resumable` export on the same node). Required with `--mode`.
        #[arg(long, value_name = "DIR_NAME", requires = "mode")]
        base: Option<String>,
        /// Export a FULL bundle (schema + data). Default: `--data-only` (app data only —
        /// no identity/RBAC/routing).
        #[arg(long)]
        full: bool,
        /// Include the identity transport container (the project KEK, passphrase-wrapped)
        /// for a same-environment RECOVERY. Implies a FULL bundle; requires a transport key
        /// (--transport-key-file, else BOATRAMP_EXPORT_TRANSPORT_KEY, else an interactive
        /// prompt). Local KEK envelopes only.
        #[arg(long)]
        include_identity: bool,
        /// File holding the transport passphrase that wraps/opens the identity container.
        #[arg(long, value_name = "FILE")]
        transport_key_file: Option<std::path::PathBuf>,
    },
    /// Import a BRPROJ bundle into a project on the RUNNING node (`Project·Admin` on the target).
    /// Dry-run (a plan, no mutation) unless `--apply`.
    Import {
        /// The project to import into.
        name: String,
        /// The bundle file to import (the streamed default). Mutually exclusive with
        /// `--resumable`; exactly one is required.
        #[arg(
            long = "in",
            value_name = "FILE",
            required_unless_present_any = ["resumable", "clone_from"]
        )]
        input: Option<std::path::PathBuf>,
        /// RESUMABLE import: read a member-object directory of this NAME on the NODE (under
        /// the node's configured `[serve] resumable_export_dir` base — the output of a
        /// resumable export) instead of sending a file. Host-confined relative name.
        #[arg(long, value_name = "DIR_NAME", conflicts_with = "input")]
        resumable: Option<String>,
        /// STREAMING CLONE: pull the project from a LIVE source node over the network instead
        /// of a bundle file — the target fetches the source manifest, diffs its own store, and
        /// restores only the missing members (no bundle lands anywhere). This is the source
        /// node's base URL. `Project·Admin` on BOTH nodes (not node-global). Mutually exclusive
        /// with `--in`/`--resumable`.
        #[arg(long, value_name = "SOURCE_URL", conflicts_with_all = ["input", "resumable"])]
        clone_from: Option<String>,
        /// The SOURCE project to clone (only with `--clone-from`). Defaults to the target
        /// project NAME — the common same-name env-clone.
        #[arg(long, value_name = "PROJECT", requires = "clone_from")]
        clone_source_project: Option<String>,
        /// File holding the operator's SOURCE-node Project-Admin token for `--clone-from`
        /// (falls back to BOATRAMP_CLONE_SOURCE_TOKEN). The token is sent in a header over TLS,
        /// never on the command line.
        #[arg(long, value_name = "FILE", requires = "clone_from")]
        clone_source_token_file: Option<std::path::PathBuf>,
        /// Pull a `--data-only` clone (app data only — no control-plane KV). Only with
        /// `--clone-from`.
        #[arg(long, requires = "clone_from")]
        clone_data_only: bool,
        /// Stream-level VERIFY a clone (only with `--clone-from`, no `--apply`): open the source
        /// stream and validate the whole bundle end-to-end WITHOUT mutating the target. The default
        /// `--clone-from` dry-run is instead the CHEAP PLAN (manifest + diff only — no stream); use
        /// this when you want the heavier, full end-to-end validation a plan does not perform.
        #[arg(long, requires = "clone_from", conflicts_with = "apply")]
        clone_verify: bool,
        /// Execute the import (default: a dry-run plan — mutate nothing).
        #[arg(long)]
        apply: bool,
        /// Overlay a non-empty control-plane KV destination (the commingle override; only
        /// meaningful for a FULL bundle).
        #[arg(long)]
        force: bool,
        /// Proceed despite a Postgres schema-ledger fingerprint mismatch between the
        /// bundle and the target.
        #[arg(long)]
        allow_schema_skew: bool,
        /// Replace an EXISTING target project (one that already holds its own KV/blob data).
        /// Default off — a clone into a fresh target is the safe default; this is opt-in.
        #[arg(long)]
        overwrite: bool,
        /// Identity decision: `fresh` (default — the target mints its own identity and
        /// source-sealed secrets are dropped) or `adopt` (install the bundle's KEK for a
        /// same-environment recovery; requires a transport key).
        #[arg(long, default_value = "fresh", value_parser = ["fresh", "adopt"])]
        identity: String,
        /// File holding the transport passphrase (for `--identity adopt`). Falls back to
        /// BOATRAMP_EXPORT_TRANSPORT_KEY, then an interactive prompt.
        #[arg(long, value_name = "FILE")]
        transport_key_file: Option<std::path::PathBuf>,
    },
}

/// Whether a `--force` confirmation `typed` at the prompt authorizes deleting
/// `project` — an exact match (after trimming surrounding whitespace/newline) of the
/// project name. A pure function so the confirmation gate is unit-testable without a
/// TTY.
fn confirmation_matches(project: &str, typed: &str) -> bool {
    typed.trim() == project
}

/// Render a clone plan's to-transfer byte count. A fallback backend with no per-object size makes
/// the total a LOWER BOUND (`exact == false`), shown with a trailing `+` and `~`, so the operator
/// is not misled into reading a partial sum as the whole transfer.
fn approx_bytes(bytes: u64, exact: bool) -> String {
    if exact {
        format!("~{bytes} bytes")
    } else {
        format!("≥~{bytes} bytes")
    }
}

/// Resolve the identity-transport passphrase, in precedence order (owner decision,
/// 2026-10-14): `--transport-key-file` (0600-ish operator file, trailing newline trimmed),
/// then `BOATRAMP_EXPORT_TRANSPORT_KEY`, then a hidden interactive prompt. Never echoed,
/// never placed on a command line.
fn resolve_transport_key(file: Option<&std::path::Path>, prompt: &str) -> Result<Vec<u8>> {
    if let Some(p) = file {
        let s = std::fs::read_to_string(p).map_err(Error::Io)?;
        let key = s.trim_end_matches(['\n', '\r']).as_bytes().to_vec();
        if key.is_empty() {
            return Err(Error::Aborted(format!(
                "transport key file {} is empty",
                p.display()
            )));
        }
        return Ok(key);
    }
    if let Ok(v) = std::env::var("BOATRAMP_EXPORT_TRANSPORT_KEY")
        && !v.is_empty()
    {
        return Ok(v.into_bytes());
    }
    let pw = rpassword::prompt_password(prompt).map_err(Error::Io)?;
    if pw.is_empty() {
        return Err(Error::Aborted("transport key must not be empty".into()));
    }
    Ok(pw.into_bytes())
}

/// Resolve the operator's SOURCE-node Project-Admin token for `--clone-from`:
/// `--clone-source-token-file` (trailing newline trimmed) then `BOATRAMP_CLONE_SOURCE_TOKEN`.
/// A bearer secret, so it is read from a file / env — never a command-line argument — and sent
/// to the target node in a header over TLS, which forwards it to the source.
fn resolve_source_token(file: Option<&std::path::Path>) -> Result<Vec<u8>> {
    if let Some(p) = file {
        let s = std::fs::read_to_string(p).map_err(Error::Io)?;
        let tok = s.trim_end_matches(['\n', '\r']).as_bytes().to_vec();
        if tok.is_empty() {
            return Err(Error::Aborted(format!(
                "clone source token file {} is empty",
                p.display()
            )));
        }
        return Ok(tok);
    }
    if let Ok(v) = std::env::var("BOATRAMP_CLONE_SOURCE_TOKEN")
        && !v.is_empty()
    {
        return Ok(v.into_bytes());
    }
    Err(Error::Aborted(
        "a clone needs the SOURCE node's Project-Admin token: pass --clone-source-token-file \
         or set BOATRAMP_CLONE_SOURCE_TOKEN"
            .into(),
    ))
}

/// A one-line human summary of a teardown [plan](crate::client) for the operator, e.g.
/// `project \`x\` owns: 2 sites (a, b), 1 function (f), 1 compute (pg + volume pg-data), 3 secrets`.
/// Reads the fields defensively from the plan JSON so a server that adds fields does
/// not break the CLI.
fn summarize_plan(name: &str, plan: &serde_json::Value) -> String {
    let arr = |k: &str| -> Vec<String> {
        plan.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut parts: Vec<String> = Vec::new();

    let sites = arr("sites");
    if !sites.is_empty() {
        parts.push(format!(
            "{} site{} ({})",
            sites.len(),
            if sites.len() == 1 { "" } else { "s" },
            sites.join(", ")
        ));
    }
    let functions = arr("functions");
    if !functions.is_empty() {
        parts.push(format!(
            "{} function{} ({})",
            functions.len(),
            if functions.len() == 1 { "" } else { "s" },
            functions.join(", ")
        ));
    }
    if let Some(compute) = plan.get("compute").and_then(|v| v.as_array())
        && !compute.is_empty()
    {
        let items: Vec<String> = compute
            .iter()
            .map(|c| {
                let cname = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let vols: Vec<&str> = c
                    .get("volumes")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                if vols.is_empty() {
                    cname.to_string()
                } else {
                    format!(
                        "{cname} + volume{} {}",
                        if vols.len() == 1 { "" } else { "s" },
                        vols.join(", ")
                    )
                }
            })
            .collect();
        parts.push(format!("{} compute ({})", compute.len(), items.join("; ")));
    }
    let secrets = arr("secrets");
    if !secrets.is_empty() {
        parts.push(format!(
            "{} secret{}",
            secrets.len(),
            if secrets.len() == 1 { "" } else { "s" }
        ));
    }
    if let Some(n) = plan.get("safelist").and_then(serde_json::Value::as_u64)
        && n > 0
    {
        parts.push(format!(
            "{n} graphql safelist entr{}",
            if n == 1 { "y" } else { "ies" }
        ));
    }
    let subgraphs = arr("subgraphs");
    if !subgraphs.is_empty() {
        parts.push(format!(
            "{} subgraph{} ({})",
            subgraphs.len(),
            if subgraphs.len() == 1 { "" } else { "s" },
            subgraphs.join(", ")
        ));
    }
    if let Some(other) = plan.get("other_families").and_then(|v| v.as_object()) {
        for (family, count) in other {
            let c = count.as_u64().unwrap_or(0);
            parts.push(format!("{c} {family} key{}", if c == 1 { "" } else { "s" }));
        }
    }

    if parts.is_empty() {
        format!("project `{name}` owns nothing")
    } else {
        format!("project `{name}` owns: {}", parts.join(", "))
    }
}

/// One non-conforming resource identifier `project doctor` found.
#[derive(Debug, serde::Serialize)]
struct Finding {
    /// The offending identifier (the raw stored name).
    name: String,
    /// The resource kind (`project` / `site` / `function` / `compute` / `secret` /
    /// `subgraph`).
    kind: String,
    /// The owning project (equal to `name` for a `project`-kind finding).
    project: String,
    /// Why it fails the v0.7.0 slug rule (the canonical validator's reason).
    reason: String,
    /// A one-line human summary of what the owning project AFFECTS (from
    /// [`summarize_plan`]).
    affected: String,
    /// A copy-pasteable suggested fix. For an INERT project the fix is a delete
    /// (`boatramp project rm <name>`); otherwise the operator must migrate off it
    /// first (the general rename is deferred).
    suggested_fix: String,
}

/// Whether the teardown `plan` shows the project owns nothing (inert) — the emptiness
/// oracle the SUGGESTED FIX keys off. Reads the same families [`summarize_plan`] does.
fn plan_is_inert(plan: &serde_json::Value) -> bool {
    let empty_arr = |k: &str| {
        plan.get(k)
            .and_then(|v| v.as_array())
            .is_none_or(Vec::is_empty)
    };
    let compute_empty = plan
        .get("compute")
        .and_then(|v| v.as_array())
        .is_none_or(Vec::is_empty);
    let safelist_empty = plan
        .get("safelist")
        .and_then(serde_json::Value::as_u64)
        .is_none_or(|n| n == 0);
    let others_empty = plan
        .get("other_families")
        .and_then(|v| v.as_object())
        .is_none_or(|m| m.values().all(|v| v.as_u64().unwrap_or(0) == 0));
    empty_arr("sites")
        && empty_arr("functions")
        && compute_empty
        && empty_arr("secrets")
        && empty_arr("subgraphs")
        && safelist_empty
        && others_empty
}

/// Collect the resource names a teardown `plan` reports the project owns, paired with
/// their kind — the identifiers `doctor` re-screens against the v0.7.0 slug rule.
fn owned_names(plan: &serde_json::Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let arr = |k: &str| -> Vec<String> {
        plan.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    for kind in ["sites", "functions", "secrets", "subgraphs"] {
        // Singularize for the report.
        let singular = kind.trim_end_matches('s');
        for n in arr(kind) {
            out.push((n, singular.to_string()));
        }
    }
    if let Some(compute) = plan.get("compute").and_then(|v| v.as_array()) {
        for c in compute {
            if let Some(n) = c.get("name").and_then(|v| v.as_str()) {
                out.push((n.to_string(), "compute".to_string()));
            }
        }
    }
    out
}

/// `boatramp project doctor`: scan every project (and the names it owns) for
/// identifiers the v0.7.0 slug allowlist rejects. Read-only. Prints a table (or JSON
/// under `--output-format json`) and exits non-zero when any non-conforming name is found.
async fn doctor(
    cp: &client::ControlPlane,
    mode: crate::output::OutputMode,
) -> Result<ProjectOutput> {
    let json = matches!(mode, crate::output::OutputMode::Json);
    let projects = cp.list_projects().await?;
    let mut findings: Vec<Finding> = Vec::new();

    for p in &projects {
        let Some(pname) = p.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        // Fetch the teardown plan once (dry-run, mutates nothing) — the AFFECTED summary
        // AND the inert-vs-live emptiness oracle both read it. The plan endpoint accepts
        // the opaque (possibly non-conforming) name as a source-only key.
        let plan = cp
            .project_teardown_plan(pname)
            .await
            .unwrap_or_else(|_| serde_json::json!({ "project": pname }));
        let affected = summarize_plan(pname, &plan);
        let inert = plan_is_inert(&plan);
        let fix = |name: &str, is_project: bool| -> String {
            if is_project && inert {
                format!("boatramp project rm {name}")
            } else if is_project {
                format!(
                    "project `{name}` still owns resources — migrate them to a valid-slug \
                     project, then `boatramp project rm {name}` (a general rename is not \
                     yet available)"
                )
            } else {
                format!(
                    "recreate this resource under a valid-slug name in project `{name}`, \
                     then remove the non-conforming one"
                )
            }
        };

        // The project name itself.
        if let Err(err) = boatramp_core::project::validate_resource_name("project", pname) {
            findings.push(Finding {
                name: pname.to_string(),
                kind: "project".to_string(),
                project: pname.to_string(),
                reason: err.reason.to_string(),
                affected: affected.clone(),
                suggested_fix: fix(pname, true),
            });
        }
        // Every name it owns.
        for (owned, kind) in owned_names(&plan) {
            if let Err(err) = boatramp_core::project::validate_resource_name("resource", &owned) {
                findings.push(Finding {
                    name: owned,
                    kind,
                    project: pname.to_string(),
                    reason: err.reason.to_string(),
                    affected: affected.clone(),
                    suggested_fix: fix(pname, false),
                });
            }
        }
    }

    // `doctor` keeps its own output contract: a bespoke findings serialization (JSON under the
    // global `--output-format json`) and a non-zero exit when any finding is present (a CI
    // preflight). Those are incompatible with the emit-once model (`emit` renders only the `Ok`
    // value, and the findings must print *and* exit non-zero), so the findings paths write directly
    // here and signal via `Err`; only the clean human path flows through the typed result.
    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        return Ok(ProjectOutput::DoctorClean);
    } else {
        println!(
            "{} non-conforming identifier{} (v0.7.0 slug allowlist):\n",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        );
        for f in &findings {
            println!("  {} `{}` (project `{}`)", f.kind, f.name, f.project);
            println!("      why:       {}", f.reason);
            println!("      affected:  {}", f.affected);
            println!("      fix:       {}", f.suggested_fix);
            println!();
        }
    }

    if findings.is_empty() {
        // The JSON clean path already wrote `[]`; nothing left for `emit` to render.
        Ok(ProjectOutput::Passthrough)
    } else {
        // Non-zero exit for CI preflight (mirrors the migration-gate refusal style).
        Err(Error::Aborted(format!(
            "{} non-conforming identifier(s) found — {}",
            findings.len(),
            boatramp_core::project::INVALID_NAME_CURE
        )))
    }
}

/// The result of a `project` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ProjectOutput {
    /// A project was created.
    Created { name: String },
    /// `project ls` — all projects (the control-plane records).
    List { projects: Vec<serde_json::Value> },
    /// `project show` — one project's full record.
    Show { project: serde_json::Value },
    /// `project doctor` found no non-conforming identifiers (clean).
    DoctorClean,
    /// `project rm --dry-run` — a teardown preview; nothing was deleted.
    RmDryRun {
        project: String,
        plan: serde_json::Value,
    },
    /// A project was force-deleted (cascade teardown); `report` is what was removed.
    ForceDeleted {
        project: String,
        report: serde_json::Value,
    },
    /// A project was deleted (non-cascade).
    Deleted { name: String },
    /// A project was exported to a bundle.
    Exported {
        project: String,
        data_only: bool,
        include_identity: bool,
        out: String,
    },
    /// A bundle was imported (or dry-run planned); `report` is the server's plan/outcome.
    Imported {
        project: String,
        applied: bool,
        report: String,
    },
    /// A streaming clone DRY-RUN: the cheap plan of what a real clone would transfer/restore —
    /// manifest + diff only, nothing streamed.
    ClonePlanned {
        plan: boatramp_core::project_export::ClonePlan,
    },
    /// A streaming clone was executed (`--apply`) or validated (`--clone-verify`): `plan` is what
    /// ran, `report` the import/restore outcome.
    Cloned {
        plan: boatramp_core::project_export::ClonePlan,
        report: boatramp_core::project_export::ImportReport,
    },
    /// The output was already written directly by this arm (a delegated subcommand's own
    /// printing, or `doctor`'s findings report); nothing is left for `emit` to render.
    Passthrough,
}

impl crate::output::Rendered for ProjectOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Created { name } => writeln!(w, "created project `{name}`"),
            Self::List { projects } => {
                if projects.is_empty() {
                    return writeln!(w, "no projects");
                }
                for p in projects {
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let display = p
                        .get("meta")
                        .and_then(|m| m.get("display"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty());
                    match display {
                        Some(d) => writeln!(w, "{name}\t{d}")?,
                        None => writeln!(w, "{name}")?,
                    }
                }
                Ok(())
            }
            Self::Show { project } => {
                let rendered =
                    serde_json::to_string_pretty(project).map_err(std::io::Error::other)?;
                writeln!(w, "{rendered}")
            }
            Self::DoctorClean => writeln!(
                w,
                "no non-conforming identifiers found — every name is a valid v0.7.0 slug"
            ),
            Self::RmDryRun { project, plan } => {
                writeln!(
                    w,
                    "{} — nothing deleted (--dry-run)",
                    summarize_plan(project, plan)
                )
            }
            Self::ForceDeleted { project, report } => {
                writeln!(w, "force-deleted {}", summarize_plan(project, report))
            }
            Self::Deleted { name } => writeln!(w, "deleted project `{name}`"),
            Self::Exported {
                project,
                data_only,
                include_identity,
                out,
            } => writeln!(
                w,
                "exported project `{project}` ({}{}) -> {out}",
                if *data_only { "data-only" } else { "full" },
                if *include_identity { " +identity" } else { "" },
            ),
            Self::Imported {
                applied, report, ..
            } => {
                if !applied {
                    writeln!(
                        w,
                        "project import DRY-RUN (no mutation; re-run with --apply):"
                    )?;
                }
                write!(w, "{report}")?;
                if !report.ends_with('\n') {
                    writeln!(w)?;
                }
                Ok(())
            }
            Self::ClonePlanned { plan } => {
                writeln!(
                    w,
                    "clone plan for `{}` ← `{}` ({}):",
                    plan.target_project,
                    plan.source_project,
                    if plan.data_only { "data-only" } else { "full" },
                )?;
                writeln!(
                    w,
                    "  blobs: {} to transfer, {} already present, {} total ({})",
                    plan.blobs_to_transfer,
                    plan.blobs_present,
                    plan.blobs_total,
                    approx_bytes(plan.bytes_to_transfer, plan.bytes_exact),
                )?;
                if !plan.non_blob_members.is_empty() {
                    writeln!(w, "  members: {}", plan.non_blob_members.join(", "))?;
                }
                writeln!(
                    w,
                    "  (dry-run — nothing transferred; re-run with --apply to execute)"
                )
            }
            Self::Cloned { plan, report } => {
                writeln!(
                    w,
                    "cloned `{}` ← `{}` ({}): transferred {} of {} blobs ({}){}",
                    plan.target_project,
                    plan.source_project,
                    if plan.data_only { "data-only" } else { "full" },
                    plan.blobs_to_transfer,
                    plan.blobs_total,
                    approx_bytes(plan.bytes_to_transfer, plan.bytes_exact),
                    if report.dry_run {
                        " [validate-only]"
                    } else {
                        ""
                    },
                )?;
                writeln!(
                    w,
                    "  restored: {} blobs, pg {}, libsql {}, kv {} records",
                    report.blobs, report.pg_databases, report.libsql_databases, report.kv_records,
                )?;
                for note in &report.notes {
                    writeln!(w, "  note: {note}")?;
                }
                Ok(())
            }
            Self::Passthrough => Ok(()),
        }
    }
}

/// Entry point for `boatramp project`.
pub async fn run(
    args: ProjectArgs,
    config: &ProjectConfig,
    mode: crate::output::OutputMode,
) -> Result<ProjectOutput> {
    let (server, http) = client::connect(args.server, config)?;
    // The project-collection endpoints (list/create/get/delete) are not project-scoped, so
    // the resolved project is inert for them; `migrate`, however, targets the active
    // `--project`'s migrate surface via its `project_seg`, so we resolve it here.
    let cp = client::ControlPlane::new(server, http, client::resolve_project(config));

    match args.command {
        ProjectCommand::Create {
            name,
            display,
            description,
            region,
        } => {
            let mut body = serde_json::Map::new();
            body.insert("name".into(), serde_json::Value::String(name.clone()));
            if let Some(d) = display {
                body.insert("display".into(), serde_json::Value::String(d));
            }
            if let Some(d) = description {
                body.insert("description".into(), serde_json::Value::String(d));
            }
            if let Some(r) = region {
                body.insert("region".into(), serde_json::Value::String(r));
            }
            cp.create_project(&serde_json::Value::Object(body)).await?;
            Ok(ProjectOutput::Created { name })
        }
        ProjectCommand::Ls => {
            let projects = cp.list_projects().await?;
            Ok(ProjectOutput::List { projects })
        }
        ProjectCommand::Show { name } => {
            let project = cp.get_project(&name).await?;
            Ok(ProjectOutput::Show { project })
        }
        ProjectCommand::Doctor => doctor(&cp, mode).await,
        ProjectCommand::Rm {
            name,
            force,
            dry_run,
            yes,
        } => {
            if dry_run {
                // Preview only — mutate nothing.
                let plan = cp.project_teardown_plan(&name).await?;
                Ok(ProjectOutput::RmDryRun {
                    project: name,
                    plan,
                })
            } else if force {
                // Always show the plan first, then require confirmation unless -y. The
                // preview + prompt are the interactive confirm flow (direct stdout/stdin),
                // not the command's typed result.
                let plan = cp.project_teardown_plan(&name).await?;
                println!("{}", summarize_plan(&name, &plan));
                if !yes {
                    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                        return Err(Error::Aborted(
                            "refusing to force-delete non-interactively; pass --yes to confirm"
                                .to_string(),
                        ));
                    }
                    use std::io::Write;
                    print!(
                        "this permanently destroys the above and cannot be undone; \
                         type the project name to confirm: "
                    );
                    std::io::stdout().flush().map_err(Error::Io)?;
                    let mut typed = String::new();
                    std::io::stdin().read_line(&mut typed).map_err(Error::Io)?;
                    if !confirmation_matches(&name, &typed) {
                        return Err(Error::Aborted(format!(
                            "confirmation `{}` does not match project `{name}` — aborted",
                            typed.trim()
                        )));
                    }
                }
                let report = cp.force_delete_project(&name).await?;
                Ok(ProjectOutput::ForceDeleted {
                    project: name,
                    report,
                })
            } else {
                match cp.delete_project(&name).await {
                    Ok(()) => Ok(ProjectOutput::Deleted { name }),
                    // The server's `409` enumerated refusal, printed verbatim plus a
                    // hint to cascade instead.
                    Err(crate::client::ClientError::Refused(msg)) => Err(Error::Aborted(format!(
                        "{msg}\n… or `project rm {name} --force` to cascade the teardown"
                    ))),
                    Err(e) => Err(e.into()),
                }
            }
        }
        ProjectCommand::Migrate(margs) => {
            crate::project_migrate::run(margs, &cp).await?;
            Ok(ProjectOutput::Passthrough)
        }
        ProjectCommand::Repair(rargs) => {
            crate::project_repair::run(rargs, &cp).await?;
            Ok(ProjectOutput::Passthrough)
        }
        ProjectCommand::Export {
            name,
            out,
            resumable,
            mode,
            base,
            full,
            include_identity,
            transport_key_file,
        } => {
            // `--include-identity` implies a FULL bundle (data-only carries no
            // control-plane / identity), and needs a transport key to wrap the KEK.
            let data_only = !full && !include_identity;
            // A delta (`--mode` + `--base`, enforced paired by clap `requires`) only makes sense
            // for a resumable export — the base is a node-local member-object dir.
            if mode.is_some() && resumable.is_none() {
                return Err(Error::Aborted(
                    "--mode/--base (delta export) require --resumable: a delta chains onto a \
                     node-local member-object directory"
                        .into(),
                ));
            }
            let transport_key = if include_identity {
                Some(resolve_transport_key(
                    transport_key_file.as_deref(),
                    "Transport passphrase (wraps the exported KEK): ",
                )?)
            } else {
                None
            };
            if let Some(dir_name) = resumable {
                // RESUMABLE: the bundle is written to a node-local directory (resuming an
                // interrupted run); nothing streams back to the client. A delta export also
                // passes --mode/--base so the node chains onto the named base.
                cp.project_export_resumable(
                    &name,
                    data_only,
                    include_identity,
                    transport_key,
                    &dir_name,
                    mode.as_deref(),
                    base.as_deref(),
                )
                .await?;
                let kind = match mode.as_deref() {
                    Some(m) => format!("{m} delta onto {}", base.as_deref().unwrap_or("?")),
                    None => "full".to_string(),
                };
                Ok(ProjectOutput::Exported {
                    project: name,
                    data_only,
                    include_identity,
                    out: format!("(resumable node dir: {dir_name}; {kind})"),
                })
            } else {
                // clap's `required_unless_present = "resumable"` guarantees `out` here.
                let out = out.expect("clap requires --out unless --resumable");
                cp.project_export(&name, data_only, include_identity, transport_key, &out)
                    .await?;
                Ok(ProjectOutput::Exported {
                    project: name,
                    data_only,
                    include_identity,
                    out: out.display().to_string(),
                })
            }
        }
        ProjectCommand::Import {
            name,
            input,
            resumable,
            apply,
            force,
            allow_schema_skew,
            overwrite,
            identity,
            transport_key_file,
            clone_from,
            clone_source_project,
            clone_source_token_file,
            clone_data_only,
            clone_verify,
        } => {
            // STREAMING CLONE from a live source node — a distinct mode (no bundle file).
            if let Some(source_url) = clone_from {
                let source_token = resolve_source_token(clone_source_token_file.as_deref())?;
                let outcome = cp
                    .project_clone_from(
                        &name,
                        &source_url,
                        clone_source_project.as_deref(),
                        &source_token,
                        apply,
                        clone_verify,
                        overwrite,
                        force,
                        clone_data_only,
                    )
                    .await?;
                return Ok(match outcome {
                    crate::client::CloneOutcome::Planned(plan) => {
                        ProjectOutput::ClonePlanned { plan }
                    }
                    crate::client::CloneOutcome::Applied { plan, report } => {
                        ProjectOutput::Cloned { plan, report }
                    }
                });
            }
            let transport_key = if identity == "adopt" {
                Some(resolve_transport_key(
                    transport_key_file.as_deref(),
                    "Transport passphrase (opens the bundle's KEK): ",
                )?)
            } else {
                None
            };
            let report = if let Some(dir_name) = resumable {
                // RESUMABLE: read the member-object directory on the node (no body sent).
                cp.project_import_resumable(
                    &name,
                    &dir_name,
                    apply,
                    force,
                    allow_schema_skew,
                    overwrite,
                    &identity,
                    transport_key,
                )
                .await?
            } else {
                let input = input.expect("clap requires --in unless --resumable");
                cp.project_import(
                    &name,
                    &input,
                    apply,
                    force,
                    allow_schema_skew,
                    overwrite,
                    &identity,
                    transport_key,
                )
                .await?
            };
            Ok(ProjectOutput::Imported {
                project: name,
                applied: apply,
                report,
            })
        }
        ProjectCommand::TenantSecrets(tsargs) => {
            crate::project_tenant_secrets::run(tsargs, &cp).await?;
            Ok(ProjectOutput::Passthrough)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal top-level parser mirroring `main`'s `project` arm, so the
    /// `project rm …` flag surface can be arg-parsed in isolation.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Project(ProjectArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<ProjectCommand, clap::Error> {
        let cli = Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))?;
        let Cmd::Project(args) = cli.cmd;
        Ok(args.command)
    }

    #[test]
    fn rm_flags_parse() {
        // Bare `rm <name>` → no force, no dry-run, no yes.
        match parse(&["project", "rm", "acme"]) {
            Ok(ProjectCommand::Rm {
                name,
                force,
                dry_run,
                yes,
            }) => {
                assert_eq!(name, "acme");
                assert!(!force && !dry_run && !yes);
            }
            other => panic!("expected rm, got {other:?}"),
        }
        // `--force --dry-run -y` all set (short `-y` for `--yes`).
        match parse(&["project", "rm", "acme", "--force", "--dry-run", "-y"]) {
            Ok(ProjectCommand::Rm {
                force,
                dry_run,
                yes,
                ..
            }) => {
                assert!(force && dry_run && yes);
            }
            other => panic!("expected rm with flags, got {other:?}"),
        }
        // `--yes` long form.
        match parse(&["project", "rm", "acme", "--yes"]) {
            Ok(ProjectCommand::Rm { yes, .. }) => assert!(yes),
            other => panic!("expected rm --yes, got {other:?}"),
        }
        // `rm` requires a name.
        assert!(parse(&["project", "rm"]).is_err());
    }

    #[test]
    fn clone_import_flags_parse_and_are_mutually_exclusive() {
        // `--clone-from` is a third import mode: no `--in` / `--resumable` required.
        match parse(&[
            "project",
            "import",
            "acme",
            "--clone-from",
            "https://src.example.com",
            "--apply",
        ]) {
            Ok(ProjectCommand::Import {
                name,
                clone_from,
                clone_source_project,
                input,
                resumable,
                apply,
                ..
            }) => {
                assert_eq!(name, "acme");
                assert_eq!(clone_from.as_deref(), Some("https://src.example.com"));
                assert!(clone_source_project.is_none());
                assert!(input.is_none() && resumable.is_none());
                assert!(apply);
            }
            other => panic!("expected clone import, got {other:?}"),
        }
        // `--clone-source-project` + data-only knob ride along.
        match parse(&[
            "project",
            "import",
            "beta",
            "--clone-from",
            "https://src.example.com",
            "--clone-source-project",
            "acme",
            "--clone-data-only",
        ]) {
            Ok(ProjectCommand::Import {
                clone_source_project,
                clone_data_only,
                ..
            }) => {
                assert_eq!(clone_source_project.as_deref(), Some("acme"));
                assert!(clone_data_only);
            }
            other => panic!("expected clone import with source project, got {other:?}"),
        }
        // `--clone-from` is mutually exclusive with `--in` and with `--resumable`.
        assert!(
            parse(&[
                "project",
                "import",
                "acme",
                "--clone-from",
                "https://s",
                "--in",
                "/tmp/b.brproj"
            ])
            .is_err(),
            "--clone-from must conflict with --in"
        );
        assert!(
            parse(&[
                "project",
                "import",
                "acme",
                "--clone-from",
                "https://s",
                "--resumable",
                "d"
            ])
            .is_err(),
            "--clone-from must conflict with --resumable"
        );
        // Without any mode, `--in` is still required (the clone mode did not relax that).
        assert!(
            parse(&["project", "import", "acme"]).is_err(),
            "import still needs one of --in / --resumable / --clone-from"
        );
        // `--clone-verify` parses with `--clone-from`, and is mutually exclusive with `--apply`
        // (verify is the stream-level validate for a NON-apply run; the default is the cheap plan).
        match parse(&[
            "project",
            "import",
            "acme",
            "--clone-from",
            "https://src.example.com",
            "--clone-verify",
        ]) {
            Ok(ProjectCommand::Import {
                clone_verify,
                apply,
                ..
            }) => {
                assert!(clone_verify);
                assert!(!apply);
            }
            other => panic!("expected clone import with verify, got {other:?}"),
        }
        assert!(
            parse(&[
                "project",
                "import",
                "acme",
                "--clone-from",
                "https://s",
                "--clone-verify",
                "--apply",
            ])
            .is_err(),
            "--clone-verify must conflict with --apply"
        );
    }

    #[test]
    fn confirmation_match_is_exact_after_trim() {
        // An exact typed name (with the trailing newline stdin leaves) authorizes.
        assert!(confirmation_matches("acme", "acme\n"));
        assert!(confirmation_matches("acme", "  acme  "));
        // Any mismatch aborts.
        assert!(!confirmation_matches("acme", "acm"));
        assert!(!confirmation_matches("acme", "acme-prod"));
        assert!(!confirmation_matches("acme", ""));
        assert!(!confirmation_matches("acme", "Acme"));
    }

    #[test]
    fn summarize_plan_reads_families() {
        let plan = serde_json::json!({
            "project": "x",
            "sites": ["a", "b"],
            "functions": ["f"],
            "compute": [{ "name": "pg", "volumes": ["pg-data"] }],
            "secrets": ["s1", "s2", "s3"],
            "safelist": 2,
            "subgraphs": ["users"],
            "other_families": {}
        });
        let s = summarize_plan("x", &plan);
        assert!(s.contains("2 sites (a, b)"), "{s}");
        assert!(s.contains("1 function (f)"), "{s}");
        assert!(s.contains("pg + volume pg-data"), "{s}");
        assert!(s.contains("3 secrets"), "{s}");
        assert!(s.contains("2 graphql safelist entries"), "{s}");
        assert!(s.contains("1 subgraph (users)"), "{s}");

        // An empty plan says so.
        let empty = serde_json::json!({ "project": "x" });
        assert_eq!(summarize_plan("x", &empty), "project `x` owns nothing");
    }
}
