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
    /// Delete a project. Refused while it owns resources (unless `--force`) or if it
    /// is the reserved `default`.
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
}

/// Whether a `--force` confirmation `typed` at the prompt authorizes deleting
/// `project` — an exact match (after trimming surrounding whitespace/newline) of the
/// project name. A pure function so the confirmation gate is unit-testable without a
/// TTY.
fn confirmation_matches(project: &str, typed: &str) -> bool {
    typed.trim() == project
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
    if let Some(compute) = plan.get("compute").and_then(|v| v.as_array()) {
        if !compute.is_empty() {
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
    }
    let secrets = arr("secrets");
    if !secrets.is_empty() {
        parts.push(format!(
            "{} secret{}",
            secrets.len(),
            if secrets.len() == 1 { "" } else { "s" }
        ));
    }
    if let Some(n) = plan.get("safelist").and_then(serde_json::Value::as_u64) {
        if n > 0 {
            parts.push(format!(
                "{n} graphql safelist entr{}",
                if n == 1 { "y" } else { "ies" }
            ));
        }
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

/// Entry point for `boatramp project`.
pub async fn run(args: ProjectArgs, config: &ProjectConfig) -> Result<()> {
    let (server, http) = client::connect(args.server, config)?;
    // The `project` subcommand only calls project-collection endpoints (list/create/
    // get/delete), which are not site-scoped, so the resolved project is inert here —
    // passed only to satisfy the constructor.
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
            println!("created project `{name}`");
        }
        ProjectCommand::Ls => {
            let projects = cp.list_projects().await?;
            if projects.is_empty() {
                println!("no projects");
            } else {
                for p in projects {
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let display = p
                        .get("meta")
                        .and_then(|m| m.get("display"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty());
                    match display {
                        Some(d) => println!("{name}\t{d}"),
                        None => println!("{name}"),
                    }
                }
            }
        }
        ProjectCommand::Show { name } => {
            let project = cp.get_project(&name).await?;
            println!("{}", serde_json::to_string_pretty(&project)?);
        }
        ProjectCommand::Rm {
            name,
            force,
            dry_run,
            yes,
        } => {
            if dry_run {
                // Preview only — mutate nothing.
                let plan = cp.project_teardown_plan(&name).await?;
                println!(
                    "{} — nothing deleted (--dry-run)",
                    summarize_plan(&name, &plan)
                );
            } else if force {
                // Always show the plan first, then require confirmation unless -y.
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
                println!("force-deleted {}", summarize_plan(&name, &report));
            } else {
                match cp.delete_project(&name).await {
                    Ok(()) => println!("deleted project `{name}`"),
                    // The server's `409` enumerated refusal, printed verbatim plus a
                    // hint to cascade instead.
                    Err(crate::client::ClientError::Refused(msg)) => {
                        return Err(Error::Aborted(format!(
                            "{msg}\n… or `project rm {name} --force` to cascade the teardown"
                        )));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(())
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
