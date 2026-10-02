//! The `tenancy` subcommand: manage a project's tenancy schema — the per-table
//! tenant-key map the host scope injector consults when scoping guest `sql`/`orm`
//! queries.
//!
//! The schema names each table's [`TableScope`](boatramp_core::tenancy::TableScope):
//! `tenant` (keyed on the project default tenant column), `tenant_keyed` (keyed on a
//! named column — e.g. the identity table on its own primary key), or `unscoped` (a
//! shared reference table, no tenant predicate). A table that appears in **no** entry
//! is **denied** — deny-by-default — so a query touching it is refused rather than
//! silently unscoped.
//!
//! Mutating the schema redraws the isolation boundary for every guest query, so the
//! server gates `apply`/`clear` at `Project·Admin` (never the deploy-grade publisher
//! right). Scoping follows the uniform project rule: the global `--project` /
//! `BOATRAMP_PROJECT` flag selects the tenant, exactly like `secrets` / `email`.
//!
//! The on-disk format is JSON (round-trips cleanly with `show`): `boatramp tenancy
//! show > schema.json`, edit, `boatramp tenancy apply schema.json`.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `tenancy` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server / building the client failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed (incl. a non-2xx status — e.g. a
    /// `403` when the token lacks `Project·Admin`).
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Reading the schema file failed.
    #[error("reading schema file {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The schema file was not valid JSON for a [`TenancySchema`].
    #[error("parsing schema file {path}: {source}")]
    Parse {
        /// The path whose contents did not parse.
        path: String,
        /// The underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// Serializing the fetched schema for display failed (should never happen).
    #[error("rendering schema: {0}")]
    Render(#[source] serde_json::Error),
}

/// `tenancy` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp tenancy`.
#[derive(Debug, clap::Args)]
pub struct TenancyArgs {
    /// boatramp server base URL (overrides [publish].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: TenancyCommand,
}

#[derive(Debug, Subcommand)]
enum TenancyCommand {
    /// Print the project's current tenancy schema as JSON. A project that declared
    /// none prints the default schema (`tenant_id`, no tables) — legacy single-column
    /// scoping.
    Show,
    /// Replace the project's tenancy schema from a JSON file (`Project·Admin`).
    Apply {
        /// Path to the schema JSON (as produced by `tenancy show`).
        file: std::path::PathBuf,
    },
    /// Clear the project's tenancy schema, reverting to legacy `Uniform` single-column
    /// scoping (`Project·Admin`). Idempotent.
    Clear,
    /// Dry-run a `token`-source claim transform against a sample claim value, **locally**
    /// (no server), through the SAME `derive_tenant` the host runs. Prints the derived
    /// tenant key, or the exact stage that denied it (the same deny taxonomy the host
    /// logs) — so a regex/template misconfiguration is a 30-second check instead of
    /// staring at silently fail-closed requests.
    TestExtract {
        /// The claim's sample VALUE (e.g. a Salesforce `sub` identity URL).
        #[arg(long)]
        value: String,
        /// A `{tenant}`/`{_}` path template (the recommended surface).
        #[arg(long, conflicts_with = "regex")]
        template: Option<String>,
        /// A single-named-capture regex `(?<tenant>…)` (the escape hatch).
        #[arg(long)]
        regex: Option<String>,
        /// The optional per-issuer namespace (produces `<namespace>:<extracted>`).
        #[arg(long)]
        namespace: Option<String>,
    },
}

/// Local dry-run of the `token`-source claim transform (the `test-extract` subcommand). No server;
/// runs the host's real [`derive_tenant`] and apply-time validators so the verdict matches production.
fn test_extract(
    value: &str,
    template: Option<&str>,
    regex: Option<&str>,
    namespace: Option<&str>,
) -> Result<()> {
    use boatramp_core::claim_extract::{
        DeriveOutcome, derive_tenant, validate_extract, validate_namespace,
    };
    use boatramp_core::tenancy::{ClaimExtract, ExtractSyntax};

    let extract = match (template, regex) {
        (Some(t), _) => Some(ClaimExtract {
            syntax: ExtractSyntax::Template,
            pattern: t.to_string(),
        }),
        (None, Some(r)) => Some(ClaimExtract {
            syntax: ExtractSyntax::Regex,
            pattern: r.to_string(),
        }),
        (None, None) => None,
    };
    // Report config that apply would reject, before attempting the match.
    if let Some(ext) = &extract
        && let Err(e) = validate_extract(ext)
    {
        println!("extract INVALID — apply would reject: {e}");
        return Ok(());
    }
    if let Some(ns) = namespace
        && let Err(e) = validate_namespace(ns)
    {
        println!("namespace INVALID — apply would reject: {e}");
        return Ok(());
    }
    // No transform ⇒ the verbatim path (the host injects the claim value unchanged, unscreened).
    if extract.is_none() && namespace.is_none() {
        println!("no transform configured — tenant = {value:?} (verbatim)");
        return Ok(());
    }
    let claim = serde_json::Value::String(value.to_string());
    match derive_tenant(extract.as_ref(), namespace, &claim) {
        DeriveOutcome::Resolved(key) => println!("resolved tenant key: {key}"),
        DeriveOutcome::ClaimNonString => println!("DENY: claim is not a string"),
        DeriveOutcome::NoMatch { empty_capture } => println!(
            "DENY: extraction did not match the value{}",
            if empty_capture {
                " (matched, but captured the empty string)"
            } else {
                ""
            }
        ),
        DeriveOutcome::KeyRejected(reason) => println!("DENY: derived key rejected — {reason}"),
    }
    Ok(())
}

/// Entry point for `boatramp tenancy`.
pub async fn run(args: TenancyArgs, config: &ProjectConfig) -> Result<()> {
    // `test-extract` is a LOCAL dry-run — handle it before touching the control plane.
    if let TenancyCommand::TestExtract {
        value,
        template,
        regex,
        namespace,
    } = &args.command
    {
        return test_extract(
            value,
            template.as_deref(),
            regex.as_deref(),
            namespace.as_deref(),
        );
    }
    let (server, http) = client::connect(args.server.clone(), config)?;
    let project = client::resolve_project(config);
    let cp = client::ControlPlane::new(server, http, project.clone());

    match args.command {
        TenancyCommand::Show => {
            let schema = cp.get_project_tenancy().await?;
            let rendered = serde_json::to_string_pretty(&schema).map_err(Error::Render)?;
            println!("{rendered}");
        }
        TenancyCommand::Apply { file } => {
            let path = file.display().to_string();
            let bytes = std::fs::read(&file).map_err(|source| Error::Read {
                path: path.clone(),
                source,
            })?;
            let schema: boatramp_core::tenancy::TenancySchema = serde_json::from_slice(&bytes)
                .map_err(|source| Error::Parse {
                    path: path.clone(),
                    source,
                })?;
            cp.put_project_tenancy(&schema).await?;
            println!(
                "applied tenancy schema to project `{project}` ({} table(s))",
                schema.tables.len()
            );
            // #503: surface the WRITE-GLOBAL tables so the operator sees exactly which shared tables
            // any scoped route may write UNSTAMPED — the irreducible operator-trust residual (the
            // host cannot verify a declared-global table is truly tenant-less; a misdeclaration lets
            // any granted route write across tenants).
            let write_global: Vec<&String> = schema
                .tables
                .iter()
                .filter_map(|(name, scope)| {
                    matches!(
                        scope,
                        boatramp_core::tenancy::TableScope::Unscoped { writable: true }
                    )
                    .then_some(name)
                })
                .collect();
            if !write_global.is_empty() {
                let names: Vec<&str> = write_global.iter().map(|s| s.as_str()).collect();
                println!(
                    "  write-global (writable, any scoped route may write UNSTAMPED — ensure these \
                     are genuinely tenant-less): {}",
                    names.join(", ")
                );
            }
        }
        TenancyCommand::Clear => {
            cp.clear_project_tenancy().await?;
            println!("cleared tenancy schema for project `{project}` (legacy Uniform scoping)");
        }
        // Handled by the early-return local dry-run above (no control plane).
        TenancyCommand::TestExtract { .. } => {
            unreachable!("test-extract is handled before connect")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal top-level parser mirroring `main`'s: the global `--project` flag +
    /// the `tenancy` subcommand, so we can arg-parse `boatramp tenancy …` in isolation.
    #[derive(Parser)]
    struct Cli {
        #[arg(long, global = true, env = "BOATRAMP_PROJECT")]
        project: Option<String>,
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Tenancy(TenancyArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))
    }

    #[test]
    fn subcommands_parse() {
        assert!(parse(&["tenancy", "show"]).is_ok());
        assert!(parse(&["tenancy", "apply", "schema.json"]).is_ok());
        assert!(parse(&["tenancy", "clear"]).is_ok());
        // `apply` needs a file argument.
        assert!(parse(&["tenancy", "apply"]).is_err());
        // `test-extract` needs a --value; --template and --regex are mutually exclusive.
        assert!(
            parse(&[
                "tenancy",
                "test-extract",
                "--value",
                "https://login.salesforce.com/id/00D/005",
                "--template",
                "https://login.salesforce.com/id/{tenant}/{_}",
                "--namespace",
                "sfdc",
            ])
            .is_ok()
        );
        assert!(parse(&["tenancy", "test-extract"]).is_err()); // --value required
        assert!(
            parse(&[
                "tenancy",
                "test-extract",
                "--value",
                "x",
                "--template",
                "{tenant}",
                "--regex",
                "(?<tenant>.+)",
            ])
            .is_err() // template + regex conflict
        );
    }

    #[test]
    fn test_extract_runs_the_real_derivation_offline() {
        // The dry-run resolves the SF org id and namespaces it (no server).
        super::test_extract(
            "https://login.salesforce.com/id/00D5f0000000abcEAA/0055f00000ABC",
            Some("https://login.salesforce.com/id/{tenant}/{_}"),
            None,
            Some("sfdc"),
        )
        .expect("dry-run succeeds");
        // A non-matching value denies (prints DENY), still Ok.
        super::test_extract("not-a-url", Some("https://x/{tenant}"), None, Some("sfdc"))
            .expect("dry-run of a non-match still returns Ok (prints a DENY diagnosis)");
    }

    #[test]
    fn the_global_project_flag_reaches_the_subcommand() {
        let cli = parse(&["tenancy", "--project", "acme", "show"]).expect("parses");
        assert_eq!(cli.project.as_deref(), Some("acme"));
        let cli = parse(&["tenancy", "show"]).expect("parses");
        assert_eq!(cli.project, None);
    }
}
