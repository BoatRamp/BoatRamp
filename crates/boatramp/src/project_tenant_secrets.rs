//! `boatramp project tenant-secrets set/ls/rm/rotate --tenant <t>` (task #493): manage a project's
//! **per-tenant** sealed secret store — each firm's OWN third-party credential (e.g. an OAuth
//! `client_secret`), sealed server-side under `(project, tenant, name)` with the operator's
//! `[secrets]` envelope.
//!
//! Like `boatramp secrets`, the value never leaves the store over the API — this command only ever
//! SENDS a plaintext to be sealed (`set`/`rotate`) or reads value-free metadata (`ls`). It is
//! DELIBERATELY nested under `project` (not the bare `boatramp secrets`, which is the per-project
//! `boatramp:<name>` env store): the two are different keyspaces, and the tenant dimension is
//! specific to this runtime store. The `--project` global flag selects the project; `--tenant`
//! names the firm within it.

use clap::Subcommand;

use crate::client::ControlPlane;

/// A failure in the `project tenant-secrets` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A control-plane request failed or was refused (the server's status + value-free body — e.g.
    /// the no-envelope `501`, or an invalid-tenant/name `400`).
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Reading the plaintext from a `--file` (or stdin) failed.
    #[error("reading secret value: {0}")]
    Read(#[source] std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// The three ways to supply a secret's plaintext, mutually exclusive (identical to `boatramp
/// secrets`). `--stdin`/`--file` are preferred; `--value` lands in shell history.
#[derive(Debug, clap::Args)]
struct ValueSource {
    /// Read the plaintext from standard input (preferred: nothing hits argv/history).
    #[arg(long, group = "value_source")]
    stdin: bool,
    /// Read the plaintext from a file.
    #[arg(long, group = "value_source", value_name = "PATH")]
    file: Option<std::path::PathBuf>,
    /// The plaintext inline. Convenient, but it lands in your shell history and the process table —
    /// prefer `--stdin` or `--file` for anything sensitive.
    #[arg(long, group = "value_source", value_name = "VALUE")]
    value: Option<String>,
}

/// Arguments for `boatramp project tenant-secrets`.
#[derive(Debug, clap::Args)]
pub struct TenantSecretsArgs {
    #[command(subcommand)]
    command: TenantSecretsCommand,
}

#[derive(Debug, Subcommand)]
enum TenantSecretsCommand {
    /// Set (or rotate) a per-tenant secret: seal `value` server-side under `(tenant, name)`.
    /// Setting an existing name rotates it (a new revision, same `created_at`).
    Set {
        /// The tenant (firm) id the secret belongs to.
        #[arg(long)]
        tenant: String,
        /// The secret name (what the guest names in a `tenant-secrets` `get`).
        name: String,
        #[command(flatten)]
        source: ValueSource,
    },
    /// Rotate a per-tenant secret — an alias for `set` (overwrite in place), for intent-clarity.
    Rotate {
        /// The tenant (firm) id.
        #[arg(long)]
        tenant: String,
        /// The secret name.
        name: String,
        #[command(flatten)]
        source: ValueSource,
    },
    /// List one tenant's secrets: name / revision / last-updated. Never a value, and only this
    /// tenant's names (never project-wide).
    Ls {
        /// The tenant (firm) id to list.
        #[arg(long)]
        tenant: String,
    },
    /// Remove a per-tenant secret by name.
    Rm {
        /// The tenant (firm) id.
        #[arg(long)]
        tenant: String,
        /// The secret name.
        name: String,
    },
}

/// Entry point for `boatramp project tenant-secrets`, given a resolved [`ControlPlane`] (the
/// `project` command already resolved `--project` + the server + client).
pub async fn run(args: TenantSecretsArgs, cp: &ControlPlane) -> Result<()> {
    match args.command {
        TenantSecretsCommand::Set {
            tenant,
            name,
            source,
        }
        | TenantSecretsCommand::Rotate {
            tenant,
            name,
            source,
        } => {
            let value = read_value(source)?;
            let meta = cp.tenant_secret_set(&tenant, &name, &value).await?;
            // Never echo the value; confirm by metadata only.
            println!("set {}/{} (revision {})", tenant, meta.name, meta.revision);
        }
        TenantSecretsCommand::Ls { tenant } => {
            let secrets = cp.tenant_secret_list(&tenant).await?;
            if secrets.is_empty() {
                println!("no secrets for tenant {tenant}");
                return Ok(());
            }
            println!("{:<32}  {:>8}  UPDATED", "NAME", "REVISION");
            for s in secrets {
                println!("{:<32}  {:>8}  {}", s.name, s.revision, s.updated_at);
            }
        }
        TenantSecretsCommand::Rm { tenant, name } => {
            if cp.tenant_secret_delete(&tenant, &name).await? {
                println!("removed {tenant}/{name}");
            } else {
                println!("no matching secret {tenant}/{name}");
            }
        }
    }
    Ok(())
}

/// Read the plaintext from exactly one of stdin / a file / an inline `--value` (identical to
/// `boatramp secrets`). Clap's `group` enforces mutual exclusion; this requires one is present.
fn read_value(source: ValueSource) -> Result<String> {
    use std::io::Read as _;
    if source.stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(Error::Read)?;
        Ok(buf.trim_end_matches('\n').to_string())
    } else if let Some(path) = source.file {
        let bytes = std::fs::read(&path).map_err(Error::Read)?;
        String::from_utf8(bytes)
            .map_err(|e| Error::Read(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
            .map(|s| s.trim_end_matches('\n').to_string())
    } else if let Some(value) = source.value {
        Ok(value)
    } else {
        Err(Error::Read(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a value is required: pass one of --stdin, --file <path>, or --value <VALUE>",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal parser mirroring `project`'s nesting: the global `--project` + a `tenant-secrets`
    /// subcommand, so we can arg-parse `project tenant-secrets …` in isolation.
    #[derive(Parser)]
    struct Cli {
        #[arg(long, global = true, env = "BOATRAMP_PROJECT")]
        project: Option<String>,
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        TenantSecrets(TenantSecretsArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))
    }

    #[test]
    fn set_requires_tenant_and_exactly_one_value_source() {
        assert!(parse(&[
            "tenant-secrets",
            "set",
            "--tenant",
            "firm-1",
            "oauth",
            "--value",
            "s"
        ])
        .is_ok());
        assert!(parse(&[
            "tenant-secrets",
            "set",
            "--tenant",
            "firm-1",
            "oauth",
            "--stdin"
        ])
        .is_ok());
        // Missing --tenant is a parse error.
        assert!(parse(&["tenant-secrets", "set", "oauth", "--value", "s"]).is_err());
        // Two value sources are mutually exclusive.
        assert!(parse(&[
            "tenant-secrets",
            "set",
            "--tenant",
            "firm-1",
            "oauth",
            "--stdin",
            "--value",
            "x"
        ])
        .is_err());
    }

    #[test]
    fn ls_rm_rotate_parse_with_tenant() {
        assert!(parse(&["tenant-secrets", "ls", "--tenant", "firm-1"]).is_ok());
        assert!(parse(&["tenant-secrets", "rm", "--tenant", "firm-1", "oauth"]).is_ok());
        assert!(parse(&[
            "tenant-secrets",
            "rotate",
            "--tenant",
            "firm-1",
            "oauth",
            "--stdin"
        ])
        .is_ok());
        // ls without --tenant is refused (never project-wide).
        assert!(parse(&["tenant-secrets", "ls"]).is_err());
    }

    #[test]
    fn the_global_project_flag_reaches_the_subcommand() {
        let cli = parse(&[
            "tenant-secrets",
            "--project",
            "acme",
            "ls",
            "--tenant",
            "firm-1",
        ])
        .expect("parses");
        assert_eq!(cli.project.as_deref(), Some("acme"));
    }
}
