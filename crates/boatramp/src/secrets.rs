//! The `secrets` subcommand: manage a project's internal, sealed secret store.
//!
//! Secrets are sealed **server-side** with the operator's `[secrets]` key envelope
//! and stored per-project; the value never leaves the store over the API. This
//! command therefore only ever *sends* a plaintext to be sealed (`set`/`rotate`) or
//! reads value-free metadata (`ls`) — there is no way to read a value back. A guest
//! consumes a secret by referencing it as `boatramp:<name>` in its `secrets` map,
//! resolved server-side at instantiation.
//!
//! Scoping follows the uniform project rule: the global `--project` /
//! `BOATRAMP_PROJECT` flag (falling back to `[publish].project`, else the `default`
//! project) selects the tenant, exactly like `function` / `compute` — so a secret is
//! set, listed, and removed within one project's sealed keyspace.

use boatramp_core::secret_store::SecretMeta;
use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `secrets` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server / building the client failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Reading the plaintext from a `--file` (or stdin) failed.
    #[error("reading secret value: {0}")]
    Read(#[source] std::io::Error),
    /// The server refused the request; carries the status + its (value-free) body so
    /// the operator sees the reason (e.g. the no-envelope `501`, or an invalid name).
    #[error("server returned HTTP {status}: {body}")]
    Server { status: u16, body: String },
}

/// `secrets` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp secrets`.
#[derive(Debug, clap::Args)]
pub struct SecretsArgs {
    /// boatramp server base URL (overrides [publish].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: SecretsCommand,
}

/// The three ways to supply a secret's plaintext, mutually exclusive. `--stdin` and
/// `--file` are preferred; `--value` is convenient but leaves the plaintext in shell
/// history, so it carries a warning.
#[derive(Debug, clap::Args)]
struct ValueSource {
    /// Read the plaintext from standard input (preferred: nothing hits argv/history).
    #[arg(long, group = "value_source")]
    stdin: bool,
    /// Read the plaintext from a file.
    #[arg(long, group = "value_source", value_name = "PATH")]
    file: Option<std::path::PathBuf>,
    /// The plaintext inline. Convenient, but it lands in your shell history and the
    /// process table — prefer `--stdin` or `--file` for anything sensitive.
    #[arg(long, group = "value_source", value_name = "VALUE")]
    value: Option<String>,
}

#[derive(Debug, Subcommand)]
enum SecretsCommand {
    /// Set (or rotate) a secret: seal `value` server-side under `name`. Setting an
    /// existing name rotates it (a new revision, same `created_at`).
    Set {
        /// The secret name (used as `boatramp:<name>` in a guest's `secrets` map).
        name: String,
        #[command(flatten)]
        source: ValueSource,
    },
    /// Rotate a secret — an alias for `set` (overwrite in place), for intent-clarity.
    Rotate {
        /// The secret name.
        name: String,
        #[command(flatten)]
        source: ValueSource,
    },
    /// List the project's secrets: name / revision / last-updated. Never a value —
    /// the store holds only sealed bytes, and the API never returns them.
    Ls,
    /// Remove a secret by name.
    Rm {
        /// The secret name.
        name: String,
    },
}

/// Entry point for `boatramp secrets`.
pub async fn run(args: SecretsArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    // The project-scoped collection segment (`secrets` for the default project, else
    // `projects/<proj>/secrets`) — the same `--project` routing as function/compute.
    let seg = client::project_seg(&client::resolve_project(config), "secrets");

    match args.command {
        SecretsCommand::Set { name, source } | SecretsCommand::Rotate { name, source } => {
            let value = read_value(source)?;
            let resp = http
                .post(format!("{server}/api/{seg}"))
                .json(&SetRequest {
                    name: &name,
                    value: &value,
                })
                .send()
                .await?;
            let meta: SecretMeta = parse_json(resp).await?;
            // Never echo the value; confirm by metadata only.
            println!("set {} (revision {})", meta.name, meta.revision);
        }
        SecretsCommand::Ls => {
            let resp = http.get(format!("{server}/api/{seg}")).send().await?;
            let secrets: Vec<SecretMeta> = parse_json(resp).await?;
            if secrets.is_empty() {
                println!("no secrets");
                return Ok(());
            }
            println!("{:<32}  {:>8}  UPDATED", "NAME", "REVISION");
            for s in secrets {
                println!("{:<32}  {:>8}  {}", s.name, s.revision, s.updated_at);
            }
        }
        SecretsCommand::Rm { name } => {
            let resp = http
                .delete(format!("{server}/api/{seg}/{name}"))
                .send()
                .await?;
            check_no_content(resp).await?;
            println!("removed {name}");
        }
    }
    Ok(())
}

/// The `set` request body: the server seals `value` and stores it under `name`.
#[derive(serde::Serialize)]
struct SetRequest<'a> {
    name: &'a str,
    value: &'a str,
}

/// Read the plaintext from exactly one of stdin / a file / an inline `--value`.
/// Clap's `group` already enforces mutual exclusion; this requires one is present.
fn read_value(source: ValueSource) -> Result<String> {
    use std::io::Read as _;
    if source.stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(Error::Read)?;
        // A trailing newline from a heredoc/echo is almost never part of the secret.
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

/// Deserialize a JSON success body, mapping a non-2xx status to a legible
/// [`Error::Server`] carrying the server's (value-free) message — so the no-envelope
/// `501` and an invalid-name `400` read clearly instead of as a raw reqwest error.
async fn parse_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        return Err(Error::Server {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).trim().to_string(),
        });
    }
    serde_json::from_slice(&bytes).map_err(|e| Error::Server {
        status: status.as_u16(),
        body: format!("could not parse response: {e}"),
    })
}

/// Expect a `204 No Content` (or any 2xx); surface a non-success status + body.
async fn check_no_content(resp: reqwest::Response) -> Result<()> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let bytes = resp.bytes().await?;
    Err(Error::Server {
        status: status.as_u16(),
        body: String::from_utf8_lossy(&bytes).trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal top-level parser mirroring `main`'s: the global `--project` flag +
    /// the `secrets` subcommand, so we can arg-parse `boatramp secrets …` in isolation.
    #[derive(Parser)]
    struct Cli {
        #[arg(long, global = true, env = "BOATRAMP_PROJECT")]
        project: Option<String>,
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Secrets(SecretsArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))
    }

    #[test]
    fn set_accepts_exactly_one_value_source() {
        // A single source parses.
        assert!(parse(&["secrets", "set", "api-key", "--value", "s3cr3t"]).is_ok());
        assert!(parse(&["secrets", "set", "api-key", "--stdin"]).is_ok());
        assert!(parse(&["secrets", "set", "api-key", "--file", "/tmp/k"]).is_ok());
        // Two sources at once are mutually exclusive → a parse error.
        assert!(parse(&["secrets", "set", "api-key", "--stdin", "--value", "x"]).is_err());
        assert!(parse(&["secrets", "set", "api-key", "--file", "/tmp/k", "--value", "x"]).is_err());
    }

    #[test]
    fn rotate_mirrors_set_and_ls_rm_parse() {
        assert!(parse(&["secrets", "rotate", "api-key", "--stdin"]).is_ok());
        assert!(parse(&["secrets", "ls"]).is_ok());
        assert!(parse(&["secrets", "rm", "api-key"]).is_ok());
    }

    #[test]
    fn the_global_project_flag_reaches_the_secrets_subcommand() {
        // The uniform `--project` flag (default `default`) is honored on secrets, as
        // on every other project-scoped command; parsing it here proves the surface.
        let cli = parse(&["secrets", "--project", "acme", "ls"]).expect("parses");
        assert_eq!(cli.project.as_deref(), Some("acme"));
        // Unset ⇒ the default project (resolved via `client::resolve_project`).
        let cli = parse(&["secrets", "ls"]).expect("parses");
        assert_eq!(cli.project, None);
    }
}
