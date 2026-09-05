//! The `email` subcommand: manage a project's SMTP delivery profiles.
//!
//! A profile is the connection config (host / port / security / AUTH) for one SMTP
//! relay plus a default sender. The **password is sealed server-side** with the
//! operator's `[secrets]` key envelope and stored per-project; it never leaves the
//! store over the API — `ls`/`show` return only the redacted config. A guest
//! function/handler *uses* a profile by importing the `email` capability and calling
//! `send`; it can neither read nor reconfigure a profile (that is this command's
//! job, gated by a boatramp token).
//!
//! Scoping follows the uniform project rule: the global `--project` /
//! `BOATRAMP_PROJECT` flag (falling back to `[publish].project`, else `default`)
//! selects the tenant, exactly like `function` / `compute` / `secrets`.

use boatramp_core::email_config::EmailProfileInfo;
use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `email` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server / building the client failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Reading the password from stdin failed.
    #[error("reading SMTP password: {0}")]
    Read(#[source] std::io::Error),
    /// The server refused the request; carries the status + its (password-free) body
    /// so the operator sees the reason (the no-envelope `501`, an invalid config…).
    #[error("server returned HTTP {status}: {body}")]
    Server { status: u16, body: String },
}

/// `email` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp email`.
#[derive(Debug, clap::Args)]
pub struct EmailArgs {
    /// boatramp server base URL (overrides [publish].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: EmailCommand,
}

/// How to supply the SMTP AUTH password (mutually exclusive; omit both for an
/// unauthenticated relay). `--password-stdin` is preferred — nothing hits argv.
#[derive(Debug, clap::Args)]
struct PasswordSource {
    /// The SMTP AUTH password inline. Convenient, but it lands in your shell history
    /// and the process table — prefer `--password-stdin` for anything sensitive.
    #[arg(long, group = "password_source", value_name = "PASSWORD")]
    password: Option<String>,
    /// Read the SMTP AUTH password from standard input (preferred).
    #[arg(long, group = "password_source")]
    password_stdin: bool,
}

#[derive(Debug, Subcommand)]
enum EmailCommand {
    /// Set (or reconfigure) an SMTP profile: seal its password server-side under
    /// `name`. Setting an existing name reconfigures it in place (a new revision,
    /// same `created_at`).
    Set {
        /// The profile name (a guest selects it via the message's `profile`; omit in
        /// the guest to use `default`).
        name: String,
        /// SMTP relay hostname.
        #[arg(long)]
        host: String,
        /// SMTP relay port; omit for the conventional port of `--security`
        /// (587 starttls / 465 tls / 25 plaintext).
        #[arg(long)]
        port: Option<u16>,
        /// Transport security: `starttls` (587), `tls` (implicit, 465), or
        /// `plaintext` (a trusted local relay only).
        #[arg(long, default_value = "starttls")]
        security: String,
        /// SMTP AUTH username (omit for an unauthenticated relay).
        #[arg(long)]
        username: Option<String>,
        #[command(flatten)]
        password: PasswordSource,
        /// The default (and only permitted) `From` address for this profile.
        #[arg(long)]
        from: String,
        /// Default sends through this profile to the durable spool (persisted +
        /// retried); a guest can still opt in/out per message.
        #[arg(long)]
        durable: bool,
    },
    /// List the project's SMTP profiles (redacted — never the password).
    Ls,
    /// Show one profile's redacted config.
    Show {
        /// The profile name.
        name: String,
    },
    /// Remove a profile by name.
    Rm {
        /// The profile name.
        name: String,
    },
}

/// Entry point for `boatramp email`.
pub async fn run(args: EmailArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    // The project-scoped collection segment (`email` for the default project, else
    // `projects/<proj>/email`) — the same `--project` routing as secrets/function.
    let seg = client::project_seg(&client::resolve_project(config), "email");

    match args.command {
        EmailCommand::Set {
            name,
            host,
            port,
            security,
            username,
            password,
            from,
            durable,
        } => {
            let password = read_password(password)?;
            let resp = http
                .put(format!("{server}/api/{seg}/profiles/{name}"))
                .json(&SetProfileRequest {
                    host: &host,
                    port,
                    security: &security,
                    username: username.as_deref(),
                    password,
                    from: &from,
                    durable,
                })
                .send()
                .await?;
            let info: EmailProfileInfo = parse_json(resp).await?;
            // Never echo the password; confirm by redacted config only.
            println!(
                "set email profile {} ({} {}:{} from {})",
                info.name, info.security, info.host, info.port, info.from
            );
        }
        EmailCommand::Ls => {
            let resp = http
                .get(format!("{server}/api/{seg}/profiles"))
                .send()
                .await?;
            let profiles: Vec<EmailProfileInfo> = parse_json(resp).await?;
            if profiles.is_empty() {
                println!("no email profiles");
                return Ok(());
            }
            println!(
                "{:<20}  {:<28}  {:<10}  {:<28}  DURABLE",
                "NAME", "HOST", "SECURITY", "FROM"
            );
            for p in profiles {
                println!(
                    "{:<20}  {:<28}  {:<10}  {:<28}  {}",
                    p.name,
                    format!("{}:{}", p.host, p.port),
                    p.security,
                    p.from,
                    p.durable
                );
            }
        }
        EmailCommand::Show { name } => {
            let resp = http
                .get(format!("{server}/api/{seg}/profiles/{name}"))
                .send()
                .await?;
            let p: EmailProfileInfo = parse_json(resp).await?;
            println!("name:     {}", p.name);
            println!("host:     {}:{}", p.host, p.port);
            println!("security: {}", p.security);
            println!(
                "username: {}",
                p.username.as_deref().unwrap_or("(none — unauthenticated)")
            );
            println!(
                "password: {}",
                if p.has_password {
                    "(set, sealed)"
                } else {
                    "(none)"
                }
            );
            println!("from:     {}", p.from);
            println!("durable:  {}", p.durable);
        }
        EmailCommand::Rm { name } => {
            let resp = http
                .delete(format!("{server}/api/{seg}/profiles/{name}"))
                .send()
                .await?;
            check_no_content(resp).await?;
            println!("removed email profile {name}");
        }
    }
    Ok(())
}

/// The `set` request body — mirrors the server's `SetEmailProfileRequest`. The
/// server seals `password` and stores the profile under the path `name`.
#[derive(serde::Serialize)]
struct SetProfileRequest<'a> {
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    security: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    from: &'a str,
    durable: bool,
}

/// Read the password from stdin / inline / neither (an unauthenticated relay).
fn read_password(source: PasswordSource) -> Result<Option<String>> {
    use std::io::Read as _;
    if source.password_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(Error::Read)?;
        Ok(Some(buf.trim_end_matches('\n').to_string()))
    } else if let Some(pw) = source.password {
        Ok(Some(pw))
    } else {
        Ok(None)
    }
}

/// Deserialize a JSON success body, mapping a non-2xx status to a legible
/// [`Error::Server`] carrying the server's (password-free) message.
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

    #[derive(Parser)]
    struct Cli {
        #[arg(long, global = true, env = "BOATRAMP_PROJECT")]
        project: Option<String>,
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Email(EmailArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))
    }

    #[test]
    fn set_parses_with_and_without_a_password_source() {
        // No password → an unauthenticated relay.
        assert!(parse(&[
            "email",
            "set",
            "default",
            "--host",
            "smtp.example.com",
            "--from",
            "a@b.com",
        ])
        .is_ok());
        // Inline or stdin password parse.
        assert!(parse(&[
            "email",
            "set",
            "default",
            "--host",
            "h",
            "--from",
            "a@b.com",
            "--password",
            "pw",
        ])
        .is_ok());
        assert!(parse(&[
            "email",
            "set",
            "default",
            "--host",
            "h",
            "--from",
            "a@b.com",
            "--password-stdin",
        ])
        .is_ok());
        // Two password sources at once are mutually exclusive → a parse error.
        assert!(parse(&[
            "email",
            "set",
            "default",
            "--host",
            "h",
            "--from",
            "a@b.com",
            "--password",
            "pw",
            "--password-stdin",
        ])
        .is_err());
    }

    #[test]
    fn ls_show_rm_parse_and_project_flag_reaches_the_subcommand() {
        assert!(parse(&["email", "ls"]).is_ok());
        assert!(parse(&["email", "show", "default"]).is_ok());
        assert!(parse(&["email", "rm", "default"]).is_ok());
        let cli = parse(&["email", "--project", "acme", "ls"]).expect("parses");
        assert_eq!(cli.project.as_deref(), Some("acme"));
    }
}
