//! The `build` subcommand and the shared build-command runner.
//!
//! Today building is delegated to an external command (`npm run build`, vite,
//! webpack, esbuild, ...), which makes boatramp framework-agnostic and lets it
//! act as the deploy step of any existing toolchain. The `bundler` cargo
//! feature is reserved for a future in-process Rust bundler.

use std::path::PathBuf;

use crate::config::ProjectConfig;

/// A failure in the `build` / `validate` subcommands.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No build command was configured and none was passed.
    #[error("no build command configured; set build.command in project.cfg or pass --command")]
    NoBuildCommand,
    /// Reading the project config to validate failed.
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Parsing or compile-checking the project config failed.
    #[error("{path}: {source}")]
    Config {
        path: String,
        #[source]
        source: crate::config::ConfigError,
    },
    /// The external build command exited non-zero.
    #[error("build command failed: `{command}` exited with {status}")]
    CommandFailed {
        command: String,
        status: std::process::ExitStatus,
    },
    /// Spawning or running the build command failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `build` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp build`.
#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    /// Override the configured build command.
    #[arg(long)]
    command: Option<String>,
}

/// Entry point for `boatramp build`.
pub async fn run(args: BuildArgs, config: &ProjectConfig) -> Result<()> {
    let command = resolve_command(args.command, config)?;
    run_command(&command).await
}

/// Determine which build command to run, preferring an explicit override.
pub fn resolve_command(override_command: Option<String>, config: &ProjectConfig) -> Result<String> {
    override_command
        .or_else(|| config.build.as_ref().map(|build| build.command.clone()))
        .ok_or(Error::NoBuildCommand)
}

/// Arguments for `boatramp validate`.
#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Path to the project config to validate.
    #[arg(default_value = "project.cfg")]
    path: PathBuf,
}

/// Entry point for `boatramp validate`: parse and compile-check a `project.cfg`
/// (its `routing` section).
pub fn validate(args: ValidateArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.path).map_err(|source| Error::Read {
        path: args.path.display().to_string(),
        source,
    })?;
    let project = ProjectConfig::parse(&text).map_err(|source| Error::Config {
        path: args.path.display().to_string(),
        source,
    })?;
    let config = &project.routing;
    println!(
        "{} ok — {} redirect(s), {} rewrite(s), {} header rule(s)",
        args.path.display(),
        config.redirects.len(),
        config.rewrites.len(),
        config.headers.len(),
    );
    if !config.handlers.is_empty()
        || !config.consumers.is_empty()
        || !config.crons.is_empty()
        || !config.streams.is_empty()
    {
        println!(
            "  {} handler(s), {} consumer(s), {} cron(s), {} stream(s)",
            config.handlers.len(),
            config.consumers.len(),
            config.crons.len(),
            config.streams.len(),
        );
    }
    Ok(())
}

/// Run `command` via the system shell, failing on a non-zero exit.
pub async fn run_command(command: &str) -> Result<()> {
    tracing::info!(%command, "running build command");
    let status = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .await?;
    if !status.success() {
        return Err(Error::CommandFailed {
            command: command.to_string(),
            status,
        });
    }
    Ok(())
}
