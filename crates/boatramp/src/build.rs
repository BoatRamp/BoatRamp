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

/// The result of `boatramp build`: the external build command that ran.
///
/// `build` itself emits no human text — the build tool it shells out to prints its
/// own output on the inherited stdio — so [`render_human`](crate::output::Rendered::render_human)
/// writes nothing. JSON callers still get the command that was executed.
#[derive(Debug, serde::Serialize)]
pub struct BuildOutput {
    /// The build command that was run (e.g. `npm run build`).
    command: String,
}

impl crate::output::Rendered for BuildOutput {
    fn render_human(&self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        // `build` historically printed nothing of its own; the build tool's output
        // goes to the inherited stdio. Preserve that: no extra line.
        Ok(())
    }
}

/// The result of `boatramp validate`: a parsed-and-compile-checked `project.cfg`
/// summary (the counts of each routing surface). Rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
pub struct ValidateOutput {
    /// The config file that was validated.
    path: String,
    redirects: usize,
    rewrites: usize,
    headers: usize,
    handlers: usize,
    consumers: usize,
    crons: usize,
    streams: usize,
}

impl crate::output::Rendered for ValidateOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(
            w,
            "{} ok — {} redirect(s), {} rewrite(s), {} header rule(s)",
            self.path, self.redirects, self.rewrites, self.headers,
        )?;
        if self.handlers > 0 || self.consumers > 0 || self.crons > 0 || self.streams > 0 {
            writeln!(
                w,
                "  {} handler(s), {} consumer(s), {} cron(s), {} stream(s)",
                self.handlers, self.consumers, self.crons, self.streams,
            )?;
        }
        Ok(())
    }
}

/// Arguments for `boatramp build`.
#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    /// Override the configured build command.
    #[arg(long)]
    command: Option<String>,
}

/// Entry point for `boatramp build`.
pub async fn run(args: BuildArgs, config: &ProjectConfig) -> Result<BuildOutput> {
    let command = resolve_command(args.command, config)?;
    run_command(&command).await?;
    Ok(BuildOutput { command })
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
pub fn validate(args: ValidateArgs) -> Result<ValidateOutput> {
    let text = std::fs::read_to_string(&args.path).map_err(|source| Error::Read {
        path: args.path.display().to_string(),
        source,
    })?;
    let project = ProjectConfig::parse(&text).map_err(|source| Error::Config {
        path: args.path.display().to_string(),
        source,
    })?;
    let config = &project.routing;
    Ok(ValidateOutput {
        path: args.path.display().to_string(),
        redirects: config.redirects.len(),
        rewrites: config.rewrites.len(),
        headers: config.headers.len(),
        handlers: config.handlers.len(),
        consumers: config.consumers.len(),
        crons: config.crons.len(),
        streams: config.streams.len(),
    })
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
