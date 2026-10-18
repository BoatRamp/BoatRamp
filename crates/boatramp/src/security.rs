//! The `security` subcommand: inspect the operator security posture.
//!
//! The posture (the hardening knobs) is resolved from the
//! `[security]` section of the **server** config (`boatramp.cfg`): a profile
//! preset (`multi-tenant` / `single-tenant` / `dev`, default `multi-tenant`)
//! plus individual overrides that win over the profile. `explain` prints the
//! resolved value of every knob and where it came from — read-only, so operators
//! can confirm the posture a node will serve under before starting it.

use clap::Subcommand;

use crate::config::ServerConfig;

/// A failure in the `security` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the configured posture failed (e.g. an unknown profile name).
    #[error(transparent)]
    Security(#[from] boatramp_core::security::SecurityError),
}

/// `security` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp security`.
#[derive(Debug, clap::Args)]
pub struct SecurityArgs {
    #[command(subcommand)]
    command: SecurityCommand,
}

#[derive(Debug, Subcommand)]
enum SecurityCommand {
    /// Print the resolved security posture from `boatramp.cfg` (profile + every
    /// knob's value and source).
    Explain,
}

/// The result of a `security` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SecurityOutput {
    /// `security explain` — the resolved posture, as the human text each knob's
    /// value + source. The resolved [`SecurityPosture`](boatramp_core::security)
    /// is not `Serialize`, so JSON carries the rendered explanation verbatim.
    Explain { explanation: String },
}

impl crate::output::Rendered for SecurityOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            // `explain()` already terminates each line; mirror the former `print!`
            // (no extra trailing newline) with `write!`.
            Self::Explain { explanation } => write!(w, "{explanation}"),
        }
    }
}

/// Entry point for `boatramp security`. Reads the server config (`boatramp.cfg`).
pub fn run(args: SecurityArgs, config: &ServerConfig) -> Result<SecurityOutput> {
    match args.command {
        SecurityCommand::Explain => {
            let security = config.security.clone().unwrap_or_default();
            Ok(SecurityOutput::Explain {
                explanation: security.explain()?,
            })
        }
    }
}
