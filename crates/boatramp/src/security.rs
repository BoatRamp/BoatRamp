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

/// Entry point for `boatramp security`. Reads the server config (`boatramp.cfg`).
pub fn run(args: SecurityArgs, config: &ServerConfig) -> Result<()> {
    match args.command {
        SecurityCommand::Explain => {
            let security = config.security.clone().unwrap_or_default();
            print!("{}", security.explain()?);
        }
    }
    Ok(())
}
