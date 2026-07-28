//! The `mcp` subcommand: run the Model Context Protocol server so an agent
//! (Claude, Codex, …) can drive one or more boatramp instances, or manage the
//! instances it targets.
//!
//! - `boatramp mcp` (or `mcp serve`) speaks MCP over **stdio** — what a desktop
//!   agent spawns.
//! - `boatramp mcp setup add/list/remove` edits `~/.config/boatramp/mcp.toml`.
//!
//! The tool surface + transport live in the `boatramp-mcp` crate (kept separate
//! so rmcp's schemars 1.x doesn't collide with the operator's schemars 0.8).

use clap::{Args, Subcommand};

/// A failure in the `mcp` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the MCP server / config layer.
    #[error(transparent)]
    Mcp(#[from] boatramp_mcp::Error),
}

/// `boatramp mcp [serve | setup …]`.
#[derive(Debug, Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub action: Option<McpAction>,
}

/// The `mcp` actions; absent means `serve`.
#[derive(Debug, Subcommand)]
pub enum McpAction {
    /// Serve the MCP protocol over stdio (the default action).
    Serve,
    /// Manage the boatramp instances the MCP server can drive.
    Setup {
        #[command(subcommand)]
        action: SetupAction,
    },
}

/// `boatramp mcp setup …` — instance registry management.
#[derive(Debug, Subcommand)]
pub enum SetupAction {
    /// Register a boatramp instance.
    Add {
        /// The name the agent uses to select this instance.
        name: String,
        /// The control-plane base URL (e.g. https://boatramp.example.com).
        #[arg(long)]
        server: String,
        /// Admin token spec: `env:VAR`, `path:/file`, or a literal (empty = none).
        #[arg(long, default_value = "")]
        token: String,
        /// Token holder (`cnf`) private-key spec for per-request DPoP/PoP proofs.
        #[arg(long)]
        holder_key: Option<String>,
        /// Server raw-public-key SPKI hex to pin (RFC 7250 `--tls rpk`).
        #[arg(long)]
        server_pubkey: Option<String>,
        /// Skip TLS verification (self-signed cert on a trusted network only).
        #[arg(long)]
        insecure: bool,
    },
    /// List the registered instances.
    List,
    /// Remove a registered instance by name.
    Remove {
        /// The instance name to remove.
        name: String,
    },
}

/// Run the `mcp` subcommand.
pub async fn run(args: McpArgs) -> Result<(), Error> {
    match args.action.unwrap_or(McpAction::Serve) {
        McpAction::Serve => boatramp_mcp::serve_stdio().await?,
        McpAction::Setup { action } => match action {
            SetupAction::Add {
                name,
                server,
                token,
                holder_key,
                server_pubkey,
                insecure,
            } => {
                let msg = boatramp_mcp::setup::add(boatramp_mcp::InstanceConfig {
                    name,
                    server,
                    token,
                    holder_key,
                    server_pubkey,
                    insecure,
                })?;
                println!("{msg}");
            }
            SetupAction::List => println!("{}", boatramp_mcp::setup::list()?),
            SetupAction::Remove { name } => println!("{}", boatramp_mcp::setup::remove(&name)?),
        },
    }
    Ok(())
}
