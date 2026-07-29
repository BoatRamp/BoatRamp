//! The Model Context Protocol (MCP) server for boatramp.
//!
//! Exposes the control-plane API as MCP tools so an agent (Claude, Codex, …) can
//! drive one or many boatramp instances over either transport:
//!  - **stdio** — the `boatramp mcp` subcommand a desktop agent spawns
//!    ([`serve_stdio`]).
//!  - **HTTP** — a streamable-http endpoint mounted on `boatramp serve` (the
//!    `http` feature; [`http_router`]).
//!
//! Multiple named instances (like `../corteza-mcp`) are configured in
//! `~/.config/boatramp/mcp.toml`; every tool takes an optional `instance` to pick
//! among them (required only when more than one is registered).

pub mod client;
pub mod config;
pub mod error;
pub mod registry;
mod server;
pub mod setup;

pub use client::{caller_bearer, ControlPlane, HttpControlPlane, CALLER_BEARER};
pub use config::{Config, InstanceConfig};
pub use error::{Error, Result};
pub use registry::{Backend, InstanceRegistry, SingleBackend};
pub use server::BoatrampMcp;

use std::sync::Arc;

/// Load the config, connect every configured instance, and serve the MCP protocol
/// over **stdio** until the client disconnects. This is what `boatramp mcp` runs.
pub async fn serve_stdio() -> Result<()> {
    use rmcp::ServiceExt;
    let config = Config::load()?;
    let backend: Arc<dyn Backend> = Arc::new(InstanceRegistry::from_config(&config)?);
    if backend.is_empty() {
        tracing::warn!(
            "no boatramp instances registered; add one with `boatramp mcp setup add <name> --server <url>`"
        );
    }
    let server = BoatrampMcp::new(backend);
    let service = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| Error::Config(format!("mcp stdio serve: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| Error::Config(format!("mcp stdio serve: {e}")))?;
    Ok(())
}
