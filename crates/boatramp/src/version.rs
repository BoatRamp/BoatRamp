//! `boatramp version` — report the boatramp version, LOCALLY (this binary) or from a RUNNING
//! daemon (`--server <url>` / `--remote`). The remote read hits `GET /api/version`, which is gated
//! at `system·read` (operator-only): there is deliberately NO unauthenticated version surface on the
//! server (no `Server:` header, no public `/version`), so the remote query uses the client's
//! control-plane token exactly like every other control-plane verb.
//!
//! This is distinct from clap's built-in `boatramp --version` flag: the subcommand adds `--json`
//! and the `--server`/`--remote` remote read (answering "which build is ACTUALLY deployed?", which
//! the local flag can't).

use clap::Args;
use serde_json::json;

use crate::client;
use crate::config::ProjectConfig;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A control-plane transport/refusal error from the remote `GET /api/version` (or resolving the
    /// server target) — e.g. no server configured, or a `401`/`403` (missing/insufficient token).
    #[error(transparent)]
    Client(#[from] client::ClientError),
}

type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp version`.
#[derive(Debug, Args)]
pub struct VersionArgs {
    /// Query a RUNNING daemon's version at this URL instead of reporting this binary's. Uses the
    /// control-plane token; the endpoint is `system·read` (operator-only).
    #[arg(long, value_name = "URL")]
    server: Option<String>,

    /// Query the CONFIGURED daemon (`[deploy].server` / `BOATRAMP_SERVER`) — a shorthand for
    /// `--server` without retyping the URL. Ignored when `--server` is given.
    #[arg(long)]
    remote: bool,

    /// Emit a JSON object (`{version, source[, server]}`) instead of a human line.
    #[arg(long)]
    json: bool,
}

/// Entry point for `boatramp version`. Local unless `--server`/`--remote` selects a running daemon.
pub async fn run(args: VersionArgs, config: &ProjectConfig) -> Result<()> {
    let go_remote = args.server.is_some() || args.remote;
    if !go_remote {
        // LOCAL: this binary's own package version — no server, no token, no network. `CARGO_PKG_VERSION`
        // is the workspace version every crate shares, so it IS the boatramp release.
        let version = env!("CARGO_PKG_VERSION");
        if args.json {
            println!("{}", json!({ "version": version, "source": "local" }));
        } else {
            println!("boatramp {version}");
        }
        return Ok(());
    }

    // REMOTE: ask the running daemon which build it is (`GET /api/version`, `system·read`). The URL
    // comes from `--server`, else the configured `[deploy].server` / `BOATRAMP_SERVER` (via `--remote`).
    let server = client::resolve_server(args.server, config)?;
    let cp = client::ControlPlane::new(
        server.clone(),
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let info = cp.node_version().await?;
    if args.json {
        println!(
            "{}",
            json!({ "version": info.version, "source": "remote", "server": server })
        );
    } else {
        println!("boatramp {} (server {server})", info.version);
    }
    Ok(())
}
