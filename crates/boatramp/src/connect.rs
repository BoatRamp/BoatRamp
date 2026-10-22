//! `boatramp connect <svc>` (overlay-service-tunneler plan §4/§9.5): a one-shot dial + stdio splice
//! over the shared tunnel core — for `ssh ProxyCommand`/scripting, where the caller already has one
//! specific destination in mind and does not want to stand up a SOCKS daemon for it.
//!
//! Reuses exactly the same `ControlPlane` construction `tunnel.rs` does
//! ([`crate::tunnel::HttpControlPlane`]) — the two commands differ only in their front-end (a SOCKS
//! daemon vs. one stdio splice), never in how they reach the control plane or the overlay core.

use boatramp_overlay_tunnel::Tunnel;
use clap::Args;

/// Arguments for `boatramp connect`.
#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// The overlay service to reach (e.g. `db`, `svc-db`, or `svc/db`).
    pub service: String,
    /// boatramp server base URL (overrides `[publish].server`).
    #[arg(long, env = "BOATRAMP_SERVER")]
    pub server: Option<String>,
}

/// Dial `args.service` and splice it to stdio until either side closes — the shape an `ssh
/// ProxyCommand` or a script pipes through.
pub async fn run(
    args: ConnectArgs,
    config: &crate::config::ProjectConfig,
) -> Result<(), crate::tunnel::TunnelCmdError> {
    let (server, http) = crate::client::connect(args.server.clone(), config)?;
    let holder = crate::overlay::operator_identity()?;
    let control_plane = std::sync::Arc::new(crate::tunnel::HttpControlPlane::new(server, http));
    let tunnel = Tunnel::new(control_plane, holder).await?;

    let flow = tunnel.open(&args.service).await?;
    // `Flow` is one `AsyncRead + AsyncWrite` value, but stdin/stdout are two independent streams —
    // split it into independent halves so each direction can run concurrently without two `&mut
    // Flow` borrows fighting over the same value.
    let (mut flow_read, mut flow_write) = tokio::io::split(flow);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    tokio::select! {
        result = tokio::io::copy(&mut stdin, &mut flow_write) => { result?; }
        result = tokio::io::copy(&mut flow_read, &mut stdout) => { result?; }
    }
    Ok(())
}
