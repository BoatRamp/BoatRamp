//! The `forward` subcommand (IU-10): a native overlay **client-edge**.
//!
//! `boatramp forward <local-addr> <cluster-target>` binds a local listener and, per accepted
//! connection, capability-gated-dials into the cluster — relay-blind E2EE to the in-cluster target
//! (egress) — and splices the socket over the overlay. Shaped like `ssh -L` / `kubectl
//! port-forward`; the basic tier is explicit per-port forwards, with no OS capture.
//!
//! This is the first NATIVE consumer of the overlay fabric — boatramp's own CLI exercises dial →
//! relay-blind E2EE → egress end to end. Target addressing + relay/egress discovery (26.1 §7e) are a
//! deferred design decision; the first slice takes the relay address + the pinned identities + the
//! dial token explicitly on the command line.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use boatramp_overlay::{
    DialRequest, OverlayId, OverlayPeerPolicy, OverlaySecret, client_endpoint, forward_flow,
};
use clap::Args;
use tokio::net::TcpListener;

/// Arguments for `boatramp forward`.
#[derive(Args, Debug)]
pub struct ForwardArgs {
    /// Local address to bind and forward (e.g. `127.0.0.1:5432`).
    pub local: String,
    /// The in-cluster target to reach (e.g. `svc/db`, `node/<id>`).
    pub target: String,
    /// The cluster relay/ingress socket address to dial.
    #[arg(long)]
    pub relay: SocketAddr,
    /// The relay's overlay identity to pin (`bro1…` or `ed25519:<hex>`).
    #[arg(long)]
    pub relay_id: String,
    /// The egress/terminator's overlay identity to pin for the E2EE session.
    #[arg(long)]
    pub egress_id: String,
    /// The dial capability token (COSE), holder-bound to this client's identity.
    #[arg(long, conflicts_with = "token_file")]
    pub token: Option<String>,
    /// Read the dial token from a file instead of `--token`.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// This client's overlay identity seed — `ed25519:<hex>` inline, or a path to a file holding it.
    #[arg(long)]
    pub identity: String,
}

/// A `forward` failure.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("bind / accept: {0}")]
    Io(#[from] std::io::Error),
    #[error("overlay identity: {0}")]
    Identity(#[from] boatramp_overlay::OverlayIdError),
    #[error("overlay transport: {0}")]
    Quic(#[from] boatramp_overlay::QuicError),
    #[error("no dial token — pass --token or --token-file")]
    NoToken,
}

/// Parse an overlay identity given as bech32 (`bro1…`) or canonical hex (`ed25519:<hex>`).
fn parse_id(s: &str) -> Result<OverlayId, ForwardError> {
    if let Ok(id) = OverlayId::from_bech32(s) {
        return Ok(id);
    }
    Ok(OverlayId::from_hex(s)?)
}

/// Load the client's identity secret from an inline `ed25519:<hex>` seed or a file path.
fn load_identity(spec: &str) -> Result<OverlaySecret, ForwardError> {
    let seed = if spec.starts_with("ed25519:") {
        spec.to_string()
    } else {
        std::fs::read_to_string(spec)?.trim().to_string()
    };
    Ok(OverlaySecret::from_seed_hex(&seed)?)
}

fn load_token(args: &ForwardArgs) -> Result<String, ForwardError> {
    if let Some(t) = &args.token {
        return Ok(t.clone());
    }
    if let Some(path) = &args.token_file {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    Err(ForwardError::NoToken)
}

/// Run the forwarder until interrupted.
pub async fn run(args: ForwardArgs) -> Result<(), ForwardError> {
    let secret = load_identity(&args.identity)?;
    let relay_id = parse_id(&args.relay_id)?;
    let egress_id = parse_id(&args.egress_id)?;
    let token = load_token(&args)?;

    // One dial-only endpoint pinning the relay, reused for every accepted connection.
    let endpoint = client_endpoint(&secret, &OverlayPeerPolicy::Pin(relay_id))?;
    let listener = TcpListener::bind(&args.local).await?;
    let bound = listener.local_addr()?;

    eprintln!(
        "boatramp forward: {bound} → {} via relay {} (overlay, relay-blind E2EE) — Ctrl-C to stop",
        args.target, args.relay
    );

    let secret = Arc::new(secret);
    let token = Arc::new(token);
    let target = Arc::new(args.target);
    let relay = args.relay;

    loop {
        let (sock, _peer) = listener.accept().await?;
        let endpoint = endpoint.clone();
        let secret = Arc::clone(&secret);
        let token = Arc::clone(&token);
        let target = Arc::clone(&target);
        tokio::spawn(async move {
            let request = DialRequest {
                service: (*target).clone(),
                token: (*token).clone(),
                e2ee: true,
            };
            if let Err(e) = forward_flow(sock, &endpoint, relay, &secret, egress_id, request).await
            {
                tracing::warn!(error = %e, "overlay forward connection failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ForwardArgs,
    }

    #[test]
    fn parses_forward_args() {
        let w = Wrap::try_parse_from([
            "forward",
            "127.0.0.1:5432",
            "svc/db",
            "--relay",
            "10.0.0.1:9000",
            "--relay-id",
            "bro1qqqq",
            "--egress-id",
            "ed25519:00",
            "--token",
            "abc",
            "--identity",
            "ed25519:1111",
        ])
        .unwrap();
        assert_eq!(w.args.local, "127.0.0.1:5432");
        assert_eq!(w.args.target, "svc/db");
        assert_eq!(w.args.relay.to_string(), "10.0.0.1:9000");
        assert_eq!(w.args.token.as_deref(), Some("abc"));
    }

    #[test]
    fn token_sources_are_mutually_exclusive() {
        let r = Wrap::try_parse_from([
            "forward",
            "127.0.0.1:1",
            "svc/x",
            "--relay",
            "1.1.1.1:1",
            "--relay-id",
            "x",
            "--egress-id",
            "y",
            "--identity",
            "ed25519:00",
            "--token",
            "a",
            "--token-file",
            "/tmp/t",
        ]);
        assert!(r.is_err(), "--token and --token-file must conflict");
    }
}
