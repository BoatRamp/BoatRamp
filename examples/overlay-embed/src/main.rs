//! Minimal native embedder of the boatramp overlay client SDK.
//!
//! Binds a local TCP port and forwards every accepted connection into the cluster over the
//! relay-blind, end-to-end-encrypted overlay to an in-cluster `service`, using an operator-minted
//! dial capability. This is the shape a native app (or `boatramp forward`) uses — the SDK hides the
//! QUIC dial, the E2EE handshake, and the splice behind two calls.
//!
//! Usage:
//!   overlay-embed <local-bind> <relay-addr> <relay-id> <egress-id> <service> <dial-cap>
//! e.g.
//!   overlay-embed 127.0.0.1:5432 10.0.0.1:9000 bro1relay… bro1egress… svc/db <token>

use std::net::SocketAddr;
use std::sync::Arc;

use boatramp_overlay_client::{OverlayClient, OverlayId, OverlaySecret, PathMode};
use tokio::net::TcpListener;

fn parse_id(s: &str) -> Result<OverlayId, Box<dyn std::error::Error>> {
    OverlayId::from_bech32(s)
        .or_else(|_| OverlayId::from_hex(s))
        .map_err(Into::into)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, local, relay, relay_id, egress_id, service, cap] = &args[..] else {
        return Err(
            "usage: overlay-embed <local-bind> <relay-addr> <relay-id> <egress-id> \
             <service> <dial-cap>"
                .into(),
        );
    };
    let local: SocketAddr = local.parse()?;
    let relay: SocketAddr = relay.parse()?;

    // An ephemeral client identity for this demo; a real app loads a persistent seed. The client
    // pins the relay (at TLS) and the egress (for the end-to-end E2EE session).
    let client = Arc::new(
        OverlayClient::builder(OverlaySecret::generate()?)
            .relay(relay, parse_id(relay_id)?)
            .egress(parse_id(egress_id)?)
            .path_mode(PathMode::PreferDirect)
            .build()?,
    );
    let service = Arc::new(service.clone());
    let cap = Arc::new(cap.clone());

    let listener = TcpListener::bind(local).await?;
    eprintln!("overlay-embed: {local} -> {service} via relay {relay} (relay-blind E2EE)");

    loop {
        let (socket, peer) = listener.accept().await?;
        let client = Arc::clone(&client);
        let service = Arc::clone(&service);
        let cap = Arc::clone(&cap);
        tokio::spawn(async move {
            if let Err(e) = forward_one(&client, socket, &service, &cap).await {
                eprintln!("overlay-embed: flow from {peer} failed: {e}");
            }
        });
    }
}

/// Forward one accepted connection into the cluster. On unix the connection's OWNED fd is handed to
/// the SDK's fd-adoption seam ([`OverlayClient::forward_connected_fd`]) — the path the increment-2
/// C-ABI / UniFFI mobile bindings funnel a platform socket into; elsewhere the plain
/// [`OverlayClient::forward_socket`] entry point is used.
async fn forward_one(
    client: &OverlayClient,
    socket: tokio::net::TcpStream,
    service: &str,
    cap: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(unix)]
    {
        let fd = std::os::fd::OwnedFd::from(socket.into_std()?);
        client
            .forward_connected_fd(fd, service, cap, PathMode::PreferDirect)
            .await?;
    }
    #[cfg(not(unix))]
    {
        client
            .forward_socket(socket, service, cap, PathMode::PreferDirect)
            .await?;
    }
    Ok(())
}
