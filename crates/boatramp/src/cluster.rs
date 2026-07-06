//! The `cluster` subcommand: operate a self-hosted cluster's mesh membership.
//! `join-token` mints a **single-use** mesh join token
//! server-side (the issuing node holds the root private key), bound to one node
//! id and one mesh public key — so a stolen token can't admit a different key.
//!
//! This is a thin control-plane HTTP client (no cluster runtime), so it is
//! available on every build: an operator mints a join token against the cluster's
//! control-plane API from anywhere.

use clap::Subcommand;
use serde::Deserialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `cluster` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// The mesh public key was not valid hex.
    #[error("--pubkey must be a hex-encoded mesh public key")]
    BadPubkey,
}

/// `cluster` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp cluster`.
#[derive(Debug, clap::Args)]
pub struct ClusterArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: ClusterCommand,
}

#[derive(Debug, Subcommand)]
enum ClusterCommand {
    /// Mint a single-use mesh join token for a node (printed once). Bind it to
    /// the joining node's id and its mesh public key (printed in the node's
    /// startup log); a stolen token cannot admit a different key.
    JoinToken {
        /// The joining node's id.
        #[arg(long)]
        node: u64,
        /// The joining node's mesh public key (hex, from its startup log).
        #[arg(long)]
        pubkey: String,
        /// Token time-to-live in seconds (default: the server's short window).
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Rotate the `--server` node's own mesh key, make-before-break.
    /// Node-local: rotation happens on the node whose API you target (only
    /// it holds and mints its private key), so this rotates that node's key.
    RotateKey,
    /// Revoke a node from the mesh: its trust is deleted
    /// cluster-wide (it can no longer authenticate) and it is dropped from the
    /// quorum. Target the leader's API so the quorum change applies.
    Revoke {
        /// The node id to revoke.
        node: u64,
    },
}

#[derive(serde::Serialize)]
struct JoinTokenRequest {
    node_id: u64,
    pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_secs: Option<u64>,
}

#[derive(Deserialize)]
struct JoinTokenResponse {
    token: String,
    node_id: u64,
    #[serde(default)]
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct RotateKeyResponse {
    pubkey: String,
}

#[derive(serde::Serialize)]
struct RevokeRequest {
    node_id: u64,
}

/// Whether `s` is a non-empty, even-length hex string (a mesh SPKI).
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Entry point for `boatramp cluster`.
pub async fn run(args: ClusterArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        ClusterCommand::JoinToken {
            node,
            pubkey,
            ttl_secs,
        } => {
            let pubkey = pubkey.trim().to_string();
            if !is_hex(&pubkey) {
                return Err(Error::BadPubkey);
            }
            let response: JoinTokenResponse = http
                .post(format!("{server}/api/cluster/join-token"))
                .json(&JoinTokenRequest {
                    node_id: node,
                    pubkey,
                    ttl_secs,
                })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", response.token);
            eprintln!("node: {}", response.node_id);
            if let Some(exp) = response.expires_at {
                eprintln!("expires at (unix): {exp}");
            }
            eprintln!("single-use — the node presents this once to join; it cannot be recovered");
        }
        ClusterCommand::RotateKey => {
            let response: RotateKeyResponse = http
                .post(format!("{server}/api/cluster/rotate-key"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", response.pubkey);
            eprintln!(
                "mesh key rotated (make-before-break); update this node's `pubkey` in peer config"
            );
        }
        ClusterCommand::Revoke { node } => {
            http.post(format!("{server}/api/cluster/revoke"))
                .json(&RevokeRequest { node_id: node })
                .send()
                .await?
                .error_for_status()?;
            eprintln!("node {node} revoked from the mesh");
        }
    }
    Ok(())
}
