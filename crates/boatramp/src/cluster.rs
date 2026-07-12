//! The `cluster` subcommand: operate a self-hosted cluster's mesh membership.
//! `join-token` mints a **single-use bearer** mesh join token server-side (the
//! issuing node holds the root private key). The token carries no node id or key:
//! the joining node self-identifies from its own mesh keypair and proves
//! possession of it at join time, so a stolen token can admit only a node that
//! also completes the possession proof — and only once (single-use `jti`).
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
    /// Encoding the join ticket failed.
    #[cfg(feature = "cluster")]
    #[error("join ticket: {0}")]
    Ticket(String),
    /// `cluster remove <address>` found no member with that address.
    #[error("no cluster member with address {0} (see `cluster status`)")]
    NoSuchMember(String),
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
    /// Print a one-paste **join ticket** for a new node: a single-use join token
    /// bundled with the seed address + the cluster root anchor, so the joiner
    /// self-identifies and joins with no peer map. Run against any existing node.
    #[cfg(feature = "cluster")]
    Add {
        /// The cluster **root public key** (`es256:`/`ed25519:` hex) — the anchor
        /// the joiner verifies the seed + members against. From `auth pubkey`.
        #[arg(long)]
        root_pubkey: String,
        /// The seed control-plane address the joiner should reach (defaults to
        /// `--server`). This is where the joiner POSTs its `/api/cluster/join`.
        #[arg(long)]
        seed: Option<String>,
        /// Token time-to-live in seconds (default: the server's short window).
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Print only the raw single-use token (scripting escape hatch), not the
        /// full ticket.
        #[arg(long)]
        print_token_only: bool,
    },
    /// Mint a single-use **bearer** mesh join token (printed once). Any node can
    /// redeem it, but only by proving possession of its own mesh key at join
    /// time, and only once — hand it to exactly one joining node. (Prefer
    /// `cluster add`, which bundles the token into a one-paste join ticket.)
    JoinToken {
        /// Token time-to-live in seconds (default: the server's short window).
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Show the cluster membership — address-primary: ADDRESS, ROLE, a short
    /// node-id label, and STATE (ready/lagging). Target the leader for accurate
    /// learner catch-up.
    Status {
        /// Show full node ids instead of the short 8-hex label.
        #[arg(long)]
        full: bool,
    },
    /// Rotate the `--server` node's own mesh key, make-before-break.
    /// Node-local: rotation happens on the node whose API you target (only
    /// it holds and mints its private key), so this rotates that node's key.
    RotateKey,
    /// Remove a node from the cluster (subsumes `revoke`): its trust is deleted
    /// cluster-wide (it can no longer authenticate) and it is dropped from the
    /// quorum. The target is a **mesh address** (as shown by `status`) or a raw
    /// node id. Target the leader's API so the quorum change applies.
    Remove {
        /// The node to remove: its mesh address (preferred) or its raw node id.
        target: String,
    },
    /// Revoke a node from the mesh by raw node id (low-level; prefer `remove`,
    /// which accepts an address). Target the leader's API.
    Revoke {
        /// The node id to revoke.
        node: u64,
    },
}

#[derive(serde::Serialize)]
struct JoinTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_secs: Option<u64>,
}

#[derive(Deserialize)]
struct JoinTokenResponse {
    token: String,
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

/// One row from `GET /api/cluster/members` (mirrors the server's `MeshMember`).
#[derive(Debug, Clone, Deserialize)]
struct MemberRow {
    node: u64,
    #[serde(default)]
    voter: bool,
    #[serde(default)]
    caught_up: bool,
    #[serde(default)]
    leader: bool,
    #[serde(default)]
    addr: Option<String>,
}

/// A member's role for display.
fn role(m: &MemberRow) -> &'static str {
    if m.leader {
        "leader"
    } else if m.voter {
        "voter"
    } else {
        "learner"
    }
}

/// A learner's readiness for display (voters/leaders are always "ready").
fn state(m: &MemberRow) -> &'static str {
    if m.voter || m.caught_up {
        "ready"
    } else {
        "lagging"
    }
}

/// Render the address-primary status table (a pure fn so it is unit-tested).
/// `full` shows the whole node id; otherwise a short 8-hex label.
fn format_status(members: &[MemberRow], full: bool) -> String {
    let id_label = |node: u64| {
        if full {
            node.to_string()
        } else {
            // Short label: the top 8 hex of the id (its display fingerprint).
            format!("{:016x}", node)[..8].to_string()
        }
    };
    let mut out = format!("{:<28}  {:<8}  {:<16}  {}\n", "ADDRESS", "ROLE", "NODE", "STATE");
    for m in members {
        out.push_str(&format!(
            "{:<28}  {:<8}  {:<16}  {}\n",
            m.addr.as_deref().unwrap_or("(unknown)"),
            role(m),
            id_label(m.node),
            state(m),
        ));
    }
    out
}

/// Entry point for `boatramp cluster`.
pub async fn run(args: ClusterArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        #[cfg(feature = "cluster")]
        ClusterCommand::Add {
            root_pubkey,
            seed,
            ttl_secs,
            print_token_only,
        } => {
            let response: JoinTokenResponse = http
                .post(format!("{server}/api/cluster/join-token"))
                .json(&JoinTokenRequest { ttl_secs })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if print_token_only {
                println!("{}", response.token);
            } else {
                // The seed the joiner reaches defaults to the node we just minted
                // against (its control plane serves `/api/cluster/join`).
                let seed_addr = seed.unwrap_or_else(|| server.clone());
                let ticket = crate::join::JoinTicket {
                    seeds: vec![seed_addr.clone()],
                    root_pubkeys: vec![root_pubkey.trim().to_string()],
                    token: response.token,
                }
                .encode()
                .map_err(|e| Error::Ticket(e.to_string()))?;
                println!("{ticket}");
                eprintln!("single-use join ticket — hand it to exactly one new node, e.g.:");
                eprintln!("  boatramp serve --cluster-join {ticket}");
            }
            if let Some(exp) = response.expires_at {
                eprintln!("expires at (unix): {exp}");
            }
        }
        ClusterCommand::JoinToken { ttl_secs } => {
            let response: JoinTokenResponse = http
                .post(format!("{server}/api/cluster/join-token"))
                .json(&JoinTokenRequest { ttl_secs })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", response.token);
            if let Some(exp) = response.expires_at {
                eprintln!("expires at (unix): {exp}");
            }
            eprintln!("single-use bearer — hand it to exactly one joining node; it cannot be recovered");
        }
        ClusterCommand::Status { full } => {
            let members: Vec<MemberRow> = http
                .get(format!("{server}/api/cluster/members"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            print!("{}", format_status(&members, full));
        }
        ClusterCommand::Remove { target } => {
            // Resolve an address to a node id via the membership; a bare integer
            // is taken as a raw node id.
            let node = match target.parse::<u64>() {
                Ok(id) => id,
                Err(_) => {
                    let members: Vec<MemberRow> = http
                        .get(format!("{server}/api/cluster/members"))
                        .send()
                        .await?
                        .error_for_status()?
                        .json()
                        .await?;
                    members
                        .iter()
                        .find(|m| m.addr.as_deref() == Some(target.as_str()))
                        .map(|m| m.node)
                        .ok_or_else(|| Error::NoSuchMember(target.clone()))?
                }
            };
            http.post(format!("{server}/api/cluster/revoke"))
                .json(&RevokeRequest { node_id: node })
                .send()
                .await?
                .error_for_status()?;
            eprintln!("removed {target} (node {node}) from the cluster");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The status table is address-primary, labels roles + learner readiness, and
    /// shortens node ids unless `--full`.
    #[test]
    fn status_table_is_address_primary_and_role_labelled() {
        let members = vec![
            MemberRow {
                node: 0x1122_3344_5566_7788,
                voter: true,
                caught_up: true,
                leader: true,
                addr: Some("https://a:7000".into()),
            },
            MemberRow {
                node: 0xAABB_CCDD_EEFF_0011,
                voter: false,
                caught_up: false,
                leader: false,
                addr: None,
            },
        ];
        let short = format_status(&members, false);
        assert!(short.contains("ADDRESS"));
        assert!(short.contains("https://a:7000"));
        assert!(short.contains("leader"));
        assert!(short.contains("11223344")); // short 8-hex label
        assert!(short.contains("(unknown)")); // the learner has no address
        assert!(short.contains("lagging")); // not caught up
        assert!(short.contains("learner"));

        // `--full` shows the entire id.
        let full = format_status(&members, true);
        assert!(full.contains(&0x1122_3344_5566_7788u64.to_string()));
    }
}
