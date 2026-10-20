//! The `overlay` subcommand group: admin-side tooling for the overlay forward-flow feature.
//!
//! `boatramp forward` (the client-edge, [`crate::forward`]) needs a holder-bound overlay-dial
//! capability and the relay/egress identities to pin. Producing those by hand is not an operator
//! workflow — this module mints them. `boatramp overlay grant <service>` resolves the cluster root
//! signer (offline, exactly as `token mint` does), generates the client's overlay identity (or binds
//! a supplied one), mints the dial capability, and packages everything a `forward` needs into a
//! single copy-pasteable **forward ticket** (`brfwd1.…`, the overlay analog of the cluster
//! `JoinTicket`). The operator then runs `boatramp forward 127.0.0.1:5432 --ticket <blob>` — one
//! flag, `ssh -L`-shaped — instead of assembling five low-level flags.
//!
//! The grant is offline: its authority is possession of the cluster root private key (the trust
//! root the relay/egress verify dials against), so a minted capability verifies against an
//! already-deployed cluster with no new key distribution. (A server-side `overlay grant --server`
//! that also auto-enrolls the client in the relay's `allowed_clients` is a follow-up; the offline
//! grant prints the `allowed_clients` line to add by hand.)

use base64::Engine as _;
use clap::{Args, Subcommand};

use boatramp_core::cose::{TokenPublicKey, mint_overlay_dial};
use boatramp_overlay::{OverlayId, OverlaySecret};

use crate::output::Rendered;

type Result<T> = std::result::Result<T, Error>;

/// An `overlay` command failure (wrapped by [`crate::error::Error`]).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A grant/ticket failure (bad identity, mint failure, malformed ticket).
    #[error("overlay: {0}")]
    Overlay(String),
    /// Resolving or signing with the cluster root signer failed.
    #[error("overlay signer: {0}")]
    Signer(String),
}

/// Magic prefix for a forward ticket (mirrors the cluster join ticket's `brjoin1`).
const TICKET_MAGIC: &str = "brfwd1";

/// `boatramp overlay …` — admin tooling for the overlay forward-flow feature.
#[derive(Args, Debug)]
pub struct OverlayArgs {
    #[command(subcommand)]
    command: OverlayCommand,
}

#[derive(Subcommand, Debug)]
enum OverlayCommand {
    /// Mint a dial capability for `service` and emit a one-flag forward ticket.
    ///
    /// Offline: signs with the cluster root key resolved from the config (or
    /// `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`), the same signer `token mint` uses.
    Grant {
        /// The in-cluster service to authorize (e.g. `svc/db`); must match the relay's route and
        /// the egress's service name.
        service: String,
        /// The relay/ingress socket address the client will dial (`host:port`).
        #[arg(long)]
        relay: String,
        /// The relay's overlay identity to pin (`ed25519:<hex>` or `bro1…`).
        #[arg(long)]
        relay_id: String,
        /// The egress/terminator's overlay identity to pin for the E2EE session.
        #[arg(long)]
        egress_id: String,
        /// Bind the capability to a client identity the client already generated (its public
        /// `ed25519:<hex>`/`bro1…`); the ticket then carries no secret and the client supplies
        /// `--identity`. Omit to have the grant generate the client identity and embed its seed in
        /// the ticket (convenience — the ticket is then secret).
        #[arg(long)]
        holder_pub: Option<String>,
        /// Capability lifetime in seconds (an overlay-dial capability must be time-bounded).
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// Path to the config holding the root signer (`[serve.signer]` / `auth_root_private_key`).
        #[arg(long, default_value = "boatramp.cfg")]
        config: std::path::PathBuf,
    },
}

/// A copy-pasteable **forward ticket**: everything `boatramp forward` needs to reach a service,
/// bundled into one magic-prefixed base64url(JSON) blob (the overlay analog of [`crate::join`]'s
/// `JoinTicket`). Self-describing, but the relay/egress still verify the capability against their own
/// trust root on use — a forged ticket buys nothing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForwardTicket {
    /// The relay/ingress `host:port` to dial.
    pub relay: String,
    /// The relay's overlay identity to pin.
    pub relay_id: String,
    /// The egress/terminator's overlay identity to pin for the E2EE session.
    pub egress_id: String,
    /// The in-cluster target service (authoritative; equals the capability's scope).
    pub service: String,
    /// The holder-bound overlay-dial capability (COSE).
    pub token: String,
    /// The client's overlay identity seed (`ed25519:<hex>`) — present ONLY when the grant generated
    /// the identity (convenience mode). **Secret.** Absent in `--holder-pub` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

impl ForwardTicket {
    /// Encode to `brfwd1.<base64url(json)>`.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(|e| Error::Overlay(e.to_string()))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("{TICKET_MAGIC}.{b64}"))
    }

    /// Decode a `brfwd1.…` ticket, rejecting a bad prefix or empty required fields.
    pub fn decode(blob: &str) -> Result<Self> {
        let b64 = blob
            .trim()
            .strip_prefix(TICKET_MAGIC)
            .and_then(|r| r.strip_prefix('.'))
            .ok_or_else(|| {
                Error::Overlay(format!(
                    "not a forward ticket (expected `{TICKET_MAGIC}.…`)"
                ))
            })?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| Error::Overlay(format!("malformed forward ticket: {e}")))?;
        let t: Self = serde_json::from_slice(&json)
            .map_err(|e| Error::Overlay(format!("malformed forward ticket: {e}")))?;
        if t.relay.is_empty()
            || t.relay_id.is_empty()
            || t.egress_id.is_empty()
            || t.service.is_empty()
            || t.token.is_empty()
        {
            return Err(Error::Overlay(
                "forward ticket is missing a required field".into(),
            ));
        }
        Ok(t)
    }
}

/// The result of an `overlay` command (emitted via [`crate::output`]).
#[derive(serde::Serialize)]
pub enum OverlayOutput {
    /// `overlay grant` — the forward ticket plus the relay enrollment the admin must apply.
    Granted {
        /// The `brfwd1.…` ticket for the operator to redeem with `forward --ticket`.
        ticket: String,
        /// The client's overlay identity (`ed25519:<hex>`) to enroll in the relay.
        client_id: String,
        /// The exact `[overlay] allowed_clients` entry to add on the relay node.
        enroll: String,
        /// Whether the ticket carries the client's secret seed (convenience mode).
        secret_ticket: bool,
    },
}

impl Rendered for OverlayOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Granted {
                ticket,
                client_id,
                enroll,
                secret_ticket,
            } => {
                writeln!(w, "{ticket}")?;
                writeln!(w)?;
                if *secret_ticket {
                    writeln!(
                        w,
                        "# This ticket embeds the client's private seed — treat it as a secret."
                    )?;
                }
                writeln!(
                    w,
                    "# Redeem on the client:   boatramp forward <local-addr> --ticket <ticket>"
                )?;
                writeln!(
                    w,
                    "# Enroll on the relay node ([overlay] allowed_clients), then reload:"
                )?;
                writeln!(w, "#   client id: {client_id}")?;
                writeln!(w, "#   allowed_clients entry: {enroll}")
            }
        }
    }
}

/// Parse an overlay identity given as bech32 (`bro1…`) or canonical hex (`ed25519:<hex>`).
fn parse_id(s: &str) -> Result<OverlayId> {
    if let Ok(id) = OverlayId::from_bech32(s) {
        return Ok(id);
    }
    OverlayId::from_hex(s).map_err(|e| Error::Overlay(format!("overlay identity `{s}`: {e}")))
}

/// Run an `overlay` command.
pub async fn run(args: OverlayArgs) -> Result<OverlayOutput> {
    match args.command {
        OverlayCommand::Grant {
            service,
            relay,
            relay_id,
            egress_id,
            holder_pub,
            ttl_secs,
            config,
        } => {
            // Validate the pinned ids up front (fail before signing on a typo).
            let _ = parse_id(&relay_id)?;
            let _ = parse_id(&egress_id)?;

            // The client identity: bind a supplied public key (ticket carries no secret), or
            // generate one and embed its seed (convenience).
            let (holder, client_id, identity) = match &holder_pub {
                Some(pub_spec) => {
                    let id = parse_id(pub_spec)?;
                    (id.to_public(), id.to_hex(), None)
                }
                None => {
                    let secret =
                        OverlaySecret::generate().map_err(|e| Error::Overlay(e.to_string()))?;
                    let id = secret.id();
                    (
                        id.to_public(),
                        id.to_hex(),
                        Some(secret.seed_hex().to_string()),
                    )
                }
            };

            let token = mint_dial(&holder, &service, ttl_secs, &config).await?;
            let secret_ticket = identity.is_some();
            let ticket = ForwardTicket {
                relay,
                relay_id,
                egress_id,
                service,
                token,
                identity,
            }
            .encode()?;
            let enroll = format!("\"{client_id}\"");
            Ok(OverlayOutput::Granted {
                ticket,
                client_id,
                enroll,
                secret_ticket,
            })
        }
    }
}

/// Mint a holder-bound overlay-dial capability for `service`, signed offline by the root signer
/// resolved from `config` (reusing `token`'s resolver — the same cluster root key).
async fn mint_dial(
    holder: &TokenPublicKey,
    service: &str,
    ttl_secs: u64,
    config: &std::path::Path,
) -> Result<String> {
    let signer = crate::token::resolve_signer(config)
        .await
        .map_err(|e| Error::Signer(e.to_string()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    mint_overlay_dial(holder, service, ttl_secs, now, &*signer)
        .await
        .map_err(|e| Error::Overlay(format!("minting dial capability: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_ticket_round_trips() {
        let t = ForwardTicket {
            relay: "10.0.0.1:9100".into(),
            relay_id: "ed25519:aa".into(),
            egress_id: "ed25519:bb".into(),
            service: "svc/db".into(),
            token: "COSEBLOB".into(),
            identity: Some("ed25519:cc".into()),
        };
        let blob = t.encode().unwrap();
        assert!(blob.starts_with("brfwd1."));
        let back = ForwardTicket::decode(&blob).unwrap();
        assert_eq!(back.relay, "10.0.0.1:9100");
        assert_eq!(back.service, "svc/db");
        assert_eq!(back.token, "COSEBLOB");
        assert_eq!(back.identity.as_deref(), Some("ed25519:cc"));
    }

    #[test]
    fn forward_ticket_rejects_garbage() {
        assert!(ForwardTicket::decode("not-a-ticket").is_err());
        assert!(ForwardTicket::decode("brfwd1.@@@@").is_err());
        // A ticket missing a required field is refused.
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"relay\":\"\",\"relay_id\":\"x\",\"egress_id\":\"y\",\"service\":\"s\",\"token\":\"t\"}");
        assert!(ForwardTicket::decode(&format!("brfwd1.{bad}")).is_err());
    }
}
