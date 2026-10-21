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

use boatramp_core::cose::{TokenPublicKey, mint_overlay_dial, mint_overlay_publish};
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
/// Magic prefix for an **expose ticket** (the reverse-ingress analog of the forward ticket).
const EXPOSE_TICKET_MAGIC: &str = "brexp1";

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
    /// Mint an overlay-publish capability for `service` and emit a one-flag EXPOSE ticket for
    /// `boatramp expose --ticket` (the reverse-ingress analog of `grant`).
    ///
    /// Offline: signs with the cluster root key resolved from the config (or
    /// `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`), the same signer `token mint`/`grant` use. The ticket also
    /// carries the cluster trust root's PUBLIC key, which the exposer needs to independently verify
    /// each incoming forward client's dial capability (zero-trust — the exposer is the terminator).
    GrantExpose {
        /// The in-cluster service to publish AS (e.g. `svc/db`); must match the relay's registry key
        /// and the exposer's `expose <local> as svc/<name>`.
        service: String,
        /// The relay/ingress socket address the exposer will dial OUT to (`host:port`).
        #[arg(long)]
        relay: String,
        /// The relay's overlay identity to pin (`ed25519:<hex>` or `bro1…`).
        #[arg(long)]
        relay_id: String,
        /// Bind the capability to an exposer identity it already generated (its public
        /// `ed25519:<hex>`/`bro1…`); the ticket then carries no secret and the exposer supplies
        /// `--identity`. Omit to have the grant generate the exposer identity and embed its seed.
        #[arg(long)]
        holder_pub: Option<String>,
        /// Capability lifetime in seconds (an overlay-publish capability must be time-bounded).
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// Path to the config holding the root signer (`[serve.signer]` / `auth_root_private_key`).
        #[arg(long, default_value = "boatramp.cfg")]
        config: std::path::PathBuf,
    },
    /// Print this operator's overlay identity (load-or-generate at `~/.config/boatramp/overlay.key`).
    /// This is the identity self-serve `boatramp forward svc/<name>` binds its dial capability to.
    Id,
    /// List the cluster's overlay service directory (`GET /api/overlay/services`).
    Ls {
        /// boatramp server base URL (overrides `[publish].server`).
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
    },
    /// Resolve one overlay service name to its topology (relay + egress identities).
    Resolve {
        /// The service name (e.g. `svc/db`).
        name: String,
        /// boatramp server base URL (overrides `[publish].server`).
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
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

/// A copy-pasteable **expose ticket**: everything `boatramp expose` needs to publish a local service
/// into the cluster, bundled into one magic-prefixed base64url(JSON) blob (the reverse-ingress analog
/// of [`ForwardTicket`]). No `egress_id` — the exposer IS the egress. It DOES carry the cluster
/// `trust_root` public key, because the exposer (the terminator) independently verifies each incoming
/// forward client's dial capability against it (zero-trust). Self-describing, but the relay still
/// verifies the publish capability against its own trust root on use — a forged ticket buys nothing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExposeTicket {
    /// The relay/ingress `host:port` to dial OUT to.
    pub relay: String,
    /// The relay's overlay identity to pin (and prove the relay with in the registration handshake).
    pub relay_id: String,
    /// The in-cluster service name to publish AS (authoritative; equals the capability's scope).
    pub service: String,
    /// The holder-bound overlay-publish capability (COSE).
    pub token: String,
    /// The cluster trust root's PUBLIC key (`ed25519:`/`es256:` tagged hex) — the exposer verifies
    /// each incoming forward client's dial capability against this (zero-trust terminator).
    pub trust_root: String,
    /// The exposer's overlay identity seed (`ed25519:<hex>`) — present ONLY when the grant generated
    /// the identity (convenience mode). **Secret.** Absent in `--holder-pub` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

impl ExposeTicket {
    /// Encode to `brexp1.<base64url(json)>`.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(|e| Error::Overlay(e.to_string()))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("{EXPOSE_TICKET_MAGIC}.{b64}"))
    }

    /// Decode a `brexp1.…` ticket, rejecting a bad prefix or empty required fields.
    pub fn decode(blob: &str) -> Result<Self> {
        let b64 = blob
            .trim()
            .strip_prefix(EXPOSE_TICKET_MAGIC)
            .and_then(|r| r.strip_prefix('.'))
            .ok_or_else(|| {
                Error::Overlay(format!(
                    "not an expose ticket (expected `{EXPOSE_TICKET_MAGIC}.…`)"
                ))
            })?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| Error::Overlay(format!("malformed expose ticket: {e}")))?;
        let t: Self = serde_json::from_slice(&json)
            .map_err(|e| Error::Overlay(format!("malformed expose ticket: {e}")))?;
        if t.relay.is_empty()
            || t.relay_id.is_empty()
            || t.service.is_empty()
            || t.token.is_empty()
            || t.trust_root.is_empty()
        {
            return Err(Error::Overlay(
                "expose ticket is missing a required field".into(),
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
    /// `overlay grant-expose` — the expose ticket plus the relay enrollment the admin must apply.
    ExposeGranted {
        /// The `brexp1.…` ticket for the exposer to redeem with `expose --ticket`.
        ticket: String,
        /// The exposer's overlay identity (`ed25519:<hex>`) to enroll in the relay (mutual-pin only).
        client_id: String,
        /// The exact `[overlay] allowed_clients` entry to add on the relay node (mutual-pin only).
        enroll: String,
        /// Whether the ticket carries the exposer's secret seed (convenience mode).
        secret_ticket: bool,
    },
    /// `overlay id` — this operator's overlay identity.
    Identity {
        /// Canonical `ed25519:<hex>`.
        id: String,
        /// Friendly `bro1…` rendering.
        bech32: String,
    },
    /// `overlay ls` — the service directory.
    Directory { services: Vec<ServiceEntry> },
    /// `overlay resolve <name>` — one service's topology.
    Resolved(ServiceEntry),
}

/// One overlay service directory entry (the CLI mirror of the server's response).
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServiceEntry {
    pub service: String,
    pub relay: String,
    pub relay_id: String,
    pub egress_id: String,
    /// The relay's client-auth posture ("capability-only" | "mutual-pin").
    #[serde(default)]
    pub client_auth: String,
}

impl Rendered for OverlayOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Identity { id, bech32 } => {
                writeln!(w, "{id}")?;
                writeln!(w, "{bech32}")
            }
            Self::Directory { services } => {
                if services.is_empty() {
                    return writeln!(w, "no overlay services in the directory");
                }
                // Headerless, tab-separated for pipe purity (columns documented in cli.md):
                // service, relay addr, egress id, client-auth posture.
                for s in services {
                    writeln!(
                        w,
                        "{}\t{}\t{}\t{}",
                        s.service, s.relay, s.egress_id, s.client_auth
                    )?;
                }
                Ok(())
            }
            Self::Resolved(s) => {
                writeln!(w, "service:     {}", s.service)?;
                writeln!(w, "relay:       {} ({})", s.relay, s.relay_id)?;
                writeln!(w, "egress id:   {}", s.egress_id)?;
                if !s.client_auth.is_empty() {
                    writeln!(w, "client auth: {}", s.client_auth)?;
                }
                Ok(())
            }
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
                    "# If the relay is mutual-pin, enroll this client id in [overlay] allowed_clients"
                )?;
                writeln!(
                    w,
                    "# and reload; a capability-only relay needs NO enrollment — the ticket works as-is."
                )?;
                writeln!(w, "#   client id: {client_id}")?;
                writeln!(w, "#   allowed_clients entry (mutual-pin only): {enroll}")
            }
            Self::ExposeGranted {
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
                        "# This ticket embeds the exposer's private seed — treat it as a secret."
                    )?;
                }
                writeln!(
                    w,
                    "# Redeem on the exposer:   boatramp expose <local-addr> as <service> --ticket <ticket>"
                )?;
                writeln!(
                    w,
                    "# If the relay is mutual-pin, enroll this exposer id in [overlay] allowed_clients"
                )?;
                writeln!(
                    w,
                    "# and reload; a capability-only relay needs NO enrollment — the ticket works as-is."
                )?;
                writeln!(w, "#   exposer id: {client_id}")?;
                writeln!(w, "#   allowed_clients entry (mutual-pin only): {enroll}")
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
pub async fn run(
    args: OverlayArgs,
    config: &crate::config::ProjectConfig,
) -> Result<OverlayOutput> {
    match args.command {
        OverlayCommand::Id => {
            let secret = operator_identity()?;
            let id = secret.id();
            Ok(OverlayOutput::Identity {
                id: id.to_hex(),
                bech32: id.to_bech32(),
            })
        }
        OverlayCommand::Ls { server } => {
            let services = fetch_directory(server, config).await?;
            Ok(OverlayOutput::Directory { services })
        }
        OverlayCommand::Resolve { name, server } => {
            let services = fetch_directory(server, config).await?;
            services
                .into_iter()
                .find(|s| s.service == name)
                .map(OverlayOutput::Resolved)
                .ok_or_else(|| {
                    Error::Overlay(format!(
                        "no overlay service `{name}` in the directory — run `boatramp overlay ls` to \
                         see available services"
                    ))
                })
        }
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
        OverlayCommand::GrantExpose {
            service,
            relay,
            relay_id,
            holder_pub,
            ttl_secs,
            config,
        } => {
            // Validate the pinned relay id up front (fail before signing on a typo).
            let _ = parse_id(&relay_id)?;

            // The exposer identity: bind a supplied public key (ticket carries no secret), or
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

            // Mint the publish capability AND capture the signer's public key as the trust root the
            // exposer will verify incoming dial capabilities against (zero-trust terminator).
            let (token, trust_root) = mint_publish(&holder, &service, ttl_secs, &config).await?;
            let secret_ticket = identity.is_some();
            let ticket = ExposeTicket {
                relay,
                relay_id,
                service,
                token,
                trust_root,
                identity,
            }
            .encode()?;
            let enroll = format!("\"{client_id}\"");
            Ok(OverlayOutput::ExposeGranted {
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

/// Mint a holder-bound overlay-PUBLISH capability for `service`, signed offline by the root signer
/// resolved from `config` (the same cluster root key as `token`/`grant`). Returns the capability AND
/// the signer's public key (the trust root the exposer verifies incoming dial capabilities against).
async fn mint_publish(
    holder: &TokenPublicKey,
    service: &str,
    ttl_secs: u64,
    config: &std::path::Path,
) -> Result<(String, String)> {
    let signer = crate::token::resolve_signer(config)
        .await
        .map_err(|e| Error::Signer(e.to_string()))?;
    let trust_root = signer.public_key().to_hex();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let token = mint_overlay_publish(holder, service, ttl_secs, now, &*signer)
        .await
        .map_err(|e| Error::Overlay(format!("minting publish capability: {e}")))?;
    Ok((token, trust_root))
}

/// The operator's overlay identity key path: `$XDG_CONFIG_HOME/boatramp/overlay.key`, else
/// `~/.config/boatramp/overlay.key` (the established CLI config dir).
fn operator_key_path() -> Result<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .ok_or_else(|| {
            Error::Overlay("cannot locate the config dir (set HOME or XDG_CONFIG_HOME)".into())
        })?;
    Ok(base.join("boatramp").join("overlay.key"))
}

/// Load the operator's persistent overlay identity, generating + persisting one (`0600`, atomic) on
/// first use — like an SSH key. This is the identity self-serve `forward svc/<name>` binds its dial
/// capability to and uses for the E2EE handshake.
pub(crate) fn operator_identity() -> Result<OverlaySecret> {
    let path = operator_key_path()?;
    let io = |e: std::io::Error| Error::Overlay(format!("{}: {e}", path.display()));
    match std::fs::read_to_string(&path) {
        Ok(seed) => {
            OverlaySecret::from_seed_hex(seed.trim()).map_err(|e| Error::Overlay(e.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let secret = OverlaySecret::generate().map_err(|e| Error::Overlay(e.to_string()))?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
                }
            }
            #[cfg(unix)]
            {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(io)?;
                f.write_all(secret.seed_hex().as_bytes()).map_err(io)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&path, secret.seed_hex().as_bytes()).map_err(io)?;
            }
            // Finding G: announce the new persistent identity the way `ssh-keygen` announces its path,
            // so first-run `forward`/`overlay id` doesn't silently create a key the operator can't find.
            eprintln!(
                "boatramp overlay: generated a persistent overlay identity at {}",
                path.display()
            );
            Ok(secret)
        }
        Err(e) => Err(io(e)),
    }
}

/// `POST /api/overlay/dial` request/response (CLI mirror of the server types).
#[derive(serde::Serialize)]
pub(crate) struct DialRequestBody {
    pub service: String,
    pub holder_pubkey: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct DialResponseBody {
    pub relay: String,
    pub relay_id: String,
    pub egress_id: String,
    /// The relay's client-auth posture ("capability-only" | "mutual-pin"); selects the client's TLS
    /// posture when dialing (capability-only ⇒ present no client cert).
    #[serde(default)]
    pub relay_client_auth: String,
    pub token: String,
}

/// GET the overlay service directory from the control plane.
async fn fetch_directory(
    server: Option<String>,
    config: &crate::config::ProjectConfig,
) -> Result<Vec<ServiceEntry>> {
    let (server, http) =
        crate::client::connect(server, config).map_err(|e| Error::Overlay(e.to_string()))?;
    http.get(format!("{server}/api/overlay/services"))
        .send()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?
        .error_for_status()
        .map_err(|e| Error::Overlay(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))
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

    #[test]
    fn expose_ticket_round_trips() {
        let t = ExposeTicket {
            relay: "10.0.0.1:9100".into(),
            relay_id: "ed25519:aa".into(),
            service: "svc/db".into(),
            token: "PUBLISHCOSE".into(),
            trust_root: "es256:beef".into(),
            identity: Some("ed25519:cc".into()),
        };
        let blob = t.encode().unwrap();
        assert!(blob.starts_with("brexp1."));
        let back = ExposeTicket::decode(&blob).unwrap();
        assert_eq!(back.relay, "10.0.0.1:9100");
        assert_eq!(back.service, "svc/db");
        assert_eq!(back.token, "PUBLISHCOSE");
        assert_eq!(back.trust_root, "es256:beef");
        assert_eq!(back.identity.as_deref(), Some("ed25519:cc"));
    }

    #[test]
    fn expose_ticket_rejects_garbage_and_a_forward_ticket() {
        assert!(ExposeTicket::decode("not-a-ticket").is_err());
        assert!(ExposeTicket::decode("brexp1.@@@@").is_err());
        // A forward ticket is not an expose ticket (distinct magic).
        let fwd = ForwardTicket {
            relay: "1.2.3.4:5".into(),
            relay_id: "ed25519:aa".into(),
            egress_id: "ed25519:bb".into(),
            service: "svc/db".into(),
            token: "t".into(),
            identity: None,
        }
        .encode()
        .unwrap();
        assert!(ExposeTicket::decode(&fwd).is_err());
        // Missing the required trust_root is refused.
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"relay\":\"a:1\",\"relay_id\":\"x\",\"service\":\"s\",\"token\":\"t\",\"trust_root\":\"\"}");
        assert!(ExposeTicket::decode(&format!("brexp1.{bad}")).is_err());
    }
}
