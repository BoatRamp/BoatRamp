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

use boatramp_core::cose::{
    OverlayMemberRole, TokenPublicKey, join_challenge, mint_overlay_dial, mint_overlay_enroll,
    mint_overlay_publish, verify_overlay_enroll,
};
use boatramp_overlay::{OverlayId, OverlaySecret, SasCode};

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
/// Magic prefix for an **enrollment ticket** — the `HRP_JOIN` (`"brojoin"`, reserved in
/// `boatramp-overlay-proto`'s `wire.rs`) + the bech32-style `1`, so a rendered invitation reads
/// `brojoin1.…` (the overlay-enrollment analog of the cluster `JoinTicket`).
const ENROLL_TICKET_MAGIC: &str = "brojoin1";

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
    /// Mint a single-use overlay-ENROLL invitation for a role + scope and emit a one-flag
    /// `brojoin1.…` enrollment ticket for `boatramp overlay join`.
    ///
    /// Offline: signs with the cluster root key resolved from the config (or
    /// `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`), the same signer `token mint`/`grant` use. The authority is
    /// possession of the cluster root private key — the trust root the relay verifies the invitation
    /// against on redemption. The ticket carries the root's PUBLIC key so the enrollee can verify the
    /// invitation + extract the single-use handle it must prove possession against. The invitation is
    /// a confidential BEARER secret (whoever holds it, plus their own overlay key, can enroll until it
    /// is spent): deliver it over a private channel; its blast radius is bounded by `exp` + single-use.
    Invite {
        /// The role the invitation grants once redeemed.
        #[arg(long, value_parser = ["node", "device", "workload"])]
        role: String,
        /// The service scope the enrollee may dial/expose once enrolled (e.g. `svc/db`, or `*`).
        #[arg(long)]
        scope: String,
        /// Invitation lifetime in seconds (an enrollment invitation MUST be time-bounded).
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// The relay's overlay identity to pin once enrolled (`ed25519:<hex>`/`bro1…`); advisory,
        /// carried in the ticket for the enrollee's reference.
        #[arg(long)]
        relay: Option<String>,
        /// Path to the config holding the root signer (`[serve.signer]` / `auth_root_private_key`).
        #[arg(long, default_value = "boatramp.cfg")]
        config: std::path::PathBuf,
    },
    /// Redeem an overlay-enroll invitation: prove possession of this node's overlay identity and be
    /// admitted into the relay's live trust set, adopting the returned membership credential.
    Join {
        /// The `brojoin1.…` enrollment ticket from `boatramp overlay invite`.
        token: String,
        /// The overlay identity to enroll: a tagged seed (`ed25519:<hex>`) or a path to a key file.
        /// Omit to load-or-generate this operator's persistent identity (as `overlay id` does).
        #[arg(long)]
        identity: Option<String>,
        /// boatramp server base URL to redeem against (overrides `[publish].server`).
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
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
    /// Pair with another operator's device and mutually verify identities with a short authentication
    /// string (SAS), detecting an active man-in-the-middle.
    ///
    /// Two transports: DIRECT (one side `--listen <addr>`, the other dials `<peer-addr>`) for peers
    /// that can reach each other, and RELAY RENDEZVOUS (one side `--accept <bropair1…>` parks at the
    /// cluster relay, the other redeems `<bropair1…>`) for NAT'd peers that cannot — they meet through
    /// the relay, which bridges ciphertext blind. Mint a rendezvous code with `overlay pair-code`.
    /// Both transports run the SAME relay-blind E2EE handshake + commit-then-reveal nonce exchange, and
    /// each derives a SAS the two operators compare out of band. On a match the peer's proven identity
    /// is pinned (locally, in-memory this increment); on a mismatch the command aborts without pinning.
    Pair {
        /// Act as the DIRECT-DIAL RESPONDER: listen on this `host:port` for a pairing dialer.
        #[arg(long, value_name = "ADDR", conflicts_with = "peer")]
        listen: Option<String>,
        /// Act as the RELAY-RENDEZVOUS RESPONDER: park this `bropair1…` code at the cluster relay and
        /// wait for the NAT'd peer to redeem it (for peers that cannot direct-dial). Mint a code with
        /// `overlay pair-code`.
        #[arg(long, value_name = "CODE", conflicts_with_all = ["listen", "peer"])]
        accept: Option<String>,
        /// Only meaningful with `--accept`: present this holder-bound `overlay-pairing-park`
        /// capability (from `overlay pair-code --accepter-pubkey`, the `park_cap` it prints) and prove
        /// possession of it to the relay — REQUIRED when the relay's `pairing_park` config is
        /// `"authenticated"`; omit for an OPEN-mode relay (today's default), where it is never sent.
        #[arg(long, value_name = "CAP", requires = "accept")]
        park_cap: Option<String>,
        /// Act as the INITIATOR over the human-typeable SHORT-CODE path: redeem this short code (e.g.
        /// `1234-5678`; separators optional) via the control plane's unauthenticated relay-topology
        /// lookup (`GET /api/overlay/pair-relay` — a short code carries no topology of its own), then
        /// the relay's rate-limited short-redeem. Mint one with `overlay pair-code --short`.
        #[arg(long, value_name = "CODE", conflicts_with_all = ["listen", "accept", "peer"])]
        short: Option<String>,
        /// Act as the INITIATOR: either a peer `host:port` to DIRECT-DIAL (the address the responder is
        /// listening on), or a `bropair1…` rendezvous code to REDEEM through the cluster relay.
        #[arg(value_name = "PEER_OR_CODE", conflicts_with_all = ["listen", "short"])]
        peer: Option<String>,
        /// The overlay identity to pair AS: a tagged seed (`ed25519:<hex>`) or a key-file path.
        /// Omit to use this operator's persistent identity (as `overlay id`).
        #[arg(long)]
        identity: Option<String>,
        /// Non-interactive confirm: the FULL expected SAS words (e.g. `cargo-delta-hotel`), as shown
        /// on the PEER's device, compared case-insensitively. The pairing ABORTS unless the derived
        /// SAS equals this — there is no check-skipping `--yes`. Required when stdin is not a TTY.
        #[arg(long, value_name = "SAS_WORDS")]
        expect: Option<String>,
        /// Bound the pairing window in seconds (the handshake must complete within it; the wait for a
        /// peer to redeem a parked rendezvous is bounded separately by the relay's rendezvous TTL).
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// boatramp server base URL (overrides `[publish].server`) — used ONLY by the `--short` path,
        /// to look up the relay topology (`GET /api/overlay/pair-relay`); every other transport needs
        /// no control-plane call.
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
    },
    /// Mint a single-use, short-TTL PAIRING rendezvous code (`bropair1…`) so two peers that cannot
    /// direct-dial each other (both NAT'd) can meet through the cluster relay, which bridges their
    /// ciphertext blind. Gated `Overlay·Admin` at the server (`POST /api/overlay/pair-code`). Share
    /// the printed code with the new peer: park it with `overlay pair --accept <code>`, and the peer
    /// redeems it with `overlay pair <code>`.
    PairCode {
        /// Code lifetime in seconds (a pairing code is short-lived — minutes; the server clamps it).
        #[arg(long, default_value_t = 300)]
        ttl_secs: u64,
        /// ALSO mint a human-typeable pairing SHORT CODE (e.g. `1234-5678`) aliasing the same
        /// rendezvous — easier to read aloud / type on a second device than `bropair1…`. Low-entropy
        /// by design; the relay rate-limits + locks out online guessing on redeem.
        #[arg(long)]
        short: bool,
        /// The ACCEPTER's overlay public key (`ed25519:<hex>`/`bro1…`, e.g. from their `overlay id`) —
        /// REQUIRED when this cluster's relay runs AUTHENTICATED pairing-park (`[overlay]
        /// pairing_park = "authenticated"`), in which case the mint ALSO returns a holder-bound
        /// `overlay-pairing-park` capability bound to this key: give that capability to the accepter
        /// alongside the code (they present it with `overlay pair --accept <code> --park-cap <cap>`).
        /// Ignored (and optional) against an OPEN-mode relay (today's default).
        #[arg(long, value_name = "PUBKEY")]
        accepter_pubkey: Option<String>,
        /// boatramp server base URL (overrides `[publish].server`).
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
    },
    /// Manage the cluster's **overlay flow policy** — the per-flow access gate that decides which
    /// dial/publish-cap mints the control plane will issue (deny-or-shrink-TTL only), separate
    /// from the RBAC that grants `Overlay·Write`/`Admin`. All three verbs are `System·Admin`.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCommand,
    },
}

/// `boatramp overlay policy …` — administer the overlay flow policy (`System·Admin`).
#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Show the active overlay flow policy (Cedar text) + its version (`GET /api/overlay/policy`).
    Ls {
        /// boatramp server base URL (overrides `[publish].server`).
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
    },
    /// Replace the overlay flow policy from a `.cedar` file (or `-` for stdin)
    /// (`PUT /api/overlay/policy`). Validated server-side (parse + schema + temporal screen); a
    /// validation failure prints the server's `400` body verbatim. An EMPTY file turns the gate
    /// OFF. Storing the FIRST policy surfaces a default-deny CLIFF warning.
    Set {
        /// Path to the `.cedar` policy file, or `-` to read the policy from stdin.
        file: String,
        /// Expected current version (the `version` from `policy ls`) for a conditional write; a
        /// stale version → `409` (re-read + retry). Omit to overwrite the current value.
        #[arg(long)]
        if_match: Option<String>,
        /// boatramp server base URL (overrides `[publish].server`).
        #[arg(long, env = "BOATRAMP_SERVER")]
        server: Option<String>,
    },
    /// Dry-run a dial/expose mint against the active (or a supplied) policy — NO capability is
    /// minted (`POST /api/overlay/policy/test`). Prints ALLOW/DENY, the TTL ceiling, and the
    /// deciding policies + diagnostics (a `System·Admin`-only authoring aid).
    Test {
        /// The flow action to simulate.
        #[arg(long, value_parser = ["dial", "expose"])]
        action: String,
        /// The target service name (e.g. `svc/db`).
        #[arg(long)]
        service: String,
        /// The holder key (`ed25519:<hex>` / `bro1…`); defaults to this operator's overlay id.
        #[arg(long)]
        holder: Option<String>,
        /// Simulate a bound member credential's role (`node`/`device`/`workload`); absent ⇒ key-only.
        #[arg(long)]
        role: Option<String>,
        /// Simulate a bound member credential's service scope; absent ⇒ key-only.
        #[arg(long)]
        scope: Option<String>,
        /// Simulate `enrolled = true` on the holder (a bound member credential was presented).
        #[arg(long)]
        enrolled: bool,
        /// The requested TTL (seconds) to evaluate — the policy may shrink it.
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
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

/// A copy-pasteable **enrollment ticket**: everything `boatramp overlay join` needs to redeem an
/// overlay-enroll invitation, bundled into one magic-prefixed base64url(JSON) blob (the
/// overlay-enrollment analog of [`ForwardTicket`]). It carries the cluster `trust_root` public key so
/// the enrollee can verify the invitation and extract the single-use handle (`jti`) its possession
/// proof must bind to — without needing the root key out of band. The invitation `token` it carries
/// is a **confidential bearer secret** (it grants enrollment until spent); the relay still verifies it
/// against its own trust root + requires a matching possession proof on use, so a forged ticket buys
/// nothing, but a *leaked unspent* ticket is a bearer risk bounded by `exp` + single-use.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrollTicket {
    /// The overlay-enroll invitation (COSE) to redeem.
    pub token: String,
    /// The cluster trust root's PUBLIC key (`ed25519:`/`es256:` tagged hex) — the enrollee verifies
    /// the invitation against this to extract the `jti` its possession proof binds to.
    pub trust_root: String,
    /// The role the invitation grants (display/reference; authoritative value is inside the token).
    pub role: String,
    /// The scope the invitation grants (display/reference; authoritative value is inside the token).
    pub scope: String,
    /// The relay's overlay identity to pin once enrolled (advisory; display/reference). Absent when
    /// the inviter did not supply one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

impl EnrollTicket {
    /// Encode to `brojoin1.<base64url(json)>`.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(|e| Error::Overlay(e.to_string()))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("{ENROLL_TICKET_MAGIC}.{b64}"))
    }

    /// Decode a `brojoin1.…` ticket, rejecting a bad prefix or empty required fields.
    pub fn decode(blob: &str) -> Result<Self> {
        let b64 = blob
            .trim()
            .strip_prefix(ENROLL_TICKET_MAGIC)
            .and_then(|r| r.strip_prefix('.'))
            .ok_or_else(|| {
                Error::Overlay(format!(
                    "not an enrollment ticket (expected `{ENROLL_TICKET_MAGIC}.…`)"
                ))
            })?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| Error::Overlay(format!("malformed enrollment ticket: {e}")))?;
        let t: Self = serde_json::from_slice(&json)
            .map_err(|e| Error::Overlay(format!("malformed enrollment ticket: {e}")))?;
        if t.token.is_empty() || t.trust_root.is_empty() || t.scope.is_empty() {
            return Err(Error::Overlay(
                "enrollment ticket is missing a required field".into(),
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
    /// `overlay invite` — the enrollment ticket plus the raw invitation + redeem hint.
    Invited {
        /// The `brojoin1.…` enrollment ticket for the enrollee to redeem with `overlay join`.
        ticket: String,
        /// The raw overlay-enroll invitation (COSE) — the confidential bearer secret inside the ticket.
        token: String,
        /// The role the invitation grants.
        role: String,
        /// The scope the invitation grants.
        scope: String,
        /// The invitation's expiry (Unix seconds).
        expires_at: u64,
    },
    /// `overlay join` — the adopted membership credential after a successful enrollment.
    Enrolled {
        /// The root-signed `overlay-member` credential the enrollee adopts.
        member: String,
        /// The role the membership grants.
        role: String,
        /// The scope the membership grants.
        scope: String,
        /// The credential's expiry (Unix seconds).
        expires_at: u64,
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
    /// `overlay policy ls` — the active flow policy (Cedar text) + its version.
    FlowPolicy {
        /// The Cedar policy text (empty when the gate is off / no policy stored).
        policy: String,
        /// The optimistic-concurrency version (echo back as `--if-match` on `set`).
        version: String,
    },
    /// `overlay policy set` — the stored policy's new version + a possible default-deny warning.
    FlowPolicyStored {
        /// The new version.
        version: String,
        /// Present only when this `set` stored the FIRST policy (the gate just became default-deny).
        warning: Option<String>,
        /// Whether an empty policy was stored (the gate was turned OFF).
        cleared: bool,
    },
    /// `overlay policy test` — a dry-run flow decision.
    FlowPolicyTest {
        /// `allow` or `deny`.
        decision: String,
        /// The policy-imposed TTL ceiling (seconds), if any.
        ttl_ceiling: Option<u64>,
        /// The deciding policy ids.
        deciding_policies: Vec<String>,
        /// Evaluation diagnostics.
        diagnostics: Vec<String>,
        /// A posture note (feature off / corrupt), if any.
        note: Option<String>,
    },
    /// `overlay pair-code` — a minted pairing rendezvous code (`bropair1…`) + the relay it meets at.
    PairCodeMinted {
        /// The copy-pasteable `bropair1…` rendezvous code to share with the new peer.
        code: String,
        /// The ingress relay `host:port` both peers meet at (also embedded in the code).
        relay: String,
        /// The relay's overlay identity both peers pin (also embedded in the code).
        relay_id: String,
        /// The code's expiry (Unix seconds).
        expires_at: u64,
        /// The human-typeable short-code alias (e.g. `"1234-5678"`), present only when `--short` was
        /// requested.
        short_code: Option<String>,
        /// The holder-bound `overlay-pairing-park` capability (COSE), present only when this
        /// cluster's relay runs AUTHENTICATED pairing-park (`--accepter-pubkey` was honored). Give it
        /// to the accepter alongside the code: they present it with
        /// `overlay pair --accept <code> --park-cap <cap>`.
        park_cap: Option<String>,
    },
    /// `overlay pair` — a confirmed pairing: the peer's proven identity (pinned locally) plus the
    /// SAS the operators compared.
    Paired {
        /// The peer's E2EE-proven overlay identity (`ed25519:<hex>`), now pinned.
        peer_id: String,
        /// The peer identity's display fingerprint.
        fingerprint: String,
        /// The SAS word rendering the operators compared.
        sas_words: String,
        /// The SAS keypad-digit rendering the operators compared.
        sas_digits: String,
    },
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
            Self::Invited {
                ticket,
                token: _,
                role,
                scope,
                expires_at,
            } => {
                writeln!(w, "{ticket}")?;
                writeln!(w)?;
                writeln!(
                    w,
                    "# This enrollment ticket embeds a single-use invitation — treat it as a secret \
                     (a leaked unspent ticket grants enrollment until it expires or is spent)."
                )?;
                writeln!(w, "#   role:  {role}")?;
                writeln!(w, "#   scope: {scope}")?;
                writeln!(w, "#   expires at (unix): {expires_at}")?;
                writeln!(
                    w,
                    "# Redeem on the enrollee:   boatramp overlay join <ticket> --server <url>"
                )
            }
            Self::Enrolled {
                member,
                role,
                scope,
                expires_at,
            } => {
                writeln!(w, "enrolled for scope {scope} (role {role})")?;
                writeln!(w, "# member credential expires at (unix): {expires_at}")?;
                writeln!(w, "{member}")
            }
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
            Self::FlowPolicy { policy, version } => {
                if policy.trim().is_empty() {
                    writeln!(w, "# no overlay flow policy in effect (the gate is OFF)")?;
                } else {
                    write!(w, "{policy}")?;
                    if !policy.ends_with('\n') {
                        writeln!(w)?;
                    }
                }
                writeln!(w, "# version: {version}")
            }
            Self::FlowPolicyStored {
                version,
                warning,
                cleared,
            } => {
                if *cleared {
                    writeln!(w, "overlay flow policy cleared (the gate is now OFF)")?;
                } else {
                    writeln!(w, "overlay flow policy stored")?;
                }
                writeln!(w, "# version: {version}")?;
                if let Some(warn) = warning {
                    writeln!(w, "# WARNING: {warn}")?;
                }
                Ok(())
            }
            Self::FlowPolicyTest {
                decision,
                ttl_ceiling,
                deciding_policies,
                diagnostics,
                note,
            } => {
                writeln!(w, "decision: {decision}")?;
                if let Some(c) = ttl_ceiling {
                    writeln!(
                        w,
                        "ttl ceiling: {c} (the policy would shrink the requested TTL)"
                    )?;
                }
                if !deciding_policies.is_empty() {
                    writeln!(w, "deciding policies: {}", deciding_policies.join(", "))?;
                }
                for d in diagnostics {
                    writeln!(w, "# diagnostic: {d}")?;
                }
                if let Some(n) = note {
                    writeln!(w, "# {n}")?;
                }
                Ok(())
            }
            Self::PairCodeMinted {
                code,
                relay,
                relay_id,
                expires_at,
                short_code,
                park_cap,
            } => {
                writeln!(w, "{code}")?;
                writeln!(w)?;
                writeln!(
                    w,
                    "# Single-use pairing rendezvous code — share it with the new peer over a private \
                     channel (a leaked code only lets someone RACE to pair; the SAS still catches it)."
                )?;
                writeln!(w, "#   relay:             {relay} ({relay_id})")?;
                writeln!(w, "#   expires at (unix): {expires_at}")?;
                match park_cap {
                    None => {
                        writeln!(
                            w,
                            "# Park it (operator):  boatramp overlay pair --accept {code}"
                        )?;
                    }
                    Some(cap) => {
                        writeln!(w)?;
                        writeln!(
                            w,
                            "# AUTHENTICATED pairing-park: give the accepter this capability too (a \
                             secret bound to their key — deliver it over a private channel):"
                        )?;
                        writeln!(w, "{cap}")?;
                        writeln!(w)?;
                        writeln!(
                            w,
                            "# Park it (accepter):  boatramp overlay pair --accept {code} --park-cap {cap}"
                        )?;
                    }
                }
                writeln!(w, "# Redeem it (peer):    boatramp overlay pair {code}")?;
                if let Some(short) = short_code {
                    writeln!(w)?;
                    writeln!(
                        w,
                        "# Human-typeable short code (an INDEPENDENT alias — low-entropy, rate-limited \
                         + lockout-guarded at the relay; the SAS still catches a MITM): {short}"
                    )?;
                    writeln!(
                        w,
                        "# Redeem it (peer):    boatramp overlay pair --short {short}"
                    )?;
                }
                Ok(())
            }
            Self::Paired {
                peer_id,
                fingerprint,
                sas_words,
                sas_digits,
            } => {
                writeln!(w, "paired with {peer_id}")?;
                writeln!(w, "  fingerprint: {fingerprint}")?;
                writeln!(w, "  SAS words:   {sas_words}")?;
                writeln!(w, "  SAS digits:  {sas_digits}")?;
                writeln!(
                    w,
                    "# identity verified out-of-band via the SAS and pinned (in-memory this session)"
                )
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
        OverlayCommand::Pair {
            listen,
            accept,
            park_cap,
            short,
            peer,
            identity,
            expect,
            timeout_secs,
            server,
        } => {
            pair_run(
                listen,
                accept,
                park_cap,
                short,
                peer,
                identity,
                expect,
                timeout_secs,
                server,
                config,
            )
            .await
        }
        OverlayCommand::PairCode {
            ttl_secs,
            short,
            accepter_pubkey,
            server,
        } => pair_code_run(ttl_secs, short, accepter_pubkey, server, config).await,
        OverlayCommand::Policy { cmd } => policy_run(cmd, config).await,
        OverlayCommand::Invite {
            role,
            scope,
            ttl_secs,
            relay,
            config,
        } => {
            let Some(role_enum) = OverlayMemberRole::parse(&role) else {
                return Err(Error::Overlay(format!(
                    "role `{role}` must be node|device|workload"
                )));
            };
            if let Some(r) = &relay {
                let _ = parse_id(r)?; // validate the pinned relay id up front (fail before signing)
            }
            let (token, trust_root, expires_at) =
                mint_enroll(role_enum, &scope, ttl_secs, &config).await?;
            let ticket = EnrollTicket {
                token: token.clone(),
                trust_root,
                role: role.clone(),
                scope: scope.clone(),
                relay,
            }
            .encode()?;
            Ok(OverlayOutput::Invited {
                ticket,
                token,
                role,
                scope,
                expires_at,
            })
        }
        OverlayCommand::Join {
            token,
            identity,
            server,
        } => {
            let ticket = EnrollTicket::decode(&token)?;
            let trust_root = TokenPublicKey::from_hex(&ticket.trust_root)
                .map_err(|e| Error::Overlay(format!("enrollment ticket trust_root: {e}")))?;
            let now = now_secs();
            // Verify the invitation against the trust root to extract the single-use `jti` the
            // possession proof must bind to (the relay re-verifies it on redemption).
            let verified = verify_overlay_enroll(&ticket.token, &trust_root, now).map_err(|e| {
                Error::Overlay(format!("enrollment invitation did not verify: {e}"))
            })?;
            // This node's overlay identity: the key being enrolled. Its private half never leaves —
            // only a possession proof over the challenge does.
            let secret = load_identity(identity.as_deref())?;
            let overlay_pubkey = secret.id().to_hex();
            let rpk = secret
                .rpk_identity()
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let proof_iat = now;
            let challenge = join_challenge(&verified.jti, &overlay_pubkey, proof_iat);
            let proof = rpk
                .sign(&challenge)
                .map_err(|e| Error::Overlay(format!("building possession proof: {e}")))?;
            let body = redeem_enroll(
                server,
                config,
                &ticket.token,
                &overlay_pubkey,
                &hex::encode(proof),
                proof_iat,
            )
            .await?;
            Ok(OverlayOutput::Enrolled {
                member: body.member,
                role: body.role,
                scope: body.scope,
                expires_at: body.expires_at,
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

/// The operator's decision after seeing the SAS: pin the peer, or abort without pinning.
#[derive(Debug, PartialEq, Eq)]
enum ConfirmOutcome {
    /// The SAS matched — pin the peer's proven identity.
    Confirm,
    /// The SAS did not match (or was declined) — pin nothing, fail-closed.
    Reject,
}

/// Decide a pairing from the operator's answer: `Confirm` iff `typed` parses as the FULL SAS words
/// AND equals the locally-derived `sas`. A mistyped, unparseable, or differing value is `Reject`
/// (never a default-yes) — the parse itself is case-insensitive and separator-tolerant via
/// [`SasCode::from_words`], so only a genuinely matching code confirms.
fn decide_sas(sas: &SasCode, typed: &str) -> ConfirmOutcome {
    match SasCode::from_words(typed) {
        Some(got) if got == *sas => ConfirmOutcome::Confirm,
        _ => ConfirmOutcome::Reject,
    }
}

/// Run `overlay pair`: stand up the chosen transport (direct-dial, or the relay-blind `bropair1`
/// rendezvous for NAT'd peers), run the SAS pairing handshake, confirm the SAS out-of-band
/// (fail-closed), and pin the peer on a positive match. The handshake is identical on every
/// transport; only how the two bi-stream halves are established differs.
#[allow(clippy::too_many_arguments)]
async fn pair_run(
    listen: Option<String>,
    accept_code: Option<String>,
    park_cap: Option<String>,
    short_code: Option<String>,
    peer: Option<String>,
    identity: Option<String>,
    expect: Option<String>,
    timeout_secs: u64,
    server: Option<String>,
    config: &crate::config::ProjectConfig,
) -> Result<OverlayOutput> {
    use boatramp_overlay::{
        OverlayPeerPolicy, PairCode, Role, ShortCode, VerifiedPeers, accept,
        client_endpoint_server_auth, dial, identity_fp, pair_dial_endpoint, pair_relay_park,
        pair_relay_park_authenticated, pair_relay_redeem, pair_relay_redeem_short, server_endpoint,
    };
    use boatramp_overlay_client::OverlayClient;

    let secret = load_identity(identity.as_deref())?;
    // Build a pairing client over this identity — the handshake itself now runs through the SDK
    // (dogfood). The client gets its OWN copy of the identity (the seed is zeroized, so not `Clone`);
    // `secret` is kept here for the listener's accept-side `server_endpoint` (a server-role
    // constructor outside the client SDK).
    let client = OverlayClient::builder(
        boatramp_overlay::OverlaySecret::from_seed_hex(secret.seed_hex().as_str())
            .map_err(|e| Error::Overlay(e.to_string()))?,
    )
    .build()
    .map_err(|e| Error::Overlay(e.to_string()))?;
    let deadline = std::time::Duration::from_secs(timeout_secs);
    let q = |e: boatramp_overlay::QuicError| Error::Overlay(e.to_string());

    // Decode a `bropair1…` rendezvous code into the relay socket to dial + the relay id to pin.
    let decode_code = |raw: &str| -> Result<(std::net::SocketAddr, PairCode)> {
        let code =
            PairCode::decode(raw).map_err(|e| Error::Overlay(format!("pairing code: {e}")))?;
        let addr = code
            .relay_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| {
                Error::Overlay(format!(
                    "pairing code relay address `{}`: {e}",
                    code.relay_addr
                ))
            })?;
        Ok((addr, code))
    };

    // Hold the endpoint + connection alive through the (possibly interactive) confirm, so the final
    // sealed reveal reaches the peer and the stream is not reset early.
    let _hold;
    let (sas, peer_id) = match (accept_code, listen, peer, short_code) {
        // Relay rendezvous RESPONDER: park the code at the relay and wait for the NAT'd peer to redeem.
        (Some(code_s), _, _, _) => {
            let (relay_addr, code) = decode_code(&code_s)?;
            let ep =
                client_endpoint_server_auth(&OverlayPeerPolicy::Pin(code.relay_id)).map_err(q)?;
            eprintln!(
                "boatramp overlay pair: parked at relay {} as {} — waiting for the peer to redeem the code",
                code.relay_addr,
                secret.id().to_bech32()
            );
            // AUTHENTICATED pairing-park (owner decision, per-relay operator config): when the
            // operator supplied a `--park-cap`, present it and prove possession to the relay — EXACTLY
            // the holder-binding the exposer-registration path already applies. Omitted ⇒ the OPEN-mode
            // flow, byte-for-byte unchanged.
            let (conn, mut send, mut recv) = match park_cap {
                Some(cap) => pair_relay_park_authenticated(
                    &ep,
                    relay_addr,
                    code.relay_id,
                    code.rendezvous,
                    &secret,
                    cap,
                )
                .await
                .map_err(|e| {
                    Error::Overlay(format!("relay rendezvous (authenticated park): {e}"))
                })?,
                None => pair_relay_park(&ep, relay_addr, code.rendezvous)
                    .await
                    .map_err(|e| Error::Overlay(format!("relay rendezvous (park): {e}")))?,
            };
            let out = client
                .pair(&mut send, &mut recv, Role::Responder, deadline)
                .await
                .map_err(|e| Error::Overlay(format!("pairing handshake: {e}")))?;
            _hold = (ep, conn);
            out
        }
        // Relay rendezvous INITIATOR: the positional arg is a `bropair1…` code — redeem it.
        // Lowercase-normalize the discriminator (INFO-3) so a pasted UPPERCASE bech32m code (which
        // decodes fine) routes to redeem instead of falling through to the direct-dial addr parse.
        (None, None, Some(ref p), None)
            if p.trim().to_ascii_lowercase().starts_with("bropair1") =>
        {
            let (relay_addr, code) = decode_code(p)?;
            let ep =
                client_endpoint_server_auth(&OverlayPeerPolicy::Pin(code.relay_id)).map_err(q)?;
            let (conn, mut send, mut recv) = pair_relay_redeem(&ep, relay_addr, code.rendezvous)
                .await
                .map_err(|e| Error::Overlay(format!("relay rendezvous (redeem): {e}")))?;
            let out = client
                .pair(&mut send, &mut recv, Role::Initiator, deadline)
                .await
                .map_err(|e| Error::Overlay(format!("pairing handshake: {e}")))?;
            _hold = (ep, conn);
            out
        }
        // Relay rendezvous INITIATOR over the SHORT-CODE path: no topology is embedded in a short
        // code, so fetch this cluster's relay topology first (unauthenticated —
        // `GET /api/overlay/pair-relay`), then redeem the normalized digit string at the relay.
        (None, None, None, Some(code_s)) => {
            let digits = ShortCode::normalize(&code_s)
                .map_err(|e| Error::Overlay(format!("pairing short code: {e}")))?;
            let (relay_addr, relay_id) = fetch_pair_relay(server.clone(), config).await?;
            let ep = client_endpoint_server_auth(&OverlayPeerPolicy::Pin(relay_id)).map_err(q)?;
            let (conn, mut send, mut recv) = pair_relay_redeem_short(&ep, relay_addr, digits)
                .await
                .map_err(|e| Error::Overlay(format!("relay rendezvous (short redeem): {e}")))?;
            let out = client
                .pair(&mut send, &mut recv, Role::Initiator, deadline)
                .await
                .map_err(|e| Error::Overlay(format!("pairing handshake: {e}")))?;
            _hold = (ep, conn);
            out
        }
        // Direct-dial RESPONDER: listen for a dialer.
        (None, Some(bind), _, None) => {
            let addr = bind
                .parse::<std::net::SocketAddr>()
                .map_err(|e| Error::Overlay(format!("--listen `{bind}`: {e}")))?;
            let ep = server_endpoint(&secret, &OverlayPeerPolicy::AcceptAny, addr).map_err(q)?;
            eprintln!(
                "boatramp overlay pair: listening on {} as {}",
                ep.local_addr().map_err(|e| Error::Overlay(e.to_string()))?,
                secret.id().to_bech32()
            );
            let conn = accept(&ep)
                .await
                .map_err(q)?
                .ok_or_else(|| Error::Overlay("listener closed before a peer dialed".into()))?;
            let (mut send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|e| Error::Overlay(format!("accepting the pairing stream: {e}")))?;
            let out = client
                .pair(&mut send, &mut recv, Role::Responder, deadline)
                .await
                .map_err(|e| Error::Overlay(format!("pairing handshake: {e}")))?;
            _hold = (ep, conn);
            out
        }
        // Direct-dial INITIATOR: the positional arg is a peer `host:port`.
        (None, None, Some(addr_s), None) => {
            let addr = addr_s
                .parse::<std::net::SocketAddr>()
                .map_err(|e| Error::Overlay(format!("peer address `{addr_s}`: {e}")))?;
            let ep = pair_dial_endpoint().map_err(q)?;
            let conn = dial(&ep, addr)
                .await
                .map_err(|e| Error::Overlay(format!("dialing {addr}: {e}")))?;
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| Error::Overlay(format!("opening the pairing stream: {e}")))?;
            let out = client
                .pair(&mut send, &mut recv, Role::Initiator, deadline)
                .await
                .map_err(|e| Error::Overlay(format!("pairing handshake: {e}")))?;
            _hold = (ep, conn);
            out
        }
        (None, None, None, None) => {
            return Err(Error::Overlay(
                "specify a transport: `--listen <addr>` or a peer `<addr>` (direct), \
                 `--accept <bropair1…>` or a `<bropair1…>` code (relay rendezvous), or \
                 `--short <code>` (short-code relay rendezvous)"
                    .into(),
            ));
        }
        // Unreachable via the CLI (clap's `conflicts_with_all` refuses `--short` alongside
        // `--listen`/`peer` before this function is ever called) — exhaustiveness only.
        _ => {
            return Err(Error::Overlay(
                "`--short` cannot be combined with `--listen` or a peer address".into(),
            ));
        }
    };

    let fp = identity_fp(&peer_id);
    match confirm_sas(&sas, &peer_id, &fp, expect.as_deref())? {
        ConfirmOutcome::Confirm => {
            // Pin the E2EE-proven identity (never operator-typed). In-memory this increment; a
            // KV-persistent verified pin is the next increment.
            let mut pins = VerifiedPeers::new();
            let vp = pins.confirm(peer_id);
            Ok(OverlayOutput::Paired {
                peer_id: peer_id.to_hex(),
                fingerprint: vp.fingerprint.to_string(),
                sas_words: sas.words(),
                sas_digits: sas.digits(),
            })
        }
        ConfirmOutcome::Reject => {
            // Fail-closed: no pin, loud warning, security event, non-zero exit.
            eprintln!("DO NOT CONFIRM — safety numbers differ; a man-in-the-middle may be present");
            tracing::warn!(
                target: "overlay.pair",
                peer = %peer_id.to_bech32(),
                "overlay pairing REJECTED: SAS did not match — identity NOT pinned"
            );
            Err(Error::Overlay(
                "pairing aborted: the safety numbers did not match — the peer was NOT pinned"
                    .into(),
            ))
        }
    }
}

/// `POST /api/overlay/pair-code` request/response (CLI mirror of the server types).
#[derive(serde::Serialize)]
struct PairCodeRequestBody {
    ttl_secs: u64,
    /// ALSO mint a human-typeable short-code alias (overlay follow-up #2 inc3).
    #[serde(default)]
    short: bool,
    /// The accepter's overlay pubkey to bind an `overlay-pairing-park` capability to — only
    /// meaningful (and required) against an AUTHENTICATED-pairing-park relay; ignored in OPEN mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepter_pubkey: Option<String>,
}

#[derive(serde::Deserialize)]
struct PairCodeResponseBody {
    relay: String,
    relay_id: String,
    /// Hex of the single-use rendezvous id the relay keys the park/redeem on.
    rendezvous: String,
    expires_at: u64,
    /// The grouped short-code alias (e.g. `"1234-5678"`), present only when `short` was requested.
    #[serde(default)]
    short_code: Option<String>,
    /// The holder-bound `overlay-pairing-park` capability (COSE), present only when this cluster's
    /// relay runs AUTHENTICATED pairing-park (`accepter_pubkey` was supplied and honored).
    #[serde(default)]
    park_cap: Option<String>,
}

/// Run `overlay pair-code`: mint a single-use pairing rendezvous code at the control plane
/// (`Overlay·Admin`) and assemble the copy-pasteable `bropair1…` the operator shares with the new
/// peer. The server returns the relay topology + a fresh rendezvous id; the CLI packs them into the
/// bech32m code (the overlay analog of assembling a `brfwd1…` ticket from the dial response). With
/// `short`, also prints the server-minted human-typeable short-code alias. With `accepter_pubkey` (
/// REQUIRED against an AUTHENTICATED-pairing-park relay), the response ALSO carries a holder-bound
/// `overlay-pairing-park` capability — printed alongside the code for the operator to hand to the
/// accepter, who presents it with `overlay pair --accept <code> --park-cap <cap>`.
async fn pair_code_run(
    ttl_secs: u64,
    short: bool,
    accepter_pubkey: Option<String>,
    server: Option<String>,
    config: &crate::config::ProjectConfig,
) -> Result<OverlayOutput> {
    use boatramp_overlay::PairCode;

    let (server, http) =
        crate::client::connect(server, config).map_err(|e| Error::Overlay(e.to_string()))?;
    let resp = http
        .post(format!("{server}/api/overlay/pair-code"))
        .json(&PairCodeRequestBody {
            ttl_secs,
            short,
            accepter_pubkey,
        })
        .send()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Overlay(format!(
            "overlay pair-code refused ({}): {}",
            status.as_u16(),
            body.trim()
        )));
    }
    let body: PairCodeResponseBody = resp
        .json()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?;
    let rendezvous = hex::decode(body.rendezvous.trim())
        .map_err(|e| Error::Overlay(format!("pair-code rendezvous id: {e}")))?;
    let relay_id = parse_id(&body.relay_id)?;
    let code = PairCode::new(rendezvous, body.relay.clone(), relay_id, body.expires_at)
        .map_err(|e| Error::Overlay(format!("assembling pairing code: {e}")))?
        .encode()
        .map_err(|e| Error::Overlay(format!("encoding pairing code: {e}")))?;
    Ok(OverlayOutput::PairCodeMinted {
        code,
        relay: body.relay,
        relay_id: body.relay_id,
        expires_at: body.expires_at,
        short_code: body.short_code,
        park_cap: body.park_cap,
    })
}

/// `GET /api/overlay/pair-relay` response (CLI mirror of the server type).
#[derive(serde::Deserialize)]
struct PairRelayResponseBody {
    relay: String,
    relay_id: String,
}

/// Fetch this cluster's pairing ingress-relay topology (self-serve `overlay pair --short <code>`).
/// UNAUTHENTICATED at the control plane (no RBAC right — the short-code dialer has no credential at
/// all yet); the route still sits behind the auth middleware's bare-bearer-PRESENCE check (exactly
/// like `/api/overlay/enroll`), so an EMPTY placeholder bearer is presented — never verified for this
/// exempted path.
async fn fetch_pair_relay(
    server: Option<String>,
    config: &crate::config::ProjectConfig,
) -> Result<(std::net::SocketAddr, OverlayId)> {
    let server =
        crate::client::resolve_server(server, config).map_err(|e| Error::Overlay(e.to_string()))?;
    let http = crate::client::http_client(Some(""));
    let resp = http
        .get(format!("{server}/api/overlay/pair-relay"))
        .send()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Overlay(format!(
            "overlay pair-relay lookup refused ({}): {}",
            status.as_u16(),
            body.trim()
        )));
    }
    let body: PairRelayResponseBody = resp
        .json()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?;
    let addr = body
        .relay
        .parse::<std::net::SocketAddr>()
        .map_err(|e| Error::Overlay(format!("pair-relay address `{}`: {e}", body.relay)))?;
    let relay_id = parse_id(&body.relay_id)?;
    Ok((addr, relay_id))
}

/// Gather the operator's confirmation of the derived `sas`, fail-closed.
///
/// `--expect` (the SAS words shown on the PEER device) is the non-interactive path: present, it is
/// compared directly ([`decide_sas`]) and no prompt is shown. Absent, an interactive TTY is
/// required — a non-TTY stdin with no `--expect` is an error (never a default-yes on a pipe). On a
/// TTY we show the SAS + peer identity on stderr (stdout stays the typed result) and read the SAS
/// words the operator sees on the PEER device, then compare.
fn confirm_sas(
    sas: &SasCode,
    peer_id: &OverlayId,
    fp: &boatramp_overlay::Fingerprint,
    expect: Option<&str>,
) -> Result<ConfirmOutcome> {
    if let Some(words) = expect {
        return Ok(decide_sas(sas, words));
    }

    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(Error::Overlay(
            "pairing needs confirmation: pass `--expect <sas-words>` (the SAS shown on the peer \
             device) for non-interactive use — stdin is not a terminal"
                .into(),
        ));
    }

    // Interactive: show the SAS on stderr (stdout stays the typed result) and read the operator's
    // answer — the SAS words shown on the OTHER device.
    use std::io::Write as _;
    let mut err = std::io::stderr();
    writeln!(err).ok();
    writeln!(err, "Pairing with overlay peer:").ok();
    writeln!(err, "  identity:    {}", peer_id.to_hex()).ok();
    writeln!(err, "  fingerprint: {fp}").ok();
    writeln!(err, "  SAS words:   {}", sas.words()).ok();
    writeln!(err, "  SAS digits:  {}", sas.digits()).ok();
    writeln!(err).ok();
    writeln!(
        err,
        "Compare the SAS with the peer's device — it MUST match on BOTH sides."
    )
    .ok();
    write!(
        err,
        "To confirm, type the SAS words shown on the PEER device (anything else aborts): "
    )
    .ok();
    err.flush().ok();

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::Overlay(format!("reading confirmation: {e}")))?;
    Ok(decide_sas(sas, line.trim()))
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

/// Unix seconds now (the `mint`/`forward` time source), `0` before the epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a single-use `overlay-enroll` invitation for `role` + `scope`, signed offline by the root
/// signer resolved from `config` (the same cluster root key as `token`/`grant`). Returns the
/// invitation, the signer's PUBLIC key (the trust root the enrollee verifies it against), and its
/// expiry.
async fn mint_enroll(
    role: OverlayMemberRole,
    scope: &str,
    ttl_secs: u64,
    config: &std::path::Path,
) -> Result<(String, String, u64)> {
    let signer = crate::token::resolve_signer(config)
        .await
        .map_err(|e| Error::Signer(e.to_string()))?;
    let trust_root = signer.public_key().to_hex();
    let now = now_secs();
    let token = mint_overlay_enroll(role, scope, ttl_secs, now, &*signer)
        .await
        .map_err(|e| Error::Overlay(format!("minting enrollment invitation: {e}")))?;
    Ok((token, trust_root, now.saturating_add(ttl_secs)))
}

/// Load the overlay identity to enroll: a tagged seed (`ed25519:<hex>`) or a path to a key file,
/// else (none) this operator's persistent load-or-generate identity (as `overlay id` uses).
fn load_identity(spec: Option<&str>) -> Result<OverlaySecret> {
    match spec {
        None => operator_identity(),
        Some(s) => {
            let s = s.trim();
            // A tagged seed given directly?
            if let Ok(secret) = OverlaySecret::from_seed_hex(s) {
                return Ok(secret);
            }
            // Else a path to a key file (one seed line, like the operator key file).
            let seed =
                std::fs::read_to_string(s).map_err(|e| Error::Overlay(format!("{s}: {e}")))?;
            OverlaySecret::from_seed_hex(seed.trim())
                .map_err(|e| Error::Overlay(format!("{s}: {e}")))
        }
    }
}

/// `POST /api/overlay/enroll` request/response (CLI mirror of the server types).
#[derive(serde::Serialize)]
struct EnrollRequestBody {
    token: String,
    overlay_pubkey: String,
    possession_proof: String,
    proof_iat: u64,
}

#[derive(serde::Deserialize)]
struct EnrollResponseBody {
    member: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    expires_at: u64,
}

/// Redeem an overlay-enroll invitation at the control plane's `POST /api/overlay/enroll`, presenting
/// the invitation itself as the bearer (the route is token-gated — no RBAC right — and the handler
/// verifies the invitation, exactly as the cluster joiner presents its join token). The server pin
/// (`BOATRAMP_SERVER_PUBKEY`) still applies.
async fn redeem_enroll(
    server: Option<String>,
    config: &crate::config::ProjectConfig,
    token: &str,
    overlay_pubkey: &str,
    possession_proof: &str,
    proof_iat: u64,
) -> Result<EnrollResponseBody> {
    let server =
        crate::client::resolve_server(server, config).map_err(|e| Error::Overlay(e.to_string()))?;
    let http = crate::client::http_client(Some(token));
    let resp = http
        .post(format!("{server}/api/overlay/enroll"))
        .json(&EnrollRequestBody {
            token: token.to_string(),
            overlay_pubkey: overlay_pubkey.to_string(),
            possession_proof: possession_proof.to_string(),
            proof_iat,
        })
        .send()
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Overlay(format!(
            "enroll refused ({}): {}",
            status.as_u16(),
            body.trim()
        )));
    }
    resp.json().await.map_err(|e| Error::Overlay(e.to_string()))
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

/// `POST /api/overlay/expose` request/response (CLI mirror of the server types) — the self-serve
/// reverse-ingress publish path (`boatramp expose --server`).
#[derive(serde::Serialize)]
pub(crate) struct ExposeRequestBody {
    pub service: String,
    pub holder_pubkey: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct ExposeResponseBody {
    pub relay: String,
    pub relay_id: String,
    pub service: String,
    pub token: String,
    /// The cluster trust root's PUBLIC key — the exposer verifies incoming forward clients' dial
    /// capabilities against it (zero-trust terminator).
    pub trust_root: String,
    /// The relay's client-auth posture ("capability-only" | "mutual-pin"); selects the exposer's TLS
    /// posture when dialing OUT (capability-only ⇒ present no client cert).
    #[serde(default)]
    pub relay_client_auth: String,
}

/// The `POST /api/overlay/policy/test` request body (mirrors the server's `OverlayPolicyTestRequest`).
#[derive(serde::Serialize)]
struct FlowPolicyTestRequest {
    action: String,
    service: String,
    holder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrolled: Option<bool>,
    ttl_requested: u64,
}

/// The `POST /api/overlay/policy/test` response (mirrors the server's `OverlayPolicyTestResponse`).
#[derive(serde::Deserialize)]
struct FlowPolicyTestResponse {
    decision: String,
    ttl_ceiling: Option<u64>,
    #[serde(default)]
    deciding_policies: Vec<String>,
    #[serde(default)]
    diagnostics: Vec<String>,
    #[serde(default)]
    note: Option<String>,
}

/// The `PUT /api/overlay/policy` response (mirrors the server's `OverlayPolicyPutResponse`).
#[derive(serde::Deserialize)]
struct FlowPolicyPutResponse {
    version: String,
    #[serde(default)]
    warning: Option<String>,
}

/// Run an `overlay policy …` command (the `System·Admin`-gated flow-policy administration).
async fn policy_run(
    cmd: PolicyCommand,
    config: &crate::config::ProjectConfig,
) -> Result<OverlayOutput> {
    match cmd {
        PolicyCommand::Ls { server } => {
            let (server, http) = crate::client::connect(server, config)
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let resp = http
                .get(format!("{server}/api/overlay/policy"))
                .send()
                .await
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let version = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default();
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(Error::Overlay(format!(
                    "overlay policy ls refused ({}): {}",
                    status.as_u16(),
                    body.trim()
                )));
            }
            Ok(OverlayOutput::FlowPolicy {
                policy: body,
                version,
            })
        }
        PolicyCommand::Set {
            file,
            if_match,
            server,
        } => {
            // Read the policy from a file, or stdin for `-`.
            let policy = if file == "-" {
                use std::io::Read as _;
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .map_err(|e| Error::Overlay(format!("reading policy from stdin: {e}")))?;
                buf
            } else {
                std::fs::read_to_string(&file)
                    .map_err(|e| Error::Overlay(format!("reading policy file `{file}`: {e}")))?
            };
            let (server, http) = crate::client::connect(server, config)
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let mut req = http
                .put(format!("{server}/api/overlay/policy"))
                .header("content-type", "text/plain")
                .body(policy.clone());
            if let Some(m) = &if_match {
                req = req.header("if-match", m);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                // A 400 carries the server's verbatim validation message; surface it as-is.
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::Overlay(format!(
                    "overlay policy set refused ({}): {}",
                    status.as_u16(),
                    body.trim()
                )));
            }
            let parsed: FlowPolicyPutResponse = resp
                .json()
                .await
                .map_err(|e| Error::Overlay(e.to_string()))?;
            Ok(OverlayOutput::FlowPolicyStored {
                version: parsed.version,
                warning: parsed.warning,
                cleared: policy.trim().is_empty(),
            })
        }
        PolicyCommand::Test {
            action,
            service,
            holder,
            role,
            scope,
            enrolled,
            ttl_secs,
            server,
        } => {
            // Default the holder to this operator's overlay identity (as `overlay id` prints).
            let holder = match holder {
                Some(h) => parse_id(&h)?.to_hex(),
                None => operator_identity()?.id().to_hex(),
            };
            let (server, http) = crate::client::connect(server, config)
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let resp = http
                .post(format!("{server}/api/overlay/policy/test"))
                .json(&FlowPolicyTestRequest {
                    action,
                    service,
                    holder,
                    role,
                    scope,
                    // A bare flag can only express "enrolled" (true); absent ⇒ key-only (None).
                    enrolled: enrolled.then_some(true),
                    ttl_requested: ttl_secs,
                })
                .send()
                .await
                .map_err(|e| Error::Overlay(e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::Overlay(format!(
                    "overlay policy test refused ({}): {}",
                    status.as_u16(),
                    body.trim()
                )));
            }
            let parsed: FlowPolicyTestResponse = resp
                .json()
                .await
                .map_err(|e| Error::Overlay(e.to_string()))?;
            Ok(OverlayOutput::FlowPolicyTest {
                decision: parsed.decision,
                ttl_ceiling: parsed.ttl_ceiling,
                deciding_policies: parsed.deciding_policies,
                diagnostics: parsed.diagnostics,
                note: parsed.note,
            })
        }
    }
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

    #[test]
    fn enroll_ticket_round_trips() {
        let t = EnrollTicket {
            token: "ENROLLCOSE".into(),
            trust_root: "ed25519:root".into(),
            role: "device".into(),
            scope: "svc/db".into(),
            relay: Some("ed25519:relay".into()),
        };
        let blob = t.encode().unwrap();
        assert!(blob.starts_with("brojoin1."));
        let back = EnrollTicket::decode(&blob).unwrap();
        assert_eq!(back.token, "ENROLLCOSE");
        assert_eq!(back.trust_root, "ed25519:root");
        assert_eq!(back.role, "device");
        assert_eq!(back.scope, "svc/db");
        assert_eq!(back.relay.as_deref(), Some("ed25519:relay"));
    }

    #[test]
    fn decide_sas_confirms_only_a_full_matching_code() {
        // bits [0,1,255] → "acorn-admiral-igloo" (see the proto SAS stability test).
        let sas = SasCode::from_words("acorn-admiral-igloo").unwrap();
        // An exact match confirms; case- and separator-insensitive via from_words.
        assert_eq!(
            decide_sas(&sas, "acorn-admiral-igloo"),
            ConfirmOutcome::Confirm
        );
        assert_eq!(
            decide_sas(&sas, "ACORN ADMIRAL IGLOO"),
            ConfirmOutcome::Confirm
        );
        // One word off → reject (the MITM case: --expect carries the peer's DIFFERING code).
        assert_eq!(
            decide_sas(&sas, "acorn-admiral-icon"),
            ConfirmOutcome::Reject
        );
        // Unparseable / empty / partial → reject (never a default-yes).
        assert_eq!(decide_sas(&sas, "yes"), ConfirmOutcome::Reject);
        assert_eq!(decide_sas(&sas, ""), ConfirmOutcome::Reject);
        assert_eq!(decide_sas(&sas, "acorn-admiral"), ConfirmOutcome::Reject);
    }

    #[test]
    fn enroll_ticket_rejects_garbage_and_other_tickets() {
        assert!(EnrollTicket::decode("not-a-ticket").is_err());
        assert!(EnrollTicket::decode("brojoin1.@@@@").is_err());
        // A forward ticket is not an enrollment ticket (distinct magic).
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
        assert!(EnrollTicket::decode(&fwd).is_err());
        // Missing the required trust_root is refused.
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            b"{\"token\":\"t\",\"trust_root\":\"\",\"role\":\"device\",\"scope\":\"svc/db\"}",
        );
        assert!(EnrollTicket::decode(&format!("brojoin1.{bad}")).is_err());
    }
}
