//! The `expose` subcommand (overlay follow-up #4): a native overlay **reverse ingress**.
//!
//! `boatramp expose <local-addr> as svc/<name>` publishes a LOCAL service INTO the cluster overlay —
//! the reverse of `forward`. The exposer dials the relay OUTBOUND (so a NAT'd / undialable service
//! can still be published), registers under a holder-bound overlay-publish capability, and holds the
//! connection open; a cluster-side `boatramp forward svc/<name>` then reaches it, the relay opening a
//! per-flow stream down the parked connection and bridging it, blind. E2EE stays end-to-end
//! forward-client↔exposer (the exposer is the terminator), so the exposer independently authorizes
//! each incoming client's dial capability against the cluster trust root — zero-trust, exactly like an
//! in-cluster egress. Reverse flows pin `PathMode::Relay` (a NAT'd exposer is undialable).
//!
//! Increment 1 is explicit-flag + `--ticket` only (from `boatramp overlay grant-expose`); the
//! self-serve `POST /api/overlay/expose` discovery path is a later increment.

use std::net::SocketAddr;
use std::path::PathBuf;

use boatramp_core::cose::{TokenPublicKey, verify_overlay_publish};
use boatramp_overlay::{
    OverlayId, OverlayPeerPolicy, OverlaySecret, RegisterReject, client_endpoint,
    client_endpoint_server_auth, run_published_service,
};
use clap::Args;

/// Arguments for `boatramp expose`.
///
/// `boatramp expose 127.0.0.1:5432 as svc/db --ticket <blob>` is the common case (the `as` literal is
/// optional sugar). A `--ticket` from `boatramp overlay grant-expose`, or the explicit relay flags,
/// supply the topology + the holder-bound publish capability + the cluster trust root.
#[derive(Args, Debug)]
pub struct ExposeArgs {
    /// The LOCAL service address to publish (e.g. `127.0.0.1:5432`) — what the exposer connects to
    /// for each inbound flow.
    pub local: String,
    /// The in-cluster service name to publish AS (e.g. `svc/db`), optionally preceded by the literal
    /// `as`. Optional with `--ticket` (the ticket's service wins); if both are given they must match.
    #[arg(num_args = 0..=2)]
    pub service: Vec<String>,
    /// An expose ticket (`brexp1.…`) from `boatramp overlay grant-expose` — the one-flag path.
    #[arg(long, conflicts_with_all = ["relay", "relay_id", "token", "token_file", "trust_root"])]
    pub ticket: Option<String>,
    /// The cluster relay/ingress socket address to dial OUT to (explicit escape hatch).
    #[arg(long)]
    pub relay: Option<SocketAddr>,
    /// The relay's overlay identity to pin (`bro1…` or `ed25519:<hex>`).
    #[arg(long)]
    pub relay_id: Option<String>,
    /// The overlay-publish capability token (COSE), holder-bound to this exposer's identity.
    #[arg(long, conflicts_with = "token_file")]
    pub token: Option<String>,
    /// Read the publish token from a file instead of `--token`.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// The cluster trust root's PUBLIC key (`ed25519:`/`es256:` tagged hex) — the exposer verifies
    /// each incoming forward client's dial capability against it (zero-trust terminator). Carried by a
    /// `--ticket`; required with the explicit flags.
    #[arg(long)]
    pub trust_root: Option<String>,
    /// This exposer's overlay identity seed — `ed25519:<hex>` inline, or a path to a file holding it.
    /// Optional with a convenience `--ticket` (which carries the identity); required otherwise and
    /// with a `--holder-pub` ticket. Its public half MUST equal the publish capability's holder.
    #[arg(long)]
    pub identity: Option<String>,
    /// Dial the relay server-auth-only (present NO client certificate) — for a **capability-only**
    /// relay, where the registration's E2EE handshake (not a TLS pin) proves the exposer's identity.
    /// The common expose case (a NAT'd exposer needs no pre-enrollment). Omit for a mutual-pin relay
    /// (the exposer presents its cert and must be in the relay's `allowed_clients`). Ignored on
    /// self-serve (the posture is taken from the control plane).
    #[arg(long)]
    pub capability_only: bool,
    /// boatramp server base URL for self-serve resolution (overrides `[publish].server`). With
    /// neither `--ticket` nor `--relay`, `boatramp expose <local> as svc/<name>` resolves the relay
    /// topology + mints the publish capability over the control plane (`POST /api/overlay/expose`,
    /// `Overlay·Admin`), authenticated by your boatramp token — zero hand-typed topology.
    #[arg(long, env = "BOATRAMP_SERVER")]
    pub server: Option<String>,
}

/// An `expose` failure.
#[derive(Debug, thiserror::Error)]
pub enum ExposeError {
    #[error("connect / accept: {0}")]
    Io(#[from] std::io::Error),
    #[error("overlay identity: {0}")]
    Identity(#[from] boatramp_overlay::OverlayIdError),
    #[error("overlay transport: {0}")]
    Quic(#[from] boatramp_overlay::QuicError),
    #[error("no publish token — pass --token or --token-file")]
    NoToken,
    #[error(
        "a target service is required — pass it as `expose <local> as svc/<name>` or use --ticket"
    )]
    NoTarget,
    #[error("an overlay identity is required — pass --identity (this ticket carries none)")]
    NoIdentity,
    #[error(
        "relay connection details are required — pass --relay/--relay-id/--trust-root or --ticket"
    )]
    NoRelay,
    #[error(
        "the cluster trust root is required — pass --trust-root (or use a --ticket, which carries it)"
    )]
    NoTrustRoot,
    #[error("expose ticket: {0}")]
    Ticket(String),
    #[error("--service `{arg}` does not match the ticket's service `{ticket}`")]
    TicketServiceMismatch { ticket: String, arg: String },
    /// The service name `svc/<name>` is already published by a live exposer (first-live-claim-wins).
    #[error(
        "the service `{0}` is already published by another live exposer — names are \
         first-live-claim-wins; stop the other exposer or publish under a different name"
    )]
    NameTaken(String),
    /// The publish capability is expired (caught locally before dialing).
    #[error(
        "your overlay-publish capability has expired — ask an admin to mint a fresh one with \
         `boatramp overlay grant-expose`"
    )]
    CapExpired,
    /// The relay could not be reached (dial failed before registration).
    #[error("the relay `{relay}` is unreachable: {cause}")]
    RelayUnreachable { relay: SocketAddr, cause: String },
    /// The relay refused the registration for a reason other than name-collision.
    #[error("the relay refused the registration: {0}")]
    RegistrationRejected(String),
    /// The exposer's identity does not match the publish capability's holder (caught locally).
    #[error(
        "your --identity does not match the publish capability's holder — the capability was minted \
         for a different exposer key (mint one for this identity, or use the matching --identity)"
    )]
    HolderMismatch,
    /// Verifying the publish capability locally (before dialing) failed for another reason.
    #[error("the publish capability is not valid: {0}")]
    InvalidCapability(String),
    /// Parsing the supplied trust root failed.
    #[error("trust root `{spec}`: {cause}")]
    BadTrustRoot { spec: String, cause: String },
    /// Self-serve discovery (resolve + mint over the control plane) failed for a non-auth reason.
    #[error("overlay discovery: {0}")]
    Discovery(String),
    /// 401 from the control plane — authentication, not authorization. The message names the REAL
    /// auth mechanism (the operator's boatramp token), never a phantom command.
    #[error(
        "your boatramp token is missing, invalid, or expired — set a valid, unexpired token in \
         `BOATRAMP_TOKEN` or `[publish].token` (ask an admin to mint one if needed) and try again."
    )]
    Unauthenticated,
    /// 403 from the control plane — authenticated but lacks `Overlay·Admin` (publish is strictly above
    /// dial's `Overlay·Write`). Kept actionable: name the right + the control-plane-less fallback.
    #[error(
        "not authorized to self-serve overlay EXPOSE — publishing a service claims a name others \
         trust, so it needs the `Overlay·Admin` right (strictly above dial's `Overlay·Write`).\n  \
         Ask an admin to grant you `Overlay·Admin`, or use a `--ticket` from \
         `boatramp overlay grant-expose` for a control-plane-less expose."
    )]
    Unauthorized,
}

/// Parse an overlay identity given as bech32 (`bro1…`) or canonical hex (`ed25519:<hex>`).
fn parse_id(s: &str) -> Result<OverlayId, ExposeError> {
    if let Ok(id) = OverlayId::from_bech32(s) {
        return Ok(id);
    }
    Ok(OverlayId::from_hex(s)?)
}

/// Load the exposer's identity secret from an inline `ed25519:<hex>` seed or a file path.
fn load_identity(spec: &str) -> Result<OverlaySecret, ExposeError> {
    let seed = if spec.starts_with("ed25519:") {
        spec.to_string()
    } else {
        std::fs::read_to_string(spec)?.trim().to_string()
    };
    Ok(OverlaySecret::from_seed_hex(&seed)?)
}

/// Resolve the positional service argument: `svc/<name>`, optionally preceded by the literal `as`.
fn resolve_service_arg(service: &[String]) -> Option<String> {
    match service {
        [s] if s != "as" => Some(s.clone()),
        [a, s] if a == "as" => Some(s.clone()),
        _ => None,
    }
}

fn load_token(args: &ExposeArgs) -> Result<String, ExposeError> {
    if let Some(t) = &args.token {
        return Ok(t.clone());
    }
    if let Some(path) = &args.token_file {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    Err(ExposeError::NoToken)
}

/// The fully-resolved inputs an expose needs, from a ticket or the explicit flags.
struct ResolvedExpose {
    relay: SocketAddr,
    relay_id: String,
    service: String,
    token: String,
    trust_root: String,
    identity: String,
    /// `true` ⇒ dial the relay server-auth-only (capability-only relay).
    capability_only: bool,
}

/// Resolve the connection parameters from a `--ticket` (the common case) or the explicit flags.
fn resolve_params(args: &ExposeArgs) -> Result<ResolvedExpose, ExposeError> {
    let arg_service = resolve_service_arg(&args.service);
    if let Some(blob) = &args.ticket {
        let t = crate::overlay::ExposeTicket::decode(blob)
            .map_err(|e| ExposeError::Ticket(e.to_string()))?;
        if let Some(tg) = &arg_service
            && tg != &t.service
        {
            return Err(ExposeError::TicketServiceMismatch {
                ticket: t.service,
                arg: tg.clone(),
            });
        }
        let identity = args
            .identity
            .clone()
            .or(t.identity)
            .ok_or(ExposeError::NoIdentity)?;
        let relay = t
            .relay
            .parse::<SocketAddr>()
            .map_err(|_| ExposeError::Ticket(format!("bad relay address `{}`", t.relay)))?;
        Ok(ResolvedExpose {
            relay,
            relay_id: t.relay_id,
            service: t.service,
            token: t.token,
            trust_root: t.trust_root,
            identity,
            capability_only: args.capability_only,
        })
    } else {
        let service = arg_service.ok_or(ExposeError::NoTarget)?;
        let token = load_token(args)?;
        let identity = args.identity.clone().ok_or(ExposeError::NoIdentity)?;
        let relay = args.relay.ok_or(ExposeError::NoRelay)?;
        let relay_id = args.relay_id.clone().ok_or(ExposeError::NoRelay)?;
        let trust_root = args.trust_root.clone().ok_or(ExposeError::NoTrustRoot)?;
        Ok(ResolvedExpose {
            relay,
            relay_id,
            service,
            token,
            trust_root,
            identity,
            capability_only: args.capability_only,
        })
    }
}

/// Self-serve resolution (mirrors `forward`'s `resolve_via_control_plane`): resolve this node's
/// ingress relay topology AND mint a holder-bound overlay-PUBLISH capability over the control plane,
/// authenticated by the operator's own boatramp token + persistent overlay identity. This is the
/// headline `boatramp expose <local> as svc/<name>` path — zero hand-typed topology, and no per-expose
/// ticket once the operator's token carries `Overlay·Admin`.
async fn resolve_via_control_plane(
    args: &ExposeArgs,
    config: &crate::config::ProjectConfig,
) -> Result<ResolvedExpose, ExposeError> {
    let service = resolve_service_arg(&args.service).ok_or(ExposeError::NoTarget)?;
    // The operator's persistent overlay identity — the SAME key `forward` self-serve uses. The publish
    // capability is minted holder-bound to THIS identity, which the exposer then registers with.
    let secret =
        crate::overlay::operator_identity().map_err(|e| ExposeError::Discovery(e.to_string()))?;
    let holder_pubkey = secret.id().to_hex();
    let (server, http) = crate::client::connect(args.server.clone(), config)
        .map_err(|e| ExposeError::Discovery(e.to_string()))?;
    let resp = http
        .post(format!("{server}/api/overlay/expose"))
        .json(&crate::overlay::ExposeRequestBody {
            service: service.clone(),
            holder_pubkey,
        })
        .send()
        .await
        .map_err(|e| ExposeError::Discovery(e.to_string()))?;
    // Split 401 (authentication — fix your token) vs 403 (missing `Overlay·Admin` — ask an admin /
    // use a ticket), mirroring forward; any other non-success carries the server's actionable body.
    let status = resp.status();
    if status.as_u16() == 401 {
        return Err(ExposeError::Unauthenticated);
    }
    if status.as_u16() == 403 {
        return Err(ExposeError::Unauthorized);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let body = body.trim();
        return Err(ExposeError::Discovery(if body.is_empty() {
            format!("control plane returned {status} exposing `{service}`")
        } else {
            format!("control plane returned {status} exposing `{service}`: {body}")
        }));
    }
    let resp: crate::overlay::ExposeResponseBody = resp
        .json()
        .await
        .map_err(|e| ExposeError::Discovery(e.to_string()))?;
    // On self-serve the server's posture is authoritative; a passed `--capability-only` is ignored —
    // say so rather than silently dropping it (mirrors forward finding E).
    if args.capability_only {
        eprintln!(
            "boatramp expose: --capability-only ignored on self-serve; posture is taken from the \
             control plane"
        );
    }
    let relay = resp
        .relay
        .parse::<SocketAddr>()
        .map_err(|_| ExposeError::Discovery(format!("bad relay address `{}`", resp.relay)))?;
    Ok(ResolvedExpose {
        relay,
        relay_id: resp.relay_id,
        service: resp.service, // authoritative (equals the publish capability's scope)
        token: resp.token,
        trust_root: resp.trust_root,
        identity: secret.seed_hex().to_string(),
        // The relay told us its posture; a capability-only relay is server-auth-only at TLS.
        capability_only: resp.relay_client_auth == "capability-only",
    })
}

/// Current unix time (seconds).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A LOCAL preflight (before any network): verify the publish capability against the trust root and
/// confirm it is for this service + this identity, so an expired / wrong-service / wrong-identity
/// capability fails LOUDLY and immediately rather than as a confusing relay rejection. Mirrors
/// `forward`'s eager preflight intent.
fn preflight_capability(
    publish_cap: &str,
    trust_root: &TokenPublicKey,
    service: &str,
    exposer_id: &OverlayId,
) -> Result<(), ExposeError> {
    let verified = match verify_overlay_publish(publish_cap, trust_root, now_unix()) {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            return Err(if msg.to_lowercase().contains("expir") {
                ExposeError::CapExpired
            } else {
                ExposeError::InvalidCapability(msg)
            });
        }
    };
    if verified.scope != service {
        return Err(ExposeError::RegistrationRejected(format!(
            "the publish capability authorizes `{}`, not `{service}`",
            verified.scope
        )));
    }
    if verified.holder != exposer_id.to_hex() {
        return Err(ExposeError::HolderMismatch);
    }
    Ok(())
}

/// Map a reverse-ingress `NetError` from `run_published_service` into an actionable `ExposeError`.
fn map_net_error(relay: SocketAddr, e: boatramp_overlay::NetError) -> ExposeError {
    use boatramp_overlay::NetError;
    match e {
        NetError::RegistrationRejected(RegisterReject::NameTaken) => {
            ExposeError::NameTaken(String::new()) // service filled by the caller
        }
        NetError::RegistrationRejected(RegisterReject::InvalidCapability(m)) => {
            if m.to_lowercase().contains("expir") {
                ExposeError::CapExpired
            } else {
                ExposeError::RegistrationRejected(format!("invalid publish capability: {m}"))
            }
        }
        NetError::RegistrationRejected(RegisterReject::ScopeMismatch) => {
            ExposeError::RegistrationRejected(
                "the capability scope does not match the service".into(),
            )
        }
        NetError::RegistrationRejected(RegisterReject::HolderMismatch) => {
            ExposeError::HolderMismatch
        }
        NetError::Quic(q) => ExposeError::RelayUnreachable {
            relay,
            cause: q.to_string(),
        },
        NetError::Connection(c) => ExposeError::RelayUnreachable {
            relay,
            cause: c.to_string(),
        },
        other => ExposeError::RegistrationRejected(other.to_string()),
    }
}

/// Run the exposer until interrupted (or the relay connection drops).
pub async fn run(
    args: ExposeArgs,
    config: &crate::config::ProjectConfig,
) -> Result<(), ExposeError> {
    // Precedence (mirrors `forward`): an explicit `--ticket` or `--relay` is the control-plane-less
    // escape hatch; otherwise `expose <local> as svc/<name>` self-serves through the control plane
    // (resolve the ingress relay + mint the publish capability, authenticated by the operator token).
    let resolved = if args.ticket.is_some() || args.relay.is_some() {
        resolve_params(&args)?
    } else {
        resolve_via_control_plane(&args, config).await?
    };
    let ResolvedExpose {
        relay,
        relay_id: relay_id_spec,
        service,
        token,
        trust_root: trust_root_spec,
        identity: identity_spec,
        capability_only,
    } = resolved;

    let secret = load_identity(&identity_spec)?;
    let relay_id = parse_id(&relay_id_spec)?;
    let trust_root =
        TokenPublicKey::from_hex(&trust_root_spec).map_err(|e| ExposeError::BadTrustRoot {
            spec: trust_root_spec.clone(),
            cause: e.to_string(),
        })?;

    // The LOCAL service address to publish — what the exposer connects to per inbound flow.
    let local: SocketAddr = args.local.parse().map_err(|_| {
        ExposeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "`{}` is not a valid host:port local service address",
                args.local
            ),
        ))
    })?;

    // Eager LOCAL preflight — fail loudly on an expired / wrong-service / wrong-identity capability
    // before any network round-trip or the "published" banner.
    preflight_capability(&token, &trust_root, &service, &secret.id())?;

    // One dial-only endpoint pinning the relay. Capability-only ⇒ present NO client cert (the relay is
    // AcceptAny at TLS; the registration handshake proves our identity). Mutual-pin ⇒ present our cert.
    let endpoint = if capability_only {
        client_endpoint_server_auth(&OverlayPeerPolicy::Pin(relay_id))?
    } else {
        client_endpoint(&secret, &OverlayPeerPolicy::Pin(relay_id))?
    };

    let service_for_backend = service.clone();
    let service_banner = service.clone();
    let resolve_backend = move |s: &str| (s == service_for_backend.as_str()).then_some(local);

    // `run_published_service` dials + registers, fires `ready` (the banner) ONLY after a confirmed
    // registration, then serves each inbound flow until the relay connection drops.
    let ready = move || {
        eprintln!(
            "boatramp expose: {local} published as {service_banner} via relay {relay} (overlay, \
             relay-blind E2EE) — ready, Ctrl-C to stop"
        );
    };
    let outcome = run_published_service(
        &endpoint,
        relay,
        relay_id,
        &secret,
        service.clone(),
        token,
        resolve_backend,
        trust_root,
        true,
        ready,
    )
    .await;

    outcome.map_err(|e| match map_net_error(relay, e) {
        // Fill in the service name for a name-collision (map_net_error can't see it).
        ExposeError::NameTaken(_) => ExposeError::NameTaken(service),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ExposeArgs,
    }

    #[test]
    fn parses_expose_args_with_as_literal() {
        let w = Wrap::try_parse_from([
            "expose",
            "127.0.0.1:5432",
            "as",
            "svc/db",
            "--relay",
            "10.0.0.1:9000",
            "--relay-id",
            "bro1qqqq",
            "--token",
            "abc",
            "--trust-root",
            "ed25519:00",
            "--identity",
            "ed25519:1111",
            "--capability-only",
        ])
        .unwrap();
        assert_eq!(w.args.local, "127.0.0.1:5432");
        assert_eq!(
            resolve_service_arg(&w.args.service).as_deref(),
            Some("svc/db")
        );
        assert!(w.args.capability_only);
    }

    #[test]
    fn parses_expose_args_without_as_literal() {
        let w =
            Wrap::try_parse_from(["expose", "127.0.0.1:5432", "svc/db", "--ticket", "brexp1.x"])
                .unwrap();
        assert_eq!(
            resolve_service_arg(&w.args.service).as_deref(),
            Some("svc/db")
        );
    }

    #[test]
    fn ticket_conflicts_with_explicit_flags() {
        let r = Wrap::try_parse_from([
            "expose",
            "127.0.0.1:5432",
            "svc/db",
            "--ticket",
            "brexp1.xx",
            "--relay",
            "1.1.1.1:1",
        ]);
        assert!(r.is_err(), "--ticket and --relay must conflict");
    }

    /// The common case: a single `--ticket`, no other flags, and a bare local address — the ticket's
    /// service/trust-root/identity are authoritative.
    #[test]
    fn resolves_from_a_ticket() {
        let ticket = crate::overlay::ExposeTicket {
            relay: "10.0.0.1:9100".into(),
            relay_id: "ed25519:aa".into(),
            service: "svc/db".into(),
            token: "PUBCOSE".into(),
            trust_root: "es256:beef".into(),
            identity: Some("ed25519:cc".into()),
        }
        .encode()
        .unwrap();
        let w = Wrap::try_parse_from(["expose", "127.0.0.1:5432", "--ticket", &ticket]).unwrap();
        let r = resolve_params(&w.args).unwrap();
        assert_eq!(r.relay.to_string(), "10.0.0.1:9100");
        assert_eq!(r.service, "svc/db");
        assert_eq!(r.token, "PUBCOSE");
        assert_eq!(r.trust_root, "es256:beef");
        assert_eq!(r.identity, "ed25519:cc");
        assert!(!r.capability_only);
    }

    /// A positional `--service` that disagrees with the ticket's service is refused.
    #[test]
    fn ticket_service_mismatch_is_rejected() {
        let ticket = crate::overlay::ExposeTicket {
            relay: "10.0.0.1:9100".into(),
            relay_id: "ed25519:aa".into(),
            service: "svc/db".into(),
            token: "PUBCOSE".into(),
            trust_root: "es256:beef".into(),
            identity: Some("ed25519:cc".into()),
        }
        .encode()
        .unwrap();
        let w =
            Wrap::try_parse_from(["expose", "127.0.0.1:5432", "svc/other", "--ticket", &ticket])
                .unwrap();
        assert!(matches!(
            resolve_params(&w.args),
            Err(ExposeError::TicketServiceMismatch { .. })
        ));
    }

    /// The local preflight catches a wrong-holder publish capability before any network round-trip.
    #[tokio::test]
    async fn preflight_rejects_a_wrong_holder_capability() {
        use boatramp_core::cose::{LocalSigner, TokenAlg, mint_overlay_publish};

        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = {
            use boatramp_core::cose::Signer;
            root.public_key()
        };
        let holder = OverlaySecret::generate().unwrap();
        let other = OverlaySecret::generate().unwrap();
        let cap = mint_overlay_publish(&holder.id().to_public(), "svc/db", 3600, now_unix(), &root)
            .await
            .unwrap();
        // `other` (not the holder) runs the preflight → HolderMismatch.
        assert!(matches!(
            preflight_capability(&cap, &root_pub, "svc/db", &other.id()),
            Err(ExposeError::HolderMismatch)
        ));
        // Right holder, wrong service → RegistrationRejected (scope).
        assert!(matches!(
            preflight_capability(&cap, &root_pub, "svc/other", &holder.id()),
            Err(ExposeError::RegistrationRejected(_))
        ));
        // Right holder + service → ok.
        assert!(preflight_capability(&cap, &root_pub, "svc/db", &holder.id()).is_ok());
    }
}
