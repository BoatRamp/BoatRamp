//! The `forward` subcommand (IU-10): a native overlay **client-edge**.
//!
//! `boatramp forward <local-addr> <cluster-target>` binds a local listener and, per accepted
//! connection, capability-gated-dials into the cluster — relay-blind E2EE to the in-cluster target
//! (egress) — and splices the socket over the overlay. Shaped like `ssh -L` / `kubectl
//! port-forward`; the basic tier is explicit per-port forwards, with no OS capture.
//!
//! This is the first NATIVE consumer of the overlay fabric — boatramp's own CLI exercises dial →
//! relay-blind E2EE → egress end to end. The headline path is **self-serve** (26.1 §7e discovery):
//! `boatramp forward 127.0.0.1:5432 svc/db` resolves the service's topology and mints the dial
//! capability through the control plane ([`resolve_via_control_plane`]), authenticated by the
//! operator's own boatramp token and bound to their persistent overlay identity — zero hand-typed
//! topology. A `--ticket` (from `overlay grant`) or the explicit relay/egress/token flags are the
//! control-plane-less escape hatches for airgapped or pre-provisioned deployments.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use boatramp_overlay::{
    DialRequest, OverlayId, OverlayPeerPolicy, OverlaySecret, PathMode, client_endpoint,
    client_endpoint_server_auth, forward_flow,
};
use clap::Args;
use tokio::net::TcpListener;

/// Arguments for `boatramp forward`.
///
/// The common case is just `boatramp forward <local> svc/<name>` — the operator self-serves via the
/// control plane (topology + dial capability resolved from their boatramp token). A `--ticket` from
/// `boatramp overlay grant`, or the explicit relay flags, are the control-plane-less escape hatches.
#[derive(Args, Debug)]
pub struct ForwardArgs {
    /// Local address to bind and forward (e.g. `127.0.0.1:5432`).
    pub local: String,
    /// The in-cluster service to reach (e.g. `svc/db`). Resolved via the control plane when no
    /// `--ticket`/explicit flags are given. Optional with `--ticket` (the ticket's service wins); if
    /// both are given they must match.
    pub target: Option<String>,
    /// A forward ticket (`brfwd1.…`) from `boatramp overlay grant` — a control-plane-less path.
    #[arg(long, conflicts_with_all = ["relay", "relay_id", "egress_id", "token", "token_file"])]
    pub ticket: Option<String>,
    /// boatramp server base URL for self-serve resolution (overrides `[publish].server`).
    #[arg(long, env = "BOATRAMP_SERVER")]
    pub server: Option<String>,
    /// The cluster relay/ingress socket address to dial (explicit escape hatch).
    #[arg(long)]
    pub relay: Option<SocketAddr>,
    /// The relay's overlay identity to pin (`bro1…` or `ed25519:<hex>`).
    #[arg(long)]
    pub relay_id: Option<String>,
    /// The egress/terminator's overlay identity to pin for the E2EE session.
    #[arg(long)]
    pub egress_id: Option<String>,
    /// The dial capability token (COSE), holder-bound to this client's identity.
    #[arg(long, conflicts_with = "token_file")]
    pub token: Option<String>,
    /// Read the dial token from a file instead of `--token`.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// This client's overlay identity seed — `ed25519:<hex>` inline, or a path to a file holding it.
    /// Optional with a convenience `--ticket` (which carries the identity); required otherwise and
    /// with a `--holder-pub` ticket.
    #[arg(long)]
    pub identity: Option<String>,
    /// Dial the relay server-auth-only (present NO client certificate) — for a **capability-only**
    /// relay reached via `--ticket`/explicit flags (where the egress is the authority). Self-serve
    /// learns the relay's posture from the control plane and sets this automatically.
    #[arg(long)]
    pub capability_only: bool,
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
    #[error("a target service is required — pass it as the second argument or use --ticket")]
    NoTarget,
    #[error("an overlay identity is required — pass --identity (this ticket carries none)")]
    NoIdentity,
    #[error(
        "relay connection details are required — pass --relay/--relay-id/--egress-id or --ticket"
    )]
    NoRelay,
    #[error("forward ticket: {0}")]
    Ticket(String),
    #[error("--target `{arg}` does not match the ticket's service `{ticket}`")]
    TicketServiceMismatch { ticket: String, arg: String },
    #[error("overlay discovery: {0}")]
    Discovery(String),
    #[error(
        "not authorized to self-serve overlay forwards — your boatramp token needs the \
         `Overlay·Write` right.\n  \
         Ask an admin to grant you an overlay role (e.g. a token minted with `--role overlay`), or \
         use a `--ticket` from `boatramp overlay grant` for a control-plane-less forward."
    )]
    Unauthorized,
}

impl From<crate::overlay::Error> for ForwardError {
    fn from(e: crate::overlay::Error) -> Self {
        Self::Discovery(e.to_string())
    }
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

/// The fully-resolved inputs a forward needs, from any source (self-serve, ticket, explicit flags).
struct ResolvedForward {
    relay: SocketAddr,
    relay_id: String,
    egress_id: String,
    service: String,
    token: String,
    identity: String,
    /// The relay's client-auth posture. `true` ⇒ **capability-only** relay: dial server-auth-only,
    /// presenting NO client cert (the relay accepts any key; the egress is the authority). `false` ⇒
    /// **mutual-pin** relay: present the client's RPK cert so the relay can pin it. Self-serve learns
    /// this from the control plane; ticket/explicit take it from `--capability-only` (default mutual).
    capability_only: bool,
}

/// Resolve the connection parameters from a `--ticket` (the common case) or the explicit flags.
fn resolve_params(args: &ForwardArgs) -> Result<ResolvedForward, ForwardError> {
    if let Some(blob) = &args.ticket {
        let t = crate::overlay::ForwardTicket::decode(blob)
            .map_err(|e| ForwardError::Ticket(e.to_string()))?;
        if let Some(tg) = &args.target
            && tg != &t.service
        {
            return Err(ForwardError::TicketServiceMismatch {
                ticket: t.service,
                arg: tg.clone(),
            });
        }
        // Identity: an explicit --identity wins; else the ticket's embedded seed (convenience
        // mode); a holder-pub ticket carries none, so --identity is then required.
        let identity = args
            .identity
            .clone()
            .or(t.identity)
            .ok_or(ForwardError::NoIdentity)?;
        let relay = t
            .relay
            .parse::<SocketAddr>()
            .map_err(|_| ForwardError::Ticket(format!("bad relay address `{}`", t.relay)))?;
        Ok(ResolvedForward {
            relay,
            relay_id: t.relay_id,
            egress_id: t.egress_id,
            service: t.service,
            token: t.token,
            identity,
            capability_only: args.capability_only,
        })
    } else {
        let service = args.target.clone().ok_or(ForwardError::NoTarget)?;
        let token = load_token(args)?;
        let identity = args.identity.clone().ok_or(ForwardError::NoIdentity)?;
        let relay = args.relay.ok_or(ForwardError::NoRelay)?;
        let relay_id = args.relay_id.clone().ok_or(ForwardError::NoRelay)?;
        let egress_id = args.egress_id.clone().ok_or(ForwardError::NoRelay)?;
        Ok(ResolvedForward {
            relay,
            relay_id,
            egress_id,
            service,
            token,
            identity,
            capability_only: args.capability_only,
        })
    }
}

/// Self-serve resolution: resolve the service's topology AND mint a dial capability via the control
/// plane, authenticated by the operator's own boatramp token + persistent overlay identity. This is
/// the headline `boatramp forward svc/<name>` path — zero hand-typed topology, and no per-dial grant
/// once the operator's token carries `Overlay·Write`.
async fn resolve_via_control_plane(
    args: &ForwardArgs,
    config: &crate::config::ProjectConfig,
) -> Result<ResolvedForward, ForwardError> {
    let service = args.target.clone().ok_or(ForwardError::NoTarget)?;
    // The operator's persistent overlay identity (its seed is also the forward identity).
    let secret = crate::overlay::operator_identity()?;
    let holder_pubkey = secret.id().to_hex();
    let (server, http) = crate::client::connect(args.server.clone(), config)
        .map_err(|e| ForwardError::Discovery(e.to_string()))?;
    let resp = http
        .post(format!("{server}/api/overlay/dial"))
        .json(&crate::overlay::DialRequestBody {
            service: service.clone(),
            holder_pubkey,
        })
        .send()
        .await
        .map_err(|e| ForwardError::Discovery(e.to_string()))?;
    // Read the status explicitly (not `.error_for_status()`, which drops the server's actionable
    // body): a 401/403 means the operator's token lacks `Overlay·Write` — surface the fix, not a
    // bare status line (UX Blocker #2); any other non-success carries the server's own message.
    let status = resp.status();
    if matches!(status.as_u16(), 401 | 403) {
        return Err(ForwardError::Unauthorized);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let body = body.trim();
        return Err(ForwardError::Discovery(if body.is_empty() {
            format!("control plane returned {status} resolving `{service}`")
        } else {
            format!("control plane returned {status} resolving `{service}`: {body}")
        }));
    }
    let resp: crate::overlay::DialResponseBody = resp
        .json()
        .await
        .map_err(|e| ForwardError::Discovery(e.to_string()))?;
    let relay = resp
        .relay
        .parse::<SocketAddr>()
        .map_err(|_| ForwardError::Discovery(format!("bad relay address `{}`", resp.relay)))?;
    Ok(ResolvedForward {
        relay,
        relay_id: resp.relay_id,
        egress_id: resp.egress_id,
        service,
        token: resp.token,
        identity: secret.seed_hex().to_string(),
        // The relay told us its posture; a capability-only relay is server-auth-only at TLS.
        capability_only: resp.relay_client_auth == "capability-only",
    })
}

/// Run the forwarder until interrupted.
pub async fn run(
    args: ForwardArgs,
    config: &crate::config::ProjectConfig,
) -> Result<(), ForwardError> {
    // Precedence: an explicit `--ticket` or `--relay` is the control-plane-less escape hatch;
    // otherwise `forward svc/<name>` self-serves through the control plane.
    let resolved = if args.ticket.is_some() || args.relay.is_some() {
        resolve_params(&args)?
    } else {
        resolve_via_control_plane(&args, config).await?
    };
    let ResolvedForward {
        relay,
        relay_id: relay_id_spec,
        egress_id: egress_id_spec,
        service,
        token,
        identity: identity_spec,
        capability_only,
    } = resolved;

    let secret = load_identity(&identity_spec)?;
    let relay_id = parse_id(&relay_id_spec)?;
    let egress_id = parse_id(&egress_id_spec)?;

    // One dial-only endpoint pinning the relay, reused for every accepted connection. A capability-only
    // relay is server-auth-only at TLS (it requests no client cert), so present NONE; a mutual-pin
    // relay pins our RPK cert, so present it. (The E2EE identity to the egress is unaffected either
    // way — it rides the sealed handshake, not the relay TLS.)
    let endpoint = if capability_only {
        client_endpoint_server_auth(&OverlayPeerPolicy::Pin(relay_id))?
    } else {
        client_endpoint(&secret, &OverlayPeerPolicy::Pin(relay_id))?
    };
    let listener = TcpListener::bind(&args.local).await?;
    let bound = listener.local_addr()?;

    eprintln!(
        "boatramp forward: {bound} → {service} via relay {relay} (overlay, relay-blind E2EE) — Ctrl-C to stop"
    );

    let secret = Arc::new(secret);
    let token = Arc::new(token);
    let service = Arc::new(service);
    // A healthy-looking bound port whose every dial fails (not enrolled / cap not authorized /
    // expired) is a silent trap. Escalate the FIRST failure to `error!` with the fix, so the
    // operator sees "why" rather than a dead port; later failures stay at `warn!` (UX should-fix).
    let first_failure = Arc::new(AtomicBool::new(false));

    loop {
        let (sock, _peer) = listener.accept().await?;
        let endpoint = endpoint.clone();
        let secret = Arc::clone(&secret);
        let token = Arc::clone(&token);
        let service = Arc::clone(&service);
        let first_failure = Arc::clone(&first_failure);
        tokio::spawn(async move {
            let request = DialRequest {
                service: (*service).clone(),
                token: (*token).clone(),
                e2ee: true,
            };
            if let Err(e) = forward_flow(
                sock,
                &endpoint,
                relay,
                &secret,
                egress_id,
                request,
                PathMode::PreferDirect,
            )
            .await
            {
                if first_failure.swap(true, Ordering::Relaxed) {
                    tracing::warn!(error = %e, "overlay forward connection failed");
                } else {
                    tracing::error!(
                        error = %e, %service, %relay,
                        "overlay forward FAILED on the first connection — the port is bound but the \
                         dial is not getting through. Likely causes: this client identity is not \
                         enrolled in the relay's `allowed_clients`; the dial capability is not \
                         authorized for this service; or it has expired. Fix enrollment/authorization \
                         and reconnect (later failures are logged at warn)."
                    );
                }
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
        assert_eq!(w.args.target.as_deref(), Some("svc/db"));
        assert_eq!(
            w.args.relay.map(|r| r.to_string()).as_deref(),
            Some("10.0.0.1:9000")
        );
        assert_eq!(w.args.token.as_deref(), Some("abc"));
    }

    /// The common case: a single `--ticket`, no other flags, and a bare local address (the ticket's
    /// service is authoritative so the positional target is optional).
    #[test]
    fn parses_ticket_only() {
        let ticket = crate::overlay::ForwardTicket {
            relay: "10.0.0.1:9100".into(),
            relay_id: "ed25519:aa".into(),
            egress_id: "ed25519:bb".into(),
            service: "svc/db".into(),
            token: "tok".into(),
            identity: Some("ed25519:cc".into()),
        }
        .encode()
        .unwrap();
        let w = Wrap::try_parse_from(["forward", "127.0.0.1:5432", "--ticket", &ticket]).unwrap();
        assert_eq!(w.args.local, "127.0.0.1:5432");
        assert!(w.args.target.is_none());
        let r = resolve_params(&w.args).unwrap();
        assert_eq!(r.relay.to_string(), "10.0.0.1:9100");
        assert_eq!(
            (r.relay_id, r.egress_id),
            ("ed25519:aa".into(), "ed25519:bb".into())
        );
        assert_eq!(
            (r.service, r.token, r.identity),
            ("svc/db".into(), "tok".into(), "ed25519:cc".into())
        );
        // A ticket defaults to mutual-pin (grant enrolls the client); no --capability-only here.
        assert!(!r.capability_only);
    }

    /// `--ticket` conflicts with the explicit relay flags.
    #[test]
    fn ticket_conflicts_with_explicit_flags() {
        let r = Wrap::try_parse_from([
            "forward",
            "127.0.0.1:5432",
            "--ticket",
            "brfwd1.xx",
            "--relay",
            "1.1.1.1:1",
        ]);
        assert!(r.is_err(), "--ticket and --relay must conflict");
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

    /// The real path: a forward **ticket** (as `overlay grant` emits — a `mint_overlay_dial`
    /// capability bundled with the relay/egress identities and the client seed) drives a
    /// `forward_flow` through a **live** served relay → served egress → TCP backend, capability-gated
    /// and relay-blind. This is the end-to-end redeem path, not an offline round-trip: the
    /// ticket-packaged capability must actually authorize against a running egress.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ticket_drives_a_live_forward_to_the_backend() {
        use boatramp_core::cose::{LocalSigner, TokenAlg, mint_overlay_dial};
        use boatramp_overlay::{
            OverlayPeerPolicy, OverlaySecret, PathMode, RelayClientAuth, forward_flow,
            run_egress_router, run_forwarding_router, server_endpoint,
        };
        use std::collections::BTreeSet;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Cluster root (the trust root the egress verifies dials against) + the three overlay peers.
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = {
            use boatramp_core::cose::Signer;
            root.public_key()
        };
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());

        // Backend echo (the service `svc/db` fronts).
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // Served egress fronting svc/db, verifying dials against the root.
        let egress_ep = server_endpoint(
            &egress,
            &OverlayPeerPolicy::AcceptAny,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        {
            let root_pub = root_pub.clone();
            tokio::spawn(run_egress_router(
                egress_ep,
                egress,
                move |s: &str| (s == "svc/db").then_some(backend_addr),
                root_pub,
                true,
                PathMode::Relay,
            ));
        }

        // Served relay enrolling the client (allowed_clients) + routing svc/db → the egress.
        let relay_ep = server_endpoint(
            &relay,
            &OverlayPeerPolicy::Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        tokio::spawn(run_forwarding_router(
            relay_ep,
            root_pub,
            RelayClientAuth::MutualPin,
            move |s: &str| (s == "svc/db").then_some((egress_addr, egress_id, true)),
        ));

        // Mint the dial capability the way `overlay grant` does, and package it as a ticket.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_overlay_dial(&client.id().to_public(), "svc/db", 3600, now, &root)
            .await
            .unwrap();
        let ticket = crate::overlay::ForwardTicket {
            relay: relay_addr.to_string(),
            relay_id: relay_id.to_hex(),
            egress_id: egress_id.to_hex(),
            service: "svc/db".into(),
            token,
            identity: Some(client.seed_hex().to_string()),
        }
        .encode()
        .unwrap();

        // Redeem it exactly as `forward --ticket` does: decode → connection params → forward_flow.
        let r = resolve_params(&ForwardArgs {
            local: "unused".into(),
            target: None,
            ticket: Some(ticket),
            server: None,
            relay: None,
            relay_id: None,
            egress_id: None,
            token: None,
            token_file: None,
            identity: None,
            capability_only: false,
        })
        .unwrap();
        let (rid, eid, service, tok, ident) =
            (r.relay_id, r.egress_id, r.service, r.token, r.identity);
        let secret = load_identity(&ident).unwrap();
        let endpoint = quinn_client(&secret, &rid);
        let eid = parse_id(&eid).unwrap();

        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &endpoint,
                relay_addr,
                &secret,
                eid,
                DialRequest {
                    service,
                    token: tok,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });

        app.write_all(b"ticket -> live backend").await.unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.read_to_end(&mut got),
        )
        .await
        .expect("the ticket-driven forward delivers the echo in time")
        .unwrap();
        assert_eq!(got, b"ticket -> live backend");
        let _ = fwd.await;
    }

    fn quinn_client(
        secret: &boatramp_overlay::OverlaySecret,
        relay_id_spec: &str,
    ) -> boatramp_overlay::quinn::Endpoint {
        let relay_id = parse_id(relay_id_spec).unwrap();
        boatramp_overlay::client_endpoint(
            secret,
            &boatramp_overlay::OverlayPeerPolicy::Pin(relay_id),
        )
        .unwrap()
    }

    /// Self-serve discovery, the real path: the control-plane's `OverlayDirectory` resolve + the
    /// root-signer dial mint (exactly what the `/api/overlay/dial` handler does) drive a
    /// `forward_flow` through a LIVE served relay → egress → TCP backend. Proves resolve→mint→
    /// forward→served-egress→backend end to end; the HTTP handler is thin glue over
    /// `OverlayDirectory::resolve` + `mint_overlay_dial`, both exercised here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn directory_resolve_and_mint_drives_a_live_forward() {
        use boatramp_core::cose::{LocalSigner, TokenAlg, mint_overlay_dial};
        use boatramp_overlay::{
            OverlayPeerPolicy, OverlaySecret, PathMode, RelayClientAuth, forward_flow,
            run_egress_router, run_forwarding_router, server_endpoint,
        };
        use boatramp_server::{OverlayDirectory, OverlayTarget};
        use std::collections::BTreeSet;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = {
            use boatramp_core::cose::Signer;
            root.public_key()
        };
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let egress_ep = server_endpoint(
            &egress,
            &OverlayPeerPolicy::AcceptAny,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        {
            let rp = root_pub.clone();
            tokio::spawn(run_egress_router(
                egress_ep,
                egress,
                move |s: &str| (s == "svc/db").then_some(backend_addr),
                rp,
                true,
                PathMode::Relay,
            ));
        }

        let relay_ep = server_endpoint(
            &relay,
            &OverlayPeerPolicy::Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        tokio::spawn(run_forwarding_router(
            relay_ep,
            root_pub,
            RelayClientAuth::MutualPin,
            move |s: &str| (s == "svc/db").then_some((egress_addr, egress_id, true)),
        ));

        // The directory the resolve route serves (built as `spawn_overlay_roles` builds it).
        let directory = OverlayDirectory::from_entries([(
            "svc/db".to_string(),
            OverlayTarget {
                relay: relay_addr.to_string(),
                relay_id: relay_id.to_hex(),
                egress_id: egress_id.to_hex(),
                client_auth: "mutual-pin".to_string(),
            },
        )]);

        // Resolve + mint exactly as `POST /api/overlay/dial` does.
        let target = directory.resolve("svc/db").expect("svc/db resolves");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_overlay_dial(&client.id().to_public(), "svc/db", 3600, now, &root)
            .await
            .unwrap();

        // Drive forward_flow with the resolved topology + minted token (what `forward svc/db` does).
        let resolved_relay: SocketAddr = target.relay.parse().unwrap();
        let eid = parse_id(&target.egress_id).unwrap();
        let endpoint = quinn_client(&client, &target.relay_id);
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &endpoint,
                resolved_relay,
                &client,
                eid,
                DialRequest {
                    service: "svc/db".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });
        app.write_all(b"discovery -> live backend").await.unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.read_to_end(&mut got),
        )
        .await
        .expect("the discovery-driven forward delivers the echo in time")
        .unwrap();
        assert_eq!(got, b"discovery -> live backend");
        let _ = fwd.await;
    }

    /// Security Blocker #1, the load-bearing proof: a FRESH client identity never pre-enrolled in any
    /// allowlist self-serves end to end through a **capability-only** relay (`AcceptAny` + the
    /// capability gate) → the egress's E2EE-proven holder-binding → the backend. This is the test
    /// whose absence masked the bound-but-dead bug: it proves the relay does NOT need pre-enrollment
    /// and that the egress re-authz is the real authority. The relay still gates the capability (a
    /// no-cap dial is refused there) — the companion `capability_only_relay_refuses_a_dial_with_no_capability`
    /// in the overlay crate proves that half.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn capability_only_relay_admits_a_never_enrolled_client_end_to_end() {
        use boatramp_core::cose::{LocalSigner, TokenAlg, mint_overlay_dial};
        use boatramp_overlay::{
            OverlayPeerPolicy, OverlaySecret, PathMode, RelayClientAuth,
            client_endpoint_server_auth, forward_flow, run_egress_router, run_forwarding_router,
            server_endpoint,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = {
            use boatramp_core::cose::Signer;
            root.public_key()
        };
        // A brand-new client identity. It is added to NO allowlist anywhere in this test.
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (relay_id, egress_id) = (relay.id(), egress.id());

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // Egress fronting svc/db, verifying dials against the root (E2EE-proven holder-binding here).
        let egress_ep = server_endpoint(
            &egress,
            &OverlayPeerPolicy::AcceptAny,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        {
            let rp = root_pub.clone();
            tokio::spawn(run_egress_router(
                egress_ep,
                egress,
                move |s: &str| (s == "svc/db").then_some(backend_addr),
                rp,
                true,
                PathMode::Relay,
            ));
        }

        // Relay in CAPABILITY-ONLY mode: AcceptAny at TLS (no allowlist, no pre-enrollment) +
        // RelayClientAuth::CapabilityOnly (the capability gate; holder-binding deferred to the egress).
        let relay_ep = server_endpoint(
            &relay,
            &OverlayPeerPolicy::AcceptAny,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        tokio::spawn(run_forwarding_router(
            relay_ep,
            root_pub,
            RelayClientAuth::CapabilityOnly,
            move |s: &str| (s == "svc/db").then_some((egress_addr, egress_id, true)),
        ));

        // A legitimately-minted cap for the fresh client, scope svc/db.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_overlay_dial(&client.id().to_public(), "svc/db", 3600, now, &root)
            .await
            .unwrap();

        // Dial through the relay exactly as self-serve `forward` does against a capability-only relay:
        // server-auth-only (present NO client cert, since the relay is AcceptAny at TLS).
        let endpoint = client_endpoint_server_auth(&OverlayPeerPolicy::Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &endpoint,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/db".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });
        app.write_all(b"never-enrolled -> live backend")
            .await
            .unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.read_to_end(&mut got),
        )
        .await
        .expect("a capability-only relay admits a never-enrolled client's valid cap in time")
        .unwrap();
        assert_eq!(got, b"never-enrolled -> live backend");
        let _ = fwd.await;
    }
}
