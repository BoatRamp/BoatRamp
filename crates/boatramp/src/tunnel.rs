//! `boatramp tunnel` (overlay-service-tunneler plan, R1): the SOCKS5 (+ optional HTTP `CONNECT`)
//! front-end over the shared [`boatramp_overlay_tunnel`] core.
//!
//! This module is CLI glue only — plan §1.1's key layout consequence ("the SDK does no HTTP") holds
//! all the way up here too: [`HttpControlPlane`] is the ONE place in this binary that turns an
//! overlay service name into an HTTP round trip against the control plane, implementing
//! [`boatramp_overlay_tunnel::ControlPlane`] over [`crate::client::connect`] exactly the way
//! `forward.rs`'s `resolve_via_control_plane` does for a single dial. Everything past that boundary
//! — catalog, cap lifecycle, the `OverlayClient` pool, the SOCKS wire protocol — lives in the core
//! crate and is reused unchanged.

use std::net::SocketAddr;
use std::path::PathBuf;

use boatramp_overlay_tunnel::{
    ControlPlane, ControlPlaneError, DialGrant, LocalAuth, ServiceInfo, SocksServer, Tunnel,
};
use clap::Args;

/// Arguments for `boatramp tunnel`.
#[derive(Args, Debug)]
pub struct TunnelArgs {
    /// boatramp server base URL (overrides `[publish].server`).
    #[arg(long, env = "BOATRAMP_SERVER")]
    pub server: Option<String>,
    /// Start the SOCKS5 front-end, bound to this address (plan §2). On by default — SOCKS is the
    /// only consumption front-end this release ships.
    #[arg(long, num_args = 0..=1, default_value = "127.0.0.1:1080", default_missing_value = "127.0.0.1:1080")]
    pub socks: String,
    /// Also start a small HTTP `CONNECT` front-end (for `HTTPS_PROXY`/`http.proxy`-style clients),
    /// bound to this address — reuses exactly the same dispatch and safety invariants as SOCKS.
    #[arg(long, num_args = 0..=1, default_missing_value = "127.0.0.1:1081")]
    pub http_connect: Option<String>,
    /// Disable the auto-generated local SOCKS credential (plan §5/§9.2 default is ON — a loopback
    /// port with no local auth lets ANY local user proxy under your overlay identity). Pass this
    /// only on a single-user host where that is an acceptable tradeoff.
    #[arg(long)]
    pub no_local_auth: bool,
    /// Start the TUN virtual-interface front-end instead of/alongside SOCKS (plan §3). NOT
    /// implemented in this release — see the error this prints for why and what ships instead.
    #[arg(long)]
    pub tun: bool,
}

/// A `tunnel` failure.
#[derive(Debug, thiserror::Error)]
pub enum TunnelCmdError {
    #[error("bind / accept: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Addr(String),
    #[error("control plane: {0}")]
    Client(#[from] crate::client::ClientError),
    #[error("overlay identity: {0}")]
    Identity(#[from] crate::overlay::Error),
    #[error(transparent)]
    Tunnel(#[from] boatramp_overlay_tunnel::TunnelError),
    #[error(transparent)]
    Socks(#[from] boatramp_overlay_tunnel::SocksError),
    #[error("local auth: {0}")]
    LocalAuth(#[from] boatramp_overlay_tunnel::LocalAuthError),
    /// 401 from the control plane — authentication, not authorization (mirrors `forward.rs`).
    #[error(
        "your boatramp token is missing, invalid, or expired — set a valid, unexpired token in \
         `BOATRAMP_TOKEN` or `[publish].token` (ask an admin to mint one if needed) and try again."
    )]
    Unauthenticated,
    /// 403, RBAC-denied (mirrors `forward.rs`).
    #[error(
        "not authorized to self-serve overlay tunneling — your boatramp token needs the \
         `Overlay·Write` right. Ask an admin to grant you an overlay role (e.g. a token minted \
         with `--role overlay`)."
    )]
    Unauthorized,
    /// 403, flow-policy-denied (mirrors `forward.rs`; overlay follow-up #3).
    #[error(
        "overlay resolve/mint denied by this cluster's flow policy — your token is authorized \
         (`Overlay·Write`), but an operator access policy does not permit it. Ask an admin to \
         review the overlay flow policy (`boatramp overlay policy ls` / `… test`)."
    )]
    FlowDenied,
    /// Any other control-plane failure surfaced through the core's `ControlPlaneError::Other`.
    #[error("overlay control plane: {0}")]
    ControlPlane(String),
    /// The requested TUN front-end is not implemented in this release.
    #[error(
        "--tun is not implemented in this release (R1 ships the shared core + SOCKS5 front-end \
         only; TUN is plan §3/§8's R2). Use `boatramp tunnel --socks` instead."
    )]
    #[cfg(not(feature = "tun"))]
    TunNotBuilt,
    /// The `tun` cargo feature IS compiled in, but its implementation is still the R1 stub.
    #[error(transparent)]
    #[cfg(feature = "tun")]
    Tun(#[from] boatramp_overlay_tunnel::tun::TunError),
}

/// Translate a [`ControlPlaneError`] into the CLI's own actionable variant — the HTTP-agnostic core
/// error already carries the right DISTINCTION (not-found / unauthenticated / unauthorized /
/// flow-denied / other); this just picks the right user-facing message per plan/`forward.rs`
/// precedent.
impl From<ControlPlaneError> for TunnelCmdError {
    fn from(e: ControlPlaneError) -> Self {
        match e {
            ControlPlaneError::Unauthenticated => Self::Unauthenticated,
            ControlPlaneError::Unauthorized => Self::Unauthorized,
            ControlPlaneError::FlowDenied => Self::FlowDenied,
            other => Self::ControlPlane(other.to_string()),
        }
    }
}

/// Parse an overlay identity given as bech32 (`bro1…`) or canonical hex (`ed25519:<hex>`) — mirrors
/// `forward.rs`'s private `parse_id` (duplicated rather than shared: a 3-line helper over a public
/// SDK type, not worth a cross-module dependency).
fn parse_overlay_id(s: &str) -> Result<boatramp_overlay_client::OverlayId, TunnelCmdError> {
    boatramp_overlay_client::OverlayId::from_bech32(s)
        .or_else(|_| boatramp_overlay_client::OverlayId::from_hex(s))
        .map_err(|e| TunnelCmdError::Addr(format!("bad overlay id `{s}`: {e}")))
}

/// Implements [`ControlPlane`] over [`crate::client::connect`] — the ONLY HTTP this binary performs
/// on behalf of the tunnel core. One instance is scoped to one project token (built once in [`run`]),
/// so per-project isolation is free by construction (plan §5): there is no code path by which this
/// type could answer for a different project's directory.
pub(crate) struct HttpControlPlane {
    server: String,
    http: crate::client::ApiClient,
}

impl HttpControlPlane {
    /// `pub(crate)` — [`crate::connect`] builds one too, for the one-shot `boatramp connect`
    /// command (same control-plane wiring, a different front-end).
    pub(crate) fn new(server: String, http: crate::client::ApiClient) -> Self {
        Self { server, http }
    }

    fn parse_entry(e: crate::overlay::ServiceEntry) -> Result<ServiceInfo, ControlPlaneError> {
        let relay: SocketAddr = e
            .relay
            .parse()
            .map_err(|_| ControlPlaneError::Other(format!("bad relay address `{}`", e.relay)))?;
        let relay_id = parse_overlay_id(&e.relay_id)
            .map_err(|err| ControlPlaneError::Other(err.to_string()))?;
        let egress_id = parse_overlay_id(&e.egress_id)
            .map_err(|err| ControlPlaneError::Other(err.to_string()))?;
        Ok(ServiceInfo {
            service: e.service,
            relay,
            relay_id,
            egress_id,
            capability_only: e.client_auth == "capability-only",
        })
    }
}

#[async_trait::async_trait]
impl ControlPlane for HttpControlPlane {
    async fn list_services(&self) -> Result<Vec<ServiceInfo>, ControlPlaneError> {
        let resp = self
            .http
            .get(format!("{}/api/overlay/services", self.server))
            .send()
            .await
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(ControlPlaneError::Unauthenticated);
        }
        if status.as_u16() == 403 {
            return Err(ControlPlaneError::Unauthorized);
        }
        if !status.is_success() {
            return Err(ControlPlaneError::Other(format!(
                "control plane returned {status} listing overlay services"
            )));
        }
        let entries: Vec<crate::overlay::ServiceEntry> = resp
            .json()
            .await
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
        entries.into_iter().map(Self::parse_entry).collect()
    }

    async fn resolve_and_mint(
        &self,
        service: &str,
        holder: boatramp_overlay_client::OverlayId,
    ) -> Result<DialGrant, ControlPlaneError> {
        let resp = self
            .http
            .post(format!("{}/api/overlay/dial", self.server))
            .json(&crate::overlay::DialRequestBody {
                service: service.to_string(),
                holder_pubkey: holder.to_hex(),
            })
            .send()
            .await
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
        // Mirrors `forward.rs::resolve_via_control_plane`'s exact 401/403/flow-denied split.
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(ControlPlaneError::Unauthenticated);
        }
        if status.as_u16() == 404 {
            return Err(ControlPlaneError::NotFound(service.to_string()));
        }
        if status.as_u16() == 403 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("flow denied by policy") {
                return Err(ControlPlaneError::FlowDenied);
            }
            return Err(ControlPlaneError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ControlPlaneError::Other(format!(
                "control plane returned {status} resolving `{service}`: {}",
                body.trim()
            )));
        }
        let body: crate::overlay::DialResponseBody = resp
            .json()
            .await
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
        let relay: SocketAddr = body
            .relay
            .parse()
            .map_err(|_| ControlPlaneError::Other(format!("bad relay address `{}`", body.relay)))?;
        let relay_id = parse_overlay_id(&body.relay_id)
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
        let egress_id = parse_overlay_id(&body.egress_id)
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
        Ok(DialGrant {
            relay,
            relay_id,
            egress_id,
            capability_only: body.relay_client_auth == "capability-only",
            token: body.token,
            expires_at: body.expires_at,
        })
    }
}

/// The local SOCKS auth credential's persisted path (plan §9.2):
/// `$XDG_CONFIG_HOME/boatramp/tunnel-socks.auth`, else `~/.config/boatramp/tunnel-socks.auth`.
fn local_auth_path() -> Result<PathBuf, TunnelCmdError> {
    Ok(crate::overlay::config_dir()?.join("tunnel-socks.auth"))
}

/// Run `boatramp tunnel` until interrupted: build the `ControlPlane` from `client::connect`, load
/// the operator's persistent overlay identity, construct the core, and start the requested
/// front-end(s).
pub async fn run(
    args: TunnelArgs,
    config: &crate::config::ProjectConfig,
) -> Result<(), TunnelCmdError> {
    if args.tun {
        #[cfg(feature = "tun")]
        {
            boatramp_overlay_tunnel::tun::start()?;
            return Ok(());
        }
        #[cfg(not(feature = "tun"))]
        return Err(TunnelCmdError::TunNotBuilt);
    }

    let (server, http) = crate::client::connect(args.server.clone(), config)?;
    let holder = crate::overlay::operator_identity()?;

    let control_plane = std::sync::Arc::new(HttpControlPlane::new(server, http));
    let tunnel = Tunnel::new(control_plane, holder).await?;

    let auth = if args.no_local_auth {
        None
    } else {
        Some(LocalAuth::load_or_generate(&local_auth_path()?)?)
    };
    if let Some(a) = &auth {
        eprintln!(
            "boatramp tunnel: local SOCKS auth required — username `{}` (see {})",
            a.username,
            local_auth_path()?.display()
        );
    } else {
        eprintln!(
            "boatramp tunnel: --no-local-auth — any local user on this host can use this proxy"
        );
    }

    let socks_addr: SocketAddr = args
        .socks
        .parse()
        .map_err(|_| TunnelCmdError::Addr(format!("bad --socks address `{}`", args.socks)))?;
    let http_connect_addr = match &args.http_connect {
        Some(a) => Some(
            a.parse::<SocketAddr>()
                .map_err(|_| TunnelCmdError::Addr(format!("bad --http-connect address `{a}`")))?,
        ),
        None => None,
    };

    let server = SocksServer::bind(tunnel, auth, socks_addr, http_connect_addr).await?;
    eprintln!(
        "boatramp tunnel: SOCKS5 ready on {} — Ctrl-C to stop",
        server.socks_addr()?
    );
    if let Some(addr) = server.http_connect_addr()? {
        eprintln!("boatramp tunnel: HTTP CONNECT ready on {addr}");
    }
    server.serve().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        args: TunnelArgs,
    }

    #[test]
    fn socks_defaults_to_127_0_0_1_1080_with_no_flag_at_all() {
        let w = Wrap::try_parse_from(["tunnel"]).unwrap();
        assert_eq!(w.args.socks, "127.0.0.1:1080");
        assert!(w.args.http_connect.is_none());
        assert!(!w.args.no_local_auth);
        assert!(!w.args.tun);
    }

    #[test]
    fn socks_takes_an_explicit_address() {
        let w = Wrap::try_parse_from(["tunnel", "--socks", "127.0.0.1:9999"]).unwrap();
        assert_eq!(w.args.socks, "127.0.0.1:9999");
    }

    #[test]
    fn http_connect_bare_flag_uses_its_default_missing_value() {
        let w = Wrap::try_parse_from(["tunnel", "--http-connect"]).unwrap();
        assert_eq!(w.args.http_connect.as_deref(), Some("127.0.0.1:1081"));
    }

    #[test]
    fn no_local_auth_and_tun_are_plain_flags() {
        let w = Wrap::try_parse_from(["tunnel", "--no-local-auth", "--tun"]).unwrap();
        assert!(w.args.no_local_auth);
        assert!(w.args.tun);
    }

    // ---- E2E: a real SOCKS5 client, through the core, to a LIVE relay+egress+backend ----
    //
    // Extends the exact harness `forward.rs`'s own E2E tests stand up (live root signer + served
    // relay + served egress + TCP echo backend) with a mock `ControlPlane` that mints a dial
    // capability the SAME way the real `POST /api/overlay/dial` handler does
    // (`cose::mint_overlay_dial`) — proving the FULL path: a hand-written SOCKS5 client (NOT built
    // on the core's own codec, so this is real wire interop, not self-agreement) CONNECTs a bare
    // service name, the core resolves+mints+dials, and the echo round-trips relay-blind E2EE →
    // egress → backend. Also records exactly what the mock `ControlPlane` was asked to resolve,
    // proving the plan §5 IP-as-local-handle invariant end to end: only a service NAME ever reaches
    // the control plane, never an address.
    use std::sync::{Arc, Mutex};

    /// A `ControlPlane` that mints a dial capability the way `POST /api/overlay/dial` does
    /// (`cose::mint_overlay_dial`, the same root signer the live relay/egress trust), and records
    /// every `service` string it was asked to resolve.
    struct E2eControlPlane {
        relay_addr: std::net::SocketAddr,
        relay_id: boatramp_overlay_client::OverlayId,
        egress_id: boatramp_overlay_client::OverlayId,
        root: boatramp_core::cose::LocalSigner,
        requested: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ControlPlane for E2eControlPlane {
        async fn list_services(&self) -> Result<Vec<ServiceInfo>, ControlPlaneError> {
            Ok(vec![ServiceInfo {
                service: "svc/db".to_string(),
                relay: self.relay_addr,
                relay_id: self.relay_id,
                egress_id: self.egress_id,
                capability_only: false,
            }])
        }

        async fn resolve_and_mint(
            &self,
            service: &str,
            holder: boatramp_overlay_client::OverlayId,
        ) -> Result<DialGrant, ControlPlaneError> {
            // The §5 invariant, recorded live: whatever is passed here is the ENTIRE input this
            // mock (standing in for the real control plane) ever sees — a bare service name, never
            // an address of any kind.
            self.requested.lock().unwrap().push(service.to_string());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let token = boatramp_core::cose::mint_overlay_dial(
                &holder.to_public(),
                service,
                3600,
                now,
                &self.root,
            )
            .await
            .map_err(|e| ControlPlaneError::Other(e.to_string()))?;
            Ok(DialGrant {
                relay: self.relay_addr,
                relay_id: self.relay_id,
                egress_id: self.egress_id,
                capability_only: false,
                token,
                expires_at: now + 3600,
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn socks_client_connects_through_the_core_to_a_live_backend() {
        use boatramp_core::cose::{LocalSigner, Signer, TokenAlg};
        use boatramp_overlay::{
            OverlayPeerPolicy, OverlaySecret, PathMode, RelayClientAuth, run_egress_router,
            run_forwarding_router, server_endpoint,
        };
        use std::collections::BTreeSet;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Cluster root (the trust root the egress verifies dials against) + the three overlay
        // peers — identical setup to forward.rs's own live harness.
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
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

        // Served relay enrolling the client (allowed_clients) + routing svc/db -> the egress
        // (mutual-pin, like the headline self-serve `forward` path).
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

        // The mock control plane: mints exactly as `overlay_dial` does, against the SAME root the
        // live relay/egress trust.
        let cp = Arc::new(E2eControlPlane {
            relay_addr,
            relay_id,
            egress_id,
            root,
            requested: Mutex::new(Vec::new()),
        });

        let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, client)
            .await
            .unwrap();

        let server = SocksServer::bind(tunnel, None, "127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let socks_addr = server.socks_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });

        // A REAL SOCKS5 client — hand-written wire bytes, independent of the core's own codec (so
        // this proves actual RFC-1928 interop, not just "the encoder/decoder agree with each
        // other"). No local auth configured, so a bare no-auth greeting is accepted.
        let mut sock = TcpStream::connect(socks_addr).await.unwrap();
        sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        sock.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);

        // `db` — the bare-name R1 form (normalizes to `svc/db`). The plan's own illustration uses
        // the DNS-zone form `db.svc.<cluster>.boatramp`, which is an R2+ concern (plan §9.1) not
        // implemented yet; the bare name is what R1 actually supports and is what self-serve
        // `forward svc/db` already uses today.
        let name = b"db";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&0u16.to_be_bytes());
        sock.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        sock.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(
            reply[1], 0x00,
            "CONNECT to a cataloged service must succeed"
        );

        sock.write_all(b"socks -> core -> relay-blind E2EE -> egress -> backend")
            .await
            .unwrap();
        sock.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sock.read_to_end(&mut got),
        )
        .await
        .expect("the socks-driven tunnel delivers the echo in time")
        .unwrap();
        assert_eq!(
            got,
            b"socks -> core -> relay-blind E2EE -> egress -> backend"
        );

        // Plan §5's invariant, proven live: the control plane was asked for EXACTLY the resolved
        // service name — never an IP, never any other field.
        assert_eq!(*cp.requested.lock().unwrap(), vec!["svc/db".to_string()]);
    }
}
