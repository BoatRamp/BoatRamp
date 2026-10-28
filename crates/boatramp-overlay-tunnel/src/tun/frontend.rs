//! `TunFrontend` — plan §3's full assembly: device + route (plan §3.1/§3.2), the embedded DNS
//! (plan §3.3) over the synthetic-IP allocator (plan §3.4), the `smoltcp` netstack (plan §3.5)
//! bridged to the real device, the host resolver override (plan §3.6), privilege drop (plan §3.7),
//! and clean teardown (plan §3.9). Mirrors [`crate::socks::SocksServer`]'s `bind()`/`serve()` split:
//! [`TunFrontend::bind`] performs every host mutation and returns a ready front-end;
//! [`TunFrontend::serve`] runs it until a shutdown signal (or a fatal task failure) and then
//! [`TunFrontend::shutdown`]s — reverting everything `bind()` did, in the right order.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::alloc::SyntheticIpAllocator;
use super::cidr::Ipv4Cidr;
use super::device::{self, DeviceError, TunDevice};
use super::dns::{DnsServer, DnsServerError, Zone};
use super::netstack::{self, NetStackConfig};
use super::privilege::PrivilegeError;
use super::resolver::{ResolverError, ResolverGuard};
use super::teardown::{self, Marker};
use crate::core::Tunnel;

/// Default loopback address for the embedded DNS responder (plan §3.3).
///
/// The PORT is per-OS. On unix the host resolver override points the zone at an explicit
/// `address:port` (`resolvectl dns <iface> 127.0.0.1:5353`, or `/etc/resolver/<zone>`'s `port`
/// directive), so the unprivileged, collision-unlikely `5353` is used. Windows NRPT
/// (`Add-DnsClientNrptRule -NameServers 127.0.0.1`) has NO port field — it always forwards to the
/// nameserver on port 53 — so the Windows responder MUST bind `127.0.0.1:53` for NRPT to reach it.
/// Binding the privileged `:53` is fine here because the Windows tunnel runs elevated for its whole
/// lifetime anyway (see [`super::privilege`]).
#[cfg(not(windows))]
fn default_dns_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 5353))
}

/// See [`default_dns_bind`]'s non-Windows twin: Windows NRPT forwards only to port 53, so the
/// embedded responder binds `127.0.0.1:53`.
#[cfg(windows)]
fn default_dns_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 53))
}

/// Default MTU: headroom under common outer-tunnel/overlay-transport MTUs rather than the plain
/// Ethernet 1500, so this front-end's own traffic doesn't itself need IP fragmentation when it
/// rides over the overlay's own QUIC transport.
const DEFAULT_MTU: u16 = 1420;

/// User-facing configuration for the TUN front-end — what `boatramp tunnel --tun` (plus
/// `--cidr`/`--dns-zone`) builds and passes to [`TunFrontend::bind`].
#[derive(Debug, Clone)]
pub struct TunOptions {
    /// Plan §3.2, default `100.64.0.0/10`.
    pub cidr: Ipv4Cidr,
    /// Plan §3.3/§9 open decision 1 — operator-configurable, default `internal` (RFC 8375).
    pub dns_zone: String,
    /// Plan §3.3's `<cluster>` label — resolved by the CLI (config, falling back to the project
    /// name) BEFORE this struct is built; this crate stays project-config-agnostic (module doc,
    /// same posture [`crate::socks::LocalAuth`] takes for its own path).
    pub cluster: String,
    /// Where the embedded DNS responder binds — always loopback (plan §3.3); not currently exposed
    /// as its own CLI flag (`--dns-zone` controls the zone's name, not the responder's bind
    /// address), kept configurable here mainly for the plan §6 E2E/integration tests.
    pub dns_bind: SocketAddr,
    /// `None` ⇒ let the OS/`tun-rs` pick a name (`tunN` on Linux).
    pub tun_name: Option<String>,
    pub mtu: u16,
    /// The plan §3.9 dirty-state marker's path — resolved by the CLI (this crate stays path-
    /// agnostic, same posture as [`crate::socks::LocalAuth::load_or_generate`]'s path parameter).
    pub marker_path: PathBuf,
    /// Skip the host resolver override entirely (plan §3.6) — an explicit opt-out for a caller
    /// that manages its own DNS wiring (or an integration test that doesn't want to touch
    /// `/etc/resolv.conf`/`resolvectl` at all). Default `false`.
    pub skip_resolver: bool,
}

impl TunOptions {
    #[must_use]
    pub fn new(cidr: Ipv4Cidr, dns_zone: String, cluster: String, marker_path: PathBuf) -> Self {
        Self {
            cidr,
            dns_zone,
            cluster,
            dns_bind: default_dns_bind(),
            tun_name: None,
            mtu: DEFAULT_MTU,
            marker_path,
            skip_resolver: false,
        }
    }

    /// The fully-qualified zone suffix every in-zone query ends with (plan §3.3):
    /// `svc.<cluster>.<tld>.`
    #[must_use]
    pub fn zone_suffix(&self) -> String {
        format!(
            "svc.{}.{}.",
            self.cluster.to_ascii_lowercase(),
            self.dns_zone.to_ascii_lowercase()
        )
    }
}

/// A failure standing up or running the TUN front-end.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error(transparent)]
    Dns(#[from] DnsServerError),
    #[error(transparent)]
    Resolver(#[from] ResolverError),
    #[error("synthetic-IP pool: {0}")]
    PoolExhausted(#[from] super::alloc::PoolExhausted),
    #[error("privilege drop: {0}")]
    Privilege(#[from] PrivilegeError),
    #[error("marker file {0}: {1}")]
    Marker(PathBuf, #[source] std::io::Error),
}

/// A bound, running-or-ready-to-run TUN front-end. See the module doc for the `bind`/`serve` split.
pub struct TunFrontend {
    device: TunDevice,
    interface_addr: Ipv4Addr,
    dns_handle: JoinHandle<Result<(), DnsServerError>>,
    netstack_handle: JoinHandle<()>,
    netstack_shutdown: Option<oneshot::Sender<()>>,
    pump_handles: Vec<JoinHandle<()>>,
    resolver_guard: Option<ResolverGuard>,
    marker_path: PathBuf,
}

impl TunFrontend {
    /// Stand the whole front-end up: cleans up any stale marker from a crashed previous run first
    /// (plan §3.9), then opens the TUN device + installs its route (plan §3.1/§3.2), applies the
    /// host resolver override (plan §3.6), starts the embedded DNS (plan §3.3) and the netstack
    /// (plan §3.5) bridged to the real device, and finally drops privileges where feasible (plan
    /// §3.7). Every step that can fail leaves nothing dangling: an error early on just drops
    /// whatever WAS already constructed (its `Drop` impls revert it) before returning; a privilege-
    /// drop FAILURE specifically (Security review MEDIUM-3) is fatal AFTER the rest is already
    /// running, so that path explicitly calls [`TunFrontend::shutdown`] on the fully-built front-end
    /// before returning the error, rather than relying on `Drop` alone.
    pub async fn bind(tunnel: Arc<Tunnel>, options: TunOptions) -> Result<Self, TunError> {
        match teardown::cleanup_stale(&options.marker_path) {
            Ok(report) if report.found_marker => {
                tracing::info!(
                    reverted_resolver = report.reverted_resolver,
                    owner_still_running = report.owner_still_running,
                    "boatramp tunnel: found a dirty-state marker from a previous run at startup"
                );
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "boatramp tunnel: failed to check for a stale marker — continuing");
            }
        }

        let allocator_for_addr = SyntheticIpAllocator::new(options.cidr);
        let interface_addr = allocator_for_addr.reserve_interface_address();

        // 1. TUN device + route (plan §3.1/§3.2) — needs CAP_NET_ADMIN/root.
        let device = device::open(
            options.tun_name.as_deref(),
            interface_addr,
            options.cidr,
            options.mtu,
        )
        .await?;
        device::install_route(options.cidr, device.if_index).await?;

        let mut marker = Marker::new(device.name.clone(), options.cidr.to_string());
        marker
            .write(&options.marker_path)
            .map_err(|e| TunError::Marker(options.marker_path.clone(), e))?;

        // 2. Host resolver split-DNS (plan §3.6) — THE mutation that outlives the device (module
        // doc) and so the one the marker's `resolver` field actually needs to track.
        let resolver_guard = if options.skip_resolver {
            None
        } else {
            let guard =
                ResolverGuard::apply(&device.name, options.dns_bind, &options.zone_suffix())?;
            marker.resolver = Some(guard.method());
            // The zone the override was scoped to — the macOS `/etc/resolver/<zone>` backend needs
            // it to revert from a fresh process after a crash (plan §3.9); harmless for Linux.
            marker.resolver_zone = Some(options.zone_suffix());
            marker
                .write(&options.marker_path)
                .map_err(|e| TunError::Marker(options.marker_path.clone(), e))?;
            Some(guard)
        };

        // The allocator the DNS responder and the netstack SHARE for this front-end's whole life
        // (plan §3.4 — one allocator per `Tunnel`/project).
        let allocator = Arc::new(SyntheticIpAllocator::new(options.cidr));

        // 3. Embedded DNS (plan §3.3).
        let zone = Zone::new(options.dns_zone.clone(), options.cluster.clone());
        let dns_server = DnsServer::bind(
            options.dns_bind,
            zone,
            Arc::clone(&allocator),
            Arc::clone(&tunnel),
        )
        .await?;
        let dns_handle = tokio::spawn(dns_server.serve());

        // 4. The netstack (plan §3.5), bridged to the real device via two pump tasks.
        let (raw_in_rx, raw_out_tx, mut pump_handles) =
            spawn_device_pumps(Arc::clone(&device.device), usize::from(options.mtu));
        let (netstack_shutdown_tx, netstack_shutdown_rx) = oneshot::channel();
        let netstack_config = NetStackConfig {
            interface_addr,
            cidr: options.cidr,
            mtu: usize::from(options.mtu),
        };
        let netstack_handle = tokio::spawn(netstack::run(
            netstack_config,
            raw_in_rx,
            raw_out_tx,
            tunnel,
            allocator,
            netstack_shutdown_rx,
        ));
        pump_handles.shrink_to_fit();

        let front_end = Self {
            device,
            interface_addr,
            dns_handle,
            netstack_handle,
            netstack_shutdown: Some(netstack_shutdown_tx),
            pump_handles,
            resolver_guard,
            marker_path: options.marker_path,
        };

        // 5. Privilege drop where feasible (plan §3.7) — last, now that every privileged
        // operation (opening the TUN device, installing the route) is already done.
        //
        // Security review MEDIUM-3: a drop FAILURE is FATAL, not a warn-and-continue — this
        // process must never end up serving the untrusted packet-parsing netstack and the
        // untrusted-query DNS responder (both already running, above) as root because a
        // privilege drop silently didn't happen. Fail CLOSED: revert everything `bind()` already
        // built (the exact same sequence `shutdown()` takes) and return the error.
        if let Err(err) = super::privilege::drop_to_unprivileged() {
            tracing::error!(
                error = %err,
                "boatramp tunnel: privilege drop FAILED — refusing to start (this would otherwise \
                 serve the untrusted packet/DNS parsing surface as root); reverting everything \
                 set up so far"
            );
            if let Err(shutdown_err) = front_end.shutdown().await {
                tracing::warn!(
                    error = %shutdown_err,
                    "boatramp tunnel: cleanup after a failed privilege drop hit its own error"
                );
            }
            return Err(TunError::Privilege(err));
        }

        Ok(front_end)
    }

    /// The TUN device's interface name (e.g. `tun0`).
    #[must_use]
    pub fn tun_name(&self) -> &str {
        &self.device.name
    }

    /// The address assigned to the TUN interface itself (plan §3.1/§3.2).
    #[must_use]
    pub fn interface_addr(&self) -> Ipv4Addr {
        self.interface_addr
    }

    /// Run until a shutdown signal (`SIGINT`/`SIGTERM`/`SIGHUP`) or a fatal background-task
    /// failure, then [`TunFrontend::shutdown`].
    pub async fn serve(mut self) -> Result<(), TunError> {
        tokio::select! {
            () = wait_for_shutdown_signal() => {
                tracing::info!("boatramp tunnel: shutdown signal received");
            }
            res = &mut self.dns_handle => {
                tracing::warn!(?res, "boatramp tunnel: embedded DNS server task ended unexpectedly");
            }
            res = &mut self.netstack_handle => {
                tracing::warn!(?res, "boatramp tunnel: netstack task ended unexpectedly");
            }
        }
        self.shutdown().await
    }

    /// Revert every host mutation `bind()` made, in the right order, then remove the dirty-state
    /// marker (plan §3.9) — ONLY after everything it was tracking has actually been reverted.
    pub async fn shutdown(mut self) -> Result<(), TunError> {
        if let Some(tx) = self.netstack_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.netstack_handle.await;

        self.dns_handle.abort();
        let _ = self.dns_handle.await;

        for handle in self.pump_handles.drain(..) {
            handle.abort();
            let _ = handle.await;
        }

        // Revert the resolver override explicitly (idempotent — `ResolverGuard::revert` is safe to
        // call even though its own `Drop` would do the same thing when `guard` goes out of scope
        // at the end of this block).
        if let Some(mut guard) = self.resolver_guard.take() {
            guard.revert();
        }

        // `self.device` drops at the end of this function, closing the TUN fd — the kernel removes
        // the interface and, per plan §3.9's own text, every route bound to it.

        Marker::remove(&self.marker_path)
            .map_err(|e| TunError::Marker(self.marker_path.clone(), e))?;
        tracing::info!("boatramp tunnel: TUN front-end stopped cleanly");
        Ok(())
    }
}

/// What [`spawn_device_pumps`] hands back: the netstack's `raw_in`/`raw_out` channel ends, plus the
/// two pump tasks' join handles (so [`TunFrontend::shutdown`] can abort+await them).
type DevicePumps = (
    mpsc::Receiver<Vec<u8>>,
    mpsc::Sender<Vec<u8>>,
    Vec<JoinHandle<()>>,
);

/// Bridge a real device to the netstack's channel-based `run` (plan §3.5's module doc explains
/// WHY `netstack::run` itself never touches a real device: it's what makes the plan §6 E2E test
/// possible with no privilege and no real TUN at all).
fn spawn_device_pumps(device: Arc<tun_rs::AsyncDevice>, mtu: usize) -> DevicePumps {
    const CHANNEL_CAPACITY: usize = 256;
    let (raw_in_tx, raw_in_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let (raw_out_tx, mut raw_out_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);

    let reader = {
        let device = Arc::clone(&device);
        tokio::spawn(async move {
            // Headroom over the configured MTU: some platforms prepend a small per-packet header
            // (e.g. Linux's optional 4-byte "packet information" prefix) ahead of the IP payload.
            let mut buf = vec![0u8; mtu + 64];
            let mut logged_first = false;
            loop {
                match device.recv(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => {
                        if !logged_first {
                            logged_first = true;
                            // One-shot: the leading bytes of the first frame the kernel hands us —
                            // a raw IPv4 frame starts with 0x45 (v4, IHL 5); a 0x00 0x00 prefix
                            // would mean the device is delivering a 4-byte packet-information header
                            // that would misalign the IP parser.
                            tracing::debug!(
                                n,
                                head = ?&buf[..n.min(8)],
                                "boatramp tunnel: first frame read from the TUN device"
                            );
                        }
                        if raw_in_tx.send(buf[..n].to_vec()).await.is_err() {
                            break; // the netstack task is gone
                        }
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "boatramp tunnel: TUN device read ended");
                        break;
                    }
                }
            }
        })
    };
    let writer = tokio::spawn(async move {
        while let Some(frame) = raw_out_rx.recv().await {
            if let Err(err) = device.send(&frame).await {
                tracing::debug!(error = %err, "boatramp tunnel: TUN device write failed");
                break;
            }
        }
    });

    (raw_in_rx, raw_out_tx, vec![reader, writer])
}

/// Race `SIGINT`/`SIGTERM`/`SIGHUP` (plan §3.9) and return once any of them fires. `SIGTERM`/
/// `SIGHUP` handler installation can only fail in exotic sandboxed environments; such a failure
/// just means this process falls back to `SIGINT` alone rather than refusing to start.
#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    let sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
    match (sigterm, sighup) {
        (Ok(mut sigterm), Ok(mut sighup)) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
                _ = sighup.recv() => {}
            }
        }
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// Windows (R4): there is no `SIGTERM`/`SIGHUP`. The equivalent console control events are Ctrl-C
/// and Ctrl-Break (`tokio::signal::windows`), the latter of which also fires for the console
/// close / logoff / system-shutdown events, so racing the two covers the clean-teardown triggers
/// plan §3.9 wants. Ctrl-Break handler installation can only fail in exotic environments; as on
/// unix, such a failure just falls back to Ctrl-C alone rather than refusing to start.
#[cfg(windows)]
async fn wait_for_shutdown_signal() {
    match tokio::signal::windows::ctrl_break() {
        Ok(mut ctrl_break) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = ctrl_break.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}
