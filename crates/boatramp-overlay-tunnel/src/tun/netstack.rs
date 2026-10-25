//! The userspace TCP/IP stack (plan §3.5) — the heart of the TUN front-end and, per plan §5, **the
//! main new security-sensitive surface** in this release: it is the only place arbitrary bytes from
//! an untrusted network reach a full IP/TCP parser.
//!
//! ## Design
//! Built on `smoltcp` (pure-Rust, no C FFI, upstream-fuzzed — plan §3.5's explicit alternative to C
//! lwIP). [`ChannelDevice`] is a ~40-line [`smoltcp::phy::Device`] adapter over two in-memory queues
//! instead of a real file descriptor — raw frames arrive via an `mpsc` channel ([`run`]'s
//! `raw_in`) and leave via another ([`run`]'s `raw_out`); [`super::device`] is the only place a real
//! TUN fd is ever touched. This split is what makes the plan §6 E2E test possible: it feeds crafted
//! bytes straight into [`run`] with **no real device, no privilege, nothing OS-specific** — exactly
//! "feed a crafted SYN/data IP frame into the smoltcp stack directly".
//!
//! Dynamic listening, not a fixed port table: a conventional `smoltcp` server (see its own
//! `examples/server.rs`) pre-allocates one socket per well-known port. This front-end instead
//! accepts a TCP connection to **any** port on **any** address this process has allocated (plan
//! §3.4) — so before each `iface.poll()`, [`run`] peeks (via [`super::packet::peek_tcp`], never
//! panicking on hostile input) at the frames about to be fed in; a fresh `SYN` to a destination this
//! process actually allocated (checked against [`super::alloc::SyntheticIpAllocator::resolve`] —
//! **never** against a destination it didn't) gets a freshly-listening socket inserted first, so the
//! SAME `poll()` call routes the `SYN` into it. `smoltcp`'s `AnyIP` + a route-to-self (plan §3.2)
//! make the interface accept traffic for the whole CIDR without pre-registering every address as
//! its "own" (see the module's `configure_interface`).
//!
//! ## The plan §5 invariant, concretely
//! [`SyntheticIpAllocator::resolve`] turns a destination address into a **name**; [`bridge`] then
//! calls [`crate::core::Tunnel::open`] with that name — never the address. The synthetic IP is used
//! ONLY to pick which smoltcp socket/channel pair a byte stream flows through; it is never read by
//! [`bridge`], never serialized, and has no field to put it in on the dial path (same structural
//! proof `crate::core::tunnel::tests::dial_request_has_no_ip_field` already gives for the SOCKS
//! front-end — this front-end reaches the exact same [`crate::core::Tunnel::open`] call).
//!
//! ## Bounds (plan §5: "bound per-conn + total socket buffers")
//! [`MAX_CONNECTIONS`] caps how many sockets this process ever holds open at once (a SYN past the
//! cap is silently dropped — the peer's TCP retries, nothing crashes or grows unbounded);
//! [`RX_BUFFER_SIZE`]/[`TX_BUFFER_SIZE`] cap each connection's `smoltcp` buffers; [`CHANNEL_CAPACITY`]
//! caps the bridge channels between the poll loop and each connection's overlay `Flow`.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, Route, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::alloc::SyntheticIpAllocator;
use super::packet::peek_tcp;
use crate::core::Tunnel;

/// Total concurrently-open connections this netstack ever holds (plan §5).
pub const MAX_CONNECTIONS: usize = 512;
/// Per-connection `smoltcp` receive buffer size.
pub const RX_BUFFER_SIZE: usize = 64 * 1024;
/// Per-connection `smoltcp` transmit buffer size.
pub const TX_BUFFER_SIZE: usize = 64 * 1024;
/// Bridge channel depth (poll loop ↔ per-connection overlay `Flow` task) — bounded so a stalled
/// overlay flow backpressures the TCP window instead of growing an unbounded in-memory queue.
const CHANNEL_CAPACITY: usize = 32;
/// Upper bound on how long the poll loop ever sleeps with nothing to do; it wakes immediately on
/// new inbound data regardless (see `run`'s `select!`), so this only bounds reply/retry latency
/// when nothing is happening — a documented simplification over computing `Interface::poll_delay`
/// precisely (a reasonable follow-up, not a correctness issue: TCP tolerates this kind of latency).
const POLL_TICK: Duration = Duration::from_millis(10);

/// What [`run`] needs to configure the `smoltcp` interface — everything else (the device, the
/// catalog, the allocator) is passed separately.
#[derive(Debug, Clone, Copy)]
pub struct NetStackConfig {
    /// The TUN interface's own address inside the routed CIDR (plan §3.1/§3.2) — reserved by
    /// [`SyntheticIpAllocator::reserve_interface_address`], never handed out to a service.
    pub interface_addr: Ipv4Addr,
    pub cidr: super::cidr::Ipv4Cidr,
    pub mtu: usize,
}

/// A `smoltcp` [`Device`] backed by two in-process queues instead of a file descriptor (module doc)
/// — `inbound` is drained by `receive()` (FIFO, oldest frame first); `outbound` is filled by
/// `transmit()`/the receive-token's companion tx-token, then drained by [`run`] after each poll.
struct ChannelDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl ChannelDevice {
    fn new(mtu: usize) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            mtu,
        }
    }
}

struct RxToken(Vec<u8>);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct TxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> smoltcp::phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.outbound.push_back(buf);
        result
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.inbound.pop_front()?;
        Some((
            RxToken(frame),
            TxToken {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

/// Build the `smoltcp` interface with exactly one address of its own (`config.interface_addr`) plus
/// a route for the WHOLE CIDR via that same address with `AnyIP` enabled — this is what lets the
/// interface accept a connection to any of the (many, dynamically-allocated) synthetic addresses
/// without pre-registering each one as "its own" (`smoltcp::iface::Interface::set_any_ip`'s own doc:
/// "a route prefix specifies one of the interface's ip_addrs as its gateway" — see the module doc).
fn configure_interface(device: &mut ChannelDevice, config: &NetStackConfig) -> Interface {
    // `smoltcp::wire::Ipv4Address` is a plain re-export of `std::net::Ipv4Addr` (smoltcp 0.12 —
    // `pub use core::net::Ipv4Addr as Address`), so every `Ipv4Addr` value already in `config`
    // plugs directly into `IpAddress`/`Ipv4Cidr` below with no conversion helper needed.
    let iface_config = IfaceConfig::new(HardwareAddress::Ip);
    let mut iface = Interface::new(iface_config, device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(config.interface_addr), 32));
    });
    iface.routes_mut().update(|storage| {
        let _ = storage.push(Route {
            cidr: IpCidr::Ipv4(smoltcp::wire::Ipv4Cidr::new(
                config.cidr.network(),
                config.cidr.prefix_len(),
            )),
            via_router: IpAddress::Ipv4(config.interface_addr),
            preferred_until: None,
            expires_at: None,
        });
    });
    iface.set_any_ip(true);
    iface
}

/// One tracked connection: the `smoltcp` socket handle plus the two bridge channels to its (lazily
/// started, once the socket is `Established`) overlay-`Flow` task.
struct Conn {
    service: String,
    dst: (Ipv4Addr, u16),
    bridge_started: bool,
    /// Poll loop → bridge task (bytes read off the `smoltcp` socket). Kept even after the bridge
    /// starts so `is_closed()` tells the poll loop the overlay side gave up reading.
    to_app_tx: mpsc::Sender<Vec<u8>>,
    to_app_rx_holder: Option<mpsc::Receiver<Vec<u8>>>,
    /// Bridge task → poll loop (bytes read off the overlay `Flow`, waiting to go into the socket).
    from_app_rx: mpsc::Receiver<Vec<u8>>,
    from_app_tx_holder: Option<mpsc::Sender<Vec<u8>>>,
    /// Bytes pulled from `from_app_rx` that didn't fully fit in the socket's send buffer yet.
    pending_to_tun: Vec<u8>,
}

/// Run the netstack to completion: configure the interface, then loop until `shutdown` fires or
/// `raw_in` closes (the device reader task is gone — nothing more will ever arrive). Pumps raw
/// frames between `raw_in`/`raw_out` and the `smoltcp` interface, dynamically creates a listening
/// socket for each fresh `SYN` to a known-allocated destination, and bridges every connection that
/// reaches `Established` to [`Tunnel::open`] (module doc — the plan §5 invariant).
///
/// Takes `raw_in`/`raw_out` rather than a device directly so the plan §6 E2E test (and the
/// `cargo-fuzz` target) can drive this with **no real TUN device** — see the module doc.
pub async fn run(
    config: NetStackConfig,
    mut raw_in: mpsc::Receiver<Vec<u8>>,
    raw_out: mpsc::Sender<Vec<u8>>,
    tunnel: Arc<Tunnel>,
    allocator: Arc<SyntheticIpAllocator>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut device = ChannelDevice::new(config.mtu);
    let mut iface = configure_interface(&mut device, &config);
    let mut sockets = SocketSet::new(Vec::new());
    let mut conns: HashMap<smoltcp::iface::SocketHandle, Conn> = HashMap::new();
    let mut listening: HashMap<(Ipv4Addr, u16), smoltcp::iface::SocketHandle> = HashMap::new();

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            maybe = raw_in.recv() => {
                match maybe {
                    Some(frame) => device.inbound.push_back(frame),
                    None => break,
                }
            }
            () = tokio::time::sleep(POLL_TICK) => {}
        }
        // Drain whatever else already arrived without waiting again this iteration.
        while let Ok(frame) = raw_in.try_recv() {
            device.inbound.push_back(frame);
        }

        accept_fresh_syns(
            &device.inbound,
            &config,
            &allocator,
            &mut sockets,
            &mut conns,
            &mut listening,
        );

        iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        while let Some(frame) = device.outbound.pop_front() {
            if raw_out.try_send(frame).is_err() {
                break; // writer backpressured/gone — drop the rest this round, TCP retransmits
            }
        }

        service_connections(&tunnel, &mut sockets, &mut conns, &mut listening);
    }
}

/// Pre-scan (plan §3.5): for every fresh `SYN` in `inbound` that targets an address this process
/// actually allocated (via `allocator.resolve` — **never** an unconditional accept) and that isn't
/// already listening/connected/over the connection cap, insert a freshly-listening socket so THIS
/// SAME `poll()` call routes the `SYN` into it.
fn accept_fresh_syns(
    inbound: &VecDeque<Vec<u8>>,
    config: &NetStackConfig,
    allocator: &SyntheticIpAllocator,
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<smoltcp::iface::SocketHandle, Conn>,
    listening: &mut HashMap<(Ipv4Addr, u16), smoltcp::iface::SocketHandle>,
) {
    for frame in inbound {
        let Some(info) = peek_tcp(frame) else {
            continue;
        };
        if !info.is_fresh_syn() {
            continue;
        }
        if !config.cidr.contains(info.dst.0) {
            continue; // defensive — kernel routing already scopes inbound traffic to our CIDR
        }
        if listening.contains_key(&info.dst) {
            continue; // already have a listener waiting on this exact (addr, port)
        }
        if conns.len() >= MAX_CONNECTIONS {
            continue; // plan §5 total-connection bound — silently refuse, peer's TCP retries
        }
        // THE plan §5 gate: a destination this process never allocated (via DNS, plan §3.3) gets
        // no socket at all — scanning other addresses in the routed CIDR dials nothing.
        let Some(service) = allocator.resolve(info.dst.0) else {
            tracing::debug!(dst = ?info.dst, "boatramp tunnel: fresh SYN to an unallocated address — ignored");
            continue;
        };
        tracing::debug!(dst = ?info.dst, %service, "boatramp tunnel: fresh SYN to a known service — creating a listening socket");

        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; RX_BUFFER_SIZE]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; TX_BUFFER_SIZE]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let endpoint = SocketAddrV4::new(info.dst.0, info.dst.1);
        if socket.listen(endpoint).is_err() {
            continue; // e.g. an unaddressable endpoint — drop, never panic
        }
        let handle = sockets.add(socket);
        listening.insert(info.dst, handle);

        let (to_app_tx, to_app_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (from_app_tx, from_app_rx) = mpsc::channel(CHANNEL_CAPACITY);
        conns.insert(
            handle,
            Conn {
                service,
                dst: info.dst,
                bridge_started: false,
                to_app_tx,
                to_app_rx_holder: Some(to_app_rx),
                from_app_rx,
                from_app_tx_holder: Some(from_app_tx),
                pending_to_tun: Vec::new(),
            },
        );
    }
}

/// Service every tracked connection for one poll iteration: start the bridge task once a socket
/// reaches `Established`, shuttle bytes both directions, and tear down anything the `smoltcp`
/// socket itself has fully closed or that the overlay side has walked away from.
fn service_connections(
    tunnel: &Arc<Tunnel>,
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<smoltcp::iface::SocketHandle, Conn>,
    listening: &mut HashMap<(Ipv4Addr, u16), smoltcp::iface::SocketHandle>,
) {
    let mut to_remove = Vec::new();

    for (&handle, conn) in conns.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        // Security review MEDIUM-4 (the cheap half): gate on `State::Established` — the handshake
        // FULLY complete — not `is_active()`, which is already true in `SynReceived` (right after
        // this process's own SYN-ACK, before the peer's final ACK ever arrives). A bare SYN with
        // no completing ACK must drive NO dial: `is_active()` would have started the bridge (and
        // so the overlay dial) on the SYN alone, letting a peer that never finishes a single
        // handshake still trigger a mint per spoofed/incomplete attempt. The full idle/half-open
        // socket reaper (a `SynReceived` connection that never completes at all, tying up a slot
        // until `smoltcp`'s own retransmit timeout gives up) is deferred to R5 — this gate alone
        // only narrows WHEN the dial fires, not how long an incomplete attempt occupies a slot.
        if !conn.bridge_started && socket.state() == tcp::State::Established {
            conn.bridge_started = true;
            tracing::debug!(service = %conn.service, dst = ?conn.dst, "boatramp tunnel: TUN connection established — starting overlay bridge/dial");
            listening.remove(&conn.dst);
            let to_app_rx = conn
                .to_app_rx_holder
                .take()
                .expect("set exactly once at connection creation, taken exactly once here");
            let from_app_tx = conn
                .from_app_tx_holder
                .take()
                .expect("set exactly once at connection creation, taken exactly once here");
            tokio::spawn(bridge(
                Arc::clone(tunnel),
                conn.service.clone(),
                to_app_rx,
                from_app_tx,
            ));
        }

        if socket.state() == tcp::State::Closed {
            to_remove.push(handle);
            continue;
        }

        // smoltcp socket → bridge task (TUN side has data for the overlay Flow). A full channel
        // just leaves the bytes in smoltcp's own (bounded, `RX_BUFFER_SIZE`) receive buffer —
        // backpressure, not data loss, and retried next iteration.
        if socket.can_recv()
            && let Ok(permit) = conn.to_app_tx.try_reserve()
            && let Ok(bytes) = socket.recv(|buf| (buf.len(), buf.to_vec()))
            && !bytes.is_empty()
        {
            permit.send(bytes);
        }

        // bridge task → smoltcp socket (overlay Flow has data for the TUN side).
        if conn.pending_to_tun.is_empty()
            && let Ok(bytes) = conn.from_app_rx.try_recv()
        {
            conn.pending_to_tun = bytes;
        }
        if !conn.pending_to_tun.is_empty()
            && socket.can_send()
            && let Ok(sent) = socket.send_slice(&conn.pending_to_tun)
        {
            conn.pending_to_tun.drain(..sent);
        }

        // The overlay side is done (its read-from-Flow task ended, dropping its sender) and every
        // byte it ever handed us has been pushed into the socket ⇒ half-close the TUN side so the
        // local peer observes EOF too.
        if conn.to_app_tx.is_closed() && conn.pending_to_tun.is_empty() && socket.may_send() {
            socket.close();
        }
    }

    for handle in to_remove {
        if let Some(conn) = conns.remove(&handle) {
            listening.remove(&conn.dst);
        }
        sockets.remove(handle);
    }
}

/// The `cargo-fuzz` entry point (plan §5/§6 — `crates/boatramp-overlay-tunnel/fuzz`, target
/// `fuzz_netstack_ingress`, mirroring `boatramp-http/fuzz`'s existing layout/convention). Drives
/// `data` through EXACTLY the same two steps [`run`]'s loop does for one inbound frame —
/// [`accept_fresh_syns`]'s pre-scan (itself built on [`super::packet::peek_tcp`]) and one
/// `smoltcp` `Interface::poll()` — synchronously and runtime-free (no tokio, no channels, no
/// `Tunnel`): this isolates exactly the security-sensitive PARSING surface (plan §5) fuzzing needs
/// to hammer, not the async bridging machinery around it.
///
/// Runs `data` TWICE, against two independent, freshly-built interfaces:
/// 1. **Raw** — `data` fed in completely unstructured, address/protocol bytes included. This is
///    plan §5's literal "never panic on arbitrary bytes" requirement.
/// 2. **Anchored** — the SAME bytes, but with the IP version/IHL, protocol, and destination
///    address fields pinned so the frame targets a pre-allocated service's address with TCP as the
///    protocol. Unstructured mutation alone is astronomically unlikely to ever produce a byte
///    sequence that reaches the listening/`Established`/data-transfer code paths inside
///    `smoltcp`'s TCP state machine; pinning just enough of the header to GUARANTEE a matching
///    socket gets created lets the fuzzer spend its mutation budget on the flags/sequence numbers/
///    options/payload bytes that actually exercise those deeper paths, while they remain fully
///    attacker-controlled.
///
/// **Must never panic, and must never grow memory unboundedly, on ANY input** — that is this
/// function's entire contract; a `cargo-fuzz` crash report on either property is a finding.
pub fn fuzz_one_frame(data: &[u8]) {
    let config = NetStackConfig {
        interface_addr: Ipv4Addr::new(100, 64, 0, 1),
        cidr: super::cidr::default_cidr(),
        mtu: 1500,
    };
    // One allocator shared by both variants below, so "anchored"'s pinned destination is a REAL
    // allocated address (plan §5's own gate: `accept_fresh_syns` only ever creates a socket for a
    // destination `allocator.resolve` recognizes) rather than a hardcoded constant that would
    // silently stop being meaningful if the allocation scheme ever changes.
    let allocator = SyntheticIpAllocator::new(config.cidr);
    let fuzz_addr = allocator
        .allocate("svc/fuzz-target")
        .expect("a single allocation from a freshly-built pool never exhausts it");

    drive_one_frame(&config, &allocator, data);

    if data.len() >= 20 {
        let mut anchored = data.to_vec();
        anchored[0] = 0x45; // version 4, IHL 5 (20-byte header, no options) — keep it parseable
        anchored[9] = 6; // protocol TCP
        anchored[16..20].copy_from_slice(&fuzz_addr.octets());
        drive_one_frame(&config, &allocator, &anchored);
    }
}

/// Build a fresh interface + socket set, feed `frame` in as the one queued inbound frame, run the
/// pre-scan + exactly one `poll()` — [`fuzz_one_frame`]'s shared plumbing for both its variants.
fn drive_one_frame(config: &NetStackConfig, allocator: &SyntheticIpAllocator, frame: &[u8]) {
    let mut device = ChannelDevice::new(config.mtu);
    let mut iface = configure_interface(&mut device, config);
    let mut sockets = SocketSet::new(Vec::new());
    let mut conns: HashMap<smoltcp::iface::SocketHandle, Conn> = HashMap::new();
    let mut listening: HashMap<(Ipv4Addr, u16), smoltcp::iface::SocketHandle> = HashMap::new();

    device.inbound.push_back(frame.to_vec());
    accept_fresh_syns(
        &device.inbound,
        config,
        allocator,
        &mut sockets,
        &mut conns,
        &mut listening,
    );
    iface.poll(SmolInstant::now(), &mut device, &mut sockets);
}

/// The per-connection overlay bridge (module doc — the plan §5 invariant lives here: `service` is
/// a NAME, resolved by the allocator from a destination address long before this function ever
/// runs, and is the only thing [`Tunnel::open`] ever sees). Spawned once a `smoltcp` socket reaches
/// `Established`; ends (dropping both channel halves, which the poll loop observes as closure) when
/// either side is done.
async fn bridge(
    tunnel: Arc<Tunnel>,
    service: String,
    mut to_app_rx: mpsc::Receiver<Vec<u8>>,
    from_app_tx: mpsc::Sender<Vec<u8>>,
) {
    let flow = match tunnel.open(&service).await {
        Ok(flow) => flow,
        Err(err) => {
            tracing::debug!(
                %service, error = %err,
                "boatramp tunnel: TUN connection's overlay dial failed; closing"
            );
            return; // dropping `from_app_tx` tells the poll loop to half-close the TUN socket
        }
    };
    let (mut flow_read, mut flow_write) = tokio::io::split(flow);

    let read_overlay = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match flow_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if from_app_tx.send(buf[..n].to_vec()).await.is_err() {
                        break; // poll loop tore the connection down from the TUN side
                    }
                }
            }
        }
    };
    let write_overlay = async {
        while let Some(bytes) = to_app_rx.recv().await {
            if flow_write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = flow_write.shutdown().await;
    };
    tokio::join!(read_overlay, write_overlay);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{MockControlPlane, entry_at};
    use boatramp_overlay_client::OverlaySecret;
    use std::net::SocketAddr;

    fn test_config() -> NetStackConfig {
        let cidr: super::super::cidr::Ipv4Cidr = "10.99.0.0/24".parse().unwrap();
        NetStackConfig {
            interface_addr: cidr.hosts().next().unwrap(),
            cidr,
            mtu: 1500,
        }
    }

    /// Builds a minimal IPv4 + TCP frame (no options, no payload beyond `data`).
    fn build_frame(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        flags: u8,
        seq: u32,
        ack: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 20 + data.len();
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[8] = 64; // TTL
        buf[9] = 6; // TCP
        buf[12..16].copy_from_slice(&src.0.octets());
        buf[16..20].copy_from_slice(&dst.0.octets());
        let tcp = &mut buf[20..];
        tcp[0..2].copy_from_slice(&src.1.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst.1.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4; // data offset = 5 words (20 bytes), no options
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window
        tcp[20..].copy_from_slice(data);
        fixup_ipv4_checksum(&mut buf);
        fixup_tcp_checksum(&mut buf);
        buf
    }

    fn fixup_ipv4_checksum(buf: &mut [u8]) {
        buf[10] = 0;
        buf[11] = 0;
        let sum = internet_checksum(&buf[0..20]);
        buf[10..12].copy_from_slice(&sum.to_be_bytes());
    }

    fn fixup_tcp_checksum(buf: &mut [u8]) {
        let src: [u8; 4] = buf[12..16].try_into().unwrap();
        let dst: [u8; 4] = buf[16..20].try_into().unwrap();
        let tcp_len = buf.len() - 20;
        buf[20 + 16] = 0;
        buf[20 + 17] = 0;
        let mut pseudo = Vec::with_capacity(12 + tcp_len);
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.push(0);
        pseudo.push(6); // protocol TCP
        pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&buf[20..]);
        let sum = internet_checksum(&pseudo);
        buf[20 + 16..20 + 18].copy_from_slice(&sum.to_be_bytes());
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let (pairs, rest) = data.as_chunks::<2>();
        for chunk in pairs {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let [last] = rest {
            sum += u32::from(*last) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Plan §6's headline E2E test: feed a crafted `SYN` and then a data segment DIRECTLY into the
    /// netstack (no real device — `raw_in`/`raw_out` are plain channels) and assert the round trip
    /// reaches a mock `ControlPlane`'s dial — proving the smoltcp-direct path, the allocator, and
    /// `Tunnel::open` are wired correctly end to end, with NO privilege and NO real TUN device.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_crafted_syn_and_data_frame_drives_a_dial_through_the_mock_control_plane() {
        let backend: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cp = Arc::new(MockControlPlane::new(vec![entry_at(
            "svc/db", backend, true,
        )]));
        let holder = OverlaySecret::generate().unwrap();
        let tunnel = Tunnel::new(
            Arc::clone(&cp) as Arc<dyn crate::core::ControlPlane>,
            holder,
        )
        .await
        .unwrap();

        let config = test_config();
        let allocator = Arc::new(SyntheticIpAllocator::new(config.cidr));
        let dst_addr = allocator.allocate("svc/db").unwrap();

        let (raw_in_tx, raw_in_rx) = mpsc::channel(16);
        let (raw_out_tx, mut raw_out_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(run(
            config,
            raw_in_rx,
            raw_out_tx,
            Arc::clone(&tunnel),
            Arc::clone(&allocator),
            shutdown_rx,
        ));

        let client = (Ipv4Addr::new(10, 1, 1, 1), 51000);
        let dst = (dst_addr, 5432);

        // A fresh SYN to the allocated service address — must drive a listening socket into
        // existence and (since the mock control plane always resolves `svc/db`) a mint call.
        raw_in_tx
            .send(build_frame(client, dst, 0x02, 1000, 0, &[]))
            .await
            .unwrap();

        // The netstack's own SYN-ACK must come back out on `raw_out` within a short bound.
        let syn_ack = tokio::time::timeout(Duration::from_secs(5), raw_out_rx.recv())
            .await
            .expect("a SYN-ACK must be produced")
            .expect("raw_out must not have closed");
        let info = peek_tcp(&syn_ack).expect("must be a parseable TCP segment");
        assert!(info.syn && info.ack, "expected a SYN-ACK");

        // Complete the handshake (ACK) — this promotes the socket to Established and starts the
        // bridge task, which calls `Tunnel::open("svc/db")` against the mock control plane.
        raw_in_tx
            .send(build_frame(
                client,
                dst,
                0x10,
                1001,
                info_seq(&syn_ack) + 1,
                &[],
            ))
            .await
            .unwrap();

        // Give the bridge task a moment to run its dial (against the mock control plane, which
        // never touches the network) — polling `mint_calls` rather than a fixed sleep.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if cp.mint_calls.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the TUN connection must drive an overlay dial");

        // THE plan §5 assertion: the dial reached the mock control plane for `svc/db` — the exact
        // canonical SERVICE NAME, never the synthetic address `dst_addr`. `MockControlPlane` itself
        // only ever receives a `&str` service name (see `core::control_plane::ControlPlane`'s
        // signature) — there is no address parameter for an IP to have leaked through even if this
        // test tried to smuggle one in.
        assert_eq!(cp.mint_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    /// Extracts the TCP sequence number from a raw frame built the same way `build_frame` does —
    /// test-only plumbing to ACK the netstack's own SYN-ACK with the right number.
    fn info_seq(frame: &[u8]) -> u32 {
        let ihl = usize::from(frame[0] & 0x0f) * 4;
        u32::from_be_bytes([
            frame[ihl + 4],
            frame[ihl + 5],
            frame[ihl + 6],
            frame[ihl + 7],
        ])
    }

    /// Security review MEDIUM-4 (the cheap half), directly: a bare `SYN` with no completing `ACK`
    /// must drive NO dial at all — only once the handshake actually reaches `Established` does
    /// the bridge (and so the overlay dial) start. Before this fix, `is_active()` already covered
    /// `SynReceived` (right after this process's own `SYN-ACK`, before the peer's final `ACK` ever
    /// arrives), so a `SYN` alone would have triggered a mint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bare_syn_drives_no_dial_but_a_completed_handshake_does() {
        let backend: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cp = Arc::new(MockControlPlane::new(vec![entry_at(
            "svc/db", backend, true,
        )]));
        let holder = OverlaySecret::generate().unwrap();
        let tunnel = Tunnel::new(
            Arc::clone(&cp) as Arc<dyn crate::core::ControlPlane>,
            holder,
        )
        .await
        .unwrap();

        let config = test_config();
        let allocator = Arc::new(SyntheticIpAllocator::new(config.cidr));
        let dst_addr = allocator.allocate("svc/db").unwrap();

        let (raw_in_tx, raw_in_rx) = mpsc::channel(16);
        let (raw_out_tx, mut raw_out_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(run(
            config,
            raw_in_rx,
            raw_out_tx,
            Arc::clone(&tunnel),
            Arc::clone(&allocator),
            shutdown_rx,
        ));

        let client = (Ipv4Addr::new(10, 1, 1, 1), 51000);
        let dst = (dst_addr, 5432);

        // The bare SYN — no completing ACK follows yet.
        raw_in_tx
            .send(build_frame(client, dst, 0x02, 2000, 0, &[]))
            .await
            .unwrap();
        let syn_ack = tokio::time::timeout(Duration::from_secs(5), raw_out_rx.recv())
            .await
            .expect("a SYN-ACK must be produced")
            .expect("raw_out must not have closed");
        assert!(peek_tcp(&syn_ack).unwrap().ack);

        // Give the (would-be) bridge task every chance to have started and dialed — then assert
        // it did NOT. A short, bounded wait rather than a fixed sleep: there is nothing to poll
        // FOR here (the assertion is an absence), so this is deliberately generous (500ms).
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cp.mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a bare SYN (SynReceived, not yet Established) must never drive an overlay dial"
        );

        // NOW complete the handshake — this is the one thing that must flip the gate.
        raw_in_tx
            .send(build_frame(
                client,
                dst,
                0x10,
                2001,
                info_seq(&syn_ack) + 1,
                &[],
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if cp.mint_calls.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a COMPLETED handshake must drive the overlay dial");

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    /// Plan §5: a SYN to an address this process never allocated must drive NO dial at all — the
    /// allocator's reverse map is the only gate, and it is a hard deny, not an open-by-default.
    /// `accept_fresh_syns` itself never creates a socket for such a destination (so NOTHING in
    /// `conns`/`listening` is ever created, and [`Tunnel::open`]/the mock control plane's mint are
    /// never reached) — but the frame is still "deliverable" at the IP layer (`AnyIP` + the
    /// route-to-self cover the whole CIDR, by design, so the interface itself doesn't leak WHICH
    /// addresses are allocated via "deliverable vs. not"), so `smoltcp`'s OWN no-matching-socket
    /// logic may still emit a plain TCP RST — standard, information-free TCP behavior (the same
    /// thing a closed port replies with on a real OS), asserted below to be exactly that and never
    /// a `SYN-ACK` (which would mean a connection was actually accepted).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_syn_to_an_unallocated_address_drives_no_dial_and_is_never_accepted() {
        let cp = Arc::new(MockControlPlane::new(vec![]));
        let holder = OverlaySecret::generate().unwrap();
        let tunnel = Tunnel::new(
            Arc::clone(&cp) as Arc<dyn crate::core::ControlPlane>,
            holder,
        )
        .await
        .unwrap();
        let config = test_config();
        let allocator = Arc::new(SyntheticIpAllocator::new(config.cidr));
        // Deliberately never allocated — e.g. an address a scanner might probe.
        let never_allocated = Ipv4Addr::new(10, 99, 0, 77);

        let (raw_in_tx, raw_in_rx) = mpsc::channel(16);
        let (raw_out_tx, mut raw_out_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(run(
            config,
            raw_in_rx,
            raw_out_tx,
            tunnel,
            allocator,
            shutdown_rx,
        ));

        raw_in_tx
            .send(build_frame(
                (Ipv4Addr::new(10, 1, 1, 1), 1),
                (never_allocated, 5432),
                0x02,
                1,
                0,
                &[],
            ))
            .await
            .unwrap();

        // Whatever (if anything) comes back within a generous bounded window, it must never be a
        // SYN-ACK (an actually-accepted connection) — and either way, no dial may ever happen.
        if let Ok(Some(reply)) =
            tokio::time::timeout(Duration::from_millis(300), raw_out_rx.recv()).await
        {
            let info = peek_tcp(&reply).expect("must be a parseable TCP segment");
            assert!(
                !(info.syn && info.ack),
                "an unallocated destination must never be accepted with a SYN-ACK"
            );
        }
        assert_eq!(
            cp.mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an unallocated destination must drive NO overlay dial at all"
        );

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    /// A stable (non-nightly, always-run-in-CI) regression net for [`fuzz_one_frame`] — mirrors
    /// `boatramp-http/fuzz`'s own split between a `cargo +nightly fuzz run` target (open-ended,
    /// manual) and a plain `#[test]` smoke check (deterministic, part of every `cargo test`).
    /// Covers: empty input, inputs too short for any header, a plausible-looking but garbage IPv4
    /// header, and a byte pattern deliberately shaped to pass `peek_tcp`'s checks (so BOTH
    /// `fuzz_one_frame`'s "raw" and "anchored" variants reach the `smoltcp` poll call, not just
    /// the early-return paths).
    #[test]
    fn fuzz_one_frame_never_panics_on_a_handful_of_edge_cases() {
        fuzz_one_frame(&[]);
        fuzz_one_frame(&[0u8; 1]);
        fuzz_one_frame(&[0u8; 19]); // one byte short of a minimal IPv4 header
        fuzz_one_frame(&[0xffu8; 20]); // a 20-byte header of all-ones garbage
        fuzz_one_frame(&[0x45u8; 40]); // version/IHL looks right, everything else garbage

        // A frame that `peek_tcp` parses as a real (if minimal) TCP SYN — exercises the deeper
        // "a socket gets created, smoltcp processes a real-looking segment" path too.
        let mut syn_like = vec![0u8; 40];
        syn_like[0] = 0x45;
        syn_like[9] = 6;
        syn_like[20 + 13] = 0x02; // SYN flag
        fuzz_one_frame(&syn_like);
    }
}
