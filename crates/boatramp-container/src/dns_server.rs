//! The internal-DNS **socket seam** (Linux) — binds `gateway:53`, reads each
//! datagram's source IP, and drives the pure [`Resolver`](crate::dns::Resolver).
//!
//! This is the Linux-gated half of the internal resolver: it owns the UDP socket
//! bound on the compute bridge gateway, so every co-located container (whose
//! `/etc/resolv.conf` names the gateway — see [`crate::resolvconf`]) reaches it.
//! Per datagram it:
//!
//! 1. reads the peer address (the querying container's bridge IP — the isolation
//!    anchor),
//! 2. snapshots the current fleet from the [`InternalDnsSource`] into the two
//!    closures the pure resolver needs (source-IP → project, `(project,workload)` →
//!    healthy replica IPs),
//! 3. calls [`Resolver::handle_query`], and
//! 4. either sends the built reply back, or **forwards** the original query to the
//!    configured upstream resolver and relays its response verbatim.
//!
//! The decision logic is entirely in [`crate::dns`] (host-tested on macOS); this
//! file is only the socket + forward plumbing, verified by review + the live
//! container seam. UDP only (a stub resolver's default); TCP fallback is a later
//! addition — a truncated internal answer is never produced (a workload has at most
//! a handful of replicas), and a forwarded UDP answer that sets TC is relayed as-is
//! so the guest can retry over TCP directly against the upstream if it must.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::dns::{Decision, ResolvedAddrs, Resolver};

/// The control-plane view the DNS server needs, implemented in `boatramp-node`
/// over the `DeployStore` replica state. Kept as a trait here so this crate stays
/// decoupled from `boatramp-core::deploy` (mirroring how the SQL binding reaches
/// the store through `ComputeEndpointResolver`).
#[async_trait::async_trait]
pub trait InternalDnsSource: Send + Sync {
    /// A snapshot of the current co-located fleet:
    /// * `owners`: bridge IP → `(project, workload)` for every known replica (the
    ///   source-IP → project reverse map), and
    /// * `addrs`: `(project, workload)` → the workload's **healthy** replica IPs,
    ///   primary-first (the name → IP forward map).
    ///
    /// Taken once per query so a launch/stop between datagrams is reflected without
    /// a restart. A cheap read against the KV; if it ever gets hot it can be cached
    /// with a short TTL, but correctness (freshness) is preferred here.
    async fn snapshot(&self) -> DnsFleet;
}

/// A point-in-time view of the co-located fleet for the resolver (see
/// [`InternalDnsSource::snapshot`]).
#[derive(Debug, Clone, Default)]
pub struct DnsFleet {
    /// Bridge IP → `(project, workload)` — the owner of each known replica IP.
    pub owners: std::collections::BTreeMap<Ipv4Addr, (String, String)>,
    /// `(project, workload)` → healthy replica IPs (primary-first), split by family.
    pub addrs: std::collections::BTreeMap<(String, String), ResolvedAddrs>,
}

/// Run the internal DNS responder until the process exits: bind UDP `gateway:53`
/// and serve queries, forwarding non-internal ones to `upstream`.
///
/// `domain` is the effective internal suffix (`compute.dns_domain`). Binding on the
/// gateway (not `0.0.0.0`) scopes the listener to the bridge — only co-located
/// containers can reach it — and needs the bridge already up with its gateway
/// address (ensured by [`ensure_bridge`](crate::ensure_bridge) before this runs).
///
/// Returns only on a fatal bind/setup error; the per-query loop logs and continues
/// past transient IO errors so one bad datagram never takes the resolver down.
pub async fn serve(
    gateway: Ipv4Addr,
    upstream: SocketAddr,
    domain: String,
    source: Arc<dyn InternalDnsSource>,
) -> std::io::Result<()> {
    let bind = SocketAddr::from((gateway, 53));
    let socket = Arc::new(tokio::net::UdpSocket::bind(bind).await?);
    tracing::info!(%bind, %upstream, %domain, "internal DNS resolver listening on the compute bridge gateway");
    // A DNS message over UDP is capped at 512 bytes (classic) / the EDNS-advertised
    // size; 1232 is the conservative modern default that avoids fragmentation.
    let mut buf = vec![0u8; 1232];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "internal DNS: recv_from failed; continuing");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        // Only IPv4 sources are co-located containers on the bridge; an IPv6 peer
        // (unexpected on the v4 bridge) is treated as unknown ⇒ forward-only, which
        // the resolver already does for an unknown source.
        let src = match peer {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };
        let socket = socket.clone();
        let source = source.clone();
        let domain = domain.clone();
        // Handle each query on its own task so a slow upstream forward never blocks
        // an internal answer for another container.
        tokio::spawn(async move {
            if let Err(e) = handle_one(&socket, upstream, &domain, &source, src, &query, peer).await
            {
                tracing::warn!(%e, %peer, "internal DNS: handling a query failed");
            }
        });
    }
}

/// Handle a single datagram: snapshot the fleet, decide, and either reply or
/// forward. Split out so the socket loop stays small and the forward path is
/// testable in isolation by review.
async fn handle_one(
    socket: &tokio::net::UdpSocket,
    upstream: SocketAddr,
    domain: &str,
    source: &Arc<dyn InternalDnsSource>,
    src: Ipv4Addr,
    query: &[u8],
    peer: SocketAddr,
) -> std::io::Result<()> {
    let fleet = source.snapshot().await;
    let resolver = Resolver::new(
        domain,
        |ip: Ipv4Addr| fleet.owners.get(&ip).cloned(),
        |p: &str, w: &str| {
            fleet
                .addrs
                .get(&(p.to_string(), w.to_string()))
                .cloned()
                .unwrap_or_default()
        },
    );
    match resolver.handle_query(src, query) {
        Decision::Reply(bytes) => {
            socket.send_to(&bytes, peer).await?;
        }
        Decision::Forward => {
            if let Some(reply) = forward(upstream, query).await {
                socket.send_to(&reply, peer).await?;
            }
        }
    }
    Ok(())
}

/// Forward `query` to `upstream` and return its raw response. A dedicated ephemeral
/// UDP socket per forward keeps the reply correlated to this query (no cross-talk),
/// and a short timeout means a dead upstream drops the query rather than hanging the
/// task. `None` on any timeout / IO error — the guest's stub resolver will retry.
async fn forward(upstream: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    /// How long to wait for the upstream resolver before giving up on this query.
    const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
    // Bind an ephemeral socket in the same family as the upstream.
    let bind: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let up = tokio::net::UdpSocket::bind(bind).await.ok()?;
    up.connect(upstream).await.ok()?;
    up.send(query).await.ok()?;
    let mut reply = vec![0u8; 1232];
    let n = tokio::time::timeout(UPSTREAM_TIMEOUT, up.recv(&mut reply))
        .await
        .ok()?
        .ok()?;
    reply.truncate(n);
    Some(reply)
}
