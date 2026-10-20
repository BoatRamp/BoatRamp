//! ICE gathering — the network-facing half (IU-6).
//!
//! Builds the local [`CandidateSet`] from the pure model in [`boatramp_overlay_proto::ice`]: a host
//! candidate (this node's source IP toward the fabric, found by the connect-trick — no interface
//! enumeration), an optional server-reflexive candidate (the NAT's public mapping, learned via
//! STUN-lite over the E2EE signaling channel), and the relay candidate — the guaranteed floor. The
//! candidates are then exchanged over the sealed signaling channel (not a server) and used by the
//! direct-path negotiation (IU-7).

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use boatramp_overlay_proto::ice::{Candidate, CandidateKind, CandidateSet};

/// Learn the local source IP that routes **toward** `toward`, without enumerating interfaces: bind
/// the matching-family wildcard, `connect` to `toward` (UDP connect sends no packets — it only sets
/// the socket's default peer so the kernel picks the source), and read back the local address. The
/// `toward` address is a *local routing hint* (the relay/fabric address — "which of my IPs reaches
/// it"), never the peer's address.
pub fn default_route_ip(toward: SocketAddr) -> io::Result<IpAddr> {
    let wildcard: SocketAddr = if toward.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let probe = UdpSocket::bind(wildcard)?;
    probe.connect(toward)?;
    Ok(probe.local_addr()?.ip())
}

/// Gather this node's candidates toward the fabric, host-first. `local_port` is the overlay QUIC
/// endpoint's bound port (where a peer reaches this node directly); `reflexive` is the public
/// mapping if already observed; `relay` is the always-reachable floor.
pub fn gather(
    local_port: u16,
    toward: SocketAddr,
    reflexive: Option<SocketAddr>,
    relay: Option<SocketAddr>,
) -> io::Result<CandidateSet> {
    let mut set = CandidateSet::new();
    let host_ip = default_route_ip(toward)?;
    set.add(Candidate::new(
        CandidateKind::Host,
        SocketAddr::new(host_ip, local_port),
    ));
    if let Some(addr) = reflexive {
        set.add(Candidate::new(CandidateKind::ServerReflexive, addr));
    }
    if let Some(addr) = relay {
        set.add(Candidate::new(CandidateKind::Relay, addr));
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_ip_toward_loopback_is_loopback() {
        let ip = default_route_ip("127.0.0.1:9000".parse().unwrap()).unwrap();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn gather_is_host_first_with_the_relay_floor() {
        let toward = "127.0.0.1:9000".parse().unwrap();
        let relay: SocketAddr = "10.9.9.9:9000".parse().unwrap();
        let set = gather(5432, toward, None, Some(relay)).unwrap();

        // Host candidate carries the given local port; relay floor is present.
        let host = set
            .as_slice()
            .iter()
            .find(|c| c.kind == CandidateKind::Host)
            .expect("a host candidate");
        assert_eq!(host.addr.port(), 5432);
        assert!(
            set.as_slice()
                .iter()
                .any(|c| c.kind == CandidateKind::Relay && c.addr == relay)
        );
        // Priority order: host is tried before the relay.
        assert_eq!(set.as_slice()[0].kind, CandidateKind::Host);
    }
}
