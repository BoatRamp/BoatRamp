//! Minimal, panic-free IPv4 + TCP header peeking (pure, no I/O, no allocation beyond the caller's
//! own slice). [`netstack`](super::netstack) uses this to decide — BEFORE handing a raw frame to
//! the `smoltcp` poll loop — whether it is a fresh connection attempt that needs a freshly-listening
//! socket (plan §3.5). The same function is the `cargo-fuzz` target's entry point (plan §5/§6): the
//! exact code that parses arbitrary, attacker-controlled bytes in production is what gets fuzzed,
//! not a simplified stand-in.
//!
//! **Never panics, on any input of any length or content** — every slice index below is bounds-
//! checked first; a truncated, malformed, or hostile frame simply yields `None`.

use std::net::Ipv4Addr;

/// The handful of TCP segment fields the netstack's pre-scan needs: the 4-tuple + the two flags
/// that distinguish "fresh connection attempt" from everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegmentInfo {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
    pub syn: bool,
    pub ack: bool,
}

impl TcpSegmentInfo {
    /// A fresh connection attempt — `SYN` set, `ACK` clear (plan §3.5's pre-scan trigger: anything
    /// else — a retransmit against an existing connection, a `SYN-ACK`, a bare `ACK`/data segment —
    /// is left for the already-registered socket, never re-triggers listener creation).
    #[must_use]
    pub fn is_fresh_syn(&self) -> bool {
        self.syn && !self.ack
    }
}

/// IPv4 minimum header length (no options); anything shorter cannot be a valid IPv4 packet.
const IPV4_MIN_HEADER_LEN: usize = 20;
/// TCP minimum header length (no options) needed to read ports + the flags byte.
const TCP_MIN_HEADER_LEN: usize = 14;
/// IPv4 "protocol" field value for TCP (RFC 790).
const IP_PROTO_TCP: u8 = 6;
/// Byte offset of the IPv4 *source* address within the header (after version/IHL, DSCP/ECN,
/// total-length, identification, flags/fragment-offset, TTL, protocol, and header checksum).
const IPV4_SRC_ADDR_OFFSET: usize = 12;

/// Is `frame` an IPv4 packet whose **source** address is the unspecified address (`0.0.0.0`)?
///
/// This is the one inbound-frame shape the netstack must drop before `smoltcp` (0.12.0) ever sees
/// it. `smoltcp`'s own ingress filter (`iface/interface/ipv4.rs::process_ipv4`) deliberately lets a
/// packet with an unspecified *source* through — "Discard packets with non-unicast source addresses
/// but allow unspecified" — while dropping every *other* non-unicast source (broadcast, multicast).
/// That carve-out is for protocols like DHCP where a client has no address yet; this front-end runs
/// none (IPv4 + TCP only, no DHCP socket). The gap it leaves is a real, remotely-reachable panic:
/// when a freshly-listening socket ([`super::netstack`]'s `accept_fresh_syns`) accepts a `SYN` from
/// `0.0.0.0`, `smoltcp` builds a `SYN|ACK` whose *destination* is that same `0.0.0.0` and then trips
/// `assert!(!ip_repr.dst_addr().is_unspecified())` in `dispatch_ip`, **aborting the whole netstack
/// poll loop** (a crafted-`SYN` DoS against the TUN front-end; `smoltcp` 0.13+/0.14 fixed it by
/// dropping such packets in `process_tcp` *before* socket processing — we apply the identical
/// semantic one layer earlier, at our own ingress boundary, in [`super::netstack`]'s `ChannelDevice`).
/// A TCP service endpoint has no one to reply to at `0.0.0.0`, so dropping the frame loses nothing.
///
/// Bounds-checked throughout — **never panics**, on any input (the property the fuzz target asserts).
#[must_use]
pub fn ipv4_source_is_unspecified(frame: &[u8]) -> bool {
    frame.len() >= IPV4_MIN_HEADER_LEN
        && (frame[0] >> 4) == 4
        && frame[IPV4_SRC_ADDR_OFFSET] == 0
        && frame[IPV4_SRC_ADDR_OFFSET + 1] == 0
        && frame[IPV4_SRC_ADDR_OFFSET + 2] == 0
        && frame[IPV4_SRC_ADDR_OFFSET + 3] == 0
}

/// Best-effort peek at `frame` as an IPv4 packet carrying a TCP segment. `None` for anything that
/// is not well-formed enough to extract a 4-tuple + flags from: too short, wrong IP version, an IHL
/// claiming more than is actually present, or a non-TCP protocol. Bounds-checked throughout —
/// **never panics**, on any input (the property the fuzz target asserts).
#[must_use]
pub fn peek_tcp(frame: &[u8]) -> Option<TcpSegmentInfo> {
    if frame.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let version = frame[0] >> 4;
    if version != 4 {
        return None; // IPv6/garbage — this zone (plan §3.3/§3.4) is IPv4-only
    }
    let ihl_words = frame[0] & 0x0f;
    let ihl = usize::from(ihl_words) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || frame.len() < ihl {
        return None; // header length lies about what's actually present
    }
    let protocol = frame[9];
    if protocol != IP_PROTO_TCP {
        return None;
    }
    let src_ip = Ipv4Addr::new(frame[12], frame[13], frame[14], frame[15]);
    let dst_ip = Ipv4Addr::new(frame[16], frame[17], frame[18], frame[19]);

    let tcp = &frame[ihl..];
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];

    Some(TcpSegmentInfo {
        src: (src_ip, src_port),
        dst: (dst_ip, dst_port),
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal (no-options) IPv4 + TCP header for a test case; `payload` is appended but
    /// never inspected by `peek_tcp`.
    fn build_frame(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), flags: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + 20];
        buf[0] = 0x45; // version 4, IHL 5 (20 bytes)
        buf[9] = IP_PROTO_TCP;
        buf[12..16].copy_from_slice(&src.0.octets());
        buf[16..20].copy_from_slice(&dst.0.octets());
        buf[20..22].copy_from_slice(&src.1.to_be_bytes());
        buf[22..24].copy_from_slice(&dst.1.to_be_bytes());
        buf[20 + 13] = flags;
        buf
    }

    #[test]
    fn a_fresh_syn_is_recognized() {
        let src = (Ipv4Addr::new(100, 64, 0, 9), 51000);
        let dst = (Ipv4Addr::new(100, 64, 0, 2), 5432);
        let frame = build_frame(src, dst, 0x02); // SYN only
        let info = peek_tcp(&frame).unwrap();
        assert_eq!(info.src, src);
        assert_eq!(info.dst, dst);
        assert!(info.is_fresh_syn());
    }

    #[test]
    fn a_syn_ack_is_not_a_fresh_syn() {
        let frame = build_frame(
            (Ipv4Addr::new(10, 0, 0, 1), 1),
            (Ipv4Addr::new(10, 0, 0, 2), 2),
            0x12, // SYN + ACK
        );
        let info = peek_tcp(&frame).unwrap();
        assert!(!info.is_fresh_syn());
    }

    #[test]
    fn truncated_input_never_panics_and_yields_none() {
        for len in 0..24 {
            let frame = vec![0x45u8; len];
            assert!(peek_tcp(&frame).is_none(), "len={len} must not parse");
        }
    }

    #[test]
    fn a_non_ipv4_version_is_rejected() {
        let mut frame = build_frame(
            (Ipv4Addr::new(1, 1, 1, 1), 1),
            (Ipv4Addr::new(2, 2, 2, 2), 2),
            0x02,
        );
        frame[0] = 0x65; // version 6
        assert!(peek_tcp(&frame).is_none());
    }

    #[test]
    fn a_non_tcp_protocol_is_rejected() {
        let mut frame = build_frame(
            (Ipv4Addr::new(1, 1, 1, 1), 1),
            (Ipv4Addr::new(2, 2, 2, 2), 2),
            0x02,
        );
        frame[9] = 17; // UDP
        assert!(peek_tcp(&frame).is_none());
    }

    #[test]
    fn an_ihl_claiming_more_than_is_present_is_rejected_not_panicked() {
        let mut frame = build_frame(
            (Ipv4Addr::new(1, 1, 1, 1), 1),
            (Ipv4Addr::new(2, 2, 2, 2), 2),
            0x02,
        );
        frame[0] = 0x4f; // IHL = 15 words = 60 bytes, far more than this 40-byte buffer
        assert!(peek_tcp(&frame).is_none());
    }

    /// A direct, non-exhaustive proof of "never panics" over pseudo-random short/garbage buffers —
    /// the `cargo-fuzz` target (plan §5/§6) is the real, open-ended version of this assertion.
    #[test]
    fn arbitrary_byte_patterns_never_panic() {
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        for len in 0..128 {
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                // A tiny xorshift — deterministic, no new dependency.
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = (seed & 0xff) as u8;
            }
            let _ = peek_tcp(&buf); // must not panic regardless of outcome
        }
    }

    #[test]
    fn an_unspecified_ipv4_source_is_recognized() {
        // A well-formed IPv4 header whose source (bytes 12..16) is 0.0.0.0 — the shape the netstack
        // ingress drops to avoid the `smoltcp` `dispatch_ip` panic (see `ipv4_source_is_unspecified`).
        let frame = build_frame(
            (Ipv4Addr::UNSPECIFIED, 40000),
            (Ipv4Addr::new(100, 64, 0, 5), 443),
            0x02,
        );
        assert!(ipv4_source_is_unspecified(&frame));
    }

    #[test]
    fn a_unicast_ipv4_source_is_not_flagged() {
        let frame = build_frame(
            (Ipv4Addr::new(100, 64, 0, 9), 51000),
            (Ipv4Addr::new(100, 64, 0, 5), 443),
            0x02,
        );
        assert!(!ipv4_source_is_unspecified(&frame));
    }

    #[test]
    fn unspecified_source_check_is_bounds_safe_and_ipv4_only() {
        // Too short to hold a source address: must be `false`, never panic.
        for len in 0..IPV4_MIN_HEADER_LEN {
            assert!(!ipv4_source_is_unspecified(&vec![0u8; len]));
        }
        // All-zero but a non-IPv4 version nibble (here 0): not an IPv4 packet, so not our concern —
        // `smoltcp` drops it for an unknown version long before any reply is built.
        let mut not_v4 = vec![0u8; IPV4_MIN_HEADER_LEN];
        not_v4[0] = 0x60; // version 6
        assert!(!ipv4_source_is_unspecified(&not_v4));
    }
}
