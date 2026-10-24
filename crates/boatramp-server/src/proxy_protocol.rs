//! PROXY protocol (HAProxy) v1 + v2 header parsing for host-owned `[serve.listeners]` (mailroom
//! cap-req 18 completion). When a listener sits behind an L4 proxy / load balancer, the kernel peer
//! address is the PROXY's, so the per-source-IP connection-rate limiter and the `peer` handed to the
//! guest would see every client as one IP. A trusted upstream prepends a PROXY-protocol header naming
//! the REAL client; [`read_proxy_header`] consumes + parses it and returns that address.
//!
//! # Trust model (load-bearing)
//! Parsing is **opt-in per listener** (`[serve.listeners.<name>] proxy_protocol = true`): the operator
//! asserts the listener is reachable ONLY through a trusted proxy. It is NEVER parsed on a plain
//! listener — otherwise a direct client could forge the header to spoof its source IP (bypassing the
//! rate limit and lying to the guest). When enabled, a connection that does NOT present a well-formed
//! header is dropped (fail-closed) rather than falling back to the kernel peer.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// v2 signature: the 12 fixed bytes every v2 header starts with.
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// v1 lines are at most 107 bytes incl. CRLF (RFC: "PROXY" + fields).
const V1_MAX: usize = 107;
/// Cap on the v2 address block we will read (the fixed TCP6 block is 36 bytes; extra is TLVs we
/// discard). A trusted proxy never sends a huge block; bound it so a misbehaving upstream can't make
/// us read unboundedly.
const V2_ADDR_MAX: usize = 1024;

/// Read + parse a PROXY-protocol header from `stream` (consuming exactly the header bytes — never any
/// application data past it), under `timeout`. Returns:
/// - `Ok(Some(src))` — a v1/v2 TCP4/TCP6 header naming the real client `src`.
/// - `Ok(None)` — a `LOCAL` (v2) / `UNKNOWN` (v1) header, or a non-TCP family: no client address is
///   asserted, so the caller uses the kernel peer (e.g. a proxy's own health check).
/// - `Err(_)` — no/!malformed header or timeout; the caller drops the connection (fail-closed).
pub async fn read_proxy_header<S>(
    stream: &mut S,
    timeout: Duration,
) -> io::Result<Option<SocketAddr>>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, read_header_inner(stream))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy-protocol header read timed out",
            )
        })?
}

async fn read_header_inner<S>(stream: &mut S) -> io::Result<Option<SocketAddr>>
where
    S: AsyncRead + Unpin,
{
    // One discriminating byte: 'P' (0x50) ⇒ v1 text; 0x0D ⇒ v2 binary (no valid v1 starts with 0x0D).
    let first = stream.read_u8().await?;
    match first {
        b'P' => read_v1(stream).await,
        0x0D => read_v2(stream).await,
        _ => Err(bad("not a PROXY-protocol header")),
    }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// v1: the rest of a CRLF-terminated ASCII line (the leading 'P' is already consumed).
async fn read_v1<S>(stream: &mut S) -> io::Result<Option<SocketAddr>>
where
    S: AsyncRead + Unpin,
{
    // Rebuild the full line starting with the consumed 'P'; read ONE byte at a time so we never read
    // past the terminating LF into application data. Bounded by V1_MAX.
    let mut line = Vec::with_capacity(V1_MAX);
    line.push(b'P');
    loop {
        let b = stream.read_u8().await?;
        line.push(b);
        if b == b'\n' {
            break;
        }
        if line.len() >= V1_MAX {
            return Err(bad("proxy-protocol v1 line too long / no CRLF"));
        }
    }
    parse_v1_line(&line)
}

/// Parse a complete v1 line (incl. trailing CRLF). `PROXY TCP4 <s> <d> <sp> <dp>\r\n`, `PROXY TCP6 …`,
/// or `PROXY UNKNOWN…\r\n` (⇒ `None`).
fn parse_v1_line(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    let s = std::str::from_utf8(line).map_err(|_| bad("proxy-protocol v1 not ASCII"))?;
    let s = s
        .strip_suffix("\r\n")
        .or_else(|| s.strip_suffix('\n'))
        .ok_or_else(|| bad("proxy-protocol v1 not CRLF-terminated"))?;
    let mut it = s.split(' ');
    if it.next() != Some("PROXY") {
        return Err(bad("proxy-protocol v1 missing PROXY tag"));
    }
    let proto = it
        .next()
        .ok_or_else(|| bad("proxy-protocol v1 missing protocol"))?;
    let is_v6 = match proto {
        "TCP4" => false,
        "TCP6" => true,
        // `UNKNOWN` (and any unrecognized proto) ⇒ no asserted client; use the kernel peer.
        _ => return Ok(None),
    };
    let src_ip = it
        .next()
        .ok_or_else(|| bad("proxy-protocol v1 missing src ip"))?;
    let _dst_ip = it
        .next()
        .ok_or_else(|| bad("proxy-protocol v1 missing dst ip"))?;
    let src_port = it
        .next()
        .ok_or_else(|| bad("proxy-protocol v1 missing src port"))?;
    let _dst_port = it
        .next()
        .ok_or_else(|| bad("proxy-protocol v1 missing dst port"))?;
    if it.next().is_some() {
        return Err(bad("proxy-protocol v1 trailing field"));
    }
    let port: u16 = src_port
        .parse()
        .map_err(|_| bad("proxy-protocol v1 bad src port"))?;
    let ip: IpAddr = if is_v6 {
        src_ip
            .parse::<Ipv6Addr>()
            .map_err(|_| bad("proxy-protocol v1 bad src ipv6"))?
            .into()
    } else {
        src_ip
            .parse::<Ipv4Addr>()
            .map_err(|_| bad("proxy-protocol v1 bad src ipv4"))?
            .into()
    };
    Ok(Some(SocketAddr::new(ip, port)))
}

/// v2: the fixed 16-byte header (the first signature byte `0x0D` is already consumed) + the address
/// block. Returns the src address for a `PROXY` command over TCP4/TCP6; `None` for `LOCAL` / a
/// non-TCP family.
async fn read_v2<S>(stream: &mut S) -> io::Result<Option<SocketAddr>>
where
    S: AsyncRead + Unpin,
{
    // Read the remaining 15 bytes of the 16-byte fixed header (sig[1..12], ver_cmd, fam_proto, len·2).
    let mut rest = [0u8; 15];
    stream.read_exact(&mut rest).await?;
    // Verify the full 12-byte signature (byte 0 was the consumed 0x0D).
    if rest[..11] != V2_SIG[1..] {
        return Err(bad("proxy-protocol v2 bad signature"));
    }
    let ver_cmd = rest[11];
    let fam_proto = rest[12];
    let len = u16::from_be_bytes([rest[13], rest[14]]) as usize;
    if (ver_cmd >> 4) != 0x2 {
        return Err(bad("proxy-protocol v2 bad version"));
    }
    if len > V2_ADDR_MAX {
        return Err(bad("proxy-protocol v2 address block too large"));
    }
    // Read the whole declared address block (addresses + any trailing TLVs); we parse the leading
    // addresses and discard the rest.
    let mut addr = vec![0u8; len];
    stream.read_exact(&mut addr).await?;

    let command = ver_cmd & 0x0F; // 0x0 LOCAL, 0x1 PROXY
    let family = fam_proto >> 4; // 0x1 AF_INET, 0x2 AF_INET6
    // (low nibble is the transport; we accept STREAM/DGRAM alike — the caller only wants the IP.)
    if command == 0x0 {
        // LOCAL: the proxy's own connection (e.g. a health check) — no client asserted.
        return Ok(None);
    }
    if command != 0x1 {
        return Err(bad("proxy-protocol v2 unknown command"));
    }
    match family {
        0x1 => {
            // AF_INET: 4 src + 4 dst + 2 sport + 2 dport.
            if addr.len() < 12 {
                return Err(bad("proxy-protocol v2 ipv4 block too short"));
            }
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            let port = u16::from_be_bytes([addr[8], addr[9]]);
            Ok(Some(SocketAddr::new(ip.into(), port)))
        }
        0x2 => {
            // AF_INET6: 16 src + 16 dst + 2 sport + 2 dport.
            if addr.len() < 36 {
                return Err(bad("proxy-protocol v2 ipv6 block too short"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&addr[0..16]);
            let ip = Ipv6Addr::from(o);
            let port = u16::from_be_bytes([addr[32], addr[33]]);
            Ok(Some(SocketAddr::new(ip.into(), port)))
        }
        // AF_UNSPEC / anything else: no asserted client; use the kernel peer.
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    async fn parse(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
        let mut c = Cursor::new(bytes.to_vec());
        read_proxy_header(&mut c, Duration::from_secs(1)).await
    }

    #[tokio::test]
    async fn v1_tcp4() {
        let got = parse(b"PROXY TCP4 198.51.100.7 203.0.113.1 56324 443\r\n")
            .await
            .unwrap();
        assert_eq!(got, Some("198.51.100.7:56324".parse().unwrap()));
    }

    #[tokio::test]
    async fn v1_tcp6() {
        let got = parse(b"PROXY TCP6 2001:db8::7 2001:db8::1 56324 443\r\n")
            .await
            .unwrap();
        assert_eq!(got, Some("[2001:db8::7]:56324".parse().unwrap()));
    }

    #[tokio::test]
    async fn v1_unknown_is_none() {
        assert_eq!(parse(b"PROXY UNKNOWN\r\n").await.unwrap(), None);
    }

    #[tokio::test]
    async fn v1_does_not_overread() {
        // The application's first bytes follow the CRLF and must NOT be consumed by the parser.
        let mut c =
            Cursor::new(b"PROXY TCP4 198.51.100.7 203.0.113.1 1 2\r\nEHLO host\r\n".to_vec());
        let got = read_proxy_header(&mut c, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(got, Some("198.51.100.7:1".parse().unwrap()));
        let mut remaining = Vec::new();
        c.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(
            remaining, b"EHLO host\r\n",
            "application bytes after the header are untouched"
        );
    }

    #[tokio::test]
    async fn v2_tcp4() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21); // version 2, command PROXY
        h.push(0x11); // AF_INET + STREAM
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[198, 51, 100, 7]); // src
        h.extend_from_slice(&[203, 0, 113, 1]); // dst
        h.extend_from_slice(&40000u16.to_be_bytes()); // sport
        h.extend_from_slice(&443u16.to_be_bytes()); // dport
        assert_eq!(
            parse(&h).await.unwrap(),
            Some("198.51.100.7:40000".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn v2_local_is_none() {
        let mut h = V2_SIG.to_vec();
        h.push(0x20); // version 2, command LOCAL
        h.push(0x00); // AF_UNSPEC
        h.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse(&h).await.unwrap(), None);
    }

    #[tokio::test]
    async fn garbage_is_err() {
        // A direct client sending non-PROXY bytes to a proxy_protocol listener is dropped (fail-closed).
        assert!(parse(b"EHLO attacker\r\n").await.is_err());
    }
}
