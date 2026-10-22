//! A tiny hand-rolled IPv4 CIDR type (plan §3.2/§3.4): just enough to parse `--cidr` (default
//! `100.64.0.0/10`, RFC 6598 CGNAT space), test address membership (the synthetic-IP allocator's
//! exhaustion bound, and the netstack's "is this destination ours" filter), and enumerate the usable
//! host range. Deliberately not a dependency on a CIDR crate — a handful of u32 bit operations, same
//! hand-rolled-parsing posture as the SOCKS codec (plan §2) and the DNS zone handler (plan §3.3).

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An IPv4 network: a base address + prefix length (`0..=32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    /// The network address — always already masked to `prefix_len` by [`Ipv4Cidr::new`]/[`FromStr`]
    /// (a host bit set in the stored value would make [`Ipv4Cidr::contains`]/iteration wrong).
    network: Ipv4Addr,
    prefix_len: u8,
}

/// A malformed `--cidr`/`--dns-zone`-adjacent CIDR string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CidrError {
    #[error("`{0}` is not of the form `a.b.c.d/prefix`")]
    Malformed(String),
    #[error("bad IPv4 address `{0}`")]
    Addr(String),
    #[error("prefix length `{0}` is not in 0..=32")]
    Prefix(String),
}

impl Ipv4Cidr {
    /// Build a CIDR from a base address and prefix length, masking any host bits in `address` down
    /// to the network address (so `Ipv4Cidr::new(Ipv4Addr::new(100,64,0,5), 10)` is the same network
    /// as `100.64.0.0/10` — mirrors how every real CIDR parser normalizes its input).
    #[must_use]
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Self {
        let prefix_len = prefix_len.min(32);
        let mask = Self::mask_for(prefix_len);
        let network = Ipv4Addr::from(u32::from(address) & mask);
        Self {
            network,
            prefix_len,
        }
    }

    fn mask_for(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix_len))
        }
    }

    #[must_use]
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The netmask as a dotted-quad address (what `tun-rs`'s builder and `net-route`'s gateway-free
    /// route both want, alongside the plain prefix length).
    #[must_use]
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(Self::mask_for(self.prefix_len))
    }

    /// Whether `addr` falls inside this network (network + broadcast addresses included — callers
    /// that need the usable host range use [`Ipv4Cidr::hosts`] instead).
    #[must_use]
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = Self::mask_for(self.prefix_len);
        (u32::from(addr) & mask) == u32::from(self.network)
    }

    /// Total address count in the network (`2^(32-prefix)`), capped at `u32::MAX` for `/0`.
    #[must_use]
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix_len))
    }

    /// The usable host range, excluding the network address itself and (for anything narrower than
    /// `/31`) the broadcast address — the range the synthetic-IP allocator draws from. A `/31` or
    /// `/32` (degenerate, never a real `--cidr` value) yields an empty range rather than panicking.
    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> + use<> {
        let start = u32::from(self.network).saturating_add(1);
        let end = if self.prefix_len >= 31 {
            start // empty range
        } else {
            u32::from(self.network).saturating_add(self.size() as u32 - 1) // exclude broadcast
        };
        (start..end).map(Ipv4Addr::from)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_part, prefix_part) = s
            .split_once('/')
            .ok_or_else(|| CidrError::Malformed(s.to_string()))?;
        let address: Ipv4Addr = addr_part
            .parse()
            .map_err(|_| CidrError::Addr(addr_part.to_string()))?;
        let prefix_len: u8 = prefix_part
            .parse()
            .map_err(|_| CidrError::Prefix(prefix_part.to_string()))?;
        if prefix_len > 32 {
            return Err(CidrError::Prefix(prefix_part.to_string()));
        }
        Ok(Self::new(address, prefix_len))
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// The plan's default (§3.2, RFC 6598 CGNAT space): non-routable, collides with neither RFC1918 nor
/// loopback.
#[must_use]
pub fn default_cidr() -> Ipv4Cidr {
    Ipv4Cidr::new(Ipv4Addr::new(100, 64, 0, 0), 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_plan_default() {
        let c: Ipv4Cidr = "100.64.0.0/10".parse().unwrap();
        assert_eq!(c, default_cidr());
        assert_eq!(c.to_string(), "100.64.0.0/10");
    }

    #[test]
    fn a_host_address_is_masked_down_to_the_network() {
        let c = Ipv4Cidr::new(Ipv4Addr::new(100, 64, 0, 200), 10);
        assert_eq!(c.network(), Ipv4Addr::new(100, 64, 0, 0));
    }

    #[test]
    fn contains_covers_the_whole_slash_10_and_excludes_outside() {
        let c = default_cidr();
        assert!(c.contains(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(c.contains(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!c.contains(Ipv4Addr::new(100, 128, 0, 0)));
        assert!(!c.contains(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn hosts_excludes_network_and_broadcast_for_a_small_subnet() {
        let c = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 30); // 4 addrs: .0 .1 .2 .3
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert!("not-a-cidr".parse::<Ipv4Cidr>().is_err());
        assert!("100.64.0.0/99".parse::<Ipv4Cidr>().is_err());
        assert!("100.64.0.0".parse::<Ipv4Cidr>().is_err());
        assert!("256.0.0.0/8".parse::<Ipv4Cidr>().is_err());
    }
}
