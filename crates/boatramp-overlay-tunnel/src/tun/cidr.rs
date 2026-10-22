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

/// A malformed, or structurally unusable, `--cidr` string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CidrError {
    #[error("`{0}` is not of the form `a.b.c.d/prefix`")]
    Malformed(String),
    #[error("bad IPv4 address `{0}`")]
    Addr(String),
    #[error("prefix length `{0}` is not in 0..=32")]
    Prefix(String),
    /// Security review INFO: `/0` isn't just impractical, it's unrepresentable by this type's
    /// `u32`-based [`Ipv4Cidr::size`]/[`Ipv4Cidr::hosts`] arithmetic (`2^32` overflows `u32`,
    /// underflow-panicking `hosts()`'s `size() as u32 - 1` in a debug build) — rejected outright
    /// rather than ever reaching that arithmetic.
    #[error(
        "/0 has no usable host range this allocator can represent — pick a narrower prefix (the \
         default is /10)"
    )]
    ZeroPrefixUnsupported,
    /// Security review INFO: fewer than 2 usable host addresses means the TUN interface's own
    /// reserved address ([`super::alloc::SyntheticIpAllocator::reserve_interface_address`]) and the
    /// allocator's first allocation ([`super::alloc::SyntheticIpAllocator::allocate`]) COLLIDE on
    /// the same address (both fall back to [`Ipv4Cidr::network`] when [`Ipv4Cidr::hosts`] is
    /// empty) — rejected outright at parse time rather than silently colliding at runtime.
    #[error(
        "/{0} leaves fewer than 2 usable host addresses (one is needed for the TUN interface \
         itself, at least one more to allocate to a service) — use /30 or wider, e.g. the default \
         /10"
    )]
    TooNarrow(u8),
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

    /// Total address count in the network (`2^(32-prefix)`). **Only valid for `prefix_len >= 1`**
    /// — at `/0` this is `2^32`, which does not fit in the `u64` → `u32` narrowing [`Ipv4Cidr::hosts`]
    /// does with it (`FromStr` rejects `/0` outright — [`CidrError::ZeroPrefixUnsupported`] — for
    /// exactly this reason; [`Ipv4Cidr::new`] itself is NOT validated, so a direct, unvalidated
    /// `/0` construction followed by a `hosts()` call would still hit the stale arithmetic this
    /// comment used to (wrongly) call "capped").
    #[must_use]
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix_len))
    }

    /// The usable host range, excluding the network address itself and (for anything narrower than
    /// `/31`) the broadcast address — the range the synthetic-IP allocator draws from. A `/31` or
    /// `/32` (rejected by `FromStr` — [`CidrError::TooNarrow`] — but still reachable via the
    /// unvalidated [`Ipv4Cidr::new`]) yields an empty range rather than panicking.
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

    /// The validated entry point for untrusted input (`--cidr`, plan §3.2) — [`Ipv4Cidr::new`]
    /// itself stays a plain, unvalidated constructor for internal callers that already know their
    /// prefix is sane (this crate's own `default_cidr`/tests, both fixed literals).
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
        if prefix_len == 0 {
            return Err(CidrError::ZeroPrefixUnsupported);
        }
        if prefix_len > 30 {
            return Err(CidrError::TooNarrow(prefix_len));
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

    /// Security review INFO: `/0` is rejected outright (it would otherwise panic — or, in release,
    /// silently wrap — inside `hosts()`'s `size() as u32 - 1`), never reaching that arithmetic.
    #[test]
    fn rejects_slash_0() {
        let err = "100.64.0.0/0".parse::<Ipv4Cidr>().unwrap_err();
        assert!(matches!(err, CidrError::ZeroPrefixUnsupported));
    }

    /// Security review INFO: `/31` and `/32` leave fewer than 2 usable hosts — the TUN interface's
    /// own reserved address and the allocator's first allocation would otherwise collide (both fall
    /// back to the network address when `hosts()` is empty). `/30` (exactly 2 usable hosts) is the
    /// narrowest value that must still be ACCEPTED.
    #[test]
    fn rejects_slash_31_and_slash_32_but_accepts_the_slash_30_boundary() {
        assert!(matches!(
            "100.64.0.0/31".parse::<Ipv4Cidr>().unwrap_err(),
            CidrError::TooNarrow(31)
        ));
        assert!(matches!(
            "100.64.0.0/32".parse::<Ipv4Cidr>().unwrap_err(),
            CidrError::TooNarrow(32)
        ));
        let c: Ipv4Cidr = "100.64.0.0/30".parse().unwrap();
        assert_eq!(c.hosts().count(), 2, "/30 must still be accepted");
    }
}
