//! IP address management for compute guest interfaces.
//!
//! A per-node pool over a private CIDR (e.g. `10.0.0.0/24`): hand out a guest IP
//! per replica — for a microVM **tap** (VMM backend) or a container **veth**
//! (container backend) — skipping the network/broadcast and the `.1` gateway,
//! and derive a stable locally-administered MAC from the IP. The allocation set
//! is the authority the control plane persists; this is the pure logic over it.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Why an IPAM operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpamError {
    /// The CIDR did not parse.
    BadCidr(String),
    /// No free address remains in the pool.
    Exhausted,
}

impl std::fmt::Display for IpamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCidr(c) => write!(f, "invalid IPAM CIDR: {c}"),
            Self::Exhausted => write!(f, "IPAM pool exhausted"),
        }
    }
}

impl std::error::Error for IpamError {}

/// A pool of guest IPs over a private CIDR.
#[derive(Debug, Clone)]
pub struct IpPool {
    net: Ipv4Net,
    gateway: Ipv4Addr,
    allocated: BTreeSet<u32>,
}

impl IpPool {
    /// Build a pool over `cidr` (e.g. `10.0.0.0/24`). The first usable host
    /// (`.1`) is reserved as the bridge/gateway and never handed out.
    pub fn new(cidr: &str) -> Result<Self, IpamError> {
        let net: Ipv4Net = cidr
            .parse()
            .map_err(|_| IpamError::BadCidr(cidr.to_string()))?;
        let gateway = net.hosts().next().unwrap_or(net.network());
        Ok(Self {
            net,
            gateway,
            allocated: BTreeSet::new(),
        })
    }

    /// The reserved gateway address (`.1`).
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// Mark `ip` as already in use (e.g. when rebuilding state from the KV).
    pub fn reserve(&mut self, ip: Ipv4Addr) {
        self.allocated.insert(ip.into());
    }

    /// Allocate the next free guest IP.
    pub fn allocate(&mut self) -> Result<Ipv4Addr, IpamError> {
        for ip in self.net.hosts() {
            if ip == self.gateway {
                continue;
            }
            let key = u32::from(ip);
            if !self.allocated.contains(&key) {
                self.allocated.insert(key);
                return Ok(ip);
            }
        }
        Err(IpamError::Exhausted)
    }

    /// Return `ip` to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.remove(&u32::from(ip));
    }

    /// How many addresses are currently allocated.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// A stable, locally-administered unicast MAC derived from `ip`
    /// (`02:00:<the four IPv4 octets>`). The `02` prefix sets the
    /// locally-administered bit and clears the multicast bit.
    pub fn mac_for(ip: Ipv4Addr) -> String {
        let o = ip.octets();
        format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequentially_skipping_gateway() {
        let mut pool = IpPool::new("10.0.0.0/24").unwrap();
        assert_eq!(pool.gateway(), Ipv4Addr::new(10, 0, 0, 1));
        // First allocation skips .1 (gateway) → .2.
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(pool.allocated_count(), 2);
    }

    #[test]
    fn release_makes_an_address_reusable() {
        let mut pool = IpPool::new("10.0.0.0/24").unwrap();
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        pool.release(a);
        // The freed address is handed out again before moving on.
        assert_eq!(pool.allocate().unwrap(), a);
        assert_ne!(a, b);
    }

    #[test]
    fn reserve_marks_in_use() {
        let mut pool = IpPool::new("10.0.0.0/24").unwrap();
        pool.reserve(Ipv4Addr::new(10, 0, 0, 2));
        // .2 is taken → next free is .3.
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn tiny_pool_exhausts() {
        // /30 has hosts .1 and .2; .1 is the gateway → only .2 is allocatable.
        let mut pool = IpPool::new("10.0.0.0/30").unwrap();
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pool.allocate(), Err(IpamError::Exhausted));
    }

    #[test]
    fn mac_is_locally_administered_and_stable() {
        let mac = IpPool::mac_for(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(mac, "02:00:0a:00:00:05");
        // Stable.
        assert_eq!(mac, IpPool::mac_for(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn bad_cidr_errors() {
        assert!(matches!(
            IpPool::new("not-a-cidr"),
            Err(IpamError::BadCidr(_))
        ));
    }
}
