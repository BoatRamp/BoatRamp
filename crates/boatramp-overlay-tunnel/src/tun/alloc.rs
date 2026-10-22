//! The synthetic-IP allocator (plan §3.4): per-project (one [`SyntheticIpAllocator`] per
//! [`crate::core::Tunnel`], same per-project-isolation argument as the catalog/cap-cache — plan §5),
//! local-only (nothing here is ever sent over the wire), over the configured CIDR (default
//! `100.64.0.0/10`). Stable per daemon run: once a name gets an address it keeps it for the process's
//! lifetime (so a long-lived client's cached DNS answer/OS route stays valid), and forward (`name →
//! ip`)/reverse (`ip → name`) maps are both kept — the reverse map is what the netstack (plan §3.5)
//! uses to turn an inbound packet's destination address back into a service name.
//!
//! **Security (plan §5, IP-as-local-handle invariant):** this map NEVER leaves the process. The
//! netstack resolves `ip → name` here and then calls [`crate::core::Tunnel::open`] with the **name**
//! — the synthetic IP itself is not a field anywhere in the dial path (see
//! `crate::core::tunnel::tests::dial_request_has_no_ip_field`, which this module's invariant feeds).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

use super::cidr::Ipv4Cidr;

/// The allocator ran out of addresses in its configured CIDR — `/10` (4M usable addresses) in the
/// default configuration, so this is realistically only reachable with a deliberately narrow
/// `--cidr` override, but it must fail closed rather than wrap/alias two names onto one address.
#[derive(Debug, Clone, thiserror::Error)]
#[error("synthetic-IP pool ({0}) exhausted — no address left to allocate")]
pub struct PoolExhausted(pub Ipv4Cidr);

struct Maps {
    forward: HashMap<String, Ipv4Addr>,
    reverse: HashMap<Ipv4Addr, String>,
    /// The next never-yet-tried host address to hand out — monotonic within one process's
    /// lifetime, so allocation order (and therefore which name gets which address) is a pure
    /// function of arrival order, not of any attacker-visible randomness.
    next: Ipv4Addr,
}

/// Per-project, local-only, stable-per-run synthetic-IP pool (plan §3.4).
pub struct SyntheticIpAllocator {
    cidr: Ipv4Cidr,
    maps: RwLock<Maps>,
}

impl SyntheticIpAllocator {
    #[must_use]
    pub fn new(cidr: Ipv4Cidr) -> Self {
        Self {
            cidr,
            maps: RwLock::new(Maps {
                forward: HashMap::new(),
                reverse: HashMap::new(),
                next: Self::first_allocatable(cidr),
            }),
        }
    }

    /// The first address [`SyntheticIpAllocator::allocate`] may ever hand out: one past the CIDR's
    /// first usable host address, which is permanently reserved for the TUN interface itself (plan
    /// §3.1/§3.2) and surfaced via [`SyntheticIpAllocator::reserve_interface_address`] — the two
    /// ranges can never collide because allocation simply never starts at that address.
    fn first_allocatable(cidr: Ipv4Cidr) -> Ipv4Addr {
        let mut hosts = cidr.hosts();
        let _interface_addr = hosts.next();
        hosts.next().unwrap_or(cidr.network())
    }

    #[must_use]
    pub fn cidr(&self) -> Ipv4Cidr {
        self.cidr
    }

    /// Return `name`'s synthetic address, allocating a fresh one from the pool if this is the first
    /// time `name` has been seen this run. Stable: a second call with the same `name` always returns
    /// the same address (plan §3.4 — "stable mapping per daemon run").
    pub fn allocate(&self, name: &str) -> Result<Ipv4Addr, PoolExhausted> {
        {
            let maps = self.maps.read().expect("allocator lock poisoned");
            if let Some(addr) = maps.forward.get(name) {
                return Ok(*addr);
            }
        }
        let mut maps = self.maps.write().expect("allocator lock poisoned");
        // Re-check under the write lock — another thread may have allocated it while we waited.
        if let Some(addr) = maps.forward.get(name) {
            return Ok(*addr);
        }
        let candidate = maps.next;
        if !self.cidr.contains(candidate) {
            return Err(PoolExhausted(self.cidr));
        }
        maps.next = Ipv4Addr::from(u32::from(candidate).saturating_add(1));
        maps.forward.insert(name.to_string(), candidate);
        maps.reverse.insert(candidate, name.to_string());
        Ok(candidate)
    }

    /// Reverse lookup: the service name a previously-allocated synthetic `addr` belongs to, or
    /// `None` if `addr` was never handed out (e.g. a packet spoofed/aimed at an address this process
    /// never allocated — the netstack treats that as "no mapping", not as a crash).
    #[must_use]
    pub fn resolve(&self, addr: Ipv4Addr) -> Option<String> {
        self.maps
            .read()
            .expect("allocator lock poisoned")
            .reverse
            .get(&addr)
            .cloned()
    }

    /// Current allocation count — used by the netstack's device address assignment (the first usable
    /// host address in the CIDR is reserved for the TUN interface's own address, never handed out to
    /// a service — see [`SyntheticIpAllocator::reserve_interface_address`]) and by tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.maps
            .read()
            .expect("allocator lock poisoned")
            .forward
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The address reserved for the TUN interface itself (plan §3.1/§3.2 — the device needs its own
    /// address inside the routed CIDR). Always the CIDR's first usable host address; never handed out
    /// by [`SyntheticIpAllocator::allocate`] because allocation starts one address **after** it.
    #[must_use]
    pub fn reserve_interface_address(&self) -> Ipv4Addr {
        self.cidr.hosts().next().unwrap_or(self.cidr.network())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::cidr::default_cidr;

    fn small_cidr() -> Ipv4Cidr {
        "10.99.0.0/29".parse().unwrap() // 8 addrs, 5 usable hosts
    }

    #[test]
    fn allocating_the_same_name_twice_returns_the_same_address() {
        let alloc = SyntheticIpAllocator::new(small_cidr());
        let a = alloc.allocate("svc/db").unwrap();
        let b = alloc.allocate("svc/db").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_names_get_different_addresses() {
        let alloc = SyntheticIpAllocator::new(small_cidr());
        let a = alloc.allocate("svc/db").unwrap();
        let b = alloc.allocate("svc/cache").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_reverse_map_resolves_an_allocated_address_back_to_its_name() {
        let alloc = SyntheticIpAllocator::new(small_cidr());
        let addr = alloc.allocate("svc/db").unwrap();
        assert_eq!(alloc.resolve(addr), Some("svc/db".to_string()));
    }

    #[test]
    fn an_address_never_allocated_resolves_to_none() {
        let alloc = SyntheticIpAllocator::new(small_cidr());
        assert_eq!(alloc.resolve(Ipv4Addr::new(10, 99, 0, 1)), None);
    }

    #[test]
    fn the_interface_address_is_never_handed_out_by_allocate() {
        let cidr = small_cidr();
        let alloc = SyntheticIpAllocator::new(cidr);
        let iface_addr = alloc.reserve_interface_address();
        // Exhaust the (small) pool and confirm the interface address never appears among the
        // allocated addresses.
        let mut seen = Vec::new();
        while let Ok(addr) = alloc.allocate(&format!("svc/n{}", seen.len())) {
            seen.push(addr);
        }
        assert!(
            !seen.contains(&iface_addr),
            "the interface's own reserved address must never be allocated to a service"
        );
    }

    #[test]
    fn exhausting_a_small_pool_fails_closed_rather_than_aliasing() {
        let alloc = SyntheticIpAllocator::new(small_cidr());
        let mut ok = 0;
        let mut exhausted = false;
        for i in 0..100 {
            match alloc.allocate(&format!("svc/n{i}")) {
                Ok(_) => ok += 1,
                Err(PoolExhausted(_)) => {
                    exhausted = true;
                    break;
                }
            }
        }
        assert!(
            exhausted,
            "a /29 pool must exhaust within 100 distinct names"
        );
        assert!(ok > 0, "at least the first allocation must succeed");

        // Every forward entry has a DISTINCT address — no aliasing even right up to exhaustion.
        let addrs: std::collections::HashSet<_> = (0..ok)
            .map(|i| alloc.allocate(&format!("svc/n{i}")).unwrap())
            .collect();
        assert_eq!(addrs.len(), ok, "no two names must ever share an address");
    }

    #[test]
    fn per_project_isolation_is_free_by_construction() {
        // Two allocators (one per `Tunnel`/project, plan §5) never share state — allocating the
        // SAME name in each independently is just two independent first-allocations, proving there
        // is no shared/global map a cross-project name could collide in.
        let a = SyntheticIpAllocator::new(default_cidr());
        let b = SyntheticIpAllocator::new(default_cidr());
        let addr_a = a.allocate("svc/db").unwrap();
        let addr_b = b.allocate("svc/db").unwrap();
        assert_eq!(
            addr_a, addr_b,
            "same CIDR + same first name ⇒ same first address in EACH"
        );
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(a.resolve(addr_a).is_some());
        // Mutating `a` must never appear in `b`'s map — the whole point of "one allocator per
        // Tunnel" rather than a process-global singleton.
        a.allocate("svc/only-in-a").unwrap();
        assert_eq!(b.len(), 1);
    }
}
