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

    /// The network prefix length (e.g. `24` for a `/24`) — the mask to give the
    /// gateway when configuring the compute bridge.
    pub fn prefix_len(&self) -> u8 {
        self.net.prefix_len()
    }

    /// Mark `ip` as already in use (e.g. when rebuilding state from the KV).
    pub fn reserve(&mut self, ip: Ipv4Addr) {
        self.allocated.insert(ip.into());
    }

    /// Whether `ip` is currently free (not the gateway, in-network, unallocated).
    pub fn is_free(&self, ip: Ipv4Addr) -> bool {
        self.manages(ip) && !self.allocated.contains(&u32::from(ip))
    }

    /// Whether this pool is responsible for `ip` — a non-gateway host address inside
    /// its CIDR (i.e. an address it can hand out or reserve). An address on a
    /// different backend/subnet is not this pool's to manage.
    pub fn manages(&self, ip: Ipv4Addr) -> bool {
        ip != self.gateway && self.net.contains(&ip)
    }

    /// Reserve every address in `ips` that this pool can hold — the boot-time
    /// **adoption** step. A node builds a fresh pool each process start; before it
    /// hands out any new address it must reserve the IPs already assigned to
    /// persisted/running replicas, or the empty pool would re-hand a live address
    /// to a different workload (the container-IP collision). An address that is
    /// already reserved, is the gateway, or falls outside the pool's CIDR is simply
    /// skipped, so passing the full fleet's endpoints is safe and idempotent.
    pub fn reserve_in_use(&mut self, ips: &[Ipv4Addr]) {
        for &ip in ips {
            if ip != self.gateway && self.net.contains(&ip) {
                self.allocated.insert(ip.into());
            }
        }
    }

    /// Allocate a **stable** guest IP for a replica: reuse `preferred` when it is a
    /// valid address this pool can still hand out and is currently free (so a
    /// replica keeps the same endpoint across a stop+relaunch); otherwise allocate
    /// a fresh unique address. Passing `None` — or a `preferred` that is already
    /// held by *another* live replica (a pre-existing collision) or out of range —
    /// falls through to a fresh allocation, so the result is always unique against
    /// everything currently reserved. This is the single decision the container
    /// backend's launch path makes; keeping it here makes it host-testable
    /// (the backend module is Linux-only).
    pub fn allocate_stable(&mut self, preferred: Option<Ipv4Addr>) -> Result<Ipv4Addr, IpamError> {
        if let Some(ip) = preferred {
            if self.is_free(ip) {
                self.allocated.insert(ip.into());
                return Ok(ip);
            }
        }
        self.allocate()
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

    // -----------------------------------------------------------------------
    // Container-IP collision regression (v0.3.12).
    //
    // A node builds a FRESH `IpPool` every process start. The container backend's
    // `launch` allocates an IP and `stop` releases the IP parsed from the replica's
    // `backend_ref`. Across a boot reconcile — which stops stale pre-reboot
    // replicas and (re)launches replicas — an empty-on-boot pool plus the
    // release-by-ref / allocate-fresh interplay could hand the SAME address to two
    // different containers (confirmed live: two managed-Postgres containers both on
    // `10.0.0.2`). The pure lifecycle decision lives in `IpPool` (the backend module
    // is Linux-only, so the decision must be host-testable); these model the boot
    // lifecycle against it.
    // -----------------------------------------------------------------------

    /// A distilled stand-in for the container backend's IP lifecycle: a pool plus
    /// the `(project, workload, replica) -> ip` map that the boot **adoption** step
    /// seeds from persisted replica state, so a relaunch can reuse a replica's
    /// recorded endpoint (stable IP) while every launch stays unique node-wide.
    /// Keying by **project** first (v0.3.12) is what stops two projects' same-named
    /// workloads (`acme/web/0` vs `beta/web/0`) sharing a slot.
    struct BackendIpLifecycle {
        pool: IpPool,
        // Persisted endpoints: (project, workload, replica) -> assigned ip, mirroring
        // the backend's view of `project/<proj>/compute_state/*` `backend_ref`s.
        assigned: std::collections::BTreeMap<(String, String, u32), Ipv4Addr>,
    }

    impl BackendIpLifecycle {
        /// Fresh-on-boot pool that has **adopted** the IPs of the already-known
        /// replicas (the fix). Passing `&[]` models the buggy empty-on-boot pool.
        fn boot(cidr: &str, live: &[(&str, &str, u32, Ipv4Addr)]) -> Self {
            let mut pool = IpPool::new(cidr).unwrap();
            let ips: Vec<Ipv4Addr> = live.iter().map(|(_, _, _, ip)| *ip).collect();
            pool.reserve_in_use(&ips);
            let assigned = live
                .iter()
                .map(|(p, w, r, ip)| ((p.to_string(), w.to_string(), *r), *ip))
                .collect();
            Self { pool, assigned }
        }

        /// The launch path. A replica with a **recorded** IP (adopted at boot, or
        /// still mapped from a prior launch) keeps it — reusing it when it is free,
        /// or, when it is the address this very replica already reserved via
        /// adoption, in place. A replica with no record — or whose recorded IP is
        /// held by *another* live replica (a stale collision) — gets a fresh unique
        /// address. So a relaunch is stable and a launch is always node-unique.
        fn launch(&mut self, project: &str, workload: &str, replica: u32) -> Ipv4Addr {
            // Mirrors `boatramp_container::backend::IpLifecycle::launch` exactly.
            let key = (project.to_string(), workload.to_string(), replica);
            let recorded = self.assigned.get(&key).copied();
            let ip = match recorded {
                // This replica's own address (no other live holder): reclaim it,
                // ensuring it stays reserved even if a prior stop released it.
                Some(ip) if self.owns(&key, ip) => {
                    self.pool.reserve(ip);
                    ip
                }
                // Recorded-but-collided (held by another live replica) or no record:
                // reuse the recorded address iff free, else a fresh unique one.
                _ => self.pool.allocate_stable(recorded).expect("pool exhausted"),
            };
            self.assigned.insert(key, ip);
            ip
        }

        /// The stop path: forget the replica and release its IP — but only if no
        /// other live replica still maps to that address (the "release only when
        /// truly last user" rule, so tearing down one side of a stale collision
        /// can't free the address the surviving replica still holds).
        fn stop(&mut self, project: &str, workload: &str, replica: u32) {
            if let Some(ip) =
                self.assigned
                    .remove(&(project.to_string(), workload.to_string(), replica))
            {
                if !self.assigned.values().any(|&held| held == ip) {
                    self.pool.release(ip);
                }
            }
        }

        /// Whether `key` is the *only* recorded holder of `ip` (so it genuinely
        /// owns the reservation and may reclaim it in place).
        fn owns(&self, key: &(String, String, u32), ip: Ipv4Addr) -> bool {
            !self
                .assigned
                .iter()
                .any(|(k, &held)| k != key && held == ip)
        }
    }

    #[test]
    fn boot_reconcile_two_workloads_get_distinct_ips() {
        // Two managed-DB workloads persisted from before a reboot, each on its own
        // IP. The node reboots: a fresh backend ADOPTS their IPs, then the boot
        // reconcile stops the stale replicas and relaunches each ordinal.
        let live = [
            (
                "default",
                "pg-construens_a1b2",
                0u32,
                Ipv4Addr::new(10, 0, 0, 2),
            ),
            ("default", "pg", 0u32, Ipv4Addr::new(10, 0, 0, 3)),
        ];
        let mut be = BackendIpLifecycle::boot("10.0.0.0/24", &live);

        // The boot reconcile relaunches each still-desired ordinal; adoption lets
        // each reclaim its own recorded endpoint.
        let a = be.launch("default", "pg-construens_a1b2", 0);
        let b = be.launch("default", "pg", 0);

        // The core invariant: two live containers NEVER share an IP.
        assert_ne!(a, b, "two workloads' replicas must get distinct IPs");
        // And each kept its recorded endpoint across the reboot (stable).
        assert_eq!(a, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(b, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn same_named_workloads_in_different_projects_get_distinct_ips() {
        // The cross-tenant collision class (v0.3.12): two DIFFERENT projects each own
        // a workload named `web`, replica 0. Pre-fix the IPAM keyed by
        // `(workload, replica)`, so both `web/0`s collapsed to ONE slot → an IP
        // collision (and, in the backend, a shared cgroup/veth). Keying by
        // `(project, workload, replica)` keeps them distinct. Fresh pool (no adoption)
        // so both are first-time launches — the multi-tenant "each admin names their
        // own workloads" case.
        let mut be = BackendIpLifecycle::boot("10.0.0.0/24", &[]);
        let acme = be.launch("acme", "web", 0);
        let beta = be.launch("beta", "web", 0);
        assert_ne!(
            acme, beta,
            "same-named workloads in different projects must NOT share an IP"
        );

        // And each project's `web/0` is stable across a relaunch (its own slot).
        assert_eq!(be.launch("acme", "web", 0), acme);
        assert_eq!(be.launch("beta", "web", 0), beta);

        // Stopping one project's `web` frees only its address; the other is untouched.
        be.stop("acme", "web", 0);
        assert!(be.pool.is_free(acme), "acme/web/0's IP is released");
        assert!(!be.pool.is_free(beta), "beta/web/0's IP is still held");
    }

    #[test]
    fn interleaved_stop_launch_never_reuses_a_live_ip() {
        // The precise collision shape: within one pass, A is stopped (its IP freed)
        // and a DIFFERENT workload B is launched before A relaunches. The freed IP
        // must not be handed to B while A still intends to reclaim it — and even if
        // B does take it, A must then get a different, unique address.
        let live = [("default", "pg-a", 0u32, Ipv4Addr::new(10, 0, 0, 2))];
        let mut be = BackendIpLifecycle::boot("10.0.0.0/24", &live);

        be.stop("default", "pg-a", 0); // A stopped → .2 released
        let b = be.launch("default", "pg-b", 0); // new workload B launches
        let a = be.launch("default", "pg-a", 0); // A relaunches

        assert_ne!(
            a, b,
            "a relaunching replica must never collide with a live one"
        );
    }

    #[test]
    fn adoption_breaks_a_pre_existing_collision() {
        // The current bad on-disk state: two live replicas already share .2. A
        // reconcile must re-home one to a unique address rather than perpetuate it.
        // `reserve_in_use` reserves .2 once (set semantics); relaunching the second
        // replica finds its recorded .2 taken and allocates fresh.
        let live = [
            ("default", "pg-a", 0u32, Ipv4Addr::new(10, 0, 0, 2)),
            ("default", "pg-b", 0u32, Ipv4Addr::new(10, 0, 0, 2)), // collision!
        ];
        let mut be = BackendIpLifecycle::boot("10.0.0.0/24", &live);

        // The relaunch reference-counts the release: whichever launches second
        // finds .2 still held by the first and is re-homed to a fresh address.
        let a = be.launch("default", "pg-a", 0);
        let b = be.launch("default", "pg-b", 0);

        assert!(
            a == Ipv4Addr::new(10, 0, 0, 2) || b == Ipv4Addr::new(10, 0, 0, 2),
            "one replica retains the previously shared IP"
        );
        assert_ne!(
            a, b,
            "the collision is broken — the other is re-homed uniquely"
        );
    }

    #[test]
    fn relaunch_of_the_same_replica_is_stable() {
        // The confirmed live scenario: a node reboots. The fresh backend adopts the
        // replica's recorded endpoint (.7); the boot reconcile relaunches that
        // ordinal, which reclaims .7 in place, so the gateway's persisted
        // `backend_ref` stays valid across the reboot.
        let live = [("default", "pg-a", 0u32, Ipv4Addr::new(10, 0, 0, 7))];
        let mut be = BackendIpLifecycle::boot("10.0.0.0/24", &live);
        assert_eq!(be.launch("default", "pg-a", 0), Ipv4Addr::new(10, 0, 0, 7));
        // Idempotent across repeated reconcile passes.
        assert_eq!(be.launch("default", "pg-a", 0), Ipv4Addr::new(10, 0, 0, 7));
    }

    #[test]
    fn pre_fix_empty_pool_loses_a_replicas_recorded_endpoint() {
        // Documents the root cause. Pre-fix the launch path was a plain `allocate`
        // on a fresh-on-boot pool with no way to reuse a replica's recorded IP: a
        // replica the gateway had persisted at .9 gets silently reassigned to .2 on
        // the next boot (the instability that, with release-by-ref, produced the
        // live 10.0.0.2 clash).
        let mut pre_fix = IpPool::new("10.0.0.0/24").unwrap();
        let reassigned = pre_fix.allocate().unwrap();
        assert_ne!(
            reassigned,
            Ipv4Addr::new(10, 0, 0, 9),
            "pre-fix: a plain allocate cannot preserve a replica's prior endpoint"
        );

        // The fix restores stability: a fresh backend adopts the recorded endpoints,
        // and the launch path (release-then-`allocate_stable`) reclaims .9 exactly.
        let mut be = BackendIpLifecycle::boot(
            "10.0.0.0/24",
            &[("default", "pg", 0, Ipv4Addr::new(10, 0, 0, 9))],
        );
        assert_eq!(be.launch("default", "pg", 0), Ipv4Addr::new(10, 0, 0, 9));
    }

    #[test]
    fn allocate_stable_reuses_free_and_reallocates_taken() {
        let mut pool = IpPool::new("10.0.0.0/24").unwrap();
        // A free preferred address is reused verbatim.
        let want = Ipv4Addr::new(10, 0, 0, 5);
        assert_eq!(pool.allocate_stable(Some(want)).unwrap(), want);
        // The same preferred address, now taken, yields a different unique one.
        let other = pool.allocate_stable(Some(want)).unwrap();
        assert_ne!(other, want);
        // `None` preferred behaves like a plain allocate (next free, skipping taken).
        let next = pool.allocate_stable(None).unwrap();
        assert!(!pool.is_free(next) && next != want && next != other);
        // An out-of-range preferred is ignored and a valid in-CIDR address is allocated.
        let oob = pool
            .allocate_stable(Some(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap();
        assert_eq!(oob.octets()[0], 10);
    }

    #[test]
    fn reserve_in_use_skips_gateway_and_out_of_range() {
        let mut pool = IpPool::new("10.0.0.0/24").unwrap();
        pool.reserve_in_use(&[
            Ipv4Addr::new(10, 0, 0, 1),    // gateway — must not be counted
            Ipv4Addr::new(10, 0, 0, 2),    // valid
            Ipv4Addr::new(192, 168, 0, 9), // out of CIDR — skipped
        ]);
        // Only .2 was actually reserved.
        assert_eq!(pool.allocated_count(), 1);
        assert!(!pool.is_free(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn bad_cidr_errors() {
        assert!(matches!(
            IpPool::new("not-a-cidr"),
            Err(IpamError::BadCidr(_))
        ));
    }
}
