//! IP address management for compute guest interfaces.
//!
//! A per-node pool over a private CIDR (e.g. `10.0.0.0/24`): hand out a guest IP
//! per replica — for a microVM **tap** (VMM backend) or a container **veth**
//! (container backend) — skipping the network/broadcast and the `.1` gateway,
//! and derive a stable locally-administered MAC from the IP. The allocation set
//! is the authority the control plane persists; this is the pure logic over it.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

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

    /// The total number of allocatable host addresses (every host in the CIDR
    /// except the reserved gateway). The denominator for a utilization / high-water
    /// calculation. A `/24` is 254 hosts − 1 gateway = 253; a `/30` is 1.
    pub fn total_hosts(&self) -> usize {
        // `Ipv4Net::hosts()` already excludes the network/broadcast; drop the gateway.
        self.net.hosts().count().saturating_sub(1)
    }

    /// The subnet this pool manages, as a CIDR string — for diagnostics (e.g. the
    /// exhaustion warning naming the subnet the operator can widen).
    pub fn cidr(&self) -> String {
        self.net.to_string()
    }

    /// A stable, locally-administered unicast MAC derived from `ip`
    /// (`02:00:<the four IPv4 octets>`). The `02` prefix sets the
    /// locally-administered bit and clears the multicast bit.
    pub fn mac_for(ip: Ipv4Addr) -> String {
        let o = ip.octets();
        format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
    }
}

/// A **shared** IP authority over one [`IpPool`], cloneable and thread-safe
/// (`Arc<Mutex<IpPool>>`). It is the single address authority for every compute
/// backend that places guests on the *same* bridge/subnet — the native `container`
/// backend's veths and the embedded / macOS VMM backends' taps all live on one L2,
/// so they must draw from and release to ONE pool or two backends could hand out the
/// same `10.0.0.x` on the same segment (a cross-backend collision). `build_compute`
/// builds one authority per bridge/subnet and injects a clone into each co-located
/// backend; the container backend's `(project,workload,replica)`-keyed ownership map
/// stays per-backend, but the address pool underneath is this shared authority.
///
/// Every allocation path also surfaces pressure: [`allocate`](Self::allocate) /
/// [`allocate_stable`](Self::allocate_stable) log a `warn` on exhaustion (naming the
/// subnet + in-use count, noting `compute.subnet` can be widened) and cross a
/// high-water mark once, so an operator sees an approaching cliff before launches
/// start failing.
#[derive(Clone)]
pub struct IpAuthority {
    pool: Arc<Mutex<IpPool>>,
    /// Utilization fraction (0.0–1.0) past which a single high-water warning fires.
    high_water: f64,
    /// One-shot latch so the high-water warning logs once per crossing, not every
    /// allocation, and re-arms when utilization falls back below the mark.
    warned_high: Arc<Mutex<bool>>,
}

impl std::fmt::Debug for IpAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (used, total) = self
            .pool
            .lock()
            .map(|p| (p.allocated_count(), p.total_hosts()))
            .unwrap_or((0, 0));
        f.debug_struct("IpAuthority")
            .field("used", &used)
            .field("total", &total)
            .field("high_water", &self.high_water)
            .finish()
    }
}

impl IpAuthority {
    /// The default high-water utilization (90%) — an approaching-exhaustion warning
    /// fires when the pool crosses it.
    pub const DEFAULT_HIGH_WATER: f64 = 0.9;

    /// Build a shared authority over `cidr` (e.g. `10.0.0.0/24`), warning at the
    /// default high-water mark.
    pub fn new(cidr: &str) -> Result<Self, IpamError> {
        Ok(Self::over(IpPool::new(cidr)?))
    }

    /// Wrap an existing pool as the shared authority (e.g. a pool the caller already
    /// built to read its gateway/prefix for the bridge).
    pub fn over(pool: IpPool) -> Self {
        Self {
            pool: Arc::new(Mutex::new(pool)),
            high_water: Self::DEFAULT_HIGH_WATER,
            warned_high: Arc::new(Mutex::new(false)),
        }
    }

    /// The reserved gateway address (`.1`) of the shared subnet.
    pub fn gateway(&self) -> Ipv4Addr {
        self.pool.lock().expect("ipam authority").gateway()
    }

    /// The prefix length of the shared subnet.
    pub fn prefix_len(&self) -> u8 {
        self.pool.lock().expect("ipam authority").prefix_len()
    }

    /// Whether this authority's subnet is responsible for `ip` (in-CIDR, non-gateway).
    pub fn manages(&self, ip: Ipv4Addr) -> bool {
        self.pool.lock().expect("ipam authority").manages(ip)
    }

    /// Whether `ip` is currently free in the shared pool.
    pub fn is_free(&self, ip: Ipv4Addr) -> bool {
        self.pool.lock().expect("ipam authority").is_free(ip)
    }

    /// Mark `ip` as in use in the shared pool (idempotent).
    pub fn reserve(&self, ip: Ipv4Addr) {
        self.pool.lock().expect("ipam authority").reserve(ip);
    }

    /// Reserve every in-subnet address in `ips` (boot-time adoption), from *any*
    /// backend — so a running VMM guest's IP is reserved before the container backend
    /// allocates, and vice-versa. Skips the gateway + out-of-subnet addresses.
    pub fn reserve_in_use(&self, ips: &[Ipv4Addr]) {
        self.pool
            .lock()
            .expect("ipam authority")
            .reserve_in_use(ips);
    }

    /// Return `ip` to the shared pool.
    pub fn release(&self, ip: Ipv4Addr) {
        self.pool.lock().expect("ipam authority").release(ip);
    }

    /// Allocate the next free address from the shared pool, surfacing pressure
    /// (high-water + exhaustion warnings). See [`IpAuthority`].
    pub fn allocate(&self) -> Result<Ipv4Addr, IpamError> {
        let mut pool = self.pool.lock().expect("ipam authority");
        let out = pool.allocate();
        self.surface_pressure(&pool, &out);
        out
    }

    /// Allocate a stable address (reuse `preferred` when free) from the shared pool,
    /// surfacing the same pressure warnings as [`allocate`](Self::allocate).
    pub fn allocate_stable(&self, preferred: Option<Ipv4Addr>) -> Result<Ipv4Addr, IpamError> {
        let mut pool = self.pool.lock().expect("ipam authority");
        let out = pool.allocate_stable(preferred);
        self.surface_pressure(&pool, &out);
        out
    }

    /// How many addresses are currently allocated across the shared pool.
    pub fn allocated_count(&self) -> usize {
        self.pool.lock().expect("ipam authority").allocated_count()
    }

    /// Run the pure pressure decision over the just-observed pool state and emit the
    /// warnings it selects. Kept off the pure `IpPool` so `IpPool` stays log-free and
    /// the decision itself ([`pressure`]) is host-testable without a tracing capture.
    fn surface_pressure(&self, pool: &IpPool, outcome: &Result<Ipv4Addr, IpamError>) {
        let total = pool.total_hosts();
        let used = pool.allocated_count();
        let cidr = pool.cidr();
        let mut warned = self.warned_high.lock().expect("ipam high-water latch");
        match pressure(used, total, self.high_water, *warned, outcome.is_err()) {
            Pressure::Exhausted => {
                tracing::warn!(
                    subnet = %cidr,
                    in_use = used,
                    capacity = total,
                    "compute IPAM pool exhausted: no free guest IP remains — widen `compute.subnet` \
                     (e.g. a /23 or /22) to grow the pool"
                );
            }
            Pressure::CrossedHighWater => {
                *warned = true;
                tracing::warn!(
                    subnet = %cidr,
                    in_use = used,
                    capacity = total,
                    high_water_pct = (self.high_water * 100.0) as u32,
                    "compute IPAM pool utilization is high — consider widening `compute.subnet` \
                     before it exhausts"
                );
            }
            Pressure::BelowHighWater => *warned = false,
            Pressure::Nominal => {}
        }
    }
}

/// The pressure signal an allocation attempt produced — the pure decision behind
/// [`IpAuthority::surface_pressure`], so the warning logic is host-testable without a
/// tracing subscriber. `already_warned` is the caller's one-shot latch (so the
/// high-water warning fires once per crossing); `alloc_failed` is whether the
/// allocation returned [`IpamError::Exhausted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pressure {
    /// Allocation failed because the pool is full — always warn.
    Exhausted,
    /// Utilization just crossed the high-water mark (and hadn't been warned) — warn once.
    CrossedHighWater,
    /// Utilization is at/above the mark but was already warned — stay quiet (latched).
    Nominal,
    /// Utilization fell back below the mark — clear the latch so a later crossing re-warns.
    BelowHighWater,
}

/// Decide which pressure warning (if any) an allocation should emit. Pure so it is
/// unit-testable: an exhausted allocation always warns; otherwise the first crossing
/// of `high_water` (as `used/total`) warns once, and dropping back below it re-arms.
fn pressure(
    used: usize,
    total: usize,
    high_water: f64,
    already_warned: bool,
    alloc_failed: bool,
) -> Pressure {
    if alloc_failed {
        return Pressure::Exhausted;
    }
    if total == 0 {
        return Pressure::Nominal;
    }
    let util = used as f64 / total as f64;
    if util >= high_water {
        if already_warned {
            Pressure::Nominal
        } else {
            Pressure::CrossedHighWater
        }
    } else if already_warned {
        Pressure::BelowHighWater
    } else {
        Pressure::Nominal
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

    #[test]
    fn total_hosts_excludes_gateway() {
        // /24: 254 hosts (RFC network/broadcast excluded by `hosts()`), minus the gateway.
        assert_eq!(IpPool::new("10.0.0.0/24").unwrap().total_hosts(), 253);
        // /30: hosts .1,.2 → minus the .1 gateway → 1 allocatable.
        assert_eq!(IpPool::new("10.0.0.0/30").unwrap().total_hosts(), 1);
    }

    // -----------------------------------------------------------------------
    // A1: pool-pressure decision (exhaustion + high-water). Pure so the warning
    // policy is host-testable without a tracing subscriber.
    // -----------------------------------------------------------------------

    #[test]
    fn pressure_exhaustion_always_warns() {
        // A failed allocation is Exhausted regardless of the latch or utilization.
        assert_eq!(pressure(253, 253, 0.9, false, true), Pressure::Exhausted);
        assert_eq!(pressure(0, 253, 0.9, true, true), Pressure::Exhausted);
    }

    #[test]
    fn pressure_high_water_warns_once_then_latches_and_rearms() {
        let hw = 0.9;
        let total = 100;
        // Below the mark, unwarned: nominal.
        assert_eq!(pressure(80, total, hw, false, false), Pressure::Nominal);
        // First crossing (>=90%): warn once.
        assert_eq!(
            pressure(90, total, hw, false, false),
            Pressure::CrossedHighWater
        );
        // Still above the mark but already warned: stay quiet (latched).
        assert_eq!(pressure(95, total, hw, true, false), Pressure::Nominal);
        // Fell back below the mark while latched: re-arm (clear the latch).
        assert_eq!(
            pressure(50, total, hw, true, false),
            Pressure::BelowHighWater
        );
    }

    #[test]
    fn pressure_zero_capacity_is_nominal() {
        assert_eq!(pressure(0, 0, 0.9, false, false), Pressure::Nominal);
    }

    // -----------------------------------------------------------------------
    // A5: a shared IpAuthority is ONE address pool. Two backends drawing from the
    // same authority (co-located on one bridge/subnet) can never be handed the same
    // address — the cross-backend collision the shared authority prevents.
    // -----------------------------------------------------------------------

    #[test]
    fn shared_authority_never_hands_two_backends_the_same_address() {
        // One authority injected into two backends (a clone each) — the container
        // veth pool and a VMM tap pool are the same underlying pool.
        let container_view = IpAuthority::new("10.0.0.0/24").unwrap();
        let vmm_view = container_view.clone();

        // Interleave allocations across the two views, as two co-located backends
        // launching guests on the same L2 would.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..10 {
            let c = container_view.allocate().unwrap();
            let v = vmm_view.allocate().unwrap();
            assert!(
                seen.insert(c),
                "container view re-handed a live address {c}"
            );
            assert!(seen.insert(v), "vmm view re-handed a live address {v}");
            assert_ne!(c, v, "the two backends must never share an address");
        }
        // The shared pool counts every allocation from both views.
        assert_eq!(container_view.allocated_count(), 20);
        assert_eq!(vmm_view.allocated_count(), 20);
    }

    #[test]
    fn shared_authority_adoption_from_one_backend_blocks_another() {
        // A running VMM guest's IP, adopted at boot, must be reserved before the
        // container backend allocates — even though the container backend did the
        // adopting-via its own clone (they share the pool).
        let vmm_view = IpAuthority::new("10.0.0.0/24").unwrap();
        let container_view = vmm_view.clone();
        // The VMM guest already holds .2 (adopted through either view).
        vmm_view.reserve_in_use(&[Ipv4Addr::new(10, 0, 0, 2)]);
        // The container backend now allocates: it must skip the VMM's .2.
        let got = container_view.allocate().unwrap();
        assert_ne!(got, Ipv4Addr::new(10, 0, 0, 2));
        assert!(!vmm_view.is_free(Ipv4Addr::new(10, 0, 0, 2)));
        // And a release through either view frees it in the one pool.
        container_view.release(got);
        assert!(vmm_view.is_free(got));
    }
}
