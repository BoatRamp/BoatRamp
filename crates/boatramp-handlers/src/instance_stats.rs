//! Host-side observability for the wasm component **instance lifecycle** (construens
//! memory-instance-observability request): per-lane warm-hit / cold-miss / eviction /
//! instantiation counters + compile & instantiate durations, plus the live warm set, snapshotted
//! read-only for the admin stats surface. So an operator can see, from DATA, whether compiled
//! components stay warm (and if not, how often they are evicted) and whether a slow request paid a
//! cold (re)compile or a per-request instantiate — rather than inferring from end-to-end timing.
//!
//! Pure host telemetry: NO guest/WIT surface, and the serve hot path only does relaxed atomic
//! increments (no lock, no allocation). The snapshot is lock-free over the counters; the engine
//! supplies the live cache size / capacity / in-flight it reads under its own locks.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Which engine lane a component is served on — each has its own compile cache + concurrency gate,
/// so the lifecycle is tracked (and reported) per lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatLane {
    /// The synchronous request lane (`ProxyPre`).
    Request,
    /// The durable messaging-consumer lane (`ConsumerPre`).
    Consumer,
    /// The duplex session lane (`SessionHostPre`).
    Session,
}

/// Number of power-of-two buckets in a [`Histogram`]. Bucket `i>0` counts samples in
/// `[2^(i-1), 2^i)`; bucket 0 counts 0. 48 buckets cover 0..2^47 — ample for µs instantiate / ms
/// compile latencies (2^47 µs ≈ 4.4 years).
const HIST_BUCKETS: usize = 48;

/// A fixed-bucket, lock-free, allocation-free latency histogram (power-of-two buckets). Cheap enough
/// for the serve hot path (one relaxed add); p50/p99 are derived from the cumulative counts at
/// snapshot time. Samples are recorded in the DISPLAY unit (µs for instantiate, ms for compile).
#[derive(Debug)]
struct Histogram {
    buckets: [AtomicU64; HIST_BUCKETS],
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Histogram {
    /// Record one sample (in the histogram's display unit).
    fn record(&self, v: u64) {
        self.buckets[bucket_index(v)].fetch_add(1, Ordering::Relaxed);
    }

    /// The `p`-th percentile (`0..=100`), returned as the upper bound of the bucket it falls in (a
    /// conservative, power-of-two over-estimate); `0` when there are no samples.
    fn percentile(&self, p: u64) -> u64 {
        let counts: [u64; HIST_BUCKETS] =
            std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed));
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return 0;
        }
        let target = total.saturating_mul(p).div_ceil(100).max(1);
        let mut cum = 0u64;
        for (i, c) in counts.iter().enumerate() {
            cum += c;
            if cum >= target {
                return bucket_upper(i);
            }
        }
        bucket_upper(HIST_BUCKETS - 1)
    }
}

/// Bucket index for `v`: `0` for 0, else `floor(log2(v))+1`, capped at `HIST_BUCKETS-1`.
fn bucket_index(v: u64) -> usize {
    if v == 0 {
        return 0;
    }
    ((64 - v.leading_zeros()) as usize).min(HIST_BUCKETS - 1)
}

/// The representative (upper-bound) value of bucket `i`: `0` for bucket 0, else `2^i` (samples in
/// bucket `i>0` are `< 2^i`).
fn bucket_upper(i: usize) -> u64 {
    if i == 0 { 0 } else { 1u64 << i }
}

/// Lifecycle counters for one engine lane. Atomics so the serve hot path only does relaxed
/// increments; read lock-free at snapshot time.
#[derive(Debug, Default)]
pub struct LaneCounters {
    warm_hits: AtomicU64,
    cold_misses: AtomicU64,
    evictions: AtomicU64,
    instantiations: AtomicU64,
    instantiate_ns_total: AtomicU64,
    instantiate_ns_max: AtomicU64,
    compile_ns_total: AtomicU64,
    compile_ns_max: AtomicU64,
    /// Latency distributions (display units: µs for instantiate, ms for compile) for p50/p99.
    instantiate_us_hist: Histogram,
    compile_ms_hist: Histogram,
}

impl LaneCounters {
    /// A warm cache hit — the compiled+linked component was already resident (cheap clone, no
    /// cranelift compile).
    pub fn record_warm_hit(&self) {
        self.warm_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// A cold miss — the component was (re)compiled. `compile_ns` is the cranelift compile cost that
    /// a warm hit avoids (the dominant "cold start" term construens is chasing).
    pub fn record_cold_miss(&self, compile_ns: u64) {
        self.cold_misses.fetch_add(1, Ordering::Relaxed);
        self.compile_ns_total
            .fetch_add(compile_ns, Ordering::Relaxed);
        bump_max(&self.compile_ns_max, compile_ns);
        self.compile_ms_hist.record(compile_ns / 1_000_000);
    }

    /// `n` LRU evictions (0 or 1 per cache insert) — the warm cache was at capacity, so a component
    /// was dropped and its next request will pay a cold recompile. The REASON is structural (the LRU
    /// capacity cap); see [`InstanceStatsSnapshot`]'s `warm_capacity`.
    pub fn record_evictions(&self, n: u64) {
        if n > 0 {
            self.evictions.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// One per-request instance creation from the pre-instantiated component (`instantiate_async`) —
    /// the per-invocation cost distinct from the handler body and from a cold compile.
    pub fn record_instantiation(&self, ns: u64) {
        self.instantiations.fetch_add(1, Ordering::Relaxed);
        self.instantiate_ns_total.fetch_add(ns, Ordering::Relaxed);
        bump_max(&self.instantiate_ns_max, ns);
        self.instantiate_us_hist.record(ns / 1_000);
    }

    /// Project a read-only snapshot, folding in the engine-supplied live numbers (the current warm
    /// set size + capacity + in-flight + ceiling it reads under its own locks).
    fn snapshot(&self, live: LaneLive) -> LaneStats {
        let misses = self.cold_misses.load(Ordering::Relaxed);
        let insts = self.instantiations.load(Ordering::Relaxed);
        LaneStats {
            warm_now: live.warm_now,
            warm_capacity: live.warm_capacity,
            warm_components: live.warm_components,
            in_flight: live.in_flight,
            lane_ceiling: live.lane_ceiling,
            warm_hits: self.warm_hits.load(Ordering::Relaxed),
            cold_misses: misses,
            evictions: self.evictions.load(Ordering::Relaxed),
            instantiations: insts,
            instantiate_us_avg: avg_us(self.instantiate_ns_total.load(Ordering::Relaxed), insts),
            instantiate_us_max: self.instantiate_ns_max.load(Ordering::Relaxed) / 1_000,
            instantiate_us_p50: self.instantiate_us_hist.percentile(50),
            instantiate_us_p99: self.instantiate_us_hist.percentile(99),
            compile_ms_avg: avg_ms(self.compile_ns_total.load(Ordering::Relaxed), misses),
            compile_ms_max: self.compile_ns_max.load(Ordering::Relaxed) / 1_000_000,
            compile_ms_p50: self.compile_ms_hist.percentile(50),
            compile_ms_p99: self.compile_ms_hist.percentile(99),
        }
    }
}

/// The live, engine-read inputs to a lane snapshot (cache size + capacity + the resident component
/// hashes + concurrency), supplied by the engine because they live behind its locks.
pub struct LaneLive {
    pub warm_now: u64,
    pub warm_capacity: u64,
    pub warm_components: Vec<String>,
    pub in_flight: u64,
    pub lane_ceiling: u64,
}

/// Per-component live state (keyed by the component's content hash), tracked ACROSS lanes so an
/// operator can see load + footprint at the component granularity the per-lane counters can't show:
/// how many invocations of THIS component are in flight, how big it is resident, and how often it was
/// rejected (admission refused). Held behind an `Arc` so the in-flight RAII guard can decrement on
/// drop without re-taking the map lock.
#[derive(Debug, Default)]
pub struct ComponentLive {
    /// Invocations of this component in flight right now (RAII inc on serve start, dec on end).
    in_flight: AtomicI64,
    /// Resident footprint proxy in bytes — the component's source wasm length, recorded at compile
    /// (wasmtime doesn't cheaply expose the compiled `ProxyPre`/`ConsumerPre` size).
    resident_bytes: AtomicU64,
    /// Lifetime admission rejections for this component — a `try_acquire` on the lane permit failed
    /// (`HandlerError::Overloaded`, a 503). The model is FAIL-FAST (no wait-queue), so this rejection
    /// count — together with `in_flight` and, for messaging, the per-topic outstanding — IS the
    /// "queue depth" signal (there is no classic waiters gauge to report).
    overloaded: AtomicU64,
}

/// An RAII in-flight guard: increments the component's `in_flight` on creation (see
/// [`InstanceStats::enter_component`]) and decrements it on drop — so a trap/early-return on the serve
/// path can never leak a stuck count.
pub struct ComponentGuard(Arc<ComponentLive>);

impl Drop for ComponentGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// All three lanes' lifecycle counters, held on the engine (`Arc`-shared) and incremented on the
/// serve path.
#[derive(Debug, Default)]
pub struct InstanceStats {
    pub request: LaneCounters,
    pub consumer: LaneCounters,
    pub session: LaneCounters,
    /// Per-component live state (in-flight / resident bytes / rejections), keyed by content hash.
    components: Mutex<HashMap<String, Arc<ComponentLive>>>,
}

impl InstanceStats {
    /// The counters for one lane.
    pub fn lane(&self, lane: StatLane) -> &LaneCounters {
        match lane {
            StatLane::Request => &self.request,
            StatLane::Consumer => &self.consumer,
            StatLane::Session => &self.session,
        }
    }

    /// The per-component live-state cell for `hash`, creating it on first use. One map lock; the
    /// returned `Arc` lets callers (and the RAII guard) touch the atomics without re-locking.
    fn component(&self, hash: &str) -> Arc<ComponentLive> {
        let mut map = self.components.lock().unwrap();
        map.entry(hash.to_string()).or_default().clone()
    }

    /// Enter a serve of component `hash`: bump its in-flight count and return an RAII guard that
    /// decrements on drop (so a trap/early-return can't leak the count). Call right after the lane
    /// permit is acquired, on every lane (request/async/streaming/consumer).
    pub fn enter_component(&self, hash: &str) -> ComponentGuard {
        let cell = self.component(hash);
        cell.in_flight.fetch_add(1, Ordering::Relaxed);
        ComponentGuard(cell)
    }

    /// Record the resident-footprint proxy (source wasm length) for `hash`, at compile time.
    pub fn record_resident_bytes(&self, hash: &str, bytes: u64) {
        self.component(hash)
            .resident_bytes
            .store(bytes, Ordering::Relaxed);
    }

    /// Record an admission rejection (lane permit `try_acquire` failed → `Overloaded`/503) for `hash`.
    pub fn record_overloaded(&self, hash: &str) {
        self.component(hash)
            .overloaded
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the per-component live state, sorted by hash for a deterministic payload.
    fn component_stats(&self) -> Vec<ComponentStat> {
        let map = self.components.lock().unwrap();
        let mut out: Vec<ComponentStat> = map
            .iter()
            .map(|(hash, c)| ComponentStat {
                hash: hash.clone(),
                in_flight: c.in_flight.load(Ordering::Relaxed).max(0) as u64,
                resident_bytes: c.resident_bytes.load(Ordering::Relaxed),
                overloaded: c.overloaded.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by(|a, b| a.hash.cmp(&b.hash));
        out
    }

    /// Build the full read-only snapshot. The engine passes each lane's live numbers (it reads the
    /// LruCache + semaphore under its own locks) + the process memory view.
    pub fn snapshot(
        &self,
        request: LaneLive,
        consumer: LaneLive,
        session: LaneLive,
        memory: ProcessMemory,
    ) -> InstanceStatsSnapshot {
        InstanceStatsSnapshot {
            memory,
            request: self.request.snapshot(request),
            consumer: self.consumer.snapshot(consumer),
            session: self.session.snapshot(session),
            component_stats: self.component_stats(),
        }
    }
}

/// Per-component live stats (in-flight / resident bytes / admission rejections), keyed by content
/// hash — the component-granularity view the per-lane counters can't give. There is no classic
/// wait-queue (admission is fail-fast), so "queue depth" for a component reads as `in_flight` (load
/// now) + `overloaded` (lifetime rejections); for a messaging consumer the per-topic unacked
/// outstanding is the companion signal (surfaced on the messaging-stats / node-health surface).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentStat {
    /// The component's content hash.
    pub hash: String,
    /// Invocations of this component in flight right now (across lanes).
    pub in_flight: u64,
    /// Resident footprint proxy in bytes (the source wasm length recorded at compile).
    pub resident_bytes: u64,
    /// Lifetime admission rejections (a 503 `Overloaded` — the lane was at its concurrency ceiling).
    pub overloaded: u64,
}

/// Read-only lifecycle snapshot for one lane (serde: the admin stats API / CLI shape).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaneStats {
    /// Compiled components resident in this lane's warm cache right now.
    pub warm_now: u64,
    /// The lane's warm-cache capacity (the LRU cap — the eviction REASON when `warm_now` is pinned
    /// here and `evictions` climbs).
    pub warm_capacity: u64,
    /// The component hashes currently resident (so an operator sees WHICH components are warm).
    pub warm_components: Vec<String>,
    /// Invocations in flight on this lane right now.
    pub in_flight: u64,
    /// The lane's concurrency ceiling (requests beyond it queue for a permit — contention).
    pub lane_ceiling: u64,
    /// Lifetime warm hits (a resident component was reused — no compile).
    pub warm_hits: u64,
    /// Lifetime cold misses (a component was (re)compiled — the cold-start cost).
    pub cold_misses: u64,
    /// Lifetime LRU evictions (a warm component was dropped because the cache was full).
    pub evictions: u64,
    /// Lifetime per-request instantiations from a pre-instantiated component.
    pub instantiations: u64,
    /// Mean per-request instantiate cost, microseconds (distinct from a cold compile below).
    pub instantiate_us_avg: u64,
    /// Worst per-request instantiate cost, microseconds.
    pub instantiate_us_max: u64,
    /// p50 / p99 per-request instantiate cost, microseconds (power-of-two histogram upper bound).
    pub instantiate_us_p50: u64,
    pub instantiate_us_p99: u64,
    /// Mean cold-compile cost, milliseconds (the term a warm hit avoids).
    pub compile_ms_avg: u64,
    /// Worst cold-compile cost, milliseconds.
    pub compile_ms_max: u64,
    /// p50 / p99 cold-compile cost, milliseconds (power-of-two histogram upper bound).
    pub compile_ms_p50: u64,
    pub compile_ms_p99: u64,
}

/// The node's process memory view: resident set vs the configured per-instance ceiling, so an
/// operator can see headroom. `rss_bytes` is `None` where it can't be read (non-Linux / dev).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProcessMemory {
    /// Process resident set size in bytes (Linux `/proc/self/statm`), or `None` off Linux.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    /// The configured per-invocation linear-memory ceiling in bytes (the engine `Limits`), a proxy
    /// for how much one warm instance may cost — context for `rss_bytes`.
    pub per_instance_limit_bytes: u64,
}

/// The whole-engine instance-lifecycle + memory snapshot (the admin stats payload).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceStatsSnapshot {
    pub memory: ProcessMemory,
    pub request: LaneStats,
    pub consumer: LaneStats,
    pub session: LaneStats,
    /// Per-component live state (in-flight / resident bytes / rejections), sorted by hash. Additive:
    /// the per-lane `warm_components: Vec<String>` is unchanged (console back-compat).
    #[serde(default)]
    pub component_stats: Vec<ComponentStat>,
}

/// Read the process resident-set size in bytes from `/proc/self/statm` (field 2 = resident pages ×
/// page size). `None` off Linux (dev macOS) or on any read/parse error — the stats then omit RSS
/// rather than fabricate it.
#[must_use]
pub fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // Read `VmRSS: N kB` from `/proc/self/status` — already in kB, so no page-size assumption
        // (the old `/proc/self/statm` pages × 4096 under-reported RSS 4–16× on 16K/64K-page hosts,
        // e.g. some ARM64 — exactly the memory-headroom view this must get right). `None` on any
        // parse failure.
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kib: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kib * 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Monotonic-max update on an atomic (relaxed CAS loop).
fn bump_max(slot: &AtomicU64, v: u64) {
    let mut cur = slot.load(Ordering::Relaxed);
    while v > cur {
        match slot.compare_exchange_weak(cur, v, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
}

fn avg_us(total_ns: u64, count: u64) -> u64 {
    total_ns.checked_div(count).map_or(0, |v| v / 1_000)
}

fn avg_ms(total_ns: u64, count: u64) -> u64 {
    total_ns.checked_div(count).map_or(0, |v| v / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_record_and_snapshot() {
        let stats = InstanceStats::default();
        let r = stats.lane(StatLane::Request);
        r.record_warm_hit();
        r.record_warm_hit();
        r.record_cold_miss(200_000_000); // 200ms compile
        r.record_evictions(1);
        r.record_instantiation(3_000); // 3µs
        r.record_instantiation(9_000); // 9µs

        let live = |warm: &[&str]| LaneLive {
            warm_now: warm.len() as u64,
            warm_capacity: 32,
            warm_components: warm.iter().map(|s| (*s).to_string()).collect(),
            in_flight: 1,
            lane_ceiling: 10,
        };
        let snap = stats.snapshot(
            live(&["abc", "def"]),
            live(&[]),
            live(&[]),
            ProcessMemory {
                rss_bytes: Some(1024),
                per_instance_limit_bytes: 256 * 1024 * 1024,
            },
        );
        let rq = &snap.request;
        assert_eq!(rq.warm_hits, 2);
        assert_eq!(rq.cold_misses, 1);
        assert_eq!(rq.evictions, 1);
        assert_eq!(rq.instantiations, 2);
        assert_eq!(rq.warm_now, 2);
        assert_eq!(rq.warm_capacity, 32);
        assert_eq!(
            rq.warm_components,
            vec!["abc".to_string(), "def".to_string()]
        );
        assert_eq!(rq.compile_ms_avg, 200, "200ms compile");
        assert_eq!(rq.compile_ms_max, 200);
        assert_eq!(rq.instantiate_us_avg, 6, "(3+9)/2 = 6µs");
        assert_eq!(rq.instantiate_us_max, 9);
        // Idle lanes report zeros + empty warm set.
        assert_eq!(snap.consumer.warm_hits, 0);
        assert_eq!(snap.consumer.warm_now, 0);
        assert_eq!(snap.memory.rss_bytes, Some(1024));
    }

    #[test]
    fn empty_counters_are_zero_not_nan() {
        let stats = InstanceStats::default();
        let live = LaneLive {
            warm_now: 0,
            warm_capacity: 0,
            warm_components: vec![],
            in_flight: 0,
            lane_ceiling: 0,
        };
        let snap = stats.snapshot(
            LaneLive {
                ..live_clone(&live)
            },
            LaneLive {
                ..live_clone(&live)
            },
            live,
            ProcessMemory::default(),
        );
        assert_eq!(snap.request.instantiate_us_avg, 0);
        assert_eq!(snap.request.compile_ms_avg, 0);
    }

    #[test]
    fn per_component_stats_track_inflight_resident_and_overloaded() {
        let empty = || LaneLive {
            warm_now: 0,
            warm_capacity: 0,
            warm_components: vec![],
            in_flight: 0,
            lane_ceiling: 0,
        };
        let snap_of = |stats: &InstanceStats| {
            stats.snapshot(empty(), empty(), empty(), ProcessMemory::default())
        };
        let stats = InstanceStats::default();
        stats.record_resident_bytes("abc", 4096);
        stats.record_overloaded("abc");
        stats.record_overloaded("abc");
        {
            let _g1 = stats.enter_component("abc");
            let _g2 = stats.enter_component("abc");
            let snap = snap_of(&stats);
            let c = snap
                .component_stats
                .iter()
                .find(|c| c.hash == "abc")
                .expect("component abc present");
            assert_eq!(c.in_flight, 2, "two in-flight guards held");
            assert_eq!(c.resident_bytes, 4096);
            assert_eq!(c.overloaded, 2);
            // The per-lane warm_components field is untouched (console back-compat).
            assert!(snap.request.warm_components.is_empty());
        }
        // Both RAII guards dropped → in-flight returns to zero (no leak on scope exit).
        let c = snap_of(&stats)
            .component_stats
            .into_iter()
            .find(|c| c.hash == "abc")
            .expect("component abc still present");
        assert_eq!(c.in_flight, 0, "in-flight decremented on guard drop");
        assert_eq!(c.resident_bytes, 4096, "resident bytes persist");
    }

    fn live_clone(l: &LaneLive) -> LaneLive {
        LaneLive {
            warm_now: l.warm_now,
            warm_capacity: l.warm_capacity,
            warm_components: l.warm_components.clone(),
            in_flight: l.in_flight,
            lane_ceiling: l.lane_ceiling,
        }
    }
}
