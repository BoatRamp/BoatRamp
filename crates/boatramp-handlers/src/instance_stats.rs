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

use std::sync::atomic::{AtomicU64, Ordering};

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
            compile_ms_avg: avg_ms(self.compile_ns_total.load(Ordering::Relaxed), misses),
            compile_ms_max: self.compile_ns_max.load(Ordering::Relaxed) / 1_000_000,
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

/// All three lanes' lifecycle counters, held on the engine (`Arc`-shared) and incremented on the
/// serve path.
#[derive(Debug, Default)]
pub struct InstanceStats {
    pub request: LaneCounters,
    pub consumer: LaneCounters,
    pub session: LaneCounters,
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
        }
    }
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
    /// Mean cold-compile cost, milliseconds (the term a warm hit avoids).
    pub compile_ms_avg: u64,
    /// Worst cold-compile cost, milliseconds.
    pub compile_ms_max: u64,
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
