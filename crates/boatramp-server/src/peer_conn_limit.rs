//! Per-source-IP connection-rate admission for host-owned `[serve.listeners]` (mailroom cap-req #18).
//!
//! A `[serve.listeners]` listener hands each accepted TCP connection to a FaaS session/connection
//! guest (e.g. an imapd on :993). The guest NEVER sees the peer IP — it only gets the connection's
//! `wasi:io` streams — so it cannot throttle a brute-force client the way native imapd does (a client
//! otherwise resets its auth-backoff just by reconnecting, the 28g MEDIUM-1). So the HOST admits
//! each connection through a per-source-IP **token bucket** (steady `rate` tokens/sec, up to
//! `burst`) BEFORE any guest work — in the accept loop for a direct listener, or just after the
//! PROXY-protocol header reveals the real client IP (then in the spawned task) on a `proxy_protocol`
//! listener (cap-req 18 completion). A client may open `burst` connections immediately, then `rate`/sec
//! sustained; over that, the connection is refused and closed cheaply.
//!
//! Memory is bounded against an IP-spray DoS: a bucket refilled to `burst` is **idle** — dropping it
//! loses no state (a re-created bucket starts full), so when the tracked-IP map would exceed
//! `max_tracked`, the limiter evicts full (idle) buckets before inserting a new IP. If eviction frees
//! nothing (every tracked IP mid-drain — a genuine `max_tracked`-wide distributed flood), the new
//! connection is refused rather than tracked, so the map is hard-bounded at `max_tracked`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// A per-IP token bucket. `rate` tokens accrue per second up to `burst`; one token is spent per
/// admitted connection. All state is behind one mutex and admission is O(1) amortized. `admit` runs
/// from the accept loop for a direct listener, but from many concurrently-spawned per-connection
/// tasks on a `proxy_protocol` listener (the real IP is only known after the header is read) — the
/// mutex makes that safe; do not reintroduce a single-task assumption.
pub struct PeerConnLimiter {
    rate_per_sec: f64,
    burst: f64,
    max_tracked: usize,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// Accrue tokens for the time since the last touch, capped at `burst`.
    fn refill(&mut self, now: Instant, rate_per_sec: f64, burst: f64) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        if dt > 0.0 {
            self.tokens = (self.tokens + dt * rate_per_sec).min(burst);
            self.last = now;
        }
    }
    /// A bucket at full tokens is indistinguishable from a freshly-created one, so it holds no state
    /// worth keeping — safe to evict to bound memory.
    fn is_idle(&self, burst: f64) -> bool {
        self.tokens >= burst
    }
}

impl PeerConnLimiter {
    /// `rate_per_sec` tokens/sec, `burst` max tokens (the immediate allowance), `max_tracked` the
    /// hard cap on simultaneously-tracked IPs (eviction of idle buckets keeps the map within it).
    pub fn new(rate_per_sec: f64, burst: u32, max_tracked: usize) -> Self {
        Self {
            rate_per_sec,
            burst: f64::from(burst.max(1)),
            max_tracked: max_tracked.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Admit (`true`) or refuse (`false`) a connection from `ip` right now.
    pub fn admit(&self, ip: IpAddr) -> bool {
        self.admit_at(ip, Instant::now())
    }

    /// Testable core: admission decision at an explicit `now`.
    fn admit_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.buckets.lock().expect("peer-conn-limit mutex poisoned");
        // Bound the map: before tracking a NEW ip over the cap, drop idle (full) buckets. Dropping a
        // full bucket is lossless — a re-created one starts full too — so a flooding spray of fresh
        // IPs can never grow the map past `max_tracked` with meaningful state.
        if map.len() >= self.max_tracked && !map.contains_key(&ip) {
            let (rate, burst) = (self.rate_per_sec, self.burst);
            map.retain(|_, b| {
                b.refill(now, rate, burst);
                !b.is_idle(burst)
            });
            // Hard bound: if eviction freed nothing — every tracked IP is still mid-drain, i.e. a
            // genuine distributed flood of `max_tracked` simultaneously-active sources — refuse the
            // new IP rather than grow the map past its cap. Not tracking a refused connection loses
            // nothing (it is simply not admitted), and declining new sources is the correct backstop
            // under a flood of that scale. (`ip` is still absent here — retain never inserts it.)
            if map.len() >= self.max_tracked {
                return false;
            }
        }
        let burst = self.burst;
        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        bucket.refill(now, self.rate_per_sec, burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Current tracked-IP count (observability / tests).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn burst_is_admitted_then_refused_over_rate() {
        // rate 2/s, burst 3: the first 3 (the burst) are admitted at t0, the 4th is refused.
        let lim = PeerConnLimiter::new(2.0, 3, 1000);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(1), t0));
        assert!(!lim.admit_at(ip(1), t0), "4th over burst must be refused");
    }

    #[test]
    fn bucket_refills_over_time() {
        let lim = PeerConnLimiter::new(2.0, 3, 1000);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(lim.admit_at(ip(1), t0));
        }
        assert!(!lim.admit_at(ip(1), t0));
        // After 1s at 2 tokens/sec, 2 more are available.
        let t1 = t0 + Duration::from_secs(1);
        assert!(lim.admit_at(ip(1), t1));
        assert!(lim.admit_at(ip(1), t1));
        assert!(!lim.admit_at(ip(1), t1), "only 2 refilled in 1s at rate 2");
    }

    #[test]
    fn distinct_ips_have_independent_budgets() {
        let lim = PeerConnLimiter::new(1.0, 1, 1000);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(!lim.admit_at(ip(1), t0), "ip1 exhausted its 1-token burst");
        assert!(lim.admit_at(ip(2), t0), "ip2 has its own budget");
    }

    #[test]
    fn map_is_bounded_by_evicting_idle_buckets() {
        // Cap at 2 tracked IPs. Fill 2 (each spends its only token → NOT idle), then a 3rd IP at a
        // later time when 1+2 have refilled to full (idle) → eviction keeps the map within the cap.
        let lim = PeerConnLimiter::new(100.0, 1, 2);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(2), t0));
        assert_eq!(lim.tracked(), 2);
        // Well after refill (rate 100/s, burst 1 → full within 10ms), ip1/ip2 are idle (full).
        let t1 = t0 + Duration::from_secs(1);
        assert!(lim.admit_at(ip(3), t1));
        assert!(
            lim.tracked() <= 2,
            "the map must stay within max_tracked by evicting full/idle buckets, got {}",
            lim.tracked()
        );
    }

    #[test]
    fn map_is_hard_bounded_when_no_bucket_is_idle() {
        // Cap at 2. Two IPs each spend their only token at t0 (burst 1 → both mid-drain, NOT idle).
        // A 3rd IP at the SAME instant finds nothing evictable: it must be refused, and the map must
        // not grow past the cap (the DoS backstop under a max_tracked-wide active flood).
        let lim = PeerConnLimiter::new(1.0, 1, 2);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(2), t0));
        assert_eq!(lim.tracked(), 2);
        assert!(
            !lim.admit_at(ip(3), t0),
            "a new IP must be refused when the map is full of active (non-idle) IPs"
        );
        assert_eq!(
            lim.tracked(),
            2,
            "map must stay hard-bounded at max_tracked"
        );
    }
}
