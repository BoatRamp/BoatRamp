//! In-memory token-bucket rate limiter, keyed by `(site, client IP)`.
//!
//! The budget (`rps`/`burst`) is site config ([`boatramp_core::access::RateLimit`]);
//! the buckets themselves are process-local state held here. A bucket refills
//! continuously at `rps` tokens/second up to `burst`. Checking a request is a
//! single mutex-guarded arithmetic step — it happens *before* the streaming
//! body, so it never stalls a response in flight.
//!
//! The default is process-local; an opt-in **KV-backed fixed-window** store
//! ([`KvRateLimiter`]) shares limits across a cluster. Both implement
//! [`RateLimitStore`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use boatramp_core::access::RateLimit;
use boatramp_core::kv::KvStore;
use serde::{Deserialize, Serialize};

/// Cap on distinct buckets, so a flood of unique client IPs cannot grow the map
/// without bound. When exceeded, idle (full) buckets are dropped first.
const MAX_BUCKETS: usize = 100_000;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A token-bucket rate limiter shared across requests.
#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<(String, IpAddr), Bucket>>,
}

impl RateLimiter {
    /// Create an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge one request to `(site, ip)` under `limit`. Returns `true` if a
    /// token was available (request allowed), `false` if the bucket is empty
    /// (request should be rejected with `429`).
    pub fn check(&self, site: &str, ip: IpAddr, limit: &RateLimit) -> bool {
        let capacity = limit.burst_capacity() as f64;
        let rate = limit.rps.max(1) as f64;
        let now = Instant::now();

        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(&(site.to_string(), ip)) {
            // Evict idle (refilled-to-capacity) buckets to make room.
            buckets.retain(|_, b| {
                let refilled = b.tokens + now.duration_since(b.last).as_secs_f64() * rate;
                refilled < capacity
            });
        }

        let bucket = buckets.entry((site.to_string(), ip)).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * rate).min(capacity);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A rate-limit decision backend. The default ([`RateLimiter`]) is
/// process-local token buckets; [`KvRateLimiter`] shares an approximate
/// fixed-window count across a cluster via the control-plane KV.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Charge one request to `(site, ip)` under `limit`; `true` = allowed.
    async fn check(&self, site: &str, ip: IpAddr, limit: &RateLimit) -> bool;
}

#[async_trait]
impl RateLimitStore for RateLimiter {
    async fn check(&self, site: &str, ip: IpAddr, limit: &RateLimit) -> bool {
        // The in-process bucket is a synchronous arithmetic step.
        Self::check(self, site, ip, limit)
    }
}

/// Length of the KV fixed window (seconds).
const WINDOW_SECS: u64 = 1;

/// A `(site, ip)` window counter as stored in the KV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct RateLimitWindow {
    /// Unix-second the current window started.
    window_start: u64,
    /// Requests counted in the current window.
    count: u64,
}

/// Pure fixed-window decision: given the stored `window` (if any), `now`, and
/// the per-window `max`, return `(allowed, window_to_store)`. When the request
/// is rejected the window is unchanged, so the caller can skip the write.
fn fixed_window_decision(
    window: Option<RateLimitWindow>,
    now: u64,
    max: u64,
) -> (bool, RateLimitWindow) {
    match window {
        Some(w) if now < w.window_start.saturating_add(WINDOW_SECS) => {
            if w.count >= max {
                (false, w)
            } else {
                (
                    true,
                    RateLimitWindow {
                        window_start: w.window_start,
                        count: w.count + 1,
                    },
                )
            }
        }
        // No window, or it has rolled over → start a fresh one.
        _ => (
            true,
            RateLimitWindow {
                window_start: now,
                count: 1,
            },
        ),
    }
}

/// A **cluster-wide** rate limiter backed by the control-plane [`KvStore`]: an
/// approximate fixed-window counter per `(site, ip)` at `ratelimit/<site>/<ip>`.
///
/// Trade-offs (opt-in, deliberately): each *limited* request does a KV read and
/// (when allowed) a write — in cluster mode that's a Raft write per request, so
/// enable it only where shared limits matter more than that cost. Concurrent
/// requests race the read-modify-write, so the count is approximate (it can
/// admit a few extra — never over-blocks). Window keys are per-`(site, ip)`
/// (bounded by distinct clients, like the in-process map) but have no TTL, so a
/// long-lived deployment should prune stale `ratelimit/` keys periodically (or
/// use a TTL-capable backend); production-grade precision wants Redis.
pub struct KvRateLimiter {
    kv: Arc<dyn KvStore>,
    /// On a KV read failure: `true` ⇒ allow (availability), `false` ⇒ deny
    /// (fail closed). Set from the security posture; the strict
    /// default is fail-closed so a KV outage can't silently disable limits.
    fail_open: bool,
}

impl KvRateLimiter {
    /// Build over a (ideally shared/replicated) KV backend. `fail_open` selects
    /// the behavior when the KV is unreadable (see the field).
    pub fn new(kv: Arc<dyn KvStore>, fail_open: bool) -> Self {
        Self { kv, fail_open }
    }
}

#[async_trait]
impl RateLimitStore for KvRateLimiter {
    async fn check(&self, site: &str, ip: IpAddr, limit: &RateLimit) -> bool {
        let key = format!("ratelimit/{site}/{ip}");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let current = match self.kv.get(&key).await {
            Ok(Some(bytes)) => serde_json::from_slice::<RateLimitWindow>(&bytes).ok(),
            Ok(None) => None,
            // A KV read failure: deny (fail closed) unless the posture opts into
            // availability-over-precision.
            Err(_) => return self.fail_open,
        };
        let (allowed, window) = fixed_window_decision(current, now, limit.burst_capacity() as u64);
        if allowed {
            if let Ok(bytes) = serde_json::to_vec(&window) {
                let _ = self.kv.put(&key, bytes).await;
            }
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "203.0.113.1".parse().unwrap()
    }

    #[test]
    fn fixed_window_allows_up_to_max_then_blocks_then_rolls() {
        let max = 2;
        // Fresh window: allowed, count 1.
        let (ok, w) = fixed_window_decision(None, 100, max);
        assert!(ok && w.count == 1 && w.window_start == 100);
        // Second within window: allowed, count 2.
        let (ok, w) = fixed_window_decision(Some(w), 100, max);
        assert!(ok && w.count == 2);
        // Third within window: blocked, window unchanged.
        let (ok, w2) = fixed_window_decision(Some(w), 100, max);
        assert!(!ok && w2 == w);
        // After the window rolls (now ≥ start+1s): fresh window.
        let (ok, w3) = fixed_window_decision(Some(w), 101, max);
        assert!(ok && w3.count == 1 && w3.window_start == 101);
    }

    #[tokio::test]
    async fn kv_limiter_shares_count_across_checks() {
        use boatramp_core::kv::MemoryKv;
        let limiter = KvRateLimiter::new(Arc::new(MemoryKv::new()), false);
        let limit = RateLimit { rps: 1, burst: 2 }; // burst_capacity → small window max
        let cap = limit.burst_capacity();
        // The first `cap` requests in the window are admitted; the next is not.
        for _ in 0..cap {
            assert!(limiter.check("s", ip(), &limit).await);
        }
        assert!(!limiter.check("s", ip(), &limit).await);
        // A different (site, ip) has its own window.
        assert!(limiter.check("other", ip(), &limit).await);
    }

    /// A KV read failure denies (fail closed) by default, and only
    /// allows when the posture opts into fail-open.
    #[tokio::test]
    async fn kv_limiter_fails_closed_on_kv_error_unless_opted_in() {
        use async_trait::async_trait;
        use boatramp_core::error::KvError;

        // A KV whose every read errors.
        struct FailingKv;
        #[async_trait]
        impl KvStore for FailingKv {
            async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, KvError> {
                Err(KvError::Backend("kv down".into()))
            }
            async fn put(&self, _key: &str, _value: Vec<u8>) -> Result<(), KvError> {
                Ok(())
            }
            async fn delete(&self, _key: &str) -> Result<(), KvError> {
                Ok(())
            }
            async fn list_prefix(&self, _prefix: &str) -> Result<Vec<String>, KvError> {
                Ok(Vec::new())
            }
        }

        let limit = RateLimit { rps: 1, burst: 2 };
        // Fail closed (default strict posture): a KV outage denies.
        let closed = KvRateLimiter::new(Arc::new(FailingKv), false);
        assert!(!closed.check("s", ip(), &limit).await);
        // Fail open (opted in): a KV outage allows.
        let open = KvRateLimiter::new(Arc::new(FailingKv), true);
        assert!(open.check("s", ip(), &limit).await);
    }

    #[test]
    fn allows_burst_then_blocks() {
        let limiter = RateLimiter::new();
        let limit = RateLimit { rps: 1, burst: 3 };
        // Three immediate requests fit the burst; the fourth is blocked.
        assert!(limiter.check("s", ip(), &limit));
        assert!(limiter.check("s", ip(), &limit));
        assert!(limiter.check("s", ip(), &limit));
        assert!(!limiter.check("s", ip(), &limit));
    }

    #[test]
    fn separate_keys_have_separate_buckets() {
        let limiter = RateLimiter::new();
        let limit = RateLimit { rps: 1, burst: 1 };
        assert!(limiter.check("s", ip(), &limit));
        assert!(!limiter.check("s", ip(), &limit));
        // Different site, same IP: fresh bucket.
        assert!(limiter.check("other", ip(), &limit));
        // Different IP, same site: fresh bucket.
        assert!(limiter.check("s", "203.0.113.2".parse().unwrap(), &limit));
    }
}
