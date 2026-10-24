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
//! **Bucket keying (senior-architect review).** The bucket key is the peer's IPv4 address in full
//! (`/32`), but an IPv6 peer is keyed by a **prefix** (default `/64`): a single end site is routinely
//! handed a whole `/64` (or larger), so keying on the full `/128` would let one owner rotate through
//! 2⁶⁴ source addresses to get a fresh bucket per connection (limit bypassed) AND to spray the tracked
//! map with distinct keys. Masking to the `/64` collapses a site to one bucket.
//!
//! **Memory bound (senior-architect review).** The tracked-key map is an [`lru::LruCache`] hard-capped
//! at `max_tracked`: inserting a new key when full evicts the **least-recently-used** bucket in O(1).
//! For a token bucket the least-recently-touched entry is the one that has had the longest to refill —
//! i.e. the most-refilled, idle entry — so dropping it is lossless (a re-created bucket starts full).
//! This replaces the earlier O(n) `retain`-scan-then-refuse eviction; the map can never exceed
//! `max_tracked`, and under an IP-spray flood the coldest bucket is always the one shed.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

use lru::LruCache;

/// Default IPv6 bucket prefix: a peer's IPv6 address is masked to its first `/64` for keying, so a
/// whole end site (routinely a `/64`) is one bucket. Operators override per listener
/// (`conn_rate_ipv6_prefix`, validated `1..=128`). IPv4 is always keyed in full (`/32`).
pub const DEFAULT_CONN_RATE_IPV6_PREFIX: u8 = 64;

/// A per-IP token bucket. `rate` tokens accrue per second up to `burst`; one token is spent per
/// admitted connection. All state is behind one mutex and admission is O(1). `admit` runs from the
/// accept loop for a direct listener, but from many concurrently-spawned per-connection tasks on a
/// `proxy_protocol` listener (the real IP is only known after the header is read) — the mutex makes
/// that safe; do not reintroduce a single-task assumption.
pub struct PeerConnLimiter {
    rate_per_sec: f64,
    burst: f64,
    /// IPv6 bucket prefix length (bits); IPv4 is always full. Clamped to `1..=128` at construction.
    ipv6_prefix: u8,
    /// The tracked per-key buckets, hard-capped at `max_tracked` — a new key when full LRU-evicts the
    /// coldest (idle) bucket in O(1). Keyed by the BUCKET key ([`Self::bucket_key`]), not the raw peer.
    buckets: Mutex<LruCache<IpAddr, Bucket>>,
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
}

/// Mask an IPv6 address to its first `prefix` bits (the rest zeroed) for bucket keying. `prefix` is
/// `1..=128` in practice (clamped at construction); `0` is handled defensively (whole address zeroed).
fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let prefix = u32::from(prefix.min(128));
    let bits = u128::from(addr);
    // `u128::MAX << 128` would overflow the shift; guard the `prefix == 0` edge explicitly.
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(bits & mask)
}

impl PeerConnLimiter {
    /// `rate_per_sec` tokens/sec, `burst` max tokens (the immediate allowance), `max_tracked` the hard
    /// cap on simultaneously-tracked bucket keys (LRU eviction of the coldest bucket keeps the map
    /// within it), `ipv6_prefix` the IPv6 bucket-prefix length (bits; clamped `1..=128`; IPv4 keyed in
    /// full). `max_tracked` is floored at 1.
    pub fn new(rate_per_sec: f64, burst: u32, max_tracked: usize, ipv6_prefix: u8) -> Self {
        let cap = NonZeroUsize::new(max_tracked.max(1)).expect("max_tracked.max(1) >= 1");
        Self {
            rate_per_sec,
            burst: f64::from(burst.max(1)),
            ipv6_prefix: ipv6_prefix.clamp(1, 128),
            buckets: Mutex::new(LruCache::new(cap)),
        }
    }

    /// The bucket key for `ip`: the IPv4 address in full, or a genuine IPv6 address masked to
    /// `ipv6_prefix`. A **v4-mapped** IPv6 address (`::ffff:a.b.c.d`, how an IPv4 client arrives on a
    /// dual-stack `[::]` listener when `bindv6only=0`) is unwrapped to its embedded IPv4 and keyed in
    /// full FIRST — otherwise masking to the prefix would zero the v4 bits (they live in the low 32),
    /// collapsing every IPv4 peer to one `::` bucket and defeating per-IPv4 rate limiting (one client
    /// could then hold the shared bucket empty and lock out the whole IPv4 Internet for the listener).
    fn bucket_key(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(_) => ip,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(mask_v6(v6, self.ipv6_prefix)),
            },
        }
    }

    /// Admit (`true`) or refuse (`false`) a connection from `ip` right now.
    pub fn admit(&self, ip: IpAddr) -> bool {
        self.admit_at(ip, Instant::now())
    }

    /// Testable core: admission decision at an explicit `now`.
    fn admit_at(&self, ip: IpAddr, now: Instant) -> bool {
        let key = self.bucket_key(ip);
        // Recover from a poisoned lock rather than panic (security-review INFO): the critical section
        // is panic-free (float math + LruCache ops on trusted values), so poisoning is unreachable —
        // but if it ever happened, a panic here would kill the listener's accept loop. The bucket map
        // holds no cross-op invariant a mid-op panic could corrupt, so continuing with the recovered
        // map is safe and strictly better than dropping the whole listener.
        let mut map = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (rate, burst) = (self.rate_per_sec, self.burst);
        // O(1) get-or-create, promoting this key to most-recently-used. When the map is at
        // `max_tracked` and `key` is new, `LruCache` evicts the LEAST-recently-used bucket — the
        // coldest = longest-untouched = most-refilled (idle) entry, which is lossless to drop (a
        // re-created bucket starts full). So an IP-spray flood of fresh keys can never grow the map
        // past `max_tracked`, and the entry shed is always the one carrying the least state.
        let bucket = map.get_or_insert_mut(key, || Bucket {
            tokens: burst,
            last: now,
        });
        bucket.refill(now, rate, burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Current tracked-key count (observability / tests).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
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
        let lim = PeerConnLimiter::new(2.0, 3, 1000, DEFAULT_CONN_RATE_IPV6_PREFIX);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(1), t0));
        assert!(!lim.admit_at(ip(1), t0), "4th over burst must be refused");
    }

    #[test]
    fn bucket_refills_over_time() {
        let lim = PeerConnLimiter::new(2.0, 3, 1000, DEFAULT_CONN_RATE_IPV6_PREFIX);
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
        let lim = PeerConnLimiter::new(1.0, 1, 1000, DEFAULT_CONN_RATE_IPV6_PREFIX);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(!lim.admit_at(ip(1), t0), "ip1 exhausted its 1-token burst");
        assert!(lim.admit_at(ip(2), t0), "ip2 has its own budget");
    }

    #[test]
    fn map_is_bounded_by_lru_eviction() {
        // Cap at 2 tracked keys. Fill 2, then a 3rd key: the LRU (ip1, least-recently-touched) is
        // evicted in O(1) and the map stays within the cap. (Under the old scheme this depended on a
        // bucket being refilled-to-idle; with an LRU the coldest entry is shed regardless.)
        let lim = PeerConnLimiter::new(1.0, 1, 2, DEFAULT_CONN_RATE_IPV6_PREFIX);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(2), t0));
        assert_eq!(lim.tracked(), 2);
        assert!(
            lim.admit_at(ip(3), t0),
            "a new key always admits (its bucket starts full)"
        );
        assert_eq!(
            lim.tracked(),
            2,
            "the map must stay within max_tracked via LRU eviction"
        );
    }

    #[test]
    fn new_key_admits_by_evicting_lru_even_when_all_active() {
        // The LRU replacement for the old "refuse a new IP when the map is full of active buckets"
        // backstop: with an LRU map, a new key evicts the least-recently-used bucket and IS admitted
        // (the shed bucket is the coldest — least state — even under a max_tracked-wide active flood).
        // Cap at 2; ip1 and ip2 each spend their only token at t0 (both mid-drain, NOT idle).
        let lim = PeerConnLimiter::new(1.0, 1, 2, DEFAULT_CONN_RATE_IPV6_PREFIX);
        let t0 = Instant::now();
        assert!(lim.admit_at(ip(1), t0));
        assert!(lim.admit_at(ip(2), t0));
        assert_eq!(lim.tracked(), 2);
        assert!(
            lim.admit_at(ip(3), t0),
            "a new key admits by evicting the LRU bucket, even when every tracked bucket is active"
        );
        assert_eq!(lim.tracked(), 2, "map stays hard-bounded at max_tracked");
        // ip1 was the LRU and was evicted → its bucket is re-created full, so it admits again (its
        // earlier spend is forgotten — the documented, lossless cost of shedding the coldest entry).
        assert!(
            lim.admit_at(ip(1), t0),
            "the evicted key's bucket is re-created full"
        );
    }

    #[test]
    fn ipv6_is_keyed_by_prefix() {
        // Default /64 prefix: two distinct /128s inside the SAME /64 share ONE bucket (a /64 owner
        // can't rotate addresses to dodge the limit); two addresses in DIFFERENT /64s do not.
        let lim = PeerConnLimiter::new(1.0, 1, 1000, DEFAULT_CONN_RATE_IPV6_PREFIX);
        let t0 = Instant::now();
        let a: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1::2".parse().unwrap(); // same /64 as `a`
        let c: IpAddr = "2001:db8:abcd:2::1".parse().unwrap(); // a different /64
        assert!(lim.admit_at(a, t0));
        assert!(
            !lim.admit_at(b, t0),
            "a different /128 in the same /64 shares a's bucket (burst 1 already spent)"
        );
        assert!(lim.admit_at(c, t0), "a different /64 has its own bucket");
        // The two same-/64 addresses collapsed to ONE tracked key; the other /64 is a second.
        assert_eq!(lim.tracked(), 2);
    }

    #[test]
    fn ipv6_full_prefix_keys_each_address_separately() {
        // With a /128 prefix each full address is its own bucket (prefix = 128 ⇒ no masking).
        let lim = PeerConnLimiter::new(1.0, 1, 1000, 128);
        let t0 = Instant::now();
        let a: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1::2".parse().unwrap(); // same /64, different /128
        assert!(lim.admit_at(a, t0));
        assert!(
            lim.admit_at(b, t0),
            "with a /128 prefix a different address has its own bucket"
        );
    }

    #[test]
    fn v4_mapped_ipv6_peers_key_as_distinct_ipv4_not_a_collapsed_v6_bucket() {
        // REGRESSION: on a dual-stack `[::]` listener (bindv6only=0) an IPv4 client arrives as a
        // v4-mapped IPv6 `::ffff:a.b.c.d`, whose v4 bits live in the low 32. Masking to the /64 prefix
        // would zero them and collapse EVERY IPv4 peer to one `::` bucket (defeating per-IPv4 limiting
        // + letting one client lock out all IPv4). Each v4-mapped peer must key as its own /32.
        let lim = PeerConnLimiter::new(1.0, 1, 1000, DEFAULT_CONN_RATE_IPV6_PREFIX);
        let t0 = Instant::now();
        let a: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        let b: IpAddr = "::ffff:5.6.7.8".parse().unwrap();
        assert!(lim.admit_at(a, t0));
        assert!(
            lim.admit_at(b, t0),
            "a different v4-mapped peer must have its own bucket, not a collapsed `::`"
        );
        // The v4-mapped and bare forms of the SAME IPv4 are one bucket: a's burst is already spent.
        let a_bare: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(
            !lim.admit_at(a_bare, t0),
            "the v4-mapped and bare forms of one IPv4 must share a single bucket"
        );
        // Two distinct IPv4 peers ⇒ two tracked keys, never one collapsed `::`.
        assert_eq!(lim.tracked(), 2);
    }
}
