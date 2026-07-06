//! Gateway backend selection: per-upstream runtime state
//! feeding the streaming proxy in `lib.rs`. An upstream may name a **pool** of
//! backends (`targets`) load-balanced round-robin or random, with passive
//! health ejection of failing backends, and the pool may be **DNS-discovered**.
//! This module is the pure, testable selection + health + resolution
//! logic; the actual proxying stays in `lib.rs`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use boatramp_core::compute::{ActivitySource, WorkloadActivity};
use boatramp_core::gateway::{ActiveHealth, Discovery, LbPolicy, PassiveHealth, Upstream};

/// Resolves a hostname to addresses — abstracted so DNS discovery is unit
/// testable with a static map (the live path uses the system resolver).
pub trait Resolver: Send + Sync {
    /// Resolve `host` to its A/AAAA addresses (order preserved where possible).
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The system resolver (`getaddrinfo` via `ToSocketAddrs`). Port 0 is a
/// placeholder — only the addresses are used; the [`Discovery`] port is applied
/// when forming backend URLs.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        Ok((host, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect())
    }
}

/// Per-backend passive-health bookkeeping.
#[derive(Default)]
struct BackendHealth {
    /// Passive: consecutive request failures + the ejection deadline.
    consecutive_fails: u32,
    ejected_until: Option<Instant>,
    /// Active probing: running consecutive probe results + the up/down verdict.
    probe_ok: u32,
    probe_fail: u32,
    active_down: bool,
}

/// A cached DNS-discovery result for an upstream.
#[derive(Default)]
struct DnsCache {
    backends: Vec<String>,
    refreshed: Option<Instant>,
}

/// Per-upstream runtime state: the LB cursor, passive-health state per backend,
/// and the DNS-discovery cache. One per `(site, upstream)`.
#[derive(Default)]
pub struct UpstreamState {
    cursor: AtomicUsize,
    rng: AtomicU64,
    health: Mutex<HashMap<String, BackendHealth>>,
    dns: Mutex<DnsCache>,
    /// A snapshot of the upstream config armed by the serving path when the
    /// upstream has active health checks, so the background prober can probe it
    /// (and pick up config changes) without a control-plane store scan.
    probe_cfg: Mutex<Option<Upstream>>,
    /// When the active prober last ran for this upstream (interval gate).
    last_probe: Mutex<Option<Instant>>,
}

impl UpstreamState {
    /// The current backend pool: DNS-discovered (cached, refreshed every
    /// `refresh_secs`) when `discover` is set, else the static list. `now` and
    /// `resolver` are injected for testability.
    pub fn backends(&self, up: &Upstream, resolver: &dyn Resolver, now: Instant) -> Vec<String> {
        let Some(disco) = up.discover.as_ref() else {
            return up
                .static_backends()
                .into_iter()
                .map(str::to_string)
                .collect();
        };
        let mut cache = self.dns.lock().unwrap();
        let stale = cache
            .refreshed
            .map(|t| now.duration_since(t) >= Duration::from_secs(disco.refresh_secs))
            .unwrap_or(true);
        if stale {
            match resolve_discovery(disco, resolver) {
                Ok(backends) if !backends.is_empty() => {
                    cache.backends = backends;
                    cache.refreshed = Some(now);
                }
                Ok(_) => {
                    // Empty result: keep any previous backends, retry next time.
                    cache.refreshed = Some(now);
                }
                Err(err) => {
                    tracing::warn!(host = %disco.host, %err, "gateway DNS discovery failed");
                    // Serve the last-known pool until the next refresh.
                }
            }
        }
        cache.backends.clone()
    }

    /// The ordered backends to attempt for one request: ejected backends are
    /// skipped (unless *all* are ejected — then every backend is a candidate so
    /// the upstream never hard-fails on a stale ejection), the survivors are
    /// ordered by the LB policy, and the list is capped to `max_retries + 1`.
    pub fn candidates(&self, backends: &[String], up: &Upstream, now: Instant) -> Vec<String> {
        if backends.is_empty() {
            return Vec::new();
        }
        let healthy: Vec<&String> = backends
            .iter()
            .filter(|b| !self.is_unavailable(b, now))
            .collect();
        let pool: Vec<&String> = if healthy.is_empty() {
            backends.iter().collect()
        } else {
            healthy
        };
        let start = match up.lb {
            LbPolicy::RoundRobin => self.cursor.fetch_add(1, Ordering::Relaxed) % pool.len(),
            LbPolicy::Random => (self.next_rand() as usize) % pool.len(),
        };
        let attempts = (up.max_retries as usize + 1).min(pool.len());
        (0..attempts)
            .map(|i| pool[(start + i) % pool.len()].clone())
            .collect()
    }

    /// Record an attempt's outcome against `backend` for passive health.
    pub fn record(&self, backend: &str, ok: bool, health: Option<PassiveHealth>, now: Instant) {
        let Some(cfg) = health else {
            return; // ejection disabled — nothing to track.
        };
        let mut map = self.health.lock().unwrap();
        let entry = map.entry(backend.to_string()).or_default();
        if ok {
            entry.consecutive_fails = 0;
            entry.ejected_until = None;
        } else {
            entry.consecutive_fails = entry.consecutive_fails.saturating_add(1);
            if entry.consecutive_fails >= cfg.max_fails.max(1) {
                entry.ejected_until = Some(now + Duration::from_millis(cfg.fail_timeout_ms));
            }
        }
    }

    /// Arm (or refresh) the active-health probe config for this upstream — the
    /// serving path calls this each time it routes through an upstream that has
    /// `active_health`, so the background prober has a current snapshot.
    pub fn arm_active_probe(&self, up: &Upstream) {
        if up.active_health.is_some() {
            *self.probe_cfg.lock().unwrap() = Some(up.clone());
        }
    }

    /// Whether this upstream is armed for active probing.
    pub fn is_probe_armed(&self) -> bool {
        self.probe_cfg.lock().unwrap().is_some()
    }

    /// Record an active probe result against `backend`, updating the up/down
    /// verdict via the configured thresholds.
    pub fn record_probe(&self, backend: &str, ok: bool, health: &ActiveHealth) {
        let mut map = self.health.lock().unwrap();
        let entry = map.entry(backend.to_string()).or_default();
        if ok {
            entry.probe_ok = entry.probe_ok.saturating_add(1);
            entry.probe_fail = 0;
            if entry.probe_ok >= health.healthy_threshold.max(1) {
                entry.active_down = false;
            }
        } else {
            entry.probe_fail = entry.probe_fail.saturating_add(1);
            entry.probe_ok = 0;
            if entry.probe_fail >= health.unhealthy_threshold.max(1) {
                entry.active_down = true;
            }
        }
    }

    /// Run one active-probe pass if the interval has elapsed: probe every current
    /// backend (a `GET` of the health path) and fold the result into the up/down
    /// verdict. A no-op unless armed (`arm_active_probe`) with `active_health`.
    pub async fn probe_once(&self, resolver: &dyn Resolver, now: Instant) {
        let Some(up) = self.probe_cfg.lock().unwrap().clone() else {
            return;
        };
        let Some(health) = up.active_health.clone() else {
            return;
        };
        {
            let mut last = self.last_probe.lock().unwrap();
            if last
                .is_some_and(|t| now.duration_since(t) < Duration::from_millis(health.interval_ms))
            {
                return; // not due yet
            }
            *last = Some(now);
        }
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_millis(health.timeout_ms.max(1)))
            .build()
        else {
            return;
        };
        for backend in self.backends(&up, resolver, now) {
            let url = format!("{}{}", backend.trim_end_matches('/'), health.path);
            let ok = match client.get(&url).send().await {
                Ok(resp) => resp.status().as_u16() == health.expected_status,
                Err(_) => false,
            };
            self.record_probe(&backend, ok, &health);
        }
    }

    /// A backend is unavailable if passively ejected (failed live traffic) or
    /// actively marked down by the prober.
    fn is_unavailable(&self, backend: &str, now: Instant) -> bool {
        let map = self.health.lock().unwrap();
        let Some(h) = map.get(backend) else {
            return false;
        };
        h.active_down || h.ejected_until.is_some_and(|until| until > now)
    }

    /// A fast process-local xorshift step (good enough to spread load for the
    /// `Random` LB policy; not a CSPRNG). Seeded lazily from the cursor.
    fn next_rand(&self) -> u64 {
        let mut x = self.rng.load(Ordering::Relaxed);
        if x == 0 {
            x = 0x9e37_79b9_7f4a_7c15
                ^ (self.cursor.load(Ordering::Relaxed) as u64).wrapping_add(1);
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.store(x, Ordering::Relaxed);
        x
    }
}

/// Resolve a [`Discovery`] config to `scheme://addr:port` backends.
fn resolve_discovery(disco: &Discovery, resolver: &dyn Resolver) -> std::io::Result<Vec<String>> {
    let scheme = if disco.scheme.is_empty() {
        "http"
    } else {
        &disco.scheme
    };
    let mut out = Vec::new();
    for ip in resolver.resolve(&disco.host)? {
        // Bracket IPv6 literals for the URL authority.
        let host = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        out.push(format!("{scheme}://{host}:{}", disco.port));
    }
    Ok(out)
}

/// The process-wide registry of per-`(site, upstream)` runtime state. Gateway
/// selection is inherently stateful (the LB cursor + health span requests), so
/// like the metrics registry it lives in a `LazyLock` rather than per-request.
static REGISTRY: LazyLock<Mutex<HashMap<String, Arc<UpstreamState>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The [`UpstreamState`] for a `(site, upstream-name)`, created on first use.
pub fn upstream_state(site: &str, upstream: &str) -> Arc<UpstreamState> {
    let key = format!("{site}\u{1}{upstream}");
    let mut reg = REGISTRY.lock().unwrap();
    reg.entry(key).or_default().clone()
}

/// Every upstream armed for active probing (those the serving path has routed
/// through that carry `active_health`). The background prober iterates these.
pub fn armed_probe_states() -> Vec<Arc<UpstreamState>> {
    REGISTRY
        .lock()
        .unwrap()
        .values()
        .filter(|s| s.is_probe_armed())
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Scale-to-zero activity tracking: per-workload last-request time,
// the signal the reconcile loop reads to sleep idle workloads / wake parked
// ones. Like the upstream registry, it's process-wide + in-memory (per node).
// ---------------------------------------------------------------------------

/// Per-workload last-request `Instant`, written by the compute serving path.
static ACTIVITY: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Record that `workload` was just requested (called on every compute-routed
/// request, including ones that find no live replica — that request is what
/// triggers a wake-from-zero).
pub fn record_activity(workload: &str) {
    ACTIVITY
        .lock()
        .unwrap()
        .insert(workload.to_string(), Instant::now());
}

/// The last time `workload` was requested on this node, if ever.
pub fn last_activity(workload: &str) -> Option<Instant> {
    ACTIVITY.lock().unwrap().get(workload).copied()
}

/// Classify a workload from its last-request time. **Unknown** (never requested
/// on this node) is treated as `Active` — we never sleep a workload we haven't
/// observed, so a freshly launched replica isn't immediately parked.
pub fn classify_activity(
    last: Option<Instant>,
    now: Instant,
    idle_timeout: Duration,
) -> WorkloadActivity {
    match last {
        Some(t) if now.saturating_duration_since(t) >= idle_timeout => WorkloadActivity::Idle,
        _ => WorkloadActivity::Active,
    }
}

/// The reconcile loop's [`ActivitySource`], backed by the per-node activity
/// registry: a workload idle for `idle_timeout` is eligible to scale to zero,
/// and any recent request keeps it (or wakes it) `Active`. (Single-node / leader
/// today; cluster-wide aggregation rides on the multi-node serve wiring.)
pub struct GatewayActivitySource {
    idle_timeout: Duration,
}

impl GatewayActivitySource {
    /// Build a source that sleeps workloads idle for `idle_timeout`.
    pub fn new(idle_timeout: Duration) -> Self {
        Self { idle_timeout }
    }
}

#[async_trait::async_trait]
impl ActivitySource for GatewayActivitySource {
    async fn activity(&self, workload: &str) -> WorkloadActivity {
        classify_activity(last_activity(workload), Instant::now(), self.idle_timeout)
    }
}

/// Nudge for **wake-from-zero**: lets the serving path trigger an
/// immediate reconcile pass (to restore a parked replica a request just arrived
/// for) instead of waiting for the next periodic tick — the difference between a
/// ~1s invisible cold start and a multi-second one.
static RECONCILE_WAKER: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);

/// Ask the reconcile loop to run a pass **now**. Coalesced — a burst of requests
/// to the same parked workload collapses to a single extra pass.
pub fn wake_reconcile() {
    RECONCILE_WAKER.notify_one();
}

/// Await the next reconcile nudge (the reconcile loop selects on this alongside
/// its interval tick).
pub async fn await_reconcile_wake() {
    RECONCILE_WAKER.notified().await;
}

/// The background active-health prober: every `tick`, run a probe pass over each
/// armed upstream (each pass self-gates on its own `interval_ms`). Runs until the
/// returned task is aborted (on server drain).
pub fn spawn_active_health_prober() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let resolver = SystemResolver;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            for state in armed_probe_states() {
                // `Instant::now()` is fine here (live wall path); tests call
                // `probe_once` directly with an injected `now`.
                state.probe_once(&resolver, Instant::now()).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    #[test]
    fn classify_activity_sleeps_only_after_idle_timeout() {
        let now = Instant::now();
        let idle = Duration::from_secs(300);
        // Recent request → Active.
        let recent = now.checked_sub(Duration::from_secs(10)).unwrap();
        assert_eq!(
            classify_activity(Some(recent), now, idle),
            WorkloadActivity::Active
        );
        // Idle past the timeout → Idle (eligible to sleep).
        let stale = now.checked_sub(Duration::from_secs(600)).unwrap();
        assert_eq!(
            classify_activity(Some(stale), now, idle),
            WorkloadActivity::Idle
        );
        // Exactly at the threshold → Idle.
        let at = now.checked_sub(idle).unwrap();
        assert_eq!(
            classify_activity(Some(at), now, idle),
            WorkloadActivity::Idle
        );
        // Never observed → Active (don't sleep what we haven't seen).
        assert_eq!(classify_activity(None, now, idle), WorkloadActivity::Active);
    }

    #[test]
    fn record_and_read_activity_round_trips() {
        record_activity("wl-roundtrip");
        let t = last_activity("wl-roundtrip").expect("recorded");
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(last_activity("never-seen-workload").is_none());
    }

    fn pool(targets: &[&str]) -> Upstream {
        Upstream {
            targets: targets.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn round_robin_rotates_through_the_pool() {
        let up = pool(&["a", "b", "c"]);
        let state = UpstreamState::default();
        let now = Instant::now();
        let picks: Vec<String> = (0..6)
            .map(|_| state.candidates(&backends(&up), &up, now)[0].clone())
            .collect();
        // Rotation cycles a, b, c, a, b, c (order may start anywhere but cycles).
        assert_eq!(
            picks[0..3]
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        assert_eq!(picks[0], picks[3]);
        assert_eq!(picks[1], picks[4]);
    }

    #[test]
    fn ejects_after_max_fails_then_recovers() {
        let mut up = pool(&["a", "b"]);
        up.passive_health = Some(PassiveHealth {
            max_fails: 2,
            fail_timeout_ms: 1000,
        });
        let state = UpstreamState::default();
        let t0 = Instant::now();
        let bs = backends(&up);
        // Two failures on "a" eject it.
        state.record("a", false, up.passive_health, t0);
        state.record("a", false, up.passive_health, t0);
        // While ejected, candidates never include "a".
        let mid = t0 + Duration::from_millis(500);
        for _ in 0..5 {
            assert!(!state.candidates(&bs, &up, mid).contains(&"a".to_string()));
        }
        // After the cooldown it is a candidate again.
        let later = t0 + Duration::from_millis(1500);
        let seen: std::collections::HashSet<String> = (0..6)
            .flat_map(|_| state.candidates(&bs, &up, later))
            .collect();
        assert!(seen.contains("a"));
        // A success clears the fail count + ejection immediately.
        state.record("a", false, up.passive_health, later);
        state.record("a", true, up.passive_health, later);
        assert!(!state.is_unavailable("a", later));
    }

    #[test]
    fn all_ejected_falls_back_to_full_pool() {
        let mut up = pool(&["a", "b"]);
        up.passive_health = Some(PassiveHealth {
            max_fails: 1,
            fail_timeout_ms: 10_000,
        });
        let state = UpstreamState::default();
        let now = Instant::now();
        state.record("a", false, up.passive_health, now);
        state.record("b", false, up.passive_health, now);
        // Both ejected → never hard-fail; the full pool stays available.
        let cands = state.candidates(&backends(&up), &up, now);
        assert_eq!(cands.len(), 1); // max_retries 0 → one attempt, but from the full pool
    }

    #[test]
    fn max_retries_caps_candidate_count() {
        let mut up = pool(&["a", "b", "c", "d"]);
        up.max_retries = 2;
        let state = UpstreamState::default();
        let cands = state.candidates(&backends(&up), &up, Instant::now());
        assert_eq!(cands.len(), 3); // max_retries(2) + 1
                                    // Distinct backends, contiguous in the rotation.
        assert_eq!(
            cands.iter().collect::<std::collections::HashSet<_>>().len(),
            3
        );
    }

    #[test]
    fn dns_discovery_resolves_and_caches() {
        struct StubResolver(Map<String, Vec<IpAddr>>);
        impl Resolver for StubResolver {
            fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
                Ok(self.0.get(host).cloned().unwrap_or_default())
            }
        }
        let resolver = StubResolver(Map::from([(
            "svc.internal".to_string(),
            vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
        )]));
        let up = Upstream {
            discover: Some(Discovery {
                host: "svc.internal".into(),
                port: 8080,
                scheme: "http".into(),
                refresh_secs: 30,
            }),
            ..Default::default()
        };
        let state = UpstreamState::default();
        let t0 = Instant::now();
        let bs = state.backends(&up, &resolver, t0);
        assert_eq!(bs, vec!["http://10.0.0.1:8080", "http://10.0.0.2:8080"]);
        // Within the refresh window the cache is reused (no resolver dependency).
        let again = state.backends(&up, &EmptyResolver, t0 + Duration::from_secs(5));
        assert_eq!(again, bs);
    }

    struct EmptyResolver;
    impl Resolver for EmptyResolver {
        fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(Vec::new())
        }
    }

    fn backends(up: &Upstream) -> Vec<String> {
        UpstreamState::default().backends(up, &EmptyResolver, Instant::now())
    }

    #[test]
    fn active_probe_thresholds_mark_down_then_recover() {
        let state = UpstreamState::default();
        let h = ActiveHealth {
            unhealthy_threshold: 2,
            healthy_threshold: 2,
            ..Default::default()
        };
        let now = Instant::now();
        state.record_probe("a", false, &h);
        assert!(
            !state.is_unavailable("a", now),
            "one failure is below threshold"
        );
        state.record_probe("a", false, &h);
        assert!(state.is_unavailable("a", now), "two failures → down");
        state.record_probe("a", true, &h);
        assert!(
            state.is_unavailable("a", now),
            "one success is below threshold"
        );
        state.record_probe("a", true, &h);
        assert!(!state.is_unavailable("a", now), "two successes → back up");
    }

    /// A raw-TCP mock that answers every request with a fixed status line.
    async fn spawn_status(status: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp =
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn active_probe_takes_a_dead_backend_out_of_rotation() {
        let healthy = spawn_status("200 OK").await;
        let dead = spawn_status("503 Service Unavailable").await;
        let up = Upstream {
            targets: vec![healthy.clone(), dead.clone()],
            active_health: Some(ActiveHealth {
                path: "/healthz".into(),
                interval_ms: 1,
                timeout_ms: 500,
                healthy_threshold: 1,
                unhealthy_threshold: 2,
                expected_status: 200,
            }),
            ..Default::default()
        };
        let state = UpstreamState::default();
        state.arm_active_probe(&up);
        assert!(state.is_probe_armed());

        let t0 = Instant::now();
        // Two probe passes cross the dead backend's unhealthy threshold (the
        // interval gate is satisfied by advancing `now`).
        state.probe_once(&EmptyResolver, t0).await;
        state
            .probe_once(&EmptyResolver, t0 + Duration::from_millis(10))
            .await;

        let bs: Vec<String> = up.static_backends().iter().map(|s| s.to_string()).collect();
        let seen: std::collections::HashSet<String> = (0..8)
            .flat_map(|_| state.candidates(&bs, &up, t0 + Duration::from_millis(20)))
            .collect();
        assert!(seen.contains(&healthy), "healthy backend stays in rotation");
        assert!(
            !seen.contains(&dead),
            "dead backend ejected by active probing: {seen:?}"
        );
    }
}
