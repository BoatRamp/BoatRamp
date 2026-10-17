//! On-demand per-SNI TLS issuance at scale (cap-req 03).
//!
//! A multi-tenant edge fronts many customer-owned hostnames. Pre-registering a cert per hostname does
//! not scale; instead, on the first TLS handshake for an **authorized** but not-yet-issued SNI, the
//! host issues (and caches) a cert, then serves the client on its retry. The authorization gate is the
//! #02 verified-domain allowlist ([`DeployStore::resolve_site_by_host`]) — issuance for an arbitrary
//! attacker-chosen SNI is **refused** (fail-closed), so a flood of unknown SNIs can never become an
//! ACME / rate-limit storm.
//!
//! This module is the security engine: the [`OnDemandResolver`] (a `rustls` cert resolver that serves
//! a cached cert, or triggers issuance and fails this handshake so the client retries), and the
//! [`OnDemandIssuer`] worker (allowlist gate → per-node single-flight → negative cache → rate limit →
//! cluster single-flight via [`ensure_cert`] → cache). The ACME-backed [`CertIssuer`] and the config
//! + serve wiring live alongside (cap-req 03 Stage 1c); this engine is abstract over the issuance
//! backend ([`CertIssuer`]) and the allowlist ([`IssuanceGate`]) so it is unit-testable offline.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::sync::{Semaphore, mpsc};

use boatramp_core::cert::{CertStore, StoredCert, ensure_cert};

/// `acme-tls/1` — the ALPN protocol id a CA uses for a TLS-ALPN-01 challenge handshake (RFC 8737).
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Bounded trigger queue: a resolve-miss enqueues the SNI; a full queue drops (never blocks the
/// handshake), so a new-SNI flood can't grow memory.
const TRIGGER_QUEUE: usize = 256;

/// Runtime knobs for the issuer (the operator-facing `[serve] on_demand_tls` figment struct maps onto
/// this in the serve wiring).
#[derive(Debug, Clone)]
pub struct OnDemandConfig {
    /// A refused or failed SNI is negatively cached this long, so a flood collapses to O(1) map hits
    /// (no repeat allowlist lookups, no repeat CA attempts).
    pub negative_ttl: Duration,
    /// Max concurrent in-flight issuances (a global `Semaphore`), so a burst of distinct authorized
    /// names can't open unbounded orders at once.
    pub max_inflight: usize,
    /// Max CA orders placed per rolling hour (the account rate-limit floor). `0` ⇒ unlimited.
    pub rate_limit_per_hour: u32,
    /// Renew a stored cert this many seconds before `notAfter` (passed to [`ensure_cert`]).
    pub renew_before_secs: u64,
}

impl Default for OnDemandConfig {
    fn default() -> Self {
        Self {
            negative_ttl: Duration::from_secs(300),
            max_inflight: 4,
            rate_limit_per_hour: 50,
            renew_before_secs: 30 * 24 * 3600,
        }
    }
}

/// Decides whether an SNI is authorized for on-demand issuance (THE abuse gate). The real
/// implementation is the #02 verified-domain allowlist; a refusal is fail-closed.
#[async_trait]
pub trait IssuanceGate: Send + Sync {
    /// `true` iff `sni` is an attached, ownership-verified domain of some project/site.
    async fn is_authorized(&self, sni: &str) -> bool;
}

/// The #02 verified-domain allowlist: an SNI is authorized iff it resolves to an attached site
/// (`resolve_site_by_host` returns `Some`, which only happens for a host run through
/// `attach_verified_domain`). An error resolving fails **closed**.
pub struct DeployGate {
    pub deploy: boatramp_core::deploy::DeployStore,
}

#[async_trait]
impl IssuanceGate for DeployGate {
    async fn is_authorized(&self, sni: &str) -> bool {
        matches!(self.deploy.resolve_site_by_host(sni).await, Ok(Some(_)))
    }
}

/// Issues one certificate for one SNI (challenge-type selection + the CA round trip). Abstract so the
/// engine is testable without a live CA; the real implementation is ACME-backed (Stage 1c).
#[async_trait]
pub trait CertIssuer: Send + Sync {
    /// Issue a cert for `sni`, returning it as a [`StoredCert`] (chain + key PEM + `notAfter`).
    async fn issue(&self, sni: &str) -> Result<StoredCert, String>;
}

/// The live cert cache the resolver reads on the hot path. `exact` holds issued serving certs by SNI;
/// `challenge` holds the ephemeral TLS-ALPN-01 challenge certs a solver installs during a handshake.
#[derive(Default)]
pub struct CertCache {
    exact: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    challenge: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertCache {
    /// The serving cert for `sni`, if issued + cached.
    pub fn get_issued(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.exact.lock().ok()?.get(sni).cloned()
    }
    /// Install an issued serving cert for `sni`.
    pub fn insert_issued(&self, sni: &str, key: Arc<CertifiedKey>) {
        if let Ok(mut m) = self.exact.lock() {
            m.insert(sni.to_string(), key);
        }
    }
    /// The TLS-ALPN-01 challenge cert for `sni`, if a solver installed one.
    pub fn get_challenge(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.challenge.lock().ok()?.get(sni).cloned()
    }
    /// Install a TLS-ALPN-01 challenge cert for `sni` (served only on the `acme-tls/1` handshake).
    pub fn install_challenge(&self, sni: &str, key: Arc<CertifiedKey>) {
        if let Ok(mut m) = self.challenge.lock() {
            m.insert(sni.to_string(), key);
        }
    }
    /// Remove a challenge cert once the challenge is done.
    pub fn clear_challenge(&self, sni: &str) {
        if let Ok(mut m) = self.challenge.lock() {
            m.remove(sni);
        }
    }
}

/// A rolling-hour order-rate limiter (the CA account floor). `allow()` consumes one slot if under the
/// hourly cap. A `0` cap means unlimited.
struct RateLimiter {
    cap: u32,
    state: Mutex<(Instant, u32)>, // (window start, count this window)
}

impl RateLimiter {
    fn new(cap: u32) -> Self {
        Self {
            cap,
            state: Mutex::new((Instant::now(), 0)),
        }
    }
    fn allow(&self) -> bool {
        if self.cap == 0 {
            return true;
        }
        let Ok(mut g) = self.state.lock() else {
            return false; // poisoned ⇒ fail-closed
        };
        let (start, count) = &mut *g;
        if start.elapsed() >= Duration::from_secs(3600) {
            *start = Instant::now();
            *count = 0;
        }
        if *count >= self.cap {
            return false;
        }
        *count += 1;
        true
    }
}

/// The allowlist-gated, single-flight, cluster-aware issuer worker.
pub struct OnDemandIssuer {
    gate: Arc<dyn IssuanceGate>,
    issuer: Arc<dyn CertIssuer>,
    cert_store: Arc<dyn CertStore>,
    is_leader: Arc<dyn Fn() -> bool + Send + Sync>,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    cache: Arc<CertCache>,
    cfg: OnDemandConfig,
    inflight: Mutex<HashSet<String>>,
    negative: Mutex<HashMap<String, Instant>>,
    sem: Arc<Semaphore>,
    limiter: RateLimiter,
}

impl OnDemandIssuer {
    /// Whether `sni` is currently negatively cached (refused/failed recently).
    fn negative_cached(&self, sni: &str) -> bool {
        self.negative
            .lock()
            .ok()
            .and_then(|m| m.get(sni).copied())
            .is_some_and(|until| until > Instant::now())
    }

    fn deny(&self, sni: &str) {
        if let Ok(mut m) = self.negative.lock() {
            m.insert(sni.to_string(), Instant::now() + self.cfg.negative_ttl);
        }
    }

    /// Issue (or load) a cert for one SNI — the security spine. Returns without a CA call when the SNI
    /// is negatively cached, unauthorized (→ negative cache), already fresh in the store (→ cache it),
    /// or this node is not the leader (→ serve the leader's replicated cert when present). Only an
    /// authorized, stale/absent SNI on the leader, under the rate limit, reaches the CA.
    pub async fn issue_one(&self, sni: &str) {
        if self.negative_cached(sni) {
            return;
        }
        // THE abuse gate — fail-closed, before any CA contact.
        if !self.gate.is_authorized(sni).await {
            self.deny(sni);
            return;
        }
        let now = (self.now_unix)();
        let leader = (self.is_leader)();
        let result = ensure_cert(
            &*self.cert_store,
            sni,
            leader,
            now,
            self.cfg.renew_before_secs,
            || async {
                if !self.limiter.allow() {
                    return Err("on-demand issuance rate limit exceeded".to_string());
                }
                self.issuer.issue(sni).await
            },
        )
        .await;
        match result {
            Ok(Some(stored)) => {
                match crate::acme_dns::certified_key_from_pem(&stored.chain_pem, &stored.key_pem) {
                    Ok(ck) => self.cache.insert_issued(sni, Arc::new(ck)),
                    Err(e) => {
                        tracing::warn!(target: "boatramp::acme", %sni, error = %e, "on-demand cert parse failed")
                    }
                }
            }
            // Follower with nothing stored yet: leave the cache empty; the client retries once the
            // leader has issued + replicated. No CA call here.
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(target: "boatramp::acme", %sni, error = %e, "on-demand issuance failed");
                self.deny(sni);
            }
        }
    }

    /// Per-node single-flight wrapper: coalesce concurrent/duplicate triggers for the same SNI to ONE
    /// `issue_one`, bounded by the global concurrency semaphore.
    async fn issue_deduped(self: Arc<Self>, sni: String) {
        // Atomic check-insert: a concurrent trigger for the same name returns here.
        {
            let Ok(mut g) = self.inflight.lock() else {
                return;
            };
            if g.contains(&sni) {
                return;
            }
            g.insert(sni.clone());
        }
        let permit = self.sem.clone().acquire_owned().await;
        self.issue_one(&sni).await;
        drop(permit);
        if let Ok(mut g) = self.inflight.lock() {
            g.remove(&sni);
        }
    }

    /// Drain the trigger queue, dispatching each SNI to a (deduped, concurrency-bounded) issuance.
    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<String>) {
        while let Some(sni) = rx.recv().await {
            tokio::spawn(Arc::clone(&self).issue_deduped(sni));
        }
    }
}

/// The started on-demand TLS engine: owns the live [`CertCache`] and the trigger channel. Hand
/// [`resolver`](Self::resolver) to the rustls `ServerConfig`.
pub struct OnDemandTls {
    cache: Arc<CertCache>,
    trigger: mpsc::Sender<String>,
}

impl OnDemandTls {
    /// Start the issuer worker and return the engine handle.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        gate: Arc<dyn IssuanceGate>,
        issuer: Arc<dyn CertIssuer>,
        cert_store: Arc<dyn CertStore>,
        is_leader: Arc<dyn Fn() -> bool + Send + Sync>,
        now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
        cfg: OnDemandConfig,
    ) -> Self {
        let cache = Arc::new(CertCache::default());
        let (tx, rx) = mpsc::channel(TRIGGER_QUEUE);
        let sem = Arc::new(Semaphore::new(cfg.max_inflight.max(1)));
        let limiter = RateLimiter::new(cfg.rate_limit_per_hour);
        let engine = Arc::new(OnDemandIssuer {
            gate,
            issuer,
            cert_store,
            is_leader,
            now_unix,
            cache: Arc::clone(&cache),
            cfg,
            inflight: Mutex::new(HashSet::new()),
            negative: Mutex::new(HashMap::new()),
            sem,
            limiter,
        });
        tokio::spawn(engine.run(rx));
        Self { cache, trigger: tx }
    }

    /// The shared cert cache (a TLS-ALPN-01 solver installs challenge certs here).
    pub fn cache(&self) -> Arc<CertCache> {
        Arc::clone(&self.cache)
    }

    /// A `rustls` cert resolver that serves cached certs + triggers on-demand issuance for an
    /// authorized miss (the issuance gate runs in the worker, never on the handshake path).
    pub fn resolver(&self) -> Arc<OnDemandResolver> {
        Arc::new(OnDemandResolver {
            cache: Arc::clone(&self.cache),
            trigger: self.trigger.clone(),
        })
    }
}

/// A [`ResolvesServerCert`] that serves an issued cert by SNI, a TLS-ALPN-01 challenge cert on the
/// `acme-tls/1` handshake, and otherwise **triggers** on-demand issuance (non-blocking) and returns
/// `None` — failing this handshake so the client retries once the cert is warm.
pub struct OnDemandResolver {
    cache: Arc<CertCache>,
    trigger: mpsc::Sender<String>,
}

impl std::fmt::Debug for OnDemandResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for OnDemandResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        // A TLS-ALPN-01 validation handshake: serve the challenge cert if a solver installed one.
        let is_acme_alpn = hello
            .alpn()
            .is_some_and(|mut p| p.any(|proto| proto == ACME_TLS_ALPN));
        if is_acme_alpn {
            return self.cache.get_challenge(sni);
        }
        if let Some(key) = self.cache.get_issued(sni) {
            return Some(key);
        }
        // Miss: nudge the issuer (non-blocking; gated + single-flighted in the worker) and fail this
        // handshake. The client retries and hits the now-warm cache.
        let _ = self.trigger.try_send(sni.to_string());
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A stub allowlist: authorizes exactly the SNIs it was given, and counts lookups (to prove the
    /// negative cache avoids re-querying).
    struct StubGate {
        allowed: std::collections::HashSet<String>,
        lookups: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl IssuanceGate for StubGate {
        async fn is_authorized(&self, sni: &str) -> bool {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.allowed.contains(sni)
        }
    }

    /// A stub issuer: counts orders and returns a real self-signed cert so the cache populates.
    struct StubIssuer {
        orders: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl CertIssuer for StubIssuer {
        async fn issue(&self, sni: &str) -> Result<StoredCert, String> {
            self.orders.fetch_add(1, Ordering::SeqCst);
            let (chain_pem, key_pem) = self_signed(sni);
            Ok(StoredCert {
                version: 1,
                chain_pem,
                key_pem,
                not_after_unix: u64::MAX, // always fresh in the store for the test
            })
        }
    }

    fn self_signed(sni: &str) -> (String, String) {
        let kp = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![sni.to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem(), kp.serialize_pem())
    }

    fn mem_store() -> Arc<dyn CertStore> {
        Arc::new(boatramp_core::cert::KvCertStore::new(Arc::new(
            boatramp_core::kv::MemoryKv::new(),
        )))
    }

    fn engine(
        allowed: &[&str],
        orders: Arc<AtomicUsize>,
        lookups: Arc<AtomicUsize>,
    ) -> Arc<OnDemandIssuer> {
        engine_as(allowed, orders, lookups, true)
    }

    fn engine_as(
        allowed: &[&str],
        orders: Arc<AtomicUsize>,
        lookups: Arc<AtomicUsize>,
        is_leader: bool,
    ) -> Arc<OnDemandIssuer> {
        Arc::new(OnDemandIssuer {
            gate: Arc::new(StubGate {
                allowed: allowed.iter().map(|s| s.to_string()).collect(),
                lookups,
            }),
            issuer: Arc::new(StubIssuer { orders }),
            cert_store: mem_store(),
            is_leader: Arc::new(move || is_leader),
            now_unix: Arc::new(|| 1_000_000),
            cache: Arc::new(CertCache::default()),
            cfg: OnDemandConfig::default(),
            inflight: Mutex::new(HashSet::new()),
            negative: Mutex::new(HashMap::new()),
            sem: Arc::new(Semaphore::new(4)),
            limiter: RateLimiter::new(0),
        })
    }

    #[tokio::test]
    async fn authorized_unknown_sni_issues_once_and_caches() {
        let orders = Arc::new(AtomicUsize::new(0));
        let eng = engine(
            &["app.example.com"],
            orders.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        eng.issue_one("app.example.com").await;
        assert_eq!(orders.load(Ordering::SeqCst), 1, "exactly one order");
        assert!(
            eng.cache.get_issued("app.example.com").is_some(),
            "the issued cert is cached for the retry"
        );
        // A second call serves from the store (fresh) — no new order.
        eng.issue_one("app.example.com").await;
        assert_eq!(
            orders.load(Ordering::SeqCst),
            1,
            "a fresh stored cert ⇒ no re-issue"
        );
    }

    #[tokio::test]
    async fn unauthorized_sni_places_no_order_and_is_negative_cached() {
        // THE abuse gate (mutation canary): neutering `is_authorized` to return true would flip this.
        let orders = Arc::new(AtomicUsize::new(0));
        let lookups = Arc::new(AtomicUsize::new(0));
        let eng = engine(&["app.example.com"], orders.clone(), lookups.clone());
        eng.issue_one("evil.attacker.test").await;
        assert_eq!(
            orders.load(Ordering::SeqCst),
            0,
            "an unauthorized SNI must place NO order"
        );
        assert!(eng.cache.get_issued("evil.attacker.test").is_none());
        // A second attempt within the negative TTL does not even re-query the allowlist.
        eng.issue_one("evil.attacker.test").await;
        assert_eq!(orders.load(Ordering::SeqCst), 0);
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            1,
            "the negative cache short-circuits a repeat allowlist lookup"
        );
    }

    #[tokio::test]
    async fn burst_for_the_same_name_single_flights_to_one_order() {
        let orders = Arc::new(AtomicUsize::new(0));
        let eng = engine(
            &["app.example.com"],
            orders.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        let mut handles = Vec::new();
        for _ in 0..16 {
            handles.push(tokio::spawn(
                Arc::clone(&eng).issue_deduped("app.example.com".to_string()),
            ));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            orders.load(Ordering::SeqCst),
            1,
            "a burst for one new name must coalesce to ONE order"
        );
    }

    #[tokio::test]
    async fn follower_places_no_order() {
        // A non-leader never calls the CA; it serves the leader's replicated cert (none here ⇒ miss).
        let orders = Arc::new(AtomicUsize::new(0));
        let eng = engine_as(
            &["app.example.com"],
            orders.clone(),
            Arc::new(AtomicUsize::new(0)),
            false,
        );
        eng.issue_one("app.example.com").await;
        assert_eq!(
            orders.load(Ordering::SeqCst),
            0,
            "a follower must not place an order"
        );
    }
}
