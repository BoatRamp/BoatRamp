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

/// Replicated-KV prefix for cross-node issuance requests (cap-req 03 #3).
const CERTREQ_PREFIX: &str = "certreq/";
/// How often the leader drains the certreq queue.
const CERTREQ_INTERVAL: Duration = Duration::from_secs(30);
/// Max certreq markers the leader processes per tick (bounds a flood of follower requests).
const CERTREQ_BATCH: usize = 64;

/// Stamped `notAfter` for an issued cert, as a conservative renewal heuristic (the issuer doesn't
/// parse the real `notAfter`): 60 days ≤ a Let's Encrypt ~90-day cert, so `ensure_cert` renews well
/// before true expiry (never after). Mirrors the cluster-TLS path's assumed-lifetime approach.
const ASSUMED_CERT_LIFETIME_SECS: u64 = 60 * 24 * 3600;

/// Anti-hollow mutation seam for the abuse gate (`BOATRAMP_ONDEMAND_MUTATION`). Armed only under
/// `cfg(test)` or the `ondemand-gate-mutation` feature (a CI gate lane) — NEVER in a shipped build,
/// where it is a `const None` the optimizer drops, so the allowlist check is always enforced.
#[cfg(any(test, feature = "ondemand-gate-mutation"))]
fn ondemand_mutation() -> Option<String> {
    std::env::var("BOATRAMP_ONDEMAND_MUTATION").ok()
}
#[cfg(not(any(test, feature = "ondemand-gate-mutation")))]
fn ondemand_mutation() -> Option<String> {
    None
}

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
    /// The replicated control-plane KV for cross-node issuance requests (cap-req 03 #3): a FOLLOWER
    /// that sees an authorized miss records `certreq/<sni>`, and the leader's [`certreq_consumer`]
    /// drains it + issues — so a new SNI that only ever hits a follower still gets a cert.
    certreq_kv: Arc<dyn boatramp_core::kv::KvStore>,
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
        // THE abuse gate — fail-closed, before any CA contact. Only a #02-verified domain may issue.
        // MUTATION SEAM (abuse gate): `skip_allowlist` neuters this check so an unauthorized SNI would
        // issue — the CI gate re-runs the abuse test under it and REQUIRES it to go RED (proving the
        // allowlist is load-bearing). Armed only under `cfg(test)` / the `ondemand-gate-mutation`
        // feature; a shipped build has `ondemand_mutation() == None`, so the seam is inert.
        let authorized = if ondemand_mutation().as_deref() == Some("skip_allowlist") {
            true
        } else {
            self.gate.is_authorized(sni).await
        };
        if !authorized {
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
            // Follower with no stored cert for an AUTHORIZED name (we passed the gate above): record a
            // replicated issuance request so the leader's `certreq_consumer` issues it — a new SNI that
            // only ever hits a follower would otherwise never get a cert. Idempotent (re-write is a
            // no-op). The client retries once the leader has issued + replicated. No CA call here.
            Ok(None) => {
                let key = format!("{CERTREQ_PREFIX}{sni}");
                if let Err(e) = self.certreq_kv.put(&key, now.to_le_bytes().to_vec()).await {
                    tracing::debug!(target: "boatramp::acme", %sni, error = %e, "could not record a cross-node certreq");
                }
            }
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

    /// Leader-gated drain of the replicated `certreq/*` queue (cap-req 03 #3). For each pending SNI:
    /// if a cert now exists (issued directly, or replicated) drop the marker; if the name is no longer
    /// authorized drop it (cleanup); else issue on the leader (`issue_one` → `ensure_cert` issues +
    /// stores) and drop the marker once stored. So exactly one node (the leader) places the order,
    /// while any node that saw the SNI can request it. Bounded per tick; a persistently-failing name
    /// backs off via the negative cache and is retried on later ticks.
    async fn certreq_consumer(self: Arc<Self>) {
        loop {
            tokio::time::sleep(CERTREQ_INTERVAL).await;
            if !(self.is_leader)() {
                continue;
            }
            self.certreq_drain_once().await;
        }
    }

    /// One bounded drain pass over `certreq/*` (the leader-gated body of [`certreq_consumer`], split
    /// out so it is unit-testable without the timer loop).
    async fn certreq_drain_once(&self) {
        let keys = match self
            .certreq_kv
            .list_from(CERTREQ_PREFIX, "", CERTREQ_BATCH)
            .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::debug!(target: "boatramp::acme", error = %e, "certreq drain: list failed");
                return;
            }
        };
        for key in keys {
            let sni = key.strip_prefix(CERTREQ_PREFIX).unwrap_or(&key).to_string();
            // Already have the cert, or the name is no longer authorized ⇒ drop the marker.
            let have_cert = matches!(self.cert_store.get(&sni).await, Ok(Some(_)));
            if have_cert || !self.gate.is_authorized(&sni).await {
                let _ = self.certreq_kv.delete(&key).await;
                continue;
            }
            // Issue on the leader; drop the marker once the cert is stored.
            self.issue_one(&sni).await;
            if matches!(self.cert_store.get(&sni).await, Ok(Some(_))) {
                let _ = self.certreq_kv.delete(&key).await;
            }
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
        cache: Arc<CertCache>,
        cfg: OnDemandConfig,
        certreq_kv: Arc<dyn boatramp_core::kv::KvStore>,
    ) -> Self {
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
            certreq_kv,
        });
        tokio::spawn(Arc::clone(&engine).run(rx));
        // Leader-gated cross-node issuance-request drain (cap-req 03 #3).
        tokio::spawn(engine.certreq_consumer());
        Self { cache, trigger: tx }
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

/// Build the on-demand TLS engine from the node `[serve.on_demand_tls]` config, or `None` when it is
/// disabled (then the serve path uses the static resolver alone — unchanged). The `#02` allowlist is
/// the `DeployStore`; issued certs persist (and replicate) via `cert_store`; `is_leader` gates CA
/// contact. `dns_provider` is the node's ACME DNS provider, required only for the `dns-01` challenge.
#[allow(clippy::too_many_arguments)]
pub fn from_serve_config(
    cfg: &boatramp_node::config::OnDemandTlsConfig,
    deploy: boatramp_core::deploy::DeployStore,
    cert_store: Arc<dyn CertStore>,
    is_leader: Arc<dyn Fn() -> bool + Send + Sync>,
    dns_provider: Option<Arc<dyn boatramp_acme::dns::DnsProvider>>,
    account_kv: Arc<dyn boatramp_core::kv::KvStore>,
    account_envelope: Option<Arc<dyn boatramp_core::envelope::KeyEnvelope>>,
) -> Option<OnDemandTls> {
    if !cfg.enabled {
        return None;
    }
    let challenge = match cfg.challenge {
        boatramp_node::config::OnDemandChallenge::TlsAlpn01 => AcmeChallenge::TlsAlpn01,
        boatramp_node::config::OnDemandChallenge::Dns01 => match dns_provider {
            Some(p) => AcmeChallenge::Dns01(p),
            None => {
                // DNS-01 on-demand needs the node's ACME DNS provider wired to this path (a
                // follow-up); don't silently serve nothing — refuse to start on-demand and log.
                tracing::error!(
                    target: "boatramp::acme",
                    "on_demand_tls challenge = dns-01 but no DNS provider is wired here yet; \
                     on-demand issuance NOT enabled (use challenge = tls-alpn-01)"
                );
                return None;
            }
        },
    };
    let cache = Arc::new(CertCache::default());
    let now_unix: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let directory_url = cfg
        .directory_url
        .clone()
        .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string());
    // The same replicated KV backs the ACME-account persistence and the cross-node certreq queue.
    let certreq_kv = Arc::clone(&account_kv);
    let issuer = Arc::new(AcmeIssuer::new(
        challenge,
        directory_url,
        cfg.contact_email.clone(),
        Arc::clone(&cache),
        Arc::clone(&now_unix),
        account_kv,
        account_envelope,
    ));
    let gate = Arc::new(DeployGate { deploy });
    let defaults = OnDemandConfig::default();
    let runtime = OnDemandConfig {
        negative_ttl: cfg
            .negative_ttl_secs
            .map(Duration::from_secs)
            .unwrap_or(defaults.negative_ttl),
        max_inflight: cfg.max_inflight.unwrap_or(defaults.max_inflight),
        rate_limit_per_hour: cfg
            .rate_limit_per_hour
            .unwrap_or(defaults.rate_limit_per_hour),
        renew_before_secs: defaults.renew_before_secs,
    };
    tracing::info!(
        target: "boatramp::acme",
        "on-demand per-SNI TLS issuance ENABLED (allowlist = verified custom domains)"
    );
    Some(OnDemandTls::start(
        gate, issuer, cert_store, is_leader, now_unix, cache, runtime, certreq_kv,
    ))
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

impl OnDemandResolver {
    /// The resolution for a given `sni` (+ whether the handshake is a TLS-ALPN-01 validation),
    /// factored out of [`resolve`](Self::resolve) so a composite resolver can call it after the static
    /// resolver misses — `ResolvesServerCert::resolve` consumes the `ClientHello` by value, so a
    /// composite must extract `sni`/ALPN once and dispatch via this method.
    pub fn resolve_sni(&self, sni: &str, is_acme_alpn: bool) -> Option<Arc<CertifiedKey>> {
        // A TLS-ALPN-01 validation handshake: serve the challenge cert if a solver installed one.
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

/// Whether a `ClientHello` carries the `acme-tls/1` ALPN (a TLS-ALPN-01 validation handshake).
pub fn is_acme_tls_alpn(hello: &ClientHello<'_>) -> bool {
    hello
        .alpn()
        .is_some_and(|mut p| p.any(|proto| proto == ACME_TLS_ALPN))
}

impl ResolvesServerCert for OnDemandResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        let is_acme_alpn = is_acme_tls_alpn(&hello);
        self.resolve_sni(sni, is_acme_alpn)
    }
}

/// How an [`AcmeIssuer`] proves control of a name to the CA.
pub enum AcmeChallenge {
    /// TLS-ALPN-01 on the 443 edge — no extra port; the challenge cert is served through the shared
    /// [`CertCache`] + the [`OnDemandResolver`] on the `acme-tls/1` handshake. The default.
    TlsAlpn01,
    /// DNS-01 via a provider (an operator-controlled zone / a wildcard name).
    Dns01(Arc<dyn boatramp_acme::dns::DnsProvider>),
}

/// The ACME-backed [`CertIssuer`]: reuses ONE [`Account`](boatramp_acme::acme::Account) across orders,
/// created **lazily on first issuance** (so enabling on-demand TLS adds no CA round trip at serve
/// startup) and shared by concurrent issuances via a `OnceCell`. Issues per-SNI via the configured
/// challenge; for TLS-ALPN-01 it installs the challenge cert into the shared [`CertCache`] the
/// resolver serves. (Persisting the account across restarts to reuse it fleet-wide is a follow-up;
/// today each process creates its own on first use — the CA `newAccount` limit is generous.)
pub struct AcmeIssuer {
    account: tokio::sync::OnceCell<Arc<boatramp_acme::acme::Account>>,
    challenge: AcmeChallenge,
    directory_url: String,
    contact_email: Option<String>,
    cache: Arc<CertCache>,
    dns_ttl: u32,
    propagation_delay: Duration,
    timeout: Duration,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Where the ACME account credentials persist (replicated control-plane KV), so the account is
    /// reused across restarts/replicas instead of re-created per process (CA `newAccount` limit).
    account_kv: Arc<dyn boatramp_core::kv::KvStore>,
    /// Wraps the stored account credentials at rest (the account key is sensitive), when `[secrets]`
    /// is configured — mirrors `KvCertStore`'s key-wrap. `None` ⇒ stored in the clear.
    account_envelope: Option<Arc<dyn boatramp_core::envelope::KeyEnvelope>>,
}

impl AcmeIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge: AcmeChallenge,
        directory_url: String,
        contact_email: Option<String>,
        cache: Arc<CertCache>,
        now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
        account_kv: Arc<dyn boatramp_core::kv::KvStore>,
        account_envelope: Option<Arc<dyn boatramp_core::envelope::KeyEnvelope>>,
    ) -> Self {
        Self {
            account: tokio::sync::OnceCell::new(),
            challenge,
            directory_url,
            contact_email,
            cache,
            dns_ttl: 60,
            propagation_delay: Duration::from_secs(15),
            timeout: Duration::from_secs(120),
            now_unix,
            account_kv,
            account_envelope,
        }
    }

    /// The replicated-KV key the account credentials persist under (per ACME directory).
    fn account_key(&self) -> String {
        format!(
            "acme-account/{}",
            boatramp_core::deploy::sha256_hex(self.directory_url.as_bytes())
        )
    }

    /// Serialize + (optionally) wrap the account credentials for storage.
    async fn encode_creds(
        &self,
        creds: &boatramp_acme::acme::AccountCredentials,
    ) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(creds).map_err(|e| e.to_string())?;
        match &self.account_envelope {
            Some(env) => env.wrap(&json).await.map_err(|e| e.to_string()),
            None => Ok(json),
        }
    }

    /// Unwrap + deserialize stored account credentials.
    async fn decode_creds(
        &self,
        raw: &[u8],
    ) -> Result<boatramp_acme::acme::AccountCredentials, String> {
        let json = match &self.account_envelope {
            Some(env) => env.unwrap(raw).await.map_err(|e| e.to_string())?,
            None => raw.to_vec(),
        };
        serde_json::from_slice(&json).map_err(|e| e.to_string())
    }

    /// The shared ACME account: created once on first demand (concurrent callers await the same init),
    /// restored from the replicated store across restarts/replicas, else created + persisted. Any
    /// load/restore failure falls through to create (never a hard failure).
    async fn account(&self) -> Result<&Arc<boatramp_acme::acme::Account>, String> {
        self.account
            .get_or_try_init(|| async {
                let key = self.account_key();
                // 1. Try to restore a previously-stored account (no CA `newAccount`).
                if let Ok(Some(raw)) = self.account_kv.get(&key).await {
                    match self.decode_creds(&raw).await {
                        Ok(creds) => match boatramp_acme::acme::restore_account(creds).await {
                            Ok(acc) => return Ok(Arc::new(acc)),
                            Err(e) => tracing::warn!(target: "boatramp::acme", error = %e, "stored ACME account failed to restore; creating a new one"),
                        },
                        Err(e) => tracing::warn!(target: "boatramp::acme", error = %e, "stored ACME account credentials were undecodable; creating a new one"),
                    }
                }
                // 2. Create + persist (best-effort; a persist failure only costs a re-create later).
                let (acc, creds) = boatramp_acme::acme::create_account(
                    &self.directory_url,
                    self.contact_email.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?;
                match self.encode_creds(&creds).await {
                    Ok(stored) => {
                        if let Err(e) = self.account_kv.put(&key, stored).await {
                            tracing::warn!(target: "boatramp::acme", error = %e, "could not persist the ACME account (re-created on the next restart)");
                        }
                    }
                    Err(e) => tracing::warn!(target: "boatramp::acme", error = %e, "could not encode the ACME account for storage"),
                }
                Ok::<_, String>(Arc::new(acc))
            })
            .await
    }
}

#[async_trait]
impl CertIssuer for AcmeIssuer {
    async fn issue(&self, sni: &str) -> Result<StoredCert, String> {
        let account = self.account().await?;
        let request = boatramp_acme::acme::CertRequest {
            directory_url: self.directory_url.clone(),
            contact_email: self.contact_email.clone(),
            domains: vec![sni.to_string()],
            dns_ttl: self.dns_ttl,
            propagation_delay: self.propagation_delay,
            timeout: self.timeout,
        };
        let issued = match &self.challenge {
            AcmeChallenge::Dns01(provider) => {
                let solver = boatramp_acme::acme::Dns01Solver::new(provider.as_ref(), self.dns_ttl);
                boatramp_acme::acme::obtain_certificate_with(account, &request, &solver).await
            }
            AcmeChallenge::TlsAlpn01 => {
                let solver = TlsAlpn01Solver {
                    cache: Arc::clone(&self.cache),
                };
                boatramp_acme::acme::obtain_certificate_with(account, &request, &solver).await
            }
        }
        .map_err(|e| e.to_string())?;
        let not_after = (self.now_unix)().saturating_add(ASSUMED_CERT_LIFETIME_SECS);
        Ok(StoredCert::new(
            issued.certificate_pem,
            issued.private_key_pem,
            not_after,
        ))
    }
}

/// A `boatramp_acme` [`ChallengeSolver`](boatramp_acme::acme::ChallengeSolver) for TLS-ALPN-01: build
/// the ephemeral challenge cert for the identifier and install it in the shared [`CertCache`], which
/// the [`OnDemandResolver`] serves on the `acme-tls/1` handshake; clear it on cleanup.
struct TlsAlpn01Solver {
    cache: Arc<CertCache>,
}

#[async_trait]
impl boatramp_acme::acme::ChallengeSolver for TlsAlpn01Solver {
    fn challenge_type(&self) -> boatramp_acme::acme::ChallengeType {
        boatramp_acme::acme::ChallengeType::TlsAlpn01
    }
    async fn present(
        &self,
        identifier: &str,
        key_auth: &boatramp_acme::acme::KeyAuthorization,
    ) -> Result<(), boatramp_acme::acme::AcmeError> {
        let (cert_pem, key_pem) =
            boatramp_acme::acme::tls_alpn01_challenge_cert(identifier, key_auth)?;
        let ck = crate::acme_dns::certified_key_from_pem(&cert_pem, &key_pem)
            .map_err(|e| boatramp_acme::acme::AcmeError::Solver(e.to_string()))?;
        self.cache.install_challenge(identifier, Arc::new(ck));
        Ok(())
    }
    async fn cleanup(&self, identifier: &str) -> Result<(), boatramp_acme::acme::AcmeError> {
        self.cache.clear_challenge(identifier);
        Ok(())
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
        engine_full(
            allowed,
            orders,
            lookups,
            is_leader,
            mem_store(),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
        )
    }

    /// Like [`engine_as`] but with an explicit (shareable) cert store + certreq KV, for the cross-node
    /// certreq test where a follower + a leader share the replicated stores.
    fn engine_full(
        allowed: &[&str],
        orders: Arc<AtomicUsize>,
        lookups: Arc<AtomicUsize>,
        is_leader: bool,
        cert_store: Arc<dyn CertStore>,
        certreq_kv: Arc<dyn boatramp_core::kv::KvStore>,
    ) -> Arc<OnDemandIssuer> {
        Arc::new(OnDemandIssuer {
            gate: Arc::new(StubGate {
                allowed: allowed.iter().map(|s| s.to_string()).collect(),
                lookups,
            }),
            issuer: Arc::new(StubIssuer { orders }),
            cert_store,
            is_leader: Arc::new(move || is_leader),
            now_unix: Arc::new(|| 1_000_000),
            cache: Arc::new(CertCache::default()),
            cfg: OnDemandConfig::default(),
            inflight: Mutex::new(HashSet::new()),
            negative: Mutex::new(HashMap::new()),
            sem: Arc::new(Semaphore::new(4)),
            limiter: RateLimiter::new(0),
            certreq_kv,
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

    /// The CI abuse-gate: an unverified SNI must place ZERO ACME orders. Run normally it PASSES; the
    /// CI re-runs it under `BOATRAMP_ONDEMAND_MUTATION=skip_allowlist`, which neuters the #02 allowlist
    /// check — it MUST then FAIL (the unauthorized SNI issues), proving the gate is load-bearing (the
    /// #503 anti-hollow convention). Prints a marker the CI greps so a silent skip/rename fails the job.
    #[tokio::test]
    async fn on_demand_abuse_gate() {
        let orders = Arc::new(AtomicUsize::new(0));
        let eng = engine(
            &["app.example.com"],
            orders.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        eng.issue_one("evil.attacker.test").await;
        assert_eq!(
            orders.load(Ordering::SeqCst),
            0,
            "an unverified SNI must place NO ACME order (the abuse gate)"
        );
        println!("ON-DEMAND ABUSE GATE OK: an unverified SNI placed no ACME order");
    }

    /// cap-req 03 #3: a new SNI that only ever hits a FOLLOWER still gets a cert — the follower records
    /// a replicated `certreq` marker, and the leader's drain issues it (exactly once) + clears the
    /// marker; a bogus/unauthorized marker is cleaned up without issuing.
    #[tokio::test]
    async fn certreq_queue_lets_a_follower_trigger_leader_issuance() {
        let certreq_kv: Arc<dyn boatramp_core::kv::KvStore> =
            Arc::new(boatramp_core::kv::MemoryKv::new());
        let cert_store = mem_store();

        // A FOLLOWER sees an authorized miss: NO order, but records a certreq marker.
        let follower_orders = Arc::new(AtomicUsize::new(0));
        let follower = engine_full(
            &["mail.example.com"],
            follower_orders.clone(),
            Arc::new(AtomicUsize::new(0)),
            false,
            cert_store.clone(),
            certreq_kv.clone(),
        );
        follower.issue_one("mail.example.com").await;
        assert_eq!(
            follower_orders.load(Ordering::SeqCst),
            0,
            "a follower places no order"
        );
        assert!(
            certreq_kv
                .get("certreq/mail.example.com")
                .await
                .unwrap()
                .is_some(),
            "the follower recorded a cross-node certreq marker"
        );

        // The LEADER drains: issues once, stores (replicates), and clears the marker.
        let leader_orders = Arc::new(AtomicUsize::new(0));
        let leader = engine_full(
            &["mail.example.com"],
            leader_orders.clone(),
            Arc::new(AtomicUsize::new(0)),
            true,
            cert_store.clone(),
            certreq_kv.clone(),
        );
        leader.certreq_drain_once().await;
        assert_eq!(
            leader_orders.load(Ordering::SeqCst),
            1,
            "the leader issued exactly once"
        );
        assert!(
            cert_store.get("mail.example.com").await.unwrap().is_some(),
            "the issued cert is stored (replicates to followers)"
        );
        assert!(
            certreq_kv
                .get("certreq/mail.example.com")
                .await
                .unwrap()
                .is_none(),
            "the marker is cleared after issuance"
        );

        // A bogus/unauthorized certreq marker is cleaned up without issuing.
        certreq_kv
            .put("certreq/evil.attacker.test", Vec::new())
            .await
            .unwrap();
        leader.certreq_drain_once().await;
        assert_eq!(
            leader_orders.load(Ordering::SeqCst),
            1,
            "no order for an unauthorized certreq"
        );
        assert!(
            certreq_kv
                .get("certreq/evil.attacker.test")
                .await
                .unwrap()
                .is_none(),
            "the bogus marker is cleaned up"
        );
    }
}
