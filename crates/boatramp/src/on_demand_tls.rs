//! On-demand per-SNI TLS issuance at scale (cap-req 03).
//!
//! A multi-tenant edge fronts many customer-owned hostnames. Pre-registering a cert per hostname does
//! not scale; instead, on the first TLS handshake for an **authorized** but not-yet-issued SNI, the
//! host issues (and caches) a cert, then serves the client on its retry. The authorization gate is the
//! #02 verified-domain allowlist ([`DeployGate`]): the SNI must resolve to a site AND that site must
//! hold an ownership-**verified** record for the host (not mere attachment). Issuance for an arbitrary
//! attacker-chosen — or merely-attached-but-unverified — SNI is **refused** (fail-closed), so a flood
//! of such SNIs can never become an ACME / rate-limit storm.
//!
//! This module is the security engine: the [`OnDemandResolver`] (a `rustls` cert resolver that serves
//! a cached cert, or triggers issuance and fails this handshake so the client retries), and the
//! [`OnDemandIssuer`] worker (allowlist gate → per-node single-flight → negative cache → rate limit →
//! cluster single-flight via [`ensure_cert`] → cache). The ACME-backed [`CertIssuer`] and the config
//! + serve wiring live alongside (cap-req 03 Stage 1c); this engine is abstract over the issuance
//! backend ([`CertIssuer`]) and the allowlist ([`IssuanceGate`]) so it is unit-testable offline.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
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

/// The #02 verified-domain allowlist: an SNI is authorized iff it resolves to a site AND that site has
/// an **ownership-verified** record for the host. Resolution alone is NOT sufficient — a raw
/// `set_site_config` can write the `domain/<host>` index without any proof, whereas
/// `attach_verified_domain` requires `is_domain_verified` first. Gating on resolution alone would let a
/// tenant attach bogus/unverified hostnames to its own site and, by cycling SNIs for them, churn the
/// shared CA rate-limit + in-flight budget (a cross-tenant availability vector) — even though the ACME
/// challenge would ultimately refuse the cert. So we require verification here (defense-in-depth; it
/// also makes "authorized" match the documented invariant). Any error resolving/checking fails
/// **closed**.
pub struct DeployGate {
    pub deploy: boatramp_core::deploy::DeployStore,
}

#[async_trait]
impl IssuanceGate for DeployGate {
    async fn is_authorized(&self, sni: &str) -> bool {
        // Delegates to the core authority check: resolvable AND covered by a verified record (exact,
        // or a DNS-verified ancestor zone), fail-closed. See `DeployStore::is_host_issuance_authorized`.
        self.deploy.is_host_issuance_authorized(sni).await
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
                        tracing::warn!(target: "boatramp::acme", %sni, error = %e, "on-demand cert parse failed");
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
    /// out so it is unit-testable without the timer loop). Takes `&Arc<Self>` so issuance goes through
    /// the per-node [`issue_deduped`](Self::issue_deduped) single-flight — a drain tick and a
    /// concurrent resolver trigger for the same SNI then coalesce to ONE CA order instead of racing
    /// into two.
    async fn certreq_drain_once(self: &Arc<Self>) {
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
            // Issue on the leader via the single-flight (coalesces with a concurrent resolver trigger
            // for the same SNI); drop the marker once the cert is stored. If the name is already
            // in-flight elsewhere, this no-ops and the marker is retried on a later tick.
            Arc::clone(self).issue_deduped(sni.clone()).await;
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
    /// authorized miss (the issuance gate runs in the worker, never on the handshake path). The public
    /// edge resolver: UNSCOPED (serves every verified domain).
    pub fn resolver(&self) -> Arc<OnDemandResolver> {
        Arc::new(OnDemandResolver {
            cache: Arc::clone(&self.cache),
            trigger: self.trigger.clone(),
            scope: None,
        })
    }

    /// A resolver for a host-owned listener bound to `project` (cap-req 03 #4 / Finding B): shares the
    /// SAME engine (one cache, one trigger, one issuance budget) but serves issued certs ONLY for
    /// domains owned by `project`, using `deploy` for the synchronous owner check. A listener thus
    /// never serves (nor routes to its guest) a cert for another project's domain.
    pub fn scoped_resolver(
        &self,
        project: String,
        deploy: boatramp_core::deploy::DeployStore,
    ) -> Arc<OnDemandResolver> {
        Arc::new(OnDemandResolver {
            cache: Arc::clone(&self.cache),
            trigger: self.trigger.clone(),
            scope: Some(ListenerScope { project, deploy }),
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
    extra_root_ca: Option<PathBuf>,
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
    // LOW-3 (security review): without a `[secrets]` key envelope, issued cert private keys and the
    // persisted ACME account credentials are stored UNENCRYPTED in the replicated control-plane KV
    // (the documented fallback, same as the static cluster-cert store). Warn loudly so an operator
    // enabling on-demand TLS in production configures `[secrets]`.
    let envelope_wrapped = account_envelope.is_some();
    let issuer = Arc::new(AcmeIssuer::new(
        challenge,
        directory_url,
        cfg.contact_email.clone(),
        Arc::clone(&cache),
        Arc::clone(&now_unix),
        account_kv,
        account_envelope,
        extra_root_ca,
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
    if !envelope_wrapped {
        tracing::warn!(
            target: "boatramp::acme",
            "on-demand TLS is enabled WITHOUT a [secrets] key envelope: issued cert private keys and \
             the ACME account credentials persist UNENCRYPTED in the control-plane store; configure \
             [secrets] to wrap them at rest"
        );
    }
    tracing::info!(
        target: "boatramp::acme",
        "on-demand per-SNI TLS issuance ENABLED (allowlist = verified custom domains)"
    );
    Some(OnDemandTls::start(
        gate, issuer, cert_store, is_leader, now_unix, cache, runtime, certreq_kv,
    ))
}

/// Restricts a listener's on-demand resolver to the domains of ONE project (cap-req 03 #4 / Security
/// review Finding B). The public 443 edge has NO scope — it fronts every verified domain. A host-owned
/// listener is bound to exactly one project (its operator-pinned `(project, site)`), and that project
/// may front many domains (its tenants/sites). This scope makes the listener serve an issued cert ONLY
/// for an SNI whose owning project matches — so a listener bound to project P can never serve a cert
/// for another project's domain (and route that decrypted connection to P's guest), even though the
/// certs share one engine + one cache. The check is the synchronous, fail-closed
/// [`DeployStore::cached_owner`]: an SNI whose owner is not cached as this project is not served (and,
/// when the owner is a KNOWN other project, not even triggered for issuance).
#[derive(Clone)]
pub struct ListenerScope {
    project: String,
    deploy: boatramp_core::deploy::DeployStore,
}

/// A [`ResolvesServerCert`] that serves an issued cert by SNI, a TLS-ALPN-01 challenge cert on the
/// `acme-tls/1` handshake, and otherwise **triggers** on-demand issuance (non-blocking) and returns
/// `None` — failing this handshake so the client retries once the cert is warm.
pub struct OnDemandResolver {
    cache: Arc<CertCache>,
    trigger: mpsc::Sender<String>,
    /// `None` at the public edge (serves every verified domain). `Some` on a host-owned listener,
    /// restricting the issued-cert serve path to the scope's project (Finding B).
    scope: Option<ListenerScope>,
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
        // (Challenge certs are ephemeral + ALPN-gated and are validated at the 443 edge, so they are
        // not scoped here.)
        if is_acme_alpn {
            return self.cache.get_challenge(sni);
        }
        // Listener scope (Finding B): a scoped listener serves an issued cert ONLY for an SNI it can
        // synchronously confirm belongs to its project; a KNOWN other-project owner is refused outright
        // (no serve, no trigger); an UNKNOWN (uncached) owner fails closed for serving but still
        // triggers an async resolution+issuance — the retry then either confirms in-project (served) or
        // reveals another project (refused), so a wrong-project cert is never served.
        if let Some(scope) = &self.scope {
            match scope.deploy.cached_owner(sni) {
                Some(owner) if owner.project == scope.project => {
                    if let Some(key) = self.cache.get_issued(sni) {
                        return Some(key);
                    }
                    // In-project but not yet issued: trigger, fail this handshake, serve on retry.
                    let _ = self.trigger.try_send(sni.to_string());
                    return None;
                }
                Some(_) => {
                    // A confirmed OTHER project's domain: never served or issued by this listener.
                    return None;
                }
                None => {
                    // Owner not (freshly) cached: can't confirm in-project, so don't serve. Trigger an
                    // async resolution (which populates the owner cache) so a legitimate in-project
                    // domain is issued + servable on the retry. A wrong-project name issued this way is
                    // still refused on the retry (owner then resolves to the other project).
                    let _ = self.trigger.try_send(sni.to_string());
                    return None;
                }
            }
        }
        // Unscoped edge: serve any issued cert, else trigger (gated + single-flighted in the worker).
        if let Some(key) = self.cache.get_issued(sni) {
            return Some(key);
        }
        // Miss: nudge the issuer (non-blocking; gated + single-flighted in the worker) and fail this
        // handshake. The client retries and hits the now-warm cache.
        let _ = self.trigger.try_send(sni.to_string());
        None
    }

    /// Build a resolver over a pre-seeded [`CertCache`] with a dead trigger channel. Test-only seam
    /// (no engine, no issuance) for exercising the composite's handshake dispatch: a miss simply fails
    /// the handshake instead of triggering issuance. Unscoped (edge-like).
    #[cfg(test)]
    pub(crate) fn from_cache(cache: Arc<CertCache>) -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self {
            cache,
            trigger: tx,
            scope: None,
        }
    }

    /// Like [`from_cache`](Self::from_cache) but PROJECT-SCOPED (test-only seam for Finding B): serves
    /// an issued cert only for an SNI `deploy` resolves to `project`.
    #[cfg(test)]
    pub(crate) fn scoped_from_cache(
        cache: Arc<CertCache>,
        project: String,
        deploy: boatramp_core::deploy::DeployStore,
    ) -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self {
            cache,
            trigger: tx,
            scope: Some(ListenerScope { project, deploy }),
        }
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
    /// Extra root CA (PEM file) to trust for the ACME directory's TLS (a test/staging CA, e.g.
    /// Pebble). `None` ⇒ the platform's public roots (production Let's Encrypt / Google Trust
    /// Services). Threaded into both the account-create and account-restore paths so the instant-acme
    /// HTTP client trusts it — since instant-acme 0.8 the default client's platform verifier no
    /// longer honours `SSL_CERT_FILE`, so this must be set explicitly.
    extra_root_ca: Option<PathBuf>,
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
        extra_root_ca: Option<PathBuf>,
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
            extra_root_ca,
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
                        Ok(creds) => match boatramp_acme::acme::restore_account(creds, self.extra_root_ca.as_deref()).await {
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
                    self.extra_root_ca.as_deref(),
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
            extra_root_ca: self.extra_root_ca.clone(),
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

    /// A no-op blob [`Storage`] — `DeployStore`'s domain operations are KV-only, so this is never
    /// touched; it only satisfies the `DeployStore::new` constructor for the gate test below.
    struct NullStorage;
    #[async_trait]
    impl boatramp_core::Storage for NullStorage {
        async fn get(
            &self,
            _: &str,
        ) -> std::result::Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> std::result::Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: boatramp_core::ByteStream,
            _: boatramp_core::PutMeta,
        ) -> std::result::Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::unsupported("null"))
        }
        async fn head(
            &self,
            _: &str,
        ) -> std::result::Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> std::result::Result<(), boatramp_core::StorageError> {
            Ok(())
        }
        async fn list(
            &self,
            _: &str,
        ) -> std::result::Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError>
        {
            Ok(Vec::new())
        }
    }

    // Finding-A gate: on-demand issuance authorizes an attached + ownership-VERIFIED domain, and
    // REFUSES a domain that is merely attached/resolvable but not verified (which a raw
    // `set_site_config` can write without proof) — so a tenant can't churn the shared CA budget by
    // cycling bogus self-attached names. Resolution alone is not authorization.
    #[tokio::test]
    async fn deploy_gate_requires_verification_not_mere_attachment() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = DeployStore::new(
            Arc::new(NullStorage),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
        );
        let proj = ProjectRef::new("shop");
        let site = SiteName::new("storefront");

        // (1) A merely-ATTACHED, unverified domain: written into the site config (so it resolves) but
        // never verified.
        let cfg = boatramp_core::config::SiteConfig {
            domains: boatramp_core::config::DomainConfig {
                primary: Some("attached.example.test".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        store
            .set_site_config(proj, "storefront", &cfg)
            .await
            .unwrap();

        // (2) A properly VERIFIED + attached domain.
        store
            .start_domain_verification(
                proj,
                &site,
                "verified.example.test",
                boatramp_core::domain_verify::VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(proj, &site, "verified.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(proj, &site, "verified.example.test")
            .await
            .unwrap();

        // (3) A DNS-verified WILDCARD: proves control of the zone ⇒ covers the whole subtree.
        store
            .start_domain_verification(
                proj,
                &site,
                "*.wild.example.test",
                boatramp_core::domain_verify::VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(proj, &site, "*.wild.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(proj, &site, "*.wild.example.test")
            .await
            .unwrap();

        let gate = DeployGate {
            deploy: store.clone(),
        };

        // Both resolve to a site (the loose, pre-fix condition would authorize BOTH)…
        assert!(
            matches!(
                store.resolve_site_by_host("attached.example.test").await,
                Ok(Some(_))
            ),
            "the unverified domain still resolves — resolution is not verification"
        );
        // …but only the verified one is AUTHORIZED for issuance.
        assert!(
            gate.is_authorized("verified.example.test").await,
            "a verified attached domain is authorized for on-demand issuance"
        );
        assert!(
            !gate.is_authorized("attached.example.test").await,
            "a merely-attached, UNVERIFIED domain must NOT be authorized (Finding A)"
        );
        // An unknown SNI resolves to nothing ⇒ refused (fail-closed), unchanged.
        assert!(
            !gate.is_authorized("stranger.example.test").await,
            "an unresolvable SNI is refused"
        );
        // A subdomain under the DNS-verified wildcard is authorized — zone control covers the subtree
        // (single- AND multi-label; the ACME challenge is the hard backstop for the specific name).
        assert!(
            gate.is_authorized("x.wild.example.test").await,
            "a single-label subdomain under a DNS-verified wildcard is authorized"
        );
        assert!(
            gate.is_authorized("a.b.wild.example.test").await,
            "a multi-label subdomain under a DNS-verified wildcard is authorized (zone control)"
        );
        // But a subdomain of a merely-attached (unverified) name is NOT authorized.
        assert!(
            !gate.is_authorized("deep.attached.example.test").await,
            "a subdomain of an unverified domain is refused"
        );
        println!(
            "ON-DEMAND GATE VERIFIED-ONLY OK: verified + DNS-wildcard-subtree authorized, merely-attached refused"
        );
    }

    // Finding-B scope: a host-owned listener's resolver serves an issued cert ONLY for an SNI owned by
    // its own project — never another project's domain, even though both certs sit in the ONE shared
    // cache. (Closes the cross-tenant plaintext-capture vector: a listener pinned to project P can't be
    // induced to serve V's cert and route V's connection to P's guest.)
    #[tokio::test]
    async fn listener_scope_serves_only_its_own_projects_domains() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::project::ProjectRef;

        let store = DeployStore::new(
            Arc::new(NullStorage),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
        );
        // Two projects, one domain each, both written into the domain index.
        let mine = boatramp_core::config::SiteConfig {
            domains: boatramp_core::config::DomainConfig {
                primary: Some("mine.example.test".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let other = boatramp_core::config::SiteConfig {
            domains: boatramp_core::config::DomainConfig {
                primary: Some("other.example.test".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        store
            .set_site_config(ProjectRef::new("mailroom"), "s", &mine)
            .await
            .unwrap();
        store
            .set_site_config(ProjectRef::new("storefront"), "s", &other)
            .await
            .unwrap();
        // Warm the synchronous owner cache the scope check reads.
        assert!(matches!(
            store.resolve_site_by_host("mine.example.test").await,
            Ok(Some(_))
        ));
        assert!(matches!(
            store.resolve_site_by_host("other.example.test").await,
            Ok(Some(_))
        ));

        // Both certs live in the ONE shared cache (as if the edge issued both).
        let cache = Arc::new(CertCache::default());
        for sni in ["mine.example.test", "other.example.test"] {
            let (cert, key) = self_signed(sni);
            cache.insert_issued(
                sni,
                Arc::new(crate::acme_dns::certified_key_from_pem(&cert, &key).unwrap()),
            );
        }

        // A resolver scoped to the `mailroom` project (what a mailroom-pinned listener gets).
        let scoped = OnDemandResolver::scoped_from_cache(
            Arc::clone(&cache),
            "mailroom".to_string(),
            store.clone(),
        );
        assert!(
            scoped.resolve_sni("mine.example.test", false).is_some(),
            "serves its OWN project's verified domain"
        );
        assert!(
            scoped.resolve_sni("other.example.test", false).is_none(),
            "must NOT serve another project's domain, even though its cert is cached (Finding B)"
        );
        assert!(
            scoped.resolve_sni("stranger.example.test", false).is_none(),
            "an unknown SNI is not served"
        );

        // The UNSCOPED edge resolver over the same cache serves both (the edge fronts every domain).
        let edge = OnDemandResolver::from_cache(Arc::clone(&cache));
        assert!(edge.resolve_sni("mine.example.test", false).is_some());
        assert!(
            edge.resolve_sni("other.example.test", false).is_some(),
            "the edge is unscoped and serves every verified domain"
        );
        println!(
            "LISTENER PROJECT-SCOPE OK: own-project served, other-project refused, edge unscoped"
        );
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
                allowed: allowed.iter().copied().map(String::from).collect(),
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

    /// End-to-end on-demand issuance against a local [Pebble](https://github.com/letsencrypt/pebble)
    /// CA via **DNS-01** (challtestsrv), driving the REAL `OnDemandIssuer` → `AcmeIssuer` →
    /// `obtain_certificate_with` path: an authorized SNI gets a Pebble-signed cert into the store +
    /// cache; an unauthorized SNI issues nothing. `#[ignore]`d — needs `pebble` + `pebble-challtestsrv`
    /// on `PATH` (nix dev shell) + binds local ports. Run:
    /// `cargo test -p boatramp --features acme-dns,cluster on_demand_issuance_against_pebble -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs pebble + pebble-challtestsrv on PATH (nix dev shell); binds local ports"]
    async fn on_demand_issuance_against_pebble() {
        use boatramp_acme::dns::{DnsError, DnsProvider, DnsRecord};
        use std::time::Duration;

        const CHALLTESTSRV_MGMT: &str = "http://127.0.0.1:8055";
        const DIRECTORY_URL: &str = "https://localhost:14000/dir";

        /// A `DnsProvider` backed by challtestsrv's management API (set/clear the `_acme-challenge` TXT).
        struct ChallTestSrv {
            client: reqwest::Client,
        }
        #[async_trait]
        impl DnsProvider for ChallTestSrv {
            async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
                self.client
                    .post(format!("{CHALLTESTSRV_MGMT}/set-txt"))
                    .json(&serde_json::json!({ "host": format!("{}.", record.name), "value": record.value }))
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|e| DnsError::Backend(e.to_string()))?;
                Ok(())
            }
            async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
                self.client
                    .post(format!("{CHALLTESTSRV_MGMT}/clear-txt"))
                    .json(&serde_json::json!({ "host": format!("{}.", record.name) }))
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|e| DnsError::Backend(e.to_string()))?;
                Ok(())
            }
        }
        /// A child process killed on drop (so a failed test leaks no pebble processes).
        struct Child(tokio::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.start_kill();
            }
        }
        fn on_path(bin: &str) -> bool {
            std::process::Command::new(bin)
                .arg("-help")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok()
        }
        fn mint_certs(dir: &std::path::Path) -> std::path::PathBuf {
            use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();
            let leaf_key = KeyPair::generate().unwrap();
            let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
            let ca_path = dir.join("ca.pem");
            std::fs::write(&ca_path, ca_cert.pem()).unwrap();
            std::fs::write(dir.join("cert.pem"), leaf_cert.pem()).unwrap();
            std::fs::write(dir.join("key.pem"), leaf_key.serialize_pem()).unwrap();
            ca_path
        }

        if !on_path("pebble") || !on_path("pebble-challtestsrv") {
            eprintln!(
                "skipping: pebble / pebble-challtestsrv not on PATH (run inside `nix develop`)"
            );
            return;
        }
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("br-ondemand-pebble-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = mint_certs(&dir);
        // Bind the IPv6 wildcard so `localhost` (IPv6-first on macOS / IPv6-enabled runners) reaches
        // Pebble; the cert names `localhost` and Pebble rejects bare-IP `Host` headers with 400.
        let config = serde_json::json!({ "pebble": {
            "listenAddress": "[::]:14000", "managementListenAddress": "[::]:15000",
            "certificate": dir.join("cert.pem"), "privateKey": dir.join("key.pem"),
            "httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "" } });
        let config_path = dir.join("pebble.json");
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        // challtestsrv >= 2.10: DNS flag is `-dnsserver` (was `-dns01`) and a DoH responder (`-doh`)
        // must be disabled too; bound to the IPv4 loopback the management POSTs / Pebble resolver use.
        let _challtestsrv = Child(
            tokio::process::Command::new("pebble-challtestsrv")
                .args([
                    "-dnsserver",
                    "127.0.0.1:8053",
                    "-management",
                    "127.0.0.1:8055",
                ])
                .args(["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""])
                .kill_on_drop(true)
                .spawn()
                .expect("spawn pebble-challtestsrv"),
        );
        let _pebble = Child(
            tokio::process::Command::new("pebble")
                .args(["-config", config_path.to_str().unwrap()])
                .args(["-dnsserver", "127.0.0.1:8053"])
                .env("PEBBLE_VA_NOSLEEP", "1")
                .kill_on_drop(true)
                .spawn()
                .expect("spawn pebble"),
        );
        // Pebble >= 2.10 rejects any request without a `User-Agent` (HTTP 400); set one for the probe.
        let probe = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .user_agent("boatramp-ondemand-pebble-test")
            .build()
            .unwrap();
        let mut ready = false;
        for _ in 0..50 {
            if probe
                .get(DIRECTORY_URL)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        assert!(ready, "Pebble directory did not become ready");
        // Wait for challtestsrv's management API too (any HTTP response means the port is bound),
        // so the first `set-txt` during issuance doesn't race a slow-to-bind challtestsrv.
        let mut challtestsrv_ready = false;
        for _ in 0..50 {
            if probe.get(CHALLTESTSRV_MGMT).send().await.is_ok() {
                challtestsrv_ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            challtestsrv_ready,
            "pebble-challtestsrv management API did not come up"
        );
        // Trust the throwaway CA for instant-acme by passing it to the issuer (`extra_root_ca`).
        // Since instant-acme 0.8 the default client uses the platform verifier, which does NOT
        // honour `SSL_CERT_FILE`, so the CA must be configured explicitly on the account builder.

        // A real on-demand engine: DNS-01 via challtestsrv, an in-memory store, one authorized SNI.
        let cache = Arc::new(CertCache::default());
        let now_unix: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
        let issuer: Arc<dyn CertIssuer> = Arc::new(AcmeIssuer::new(
            AcmeChallenge::Dns01(Arc::new(ChallTestSrv {
                client: reqwest::Client::new(),
            })),
            DIRECTORY_URL.to_string(),
            Some("ops@example.test".to_string()),
            Arc::clone(&cache),
            Arc::clone(&now_unix),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
            None,
            Some(ca_path.clone()),
        ));
        let cert_store = mem_store();
        let eng = Arc::new(OnDemandIssuer {
            gate: Arc::new(StubGate {
                allowed: ["www.deploy.test".to_string()].into_iter().collect(),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            issuer,
            cert_store: Arc::clone(&cert_store),
            is_leader: Arc::new(|| true),
            now_unix,
            cache: Arc::clone(&cache),
            cfg: OnDemandConfig::default(),
            inflight: Mutex::new(HashSet::new()),
            negative: Mutex::new(HashMap::new()),
            sem: Arc::new(Semaphore::new(4)),
            limiter: RateLimiter::new(0),
            certreq_kv: Arc::new(boatramp_core::kv::MemoryKv::new()),
        });

        // Authorized SNI ⇒ a real Pebble-signed cert lands in the store + the resolver cache.
        eng.issue_one("www.deploy.test").await;
        assert!(
            matches!(cert_store.get("www.deploy.test").await, Ok(Some(_))),
            "an authorized SNI issues + stores a real cert"
        );
        assert!(
            cache.get_issued("www.deploy.test").is_some(),
            "the issued cert is cached for the resolver"
        );
        // Unauthorized SNI ⇒ nothing issued (the #02 gate, end to end).
        eng.issue_one("evil.deploy.test").await;
        assert!(
            matches!(cert_store.get("evil.deploy.test").await, Ok(None)),
            "an unauthorized SNI issues nothing, even against a live CA"
        );
        let _ = std::fs::remove_dir_all(&dir);
        println!("ON-DEMAND PEBBLE E2E OK: authorized SNI issued via DNS-01, unauthorized refused");
    }
}
