//! ACME **DNS-01** wildcard issuance (Let's Encrypt or any RFC 8555 CA).
//!
//! TLS-ALPN-01 (the server's existing path) cannot issue a `*.x` wildcard;
//! DNS-01 can. The flow: place an order for the wildcard identifier, prove each
//! authorization by writing its `_acme-challenge` TXT via a [`DnsProvider`],
//! finalize with a CSR (rcgen), and return the cert chain + key. The DNS write
//! is provider-agnostic, so the same flow runs against Cloudflare / Route 53 /
//! OCI / a manual operator.
//!
//! The boatramp-specific logic (challenge naming, TXT value, record cleanup) is
//! unit-tested in [`crate::dns`]; the full live CA round-trip is exercised
//! against a local Pebble CA by the `pebble_dns01` integration test
//! (`#[ignore]`d — run via `just acme-dns-e2e`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use instant_acme::{AuthorizationStatus, Identifier, NewAccount, NewOrder, OrderStatus};
// Re-exported so a caller can implement [`ChallengeSolver`] + manage account lifecycle without a
// direct `instant-acme` dependency. These also bring the names into this module's scope.
pub use instant_acme::{Account, AccountCredentials, ChallengeType, KeyAuthorization};

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, TxtResolver, acme_challenge_name};

/// A failure during ACME DNS-01 issuance.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// An error from the ACME protocol client.
    #[error("ACME protocol error: {0}")]
    Acme(#[from] instant_acme::Error),
    /// Key or CSR generation failed.
    #[error("certificate key/CSR generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// A DNS provider operation (challenge TXT write) failed.
    #[error("DNS provider: {0}")]
    Dns(#[from] crate::dns::DnsError),
    /// The CA offered no challenge of the solver's type for an authorization.
    #[error("authorization offers no {0:?} challenge")]
    NoChallenge(ChallengeType),
    /// An authorization carried a non-DNS identifier (e.g. an IP address). The DNS/TLS/HTTP
    /// challenge solvers all key off a DNS name, and boatramp only ever orders DNS identifiers, so
    /// this is a protocol violation rather than something to present a challenge for.
    #[error("authorization identifier is not a DNS name")]
    NonDnsIdentifier,
    /// The order failed validation (a challenge did not pass).
    #[error("ACME order became invalid (challenge failed)")]
    OrderInvalid,
    /// Timed out waiting for the order to become ready.
    #[error("timed out waiting for ACME order to become ready")]
    OrderReadyTimeout,
    /// Timed out waiting for the issued certificate.
    #[error("timed out waiting for the ACME certificate")]
    CertificateTimeout,
    /// A challenge solver failed to present/clean up its challenge (e.g. building or installing the
    /// TLS-ALPN-01 challenge certificate).
    #[error("challenge solver: {0}")]
    Solver(String),
}

/// What to request and how to talk to the CA.
#[derive(Clone)]
pub struct CertRequest {
    /// ACME directory URL (e.g. Let's Encrypt production/staging).
    pub directory_url: String,
    /// Account contact (an email), if the CA wants one.
    pub contact_email: Option<String>,
    /// Identifiers to certify — e.g. `["*.deploy.example.com"]`.
    pub domains: Vec<String>,
    /// TTL for the challenge TXT records.
    pub dns_ttl: u32,
    /// **Maximum** time to wait for the DNS-01 `_acme-challenge` TXT to become
    /// visible in the zone before telling the CA to validate. This is an upper
    /// bound on a *real readiness poll*, not a blind sleep: when a [`TxtResolver`]
    /// is wired into the [`Dns01Solver`], issuance proceeds as soon as the record
    /// is observed live, and only falls back to proceeding-anyway (with a warning;
    /// the CA also retries) if this bound elapses without visibility. With no
    /// resolver wired it degrades to a single blind sleep of this duration (the
    /// pre-fix behaviour). See [`wait_for_propagation`].
    pub propagation_wait: Duration,
    /// How often to re-query the resolver while waiting for the TXT to propagate
    /// (the per-attempt interval, bounded by [`propagation_wait`](Self::propagation_wait)).
    pub propagation_poll_interval: Duration,
    /// How long to keep polling the order before giving up.
    pub timeout: Duration,
    /// Extra root CA (PEM file) to trust for the ACME directory's TLS, for a test/staging CA whose
    /// directory uses a privately-issued certificate (e.g. Pebble). `None` ⇒ trust the platform's
    /// public roots (the production Let's Encrypt / Google Trust Services case). Only consulted by
    /// the account-creating convenience [`obtain_certificate`]; [`obtain_certificate_with`] takes an
    /// already-built account whose HTTP client already encodes this choice.
    pub extra_root_ca: Option<PathBuf>,
}

impl Default for CertRequest {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            contact_email: None,
            domains: Vec::new(),
            dns_ttl: 60,
            propagation_wait: Duration::from_secs(15),
            propagation_poll_interval: Duration::from_secs(2),
            timeout: Duration::from_secs(120),
            extra_root_ca: None,
        }
    }
}

/// A freshly issued certificate: the PEM chain plus the PEM private key (the key
/// is generated here by rcgen and never leaves this process except in the
/// returned struct, which the caller writes to its cert cache).
pub struct IssuedCert {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// Whether a presented challenge is yet observable the way the CA will see it — the result of
/// [`ChallengeSolver::poll_presented`], driving [`wait_for_propagation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    /// The challenge is live (for DNS-01: the `_acme-challenge` TXT's expected value resolves) —
    /// safe to tell the CA to validate.
    Ready,
    /// Not visible yet — keep polling until the deadline.
    Pending,
    /// This solver has **no way to check** readiness (DNS-01 with no [`TxtResolver`] wired). The
    /// driver then falls back to a single blind wait of the whole `propagation_wait` budget before
    /// proceeding — the pre-fix behaviour, so a caller that wires no resolver is no worse off.
    Unchecked,
}

/// Presents and tears down the ACME challenge for one authorization. Protocol-agnostic over the
/// challenge *type*, so the same order driver ([`obtain_certificate_with`]) issues via DNS-01 (for a
/// wildcard / an operator-controlled zone), TLS-ALPN-01 (the 443 edge, no extra port), or HTTP-01.
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// Which challenge type this solver satisfies (the driver picks the matching challenge).
    fn challenge_type(&self) -> ChallengeType;
    /// Present the challenge for `identifier` using `key_auth` (called before `set_challenge_ready`).
    async fn present(&self, identifier: &str, key_auth: &KeyAuthorization)
    -> Result<(), AcmeError>;
    /// Whether the challenge presented for `identifier` is now externally observable — called by
    /// [`wait_for_propagation`] repeatedly between [`present`](Self::present) and
    /// `set_challenge_ready`, so the driver tells the CA to validate only once the record is live.
    ///
    /// The default returns [`Propagation::Ready`]: a TLS-ALPN-01 / HTTP-01 solver installs its
    /// challenge **locally** in `present` (the 443 resolver slot / an HTTP path), so there is nothing
    /// external to wait for. The DNS-01 solver overrides this to resolve the `_acme-challenge` TXT and
    /// confirm the expected value has propagated (the fix for the DNS-01 validation race).
    async fn poll_presented(&self, _identifier: &str) -> Result<Propagation, AcmeError> {
        Ok(Propagation::Ready)
    }
    /// Tear down whatever `present` installed (best-effort; called once the order resolves or fails).
    async fn cleanup(&self, identifier: &str) -> Result<(), AcmeError>;
}

/// Run one ACME order for `request.domains` against an **already-created** `account`, solving every
/// pending authorization via `solver`. The account is reused across orders by the caller (a new
/// account per order would exhaust the CA `newAccount` rate limit at on-demand scale). Cleans up the
/// presented challenges before returning, on success or failure.
pub async fn obtain_certificate_with(
    account: &Account,
    request: &CertRequest,
    solver: &dyn ChallengeSolver,
) -> Result<IssuedCert, AcmeError> {
    let identifiers: Vec<Identifier> = request
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let want = solver.challenge_type();
    // Identifiers we presented a challenge for, so we clean exactly those up afterward.
    let mut presented: Vec<String> = Vec::new();
    // instant-acme 0.8 exposes the authorizations as a stream-like iterator that borrows the order
    // mutably; scope it so the borrow is released before `drive_to_certificate` reborrows `order`.
    {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            // An already-valid authorization (e.g. a reused account's cached validation) needs no
            // challenge presented.
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            // Select the solver's challenge type. Since 0.8.5, a tokenless challenge the CA may now
            // also offer (e.g. `dns-persist-01`, Let's Encrypt / Pebble ≥ 2.10.0) no longer fails
            // deserialization and so no longer wrecks this selection — `dns-01` is still picked.
            let Some(mut challenge) = authz.challenge(want.clone()) else {
                return Err(AcmeError::NoChallenge(want.clone()));
            };
            // boatramp only ever orders DNS identifiers; the base domain (wildcards arrive here
            // stripped to their base, with the wildcard flag carried separately) is what the
            // solver writes `_acme-challenge.<base>` / builds the challenge cert for.
            let identifier = match &challenge.identifier().identifier {
                Identifier::Dns(dns) => dns.clone(),
                _ => return Err(AcmeError::NonDnsIdentifier),
            };
            let key_auth = challenge.key_authorization();
            solver.present(&identifier, &key_auth).await?;
            presented.push(identifier.clone());
            // THE FIX: wait for the presented challenge to actually propagate BEFORE telling the CA
            // to validate. `set_challenge_ready` is the signal that makes the CA validate (often
            // immediately), so for DNS-01 the `_acme-challenge` TXT must already be live at the zone's
            // nameservers — otherwise the order goes `invalid` and issuance crash-loops. The wait and
            // the set-ready are kept together in `confirm_then_set_ready` so the ordering is a single,
            // unit-tested unit (a reviewer cannot silently drop the wait without a test going red).
            confirm_then_set_ready(solver, &identifier, request, &mut challenge).await?;
        }
    }

    let result = drive_to_certificate(&mut order, request).await;

    for identifier in &presented {
        if let Err(err) = solver.cleanup(identifier).await {
            tracing::warn!(target: "boatramp::acme", %err, %identifier, "challenge cleanup failed");
        }
    }
    result
}

/// The CA-facing "this challenge is ready to validate" signal — `instant-acme`'s
/// [`ChallengeHandle::set_ready`](instant_acme::ChallengeHandle::set_ready), abstracted behind a
/// trait so the **present → wait → ready** ordering (see [`confirm_then_set_ready`]) is unit-testable
/// without a live CA / a real `instant_acme::Order`. The production impl forwards to the real handle.
#[async_trait]
trait SetChallengeReady: Send {
    async fn set_ready(&mut self) -> Result<(), AcmeError>;
}

#[async_trait]
impl SetChallengeReady for instant_acme::ChallengeHandle<'_> {
    async fn set_ready(&mut self) -> Result<(), AcmeError> {
        // Fully-qualified to call the inherent method, not this trait method of the same name.
        instant_acme::ChallengeHandle::set_ready(self).await?;
        Ok(())
    }
}

/// Wait for the presented challenge to propagate, **then** tell the CA it is ready to validate.
///
/// The wait MUST precede `ready.set_ready()`: telling the CA to validate before the `_acme-challenge`
/// TXT is live is exactly what made DNS-01 orders go `invalid` and certs crash-loop. Keeping the two
/// steps in one function (over the [`SetChallengeReady`] seam) makes that ordering a single unit the
/// tests pin — deleting the [`wait_for_propagation`] call here turns the ordering test red.
async fn confirm_then_set_ready(
    solver: &dyn ChallengeSolver,
    identifier: &str,
    request: &CertRequest,
    ready: &mut dyn SetChallengeReady,
) -> Result<(), AcmeError> {
    wait_for_propagation(solver, identifier, request).await;
    ready.set_ready().await
}

/// Poll [`ChallengeSolver::poll_presented`] until the challenge for `identifier` is observable, or the
/// `request.propagation_wait` deadline elapses.
///
/// - **Happy path:** returns as soon as the record is seen live (for DNS-01, the `_acme-challenge` TXT
///   with the expected value resolves) — no fixed sleep.
/// - **No resolver wired** ([`Propagation::Unchecked`]): falls back to a single blind sleep of the
///   whole `propagation_wait` budget (the pre-fix behaviour), then proceeds.
/// - **Deadline without visibility:** logs a `warn!` and returns anyway rather than hard-failing — the
///   caller proceeds to `set_challenge_ready` and the CA retries validation on its own, so a
///   slow-propagating zone still gets a cert instead of crashing issuance.
///
/// Never returns an error: a resolver hiccup is treated as "not visible yet" and retried within the
/// deadline. Designed to be driven under `tokio::time` (the tests run it with a paused clock).
pub async fn wait_for_propagation(
    solver: &dyn ChallengeSolver,
    identifier: &str,
    request: &CertRequest,
) {
    // Clamp the interval so a zero/tiny value can't turn the loop into a busy-spin to the deadline.
    let interval = request
        .propagation_poll_interval
        .max(Duration::from_millis(50));
    let deadline = tokio::time::Instant::now() + request.propagation_wait;
    let mut polls: u32 = 0;
    loop {
        polls += 1;
        match solver.poll_presented(identifier).await {
            Ok(Propagation::Ready) => {
                if polls > 1 {
                    tracing::debug!(
                        target: "boatramp::acme", %identifier, polls,
                        "challenge record observed as propagated; telling the CA to validate"
                    );
                }
                return;
            }
            Ok(Propagation::Unchecked) => {
                tracing::debug!(
                    target: "boatramp::acme", %identifier,
                    wait_secs = request.propagation_wait.as_secs(),
                    "no propagation resolver wired; blind-waiting the propagation budget before validating"
                );
                tokio::time::sleep(request.propagation_wait).await;
                return;
            }
            Ok(Propagation::Pending) => {}
            Err(err) => {
                tracing::debug!(
                    target: "boatramp::acme", %identifier, %err,
                    "propagation poll errored; retrying within the deadline"
                );
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            tracing::warn!(
                target: "boatramp::acme", %identifier, polls,
                wait_secs = request.propagation_wait.as_secs(),
                "DNS-01 challenge record not observed within the propagation wait; telling the CA to \
                 validate anyway (it will retry — a cert may still issue once the record is live)"
            );
            return;
        }
        tokio::time::sleep(interval.min(deadline - now)).await;
    }
}

/// Is `record`'s TXT value currently visible at its name, per `resolver`? The core DNS-01 readiness
/// predicate: [`Propagation::Ready`] once the **exact** expected value appears in the resolved RRset,
/// else [`Propagation::Pending`]. A unique-per-challenge value means a stale or unrelated TXT never
/// reads as ready (no false positive), so a positive here is real evidence the authoritative servers
/// are serving this challenge. A resolver error propagates (the caller treats it as "keep waiting").
async fn txt_record_visible(
    resolver: &dyn TxtResolver,
    record: &DnsRecord,
) -> Result<Propagation, AcmeError> {
    let values = resolver.lookup_txt(&record.name).await?;
    Ok(if values.iter().any(|v| v == &record.value) {
        Propagation::Ready
    } else {
        Propagation::Pending
    })
}

/// The default [`TxtResolver`] for the DNS-01 propagation pre-check: a hickory recursive resolver.
///
/// **Why recursive, not authoritative-NS-direct (lego's robustest mode):** a *positive* observation
/// here — the unique-per-challenge TXT value resolving — is already proof that the authoritative
/// servers are serving the record (a recursive resolver only returns what some authority answered,
/// and a stale/unrelated value can't match the unique challenge value), which is exactly the
/// precondition the CA's own (recursive, multi-vantage) validator needs. The only thing a direct
/// authoritative-NS query would buy is shaving a recursive resolver's *negative*-cache lag — and a
/// false negative here merely costs extra wait up to `propagation_wait`, after which the driver
/// proceeds anyway and the CA retries. That marginal latency gain is not worth the complexity (SOA/NS
/// walking, per-NS querying, quorum) or the extra SSRF surface of dialing arbitrary nameserver IPs.
/// We cap the resolver's own negative cache (below) so a just-written record is re-queried quickly.
#[derive(Clone)]
pub struct HickoryTxtResolver {
    inner: hickory_resolver::TokioResolver,
}

impl HickoryTxtResolver {
    /// Build a resolver from the host's system configuration (`/etc/resolv.conf` etc.), with the
    /// negative cache capped so a freshly-written `_acme-challenge` TXT that was `NXDOMAIN`/empty
    /// moments ago is re-queried within seconds (the "publish then observe" loop).
    ///
    /// `BOATRAMP_ACME_PROPAGATION_RESOLVER` overrides the system resolver with an explicit,
    /// comma-separated list of `ip[:port]` recursive resolvers (UDP) — for a container whose
    /// `/etc/resolv.conf` points at an aggressively-negative-caching resolver, or to pin a known-good
    /// public resolver. Any entry that fails to parse is ignored; an all-unparseable value falls back
    /// to the system config.
    pub fn system() -> Result<Self, AcmeError> {
        use hickory_resolver::Resolver;
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;

        if let Ok(spec) = std::env::var("BOATRAMP_ACME_PROPAGATION_RESOLVER") {
            let servers: Vec<std::net::SocketAddr> = spec
                .split(',')
                .filter_map(|s| parse_resolver_addr(s.trim()))
                .collect();
            if !servers.is_empty() {
                return Self::with_nameservers(&servers);
            }
        }

        let build = |builder: hickory_resolver::ResolverBuilder<TokioRuntimeProvider>| {
            builder.with_options(Self::opts()).build()
        };
        let inner = hickory_resolver::TokioResolver::builder_tokio()
            .and_then(build)
            .or_else(|_| {
                // No usable system config ⇒ the library default (public roots): still a recursive
                // resolver, so the pre-check keeps working on a host without `/etc/resolv.conf`.
                build(Resolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioRuntimeProvider::default(),
                ))
            })
            .map_err(|e| {
                AcmeError::Dns(DnsError::Config(format!("building the DNS resolver: {e}")))
            })?;
        Ok(Self { inner })
    }

    /// Build a resolver that queries exactly `nameservers` over UDP (used to point the pre-check at a
    /// specific server — e.g. a test's mock DNS, or an operator-pinned recursive resolver). A port in
    /// the `SocketAddr` overrides the default 53.
    pub fn with_nameservers(nameservers: &[std::net::SocketAddr]) -> Result<Self, AcmeError> {
        use hickory_resolver::Resolver;
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;

        let servers: Vec<NameServerConfig> = nameservers
            .iter()
            .map(|addr| {
                let mut ns = NameServerConfig::udp(addr.ip());
                for conn in &mut ns.connections {
                    conn.port = addr.port();
                }
                ns
            })
            .collect();
        let config = ResolverConfig::from_parts(None, Vec::new(), servers);
        let inner = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(Self::opts())
            .build()
            .map_err(|e| {
                AcmeError::Dns(DnsError::Config(format!("building the DNS resolver: {e}")))
            })?;
        Ok(Self { inner })
    }

    /// Resolver options tuned for a "just published, poll until live" lookup: a small negative-cache
    /// floor so a record that was absent moments ago is re-queried quickly, and a modest positive cap.
    fn opts() -> hickory_resolver::config::ResolverOpts {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.negative_min_ttl = Some(Duration::from_secs(1));
        opts.negative_max_ttl = Some(Duration::from_secs(5));
        opts.positive_max_ttl = Some(Duration::from_secs(30));
        opts
    }
}

/// Parse one `BOATRAMP_ACME_PROPAGATION_RESOLVER` entry: `ip:port` (an explicit `SocketAddr`) or a
/// bare `ip` (default DNS port 53). Returns `None` for anything unparseable.
fn parse_resolver_addr(s: &str) -> Option<std::net::SocketAddr> {
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Some(addr);
    }
    s.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| std::net::SocketAddr::new(ip, 53))
}

#[async_trait]
impl TxtResolver for HickoryTxtResolver {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        use hickory_resolver::proto::rr::RData;
        let lookup = match self.inner.txt_lookup(name).await {
            Ok(lookup) => lookup,
            // "No such record" is not an error for a propagation poll — it just means "not live yet".
            Err(err) if err.is_no_records_found() => return Ok(Vec::new()),
            Err(err) => return Err(DnsError::Backend(err.to_string())),
        };
        // A single TXT record may arrive as several ≤255-byte chunks; join them (the challenge value
        // is one unbroken base64url string). Mirrors the server's record-verify reconstruction.
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }
}

/// Run the full **DNS-01** issuance for `request.domains`, solving challenges via `provider`. A
/// back-compatible convenience over [`obtain_certificate_with`]: it creates a throwaway account and a
/// [`Dns01Solver`]. (On-demand issuance should instead reuse one account via
/// [`create_account`]/[`restore_account`] + [`obtain_certificate_with`].)
pub async fn obtain_certificate(
    request: &CertRequest,
    provider: &dyn DnsProvider,
) -> Result<IssuedCert, AcmeError> {
    let (account, _credentials) = create_account(
        &request.directory_url,
        request.contact_email.as_deref(),
        request.extra_root_ca.as_deref(),
    )
    .await?;
    // Wire the default system resolver for the propagation pre-check so the happy path waits until
    // the `_acme-challenge` TXT is actually live before validating (the fix). If the resolver can't be
    // built (e.g. no usable resolver config), fall back to the no-pre-check solver — issuance then
    // blind-waits `propagation_wait`, no worse than before.
    match HickoryTxtResolver::system() {
        Ok(resolver) => {
            let solver = Dns01Solver::with_resolver(provider, request.dns_ttl, &resolver);
            obtain_certificate_with(&account, request, &solver).await
        }
        Err(err) => {
            tracing::warn!(
                target: "boatramp::acme", %err,
                "could not build the DNS-01 propagation resolver; proceeding without a readiness \
                 pre-check (blind propagation wait)"
            );
            let solver = Dns01Solver::new(provider, request.dns_ttl);
            obtain_certificate_with(&account, request, &solver).await
        }
    }
}

/// A [`ChallengeSolver`] that proves DNS-01 by writing the `_acme-challenge` TXT via a
/// [`DnsProvider`]. Remembers what it wrote so `cleanup` removes exactly that record — and so the
/// propagation pre-check ([`poll_presented`](ChallengeSolver::poll_presented)) can confirm *that*
/// record is live before the driver tells the CA to validate.
pub struct Dns01Solver<'a> {
    provider: &'a dyn DnsProvider,
    ttl: u32,
    /// Optional resolver for the propagation pre-check. `Some` ⇒ the driver waits until the written
    /// TXT actually resolves before validating (the fix); `None` ⇒ no pre-check (the driver blind-waits
    /// `propagation_wait`, the pre-fix behaviour). Prefer [`with_resolver`](Self::with_resolver) on any
    /// real issuance path.
    resolver: Option<&'a dyn TxtResolver>,
    written: Mutex<HashMap<String, DnsRecord>>,
}

impl<'a> Dns01Solver<'a> {
    /// A solver with **no** propagation pre-check: it writes the TXT and the driver tells the CA to
    /// validate after a blind `propagation_wait` (the pre-fix behaviour). Kept for back-compat and for
    /// callers that genuinely have no resolver; prefer [`with_resolver`](Self::with_resolver).
    pub fn new(provider: &'a dyn DnsProvider, ttl: u32) -> Self {
        Self {
            provider,
            ttl,
            resolver: None,
            written: Mutex::new(HashMap::new()),
        }
    }

    /// A solver that confirms the `_acme-challenge` TXT is **live** (via `resolver`) before the driver
    /// tells the CA to validate — the fix for the DNS-01 propagation race. The happy path returns as
    /// soon as the record resolves; a slow zone still proceeds after `propagation_wait` (the CA
    /// retries). See [`wait_for_propagation`].
    pub fn with_resolver(
        provider: &'a dyn DnsProvider,
        ttl: u32,
        resolver: &'a dyn TxtResolver,
    ) -> Self {
        Self {
            provider,
            ttl,
            resolver: Some(resolver),
            written: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ChallengeSolver for Dns01Solver<'_> {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Dns01
    }
    async fn present(
        &self,
        identifier: &str,
        key_auth: &KeyAuthorization,
    ) -> Result<(), AcmeError> {
        let record = DnsRecord {
            kind: RecordKind::Txt,
            name: acme_challenge_name(identifier),
            value: key_auth.dns_value(),
            ttl: self.ttl,
        };
        self.provider.upsert(&record).await?;
        if let Ok(mut w) = self.written.lock() {
            w.insert(identifier.to_string(), record);
        }
        Ok(())
    }
    async fn poll_presented(&self, identifier: &str) -> Result<Propagation, AcmeError> {
        // No resolver wired ⇒ no pre-check: the driver blind-waits `propagation_wait` (pre-fix).
        let Some(resolver) = self.resolver else {
            return Ok(Propagation::Unchecked);
        };
        // Check exactly what we wrote for this identifier (name + unique value) — not a freshly
        // recomputed value — so the predicate matches the record whose cleanup we also track.
        let record = self
            .written
            .lock()
            .ok()
            .and_then(|w| w.get(identifier).cloned());
        match record {
            Some(record) => txt_record_visible(resolver, &record).await,
            // `present` has not run for this identifier yet (out-of-order call): nothing to confirm.
            None => Ok(Propagation::Pending),
        }
    }
    async fn cleanup(&self, identifier: &str) -> Result<(), AcmeError> {
        let record = self
            .written
            .lock()
            .ok()
            .and_then(|mut w| w.remove(identifier));
        if let Some(record) = record {
            self.provider.delete(&record).await?;
        }
        Ok(())
    }
}

/// Build the ephemeral self-signed certificate that answers a **TLS-ALPN-01** challenge for `identifier`
/// (RFC 8737): a cert whose SAN is `identifier` carrying a **critical** `id-pe-acmeIdentifier`
/// extension (OID 1.3.6.1.5.5.7.1.31) whose value is the DER OCTET STRING of `SHA-256(key_auth)`. The
/// caller installs it in the SNI resolver's challenge slot and serves it on the `acme-tls/1` ALPN
/// handshake; it is never a real serving cert. Returns `(cert_pem, key_pem)`.
pub fn tls_alpn01_challenge_cert(
    identifier: &str,
    key_auth: &KeyAuthorization,
) -> Result<(String, String), AcmeError> {
    tls_alpn01_cert_from_digest(identifier, key_auth.digest().as_ref())
}

/// The `id-pe-acmeIdentifier` OID 1.3.6.1.5.5.7.1.31, as rcgen's arc form.
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// DER-encode the extension value for the acmeIdentifier extension: an OCTET STRING wrapping the
/// 32-byte SHA-256 `digest` (RFC 8737 §3). Pure + unit-tested.
fn acme_identifier_ext_value(digest: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + digest.len());
    v.push(0x04); // OCTET STRING
    v.push(digest.len() as u8); // 32 bytes fits a single length byte
    v.extend_from_slice(digest);
    v
}

/// Inner of [`tls_alpn01_challenge_cert`], taking the raw key-authorization digest (so it is testable
/// without an `instant_acme::Order`).
fn tls_alpn01_cert_from_digest(
    identifier: &str,
    digest: &[u8],
) -> Result<(String, String), AcmeError> {
    let mut ext = rcgen::CustomExtension::from_oid_content(
        ACME_IDENTIFIER_OID,
        acme_identifier_ext_value(digest),
    );
    ext.set_criticality(true);
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![identifier.to_string()])?;
    params.custom_extensions.push(ext);
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Create a fresh ACME account at `directory_url`. The returned [`AccountCredentials`] is opaque but
/// serde-serializable — the caller persists it (sealed) and reuses the account via [`restore_account`]
/// across restarts/replicas, so the CA's `newAccount` rate limit is hit once, not per order.
pub async fn create_account(
    directory_url: &str,
    contact_email: Option<&str>,
    extra_root_ca: Option<&Path>,
) -> Result<(Account, AccountCredentials), AcmeError> {
    let contact: Vec<String> = contact_email
        .into_iter()
        .map(|email| format!("mailto:{email}"))
        .collect();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = account_builder(extra_root_ca)?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            None,
        )
        .await?;
    Ok((account, credentials))
}

/// Restore a previously-created account from stored [`AccountCredentials`] (no CA round trip for a
/// new account). The caller keeps its own serialized copy; this consumes the parsed credentials.
/// `extra_root_ca` configures the restored account's HTTP client exactly as for [`create_account`]
/// (the restored account still talks to the directory for every order).
pub async fn restore_account(
    credentials: AccountCredentials,
    extra_root_ca: Option<&Path>,
) -> Result<Account, AcmeError> {
    Ok(account_builder(extra_root_ca)?
        .from_credentials(credentials)
        .await?)
}

/// Build the instant-acme account HTTP-client builder, trusting an extra root CA when one is given.
///
/// Since instant-acme 0.8 the default client (`Account::builder`) verifies the directory's TLS with
/// the platform verifier, which does **not** honour `SSL_CERT_FILE`; a test/staging CA with a
/// privately-issued directory cert must be trusted explicitly via `builder_with_root` (RFC: "your
/// ACME server uses a testing PKI"). Production (Let's Encrypt / Google Trust Services) passes
/// `None` and uses the platform's public roots.
fn account_builder(
    extra_root_ca: Option<&Path>,
) -> Result<instant_acme::AccountBuilder, AcmeError> {
    Ok(match extra_root_ca {
        Some(ca) => Account::builder_with_root(ca)?,
        None => Account::builder()?,
    })
}

/// Wait for the order to become ready, finalize it with a CSR, and fetch the
/// issued chain. Split out so the challenge-cleanup wrapper stays readable.
async fn drive_to_certificate(
    order: &mut instant_acme::Order,
    request: &CertRequest,
) -> Result<IssuedCert, AcmeError> {
    // No blind pre-poll sleep here any more: the propagation wait now happens BEFORE
    // `set_challenge_ready` (see `wait_for_propagation` / `confirm_then_set_ready`), where it belongs —
    // the CA is told to validate only once the record is live. By the time we get here the order is
    // already validating, so poll it straight to Ready (the backoff loop below absorbs the CA's own
    // validation latency up to `timeout`).
    let deadline = tokio::time::Instant::now() + request.timeout;
    let mut delay = Duration::from_secs(2);
    loop {
        let state = order.refresh().await?;
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => return Err(AcmeError::OrderInvalid),
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AcmeError::OrderReadyTimeout);
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(10));
    }

    // Generate the key + CSR for the requested SANs. We supply our own CSR (via `finalize_csr`)
    // rather than instant-acme's no-arg `finalize` — keeping the key material ours (rcgen,
    // never leaving this process) and the DN empty, exactly as before the 0.8 bump.
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(request.domains.clone())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;
    order.finalize_csr(csr.der()).await?;

    // Poll for the issued certificate chain.
    let deadline = tokio::time::Instant::now() + request.timeout;
    let certificate_pem = loop {
        if let Some(pem) = order.certificate().await? {
            break pem;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AcmeError::CertificateTimeout);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    Ok(IssuedCert {
        certificate_pem,
        private_key_pem: key_pair.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_identifier_ext_value_wraps_digest_as_octet_string() {
        let digest = [0xabu8; 32];
        let v = acme_identifier_ext_value(&digest);
        assert_eq!(v[0], 0x04, "OCTET STRING tag");
        assert_eq!(v[1], 32, "length byte");
        assert_eq!(&v[2..], &digest[..], "the 32-byte digest follows");
        assert_eq!(v.len(), 34);
    }

    #[test]
    fn tls_alpn01_cert_is_pem_and_digest_bound() {
        let (cert_a, key_a) =
            tls_alpn01_cert_from_digest("mail.example.com", &[0x11u8; 32]).unwrap();
        let (cert_b, _key_b) =
            tls_alpn01_cert_from_digest("mail.example.com", &[0x22u8; 32]).unwrap();
        assert!(cert_a.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_a.contains("PRIVATE KEY"));
        // The challenge cert is bound to the key-authorization digest — a different digest ⇒ a
        // different cert (the acmeIdentifier extension differs).
        assert_ne!(cert_a, cert_b, "the cert must incorporate the digest");
    }

    /// A real `*.deploy.test` **wildcard** authorization as emitted by Pebble **2.10.1** (captured
    /// live from the `pebble_dns01` integration test). It carries THREE challenges — and the
    /// `dns-persist-01` one is **tokenless** (Pebble marshals `token` with `omitempty` and sets it
    /// to `""`, so the field is absent on the wire). Let's Encrypt and Google Trust Services now
    /// emit the same tokenless `dns-persist-01` in production.
    ///
    /// This is the exact JSON that instant-acme **< 0.8.5** could not deserialize: its
    /// `Challenge.token` was a *required* field, so the token-less entry failed with
    /// `missing field \`token\``, which aborted the whole authorization — dropping the `dns-01`
    /// challenge boatramp selects and crash-looping DNS-01 issuance against the real CA. 0.8.5 added
    /// `#[serde(default)]` on `Challenge.token`, so the authorization now deserializes and `dns-01`
    /// is still selectable. This unit test is the pebble-free regression guard for that seam.
    #[cfg(feature = "acme")]
    const PEBBLE_2_10_WILDCARD_AUTHZ_JSON: &str = r#"{
        "status": "pending",
        "identifier": { "type": "dns", "value": "deploy.test" },
        "challenges": [
            {
                "type": "dns-persist-01",
                "url": "https://localhost:14000/chalZ/y9-HB3ia7eNzLFc0lIV4UlQbiP6h9SHwLVh2RMTZw_U",
                "status": "pending",
                "accounturi": "https://localhost:14000/my-account/1",
                "issuer-domain-names": ["pebble.letsencrypt.org"]
            },
            {
                "type": "dns-account-01",
                "url": "https://localhost:14000/chalZ/UDJxA781Eee1pmUTwJO65ECWesCb0zl0m-12_zlZ-q4",
                "token": "Ezuat7vfdG5CG6BZME06wIye1G__6Gz1HnEkJHbbT6s",
                "status": "pending"
            },
            {
                "type": "dns-01",
                "url": "https://localhost:14000/chalZ/BVIs1EetnsQEpmaUS_01CibqlTJDSIDSt-LCZwJSp3c",
                "token": "NL-zq0hjJc_wvNMaIO2Wxfirhv8BgKEvO937tJYpyBk",
                "status": "pending"
            }
        ],
        "expires": "2026-11-05T00:00:00Z",
        "wildcard": true
    }"#;

    /// The bumped instant-acme (>= 0.8.5) deserializes the tokenless-challenge authorization and
    /// still exposes the `dns-01` challenge with its token. On instant-acme < 0.8.5 the same
    /// `from_str` returned `Err("missing field \`token\`")` (verified against the 0.7.2 types).
    #[cfg(feature = "acme")]
    #[test]
    fn tokenless_dns_persist_01_authorization_still_deserializes_and_keeps_dns01() {
        let authz: instant_acme::AuthorizationState =
            serde_json::from_str(PEBBLE_2_10_WILDCARD_AUTHZ_JSON)
                .expect("instant-acme >= 0.8.5 must tolerate a tokenless challenge in the authz");

        // The tokenless `dns-persist-01` is present and really has an empty token (the field that
        // the old client required) — so this fixture keeps exercising the exact regression.
        let persist = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Unknown("dns-persist-01".to_string()))
            .expect("the tokenless dns-persist-01 challenge must be present");
        assert!(
            persist.token.is_empty(),
            "dns-persist-01 is the tokenless challenge that broke the old required-token deser"
        );

        // The `dns-01` challenge boatramp selects survived and carries its token.
        let dns01 = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .expect("the dns-01 challenge must still be selectable");
        assert!(!dns01.token.is_empty(), "dns-01 must keep its real token");
    }

    #[test]
    fn dns01_solver_reports_its_type() {
        struct NoopProvider;
        #[async_trait]
        impl DnsProvider for NoopProvider {
            async fn upsert(&self, _r: &DnsRecord) -> Result<(), crate::dns::DnsError> {
                Ok(())
            }
            async fn delete(&self, _r: &DnsRecord) -> Result<(), crate::dns::DnsError> {
                Ok(())
            }
        }
        let p = NoopProvider;
        let solver = Dns01Solver::new(&p, 60);
        assert_eq!(solver.challenge_type(), ChallengeType::Dns01);
    }

    // ---- propagation wait (the DNS-01 validation-race fix) ------------------------------------
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A [`TxtResolver`] whose named TXT becomes visible only after `visible_after` lookups — a
    /// deterministic stand-in for "the record is written, now wait for it to propagate".
    struct FakeResolver {
        name: String,
        value: String,
        visible_after: usize,
        lookups: AtomicUsize,
    }
    #[async_trait]
    impl TxtResolver for FakeResolver {
        async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, crate::dns::DnsError> {
            let n = self.lookups.fetch_add(1, Ordering::SeqCst) + 1;
            if name == self.name && n >= self.visible_after {
                Ok(vec![self.value.clone()])
            } else {
                Ok(Vec::new()) // not visible yet
            }
        }
    }

    #[tokio::test]
    async fn txt_record_visible_waits_for_the_exact_value() {
        let record = DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.test".into(),
            value: "the-unique-challenge-value".into(),
            ttl: 1,
        };
        // Becomes visible on the 3rd lookup.
        let resolver = FakeResolver {
            name: record.name.clone(),
            value: record.value.clone(),
            visible_after: 3,
            lookups: AtomicUsize::new(0),
        };
        assert_eq!(
            txt_record_visible(&resolver, &record).await.unwrap(),
            Propagation::Pending
        );
        assert_eq!(
            txt_record_visible(&resolver, &record).await.unwrap(),
            Propagation::Pending
        );
        assert_eq!(
            txt_record_visible(&resolver, &record).await.unwrap(),
            Propagation::Ready,
            "ready once the expected value resolves"
        );

        // A DIFFERENT value present at the name must NOT read as ready (unique-per-challenge value ⇒
        // no false positive from a stale/unrelated TXT).
        struct WrongValue;
        #[async_trait]
        impl TxtResolver for WrongValue {
            async fn lookup_txt(&self, _n: &str) -> Result<Vec<String>, crate::dns::DnsError> {
                Ok(vec!["some-other-challenge".into()])
            }
        }
        assert_eq!(
            txt_record_visible(&WrongValue, &record).await.unwrap(),
            Propagation::Pending,
            "a non-matching TXT value is not readiness"
        );
    }

    /// A [`ChallengeSolver`] whose `poll_presented` reports `Pending` until the `visible_after`-th
    /// poll, at which point it flips a shared `visible` flag true and reports `Ready`. Counts polls so
    /// the test can prove the wait really looped.
    struct FakeSolver {
        visible: Arc<AtomicBool>,
        visible_after: u32,
        polls: Arc<AtomicUsize>,
        never: bool,
    }
    #[async_trait]
    impl ChallengeSolver for FakeSolver {
        fn challenge_type(&self) -> ChallengeType {
            ChallengeType::Dns01
        }
        async fn present(&self, _i: &str, _k: &KeyAuthorization) -> Result<(), AcmeError> {
            Ok(())
        }
        async fn poll_presented(&self, _identifier: &str) -> Result<Propagation, AcmeError> {
            let n = (self.polls.fetch_add(1, Ordering::SeqCst) + 1) as u32;
            if self.never {
                return Ok(Propagation::Pending);
            }
            if n >= self.visible_after {
                self.visible.store(true, Ordering::SeqCst);
                Ok(Propagation::Ready)
            } else {
                Ok(Propagation::Pending)
            }
        }
        async fn cleanup(&self, _i: &str) -> Result<(), AcmeError> {
            Ok(())
        }
    }

    /// Records, at the moment `set_ready` fires, whether the record was already visible — so the test
    /// can assert the CA was told to validate ONLY after propagation was observed.
    struct RecordingReady {
        visible: Arc<AtomicBool>,
        saw_visible_at_ready: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl SetChallengeReady for RecordingReady {
        async fn set_ready(&mut self) -> Result<(), AcmeError> {
            self.saw_visible_at_ready
                .store(self.visible.load(Ordering::SeqCst), Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn req(wait: Duration, interval: Duration) -> CertRequest {
        CertRequest {
            propagation_wait: wait,
            propagation_poll_interval: interval,
            ..CertRequest::default()
        }
    }

    /// THE ordering gate (mutation-sensitive): `set_challenge_ready` must not fire until the readiness
    /// poll has observed the record live. If a reviewer deletes the `wait_for_propagation` call inside
    /// `confirm_then_set_ready`, `set_ready` fires at poll 0 with `visible == false` and this goes RED.
    #[tokio::test(start_paused = true)]
    async fn set_ready_waits_until_the_record_is_observed() {
        let visible = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let solver = FakeSolver {
            visible: Arc::clone(&visible),
            visible_after: 4, // visible on the 4th poll
            polls: Arc::clone(&polls),
            never: false,
        };
        let saw_visible = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ready = RecordingReady {
            visible: Arc::clone(&visible),
            saw_visible_at_ready: Arc::clone(&saw_visible),
            calls: Arc::clone(&calls),
        };

        confirm_then_set_ready(
            &solver,
            "deploy.test",
            &req(Duration::from_secs(60), Duration::from_secs(1)),
            &mut ready,
        )
        .await
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "set_ready fires exactly once"
        );
        assert!(
            saw_visible.load(Ordering::SeqCst),
            "set_ready must fire ONLY after the readiness poll observed the record live"
        );
        assert!(
            polls.load(Ordering::SeqCst) >= 4,
            "the wait really polled until visible (got {})",
            polls.load(Ordering::SeqCst)
        );
    }

    /// The deadline fallback: a record that never becomes visible still proceeds to `set_ready` (the
    /// CA retries) rather than hanging or erroring — but it is NOT reported as observed-visible.
    #[tokio::test(start_paused = true)]
    async fn set_ready_proceeds_after_deadline_without_visibility() {
        let visible = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let solver = FakeSolver {
            visible: Arc::clone(&visible),
            visible_after: u32::MAX,
            polls: Arc::clone(&polls),
            never: true,
        };
        let saw_visible = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ready = RecordingReady {
            visible: Arc::clone(&visible),
            saw_visible_at_ready: Arc::clone(&saw_visible),
            calls: Arc::clone(&calls),
        };

        confirm_then_set_ready(
            &solver,
            "deploy.test",
            &req(Duration::from_millis(500), Duration::from_millis(100)),
            &mut ready,
        )
        .await
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "proceeds to set_ready once"
        );
        assert!(
            !saw_visible.load(Ordering::SeqCst),
            "the record was never visible, so set_ready must NOT claim it was"
        );
        assert!(
            polls.load(Ordering::SeqCst) >= 2,
            "it polled repeatedly before giving up (got {})",
            polls.load(Ordering::SeqCst)
        );
    }

    /// With no resolver wired, the DNS-01 solver reports `Unchecked` so the driver blind-waits the
    /// budget (pre-fix behaviour) instead of validating instantly.
    #[tokio::test]
    async fn dns01_solver_without_resolver_is_unchecked() {
        struct NoopProvider;
        #[async_trait]
        impl DnsProvider for NoopProvider {
            async fn upsert(&self, _r: &DnsRecord) -> Result<(), crate::dns::DnsError> {
                Ok(())
            }
            async fn delete(&self, _r: &DnsRecord) -> Result<(), crate::dns::DnsError> {
                Ok(())
            }
        }
        let p = NoopProvider;
        let solver = Dns01Solver::new(&p, 60);
        assert_eq!(
            solver.poll_presented("deploy.test").await.unwrap(),
            Propagation::Unchecked
        );
    }
}
