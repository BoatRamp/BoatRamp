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

// The default DNS-01 propagation pre-check resolver: query the zone's AUTHORITATIVE nameservers
// directly (the lego/certbot approach), so a recursive resolver's negative cache can't make a
// freshly-written `_acme-challenge` TXT read as "not yet live". Falls forward to the recursive
// [`HickoryTxtResolver`] (and then to a blind wait) so issuance is never worse than before.
pub use crate::authoritative::AuthoritativeTxtResolver;

/// A failure during ACME DNS-01 issuance.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// An error from the ACME protocol client.
    ///
    /// A `rateLimited` problem is classified out of this variant into the typed
    /// [`AcmeError::RateLimited`] (see the `From<instant_acme::Error>` impl) so a
    /// caller can back off correctly rather than string-matching an opaque error.
    #[error("ACME protocol error: {0}")]
    Acme(instant_acme::Error),
    /// The CA refused the request with an ACME `rateLimited` problem (RFC 8555
    /// §6.7, `urn:ietf:params:acme:error:rateLimited`, HTTP 429) — e.g. the
    /// per-account `newOrder` limit, or the certificates-per-exact-name limit.
    ///
    /// `retry_after` is the backoff hint when the CA supplied one, parsed from
    /// the problem detail's `retry after <RFC 3339 timestamp | delay-seconds>`
    /// (the shape Let's Encrypt uses); `None` ⇒ the CA gave no parseable hint and
    /// the caller should apply its own backoff. `detail` is the CA's
    /// human-readable message (usually naming the exact limit and reset time).
    ///
    /// Surfaced as a distinct variant — rather than an opaque protocol error — so
    /// a caller can distinguish "slow down, retry later" from a hard failure and
    /// schedule a retry after `retry_after` instead of hammering the CA (which
    /// only deepens the limit).
    #[error("ACME rate limited by the CA (retry_after: {retry_after:?}): {detail:?}")]
    RateLimited {
        /// How long to wait before retrying, when the CA provided a parseable hint.
        retry_after: Option<Duration>,
        /// The CA's human-readable rate-limit message, verbatim.
        detail: Option<String>,
    },
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

impl From<instant_acme::Error> for AcmeError {
    /// Classify the `rateLimited` ACME problem (U21) out of the opaque protocol
    /// error into the typed [`AcmeError::RateLimited`], carrying the parsed
    /// `Retry-After` hint; every other error falls through to [`AcmeError::Acme`].
    /// This is the `#[from]` the `?` operator uses throughout the driver, so a
    /// rate-limit raised by `newAccount` / `newOrder` / `finalize` arrives typed.
    fn from(err: instant_acme::Error) -> Self {
        if let instant_acme::Error::Api(problem) = &err
            && is_acme_rate_limited(problem)
        {
            return Self::RateLimited {
                retry_after: parse_retry_after_from_detail(
                    problem.detail.as_deref().unwrap_or(""),
                    std::time::SystemTime::now(),
                ),
                detail: problem.detail.clone(),
            };
        }
        Self::Acme(err)
    }
}

/// Whether an ACME problem document is a `rateLimited` error. Matches the RFC 8555
/// §6.7 problem URN `urn:ietf:params:acme:error:rateLimited` by its `:ratelimited`
/// suffix (case-insensitively, so a CA that namespaces the URN prefix differently
/// still classifies), and also treats a bare HTTP 429 as rate limiting.
fn is_acme_rate_limited(problem: &instant_acme::Problem) -> bool {
    problem
        .r#type
        .as_deref()
        .is_some_and(|t| t.to_ascii_lowercase().ends_with(":ratelimited"))
        || problem.status == Some(429)
}

/// Best-effort extraction of a `Retry-After` backoff from an ACME problem detail.
///
/// instant-acme surfaces a `rateLimited` problem as its parsed JSON document and
/// does not expose the HTTP `Retry-After` header, but the CA's human-readable
/// `detail` carries the same information — Let's Encrypt writes
/// `… retry after 2026-11-22T00:00:00Z: see https://…`. We parse the token after
/// `retry after` as either RFC 3339 UTC (absolute ⇒ duration from `now`, clamped
/// to zero if already past) or a bare `delay-seconds` integer. `None` when the
/// detail carries no parseable hint (the caller then uses its own backoff).
fn parse_retry_after_from_detail(detail: &str, now: std::time::SystemTime) -> Option<Duration> {
    const MARKER: &str = "retry after ";
    let lower = detail.to_ascii_lowercase();
    let start = lower.find(MARKER)? + MARKER.len();
    // Take the first whitespace-delimited token after the marker (the detail
    // often continues with `: see https://…`), then trim trailing punctuation.
    let token = detail[start..]
        .split_whitespace()
        .next()?
        .trim_end_matches([':', ',', '.', ';', ')']);
    // `delay-seconds` form (RFC 9110): a bare count of seconds.
    if let Ok(secs) = token.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // Absolute RFC 3339 UTC timestamp form.
    let target = parse_rfc3339_utc(token)?;
    Some(target.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Parse an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) into a
/// [`SystemTime`](std::time::SystemTime), dependency-free (the crate pulls no
/// date library). Only the `Z` (UTC) zone is accepted — an ACME `Retry-After`
/// problem detail always uses it — and fractional seconds are discarded. `None`
/// for anything malformed, including an out-of-range (`>9999`) year, which would
/// otherwise overflow the civil-days arithmetic. Uses Howard Hinnant's
/// days-from-civil algorithm.
fn parse_rfc3339_utc(s: &str) -> Option<std::time::SystemTime> {
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix('z'))?;
    let (date, time) = s.split_once('T').or_else(|| s.split_once('t'))?;

    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() {
        return None;
    }

    // Drop any fractional-seconds suffix before splitting the clock.
    let mut t = time.split('.').next()?.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let min: i64 = t.next()?.parse().ok()?;
    let sec: i64 = t.next()?.parse().ok()?;
    if t.next().is_some() {
        return None;
    }

    // RFC 3339 `date-fullyear` is 4 digits, so a valid year is `0000..=9999`.
    // Bounding it here ALSO keeps the civil-days arithmetic below well inside
    // `i64` — an absurd year from a malicious/garbled CA problem detail (the only
    // reachable input, via `parse_retry_after_from_detail`) would otherwise
    // overflow `days * 86400` (a debug panic, a release wrap). Reject it instead.
    if !(0..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }

    // days-from-civil: days since 1970-01-01 (Howard Hinnant, public domain).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;

    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    if secs < 0 {
        return None;
    }
    Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Selects the rustls [`CryptoProvider`](rustls::crypto::CryptoProvider) that
/// backs the ACME client's TLS (U19) — see [`install_crypto_provider`].
#[derive(Clone, Debug)]
pub enum CryptoProviderChoice {
    /// Keep whatever process-default provider is already installed; install
    /// `aws-lc-rs` (instant-acme's own provider, always linked) only if none is.
    /// Never panics, never overrides a provider an embedder installed first —
    /// this is what the account builders install automatically, so a caller that
    /// does nothing is already protected from the ambiguous-default panic.
    Default,
    /// Force the `aws-lc-rs` provider.
    AwsLcRs,
    /// Force the `ring` provider.
    Ring,
    /// Install a caller-supplied provider (e.g. a FIPS-validated build).
    Custom(std::sync::Arc<rustls::crypto::CryptoProvider>),
}

/// The rustls [`CryptoProvider`](rustls::crypto::CryptoProvider) a
/// [`CryptoProviderChoice`] names (a fresh value, not the process default).
/// Pure; useful to a caller wiring the provider into its own rustls config.
pub fn resolve_crypto_provider(choice: &CryptoProviderChoice) -> rustls::crypto::CryptoProvider {
    match choice {
        CryptoProviderChoice::Default | CryptoProviderChoice::AwsLcRs => {
            rustls::crypto::aws_lc_rs::default_provider()
        }
        CryptoProviderChoice::Ring => rustls::crypto::ring::default_provider(),
        CryptoProviderChoice::Custom(provider) => (**provider).clone(),
    }
}

/// Install `choice` as the **process-wide default** rustls `CryptoProvider`,
/// unless one is already installed (U19).
///
/// WHY THIS EXISTS: rustls requires a process-default `CryptoProvider`. When a
/// build links BOTH the `ring` and `aws-lc-rs` providers — which happens as soon
/// as a few TLS-using crates share the process — rustls can no longer infer a
/// default, and the no-argument `rustls::ClientConfig::builder()` that
/// instant-acme's `Account::builder()` / `builder_with_root()` call **panics**
/// with *"Could not automatically determine the process-level CryptoProvider"*.
/// Installing a provider explicitly, before the first account is built,
/// side-steps that panic.
///
/// Returns `true` if THIS call installed the provider, `false` if a provider was
/// already installed (left untouched — the process default is one-shot, so an
/// explicit [`AwsLcRs`](CryptoProviderChoice::AwsLcRs) /
/// [`Ring`](CryptoProviderChoice::Ring) / [`Custom`](CryptoProviderChoice::Custom)
/// choice only takes effect when nothing has installed one yet). Idempotent and
/// safe to call from any number of issuance paths / threads.
///
/// The account builders ([`create_account`], [`restore_account`],
/// [`obtain_certificate`]) call this with [`CryptoProviderChoice::Default`]
/// automatically, so the panic is fixed even for a caller that never touches
/// this API. To force a specific provider instead, call this once at startup
/// with that choice **before** creating any account.
pub fn install_crypto_provider(choice: CryptoProviderChoice) -> bool {
    // Fast path: a default is already installed, so there is nothing to do (and
    // `install_default` below would just fail). Checked first so the common
    // auto-install from `account_builder` is a cheap no-op after the first call.
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return false;
    }
    match resolve_crypto_provider(&choice).install_default() {
        Ok(()) => true,
        // Another thread installed one between our check and this call: a default
        // now exists (the goal), so this is success for the no-panic guarantee.
        Err(_already_installed) => false,
    }
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
            // The happy path returns the instant the record is observed live at the zone's
            // authoritative nameservers (see `AuthoritativeTxtResolver`), so this is only an upper
            // bound for the slow/fallback case — a 45s budget absorbs a lagging zone without the CA
            // having to retry, while the authoritative pre-check still returns in a poll or two.
            propagation_wait: Duration::from_secs(45),
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
    let want = record.kind.flat_value();
    Ok(if values.iter().any(|v| v == &want) {
        Propagation::Ready
    } else {
        Propagation::Pending
    })
}

/// A hickory **recursive** [`TxtResolver`] — the system resolver (`/etc/resolv.conf`), or the
/// `BOATRAMP_ACME_PROPAGATION_RESOLVER` override.
///
/// This is the **fallback** tier of the DNS-01 propagation pre-check: the default is now
/// [`AuthoritativeTxtResolver`], which queries the zone's authoritative nameservers directly so a
/// recursive resolver's *negative* cache can't make a just-written `_acme-challenge` TXT keep reading
/// as "not live" (the field-reported Cloudflare slow-happy-path). When authoritative discovery can't
/// run (no SOA/NS resolvable, a NS unreachable), the authoritative resolver falls forward to **this**
/// recursive resolver, and if even this can't be built the driver blind-waits — so issuance is never
/// worse than before the authoritative path existed.
///
/// A *positive* observation here is still real evidence: the unique-per-challenge TXT value resolving
/// means some authority served it (a stale/unrelated value can't match the unique challenge value),
/// which is the precondition the CA's own recursive validator needs. We cap this resolver's negative
/// cache ([`resolver_opts`]) so a just-written record is re-queried within seconds.
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
        Ok(Self {
            inner: build_system_resolver()?,
        })
    }

    /// Build a resolver that queries exactly `nameservers` over UDP (used to point the pre-check at a
    /// specific server — e.g. a test's mock DNS, an operator-pinned recursive resolver, or a zone's
    /// **authoritative** nameservers so the [`AuthoritativeTxtResolver`] bypasses a recursive
    /// resolver's negative cache). A port in the `SocketAddr` overrides the default 53.
    pub fn with_nameservers(nameservers: &[std::net::SocketAddr]) -> Result<Self, AcmeError> {
        Ok(Self {
            inner: build_resolver_at(nameservers)?,
        })
    }
}

/// Resolver options tuned for a "just published, poll until live" lookup (U22):
/// the resolver cache is **disabled** so a freshly-written `_acme-challenge` TXT
/// is never masked by a stale cached answer.
///
/// The whole purpose of the DNS-01 self-check is to observe records that were
/// published *seconds* ago, so any caching is actively harmful: a negative answer
/// cached while the record was still absent would keep the pre-check reading "not
/// live" past the point the authoritative servers started serving it, burning the
/// propagation budget. Setting `cache_size = 0` makes every lookup hit the wire
/// and honor the authoritative TTL fresh (strictly stronger than merely capping
/// the negative TTL, which the long-lived fallback resolver would otherwise hold
/// for several seconds). The TTL caps below are kept as defense-in-depth for any
/// hickory layer that consults them independently of the response cache.
pub(crate) fn resolver_opts() -> hickory_resolver::config::ResolverOpts {
    let mut opts = hickory_resolver::config::ResolverOpts::default();
    opts.cache_size = 0;
    opts.negative_min_ttl = Some(Duration::from_secs(1));
    opts.negative_max_ttl = Some(Duration::from_secs(5));
    opts.positive_max_ttl = Some(Duration::from_secs(30));
    opts
}

/// Build the shared `TokioResolver` behind [`HickoryTxtResolver::system`] — the host's recursive
/// resolver (`/etc/resolv.conf` etc.), honouring the `BOATRAMP_ACME_PROPAGATION_RESOLVER` override,
/// with a library-default-config fallback so the pre-check still works on a host without a usable
/// resolver config. Shared so the [`AuthoritativeTxtResolver`]'s zone/NS **discovery** queries run
/// against the same recursive resolver as the fallback TXT lookups.
pub(crate) fn build_system_resolver() -> Result<hickory_resolver::TokioResolver, AcmeError> {
    use hickory_resolver::Resolver;
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    if let Ok(spec) = std::env::var("BOATRAMP_ACME_PROPAGATION_RESOLVER") {
        let servers: Vec<std::net::SocketAddr> = spec
            .split(',')
            .filter_map(|s| parse_resolver_addr(s.trim()))
            .collect();
        if !servers.is_empty() {
            return build_resolver_at(&servers);
        }
    }

    let build = |builder: hickory_resolver::ResolverBuilder<TokioRuntimeProvider>| {
        builder.with_options(resolver_opts()).build()
    };
    hickory_resolver::TokioResolver::builder_tokio()
        .and_then(build)
        .or_else(|_| {
            // No usable system config ⇒ the library default (public roots): still a recursive
            // resolver, so the pre-check keeps working on a host without `/etc/resolv.conf`.
            build(Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            ))
        })
        .map_err(|e| AcmeError::Dns(DnsError::Config(format!("building the DNS resolver: {e}"))))
}

/// Build a `TokioResolver` that queries exactly `nameservers` over UDP (a specific recursive resolver,
/// or a zone's authoritative nameservers). A port in the `SocketAddr` overrides the default 53.
pub(crate) fn build_resolver_at(
    nameservers: &[std::net::SocketAddr],
) -> Result<hickory_resolver::TokioResolver, AcmeError> {
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
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(resolver_opts())
        .build()
        .map_err(|e| AcmeError::Dns(DnsError::Config(format!("building the DNS resolver: {e}"))))
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
    // Wire the authoritative-NS propagation pre-check so the happy path waits until the
    // `_acme-challenge` TXT is actually live at the zone's own nameservers before validating (the
    // fix). It falls forward internally to the recursive resolver when authoritative discovery can't
    // run. Only if NO recursive resolver can be built at all (no usable resolver config) do we fall
    // back to the no-pre-check solver — issuance then blind-waits `propagation_wait`, no worse than
    // before.
    match AuthoritativeTxtResolver::system() {
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
        // `KeyAuthorization` is opaque; the aggregation logic lives in
        // `present_value` (which takes the raw TXT value) so it is unit-testable
        // without a live `instant_acme::Order`.
        self.present_value(identifier, key_auth.dns_value()).await
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
        let Some(record) = record else {
            return Ok(());
        };
        // After removing this identifier's value, is another authorization still
        // using the same challenge name (the wildcard+apex case, U20)? If so,
        // re-publish the reduced set so only THIS value is withdrawn; otherwise it
        // was the last value and the record is deleted outright (by content, as
        // before).
        let remaining = self.values_at(&record.name);
        if remaining.is_empty() {
            self.provider.delete(&record).await?;
        } else {
            self.provider
                .upsert_txt_set(&record.name, &remaining, self.ttl)
                .await?;
        }
        Ok(())
    }
}

impl Dns01Solver<'_> {
    /// The testable core of [`present`](ChallengeSolver::present): remember THIS
    /// identifier's record, then publish the FULL coexisting TXT set at its
    /// challenge name. A wildcard (`*.x`) and the apex (`x`) both validate at
    /// `_acme-challenge.x` with DIFFERENT values; writing one with the plain
    /// replace-`upsert` drops the other and races it to `invalid` (U20).
    /// Aggregating by name and publishing the whole set via
    /// [`DnsProvider::upsert_txt_set`] keeps every presented value live together.
    /// The lock is released before the await.
    async fn present_value(&self, identifier: &str, value: String) -> Result<(), AcmeError> {
        let record = DnsRecord {
            kind: RecordKind::Txt(vec![value]),
            name: acme_challenge_name(identifier),
            ttl: self.ttl,
        };
        if let Ok(mut w) = self.written.lock() {
            w.insert(identifier.to_string(), record.clone());
        }
        let values = self.values_at(&record.name);
        self.provider
            .upsert_txt_set(&record.name, &values, self.ttl)
            .await?;
        Ok(())
    }

    /// The distinct TXT values currently presented at challenge `name`, across all
    /// identifiers (the coexisting DNS-01 challenge set — U20). Sorted + deduped so
    /// the published set is deterministic. The lock is never held across an await.
    fn values_at(&self, name: &str) -> Vec<String> {
        let mut values: Vec<String> = self
            .written
            .lock()
            .ok()
            .map(|w| {
                w.values()
                    .filter(|r| r.name == name)
                    .map(|r| r.kind.flat_value())
                    .collect()
            })
            .unwrap_or_default();
        values.sort();
        values.dedup();
        values
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
    // U19: ensure a rustls CryptoProvider is installed before instant-acme's
    // `ClientConfig::builder()` runs, so a build that links both `ring` and
    // `aws-lc-rs` cannot panic on an ambiguous process default. This only
    // installs `aws-lc-rs` as a fallback when nothing is installed yet — an
    // embedder that wants a specific provider calls `install_crypto_provider`
    // with its choice first, and this then leaves that provider untouched.
    install_crypto_provider(CryptoProviderChoice::Default);
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
            kind: RecordKind::Txt(vec!["the-unique-challenge-value".into()]),
            name: "_acme-challenge.deploy.test".into(),
            ttl: 1,
        };
        // Becomes visible on the 3rd lookup.
        let resolver = FakeResolver {
            name: record.name.clone(),
            value: record.kind.flat_value(),
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

    // ---- U20: multi-TXT challenge set (wildcard + apex share a name) -----------

    /// A provider that records the LAST TXT set published at each name (via
    /// `upsert_txt_set`) and the names torn down via `delete`, so a test can prove
    /// the solver keeps both a wildcard's and the apex's values live together.
    #[derive(Default)]
    struct CapturingProvider {
        sets: std::sync::Mutex<HashMap<String, Vec<String>>>,
        deletes: std::sync::Mutex<Vec<String>>,
    }
    #[async_trait]
    impl DnsProvider for CapturingProvider {
        async fn upsert(&self, r: &DnsRecord) -> Result<(), crate::dns::DnsError> {
            // A direct single-value upsert reduces to a one-element set.
            self.sets
                .lock()
                .unwrap()
                .insert(r.name.clone(), vec![r.kind.flat_value()]);
            Ok(())
        }
        async fn delete(&self, r: &DnsRecord) -> Result<(), crate::dns::DnsError> {
            self.sets.lock().unwrap().remove(&r.name);
            self.deletes.lock().unwrap().push(r.name.clone());
            Ok(())
        }
        async fn upsert_txt_set(
            &self,
            name: &str,
            values: &[String],
            _ttl: u32,
        ) -> Result<(), crate::dns::DnsError> {
            self.sets
                .lock()
                .unwrap()
                .insert(name.to_string(), values.to_vec());
            Ok(())
        }
    }
    impl CapturingProvider {
        fn set_at(&self, name: &str) -> Option<Vec<String>> {
            self.sets.lock().unwrap().get(name).cloned()
        }
    }

    /// THE U20 gate (mutation-sensitive): a wildcard (`*.x`) and the apex (`x`)
    /// both present at `_acme-challenge.x` with DIFFERENT values, and BOTH values
    /// must be live together — the second `present` must not overwrite the first.
    /// If a reviewer reverts `present` to a single-record `upsert`, the set holds
    /// only the last value and this goes RED.
    #[tokio::test]
    async fn solver_keeps_wildcard_and_apex_values_coexisting() {
        const NAME: &str = "_acme-challenge.example.com";
        let provider = CapturingProvider::default();
        let solver = Dns01Solver::new(&provider, 60);

        solver
            .present_value("example.com", "value-apex".into())
            .await
            .unwrap();
        solver
            .present_value("*.example.com", "value-wild".into())
            .await
            .unwrap();

        // Both values coexist at the one challenge name (sorted, deduped).
        assert_eq!(
            provider.set_at(NAME),
            Some(vec!["value-apex".to_string(), "value-wild".to_string()]),
            "a wildcard+apex order must publish BOTH TXT values at the shared name"
        );

        // Tearing down the apex keeps the wildcard's value live (re-publish the
        // reduced set), not a blanket delete.
        solver.cleanup("example.com").await.unwrap();
        assert_eq!(
            provider.set_at(NAME),
            Some(vec!["value-wild".to_string()]),
            "cleaning up one authorization must not drop the other's value"
        );
        assert!(
            provider.deletes.lock().unwrap().is_empty(),
            "a shared name with a value still live must not be deleted"
        );

        // Tearing down the last one removes the record outright.
        solver.cleanup("*.example.com").await.unwrap();
        assert_eq!(provider.set_at(NAME), None, "the last value is deleted");
        assert_eq!(
            *provider.deletes.lock().unwrap(),
            vec![NAME.to_string()],
            "the final teardown deletes the record"
        );
    }

    /// The read/validate side (U20): with BOTH values live at the shared name, each
    /// identifier's `poll_presented` observes ITS OWN value among the set as Ready
    /// (the resolver returns every TXT record; `txt_record_visible` matches any).
    #[tokio::test]
    async fn poll_presented_sees_its_value_among_a_multi_txt_set() {
        /// Returns the full challenge set at any name, as a real resolver would.
        struct BothValues;
        #[async_trait]
        impl TxtResolver for BothValues {
            async fn lookup_txt(&self, _n: &str) -> Result<Vec<String>, crate::dns::DnsError> {
                Ok(vec!["value-apex".into(), "value-wild".into()])
            }
        }
        let provider = CapturingProvider::default();
        let resolver = BothValues;
        let solver = Dns01Solver::with_resolver(&provider, 60, &resolver);
        solver
            .present_value("example.com", "value-apex".into())
            .await
            .unwrap();
        solver
            .present_value("*.example.com", "value-wild".into())
            .await
            .unwrap();
        assert_eq!(
            solver.poll_presented("example.com").await.unwrap(),
            Propagation::Ready,
            "the apex value resolves among the multi-TXT set"
        );
        assert_eq!(
            solver.poll_presented("*.example.com").await.unwrap(),
            Propagation::Ready,
            "the wildcard value resolves among the multi-TXT set"
        );
    }

    // ---- U19: caller-selectable rustls crypto provider -------------------------

    /// Both named providers are linked and selectable (the `ring` + `aws-lc-rs`
    /// coexistence that makes the no-arg `ClientConfig::builder()` panic). Building
    /// each yields a non-empty cipher-suite list — proof the backend is present.
    #[test]
    fn resolve_crypto_provider_yields_both_backends() {
        let aws = resolve_crypto_provider(&CryptoProviderChoice::AwsLcRs);
        let ring = resolve_crypto_provider(&CryptoProviderChoice::Ring);
        assert!(
            !aws.cipher_suites.is_empty(),
            "aws-lc-rs provider is selectable"
        );
        assert!(
            !ring.cipher_suites.is_empty(),
            "ring provider is selectable"
        );
        // `Default` resolves to a concrete provider too (never panics).
        assert!(
            !resolve_crypto_provider(&CryptoProviderChoice::Default)
                .cipher_suites
                .is_empty()
        );
    }

    /// Installing the process default is idempotent and leaves a default present —
    /// which is exactly what stops instant-acme's `ClientConfig::builder()` from
    /// panicking on an ambiguous default. (Process-global; so this asserts the
    /// POST-condition and idempotency, not which call won the one-shot install.)
    #[test]
    fn install_crypto_provider_sets_a_default_idempotently() {
        install_crypto_provider(CryptoProviderChoice::Default);
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "a process-default CryptoProvider must be installed after the call"
        );
        // Now that one is definitely installed, a further install is a no-op.
        assert!(
            !install_crypto_provider(CryptoProviderChoice::Ring),
            "a second install must not replace the one-shot process default"
        );
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    // ---- U21: typed rate-limit / Retry-After -----------------------------------

    #[test]
    fn parse_rfc3339_utc_known_vectors() {
        use std::time::{Duration as D, SystemTime, UNIX_EPOCH};
        let at = |s| parse_rfc3339_utc(s).unwrap();
        assert_eq!(at("1970-01-01T00:00:00Z"), UNIX_EPOCH);
        assert_eq!(
            at("2000-01-01T00:00:00Z"),
            UNIX_EPOCH + D::from_secs(946_684_800)
        );
        // 2021-01-01T00:00:00Z is the well-known epoch 1_609_459_200.
        assert_eq!(
            at("2021-01-01T00:00:00Z"),
            UNIX_EPOCH + D::from_secs(1_609_459_200)
        );
        // Fractional seconds + lowercase `t`/`z` tolerated; a non-UTC / malformed
        // stamp is rejected.
        assert_eq!(
            at("2000-01-01T00:00:00.123Z"),
            UNIX_EPOCH + D::from_secs(946_684_800)
        );
        assert!(parse_rfc3339_utc("2000-01-01T00:00:00+01:00").is_none());
        assert!(parse_rfc3339_utc("not-a-date").is_none());
        assert!(parse_rfc3339_utc("2000-13-01T00:00:00Z").is_none());
        // The far edge of the 4-digit year range still parses (no overflow).
        assert!(parse_rfc3339_utc("9999-12-31T23:59:59Z").is_some());
        let _ = SystemTime::now();
    }

    /// F3 (security hardening): an absurd year from a garbled/hostile CA problem
    /// detail must be rejected, not overflow the civil-days arithmetic (a debug
    /// panic / a release wrap). `None`, no panic — and a sane date still parses.
    #[test]
    fn parse_rfc3339_utc_rejects_overflowing_year_without_panic() {
        // Would overflow `days * 86400` in `i64` if the year were not bounded.
        assert!(parse_rfc3339_utc("999999999999-01-01T00:00:00Z").is_none());
        // A 5-digit year is already out of RFC 3339 range.
        assert!(parse_rfc3339_utc("10000-01-01T00:00:00Z").is_none());
        // i64::MAX + 1 worth of digits fails the integer parse outright.
        assert!(parse_rfc3339_utc("99999999999999999999-01-01T00:00:00Z").is_none());
        // Reached through the real extraction path (the only reachable input).
        assert_eq!(
            parse_retry_after_from_detail(
                "rate limited, retry after 999999999999-01-01T00:00:00Z: see https://…",
                std::time::UNIX_EPOCH,
            ),
            None,
            "an unparseable absolute hint falls through to the caller's own backoff"
        );
        // A valid stamp through the same path still yields a duration.
        assert_eq!(
            parse_retry_after_from_detail(
                "retry after 2021-01-01T00:01:00Z",
                std::time::UNIX_EPOCH + Duration::from_secs(1_609_459_200),
            ),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn parse_retry_after_from_detail_forms() {
        use std::time::{Duration as D, SystemTime, UNIX_EPOCH};
        let now = UNIX_EPOCH + D::from_secs(1_609_459_200); // == 2021-01-01T00:00:00Z
        // Absolute RFC 3339 form (Let's Encrypt's shape), one hour out.
        assert_eq!(
            parse_retry_after_from_detail(
                "too many certificates already issued, retry after 2021-01-01T01:00:00Z: see https://…",
                now,
            ),
            Some(D::from_secs(3600))
        );
        // delay-seconds form.
        assert_eq!(
            parse_retry_after_from_detail("rate limited; retry after 120 seconds", now),
            Some(D::from_secs(120))
        );
        // A timestamp already in the past clamps to zero (retry now), not None.
        assert_eq!(
            parse_retry_after_from_detail("retry after 1970-01-01T00:00:00Z", now),
            Some(D::ZERO)
        );
        // No hint present ⇒ None (caller applies its own backoff).
        assert_eq!(
            parse_retry_after_from_detail("too many certificates already issued", now),
            None
        );
        let _ = SystemTime::now();
    }

    #[test]
    fn rate_limited_problem_maps_to_typed_error_with_retry_after() {
        // Build a real `instant_acme::Error::Api(Problem)` via the public
        // `From<Problem>` impl (the enum is `#[non_exhaustive]`, so the variant
        // can't be named directly, but `.into()` constructs it).
        let problem = instant_acme::Problem {
            r#type: Some("urn:ietf:params:acme:error:rateLimited".to_string()),
            detail: Some("too many certificates, retry after 120".to_string()),
            status: Some(429),
            subproblems: Vec::new(),
        };
        let err: instant_acme::Error = problem.into();
        match AcmeError::from(err) {
            AcmeError::RateLimited {
                retry_after,
                detail,
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(120)));
                assert_eq!(
                    detail.as_deref(),
                    Some("too many certificates, retry after 120")
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }

        // A NON-rate-limit problem stays an opaque protocol error (not RateLimited).
        let other = instant_acme::Problem {
            r#type: Some("urn:ietf:params:acme:error:malformed".to_string()),
            detail: Some("bad request".to_string()),
            status: Some(400),
            subproblems: Vec::new(),
        };
        let err: instant_acme::Error = other.into();
        assert!(
            matches!(AcmeError::from(err), AcmeError::Acme(_)),
            "a non-rateLimited problem must not be classified as RateLimited"
        );
    }

    #[test]
    fn is_acme_rate_limited_matches_urn_or_429() {
        let p = |ty: Option<&str>, status: Option<u16>| instant_acme::Problem {
            r#type: ty.map(str::to_string),
            detail: None,
            status,
            subproblems: Vec::new(),
        };
        assert!(is_acme_rate_limited(&p(
            Some("urn:ietf:params:acme:error:rateLimited"),
            None
        )));
        // Case-insensitive on the URN suffix.
        assert!(is_acme_rate_limited(&p(
            Some("urn:ietf:params:acme:error:RATELIMITED"),
            None
        )));
        // A bare 429 (no URN) still classifies.
        assert!(is_acme_rate_limited(&p(None, Some(429))));
        // Unrelated problems do not.
        assert!(!is_acme_rate_limited(&p(
            Some("urn:ietf:params:acme:error:malformed"),
            Some(400)
        )));
    }

    // ---- U22: the propagation self-check resolver must not cache ---------------

    /// The DNS-01 self-check resolvers are built to OBSERVE freshly-published
    /// records, so caching is actively harmful: a cached negative answer would
    /// make a just-written TXT keep reading as absent. `resolver_opts` disables the
    /// cache (`cache_size == 0`) so every lookup is fresh / honors the low TTL. If a
    /// reviewer drops that line, this goes RED.
    #[test]
    fn resolver_opts_disables_caching() {
        let opts = resolver_opts();
        assert_eq!(opts.cache_size, 0, "the self-check resolver must not cache");
    }
}
