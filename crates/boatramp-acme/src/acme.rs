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
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use instant_acme::{AuthorizationStatus, Identifier, NewAccount, NewOrder, OrderStatus};
// Re-exported so a caller can implement [`ChallengeSolver`] + manage account lifecycle without a
// direct `instant-acme` dependency. These also bring the names into this module's scope.
pub use instant_acme::{Account, AccountCredentials, ChallengeType, KeyAuthorization};

use crate::dns::{DnsProvider, DnsRecord, RecordKind, acme_challenge_name};

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
    /// The order failed validation (a challenge did not pass).
    #[error("ACME order became invalid (challenge failed)")]
    OrderInvalid,
    /// Timed out waiting for the order to become ready.
    #[error("timed out waiting for ACME order to become ready")]
    OrderReadyTimeout,
    /// Timed out waiting for the issued certificate.
    #[error("timed out waiting for the ACME certificate")]
    CertificateTimeout,
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
    /// How long to wait after writing the TXT records before telling the CA to
    /// validate (DNS-propagation slack). The CA also retries on its own.
    pub propagation_delay: Duration,
    /// How long to keep polling the order before giving up.
    pub timeout: Duration,
}

impl Default for CertRequest {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            contact_email: None,
            domains: Vec::new(),
            dns_ttl: 60,
            propagation_delay: Duration::from_secs(15),
            timeout: Duration::from_secs(120),
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
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    let want = solver.challenge_type();
    // Identifiers we presented a challenge for, so we clean exactly those up afterward.
    let mut presented: Vec<String> = Vec::new();
    let authorizations = order.authorizations().await?;
    for authz in &authorizations {
        if authz.status == AuthorizationStatus::Valid {
            continue;
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == want)
            .ok_or_else(|| AcmeError::NoChallenge(want.clone()))?;
        let Identifier::Dns(identifier) = &authz.identifier;
        let key_auth = order.key_authorization(challenge);
        solver.present(identifier, &key_auth).await?;
        presented.push(identifier.clone());
        order.set_challenge_ready(&challenge.url).await?;
    }

    let result = drive_to_certificate(&mut order, request).await;

    for identifier in &presented {
        if let Err(err) = solver.cleanup(identifier).await {
            tracing::warn!(target: "boatramp::acme", %err, %identifier, "challenge cleanup failed");
        }
    }
    result
}

/// Run the full **DNS-01** issuance for `request.domains`, solving challenges via `provider`. A
/// back-compatible convenience over [`obtain_certificate_with`]: it creates a throwaway account and a
/// [`Dns01Solver`]. (On-demand issuance should instead reuse one account via
/// [`create_account`]/[`restore_account`] + [`obtain_certificate_with`].)
pub async fn obtain_certificate(
    request: &CertRequest,
    provider: &dyn DnsProvider,
) -> Result<IssuedCert, AcmeError> {
    let (account, _credentials) =
        create_account(&request.directory_url, request.contact_email.as_deref()).await?;
    let solver = Dns01Solver::new(provider, request.dns_ttl);
    obtain_certificate_with(&account, request, &solver).await
}

/// A [`ChallengeSolver`] that proves DNS-01 by writing the `_acme-challenge` TXT via a
/// [`DnsProvider`]. Remembers what it wrote so `cleanup` removes exactly that record.
pub struct Dns01Solver<'a> {
    provider: &'a dyn DnsProvider,
    ttl: u32,
    written: Mutex<HashMap<String, DnsRecord>>,
}

impl<'a> Dns01Solver<'a> {
    pub fn new(provider: &'a dyn DnsProvider, ttl: u32) -> Self {
        Self {
            provider,
            ttl,
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
}

/// Create a fresh ACME account at `directory_url`. The returned [`AccountCredentials`] is opaque but
/// serde-serializable — the caller persists it (sealed) and reuses the account via [`restore_account`]
/// across restarts/replicas, so the CA's `newAccount` rate limit is hit once, not per order.
pub async fn create_account(
    directory_url: &str,
    contact_email: Option<&str>,
) -> Result<(Account, AccountCredentials), AcmeError> {
    let contact: Vec<String> = contact_email
        .into_iter()
        .map(|email| format!("mailto:{email}"))
        .collect();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        directory_url,
        None,
    )
    .await?;
    Ok((account, credentials))
}

/// Restore a previously-created account from stored [`AccountCredentials`] (no CA round trip for a
/// new account). The caller keeps its own serialized copy; this consumes the parsed credentials.
pub async fn restore_account(credentials: AccountCredentials) -> Result<Account, AcmeError> {
    Ok(Account::from_credentials(credentials).await?)
}

/// Wait for the order to become ready, finalize it with a CSR, and fetch the
/// issued chain. Split out so the challenge-cleanup wrapper stays readable.
async fn drive_to_certificate(
    order: &mut instant_acme::Order,
    request: &CertRequest,
) -> Result<IssuedCert, AcmeError> {
    // Give the records a moment to propagate, then poll the order to Ready.
    tokio::time::sleep(request.propagation_delay).await;
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

    // Generate the key + CSR for the requested SANs.
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(request.domains.clone())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;
    order.finalize(csr.der()).await?;

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
