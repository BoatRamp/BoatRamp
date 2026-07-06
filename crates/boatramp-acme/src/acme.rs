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

use std::time::Duration;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};

use crate::dns::{acme_challenge_name, DnsProvider, DnsRecord, RecordKind};

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
    /// The CA offered no DNS-01 challenge for an authorization.
    #[error("authorization offers no dns-01 challenge")]
    NoDns01Challenge,
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

/// Run the full DNS-01 issuance for `request.domains`, solving challenges via
/// `provider`. Cleans up the challenge TXT records before returning (on success
/// or failure).
pub async fn obtain_certificate(
    request: &CertRequest,
    provider: &dyn DnsProvider,
) -> Result<IssuedCert, AcmeError> {
    let contact: Vec<String> = request
        .contact_email
        .iter()
        .map(|email| format!("mailto:{email}"))
        .collect();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, _credentials) = Account::create(
        &NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &request.directory_url,
        None,
    )
    .await?;

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

    // Solve every pending authorization via a DNS-01 TXT record. Track what we
    // wrote so we can clean up afterwards.
    let mut written: Vec<DnsRecord> = Vec::new();
    let authorizations = order.authorizations().await?;
    for authz in &authorizations {
        if authz.status == AuthorizationStatus::Valid {
            continue;
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or(AcmeError::NoDns01Challenge)?;
        let Identifier::Dns(identifier) = &authz.identifier;
        let record = DnsRecord {
            kind: RecordKind::Txt,
            name: acme_challenge_name(identifier),
            value: order.key_authorization(challenge).dns_value(),
            ttl: request.dns_ttl,
        };
        provider.upsert(&record).await?;
        written.push(record);
        order.set_challenge_ready(&challenge.url).await?;
    }

    let result = drive_to_certificate(&mut order, request).await;

    // Best-effort cleanup of the challenge records, regardless of outcome.
    for record in &written {
        if let Err(err) = provider.delete(record).await {
            tracing::warn!(target: "boatramp::acme", %err, name = %record.name, "challenge TXT cleanup failed");
        }
    }
    result
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
