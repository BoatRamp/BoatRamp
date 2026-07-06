//! Cluster-managed TLS certificates.
//!
//! In a cluster every node terminates TLS, so issuance must be **coordinated**:
//! independent per-node issuance races on the ACME DNS-01 `_acme-challenge` TXT
//! record (a shared `*.deploy.<host>` wildcard has every node writing it) and
//! wastes CA orders. The fix is the leader-only-job pattern: **issue once on the
//! leader, distribute to all**.
//!
//! Certs are small control-plane metadata, so they live in the **replicated
//! [`KvStore`]** keyed `cert/<domain>` — over `RaftKv` that means every node
//! gets every cert in its local applied state (read locally on the SNI hot
//! path; a joining node gets them via replication). Single-node is the
//! degenerate case: the same store over the local KV.
//!
//! [`ensure_cert`] is the single-flight decision (pure of the CA + rustls): the
//! leader issues + stores when a cert is missing or near expiry; a follower
//! never calls the CA — it just serves whatever the leader has replicated. The
//! live ACME round-trip and the rustls hot-swap are wired by the serve path;
//! this module is the coordination logic and is fully unit-tested.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::envelope::KeyEnvelope;
use crate::kv::{KvError, KvStore};

// The key-free `CertStatus` view is a pure serde wire type in `boatramp-types`
// (so the server, CLI, and web console share one definition); re-exported so
// `boatramp_core::cert::CertStatus` is unchanged.
pub use boatramp_types::cert::CertStatus;

/// A stored certificate: the PEM chain + private key, plus the expiry used to
/// decide renewal. Pinned `v1` like every boatramp schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCert {
    /// Pinned schema discriminant (`v1`).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// The full certificate chain, PEM-encoded.
    pub chain_pem: String,
    /// The private key, PEM-encoded.
    pub key_pem: String,
    /// `notAfter` as a Unix timestamp (seconds), for renewal decisions.
    pub not_after_unix: u64,
}

impl StoredCert {
    /// Construct a stored cert at the pinned schema version.
    pub fn new(
        chain_pem: impl Into<String>,
        key_pem: impl Into<String>,
        not_after_unix: u64,
    ) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            chain_pem: chain_pem.into(),
            key_pem: key_pem.into(),
            not_after_unix,
        }
    }
}

/// Why a cert-coordination operation failed.
#[derive(Debug)]
pub enum CertError {
    /// An underlying [`KvStore`] error.
    Kv(KvError),
    /// (De)serialization of a stored cert failed.
    Decode(String),
    /// The issuer (CA round-trip) failed.
    Issue(String),
    /// Wrapping/unwrapping the private key at rest failed.
    Envelope(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Kv(e) => write!(f, "cert store kv error: {e}"),
            CertError::Decode(m) => write!(f, "cert decode error: {m}"),
            CertError::Issue(m) => write!(f, "cert issuance error: {m}"),
            CertError::Envelope(m) => write!(f, "cert key envelope error: {m}"),
        }
    }
}

impl std::error::Error for CertError {}

impl From<KvError> for CertError {
    fn from(e: KvError) -> Self {
        CertError::Kv(e)
    }
}

/// The KV key a domain's cert is stored under.
pub fn cert_key(domain: &str) -> String {
    format!("cert/{domain}")
}

/// A store of certs by domain, shared across the cluster.
#[async_trait]
pub trait CertStore: Send + Sync {
    /// Load the stored cert for `domain`, or `None`.
    async fn get(&self, domain: &str) -> Result<Option<StoredCert>, CertError>;
    /// Store (replacing) the cert for `domain`.
    async fn put(&self, domain: &str, cert: &StoredCert) -> Result<(), CertError>;
}

/// A [`CertStore`] over any [`KvStore`] — back it with `RaftKv` for a cluster
/// (certs replicate to every node) or a local KV for single-node.
///
/// With an optional [`KeyEnvelope`], the private key is **wrapped at rest**:
/// the stored record's `key_pem` holds `hex(wrap(key))` instead of
/// cleartext, and reads unwrap it — so a cert private key is never cleartext in
/// the replicated control plane. The `chain_pem` + expiry stay clear (not secret,
/// and the expiry drives renewal without unwrapping).
pub struct KvCertStore {
    kv: Arc<dyn KvStore>,
    envelope: Option<Arc<dyn KeyEnvelope>>,
}

impl KvCertStore {
    /// Build over the given KV backend (private keys stored **cleartext**).
    pub fn new(kv: Arc<dyn KvStore>) -> Self {
        Self { kv, envelope: None }
    }

    /// Build with a [`KeyEnvelope`], so stored private keys are wrapped at rest.
    pub fn with_envelope(kv: Arc<dyn KvStore>, envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self {
            kv,
            envelope: Some(envelope),
        }
    }
}

#[async_trait]
impl CertStore for KvCertStore {
    async fn get(&self, domain: &str) -> Result<Option<StoredCert>, CertError> {
        let Some(raw) = self.kv.get(&cert_key(domain)).await? else {
            return Ok(None);
        };
        let mut cert: StoredCert =
            serde_json::from_slice(&raw).map_err(|e| CertError::Decode(e.to_string()))?;
        if let Some(envelope) = &self.envelope {
            // `key_pem` holds `hex(wrap(key))`; recover the cleartext PEM.
            let wrapped =
                hex::decode(cert.key_pem.trim()).map_err(|e| CertError::Envelope(e.to_string()))?;
            let plaintext = envelope
                .unwrap(&wrapped)
                .await
                .map_err(|e| CertError::Envelope(e.to_string()))?;
            cert.key_pem =
                String::from_utf8(plaintext).map_err(|e| CertError::Envelope(e.to_string()))?;
        }
        Ok(Some(cert))
    }

    async fn put(&self, domain: &str, cert: &StoredCert) -> Result<(), CertError> {
        // Wrap the private key at rest when an envelope is configured.
        let to_store = if let Some(envelope) = &self.envelope {
            let wrapped = envelope
                .wrap(cert.key_pem.as_bytes())
                .await
                .map_err(|e| CertError::Envelope(e.to_string()))?;
            StoredCert {
                key_pem: hex::encode(wrapped),
                ..cert.clone()
            }
        } else {
            cert.clone()
        };
        let json = serde_json::to_vec(&to_store).map_err(|e| CertError::Decode(e.to_string()))?;
        self.kv.put(&cert_key(domain), json).await?;
        Ok(())
    }
}

/// Ensure a usable cert for `domain` is in the store, **issuing once on the
/// leader**.
///
/// - If the stored cert is valid (expires more than `renew_before_secs` after
///   `now_unix`), return it — no CA call.
/// - Otherwise, only the **leader** (`is_leader`) calls `issue` and stores the
///   result (sole writer of the DNS-01 TXT → no races, no duplicate orders). A
///   follower returns whatever is currently stored (possibly `None` until the
///   leader has issued + replicated it) and never contacts the CA.
pub async fn ensure_cert<F, Fut, E>(
    store: &dyn CertStore,
    domain: &str,
    is_leader: bool,
    now_unix: u64,
    renew_before_secs: u64,
    issue: F,
) -> Result<Option<StoredCert>, CertError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<StoredCert, E>>,
    E: std::fmt::Display,
{
    let existing = store.get(domain).await?;
    let fresh = existing
        .as_ref()
        .is_some_and(|c| c.not_after_unix > now_unix.saturating_add(renew_before_secs));
    if fresh {
        return Ok(existing);
    }
    if !is_leader {
        // Followers never issue — they serve the leader's replicated cert.
        return Ok(existing);
    }
    let cert = issue().await.map_err(|e| CertError::Issue(e.to_string()))?;
    store.put(domain, &cert).await?;
    Ok(Some(cert))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeError;
    use crate::kv::MemoryKv;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store() -> KvCertStore {
        KvCertStore::new(Arc::new(MemoryKv::new()))
    }

    /// A reversible test envelope (byte-reverse + a format tag) — enough to prove
    /// the store wraps/unwraps around a `KeyEnvelope` without a crypto backend.
    struct ReverseEnvelope;

    #[async_trait]
    impl KeyEnvelope for ReverseEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            let mut out = vec![0xEE];
            out.extend(plaintext.iter().rev());
            Ok(out)
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            match wrapped.split_first() {
                Some((0xEE, rest)) => Ok(rest.iter().rev().copied().collect()),
                _ => Err(EnvelopeError::new("not a ReverseEnvelope blob")),
            }
        }
    }

    /// With an envelope, the private key is stored wrapped (never cleartext in
    /// the KV) and reads recover it.
    #[tokio::test]
    async fn envelope_wraps_the_key_at_rest_and_reads_recover_it() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let s = KvCertStore::with_envelope(kv.clone(), Arc::new(ReverseEnvelope));
        let cert = StoredCert::new("CHAIN", "SECRET-KEY-PEM", 9999);
        s.put("blog", &cert).await.unwrap();

        // The raw KV bytes never contain the cleartext key.
        let raw = kv.get(&cert_key("blog")).await.unwrap().unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(
            !raw_str.contains("SECRET-KEY-PEM"),
            "the private key must not be stored in cleartext"
        );
        assert!(raw_str.contains("CHAIN"), "the chain stays clear");

        // A read unwraps back to the original cert.
        let got = s.get("blog").await.unwrap().unwrap();
        assert_eq!(got, cert);
    }

    /// A store with the wrong/no envelope can't read a wrapped record (fail-closed).
    #[tokio::test]
    async fn wrapped_key_is_unreadable_without_the_envelope() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        KvCertStore::with_envelope(kv.clone(), Arc::new(ReverseEnvelope))
            .put("blog", &StoredCert::new("C", "K", 1))
            .await
            .unwrap();
        // A plaintext store reads the wrapped hex verbatim (not the real key), and
        // a mismatched-format unwrap fails — either way the secret isn't exposed.
        let plain = KvCertStore::new(kv);
        let got = plain.get("blog").await.unwrap().unwrap();
        assert_ne!(
            got.key_pem, "K",
            "cleartext read must not yield the real key"
        );
    }

    /// A fake issuer that counts calls and stamps a far-future expiry.
    fn issuer(
        calls: &AtomicUsize,
        not_after: u64,
    ) -> impl FnOnce() -> std::future::Ready<Result<StoredCert, String>> + '_ {
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(StoredCert::new("CHAIN", "KEY", not_after)))
        }
    }

    #[tokio::test]
    async fn kv_cert_store_round_trips() {
        let s = store();
        assert!(s.get("blog.example.com").await.unwrap().is_none());
        let cert = StoredCert::new("chain", "key", 1000);
        s.put("blog.example.com", &cert).await.unwrap();
        assert_eq!(s.get("blog.example.com").await.unwrap(), Some(cert));
    }

    #[tokio::test]
    async fn leader_issues_once_then_serves_from_store() {
        let s = store();
        let calls = AtomicUsize::new(0);
        // No cert yet → leader issues.
        let c = ensure_cert(&s, "d", true, 100, 50, issuer(&calls, 10_000))
            .await
            .unwrap();
        assert!(c.is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Cert is fresh → no re-issue on the next pass.
        let c2 = ensure_cert(&s, "d", true, 200, 50, issuer(&calls, 10_000))
            .await
            .unwrap();
        assert_eq!(c2.unwrap().chain_pem, "CHAIN");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "fresh cert must not re-issue"
        );
    }

    #[tokio::test]
    async fn follower_never_issues_but_serves_replicated() {
        let s = store();
        let calls = AtomicUsize::new(0);
        // Follower, no cert yet → does not issue, gets None.
        let c = ensure_cert(&s, "d", false, 100, 50, issuer(&calls, 10_000))
            .await
            .unwrap();
        assert!(c.is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a follower must not call the CA"
        );
        // The leader issues + replicates (simulated by a direct put).
        s.put("d", &StoredCert::new("CHAIN", "KEY", 10_000))
            .await
            .unwrap();
        // The follower now serves the replicated cert, still without issuing.
        let c = ensure_cert(&s, "d", false, 200, 50, issuer(&calls, 10_000))
            .await
            .unwrap();
        assert_eq!(c.unwrap().chain_pem, "CHAIN");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn leader_renews_near_expiry() {
        let s = store();
        let calls = AtomicUsize::new(0);
        // A cert expiring at 1000; now=900, renew_before=200 → 1000 <= 1100 → renew.
        s.put("d", &StoredCert::new("OLD", "KEY", 1000))
            .await
            .unwrap();
        let c = ensure_cert(&s, "d", true, 900, 200, issuer(&calls, 99_999))
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "near-expiry cert must renew"
        );
        assert_eq!(c.unwrap().not_after_unix, 99_999);
    }
}
