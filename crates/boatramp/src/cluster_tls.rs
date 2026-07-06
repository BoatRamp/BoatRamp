//! Cluster-managed TLS on the serve path.
//!
//! Bridges the coordination core ([`boatramp_core::cert`]) to the rustls serving
//! config: each node's served certificates come from the **replicated cert
//! store**, and issuance is leader single-flight. A renewal pass, per domain,
//! runs [`ensure_cert`] — the leader calls the CA (writing the DNS-01 TXT as the
//! sole writer) and stores the cert; every node then loads the stored cert and
//! (re)builds its rustls config. So all nodes serve the same leader-issued cert
//! with no per-node CA calls and no TXT races.
//!
//! The store↔serve bridge + the refresh decision are unit-tested here with a
//! self-signed fixture; the live CA round-trip + the running renewal loop need
//! live-platform validation (same policy as the rest of ACME, already
//! Pebble-validated single-node).

use boatramp_acme::acme::IssuedCert;
use boatramp_core::cert::{ensure_cert, CertStore, StoredCert};

/// A failure refreshing the cluster's served certs through the replicated cert
/// store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A cert-store / coordination error (load, store, or leader issuance).
    #[error(transparent)]
    Cert(#[from] boatramp_core::cert::CertError),
}

/// `cluster_tls` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Renew long enough before expiry that a transient leader gap can't strand an
/// expired cert (the renewal loop runs far more often than this window).
pub const RENEW_BEFORE_SECS: u64 = 30 * 24 * 3600; // 30 days

/// Let's Encrypt certs are valid ~90 days; we stamp this as the stored expiry
/// when the issuer doesn't surface `notAfter` (a safe renewal heuristic —
/// renewal fires `RENEW_BEFORE_SECS` before it).
pub const ASSUMED_LIFETIME_SECS: u64 = 90 * 24 * 3600;

/// A freshly-issued cert → the stored form (stamping a heuristic expiry).
pub fn issued_to_stored(issued: &IssuedCert, now_unix: u64) -> StoredCert {
    StoredCert::new(
        issued.certificate_pem.clone(),
        issued.private_key_pem.clone(),
        now_unix.saturating_add(ASSUMED_LIFETIME_SECS),
    )
}

/// A stored cert → the issued form `build_server_config` consumes.
pub fn stored_to_issued(stored: &StoredCert) -> IssuedCert {
    IssuedCert {
        certificate_pem: stored.chain_pem.clone(),
        private_key_pem: stored.key_pem.clone(),
    }
}

/// Refresh every `domain`'s cert through the cluster cert store, returning the
/// `(domain, cert)` entries to serve (for `acme_dns::build_server_config`).
///
/// The leader issues (via `issue`) + stores any missing/near-expiry cert; every
/// node then loads whatever is stored. `issue` is the live CA call;
/// followers never invoke it.
pub async fn refresh_entries<F, Fut, E>(
    store: &dyn CertStore,
    domains: &[String],
    is_leader: bool,
    now_unix: u64,
    mut issue: F,
) -> Result<Vec<(String, IssuedCert)>>
where
    F: FnMut(String) -> Fut,
    // The `issue` callback is the caller-supplied CA round-trip (wired in
    // `serve`). `ensure_cert` is generic over the issuer's error (`E: Display`),
    // so this stays generic too — any typed issuer error flows through.
    Fut: std::future::Future<Output = std::result::Result<StoredCert, E>>,
    E: std::fmt::Display,
{
    let mut entries = Vec::with_capacity(domains.len());
    for domain in domains {
        let stored = ensure_cert(
            store,
            domain,
            is_leader,
            now_unix,
            RENEW_BEFORE_SECS,
            || issue(domain.clone()),
        )
        .await?;
        if let Some(stored) = stored {
            entries.push((domain.clone(), stored_to_issued(&stored)));
        } else {
            // A follower before the leader has issued this domain yet — skip it
            // for now; the next refresh picks it up once it's replicated.
            tracing::debug!(%domain, "cluster-tls: cert not yet available (awaiting leader)");
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::cert::KvCertStore;
    use boatramp_core::kv::MemoryKv;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A freshly-generated self-signed cert/key, so the bridge +
    /// `build_server_config` exercise real PEM that rustls accepts (no live CA,
    /// no embedded fixture).
    fn fixture_cert() -> StoredCert {
        let c = rcgen::generate_simple_self_signed(vec!["test.boatramp.local".to_string()])
            .expect("self-signed cert");
        StoredCert::new(c.cert.pem(), c.key_pair.serialize_pem(), 4_000_000_000)
    }

    fn store() -> KvCertStore {
        KvCertStore::new(Arc::new(MemoryKv::new()))
    }

    /// Install the process rustls crypto provider (the serve path does this;
    /// `build_server_config` needs it). Idempotent across tests.
    fn ensure_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[tokio::test]
    async fn follower_serves_replicated_cert_without_issuing() {
        ensure_crypto();
        let s = store();
        // The leader has already issued + replicated (simulate via a put).
        s.put("blog.example.com", &fixture_cert()).await.unwrap();

        let calls = AtomicUsize::new(0);
        let entries = refresh_entries(&s, &["blog.example.com".into()], false, 1000, |_d| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err::<StoredCert, String>(
                "a follower must not call the CA".into(),
            ))
        })
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "blog.example.com");
        // The bridged cert is real PEM that the serving config accepts.
        crate::acme_dns::build_server_config(entries).expect("rustls config from stored cert");
    }

    #[tokio::test]
    async fn leader_issues_then_bridges_to_serving_config() {
        ensure_crypto();
        let s = store();
        let issued = AtomicUsize::new(0);
        let entries = refresh_entries(&s, &["blog.example.com".into()], true, 1000, |_d| {
            issued.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok::<_, String>(fixture_cert()))
        })
        .await
        .unwrap();
        assert_eq!(issued.load(Ordering::SeqCst), 1, "leader issued once");
        assert_eq!(entries.len(), 1);
        // Stored for the followers to pick up.
        assert!(s.get("blog.example.com").await.unwrap().is_some());
        crate::acme_dns::build_server_config(entries).expect("rustls config");
    }

    #[tokio::test]
    async fn follower_skips_domain_until_leader_issues() {
        let s = store();
        // Nothing stored yet, follower → no entry, no CA call.
        let entries = refresh_entries(&s, &["pending.example.com".into()], false, 1000, |_d| {
            std::future::ready(Err::<StoredCert, String>("no CA".into()))
        })
        .await
        .unwrap();
        assert!(entries.is_empty());
    }
}
