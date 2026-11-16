//! Shared plumbing for the REST-based KMS signers (Vault / GCP / Azure).

use std::time::Duration;

/// A reqwest client for KMS calls: a bounded timeout so a stalled backend can't
/// wedge token minting, and rustls (the workspace default).
pub(crate) fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client builds with default (rustls) config")
}
