//! Certificate **wire structs** shared across boatramp.
//!
//! Only the key-free [`CertStatus`] view (for the `cert status` endpoint) is a
//! pure serde wire type and lives here so the server, CLI, and web console
//! share one definition (wasm-clean). The cluster cert *store* — `StoredCert`,
//! `CertStore`/`KvCertStore`, and `ensure_cert` — depends on the KV backend and
//! stays in `boatramp-core::cert`.

use serde::{Deserialize, Serialize};

/// A safe, key-free view of a stored cert (for the `cert status` endpoint):
/// which domain and when it expires, never the chain or private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertStatus {
    /// The domain the cert covers.
    pub domain: String,
    /// `notAfter` as a Unix timestamp (seconds).
    pub not_after_unix: u64,
}
