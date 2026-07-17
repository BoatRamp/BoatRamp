//! Domain ownership verification: prove control of a custom
//! hostname before it is attached to a site and becomes eligible for ACME
//! issuance.
//!
//! Two methods, uniform across deployment targets:
//!
//! * **DNS TXT** — the operator publishes `_boatramp-verify.<host>` with the
//!   challenge token. boatramp resolves it over public DNS. This proves DNS
//!   control *while the domain still points elsewhere*, so it is the right
//!   choice when migrating a live domain onto boatramp.
//! * **HTTP token** — the operator serves the token at
//!   `http://<host>/.well-known/boatramp-domain-verification/<token>` from
//!   wherever the host currently resolves. boatramp fetches it over the public
//!   internet. This proves control of the host as it exists today.
//!
//! The model and the match logic are pure and live here; the network probe
//! ([`DomainProbe`]) is injected, so verification is fully testable without
//! live DNS/HTTP (a fake probe in tests). The real probe lives in the server.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Path prefix boatramp fetches for the HTTP-token method. The full path is
/// [`http_challenge_path`].
pub const HTTP_WELL_KNOWN_PREFIX: &str = "/.well-known/boatramp-domain-verification/";

/// DNS record-name prefix for the TXT method (joined to the base host).
pub const DNS_RECORD_PREFIX: &str = "_boatramp-verify";

/// How long a **pending** (unverified) challenge stays valid, in seconds
/// (7 days). After this the self-serve edge route and `domain verify` stop
/// honoring it, so a stale token can't be redeemed indefinitely; the operator
/// re-runs `domain add` for a fresh one. A *verified* record never expires — it
/// records proven ownership — and a `created_at_unix` of `0` (unstamped) is
/// treated as non-expiring.
pub const CHALLENGE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// How a domain's ownership is proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationMethod {
    /// A `_boatramp-verify.<host>` TXT record carrying the token.
    Dns,
    /// A token file served under `/.well-known/` on the host.
    Http,
}

impl VerificationMethod {
    /// The stable wire/CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
        }
    }
}

impl std::str::FromStr for VerificationMethod {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dns" | "txt" | "dns-txt" => Ok(Self::Dns),
            "http" | "http-token" | "token" => Ok(Self::Http),
            other => Err(ConfigError::parse(format!(
                "unknown verification method `{other}` (expected `dns` or `http`)"
            ))),
        }
    }
}

impl std::fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A pending or completed ownership-verification challenge for one host of a
/// site. Persisted in the KV (`domainverify/<site>/<host>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DomainVerification {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    pub version: u32,
    /// The host being verified (normalized: lowercased, no `*.`/trailing dot).
    pub host: String,
    /// The random challenge token the operator must publish.
    pub token: String,
    /// The method the token is published under.
    pub method: VerificationMethod,
    /// Whether ownership has been confirmed.
    pub verified: bool,
    /// Unix seconds the challenge was created.
    pub created_at_unix: u64,
}

impl Default for DomainVerification {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            host: String::new(),
            token: String::new(),
            method: VerificationMethod::Dns,
            verified: false,
            created_at_unix: 0,
        }
    }
}

impl DomainVerification {
    /// Start a fresh, unverified challenge for `host` with a random token.
    pub fn new(host: &str, method: VerificationMethod, now_unix: u64) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            host: normalize_host(host),
            token: generate_token(),
            method,
            verified: false,
            created_at_unix: now_unix,
        }
    }

    /// The DNS record name to query (TXT method).
    pub fn dns_record_name(&self) -> String {
        dns_record_name(&self.host)
    }

    /// The path boatramp fetches on the host (HTTP method).
    pub fn http_challenge_path(&self) -> String {
        http_challenge_path(&self.token)
    }

    /// The `http://<host><path>` URL boatramp fetches (HTTP method). Plain HTTP
    /// on purpose: the host may not have a valid cert yet (that's what this
    /// verification gates), and the token is single-use and non-secret.
    pub fn http_challenge_url(&self) -> String {
        format!("http://{}{}", self.host, self.http_challenge_path())
    }

    /// Does `value` (a fetched HTTP body or a TXT record value) prove the token?
    pub fn matches(&self, value: &str) -> bool {
        value.trim() == self.token
    }

    /// Does any of the `values` (e.g. all TXT records at the name) match?
    pub fn matches_any<I, S>(&self, values: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        values.into_iter().any(|v| self.matches(v.as_ref()))
    }

    /// Whether this challenge has passed its validity window at `now_unix`.
    /// Computed from `created_at_unix` (no stored expiry field — the schema is
    /// pinned at v1):
    ///
    /// * a **verified** record (proven ownership) never expires — including one
    ///   with an unstamped `created_at_unix` of `0`;
    /// * a **pending** record with `created_at_unix == 0` is treated as expired,
    ///   so an unstamped challenge can never be redeemed via the self-serve route
    ///   (the grace applies only to verified records, not pending ones);
    /// * otherwise it expires [`CHALLENGE_TTL_SECS`] after `created_at_unix`.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        if self.verified {
            return false;
        }
        if self.created_at_unix == 0 {
            return true;
        }
        now_unix.saturating_sub(self.created_at_unix) > CHALLENGE_TTL_SECS
    }

    /// Operator-facing setup instructions for this challenge.
    pub fn instructions(&self) -> String {
        match self.method {
            VerificationMethod::Dns => format!(
                "Add this DNS record, then run `boatramp domain verify {host}`:\n  \
                 {name}  TXT  \"{token}\"",
                host = self.host,
                name = self.dns_record_name(),
                token = self.token,
            ),
            VerificationMethod::Http => format!(
                "Serve this token, then run `boatramp domain verify {host}`:\n  \
                 GET {url}\n  body: {token}",
                host = self.host,
                url = self.http_challenge_url(),
                token = self.token,
            ),
        }
    }

    /// Parse from the KV JSON representation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        serde_json::from_slice(bytes).map_err(|err| ConfigError::parse(err.to_string()))
    }

    /// Serialize to JSON for KV storage.
    pub fn to_json(&self) -> Result<Vec<u8>, ConfigError> {
        serde_json::to_vec(self).map_err(|err| ConfigError::parse(err.to_string()))
    }
}

/// Normalize a host for verification keys and queries: lowercase, strip a
/// leading `*.` (a wildcard is verified at its base domain, like ACME), and
/// strip any trailing dot.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    let base = host.strip_prefix("*.").unwrap_or(host);
    base.to_ascii_lowercase()
}

/// The TXT record name for `host` (the host is normalized first).
pub fn dns_record_name(host: &str) -> String {
    format!("{DNS_RECORD_PREFIX}.{}", normalize_host(host))
}

/// The well-known path carrying `token` (HTTP method).
pub fn http_challenge_path(token: &str) -> String {
    format!("{HTTP_WELL_KNOWN_PREFIX}{token}")
}

/// A fresh 128-bit challenge token, hex-encoded (32 chars).
fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("system RNG");
    hex::encode(bytes)
}

/// Error performing the ownership probe (DNS lookup / HTTP fetch).
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The probe could not complete (network, resolver, timeout).
    #[error("ownership probe failed: {0}")]
    Probe(String),

    /// This build was not compiled with support for the requested method
    /// (e.g. DNS resolution behind the `domain-verify-dns` server feature).
    #[error("verification method `{0}` is not supported by this build")]
    Unsupported(VerificationMethod),
}

/// The network side of verification: look up TXT records / fetch a URL. Injected
/// so the pure [`check_ownership`] flow is testable without live DNS or HTTP.
#[async_trait]
pub trait DomainProbe: Send + Sync {
    /// All TXT record values at `name` (empty if the name has none).
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, VerifyError>;

    /// The body fetched from `url` (HTTP method).
    async fn fetch_http(&self, url: &str) -> Result<String, VerifyError>;
}

/// Run `verification`'s challenge through `probe`. Returns whether ownership is
/// proven; does not mutate or persist anything.
pub async fn check_ownership(
    probe: &dyn DomainProbe,
    verification: &DomainVerification,
) -> Result<bool, VerifyError> {
    match verification.method {
        VerificationMethod::Dns => {
            let values = probe.lookup_txt(&verification.dns_record_name()).await?;
            Ok(verification.matches_any(values))
        }
        VerificationMethod::Http => {
            let body = probe.fetch_http(&verification.http_challenge_url()).await?;
            Ok(verification.matches(&body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn fixed(method: VerificationMethod) -> DomainVerification {
        DomainVerification {
            version: crate::SCHEMA_VERSION,
            host: "example.com".into(),
            token: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
            method,
            verified: false,
            created_at_unix: 100,
        }
    }

    /// A scripted probe: returns canned TXT values / HTTP body.
    struct FakeProbe {
        txt: Vec<String>,
        http: String,
        queried: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DomainProbe for FakeProbe {
        async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, VerifyError> {
            self.queried.lock().unwrap().push(name.to_string());
            Ok(self.txt.clone())
        }
        async fn fetch_http(&self, url: &str) -> Result<String, VerifyError> {
            self.queried.lock().unwrap().push(url.to_string());
            Ok(self.http.clone())
        }
    }

    #[test]
    fn normalize_strips_wildcard_dot_and_case() {
        assert_eq!(normalize_host("*.Example.COM."), "example.com");
        assert_eq!(normalize_host("  www.example.com  "), "www.example.com");
    }

    #[test]
    fn challenge_naming_is_stable() {
        let v = fixed(VerificationMethod::Dns);
        assert_eq!(v.dns_record_name(), "_boatramp-verify.example.com");
        assert_eq!(
            v.http_challenge_url(),
            "http://example.com/.well-known/boatramp-domain-verification/\
             deadbeefdeadbeefdeadbeefdeadbeef"
        );
    }

    #[test]
    fn method_parse_roundtrips() {
        assert_eq!(
            "dns".parse::<VerificationMethod>().unwrap(),
            VerificationMethod::Dns
        );
        assert_eq!(
            "HTTP".parse::<VerificationMethod>().unwrap(),
            VerificationMethod::Http
        );
        assert_eq!(
            "txt".parse::<VerificationMethod>().unwrap(),
            VerificationMethod::Dns
        );
        assert!("smtp".parse::<VerificationMethod>().is_err());
    }

    #[test]
    fn new_generates_distinct_unverified_tokens() {
        let a = DomainVerification::new("*.Example.com", VerificationMethod::Dns, 7);
        let b = DomainVerification::new("example.com", VerificationMethod::Dns, 7);
        assert_eq!(a.host, "example.com");
        assert!(!a.verified);
        assert_eq!(a.token.len(), 32);
        assert_ne!(a.token, b.token, "tokens must be random per challenge");
    }

    #[test]
    fn json_roundtrip() {
        let v = fixed(VerificationMethod::Http);
        let bytes = v.to_json().unwrap();
        assert_eq!(DomainVerification::from_json(&bytes).unwrap(), v);
    }

    #[test]
    fn pending_challenge_expires_after_ttl() {
        let v = fixed(VerificationMethod::Http); // created_at_unix = 100, unverified
        assert!(!v.is_expired(100));
        assert!(!v.is_expired(100 + CHALLENGE_TTL_SECS));
        assert!(v.is_expired(100 + CHALLENGE_TTL_SECS + 1));

        // A verified record never expires (it records proven ownership).
        let mut verified = v.clone();
        verified.verified = true;
        assert!(!verified.is_expired(100 + CHALLENGE_TTL_SECS + 10_000));

        // An unstamped *pending* record is treated as expired, so it can never be
        // redeemed via the self-serve route.
        let mut unstamped_pending = v.clone();
        unstamped_pending.created_at_unix = 0;
        assert!(unstamped_pending.is_expired(0));

        // …but an unstamped *verified* record (proven ownership) still never expires.
        let mut unstamped_verified = unstamped_pending.clone();
        unstamped_verified.verified = true;
        assert!(!unstamped_verified.is_expired(u64::MAX));
    }

    #[tokio::test]
    async fn dns_check_passes_when_a_txt_value_matches() {
        let v = fixed(VerificationMethod::Dns);
        let probe = FakeProbe {
            txt: vec!["unrelated".into(), v.token.clone()],
            http: String::new(),
            queried: Mutex::new(Vec::new()),
        };
        assert!(check_ownership(&probe, &v).await.unwrap());
        assert_eq!(
            probe.queried.lock().unwrap()[0],
            "_boatramp-verify.example.com"
        );
    }

    #[tokio::test]
    async fn dns_check_fails_when_no_value_matches() {
        let v = fixed(VerificationMethod::Dns);
        let probe = FakeProbe {
            txt: vec!["nope".into()],
            http: String::new(),
            queried: Mutex::new(Vec::new()),
        };
        assert!(!check_ownership(&probe, &v).await.unwrap());
    }

    #[tokio::test]
    async fn http_check_trims_and_matches_body() {
        let v = fixed(VerificationMethod::Http);
        let probe = FakeProbe {
            txt: Vec::new(),
            http: format!("  {}\n", v.token),
            queried: Mutex::new(Vec::new()),
        };
        assert!(check_ownership(&probe, &v).await.unwrap());
        assert!(probe.queried.lock().unwrap()[0].ends_with(&v.token));
    }

    #[tokio::test]
    async fn http_check_rejects_wrong_body() {
        let v = fixed(VerificationMethod::Http);
        let probe = FakeProbe {
            txt: Vec::new(),
            http: "something else".into(),
            queried: Mutex::new(Vec::new()),
        };
        assert!(!check_ownership(&probe, &v).await.unwrap());
    }
}
