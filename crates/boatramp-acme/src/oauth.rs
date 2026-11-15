//! Shared host-side OAuth2 token exchange + caching for the DNS adapters that authenticate with a
//! LONG-LIVED credential and mint a SHORT-LIVED bearer token (cap-req #31 — GCP service-account
//! JWT-bearer, Azure service-principal client-credentials).
//!
//! The long-lived credential is what is sealed/persisted by the caller; the minted access token is held
//! ONLY in memory in a [`TokenCell`] and is NEVER sealed, returned to the guest, or logged. The token
//! endpoints are FIXED well-known hosts (the adapter pins them; a test may override to a local stub),
//! so this module never dials a credential-controlled host.

use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;

use crate::dns::DnsError;

/// Bound on a token-exchange HTTP round-trip, so a slow/hung token endpoint can't wedge a DNS write.
pub(crate) const TOKEN_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Refresh a cached token this many seconds BEFORE its stated expiry (clock-skew + in-flight slack).
const EXPIRY_SLACK_SECS: u64 = 60;

/// Seconds since the Unix epoch (monotonic enough for an expiry comparison).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A minted access token with its absolute expiry (unix seconds).
#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: u64,
}

/// An in-memory, per-adapter cache of the last minted access token. A plain `std::sync::Mutex` (held
/// only for the quick get/store, never across the await), so the async exchange future stays `Send` and
/// a thundering-herd on expiry costs at most a few extra exchanges (never a deadlock). The token is
/// confidential and never leaves this process's memory.
pub(crate) struct TokenCell(Mutex<Option<CachedToken>>);

impl TokenCell {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// The cached token if it is still comfortably valid, else `None` (needs a fresh exchange).
    fn valid(&self) -> Option<String> {
        let guard = self.0.lock().ok()?;
        let cached = guard.as_ref()?;
        if cached.expires_at > now_unix().saturating_add(EXPIRY_SLACK_SECS) {
            Some(cached.token.clone())
        } else {
            None
        }
    }

    /// Store a freshly-minted token with its `expires_in` (seconds from now).
    fn store(&self, token: String, expires_in: u64) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = Some(CachedToken {
                token,
                expires_at: now_unix().saturating_add(expires_in),
            });
        }
    }

    /// Return a valid token, running `exchange` (the provider-specific mint) only when the cache is
    /// empty or near-expiry, and caching the result. `exchange` yields `(access_token, expires_in)`.
    pub(crate) async fn get_or_exchange<F, Fut>(&self, exchange: F) -> Result<String, DnsError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(String, u64), DnsError>>,
    {
        if let Some(tok) = self.valid() {
            return Ok(tok);
        }
        let (token, expires_in) = exchange().await?;
        self.store(token.clone(), expires_in);
        Ok(token)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    /// Lifetime in seconds. Default to a conservative hour if the endpoint omits it.
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

fn default_expires_in() -> u64 {
    3600
}

/// POST a form-encoded body to a FIXED token `endpoint` (bounded by [`TOKEN_HTTP_TIMEOUT`]) and parse
/// `{ access_token, expires_in }`. A transport/non-2xx/parse failure is a GENERIC [`DnsError::Backend`]
/// — the credential/response detail is never surfaced (the caller maps it to a client-safe error).
pub(crate) async fn post_token(
    client: &reqwest::Client,
    endpoint: &str,
    form: &[(&str, &str)],
) -> Result<(String, u64), DnsError> {
    let resp = client
        .post(endpoint)
        .form(form)
        .timeout(TOKEN_HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|_| DnsError::Backend("token exchange request failed".into()))?
        .error_for_status()
        .map_err(|_| DnsError::Backend("token endpoint rejected the credential".into()))?;
    let body: TokenResponse = resp
        .json()
        .await
        .map_err(|_| DnsError::Backend("token endpoint returned an unparseable response".into()))?;
    if body.access_token.is_empty() {
        return Err(DnsError::Backend(
            "token endpoint returned an empty token".into(),
        ));
    }
    Ok((body.access_token, body.expires_in))
}

#[cfg(test)]
pub(crate) mod test_mock {
    //! A minimal raw-TCP HTTP/1.1 mock for the token endpoint (no extra deps): every request is
    //! answered with a canned token JSON, and the POST count is exposed so a test can prove caching.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a token-endpoint mock. Returns `(url, post_count)` — the URL to pass to
    /// `with_token_endpoint`, and a counter of POSTs received (proves cache hits avoid re-exchange).
    pub(crate) async fn spawn(body: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let c = c.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]);
                    if head.starts_with("POST") {
                        c.fetch_add(1, Ordering::SeqCst);
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}/token"), count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn oauth_gate_post_token_parses_and_caches() {
        let (url, count) =
            test_mock::spawn(r#"{"access_token":"minted-xyz","expires_in":3600}"#).await;
        let client = reqwest::Client::new();
        let cell = TokenCell::new();
        // First get → exchanges (1 POST).
        let t1 = cell
            .get_or_exchange(|| post_token(&client, &url, &[("grant_type", "x")]))
            .await
            .unwrap();
        assert_eq!(t1, "minted-xyz");
        // Second get → served from cache (no new POST).
        let t2 = cell
            .get_or_exchange(|| post_token(&client, &url, &[("grant_type", "x")]))
            .await
            .unwrap();
        assert_eq!(t2, "minted-xyz");
        assert_eq!(count.load(Ordering::SeqCst), 1, "the second get was cached");
    }

    #[tokio::test]
    async fn oauth_gate_empty_token_is_backend_error() {
        let (url, _c) = test_mock::spawn(r#"{"access_token":"","expires_in":10}"#).await;
        let client = reqwest::Client::new();
        assert!(
            post_token(&client, &url, &[("grant_type", "x")])
                .await
                .is_err()
        );
    }
}
