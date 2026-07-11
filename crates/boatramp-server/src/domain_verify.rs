//! Server side of domain ownership verification.
//!
//! Holds the real network [`DomainProbe`] and the control-plane endpoints that
//! issue a challenge, check it, and — on success — attach the host to the
//! site's [`SiteConfig`] so it routes and becomes eligible for ACME.
//!
//! The HTTP-token method works in every build (it only needs an outbound HTTP
//! client). The DNS-TXT method needs a stub resolver and is compiled in only
//! with the `domain-verify-dns` feature (a public-DNS lookup is a live network
//! call — its mechanism is built here and tested via the core fake probe; the
//! against-the-internet leg is exercised in live testing). Without the feature the DNS
//! method returns a clear, actionable error instead of silently failing.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use boatramp_core::deploy::DeployStore;
use boatramp_core::domain_verify::{
    check_ownership, DomainProbe, DomainVerification, VerificationMethod, VerifyError,
};
use serde::{Deserialize, Serialize};

use crate::deploy_error_response;

/// Seconds since the Unix epoch, for challenge timestamps.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The real ownership probe: fetch over HTTP (always), resolve TXT over DNS
/// (only with the `domain-verify-dns` feature). Injected into
/// [`check_ownership`].
pub struct ServerDomainProbe {
    http: reqwest::Client,
    /// Permit HTTP challenges to non-global hosts. The strict
    /// default is `false`: a challenge may only target a globally-routable host,
    /// so an authorized site user can't turn the verifier into a blind SSRF
    /// against localhost / metadata / private services. Set from the posture.
    allow_private: bool,
}

impl ServerDomainProbe {
    /// A probe with a short-timeout HTTP client dedicated to challenge fetches.
    /// It never carries the operator's API token (challenges are non-secret).
    pub fn new(allow_private: bool) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("boatramp-domain-verify")
            // Never follow redirects: a challenge token is served directly (200),
            // and the resolve-once address pin only covers the first hop — a 3xx
            // to a different host would be re-resolved via the system resolver,
            // defeating the SSRF guard (e.g. a redirect to 169.254.169.254).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            http,
            allow_private,
        }
    }

    /// An HTTP client pinned to the challenge URL's resolved address, refusing a
    /// non-global target unless `allow_private`. Resolving once and
    /// pinning closes the DNS-rebinding window. When private targets are allowed
    /// (single-operator / dev posture) the shared client is reused as-is.
    async fn pinned_client_for(&self, url: &str) -> Result<reqwest::Client, VerifyError> {
        if self.allow_private {
            return Ok(self.http.clone());
        }
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| VerifyError::Probe(format!("bad challenge url: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| VerifyError::Probe("challenge url has no host".into()))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let mut pinned = None;
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if !boatramp_core::access::is_global_ip(addr.ip()) {
                        return Err(VerifyError::Probe(format!(
                            "challenge host {host} resolves to a non-global address \
                             ({}) — refused",
                            addr.ip()
                        )));
                    }
                    pinned.get_or_insert(addr);
                }
            }
            Err(e) => return Err(VerifyError::Probe(format!("resolving {host}: {e}"))),
        }
        let addr = pinned
            .ok_or_else(|| VerifyError::Probe(format!("challenge host {host} did not resolve")))?;
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("boatramp-domain-verify")
            .resolve(&host, addr)
            // No redirects — the pin is first-hop only (see `new`).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| VerifyError::Probe(e.to_string()))
    }
}

impl Default for ServerDomainProbe {
    fn default() -> Self {
        Self::new(false)
    }
}

#[async_trait::async_trait]
impl DomainProbe for ServerDomainProbe {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, VerifyError> {
        #[cfg(feature = "domain-verify-dns")]
        {
            resolve_txt(name).await
        }
        #[cfg(not(feature = "domain-verify-dns"))]
        {
            let _ = name;
            Err(VerifyError::Unsupported(VerificationMethod::Dns))
        }
    }

    async fn fetch_http(&self, url: &str) -> Result<String, VerifyError> {
        // Reject / pin the target before connecting.
        let client = self.pinned_client_for(url).await?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| VerifyError::Probe(e.to_string()))?
            .error_for_status()
            .map_err(|e| VerifyError::Probe(e.to_string()))?;
        let body = resp
            .text()
            .await
            .map_err(|e| VerifyError::Probe(e.to_string()))?;
        // A token is tiny; cap what we read so a bogus host can't stream forever.
        Ok(body.chars().take(4096).collect())
    }
}

/// Resolve TXT records over public DNS (the `domain-verify-dns` mechanism).
/// A name with no TXT records resolves to an empty list (verification then
/// cleanly fails), not an error.
#[cfg(feature = "domain-verify-dns")]
async fn resolve_txt(name: &str) -> Result<Vec<String>, VerifyError> {
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_resolver::TokioAsyncResolver;

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(resolver) => resolver,
        Err(_) => TokioAsyncResolver::tokio(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::config::ResolverOpts::default(),
        ),
    };
    let lookup = match resolver.txt_lookup(name).await {
        Ok(lookup) => lookup,
        Err(err) if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
            return Ok(Vec::new());
        }
        Err(err) => return Err(VerifyError::Probe(err.to_string())),
    };
    // A single TXT record may arrive as several ≤255-byte chunks; join them.
    let values = lookup
        .iter()
        .map(|txt| {
            txt.txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<String>()
        })
        .collect();
    Ok(values)
}

/// `?method=dns|http` on the start endpoint (default `http`, which works in
/// every build).
#[derive(Debug, Deserialize)]
pub(crate) struct StartQuery {
    method: Option<String>,
}

/// The result of a verification check, returned to the CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    /// The challenge after the check (its `verified` flag reflects the outcome).
    pub verification: DomainVerification,
    /// Whether ownership was proven this round.
    pub passed: bool,
    /// Whether the host was attached to the site's config (only on `passed`).
    pub attached: bool,
    /// A human-readable note on failure (what was expected / why it failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// `GET …/verification` — the current challenge for `(site, host)`, or 404.
pub(crate) async fn get_domain_verification(
    State(deploy): State<DeployStore>,
    Path((site, host)): Path<(String, String)>,
) -> Response {
    match deploy.get_domain_verification(&site, &host).await {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            "no verification challenge; start one with `domain add`\n",
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/sites/:site/domain-verifications` — every challenge for the site
/// (pending and verified), so the CLI can show in-progress verifications.
pub(crate) async fn list_domain_verifications(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
) -> Response {
    match deploy.list_domain_verifications(&site).await {
        Ok(list) => Json(list).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `POST …/verification?method=` — start (or return) a challenge.
pub(crate) async fn start_domain_verification(
    State(deploy): State<DeployStore>,
    Path((site, host)): Path<(String, String)>,
    Query(query): Query<StartQuery>,
) -> Response {
    let method = match query.method.as_deref() {
        None => VerificationMethod::Http,
        Some(raw) => match raw.parse::<VerificationMethod>() {
            Ok(method) => method,
            Err(err) => return (StatusCode::BAD_REQUEST, format!("{err}\n")).into_response(),
        },
    };
    match deploy
        .start_domain_verification(&site, &host, method, now_unix())
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE …/verification` — drop a host's challenge (used when detaching the
/// host). 204 whether or not one existed.
pub(crate) async fn remove_domain_verification(
    State(deploy): State<DeployStore>,
    Path((site, host)): Path<(String, String)>,
) -> Response {
    match deploy.remove_domain_verification(&site, &host).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `POST …/verification/check` — run the probe; on success mark verified and
/// attach the host to the site's config.
pub(crate) async fn check_domain_verification(
    State(deploy): State<DeployStore>,
    Extension(probe): Extension<Arc<dyn DomainProbe>>,
    Path((site, host)): Path<(String, String)>,
) -> Response {
    let verification = match deploy.get_domain_verification(&site, &host).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "no verification challenge; start one with `domain add`\n",
            )
                .into_response()
        }
        Err(err) => return deploy_error_response(err),
    };

    match check_ownership(probe.as_ref(), &verification).await {
        Ok(true) => {
            let verified = match deploy.mark_domain_verified(&site, &host).await {
                Ok(v) => v,
                Err(err) => return deploy_error_response(err),
            };
            let attached = match deploy.attach_verified_domain(&site, &host).await {
                Ok(_) => true,
                Err(err) => return deploy_error_response(err),
            };
            Json(CheckResult {
                verification: verified,
                passed: true,
                attached,
                detail: None,
            })
            .into_response()
        }
        Ok(false) => Json(CheckResult {
            verification,
            passed: false,
            attached: false,
            detail: Some("challenge token not found at the expected location yet".into()),
        })
        .into_response(),
        // The method isn't compiled into this build (DNS without the feature).
        Err(VerifyError::Unsupported(method)) => (
            StatusCode::NOT_IMPLEMENTED,
            format!(
                "verification method `{method}` is not supported by this build; \
                 use `--method http` or rebuild with the `domain-verify-dns` feature\n"
            ),
        )
            .into_response(),
        // The probe itself failed (network/resolver) — upstream, not our fault.
        Err(err) => (StatusCode::BAD_GATEWAY, format!("{err}\n")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With the strict posture, an HTTP challenge to a non-global
    /// host (here loopback) is refused before any connection — no blind SSRF.
    #[tokio::test]
    async fn http_probe_refuses_non_global_host() {
        let probe = ServerDomainProbe::new(false);
        let err = probe
            .fetch_http("http://127.0.0.1:9/.well-known/boatramp-challenge")
            .await
            .expect_err("loopback must be refused");
        let VerifyError::Probe(msg) = err else {
            panic!("expected a Probe rejection, got {err:?}");
        };
        assert!(
            msg.contains("non-global"),
            "rejection should name the non-global refusal, got: {msg}"
        );
    }
}
