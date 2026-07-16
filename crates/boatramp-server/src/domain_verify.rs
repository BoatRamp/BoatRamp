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
        // Follow redirects **manually**, re-validating every hop — a
        // TLS-terminating platform (fly, Cloudflare, a reverse proxy) commonly
        // 301/308s `:80→:443`, and the token then lives on `:443`. Each hop goes
        // back through `pinned_client_for`, which resolves the target, refuses a
        // non-global address, and pins to it — so following a redirect can't be
        // turned into an SSRF to `169.254.169.254`/localhost/internal (the reason
        // the reqwest clients set `redirect::Policy::none()`; we do the hops here
        // with per-hop validation, like ACME HTTP-01).
        const MAX_HOPS: usize = 5;
        let mut current = url.to_string();
        for _ in 0..=MAX_HOPS {
            let client = self.pinned_client_for(&current).await?;
            let resp = client
                .get(&current)
                .send()
                .await
                .map_err(|e| VerifyError::Probe(e.to_string()))?;
            if resp.status().is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        VerifyError::Probe(format!("redirect {} without a Location", resp.status()))
                    })?;
                // Resolve a relative `Location` against the current URL.
                let next = reqwest::Url::parse(&current)
                    .and_then(|base| base.join(location))
                    .map_err(|e| VerifyError::Probe(format!("bad redirect Location: {e}")))?;
                if !matches!(next.scheme(), "http" | "https") {
                    return Err(VerifyError::Probe(format!(
                        "refusing non-HTTP redirect to {next}"
                    )));
                }
                current = next.into();
                continue;
            }
            let resp = resp
                .error_for_status()
                .map_err(|e| VerifyError::Probe(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| VerifyError::Probe(e.to_string()))?;
            // A token is tiny; cap what we read so a bogus host can't stream forever.
            return Ok(body.chars().take(4096).collect());
        }
        Err(VerifyError::Probe(format!(
            "too many redirects (more than {MAX_HOPS})"
        )))
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

/// `POST …/domains/:host/attach-unverified` — **admin-only** (gated at
/// `system·admin` in [`crate::authz`]): attach a host to the site **without** an
/// ownership proof. The admin asserts ownership out-of-band; boatramp records a
/// verified (operator-asserted) challenge and attaches it, so the strict serving
/// gate then treats the host as a normal verified virtualhost. A site-scoped
/// publisher cannot reach this route — only an admin can claim an arbitrary host.
pub(crate) async fn attach_domain_unverified(
    State(deploy): State<DeployStore>,
    Path((site, host)): Path<(String, String)>,
) -> Response {
    // A wildcard needs the DNS method to satisfy `attach_verified_domain`'s
    // wildcard rule; an exact host uses HTTP. Either way the proof is skipped.
    let method = if host.starts_with("*.") {
        VerificationMethod::Dns
    } else {
        VerificationMethod::Http
    };
    if let Err(err) = deploy
        .start_domain_verification(&site, &host, method, now_unix())
        .await
    {
        return deploy_error_response(err);
    }
    if let Err(err) = deploy.mark_domain_verified(&site, &host).await {
        return deploy_error_response(err);
    }
    match deploy.attach_verified_domain(&site, &host).await {
        Ok(_) => (
            StatusCode::OK,
            format!("attached {host} to site {site} without verification (admin override)\n"),
        )
            .into_response(),
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

/// The reconcile-loop interval shown on the pending page — keep in sync with the
/// serve loop's `DOMAIN_VERIFY_RECONCILE_TICK` (60s) so the "just wait" promise is
/// honest.
const RECONCILE_HINT_SECS: u32 = 60;

/// HTML-escape a value substituted into the pending page (the host and token are
/// attacker-influenced, so this runs on every interpolation).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The "verification pending" holding page — an **HTTP 421 Misdirected Request**
/// served for a non-local `Host` that isn't a verified, attached virtualhost
/// (DV-2's mandatory-verification gate). It looks up any pending challenge for the
/// host to show the exact token / record + path; otherwise it shows generic
/// guidance. Self-contained HTML (no JS, no external assets) — safe on an
/// unverified host.
pub async fn verification_pending_page(deploy: &DeployStore, host: &str) -> Response {
    let host_norm = host.trim_end_matches('.').to_ascii_lowercase();
    // A pending challenge for this exact host (any site), if the operator started
    // one — so the page can show the real token + record to publish.
    let pending = deploy
        .list_all_domain_verifications()
        .await
        .ok()
        .and_then(|all| {
            all.into_iter()
                .find(|(_, v)| !v.verified && v.host == host_norm)
        });
    let (token, http_path) = match &pending {
        Some((_, v)) => (v.token.clone(), v.http_challenge_path()),
        None => (
            "run `boatramp domain add` to start".to_string(),
            "/.well-known/boatramp-domain-verification/<token>".to_string(),
        ),
    };
    let html = include_str!("verification_pending.html")
        .replace("{{HOST}}", &html_escape(&host_norm))
        .replace(
            "{{VERIFY_DNS_NAME}}",
            &html_escape(&format!("_boatramp-verify.{host_norm}")),
        )
        .replace("{{VERIFY_TOKEN}}", &html_escape(&token))
        .replace("{{VERIFY_HTTP_PATH}}", &html_escape(&http_path))
        .replace("{{RECONCILE_SECONDS}}", &RECONCILE_HINT_SECS.to_string())
        .replace("{{DNS_PROVIDER}}", "cloudflare")
        .replace(
            "{{DOCS_URL}}",
            "https://docs.boatramp.dev/how-to/custom-domain.html",
        );
    (
        StatusCode::MISDIRECTED_REQUEST,
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // No JS, no external fetches — lock it down so a future regression
            // can't introduce a sink on this attacker-adjacent host.
            (
                axum::http::header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
            ),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        html,
    )
        .into_response()
}

/// One reconcile sweep: enumerate every site's **pending** (unverified, unexpired)
/// verification and re-run the ownership probe, attaching any that now pass.
/// Returns the count newly attached. Per-host failures are logged and skipped so
/// one unreachable host never stalls the sweep.
async fn reconcile_domain_verifications(
    deploy: &DeployStore,
    probe: &dyn DomainProbe,
) -> Result<usize, boatramp_core::error::DeployError> {
    // Bound the outbound-probe fan-out per tick even across many sites: any
    // remaining pending hosts are simply retried on the next tick. Combined with
    // the per-site pending cap (`start_domain_verification`) this keeps the sweep
    // from being turned into a high-rate egress amplifier.
    const MAX_PROBES_PER_TICK: usize = 256;
    let now = now_unix();
    let mut attached = 0usize;
    let mut probes = 0usize;
    for (site, v) in deploy.list_all_domain_verifications().await? {
        if v.verified || v.is_expired(now) {
            continue;
        }
        if probes >= MAX_PROBES_PER_TICK {
            tracing::debug!(
                probed = probes,
                "domain-verify reconcile: probe budget reached; remaining hosts next tick"
            );
            break;
        }
        probes += 1;
        // Not satisfied yet, or the probe/method failed (network / a DNS method on
        // a build without the resolver) ⇒ leave it pending and retry next tick.
        if let Ok(true) = check_ownership(probe, &v).await {
            if let Err(err) = deploy.mark_domain_verified(&site, &v.host).await {
                tracing::debug!(%site, host = %v.host, %err, "domain-verify reconcile: mark failed");
                continue;
            }
            match deploy.attach_verified_domain(&site, &v.host).await {
                Ok(_) => {
                    attached += 1;
                    tracing::info!(%site, host = %v.host, "domain-verify reconcile: verified + attached");
                }
                Err(err) => {
                    tracing::debug!(%site, host = %v.host, %err, "domain-verify reconcile: attach failed");
                }
            }
        }
    }
    Ok(attached)
}

/// Spawn the domain-verification **auto-complete reconcile loop**: every `tick`,
/// on the leader, re-check all pending challenges and attach any that now pass —
/// so a challenge whose HTTP/DNS token is published (e.g. by `domain add
/// --provider`) but never finished with `domain verify` self-heals with no
/// operator action, and no persistent background daemon is needed beyond this
/// tick. Mirrors [`crate::spawn_compute_reconcile`]; the leader gate makes it a
/// single-writer in a cluster.
pub fn spawn_domain_verify_reconcile(
    deploy: DeployStore,
    allow_private: bool,
    is_leader: crate::CronLeaderGate,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    // One stateless probe for the loop's lifetime; `allow_private` follows the
    // posture (a strict fleet verifies only globally-routable hosts).
    let probe: Arc<dyn DomainProbe> = Arc::new(ServerDomainProbe::new(allow_private));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        // `interval` fires immediately; skip that first tick so the sweep waits a
        // full period before its first run (the router is already serving).
        interval.tick().await;
        loop {
            interval.tick().await;
            if !is_leader() {
                continue;
            }
            match reconcile_domain_verifications(&deploy, probe.as_ref()).await {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        attached = n,
                        "domain-verify reconcile: attached pending hosts"
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(%err, "domain-verify reconcile tick failed"),
            }
        }
    })
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

    /// The probe follows a `:80→:443`-style redirect (here a plain 302 to another
    /// path) to fetch the token — so a host behind a TLS-terminating platform that
    /// redirects to HTTPS still verifies. `allow_private` lets the loopback test
    /// server through the SSRF guard (each hop is still resolved + `is_global_ip`-
    /// checked in production).
    #[tokio::test]
    async fn http_probe_follows_a_redirect_to_the_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    // Keep-alive: handle each request on the connection.
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let resp = if req.contains("GET /redirect") {
                            "HTTP/1.1 302 Found\r\nLocation: /token\r\nContent-Length: 0\r\n\r\n"
                                .to_string()
                        } else {
                            let body = "verify-token-xyz";
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            )
                        };
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = sock.flush().await;
                    }
                });
            }
        });

        let probe = ServerDomainProbe::new(true);
        let body = probe
            .fetch_http(&format!("http://127.0.0.1:{port}/redirect"))
            .await
            .expect("the redirect must be followed to the token");
        assert_eq!(body, "verify-token-xyz");
    }

    /// A blob store the reconcile path never touches (verifications + attached
    /// hostnames live in the KV, not in blob storage).
    struct NullStorage;
    #[async_trait::async_trait]
    impl boatramp_core::Storage for NullStorage {
        async fn get(
            &self,
            _: &str,
        ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: boatramp_core::ByteStream,
            _: boatramp_core::PutMeta,
        ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::unsupported("null"))
        }
        async fn head(
            &self,
            _: &str,
        ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), boatramp_core::StorageError> {
            Ok(())
        }
        async fn list(
            &self,
            _: &str,
        ) -> Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError> {
            Ok(Vec::new())
        }
    }

    /// A probe that serves the challenge token for both HTTP and TXT — so the
    /// challenge it's asked about always passes.
    struct TokenProbe {
        token: String,
    }
    #[async_trait::async_trait]
    impl DomainProbe for TokenProbe {
        async fn lookup_txt(&self, _: &str) -> Result<Vec<String>, VerifyError> {
            Ok(vec![self.token.clone()])
        }
        async fn fetch_http(&self, _: &str) -> Result<String, VerifyError> {
            Ok(self.token.clone())
        }
    }

    #[tokio::test]
    async fn reconcile_attaches_a_now_passing_pending_host() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::kv::MemoryKv;

        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        // A pending HTTP challenge for a host on site `www` — not yet attached.
        let v = deploy
            .start_domain_verification("www", "example.com", VerificationMethod::Http, now_unix())
            .await
            .unwrap();
        assert!(!v.verified);
        assert!(deploy
            .resolve_site_by_host("example.com")
            .await
            .unwrap()
            .is_none());

        // The token is now served → one reconcile sweep verifies + attaches it.
        let probe = TokenProbe {
            token: v.token.clone(),
        };
        assert_eq!(
            reconcile_domain_verifications(&deploy, &probe)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            deploy
                .resolve_site_by_host("example.com")
                .await
                .unwrap()
                .as_deref(),
            Some("www")
        );
        // Idempotent: a second sweep sees it already verified and attaches nothing.
        assert_eq!(
            reconcile_domain_verifications(&deploy, &probe)
                .await
                .unwrap(),
            0
        );
    }
}
