//! Shared helpers for the HTTP-client subcommands (sync, deployments, rollback).

use boatramp_core::time::now_unix;
use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::config::SiteConfig;
use boatramp_core::cose::{self, LocalSigner, PopClaims};
use boatramp_core::deploy::{DeploymentList, Manifest};
use boatramp_core::domain_verify::DomainVerification;
use serde::{Deserialize, Serialize};

use crate::config::ProjectConfig;

/// A failure talking to the boatramp control-plane API.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No server URL was configured (pass `--server` or set `publish.server`).
    #[error("no server configured; pass --server or set publish.server")]
    NoServer,
    /// No site was configured (pass `--site` or set `publish.site`).
    #[error("no site configured; pass --site or set publish.site")]
    NoSite,
    /// An HTTP request to the control plane failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// Reading a local artifact (kernel/rootfs/blob) file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `client` module result: a control-plane API call; `Err` is [`ClientError`].
type Result<T> = std::result::Result<T, ClientError>;

/// Resolve the API token from `BOATRAMP_TOKEN` or `publish.token`.
pub fn token(config: &ProjectConfig) -> Option<String> {
    std::env::var("BOATRAMP_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .or_else(|| config.publish.token.clone())
}

/// Build an HTTP client that sends `Authorization: Bearer <token>` when present,
/// and — when a **holder key** and canonical origin are configured — signs a fresh
/// per-request proof-of-possession (DPoP) into the `Boatramp-PoP` header.
///
/// PoP signing turns on when all of `token`, `BOATRAMP_TOKEN_HOLDER_KEY`
/// (`"<alg>:<hex>"`, the private half of the token's `cnf`), and
/// `BOATRAMP_POP_ORIGIN` (the server's canonical origin, matching its
/// `[serve] pop_origin`) are present; otherwise the client is a plain bearer client
/// (unchanged). This is a *single* seam — every request through the returned
/// [`ApiClient`] is signed, with no per-call-site change.
///
/// When `BOATRAMP_SERVER_PUBKEY` is set (the raw-public-key SPKI hex that
/// `boatramp serve --tls rpk` prints), the client **pins** the control plane to
/// that RFC 7250 identity — so the operator reaches an `--tls rpk` server over an
/// encrypted, authenticated channel with no ACME/tunnel/proxy, on day zero. A
/// malformed pin is ignored (falls back to normal WebPKI TLS) rather than
/// silently disabling verification.
pub fn http_client(token: Option<&str>) -> ApiClient {
    let holder = std::env::var("BOATRAMP_TOKEN_HOLDER_KEY")
        .ok()
        .filter(|v| !v.is_empty());
    let origin = std::env::var("BOATRAMP_POP_ORIGIN")
        .ok()
        .filter(|v| !v.is_empty());
    let server_pubkey = std::env::var("BOATRAMP_SERVER_PUBKEY")
        .ok()
        .filter(|v| !v.is_empty());
    build_client(
        token,
        holder.as_deref(),
        origin.as_deref(),
        server_pubkey.as_deref(),
    )
}

/// The explicit-parameter builder behind [`http_client`] (which reads the same
/// values from the environment). PoP signing is enabled only when `token`,
/// `holder_key`, and `origin` are all `Some` (and the holder key parses).
pub fn build_client(
    token: Option<&str>,
    holder_key: Option<&str>,
    origin: Option<&str>,
    server_pubkey: Option<&str>,
) -> ApiClient {
    let mut builder = reqwest::Client::builder();
    if let Some(token) = token {
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
    }
    if let Some(hex) = server_pubkey {
        // The pinned rustls config's type is only inferred (never named), so the
        // CLI needs no direct `rustls` dep — `use_preconfigured_tls` takes `Any`.
        // The single logical control-plane peer is id `0`.
        if let Ok(spki) = boatramp_rpktls::parse_public_key(hex.trim()) {
            let trust = boatramp_rpktls::TrustSet::from_map(std::collections::BTreeMap::from([(
                0u64, spki,
            )]));
            if let Ok(config) = boatramp_rpktls::client_config_server_auth(trust, 0) {
                builder = builder.use_preconfigured_tls(config);
            }
        }
    }
    let inner = builder.build().unwrap_or_default();
    // Enable PoP signing only with a token + a parseable holder key + an origin.
    let pop = match (token, holder_key, origin) {
        (Some(token), Some(holder), Some(origin)) => LocalSigner::from_private_hex(holder.trim())
            .ok()
            .map(|holder| {
                Arc::new(PopSigner {
                    holder,
                    token: token.to_string(),
                    origin: origin.to_string(),
                })
            }),
        _ => None,
    };
    ApiClient { inner, pop }
}

/// A control-plane HTTP client that transparently attaches a per-request
/// proof-of-possession when a holder key is configured (see [`http_client`]). It
/// mirrors the slice of `reqwest`'s builder surface the CLI uses (`get`/`post`/
/// `put`/`delete` → `json`/`query`/`body`/`send`); `send()` returns a plain
/// [`reqwest::Response`], so response handling and error types are unchanged.
#[derive(Clone)]
pub struct ApiClient {
    inner: reqwest::Client,
    pop: Option<Arc<PopSigner>>,
}

impl ApiClient {
    /// Start a request with the given method + URL.
    fn request<U: reqwest::IntoUrl>(&self, method: reqwest::Method, url: U) -> ApiRequestBuilder {
        ApiRequestBuilder {
            inner: self.inner.request(method, url),
            client: self.inner.clone(),
            pop: self.pop.clone(),
        }
    }

    /// A `GET` request builder.
    pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> ApiRequestBuilder {
        self.request(reqwest::Method::GET, url)
    }
    /// A `POST` request builder.
    pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> ApiRequestBuilder {
        self.request(reqwest::Method::POST, url)
    }
    /// A `PUT` request builder.
    pub fn put<U: reqwest::IntoUrl>(&self, url: U) -> ApiRequestBuilder {
        self.request(reqwest::Method::PUT, url)
    }
    /// A `DELETE` request builder.
    pub fn delete<U: reqwest::IntoUrl>(&self, url: U) -> ApiRequestBuilder {
        self.request(reqwest::Method::DELETE, url)
    }
}

/// A request builder wrapping [`reqwest::RequestBuilder`], signing a PoP proof at
/// [`send`](Self::send) time when the [`ApiClient`] carries a holder key.
pub struct ApiRequestBuilder {
    inner: reqwest::RequestBuilder,
    client: reqwest::Client,
    pop: Option<Arc<PopSigner>>,
}

impl ApiRequestBuilder {
    /// Set a JSON body (mirrors [`reqwest::RequestBuilder::json`]).
    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> Self {
        self.inner = self.inner.json(json);
        self
    }
    /// Set a raw body (mirrors [`reqwest::RequestBuilder::body`]).
    pub fn body<T: Into<reqwest::Body>>(mut self, body: T) -> Self {
        self.inner = self.inner.body(body);
        self
    }
    /// Append URL query parameters (mirrors [`reqwest::RequestBuilder::query`]).
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        self.inner = self.inner.query(query);
        self
    }
    /// Set a request header (a malformed name/value is dropped by `reqwest`).
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.inner = self.inner.header(key, value);
        self
    }
    /// Build, (optionally) PoP-sign, and send the request. Returns the same
    /// [`reqwest::Response`]/[`reqwest::Error`] as a plain `reqwest` send.
    pub async fn send(self) -> reqwest::Result<reqwest::Response> {
        let mut request = self.inner.build()?;
        if let Some(pop) = &self.pop {
            pop.sign(&mut request).await;
        }
        self.client.execute(request).await
    }
}

/// Holds the token's holder (`cnf`) private key + the bound origin, and signs a
/// fresh [`PopClaims`] proof per request into the `Boatramp-PoP` header.
struct PopSigner {
    holder: LocalSigner,
    token: String,
    origin: String,
}

impl PopSigner {
    /// Attach a per-request PoP proof to `request` (best-effort: on any signing
    /// failure the request is sent unsigned, and the server rejects it — never a
    /// silent bypass, since the proof is *required* server-side for a `cnf` token).
    async fn sign(&self, request: &mut reqwest::Request) {
        // Bind the body hash only for a buffered body within the shared bound —
        // identical to the server's rule, so both agree on present-or-absent.
        let bh = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .filter(|b| !b.is_empty() && b.len() <= cose::POP_MAX_BODY_HASH_BYTES)
            .map(cose::pop_sha256_hex);
        let claims = PopClaims {
            htm: request.method().as_str().to_string(),
            htp: cose::canon_pop_path(request.url().path()),
            aud: self.origin.clone(),
            ath: cose::pop_sha256_hex(self.token.as_bytes()),
            bh,
        };
        let Ok(proof) = cose::mint_pop(&claims, &self.holder, now_unix()).await else {
            return;
        };
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&proof) {
            request.headers_mut().insert(
                reqwest::header::HeaderName::from_static("boatramp-pop"),
                value,
            );
        }
    }
}

/// Resolve the target project: `[publish].project` in config (which `main` has already
/// overlaid with `--project` / `BOATRAMP_PROJECT`), else the `default` project.
pub fn resolve_project(config: &ProjectConfig) -> String {
    config
        .publish
        .project
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| boatramp_core::project::DEFAULT_PROJECT.to_string())
}

/// Resolve the server base URL from a flag, falling back to config.
pub fn resolve_server(server: Option<String>, config: &ProjectConfig) -> Result<String> {
    let server = server
        .or_else(|| config.publish.server.clone())
        .ok_or(ClientError::NoServer)?;
    Ok(server.trim_end_matches('/').to_string())
}

/// Resolve the target server and build an authenticated client — the shared
/// preamble of every mutating subcommand. (Was reinvented verbatim as a private
/// `conn` in both `function` and `workflow`; it lives here so there is one.)
pub fn connect(server: Option<String>, config: &ProjectConfig) -> Result<(String, ApiClient)> {
    let server = resolve_server(server, config)?;
    let http = http_client(token(config).as_deref());
    Ok((server, http))
}

/// Resolve the (server base URL, site) target from flags, falling back to config.
pub fn resolve_target(
    server: Option<String>,
    site: Option<String>,
    config: &ProjectConfig,
) -> Result<(String, String)> {
    let server = resolve_server(server, config)?;
    let site = site
        .or_else(|| config.publish.site.clone())
        .ok_or(ClientError::NoSite)?;
    Ok((server, site))
}

// ---- control-plane requests -------------------------------------------------

/// Percent-encode a host for use as a URL path segment. Hostnames are
/// `[a-z0-9.-]` plus a leading `*.` for wildcards; only `*` needs escaping.
fn host_segment(host: &str) -> String {
    host.replace('*', "%2A")
}

/// The result of a `domain verify` check, shared with the server and console.
pub use boatramp_core::domain_verify::CheckResult;

/// The captured guest log line and logs endpoint response, shared with the
/// server and console.
pub use boatramp_core::logs::{LogEntry, LogsResponse};

/// Whether `s` is a bare content-address: a 64-char lowercase hex SHA-256, as
/// printed by [`hash_file`] / `blob put`. Distinguishes an existing blob hash
/// from a file path or URL in an artifact reference.
pub fn is_blob_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Stream-hash a file to its `sha256` hex (the blob's content-address).
pub async fn hash_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// A filesystem-safe temp-name fragment derived from a URL (last path segment).
fn sanitize(url: &str) -> String {
    url.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("download")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect()
}

/// The control plane's reply to a deployment negotiation (`POST …/deployments`):
/// the new deployment id and the blob hashes it is still missing (the ones the
/// client must upload). Shared by `sync` and `apply`.
#[derive(Debug, Deserialize)]
pub struct CreateDeploymentResponse {
    /// The created deployment's id.
    pub id: String,
    /// Blob hashes the server does not yet have and needs uploaded.
    pub missing: Vec<String>,
}

/// An authenticated control-plane connection: an [`ApiClient`] bound to a
/// resolved server base URL. The request methods key off it, so the client and
/// server base are threaded once (at construction) instead of by hand at every
/// call site.
pub struct ControlPlane {
    http: ApiClient,
    base: String,
    project: String,
}

impl ControlPlane {
    /// Wrap an already-built client and resolved server base.
    pub fn new(base: String, http: ApiClient, project: String) -> Self {
        Self {
            http,
            base,
            project,
        }
    }

    /// The site-collection URL segment: `sites` for the default project (byte-identical
    /// legacy `/api/sites/...`), else `projects/<proj>/sites` for a named project.
    fn sites_seg(&self) -> String {
        if self.project == boatramp_core::project::DEFAULT_PROJECT {
            "sites".to_string()
        } else {
            format!("projects/{}/sites", self.project)
        }
    }

    /// The function-collection URL segment: `functions` for the default project
    /// (byte-identical legacy `/api/functions/...`), else `projects/<proj>/functions`.
    fn functions_seg(&self) -> String {
        if self.project == boatramp_core::project::DEFAULT_PROJECT {
            "functions".to_string()
        } else {
            format!("projects/{}/functions", self.project)
        }
    }

    /// The compute-collection URL segment: `compute` for the default project
    /// (byte-identical legacy `/api/compute/...`), else `projects/<proj>/compute`.
    fn compute_seg(&self) -> String {
        if self.project == boatramp_core::project::DEFAULT_PROJECT {
            "compute".to_string()
        } else {
            format!("projects/{}/compute", self.project)
        }
    }

    /// Fetch the manifest for a specific deployment id.
    pub async fn fetch_manifest(&self, site: &str, id: &str) -> Result<Manifest> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{site}/deployments/{id}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch a site's deployment list (current + history).
    pub async fn fetch_deployments(&self, site: &str) -> Result<DeploymentList> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{site}/deployments"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch a site's config (server returns defaults if unset).
    pub async fn fetch_site_config(&self, site: &str) -> Result<SiteConfig> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{site}/config"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Replace a site's config.
    pub async fn put_site_config(&self, site: &str, config: &SiteConfig) -> Result<()> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .put(format!("{server}/api/{seg}/{site}/config"))
            .json(config)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Start (or fetch the existing) ownership challenge for a host.
    pub async fn start_domain_verification(
        &self,
        site: &str,
        host: &str,
        method: Option<&str>,
    ) -> Result<DomainVerification> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut url = format!(
            "{server}/api/{seg}/{site}/domains/{}/verification",
            host_segment(host)
        );
        if let Some(method) = method {
            url.push_str(&format!("?method={method}"));
        }
        Ok(client
            .post(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Run the ownership check for a host; on success the server attaches it.
    pub async fn check_domain_verification(&self, site: &str, host: &str) -> Result<CheckResult> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .post(format!(
                "{server}/api/{seg}/{site}/domains/{}/verification/check",
                host_segment(host)
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Admin-only: attach a host to the site **without** an ownership proof
    /// (`domain add --unverified`). Returns the server's confirmation text. The
    /// server gates this route at `system·admin`, so a site-scoped token gets a 403.
    pub async fn attach_domain_unverified(&self, site: &str, host: &str) -> Result<String> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .post(format!(
                "{server}/api/{seg}/{site}/domains/{}/attach-unverified",
                host_segment(host)
            ))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
    }

    /// Drop a host's ownership challenge (when detaching the host).
    pub async fn remove_domain_verification(&self, site: &str, host: &str) -> Result<()> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .delete(format!(
                "{server}/api/{seg}/{site}/domains/{}/verification",
                host_segment(host)
            ))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// List all ownership challenges for a site (pending and verified).
    pub async fn list_domain_verifications(&self, site: &str) -> Result<Vec<DomainVerification>> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{site}/domain-verifications"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Activate a deployment id for a site (the atomic switch / rollback).
    pub async fn activate(&self, site: &str, id: &str) -> Result<()> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .post(format!(
                "{server}/api/{seg}/{site}/deployments/{id}/activate"
            ))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Negotiate a new deployment for a site (project-scoped): POST the manifest;
    /// the server stores it and replies with the blob hashes it is still missing.
    /// `query` carries deploy provenance (source/branch/author/message/tags).
    pub async fn create_deployment(
        &self,
        site: &str,
        manifest: &Manifest,
        query: &[(&str, String)],
    ) -> Result<CreateDeploymentResponse> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .post(format!("{server}/api/{seg}/{site}/deployments"))
            .query(query)
            .json(manifest)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Upload one missing blob by its content-address (streams a `File`, sends a
    /// `Memory` variant's bytes). Idempotent server-side. Mirrors the two-arm body
    /// of [`crate::sync::upload_blob`] but returns [`ClientError`] (its `File`/
    /// `Memory` open-and-send maps cleanly onto our `Io`/`Http` variants).
    pub async fn upload_blob_source(
        &self,
        hash: &str,
        source: &crate::sync::BlobSource,
    ) -> Result<()> {
        use crate::sync::BlobSource;
        let Self {
            http, base: server, ..
        } = self;
        let body = match source {
            BlobSource::File(path) => {
                let file = tokio::fs::File::open(path).await?;
                reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file))
            }
            BlobSource::Memory(bytes) => reqwest::Body::from(bytes.clone()),
        };
        http.put(format!("{server}/api/blobs/{hash}"))
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Deploy (create/replace) a top-level function (project-scoped): PUT the
    /// function record body (`{ component, config, lifecycle }`). Returns the
    /// server's stored record verbatim.
    pub async fn deploy_function(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let seg = self.functions_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .put(format!("{server}/api/{seg}/{name}"))
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Create/replace a compute workload (project-scoped): PUT the
    /// `PutComputeRequest`-shaped `body` straight to the server (it validates).
    /// Returns the server's stored record verbatim.
    pub async fn put_compute(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let seg = self.compute_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .put(format!("{server}/api/{seg}/{name}"))
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Point a named alias at a deployment id.
    pub async fn set_alias(&self, site: &str, name: &str, id: &str) -> Result<()> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        #[derive(Serialize)]
        struct SetAlias<'a> {
            id: &'a str,
        }
        client
            .put(format!("{server}/api/{seg}/{site}/aliases/{name}"))
            .json(&SetAlias { id })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// List a site's named aliases (`name → deployment id`).
    pub async fn list_aliases(&self, site: &str) -> Result<BTreeMap<String, String>> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{site}/aliases"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Remove a named alias.
    pub async fn remove_alias(&self, site: &str, name: &str) -> Result<()> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .delete(format!("{server}/api/{seg}/{site}/aliases/{name}"))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Fetch captured guest logs for a site: the most recent `limit` lines with
    /// `seq > after`, optionally filtered to one `stream` (`stdout`/`stderr`).
    pub async fn fetch_logs(
        &self,
        site: &str,
        limit: usize,
        after: u64,
        stream: Option<&str>,
    ) -> Result<LogsResponse> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut url =
            format!("{server}/api/{seg}/{site}/_boatramp/logs?limit={limit}&after={after}");
        if let Some(stream) = stream {
            url.push_str("&stream=");
            url.push_str(stream);
        }
        Ok(client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch a site's operator handler stats (raw JSON: handler invocation counters,
    /// consumer backlog/dead-letters, live stream connections).
    pub async fn fetch_handler_stats(&self, site: &str) -> Result<serde_json::Value> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{site}/_boatramp/handlers"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Run a dead-letter operation (`purge` or `redrive`) on a consumer `topic`
    /// (scope-relative; `alias` for a background-alias consumer). Returns the number
    /// of dead-lettered messages affected (`POST …/_boatramp/dlq`).
    pub async fn operate_dlq(
        &self,
        site: &str,
        topic: &str,
        alias: Option<&str>,
        action: &str,
    ) -> Result<usize> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        #[derive(Serialize)]
        struct Request<'a> {
            topic: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            alias: Option<&'a str>,
            action: &'a str,
        }
        #[derive(Deserialize)]
        struct DlqResponse {
            affected: usize,
        }
        let resp: DlqResponse = client
            .post(format!("{server}/api/{seg}/{site}/_boatramp/dlq"))
            .json(&Request {
                topic,
                alias,
                action,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp.affected)
    }

    /// Upload a file as a content-addressed blob (`PUT /api/blobs/<hash>`, streamed).
    /// Idempotent: re-uploading an existing blob is a no-op server-side.
    pub async fn upload_blob(&self, hash: &str, path: &std::path::Path) -> Result<()> {
        let Self {
            http, base: server, ..
        } = self;
        let file = tokio::fs::File::open(path).await?;
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
        http.put(format!("{server}/api/blobs/{hash}"))
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Hash a local file and upload it as a blob; returns its content-address.
    pub async fn put_file_blob(&self, path: &std::path::Path) -> Result<String> {
        let hash = hash_file(path).await?;
        self.upload_blob(&hash, path).await?;
        Ok(hash)
    }

    /// Resolve an **artifact reference** — a `--kernel` / `--rootfs` value — to a blob
    /// hash the server can stage. Accepts three forms:
    /// - a 64-hex content-address ⇒ used as-is (assumed already uploaded);
    /// - an `http(s)://` URL ⇒ downloaded to a temp file, then hashed + uploaded;
    /// - anything else ⇒ a local file path, hashed + uploaded.
    pub async fn resolve_artifact(&self, value: &str) -> Result<String> {
        if is_blob_hash(value) {
            return Ok(value.to_string());
        }
        if value.starts_with("http://") || value.starts_with("https://") {
            use tokio::io::AsyncWriteExt;
            // Stream the URL to a temp file, then hash + upload it like a local file.
            let mut resp = self.http.get(value).send().await?.error_for_status()?;
            let tmp = std::env::temp_dir().join(format!("boatramp-artifact-{}", sanitize(value)));
            let mut out = tokio::fs::File::create(&tmp).await?;
            while let Some(chunk) = resp.chunk().await? {
                out.write_all(&chunk).await?;
            }
            out.flush().await?;
            drop(out);
            let hash = self.put_file_blob(&tmp).await?;
            let _ = tokio::fs::remove_file(&tmp).await;
            return Ok(hash);
        }
        self.put_file_blob(std::path::Path::new(value)).await
    }

    // ---- projects (0.2.0) ---------------------------------------------------

    /// List every project (`GET /api/projects`).
    pub async fn list_projects(&self) -> Result<Vec<serde_json::Value>> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/projects"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Create a project (`POST /api/projects`); returns the created project.
    pub async fn create_project(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .post(format!("{server}/api/projects"))
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Read a project (`GET /api/projects/<name>`).
    pub async fn get_project(&self, name: &str) -> Result<serde_json::Value> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/projects/{name}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Delete a project (`DELETE /api/projects/<name>`). The server refuses a
    /// non-empty project or the reserved `default`.
    pub async fn delete_project(&self, name: &str) -> Result<()> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .delete(format!("{server}/api/projects/{name}"))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_hash_detection_is_exact() {
        let hash = "a".repeat(64);
        assert!(is_blob_hash(&hash), "64 lowercase hex is a blob hash");
        assert!(is_blob_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        // Not hashes: wrong length, uppercase, path, URL, non-hex.
        assert!(!is_blob_hash(&"a".repeat(63)));
        assert!(!is_blob_hash(&"a".repeat(65)));
        assert!(
            !is_blob_hash(&"A".repeat(64)),
            "uppercase is treated as a path, not a hash"
        );
        assert!(!is_blob_hash("./vmlinux"));
        assert!(!is_blob_hash("https://example.com/vmlinux"));
        assert!(!is_blob_hash(&"g".repeat(64)), "g is not a hex digit");
    }

    #[test]
    fn sites_seg_is_legacy_for_default_project() {
        let cp = |project: &str| {
            ControlPlane::new(
                "https://cp.example".into(),
                build_client(None, None, None, None),
                project.into(),
            )
        };
        // Default project keeps the byte-identical legacy `sites` segment.
        assert_eq!(
            cp(boatramp_core::project::DEFAULT_PROJECT).sites_seg(),
            "sites"
        );
        // A named project scopes under `projects/<name>/sites`.
        assert_eq!(cp("acme").sites_seg(), "projects/acme/sites");
    }

    #[test]
    fn resolve_project_falls_back_to_default() {
        use crate::config::ProjectConfig;
        // No `[publish].project` → the `default` project.
        let mut config = ProjectConfig::default();
        assert_eq!(
            resolve_project(&config),
            boatramp_core::project::DEFAULT_PROJECT
        );
        // An empty string is treated as unset (still `default`).
        config.publish.project = Some(String::new());
        assert_eq!(
            resolve_project(&config),
            boatramp_core::project::DEFAULT_PROJECT
        );
        // A named project wins.
        config.publish.project = Some("acme".into());
        assert_eq!(resolve_project(&config), "acme");
    }

    #[test]
    fn sanitize_url_to_temp_fragment() {
        assert_eq!(
            sanitize("https://example.com/path/vmlinux-6.1.bin"),
            "vmlinux-6.1.bin"
        );
        assert_eq!(sanitize("https://example.com/a b?c=d"), "a_b_c_d");
        assert_eq!(sanitize("https://example.com/"), "example.com");
    }

    // ---- DPoP round-trip: the PoP-signing client vs the real `require_auth` ----

    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{Claims, Signer, TokenAlg};
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_server::{require_auth, Auth};

    /// The server's canonical origin — the client binds it into every proof; the
    /// server compares proofs against *this*, never the request host.
    const POP_ORIGIN: &str = "https://cp.example.test";

    /// Spawn a minimal control-plane router (`GET /api/sites`) behind the real
    /// [`require_auth`] middleware carrying `auth`, on a random loopback port.
    async fn spawn_guarded(auth: Auth) -> std::net::SocketAddr {
        let app = axum::Router::new()
            .route("/api/sites", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(auth, require_auth));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn pop_signing_client_round_trips_against_require_auth() {
        // A holder-bound (cnf) admin token + its holder private key.
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let now = now_unix();
        let claims = Claims {
            roles: vec![GrantedRole::global("admin")],
            kind: "role".into(),
            ttl_secs: Some(3600),
            now_unix: now,
        };
        let token = cose::mint_delegatable(&claims, &holder.public_key(), &root)
            .await
            .unwrap();
        let holder_priv = holder.private_hex();

        // A server that requires a valid PoP for this (cnf) token, bound to ORIGIN.
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let auth = Auth::with_key(root.public_key(), kv).with_pop(Some(POP_ORIGIN.into()), false);
        let addr = spawn_guarded(auth).await;
        let url = format!("http://127.0.0.1:{}/api/sites", addr.port());

        // The PoP-signing client (correct holder key + origin) is authorized.
        let signed = build_client(Some(&token), Some(&holder_priv), Some(POP_ORIGIN), None);
        let resp = signed.get(&url).send().await.unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "signed request → 200"
        );

        // The same token with **no** proof (plain bearer client) is rejected 401 —
        // no silent bearer downgrade for a holder-bound token.
        let plain = build_client(Some(&token), None, None, None);
        let resp = plain.get(&url).send().await.unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "missing proof → 401"
        );

        // A proof bound to the wrong origin (what a spoofed relay would carry) is
        // rejected — the server binds its *configured* origin, not the request.
        let wrong_origin = build_client(
            Some(&token),
            Some(&holder_priv),
            Some("https://evil.example.test"),
            None,
        );
        let resp = wrong_origin.get(&url).send().await.unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "wrong-origin proof → 401"
        );
    }
}
