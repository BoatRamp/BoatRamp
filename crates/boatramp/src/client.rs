//! Shared helpers for the HTTP-client subcommands (sync, deployments, rollback).

use std::collections::BTreeMap;

use boatramp_core::config::SiteConfig;
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

/// Build an HTTP client that sends `Authorization: Bearer <token>` when present.
///
/// When `BOATRAMP_SERVER_PUBKEY` is set (the raw-public-key SPKI hex that
/// `boatramp serve --tls rpk` prints), the client **pins** the control plane to
/// that RFC 7250 identity — so the operator reaches an `--tls rpk` server over an
/// encrypted, authenticated channel with no ACME/tunnel/proxy, on day zero. A
/// malformed pin is ignored (falls back to normal WebPKI TLS) rather than
/// silently disabling verification.
pub fn http_client(token: Option<&str>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Some(token) = token {
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
    }
    if let Ok(hex) = std::env::var("BOATRAMP_SERVER_PUBKEY") {
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
    builder.build().unwrap_or_default()
}

/// Resolve the server base URL from a flag, falling back to config.
pub fn resolve_server(server: Option<String>, config: &ProjectConfig) -> Result<String> {
    let server = server
        .or_else(|| config.publish.server.clone())
        .ok_or(ClientError::NoServer)?;
    Ok(server.trim_end_matches('/').to_string())
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

/// Fetch the manifest for a specific deployment id.
pub async fn fetch_manifest(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    id: &str,
) -> Result<Manifest> {
    Ok(client
        .get(format!("{server}/api/sites/{site}/deployments/{id}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Fetch a site's deployment list (current + history).
pub async fn fetch_deployments(
    client: &reqwest::Client,
    server: &str,
    site: &str,
) -> Result<DeploymentList> {
    Ok(client
        .get(format!("{server}/api/sites/{site}/deployments"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Fetch a site's config (server returns defaults if unset).
pub async fn fetch_site_config(
    client: &reqwest::Client,
    server: &str,
    site: &str,
) -> Result<SiteConfig> {
    Ok(client
        .get(format!("{server}/api/sites/{site}/config"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Replace a site's config.
pub async fn put_site_config(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    config: &SiteConfig,
) -> Result<()> {
    client
        .put(format!("{server}/api/sites/{site}/config"))
        .json(config)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Percent-encode a host for use as a URL path segment. Hostnames are
/// `[a-z0-9.-]` plus a leading `*.` for wildcards; only `*` needs escaping.
fn host_segment(host: &str) -> String {
    host.replace('*', "%2A")
}

/// The result of a `domain verify` check (mirrors the server's `CheckResult`).
#[derive(Debug, Deserialize)]
pub struct VerificationCheck {
    pub verification: DomainVerification,
    pub passed: bool,
    pub attached: bool,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Start (or fetch the existing) ownership challenge for a host.
pub async fn start_domain_verification(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    host: &str,
    method: Option<&str>,
) -> Result<DomainVerification> {
    let mut url = format!(
        "{server}/api/sites/{site}/domains/{}/verification",
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
pub async fn check_domain_verification(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    host: &str,
) -> Result<VerificationCheck> {
    Ok(client
        .post(format!(
            "{server}/api/sites/{site}/domains/{}/verification/check",
            host_segment(host)
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Drop a host's ownership challenge (when detaching the host).
pub async fn remove_domain_verification(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    host: &str,
) -> Result<()> {
    client
        .delete(format!(
            "{server}/api/sites/{site}/domains/{}/verification",
            host_segment(host)
        ))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// List all ownership challenges for a site (pending and verified).
pub async fn list_domain_verifications(
    client: &reqwest::Client,
    server: &str,
    site: &str,
) -> Result<Vec<DomainVerification>> {
    Ok(client
        .get(format!("{server}/api/sites/{site}/domain-verifications"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Activate a deployment id for a site (the atomic switch / rollback).
pub async fn activate(client: &reqwest::Client, server: &str, site: &str, id: &str) -> Result<()> {
    client
        .post(format!(
            "{server}/api/sites/{site}/deployments/{id}/activate"
        ))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Point a named alias at a deployment id.
pub async fn set_alias(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    name: &str,
    id: &str,
) -> Result<()> {
    #[derive(Serialize)]
    struct SetAlias<'a> {
        id: &'a str,
    }
    client
        .put(format!("{server}/api/sites/{site}/aliases/{name}"))
        .json(&SetAlias { id })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// List a site's named aliases (`name → deployment id`).
pub async fn list_aliases(
    client: &reqwest::Client,
    server: &str,
    site: &str,
) -> Result<BTreeMap<String, String>> {
    Ok(client
        .get(format!("{server}/api/sites/{site}/aliases"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Remove a named alias.
pub async fn remove_alias(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    name: &str,
) -> Result<()> {
    client
        .delete(format!("{server}/api/sites/{site}/aliases/{name}"))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// One captured guest log line (a subset of the server's `logs::LogEntry`; the
/// `ts_ms` field is present in the response but not needed for the tail).
#[derive(Debug, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub stream: String,
    pub line: String,
}

/// The logs endpoint response.
#[derive(Debug, Deserialize)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
    pub dropped: u64,
}

/// Fetch captured guest logs for a site: the most recent `limit` lines with
/// `seq > after`, optionally filtered to one `stream` (`stdout`/`stderr`).
pub async fn fetch_logs(
    client: &reqwest::Client,
    server: &str,
    site: &str,
    limit: usize,
    after: u64,
    stream: Option<&str>,
) -> Result<LogsResponse> {
    let mut url = format!("{server}/api/sites/{site}/_boatramp/logs?limit={limit}&after={after}");
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
pub async fn fetch_handler_stats(
    client: &reqwest::Client,
    server: &str,
    site: &str,
) -> Result<serde_json::Value> {
    Ok(client
        .get(format!("{server}/api/sites/{site}/_boatramp/handlers"))
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
    client: &reqwest::Client,
    server: &str,
    site: &str,
    topic: &str,
    alias: Option<&str>,
    action: &str,
) -> Result<usize> {
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
        .post(format!("{server}/api/sites/{site}/_boatramp/dlq"))
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

// ---- content-addressed blobs (kernels, rootfs images, …) -------------------

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

/// Upload a file as a content-addressed blob (`PUT /api/blobs/<hash>`, streamed).
/// Idempotent: re-uploading an existing blob is a no-op server-side.
pub async fn upload_blob(
    http: &reqwest::Client,
    server: &str,
    hash: &str,
    path: &std::path::Path,
) -> Result<()> {
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
pub async fn put_file_blob(
    http: &reqwest::Client,
    server: &str,
    path: &std::path::Path,
) -> Result<String> {
    let hash = hash_file(path).await?;
    upload_blob(http, server, &hash, path).await?;
    Ok(hash)
}

/// Resolve an **artifact reference** — a `--kernel` / `--rootfs` value — to a blob
/// hash the server can stage. Accepts three forms:
/// - a 64-hex content-address ⇒ used as-is (assumed already uploaded);
/// - an `http(s)://` URL ⇒ downloaded to a temp file, then hashed + uploaded;
/// - anything else ⇒ a local file path, hashed + uploaded.
pub async fn resolve_artifact(http: &reqwest::Client, server: &str, value: &str) -> Result<String> {
    if is_blob_hash(value) {
        return Ok(value.to_string());
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        use tokio::io::AsyncWriteExt;
        // Stream the URL to a temp file, then hash + upload it like a local file.
        let mut resp = http.get(value).send().await?.error_for_status()?;
        let tmp = std::env::temp_dir().join(format!("boatramp-artifact-{}", sanitize(value)));
        let mut out = tokio::fs::File::create(&tmp).await?;
        while let Some(chunk) = resp.chunk().await? {
            out.write_all(&chunk).await?;
        }
        out.flush().await?;
        drop(out);
        let hash = put_file_blob(http, server, &tmp).await?;
        let _ = tokio::fs::remove_file(&tmp).await;
        return Ok(hash);
    }
    put_file_blob(http, server, std::path::Path::new(value)).await
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
    fn sanitize_url_to_temp_fragment() {
        assert_eq!(
            sanitize("https://example.com/path/vmlinux-6.1.bin"),
            "vmlinux-6.1.bin"
        );
        assert_eq!(sanitize("https://example.com/a b?c=d"), "a_b_c_d");
        assert_eq!(sanitize("https://example.com/"), "example.com");
    }
}
