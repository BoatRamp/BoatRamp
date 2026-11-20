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
    /// The control plane refused the request (`409`), carrying its own explanatory
    /// message — surfaced verbatim rather than as a generic HTTP status error.
    #[error("{0}")]
    Refused(String),
    /// An async (`?wait=false`) function deploy reached a terminal `failed` state, or did not
    /// reach a terminal state in the poll budget — carrying the server's coarse reason.
    #[error("{0}")]
    Deploy(String),
}

/// `client` module result: a control-plane API call; `Err` is [`ClientError`].
type Result<T> = std::result::Result<T, ClientError>;

/// The outcome of a [streaming clone](ApiClient::project_clone_from): either the cheap dry-run
/// PLAN (the default — manifest + diff, no stream), or the APPLIED result (the plan plus the final
/// import report, after streaming the bundle with live progress).
#[derive(Debug)]
pub enum CloneOutcome {
    /// Dry-run: the cheap plan of what a real clone would transfer/restore. Nothing was streamed.
    Planned(boatramp_core::project_export::ClonePlan),
    /// `--apply` (or `--clone-verify`): the plan that was executed plus the final import report.
    Applied {
        plan: boatramp_core::project_export::ClonePlan,
        report: boatramp_core::project_export::ImportReport,
    },
}

/// Clone-robustness knobs (PLAN-clone-robustness #1 + #2 + #3) shared by
/// [`ApiClient::project_import`] and [`ApiClient::project_clone_from`] — carried to the node's
/// import as query params (file import) / JSON (clone). The [`Default`] (all-off) is the strict,
/// hard-fail-the-first-mismatch behaviour.
#[derive(Debug, Clone, Default)]
pub struct MismatchFlags {
    /// Scan ALL members, report EVERY declared≠streamed mismatch in one pass, fail at the end.
    pub enumerate: bool,
    /// Warn + continue past a mismatched member (not applied), scoped to re-generable `der/`.
    pub skip: bool,
    /// Broaden `skip` to ANY blob member (never a non-blob one) — the louder opt-in.
    pub skip_any_blob: bool,
    /// Clone-robustness (PLAN-clone-robustness #2): the raw `--continue-on-error` value — `None`
    /// ⇒ Off, `Some("all")` ⇒ forgive every kind, `Some("backend,member-mismatch")` ⇒ a kind list.
    /// Forwarded verbatim; the node parses it fail-closed (an unknown kind is a `400`).
    pub continue_on_error: Option<String>,
    /// Clone-robustness (PLAN-clone-robustness #3) REPAIR: the TARGET blob keys to restore
    /// EXCLUSIVELY (parsed from an `--only-blobs` manifest). Empty ⇒ restore everything.
    pub only_blobs: Vec<String>,
}

/// Give up resuming an interrupted clone only after this many CONSECUTIVE interruptions that made
/// **no forward progress** (the per-SHA diff showed the same number of blobs still to transfer). A
/// transfer that keeps progressing through periodic connection drops is resumed indefinitely; only a
/// genuinely stuck connection is abandoned, with the advice to re-run (which resumes).
const CLONE_RESUME_MAX_STALLED_ATTEMPTS: u32 = 6;

/// Backoff before re-issuing an interrupted clone: `1,2,4,8,16,30s` by consecutive-stall count
/// (capped at 30s), long enough to outlast a transient edge/proxy blip without hammering.
fn clone_resume_backoff(stalled: u32) -> std::time::Duration {
    std::time::Duration::from_secs((1u64 << stalled.min(5)).min(30))
}

/// The outcome of ONE `/clone/from` apply/verify attempt (one long-held streaming request).
///
/// The apply/verify transfer rides a SINGLE tens-of-minutes-long, near-idle HTTP response (only a
/// ~5s progress heartbeat flows on this connection — the bulk bytes move on the target's SEPARATE
/// pull from the source). An edge/proxy idle-cut or a transient reset severs the response body
/// mid-wait, which `reqwest` surfaces as `error decoding response body`. The clone is IDEMPOTENT and
/// RESUMABLE — the target restores each blob into its LIVE content-addressed store as it streams, and
/// the per-SHA presence diff skips already-restored blobs on a re-issue — so a transport interruption
/// is a [`Interrupted`](Self::Interrupted) that the caller RECOVERS by re-issuing, not a fatal error.
#[derive(Debug)]
enum CloneAttemptOutcome {
    /// The stream delivered a plan and a terminal report — the clone converged. Boxed so this
    /// (much larger) variant does not bloat every `Interrupted`/`Fatal` on the resume loop's hot path.
    Applied {
        plan: Box<boatramp_core::project_export::ClonePlan>,
        report: Box<boatramp_core::project_export::ImportReport>,
    },
    /// The response was severed before the terminal report (a transport reset/truncation, or a
    /// transient `502/503/504`): RESUMABLE. `remaining` is the blobs-still-to-transfer the attempt
    /// observed in its plan (`None` if cut before the plan arrived), used to detect forward progress
    /// across attempts.
    Interrupted {
        reason: String,
        remaining: Option<usize>,
    },
    /// A REAL failure — a terminal `Error` event from the target, a malformed progress line, or a
    /// non-transient refusal status — that re-issuing cannot fix. Surface it, do not retry.
    Fatal(String),
}

/// Advance the resume stall/progress accounting after one [`CloneAttemptOutcome::Interrupted`]. Pure
/// (no I/O) so the give-up policy is unit-tested without a live transfer. `remaining` is the
/// blobs-still-to-transfer the interrupted attempt observed. Returns the updated
/// `(stall, best_remaining)` and whether to GIVE UP (too many consecutive no-progress attempts).
fn clone_resume_step(
    stall: u32,
    best_remaining: Option<usize>,
    remaining: Option<usize>,
) -> (u32, Option<usize>, bool) {
    // Forward progress = fewer blobs still to transfer than the best we have ever seen. The first
    // measurement (no prior best) counts as progress so a transfer that is moving is never abandoned.
    let progressed = match (remaining, best_remaining) {
        (Some(r), Some(b)) => r < b,
        (Some(_), None) => true,
        (None, _) => false,
    };
    let best_remaining = match remaining {
        Some(r) => Some(best_remaining.map_or(r, |b| b.min(r))),
        None => best_remaining,
    };
    let stall = if progressed { 0 } else { stall + 1 };
    let give_up = stall >= CLONE_RESUME_MAX_STALLED_ATTEMPTS;
    (stall, best_remaining, give_up)
}

/// Drive ONE clone attempt's NDJSON progress stream to a [`CloneAttemptOutcome`]: parse each line,
/// surface the plan + transfer heartbeats on `tracing` (stderr) so the operator is never left in
/// silence, and collect the terminal report. A transport error from the body stream (the
/// `error decoding response body` the bug reported), or a clean end BEFORE the terminal report, is a
/// resumable [`Interrupted`](CloneAttemptOutcome::Interrupted); a terminal `Error` event or a
/// malformed line is [`Fatal`](CloneAttemptOutcome::Fatal). Generic over the chunk/error types so it
/// is driven by `reqwest`'s `bytes_stream()` in production and an in-memory stream in tests.
async fn drive_clone_ndjson<S, B, E>(stream: S, target: &str) -> CloneAttemptOutcome
where
    S: futures::Stream<Item = std::result::Result<B, E>>,
    B: AsRef<[u8]>,
    E: std::fmt::Display,
{
    use boatramp_core::project_export::CloneEvent;
    use futures::StreamExt as _;
    futures::pin_mut!(stream);
    let mut buf: Vec<u8> = Vec::new();
    let mut plan: Option<boatramp_core::project_export::ClonePlan> = None;
    let mut report: Option<boatramp_core::project_export::ImportReport> = None;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            // A transport-level body error mid-stream: the long-held response was severed (this is
            // the `error decoding response body` the bug surfaced). RESUMABLE — the target skips the
            // blobs already restored to its live store on a re-issue.
            Err(e) => {
                return CloneAttemptOutcome::Interrupted {
                    reason: e.to_string(),
                    remaining: plan.as_ref().map(|p| p.blobs_to_transfer),
                };
            }
        };
        buf.extend_from_slice(chunk.as_ref());
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let line = &line[..line.len() - 1];
            if line.is_empty() {
                continue;
            }
            let ev: CloneEvent = match serde_json::from_slice(line) {
                Ok(ev) => ev,
                Err(e) => {
                    return CloneAttemptOutcome::Fatal(format!(
                        "clone progress line was not valid JSON: {e}"
                    ));
                }
            };
            match ev {
                CloneEvent::Plan(p) => {
                    tracing::info!(
                        target = %target,
                        source = %p.source_project,
                        blobs_total = p.blobs_total,
                        blobs_present = p.blobs_present,
                        blobs_to_transfer = p.blobs_to_transfer,
                        bytes_to_transfer = p.bytes_to_transfer,
                        bytes_exact = p.bytes_exact,
                        "clone plan: transferring {} of {} blobs (~{} bytes){}",
                        p.blobs_to_transfer,
                        p.blobs_total,
                        p.bytes_to_transfer,
                        if p.bytes_exact { "" } else { "+" },
                    );
                    plan = Some(p);
                }
                CloneEvent::Progress {
                    bytes_transferred,
                    elapsed_secs,
                } => tracing::info!(
                    bytes_transferred,
                    elapsed_secs,
                    "clone progress: {bytes_transferred} bytes transferred in {elapsed_secs}s"
                ),
                CloneEvent::Report(r) => report = Some(r),
                CloneEvent::Error { message } => {
                    // A restore failure the target reported AFTER the stream opened — a REAL failure,
                    // not a transport drop. Re-issuing will not fix it; surface it.
                    return CloneAttemptOutcome::Fatal(format!(
                        "clone failed after the stream opened: {message}"
                    ));
                }
            }
        }
    }
    match (plan, report) {
        (Some(plan), Some(report)) => CloneAttemptOutcome::Applied {
            plan: Box::new(plan),
            report: Box::new(report),
        },
        // The stream ended cleanly WITHOUT both a plan and a terminal report — the connection was
        // closed before the terminal event arrived (a proxy closing the near-idle long-held
        // connection), or a malformed plan-less stream. RESUMABLE either way.
        (plan, _) => CloneAttemptOutcome::Interrupted {
            reason: "stream ended without a terminal report (truncated response)".into(),
            remaining: plan.as_ref().map(|p| p.blobs_to_transfer),
        },
    }
}

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
    if let Some(token) = token
        && let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
    {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, value);
        builder = builder.default_headers(headers);
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

/// The URL path segment for a resource collection under a project: the bare
/// `collection` for the reserved `default` project (byte-identical legacy
/// `/api/<collection>/…`), else `projects/<proj>/<collection>`. The single source of
/// the project-scoping rule, shared by [`ControlPlane`] and the imperative commands
/// (`sync` / `compute` / `function`) so `--project` routes the same everywhere.
pub fn project_seg(project: &str, collection: &str) -> String {
    if project == boatramp_core::project::DEFAULT_PROJECT {
        collection.to_string()
    } else {
        format!("projects/{project}/{collection}")
    }
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

/// Print one daemon-mediated blob-drain progress snapshot to stderr (a `"type":"progress"` NDJSON
/// line). Kept on stderr so stdout carries only the final report (`--json` stays parseable). Best
/// effort — a missing field renders `?`.
fn print_drain_progress(v: &serde_json::Value) {
    let n = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_u64)
            .map(|x| x.to_string())
            .unwrap_or_else(|| "?".to_string())
    };
    let dry = v
        .get("dry_run")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    eprintln!(
        "blob drain{}: {} / {} object(s) — copied {}, skipped {}, {} byte(s)",
        if dry { " (dry-run)" } else { "" },
        n("done"),
        n("total"),
        n("copied"),
        n("skipped"),
        n("copied_bytes"),
    );
}

/// Print one drained-source blob-purge progress snapshot to stderr (a `"type":"progress"` NDJSON
/// line). Same stderr-only discipline as [`print_drain_progress`] so `--json` stdout stays parseable.
fn print_purge_progress(v: &serde_json::Value) {
    let n = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_u64)
            .map(|x| x.to_string())
            .unwrap_or_else(|| "?".to_string())
    };
    let dry = v
        .get("dry_run")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    eprintln!(
        "blob purge{}: {} / {} object(s) — purged {}, kept-unconfirmed {}, {} byte(s)",
        if dry { " (dry-run)" } else { "" },
        n("done"),
        n("total"),
        n("purged"),
        n("skipped_unconfirmed"),
        n("purged_bytes"),
    );
}

/// Consume an **NDJSON** control-plane stream (the daemon-mediated blob drain + purge share this):
/// accumulate raw bytes, split on `\n`, parse each complete line, print each `"type":"progress"`
/// snapshot to stderr via `on_progress` (keeping stdout clean for the report), and return the LAST
/// `"type":"report"` object. `op` names the operation for the "no final report" error. A well-behaved
/// daemon always ends with a report line; a stream that closed without one is surfaced as an error
/// rather than a false success.
async fn consume_ndjson_report(
    resp: reqwest::Response,
    op: &str,
    on_progress: fn(&serde_json::Value),
) -> Result<serde_json::Value> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut last_report: Option<serde_json::Value> = None;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.extend_from_slice(&chunk);
        // Drain every complete `\n`-terminated line out of the buffer.
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let text = String::from_utf8_lossy(&line);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
                // A malformed line is non-fatal — skip it (the daemon only emits valid JSON lines).
                continue;
            };
            match value.get("type").and_then(serde_json::Value::as_str) {
                Some("report") => last_report = Some(value),
                // A progress snapshot — show liveness on stderr, keep stdout clean for the report.
                _ => on_progress(&value),
            }
        }
    }
    last_report.ok_or_else(|| {
        ClientError::Refused(format!(
            "{op} stream ended without a final report (connection cut? re-run to resume)"
        ))
    })
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

/// The running node's boatramp version, from `GET /api/version` (for `boatramp version --server`).
/// Shaped as an object (not a bare string) so the server can add fields without breaking the client.
#[derive(Debug, Deserialize)]
pub struct VersionInfo {
    /// The exact package version of the remote binary (e.g. `"0.7.3"`).
    pub version: String,
}

/// An AND-composed dead-letter filter for the `dlq` commands (mirrors the server's wire filter).
/// Serializes `match_last_error` as `match`. All-`None` = the whole DLQ.
#[derive(Debug, Default, Serialize)]
pub struct DlqFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_than_ms: Option<u64>,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// One consumer group returned by `queue groups`.
#[derive(Debug, Deserialize)]
pub struct GroupEntry {
    pub group: String,
    #[serde(default)]
    pub hwm: String,
    pub in_flight: usize,
    pub lag: usize,
}

/// One live message returned by `queue peek` (payload base64).
#[derive(Debug, Deserialize)]
pub struct QueuePeekEntry {
    pub id: String,
    pub attempts: u32,
    #[serde(default)]
    pub leased: bool,
    #[serde(default)]
    pub signed_context_present: bool,
    pub payload_b64: String,
}

/// One dead-letter as returned by the `dlq` list/show/dry-run views.
#[derive(Debug, Deserialize)]
pub struct DlqEntry {
    pub id: String,
    pub group: String,
    pub attempts: u32,
    pub last_error: Option<String>,
    #[serde(default)]
    pub signed_context_present: bool,
    /// Present only from a `show` (base64 payload).
    #[serde(default)]
    pub payload_b64: Option<String>,
}

/// Value-free metadata for one per-tenant sealed secret (task #493), the shape the
/// `/api/…/tenant-secrets/…` control-plane returns. Never carries a value.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TenantSecretMeta {
    pub name: String,
    // Part of the returned metadata contract; the `ls` view prints `updated_at`, but the field is
    // kept so a caller/JSON consumer sees the full shape.
    #[serde(default)]
    #[allow(dead_code)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
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

/// The self-describing minted S3 upload credential the server returns from `POST /api/blob-mint-upload`
/// (`kind` selecting the shape). For `presigned_put`, `url`/`method`/`required_headers` are set; for
/// `temp_credentials`, the STS-style fields + the enforced/advisory contract. Fields for the other
/// shape deserialize to their default (absent).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MintUploadResult {
    /// `"presigned_put"` or `"temp_credentials"`.
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub required_headers: Vec<(String, String)>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub force_path_style: Option<bool>,
    pub expires_at: u64,
    pub expires_in_secs: u64,
    #[serde(default)]
    pub enforced: Vec<String>,
    #[serde(default)]
    pub advisory: Vec<String>,
}

/// Which operator queue/DLQ surface a `queue`/`dlq` op targets: a single **site's** own
/// queues (with an optional background-`alias` scope), or the **shared project bus**
/// (`{project}/bus/{topic}`, common to every site in the project). The two differ only in
/// the endpoint path (site: `/api/<sites-seg>/<site>/_boatramp/…`; bus:
/// `/api/projects/<proj>/_boatramp/bus/…`) and that the bus has no `alias` axis — the
/// request/response shapes are identical, so every client method takes an `OpScope` and
/// the CLI picks one from a `--bus` flag.
#[derive(Debug, Clone, Copy)]
pub enum OpScope<'a> {
    /// A single site's queues, optionally under a background-alias (`{site}/{alias}`) scope.
    Site {
        /// The site name.
        site: &'a str,
        /// The background-alias scope, if any.
        alias: Option<&'a str>,
    },
    /// The shared, project-scoped bus (authorized at `Project·Read`/`Project·Admin`).
    Bus,
}

impl<'a> OpScope<'a> {
    /// The site surface under an optional background-alias scope.
    pub fn site_alias(site: &'a str, alias: Option<&'a str>) -> Self {
        Self::Site { site, alias }
    }

    /// The background-alias scope carried in a POST body / GET query. Always `None` for
    /// the project bus (it is not per-deployment).
    fn alias(&self) -> Option<&'a str> {
        match self {
            Self::Site { alias, .. } => *alias,
            Self::Bus => None,
        }
    }
}

/// One control-plane KV record on the selective-sync wire (`/api/project-kv-stratum`): the key
/// verbatim + its value base64-encoded. The CLI RELAYS these opaquely (source → dest) and never
/// inspects a value — so it needs no base64 dependency, and the value never lands in a log/argv.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KvStratumEntry {
    /// The control-plane KV key, exactly as the source stored it.
    pub key: String,
    /// The value bytes, base64 (standard alphabet) — relayed opaquely.
    pub value_b64: String,
}

/// The `GET /api/project-kv-stratum` response shape (the source slice).
#[derive(Debug, serde::Deserialize)]
struct KvStratumReadBody {
    #[serde(default)]
    entries: Vec<KvStratumEntry>,
}

/// The `POST /api/project-kv-stratum` request body (land a slice on the target).
#[derive(Debug, serde::Serialize)]
struct KvStratumWriteBody<'a> {
    source_project: &'a str,
    exclude_prefixes: &'a [String],
    entries: &'a [KvStratumEntry],
}

/// One entry the DEST write skipped (incoherent / excluded), relayed back for the operator report.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KvStratumSkip {
    /// The target key that was not written.
    pub key: String,
    /// Why it was skipped.
    pub reason: String,
}

/// The `POST /api/project-kv-stratum` outcome: records landed, entries skipped-and-reported, and
/// system-principal markers the dest neutralized.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KvStratumWriteOutcome {
    /// Records actually written to the destination.
    pub written: usize,
    /// Entries skipped (incoherent / excluded) — never half-applied; drives `--strict`.
    #[serde(default)]
    pub skipped: Vec<KvStratumSkip>,
    /// System-principal markers (`current-principal/<site>`) the dest refused to write (always,
    /// fail-closed) — a `Project·Admin` carry can never grant a site the System principal.
    /// Informational only; NEVER triggers a `--strict` refuse.
    #[serde(default)]
    pub neutralized: Vec<String>,
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
        project_seg(&self.project, "sites")
    }

    /// The function-collection URL segment: `functions` for the default project
    /// (byte-identical legacy `/api/functions/...`), else `projects/<proj>/functions`.
    fn functions_seg(&self) -> String {
        project_seg(&self.project, "functions")
    }

    /// The compute-collection URL segment: `compute` for the default project
    /// (byte-identical legacy `/api/compute/...`), else `projects/<proj>/compute`.
    fn compute_seg(&self) -> String {
        project_seg(&self.project, "compute")
    }

    /// The project-BUS operator path prefix: always the project-scoped
    /// `projects/<proj>/_boatramp/bus` form (there is no legacy/unscoped bus route —
    /// even the `default` project's shared bus is addressed project-scoped), so a
    /// `boatramp queue|dlq --bus` targets the right project's shared bus. The server
    /// authorizes this path at `Project·Read` (GET) / `Project·Admin` (destructive POST).
    fn bus_prefix(&self) -> String {
        format!("projects/{}/_boatramp/bus", self.project)
    }

    /// The full operator-endpoint URL for a given [`OpScope`] and operation suffix
    /// (`"dlq"`, `"queue/peek"`, …): the per-site `…/<sites-seg>/<site>/_boatramp/<op>` for
    /// [`OpScope::Site`], or the shared `…/projects/<proj>/_boatramp/bus/<op>` for
    /// [`OpScope::Bus`]. The single place the site-vs-bus path split lives.
    fn op_url(&self, scope: OpScope<'_>, op: &str) -> String {
        match scope {
            OpScope::Site { site, .. } => {
                let seg = self.sites_seg();
                format!("{}/api/{seg}/{site}/_boatramp/{op}", self.base)
            }
            OpScope::Bus => format!("{}/api/{}/{op}", self.base, self.bus_prefix()),
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

    /// List the project's site names (`GET /api/{seg}` sites). Read-only; the server returns the
    /// union of the project's `site/`/`current/`/`history/` pointers as a `Vec<String>`. Used by
    /// `project sync` to enumerate the source's sites for the per-site carry/rewrite.
    pub async fn list_sites(&self) -> Result<Vec<String>> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}"))
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

    /// List the NAMES of the project's sealed secrets (`GET /api/secrets` — names + metadata, never
    /// values). Used by `project sync` to detect a site config whose `[handlers].secrets` references
    /// a `boatramp:<name>` secret not yet sealed on the destination, so it can DEFER that config to a
    /// later `deploy:apply` rather than fail the run. A node with no `[secrets]` envelope answers
    /// `501`, surfaced as an error the caller treats as "can't determine — don't defer".
    pub async fn list_secret_names(&self) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct NameOnly {
            name: String,
        }
        let seg = project_seg(&self.project, "secrets");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let metas: Vec<NameOnly> = client
            .get(format!("{server}/api/{seg}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(metas.into_iter().map(|m| m.name).collect())
    }

    /// List the NAMES of the project's registered GraphQL federation subgraphs
    /// (`GET /api/graphql/subgraphs` — empty-safe `[]`, never an error on an empty registry, unlike
    /// the composed `supergraph` read). Used by `project sync` to detect a carried site config whose
    /// `handlers.graphql.subgraphs` include list names a subgraph not yet registered on the
    /// destination, so it can DEFER that config to a later `deploy:apply` (which owns subgraph
    /// registration) rather than failing the run.
    pub async fn list_subgraph_names(&self) -> Result<Vec<String>> {
        let seg = project_seg(&self.project, "graphql/subgraphs");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch the project's tenancy schema (the per-table tenant-key map). A project
    /// that declared none returns the default schema (`tenant_id`, no tables).
    pub async fn get_project_tenancy(&self) -> Result<boatramp_core::tenancy::TenancySchema> {
        let seg = project_seg(&self.project, "tenancy");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Replace the project's tenancy schema (`Project·Admin`).
    pub async fn put_project_tenancy(
        &self,
        schema: &boatramp_core::tenancy::TenancySchema,
    ) -> Result<()> {
        let seg = project_seg(&self.project, "tenancy");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .put(format!("{server}/api/{seg}"))
            .json(schema)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    // ---- schema migrations (0.4.x) -----------------------------------------

    /// Read a managed database's applied-migration ledger, in order
    /// (`GET /api/{seg}/migrate/{db}/status`; `Project·Read`).
    pub async fn migrate_status(&self, db: &str) -> Result<boatramp_core::sql::MigrationStatus> {
        let seg = project_seg(&self.project, "migrate");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{db}/status"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Read the running node's boatramp version (`GET /api/version`; `System·Read`) — the exact
    /// package version of the binary actually serving, for `boatramp version --server`. Not
    /// project-scoped (a node-level read, like `/api/metrics`), so no `{seg}`. A `401`/`403`
    /// (missing/insufficient token) surfaces via `error_for_status` as a transport error.
    pub async fn node_version(&self) -> Result<VersionInfo> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/version"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// LIVE control-plane KV checkpoint (`POST /api/kv-checkpoint`, `System·Admin`, v0.11.0 UX C6):
    /// advance the durable frontier NOW (freeze WAL→L0) on the RUNNING daemon WITHOUT stopping the
    /// writer, so an operator can snapshot a guaranteed-bootable volume of the live node. Returns the
    /// server's confirmation line; a non-2xx (`403` insufficient right, `500` checkpoint error) is
    /// surfaced verbatim as [`ClientError::Refused`].
    pub async fn kv_checkpoint(&self) -> Result<String> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .post(format!("{server}/api/kv-checkpoint"))
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(body)
        } else {
            Err(ClientError::Refused(format!(
                "kv checkpoint refused ({status}): {}",
                body.trim_end()
            )))
        }
    }

    /// Export a project to a `BRPROJ` bundle (`POST /api/project-export`, `Project·Admin` on the target),
    /// STREAMING the response body to `out` (written to a `.part` sibling then renamed, so a
    /// partial download never masquerades as a complete bundle). `data_only` selects the
    /// app-data-only bundle vs full schema+data.
    pub async fn project_export(
        &self,
        project: &str,
        data_only: bool,
        include_identity: bool,
        transport_key: Option<Vec<u8>>,
        out: &std::path::Path,
    ) -> Result<()> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut req = client.post(format!("{server}/api/project-export")).query(&[
            ("project", project),
            ("data_only", if data_only { "true" } else { "false" }),
            (
                "include_identity",
                if include_identity { "true" } else { "false" },
            ),
        ]);
        if let Some(key) = &transport_key {
            // Secret → an HTTP header (over TLS), never a query param / command line.
            let value = std::str::from_utf8(key).map_err(|_| {
                ClientError::Refused(
                    "transport key must be valid UTF-8 for the request header".into(),
                )
            })?;
            req = req.header("x-boatramp-transport-key", value);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "project export refused ({status}): {}",
                body.trim_end()
            )));
        }
        let tmp = std::path::PathBuf::from(format!("{}.part", out.display()));
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| ClientError::Refused(format!("cannot create {}: {e}", tmp.display())))?;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            f.write_all(&chunk)
                .await
                .map_err(|e| ClientError::Refused(format!("write {}: {e}", tmp.display())))?;
        }
        f.flush()
            .await
            .map_err(|e| ClientError::Refused(format!("flush {}: {e}", tmp.display())))?;
        drop(f);
        tokio::fs::rename(&tmp, out)
            .await
            .map_err(|e| ClientError::Refused(format!("finalize bundle {}: {e}", out.display())))?;
        Ok(())
    }

    /// Import a `BRPROJ` bundle into a project (`POST /api/project-import`, `Project·Admin` on the target),
    /// STREAMING `bundle` as the request body. Returns the server's report text (JSON). A
    /// non-2xx — `409` schema-skew / KV-commingle refusal, `501` no driver — is surfaced
    /// verbatim as [`ClientError::Refused`].
    // Each argument is a distinct import knob the API exposes (apply/force/allow-schema-skew/
    // overwrite/identity/transport-key); a wrapper struct would only move the same fields the
    // single CLI caller already unpacks, so mirror the API surface directly.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn project_import(
        &self,
        project: &str,
        bundle: &std::path::Path,
        apply: bool,
        force: bool,
        allow_schema_skew: bool,
        overwrite: bool,
        identity: &str,
        transport_key: Option<Vec<u8>>,
        mismatch: MismatchFlags,
    ) -> Result<String> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let file = tokio::fs::File::open(bundle)
            .await
            .map_err(|e| ClientError::Refused(format!("cannot open {}: {e}", bundle.display())))?;
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
        let bstr = |b: bool| if b { "true" } else { "false" };
        let mut query: Vec<(&str, String)> = vec![
            ("project", project.to_string()),
            ("apply", bstr(apply).into()),
            ("force", bstr(force).into()),
            ("allow_schema_skew", bstr(allow_schema_skew).into()),
            ("overwrite", bstr(overwrite).into()),
            ("identity", identity.to_string()),
            ("enumerate_mismatches", bstr(mismatch.enumerate).into()),
            ("skip_member_mismatch", bstr(mismatch.skip).into()),
            (
                "skip_any_blob_mismatch",
                bstr(mismatch.skip_any_blob).into(),
            ),
        ];
        if let Some(c) = &mismatch.continue_on_error {
            query.push(("continue_on_error", c.clone()));
        }
        if !mismatch.only_blobs.is_empty() {
            // Blob keys contain `/` but never `,`, so a comma-joined list round-trips unambiguously.
            query.push(("only_blobs", mismatch.only_blobs.join(",")));
        }
        let mut req = client
            .post(format!("{server}/api/project-import"))
            .query(&query)
            .header("content-type", "application/octet-stream");
        if let Some(key) = &transport_key {
            // Secret → an HTTP header (over TLS), never a query param / command line.
            let value = std::str::from_utf8(key).map_err(|_| {
                ClientError::Refused(
                    "transport key must be valid UTF-8 for the request header".into(),
                )
            })?;
            req = req.header("x-boatramp-transport-key", value);
        }
        let resp = req.body(body).send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(text)
        } else {
            Err(ClientError::Refused(format!(
                "project import refused ({status}): {}",
                text.trim_end()
            )))
        }
    }

    /// STREAMING CLONE (`POST /api/projects/<target>/clone/from`, `Project·Admin` — NOT the
    /// node-global `System·Admin` import): the TARGET node pulls the whole project from `source_url`
    /// (manifest → per-SHA diff → filtered stream → inc2 restore), so no bundle lands anywhere. The
    /// operator's SOURCE Project-Admin bearer travels in the `X-Boatramp-Source-Token` header (over
    /// TLS, never a URL); the client's own bearer gates the TARGET side.
    ///
    /// The DEFAULT dry-run (`apply=false`, `verify=false`) returns a CHEAP [`CloneOutcome::Planned`]
    /// — the server stops after the manifest + diff, so it answers fast even at tens of GB. `apply`
    /// (or `verify`, the stream-level validate) streams an NDJSON progress channel — the plan, then
    /// periodic transfer heartbeats surfaced via `tracing` (stderr), then the terminal report — and
    /// returns [`CloneOutcome::Applied`]. A long clone is therefore never zero-output.
    #[allow(clippy::too_many_arguments)]
    pub async fn project_clone_from(
        &self,
        target: &str,
        source_url: &str,
        source_project: Option<&str>,
        source_token: &[u8],
        apply: bool,
        verify: bool,
        overwrite: bool,
        force: bool,
        data_only: bool,
        managed_restore: Option<boatramp_core::project_export::ManagedRestore>,
        // DATA-PLANE-ONLY CLAMP: apply the managed-DB members of a FULL bundle but SKIP its
        // control-plane KV slice (so the source's domain layer never lands). Set on an absent-dest sync.
        skip_control_plane_kv: bool,
        // Managed-DB self-heal (`--drop-soft-deleted`): on a self-heal of a prior-failed sync tangle,
        // additionally DESTROY the `__deleted_` grace tombstone(s) rather than preserving them.
        // DATA-LOSS opt-in; default false. Forwarded to the node's sidecar restore reconcile.
        drop_soft_deleted: bool,
        mismatch: MismatchFlags,
    ) -> Result<CloneOutcome> {
        use boatramp_core::project_export::ClonePlan;
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let token = std::str::from_utf8(source_token).map_err(|_| {
            ClientError::Refused(
                "the source token must be valid UTF-8 for the request header".into(),
            )
        })?;
        let mut body = serde_json::json!({
            "source_url": source_url,
            "apply": apply,
            "verify": verify,
            "overwrite": overwrite,
            "force": force,
            "data_only": data_only,
            "enumerate_mismatches": mismatch.enumerate,
            "skip_member_mismatch": mismatch.skip,
            "skip_any_blob_mismatch": mismatch.skip_any_blob,
            "only_blobs": mismatch.only_blobs,
            "skip_control_plane_kv": skip_control_plane_kv,
            "drop_soft_deleted": drop_soft_deleted,
        });
        if let Some(sp) = source_project {
            body["source_project"] = serde_json::Value::String(sp.to_string());
        }
        // The managed-restore MODE (orthogonal to `data_only`) — only sent when explicitly chosen;
        // absent lets the source apply the legacy coupling. `project sync` sets `ShadowSwap`.
        if let Some(mr) = managed_restore {
            body["managed_restore"] = serde_json::Value::String(mr.as_str().to_string());
        }
        if let Some(c) = &mismatch.continue_on_error {
            body["continue_on_error"] = serde_json::Value::String(c.clone());
        }
        let url = format!("{server}/api/projects/{target}/clone/from");

        // The DEFAULT dry-run answers with a single cheap ClonePlan JSON — one short request, no
        // long-held connection, so it is NOT part of the resumable transfer loop below.
        if !apply && !verify {
            let resp = client
                .post(url.as_str())
                .header("x-boatramp-source-token", token)
                .json(&body)
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(ClientError::Refused(format!(
                    "project clone refused ({status}): {}",
                    text.trim_end()
                )));
            }
            let bytes = resp.bytes().await?;
            let plan: ClonePlan = serde_json::from_slice(&bytes).map_err(|e| {
                ClientError::Refused(format!("clone plan response was not valid JSON: {e}"))
            })?;
            return Ok(CloneOutcome::Planned(plan));
        }

        // apply / verify: the transfer rides a SINGLE tens-of-minutes-long, near-idle streaming
        // response (only the ~5s progress heartbeat flows on this connection; the bulk bytes move on
        // the target's SEPARATE pull from the source). An edge/proxy idle-cut or a transient reset
        // severs the response body mid-wait — `reqwest`'s `error decoding response body`, the reported
        // failure. The clone is IDEMPOTENT + RESUMABLE (the target restores each blob into its LIVE
        // store as it streams, and its per-SHA diff skips already-restored blobs on a re-issue), so we
        // RECOVER a transport interruption by re-issuing and converging rather than failing the whole
        // transfer. We only give up after `CLONE_RESUME_MAX_STALLED_ATTEMPTS` consecutive interruptions
        // that made NO forward progress. (`verify` persists nothing, so a resume re-validates — bounded
        // by the same stall budget.)
        let mut stall: u32 = 0;
        let mut best_remaining: Option<usize> = None;
        loop {
            match self.clone_apply_attempt(&url, token, &body, target).await {
                CloneAttemptOutcome::Applied { plan, report } => {
                    return Ok(CloneOutcome::Applied {
                        plan: *plan,
                        report: *report,
                    });
                }
                CloneAttemptOutcome::Fatal(msg) => return Err(ClientError::Refused(msg)),
                CloneAttemptOutcome::Interrupted { reason, remaining } => {
                    let (new_stall, new_best, give_up) =
                        clone_resume_step(stall, best_remaining, remaining);
                    stall = new_stall;
                    best_remaining = new_best;
                    if give_up {
                        return Err(ClientError::Refused(format!(
                            "clone data transfer to {target} keeps dropping mid-transfer without \
                             making progress (last: {reason}); the connection is too unstable to \
                             complete in one run — re-run the command to resume (already-transferred \
                             blobs are skipped)"
                        )));
                    }
                    let backoff = clone_resume_backoff(stall.saturating_sub(1));
                    tracing::warn!(
                        target = %target,
                        reason = %reason,
                        stall,
                        backoff_secs = backoff.as_secs(),
                        "clone transfer interrupted mid-stream; resuming (the target skips \
                         already-transferred blobs)"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// Issue ONE `/clone/from` apply/verify request and drive its NDJSON stream to a
    /// [`CloneAttemptOutcome`]. A send failure (the response never reached its headers) and a
    /// transient `502/503/504` are both resumable [`Interrupted`](CloneAttemptOutcome::Interrupted);
    /// a non-transient refusal status is [`Fatal`](CloneAttemptOutcome::Fatal). The streaming body is
    /// classified by [`drive_clone_ndjson`]. Factored out so [`project_clone_from`]'s resume loop re-
    /// issues an identical request (the request body is idempotent — the target's per-SHA diff makes a
    /// re-issue transfer only what is still missing).
    async fn clone_apply_attempt(
        &self,
        url: &str,
        token: &str,
        body: &serde_json::Value,
        target: &str,
    ) -> CloneAttemptOutcome {
        let resp = match self
            .http
            .post(url)
            .header("x-boatramp-source-token", token)
            .json(body)
            .send()
            .await
        {
            Ok(r) => r,
            // The request did not reach its response headers (connect error / reset before `200`):
            // transport-level, and nothing could have been applied yet. RESUMABLE.
            Err(e) => {
                return CloneAttemptOutcome::Interrupted {
                    reason: format!("request did not reach the target: {e}"),
                    remaining: None,
                };
            }
        };
        let status = resp.status();
        if !status.is_success() {
            // A gateway/proxy transient (the edge briefly could not reach the backend) is RESUMABLE;
            // any other non-success is a real refusal that re-issuing cannot fix.
            if matches!(status.as_u16(), 502..=504) {
                return CloneAttemptOutcome::Interrupted {
                    reason: format!("target returned a transient {status}"),
                    remaining: None,
                };
            }
            let text = resp.text().await.unwrap_or_default();
            return CloneAttemptOutcome::Fatal(format!(
                "project clone refused ({status}): {}",
                text.trim_end()
            ));
        }
        drive_clone_ndjson(resp.bytes_stream(), target).await
    }

    /// RESUMABLE export (`POST /api/project-export?resumable=<dir_name>`, `Project·Admin` on the target):
    /// the node writes a member-object directory of `dir_name` (under its configured base,
    /// resuming an interrupted run) — nothing streams back, so no local file is written.
    ///
    /// A DELTA export passes `mode` (`differential`|`incremental`) + `base` (the base/parent
    /// resumable-dir name to chain onto); both `None` ⇒ a full resumable export.
    #[allow(clippy::too_many_arguments)]
    pub async fn project_export_resumable(
        &self,
        project: &str,
        data_only: bool,
        include_identity: bool,
        transport_key: Option<Vec<u8>>,
        dir_name: &str,
        mode: Option<&str>,
        base: Option<&str>,
    ) -> Result<()> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut query: Vec<(&str, &str)> = vec![
            ("project", project),
            ("data_only", if data_only { "true" } else { "false" }),
            (
                "include_identity",
                if include_identity { "true" } else { "false" },
            ),
            ("resumable", dir_name),
        ];
        if let Some(m) = mode {
            query.push(("mode", m));
        }
        if let Some(b) = base {
            query.push(("base", b));
        }
        let mut req = client
            .post(format!("{server}/api/project-export"))
            .query(&query);
        if let Some(key) = &transport_key {
            let value = std::str::from_utf8(key).map_err(|_| {
                ClientError::Refused(
                    "transport key must be valid UTF-8 for the request header".into(),
                )
            })?;
            req = req.header("x-boatramp-transport-key", value);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(())
        } else {
            Err(ClientError::Refused(format!(
                "resumable project export refused ({status}): {}",
                text.trim_end()
            )))
        }
    }

    /// RESUMABLE import (`POST /api/project-import?resumable=<dir_name>`, `Project·Admin` on the target):
    /// the node reads a member-object directory of `dir_name` (under its configured base) —
    /// no request body. Returns the server's report text (JSON), like [`project_import`].
    #[allow(clippy::too_many_arguments)]
    pub async fn project_import_resumable(
        &self,
        project: &str,
        dir_name: &str,
        apply: bool,
        force: bool,
        allow_schema_skew: bool,
        overwrite: bool,
        identity: &str,
        transport_key: Option<Vec<u8>>,
    ) -> Result<String> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut req = client.post(format!("{server}/api/project-import")).query(&[
            ("project", project),
            ("apply", if apply { "true" } else { "false" }),
            ("force", if force { "true" } else { "false" }),
            (
                "allow_schema_skew",
                if allow_schema_skew { "true" } else { "false" },
            ),
            ("overwrite", if overwrite { "true" } else { "false" }),
            ("identity", identity),
            ("resumable", dir_name),
        ]);
        if let Some(key) = &transport_key {
            let value = std::str::from_utf8(key).map_err(|_| {
                ClientError::Refused(
                    "transport key must be valid UTF-8 for the request header".into(),
                )
            })?;
            req = req.header("x-boatramp-transport-key", value);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(text)
        } else {
            Err(ClientError::Refused(format!(
                "resumable project import refused ({status}): {}",
                text.trim_end()
            )))
        }
    }

    /// Trigger a schema-migration `verb` (`apply` / `dry-run` / `baseline`) over an
    /// already-uploaded step-set bundle (`POST /api/{seg}/migrate/{db}/{verb}`;
    /// `Project·Admin`). A step failure comes back as `422` whose body is still a valid
    /// [`MigrationReport`](boatramp_core::sql::MigrationReport) with `failed` set — returned
    /// as `Ok` so the caller can show which step failed and exit non-zero. A bundle/ledger
    /// error (`400`/`409`/`501`/`503`) is surfaced verbatim as [`ClientError::Refused`].
    ///
    /// A still-provisioning managed backend answers a retryable `503` + `Retry-After`; `wait`
    /// bounds how long to wait on it (via the shared [`crate::managed_wait`] helper) before
    /// surfacing it, so a cold-start migration blocks until the DB is ready rather than failing
    /// immediately.
    pub async fn migrate_trigger(
        &self,
        db: &str,
        verb: &str,
        bundle: &str,
        up_to: Option<&str>,
        wait: crate::managed_wait::WaitPolicy,
    ) -> Result<boatramp_core::sql::MigrationReport> {
        let seg = project_seg(&self.project, "migrate");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let url = format!("{server}/api/{seg}/{db}/{verb}");
        let body = serde_json::json!({ "bundle": bundle, "up_to": up_to });
        let resp = crate::managed_wait::send_with_ready_wait(wait, || {
            client.post(url.as_str()).json(&body).send()
        })
        .await?;
        let status = resp.status();
        // 200 = clean; 422 = a step failed but the body is still a full report (halted at
        // the failing step, prefix applied). Both carry a `MigrationReport` to render.
        if status.is_success() || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            // A `503` after the wait budget was spent is the still-provisioning case — hint the
            // cure (raise the wait) rather than reading like a terminal refusal.
            let hint = if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                " — the managed database is still provisioning; retry or raise `--wait-ready-secs`"
            } else {
                ""
            };
            Err(ClientError::Refused(format!(
                "schema migrate {verb} refused ({status}){hint}: {}",
                body.trim()
            )))
        }
    }

    // ---- per-tenant sealed secrets (task #493) -----------------------------

    /// Seal `value` under `(project, tenant, name)` (`PUT /api/{seg}/{tenant}/{name}`;
    /// `Secrets·Write`). Rotation = PUT an existing name. Returns the value-free
    /// [`TenantSecretMeta`]; the value is never echoed. A `501` (no envelope), `400` (invalid
    /// tenant/name) or other non-2xx is surfaced verbatim as [`ClientError::Refused`].
    pub async fn tenant_secret_set(
        &self,
        tenant: &str,
        name: &str,
        value: &str,
    ) -> Result<TenantSecretMeta> {
        let seg = project_seg(&self.project, "tenant-secrets");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .put(format!("{server}/api/{seg}/{tenant}/{name}"))
            .json(&serde_json::json!({ "value": value }))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Refused(format!(
                "tenant-secret set refused ({status}): {}",
                body.trim()
            )))
        }
    }

    /// List ONE tenant's secret names + metadata (`GET /api/{seg}/{tenant}`; `Secrets·Read`),
    /// never a value, never project-wide.
    pub async fn tenant_secret_list(&self, tenant: &str) -> Result<Vec<TenantSecretMeta>> {
        let seg = project_seg(&self.project, "tenant-secrets");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .get(format!("{server}/api/{seg}/{tenant}"))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Refused(format!(
                "tenant-secret ls refused ({status}): {}",
                body.trim()
            )))
        }
    }

    /// Delete `(project, tenant, name)` (`DELETE /api/{seg}/{tenant}/{name}`; `Secrets·Write`).
    /// `Ok(true)` if it existed, `Ok(false)` on a `404`, else [`ClientError::Refused`].
    pub async fn tenant_secret_delete(&self, tenant: &str, name: &str) -> Result<bool> {
        let seg = project_seg(&self.project, "tenant-secrets");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .delete(format!("{server}/api/{seg}/{tenant}/{name}"))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(true)
        } else if status == reqwest::StatusCode::NOT_FOUND {
            Ok(false)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Refused(format!(
                "tenant-secret rm refused ({status}): {}",
                body.trim()
            )))
        }
    }

    // ---- provisioning drift-repair (v0.5.0) --------------------------------

    /// Run a provisioning drift-repair over managed database `db`: `apply` (mutating —
    /// `POST /api/{seg}/repair/{db}`) or `dry-run` (report-only —
    /// `POST /api/{seg}/repair/{db}/dry-run`). Both are `Project·Admin`. A run that produced a
    /// report (even with errored checks → `422`) comes back as `Ok` so the caller can render the
    /// per-check verdicts + set the exit code; a run that couldn't produce a report at all
    /// (`400`/`501`/`503`) is surfaced as [`ClientError::Refused`].
    pub async fn repair_trigger(
        &self,
        db: &str,
        apply: bool,
    ) -> Result<boatramp_core::sql::RepairReport> {
        let seg = project_seg(&self.project, "repair");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let url = if apply {
            format!("{server}/api/{seg}/{db}")
        } else {
            format!("{server}/api/{seg}/{db}/dry-run")
        };
        let resp = client.post(url).send().await?;
        let status = resp.status();
        // 200 = every check ok/repaired/skipped; 422 = a check errored but the body is still a
        // full report. Both carry a `RepairReport` to render.
        if status.is_success() || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Refused(format!(
                "provisioning repair refused ({status}): {}",
                body.trim()
            )))
        }
    }

    // ---- declarative managed databases (v0.6.0, #501 Stage B) --------------

    /// Declare (persist + eagerly provision) a managed database from a manifest
    /// `databases:` entry: `PUT /api/{seg}/databases/{name}` with the typed
    /// [`ApplyDatabase`](boatramp_core::compute::ApplyDatabase) body. `Project·Admin`.
    /// The server enforces daemon-config-wins, identity-change refusal, and
    /// caller's-project binding; a refusal (`409`/`400`/`501`) surfaces as a
    /// [`ClientError`] carrying the server's reason.
    pub async fn declare_database(
        &self,
        name: &str,
        db: &boatramp_core::compute::ApplyDatabase,
    ) -> Result<()> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .put(format!("{server}/api/{seg}/{name}"))
            .json(db)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// List the project's declared managed databases (`GET /api/{seg}/databases`).
    /// Read-only (`Project·Read`). Each is the stored typed
    /// [`ApplyDatabase`](boatramp_core::compute::ApplyDatabase).
    pub async fn list_databases(&self) -> Result<Vec<boatramp_core::compute::ApplyDatabase>> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch one declared managed database (`GET /api/{seg}/databases/{name}`).
    /// Read-only (`Project·Read`); a missing declaration is a `404` → [`ClientError`].
    pub async fn get_database(&self, name: &str) -> Result<boatramp_core::compute::ApplyDatabase> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{name}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    // ---- selective-sync control-plane KV strata (PLAN-project-sync) --------
    //
    // The per-stratum, project-scoped admin KV transport `project sync` uses to carry the
    // NON-SECRET control-plane strata (settings / graphql / history) it could not before. Both
    // verbs are `Project·Admin` on this ControlPlane's project (the dest token on `self`, or the
    // SOURCE node's forwarded Project-Admin token when `self` is a cross-node source client).

    /// SOURCE read: fetch this project's `piece` KV slice
    /// (`GET /api/project-kv-stratum?project=<p>&piece=<piece>`). Returns the opaque wire entries
    /// (key + base64 value); the CLI relays them to the dest WITHOUT decoding. A server refusal
    /// (a non-carryable piece, a scope guard, a degraded read) surfaces as a [`ClientError`]
    /// carrying the server's reason.
    pub async fn get_kv_stratum(&self, piece: &str) -> Result<Vec<KvStratumEntry>> {
        let Self {
            http: client,
            base: server,
            project,
            ..
        } = self;
        let resp = client
            .get(format!("{server}/api/project-kv-stratum"))
            .query(&[("project", project.as_str()), ("piece", piece)])
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "kv-stratum read of `{piece}` for project `{project}` refused ({status}): {}",
                text.trim_end()
            )));
        }
        let body: KvStratumReadBody = resp.json().await?;
        Ok(body.entries)
    }

    /// DEST write: land a `piece` KV slice on this project
    /// (`POST /api/project-kv-stratum?project=<p>&piece=<piece>`). `source_project` re-keys the
    /// leading segment (a no-op for a same-name sync); `exclude_prefixes` are the engine's
    /// coherence excludes. The server STRUCTURALLY re-validates every key against the target's own
    /// piece prefixes and applies the history→siteconfig dependency, so the returned
    /// [`KvStratumWriteOutcome`] reports what landed + what was skipped. A run-level refusal (a
    /// scope-guard rejection, a write failure) surfaces as a [`ClientError`].
    pub async fn put_kv_stratum(
        &self,
        piece: &str,
        source_project: &str,
        exclude_prefixes: &[String],
        entries: &[KvStratumEntry],
    ) -> Result<KvStratumWriteOutcome> {
        let Self {
            http: client,
            base: server,
            project,
            ..
        } = self;
        let resp = client
            .post(format!("{server}/api/project-kv-stratum"))
            .query(&[("project", project.as_str()), ("piece", piece)])
            .json(&KvStratumWriteBody {
                source_project,
                exclude_prefixes,
                entries,
            })
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "kv-stratum write of `{piece}` to project `{project}` refused ({status}): {}",
                text.trim_end()
            )));
        }
        Ok(resp.json().await?)
    }

    /// Fetch the read-only status view of a declared managed database
    /// (`GET /api/{seg}/databases/{name}/status`) — the declaration + derived server
    /// workload handle. Never returns a secret.
    pub async fn database_status(&self, name: &str) -> Result<serde_json::Value> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/{seg}/{name}/status"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Eager-provision an already-declared managed database, idempotently
    /// (`POST /api/{seg}/databases/{name}/ensure`). `Project·Admin`. This provisions the
    /// database so an operator can migrate it before any component runs — the declaration
    /// still lives in the `databases:` manifest (ensure never *declares*). Returns on the
    /// server's acknowledgement (`204`); readiness is then observable via `db status`.
    pub async fn ensure_database(&self, name: &str) -> Result<()> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .post(format!("{server}/api/{seg}/{name}/ensure"))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Restart a managed database (`POST /api/{seg}/databases/{name}/restart`).
    /// `Project·Admin`. Stops the workload's currently-running replica(s) so the
    /// reconcile loop relaunches a fresh one, applying any restart-requiring config
    /// change staged on the declaration in the process (e.g. a flipped
    /// `delta_capture`). Returns `(workload, config_applied, replicas_restarted)`.
    pub async fn restart_database(&self, name: &str) -> Result<(String, bool, usize)> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let v: serde_json::Value = client
            .post(format!("{server}/api/{seg}/{name}/restart"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok((
            v.get("workload")
                .and_then(|w| w.as_str())
                .unwrap_or(name)
                .to_string(),
            v.get("config_applied")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            v.get("replicas_restarted")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize,
        ))
    }

    /// Ensure a login role on a declared managed database
    /// (`POST /api/{seg}/databases/{database}/users/{user}/ensure`). `Project·Admin`.
    /// Returns `(created, password)`: `password` is `Some` ONLY on the call that minted
    /// the role (return-once), `None` on a re-ensure. `password_secret` is an optional
    /// operator-supplied secret ref (BYO).
    pub async fn ensure_user(
        &self,
        database: &str,
        user: &str,
        password_secret: Option<&str>,
    ) -> Result<(bool, String, Option<String>)> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut req = client.post(format!("{server}/api/{seg}/{database}/users/{user}/ensure"));
        if let Some(sref) = password_secret {
            req = req.json(&serde_json::json!({ "password_secret": sref }));
        }
        let v: serde_json::Value = req.send().await?.error_for_status()?.json().await?;
        // (created, role_name, password). `role_name` is the ACTUAL cluster principal to
        // connect as (per-tenant-qualified on Shared); fall back to the requested name if an
        // older server omits it. `password` is present only when freshly minted (once).
        Ok((
            v.get("created")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            v.get("role_name")
                .and_then(|r| r.as_str())
                .unwrap_or(user)
                .to_string(),
            v.get("password")
                .and_then(|p| p.as_str())
                .map(std::string::ToString::to_string),
        ))
    }

    /// Drop a managed-DB login role (`DELETE /api/{seg}/{database}/users/{user}`).
    /// `Project·Admin`; idempotent. Returns `(existed, role_name)` — `existed` whether a
    /// sealed credential was present, `role_name` the actual cluster principal dropped.
    pub async fn drop_user(&self, database: &str, user: &str) -> Result<(bool, String)> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let v: serde_json::Value = client
            .delete(format!("{server}/api/{seg}/{database}/users/{user}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok((
            v.get("existed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            v.get("role_name")
                .and_then(|r| r.as_str())
                .unwrap_or(user)
                .to_string(),
        ))
    }

    /// HARD-DROP a managed database (`DELETE /api/{seg}/databases/{name}?confirm={name}`).
    /// `Project·Admin`. IRREVERSIBLE: the explicit operator teardown / orphan-recovery verb. The
    /// `?confirm={name}` echoes the name as the server's typed confirmation guard. With
    /// `orphan = true` adds `?orphan=true` — the UNDECLARED-ORPHAN recovery path that hard-drops the
    /// derived database even when no binding is declared (the derivation is reconstructed server-side
    /// from `(project, name)`, never a raw name). Returns the derived PHYSICAL database name the
    /// server dropped (for operator confirmation).
    pub async fn drop_database(&self, name: &str, orphan: bool) -> Result<(String, Vec<String>)> {
        let seg = project_seg(&self.project, "databases");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut query: Vec<(&str, &str)> = vec![("confirm", name)];
        if orphan {
            query.push(("orphan", "true"));
        }
        let v: serde_json::Value = client
            .delete(format!("{server}/api/{seg}/{name}"))
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let physical = v
            .get("physical")
            .and_then(|p| p.as_str())
            .unwrap_or(name)
            .to_string();
        // Per-tenant roles the server deliberately LEFT (shared with a live sibling binding) — a
        // data-loss-safety fail-safe; absent on the clean path.
        let retained_roles = v
            .get("retained_roles")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok((physical, retained_roles))
    }

    /// Clear the project's tenancy schema (revert to legacy `Uniform` scoping).
    pub async fn clear_project_tenancy(&self) -> Result<()> {
        let seg = project_seg(&self.project, "tenancy");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .delete(format!("{server}/api/{seg}"))
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

    /// Operator-only generic DNS record-set verifier (`domain verify-records`):
    /// resolve `specs` over DNS and return the per-record [`VerifyReport`]. The
    /// server gates this at `system·admin`, so a site-scoped token gets a 403. A
    /// `400` (bad spec), `501` (no DNS feature) or other non-2xx is surfaced
    /// verbatim as [`ClientError::Refused`].
    pub async fn verify_records(
        &self,
        site: &str,
        host: &str,
        specs: &[boatramp_core::record_verify::RecordSpec],
    ) -> Result<boatramp_core::record_verify::VerifyReport> {
        let seg = self.sites_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .post(format!(
                "{server}/api/{seg}/{site}/domains/{}/verify-records",
                host_segment(host)
            ))
            .json(&serde_json::json!({ "specs": specs }))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Refused(format!(
                "verify-records refused ({status}): {}",
                body.trim()
            )))
        }
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
    /// function record body (`{ component, config, lifecycle }`).
    ///
    /// Bug #499: the deploy uses `?wait=false` (accept-then-validate) + `?compose=defer` so the
    /// slow work — the CPU-bound Cranelift compile + subgraph introspect/compose — runs in the
    /// SERVER's background off the request critical path, never blocking the control-plane request
    /// worker (a single-worker fly.io machine would otherwise starve the executor and 502 the next
    /// request, e.g. `/healthz`). The server returns `202 Accepted` + a `Validating` status; this
    /// method then polls `GET .../deploys/{version}` to a terminal outcome so `apply` still reports
    /// success/failure correctly. A caller applying subgraphs must call
    /// [`compose_subgraphs`](Self::compose_subgraphs) once after all deploys to promote the staged
    /// SDLs (the `?compose=defer` counterpart).
    pub async fn deploy_function(&self, name: &str, body: &serde_json::Value) -> Result<()> {
        let seg = self.functions_seg();
        let version = body
            .get("component")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .put(format!(
                "{server}/api/{seg}/{name}?wait=false&compose=defer"
            ))
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        // The server accepts the deploy (`202`) and validates in the background; poll the status
        // handle to a terminal (`active`/`failed`). A `version` is always present (the CLI always
        // sends `component`), so the poll targets the exact pending version.
        let Some(version) = version else {
            // No component hash in the body — nothing to poll against. The `202` already means the
            // deploy was accepted; treat as done (this shape isn't produced by the CLI).
            return Ok(());
        };
        // Consume the 202 body (a `Validating` status); the outcome is read by polling below.
        let _ = resp.bytes().await;
        self.poll_deploy_status(name, &version).await
    }

    /// Poll `GET /api/functions/{name}/deploys/{version}` (deploy-resilience #1b) until the async
    /// deploy reaches a terminal state. `Ok(())` on `active` (validated + promoted); an error on
    /// `failed` (carrying the server's coarse reason). A brief bounded poll — an async deploy's
    /// slow part is a several-hundred-ms compile + a compose, so terminal is reached quickly; the
    /// loop is capped so a wedged deploy surfaces an error rather than hanging `apply` forever.
    async fn poll_deploy_status(&self, name: &str, version: &str) -> Result<()> {
        let seg = self.functions_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let url = format!("{server}/api/{seg}/{name}/deploys/{version}");
        // Up to ~120s (240 × 500ms): generous for a cold compile + compose, bounded so a genuinely
        // stuck deploy fails `apply` instead of hanging. `Validating` ⇒ keep polling.
        for _ in 0..240 {
            let status: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            match status.get("status").and_then(serde_json::Value::as_str) {
                Some("active") => return Ok(()),
                Some("failed") => {
                    let reason = status
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown reason");
                    return Err(ClientError::Deploy(format!(
                        "function `{name}` deploy failed: {reason}"
                    )));
                }
                // `validating` (or an unrecognized transient) — keep waiting.
                _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            }
        }
        Err(ClientError::Deploy(format!(
            "function `{name}` deploy did not reach a terminal state in time"
        )))
    }

    /// Promote the project's **staged** subgraphs in one composition (`POST .../graphql/compose`)
    /// — the `?compose=defer` counterpart (deploy-resilience #3). An `apply` that deployed one or
    /// more subgraph functions with `?compose=defer` calls this ONCE at the end: the whole set is
    /// validated + promoted together (a composition failure promotes nothing and leaves the live
    /// supergraph untouched). Project-scoped via `project_seg` (`graphql` for the default project,
    /// else `projects/<proj>/graphql`). A no-op server response (nothing staged) is still success.
    pub async fn compose_subgraphs(&self) -> Result<()> {
        let seg = project_seg(&self.project, "graphql");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        client
            .post(format!("{server}/api/{seg}/compose"))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Register one **trusted operation** in the project's GraphQL safelist
    /// (`POST .../graphql/safelist`), the same endpoint `boatramp graphql safelist add`
    /// uses. The server runs its `guard_query`→`register` validation, so a malformed op
    /// is rejected server-side; registration is idempotent (an already-registered op
    /// re-registers to the same hash). **Register-only** — this never deletes/prunes.
    /// Project-scoped via `project_seg` (`graphql` for the default project, else
    /// `projects/<proj>/graphql`). `site`, when present (the declarative `apply` path), is sent as
    /// `?site=<name>` so the server validates the op against that site's per-site subgraph subset
    /// (fail-closed on a root absent from the subset). `None` ⇒ project-level, no subset check.
    pub async fn register_graphql_safelist(&self, query: &str, site: Option<&str>) -> Result<()> {
        let seg = project_seg(&self.project, "graphql");
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut req = client
            .post(format!("{server}/api/{seg}/safelist"))
            .json(&serde_json::json!({ "query": query }));
        if let Some(site) = site {
            req = req.query(&[("site", site)]);
        }
        req.send().await?.error_for_status()?;
        Ok(())
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

    /// Fetch captured guest logs for a **function** (symmetric to [`fetch_logs`]): the
    /// most recent `limit` lines with `seq > after`, optionally filtered to one `stream`.
    /// Honors `--project` via `functions_seg` (`functions` for the default project, else
    /// `projects/<proj>/functions`), so a per-tenant function's logs are reachable.
    ///
    /// [`fetch_logs`]: Self::fetch_logs
    pub async fn fetch_function_logs(
        &self,
        function: &str,
        limit: usize,
        after: u64,
        stream: Option<&str>,
    ) -> Result<LogsResponse> {
        let seg = self.functions_seg();
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let mut url =
            format!("{server}/api/{seg}/{function}/_boatramp/logs?limit={limit}&after={after}");
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

    /// Fetch the NODE-global wasm instance-lifecycle + memory stats (raw JSON: per-lane warm-hit /
    /// cold-miss / eviction / instantiation counters + durations, the live warm set, in-flight vs
    /// ceiling, and process RSS vs the per-instance limit). `GET /api/instance-stats` — a node-global
    /// path (not project-scoped), gated `System·Read`.
    pub async fn fetch_instance_stats(&self) -> Result<serde_json::Value> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .get(format!("{server}/api/instance-stats"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Run a dead-letter mutation (`purge` / `redrive` / `discard`) on a consumer `topic`
    /// (scope-relative; `alias` for a background-alias consumer), optionally filter-selective and/or
    /// `dry_run`. Returns the number affected plus (for a dry-run) the matching preview
    /// (`POST …/_boatramp/dlq`).
    pub async fn operate_dlq(
        &self,
        scope: OpScope<'_>,
        topic: &str,
        action: &str,
        filter: &DlqFilter,
        dry_run: bool,
    ) -> Result<(usize, Vec<DlqEntry>)> {
        let url = self.op_url(scope, "dlq");
        let client = &self.http;
        #[derive(Serialize)]
        struct Request<'a> {
            topic: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            alias: Option<&'a str>,
            action: &'a str,
            filter: &'a DlqFilter,
            dry_run: bool,
        }
        #[derive(Deserialize)]
        struct DlqResponse {
            affected: usize,
            #[serde(default)]
            matched: Vec<DlqEntry>,
        }
        let resp: DlqResponse = client
            .post(url)
            .json(&Request {
                topic,
                alias: scope.alias(),
                action,
                filter,
                dry_run,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok((resp.affected, resp.matched))
    }

    /// Pause or resume a topic (`POST …/_boatramp/queue/pause`, P2 flow control).
    pub async fn pause_queue(&self, scope: OpScope<'_>, topic: &str, paused: bool) -> Result<()> {
        let url = self.op_url(scope, "queue/pause");
        let client = &self.http;
        #[derive(Serialize)]
        struct Request<'a> {
            topic: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            alias: Option<&'a str>,
            paused: bool,
        }
        client
            .post(url)
            .json(&Request {
                topic,
                alias: scope.alias(),
                paused,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Set a topic's per-topic operator flow-control policy (`POST …/_boatramp/queue/policy`,
    /// v0.4.24). Each cap is optional (`None` = uncapped on that axis).
    pub async fn set_topic_policy(
        &self,
        scope: OpScope<'_>,
        topic: &str,
        max_depth: Option<usize>,
        max_rate_per_sec: Option<u32>,
        max_unflushed: Option<usize>,
    ) -> Result<()> {
        let url = self.op_url(scope, "queue/policy");
        let client = &self.http;
        #[derive(Serialize)]
        struct Request<'a> {
            topic: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            alias: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_depth: Option<usize>,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_rate_per_sec: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_unflushed: Option<usize>,
        }
        client
            .post(url)
            .json(&Request {
                topic,
                alias: scope.alias(),
                max_depth,
                max_rate_per_sec,
                max_unflushed,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// List a topic's consumer groups (`GET …/_boatramp/queue/groups`).
    pub async fn list_groups(&self, scope: OpScope<'_>, topic: &str) -> Result<Vec<GroupEntry>> {
        let url = self.op_url(scope, "queue/groups");
        let client = &self.http;
        #[derive(Deserialize)]
        struct GroupsResponse {
            #[allow(dead_code)]
            version: u32,
            groups: Vec<GroupEntry>,
        }
        let mut req = client.get(url).query(&[("topic", topic)]);
        if let Some(alias) = scope.alias() {
            req = req.query(&[("alias", alias)]);
        }
        let resp: GroupsResponse = req.send().await?.error_for_status()?.json().await?;
        Ok(resp.groups)
    }

    /// Reset or delete a consumer group (`POST …/_boatramp/queue/group`). For `reset`, `start` is
    /// `"earliest"` or `"latest"`.
    pub async fn group_op(
        &self,
        scope: OpScope<'_>,
        topic: &str,
        group: &str,
        action: &str,
        start: Option<&str>,
    ) -> Result<()> {
        let url = self.op_url(scope, "queue/group");
        let client = &self.http;
        #[derive(Serialize)]
        struct Request<'a> {
            topic: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            alias: Option<&'a str>,
            group: &'a str,
            action: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            start: Option<&'a str>,
        }
        client
            .post(url)
            .json(&Request {
                topic,
                alias: scope.alias(),
                group,
                action,
                start,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Peek the head of a topic's LIVE work-queue without consuming (`GET …/_boatramp/queue/peek`).
    pub async fn peek_queue(
        &self,
        scope: OpScope<'_>,
        topic: &str,
        limit: Option<usize>,
    ) -> Result<Vec<QueuePeekEntry>> {
        let url = self.op_url(scope, "queue/peek");
        let client = &self.http;
        #[derive(Deserialize)]
        struct QueuePeekResponse {
            #[allow(dead_code)]
            version: u32,
            messages: Vec<QueuePeekEntry>,
        }
        let mut req = client.get(url).query(&[("topic", topic)]);
        if let Some(alias) = scope.alias() {
            req = req.query(&[("alias", alias)]);
        }
        if let Some(limit) = limit {
            req = req.query(&[("limit", limit.to_string())]);
        }
        let resp: QueuePeekResponse = req.send().await?.error_for_status()?.json().await?;
        Ok(resp.messages)
    }

    /// Replay a GROUPED topic's retained history from an offset without consuming
    /// (`GET …/_boatramp/queue/replay`, P2). Returns the messages plus the `next_after` cursor to
    /// page forward (`None` when the history is exhausted).
    pub async fn replay_queue(
        &self,
        scope: OpScope<'_>,
        topic: &str,
        after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<(Vec<QueuePeekEntry>, Option<String>)> {
        let url = self.op_url(scope, "queue/replay");
        let client = &self.http;
        #[derive(Deserialize)]
        struct QueueReplayResponse {
            #[allow(dead_code)]
            version: u32,
            messages: Vec<QueuePeekEntry>,
            #[serde(default)]
            next_after: Option<String>,
        }
        let mut req = client.get(url).query(&[("topic", topic)]);
        if let Some(alias) = scope.alias() {
            req = req.query(&[("alias", alias)]);
        }
        if let Some(after) = after {
            req = req.query(&[("after", after)]);
        }
        if let Some(limit) = limit {
            req = req.query(&[("limit", limit.to_string())]);
        }
        let resp: QueueReplayResponse = req.send().await?.error_for_status()?.json().await?;
        Ok((resp.messages, resp.next_after))
    }

    /// List (or `show`) a topic's dead-letters (`GET …/_boatramp/dlq`), filter-matching. `show` with
    /// `filter.id` set returns the single dead-letter in full (with `payload_b64`); otherwise a
    /// metadata listing.
    pub async fn list_dlq(
        &self,
        scope: OpScope<'_>,
        topic: &str,
        show: bool,
        filter: &DlqFilter,
    ) -> Result<Vec<DlqEntry>> {
        let url = self.op_url(scope, "dlq");
        let client = &self.http;
        #[derive(Deserialize)]
        struct DlqListResponse {
            #[allow(dead_code)]
            version: u32,
            dead_letters: Vec<DlqEntry>,
        }
        let mut req = client.get(url).query(&[("topic", topic)]);
        if let Some(alias) = scope.alias() {
            req = req.query(&[("alias", alias)]);
        }
        if show {
            req = req.query(&[("show", "true")]);
        }
        if let Some(id) = &filter.id {
            req = req.query(&[("id", id)]);
        }
        if let Some(group) = &filter.group {
            req = req.query(&[("group", group)]);
        }
        if let Some(older) = filter.older_than_ms {
            req = req.query(&[("older_than_ms", older.to_string())]);
        }
        if let Some(m) = &filter.match_last_error {
            req = req.query(&[("match", m)]);
        }
        if let Some(limit) = filter.limit {
            req = req.query(&[("limit", limit.to_string())]);
        }
        let resp: DlqListResponse = req.send().await?.error_for_status()?.json().await?;
        Ok(resp.dead_letters)
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

    /// Trigger the daemon-mediated blob drain (`POST /api/blob-drain`, `System·Admin`, v0.6.3): the
    /// running daemon drains its OWN configured `[serve.blob_fallback]` secondary → primary. The body
    /// names no source/dest (the daemon uses its own pair). Consumes the streamed **NDJSON** response
    /// (`application/x-ndjson`): each `\n`-delimited line is a JSON object — a `"type":"progress"`
    /// snapshot (printed to stderr as it arrives so a long copy shows liveness) or the FINAL
    /// `"type":"report"` object, which is returned. A `422` (no fallback configured) or any non-2xx is
    /// surfaced verbatim as [`ClientError::Refused`] (mirrors [`migrate_trigger`](Self::migrate_trigger)'s
    /// 200-vs-error branching); the caller decides the exit code from the returned report's fields.
    pub async fn blob_drain(
        &self,
        dry_run: bool,
        concurrency: Option<usize>,
        prefix: Option<&str>,
    ) -> Result<serde_json::Value> {
        let Self {
            http, base: server, ..
        } = self;
        let body = serde_json::json!({
            "dry_run": dry_run,
            "concurrency": concurrency,
            "prefix": prefix,
        });
        let resp = http
            .post(format!("{server}/api/blob-drain"))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            // 422 = no [serve.blob_fallback] configured; any other non-2xx = refused/error. The body is
            // a small JSON error object (or text) — surface it verbatim.
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "blob drain refused ({status}): {}",
                text.trim()
            )));
        }

        // Consume the NDJSON stream (progress → stderr, final report → returned). Shared with
        // `blob_purge` via `consume_ndjson_report`.
        consume_ndjson_report(resp, "blob drain", print_drain_progress).await
    }

    /// Run a general provably-safe blob purge (`POST /api/blob-purge`, `System·Admin`, v0.6.4): the
    /// running daemon reclaims a PROVABLY-SAFE object set — `unreferenced` (GC of blobs no live
    /// manifest points at) or `drained_source` (delete a migration-source key only once byte-confirmed
    /// in the primary). Dry-run unless `apply`; `prefix` scopes a `drained_source` purge. Consumes the
    /// streamed **NDJSON** response (reusing the drain's [`consume_ndjson_report`] consumer): progress
    /// lines print to stderr, the FINAL `"type":"report"` object is returned. A **409** (an
    /// `unreferenced` purge refused while a read-fallback secondary is attached), a **422** (no
    /// fallback for `drained_source`), or any other non-2xx is surfaced verbatim as
    /// [`ClientError::Refused`]; the caller decides the exit code from the returned report's fields.
    pub async fn blob_purge(
        &self,
        mode: &str,
        apply: bool,
        prefix: Option<&str>,
        superseded_ext: Option<&str>,
    ) -> Result<serde_json::Value> {
        let Self {
            http, base: server, ..
        } = self;
        let mut body = serde_json::json!({
            "mode": mode,
            "apply": apply,
            "prefix": prefix,
        });
        // Only the `legacy_derivatives` mode reads `superseded_ext`; the server rejects an unknown
        // field, so send it ONLY when present.
        if let Some(ext) = superseded_ext {
            body["superseded_ext"] = serde_json::Value::String(ext.to_string());
        }
        let resp = http
            .post(format!("{server}/api/blob-purge"))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            // 409 = unreferenced refused (a fallback is attached); 422 = no fallback for
            // drained-source; any other non-2xx = refused/error. The body is a small JSON error
            // object (or text) — surface it verbatim.
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "blob purge refused ({status}): {}",
                text.trim()
            )));
        }
        consume_ndjson_report(resp, "blob purge", print_purge_progress).await
    }

    /// Fetch the node's structured blob transition-mode state (`GET /api/blob-status`, `System·Read`,
    /// v0.6.4): `{ "blob_fallback_active": <bool> }` — whether a read-fallback secondary is attached
    /// (the node is mid-migration). Returns the parsed JSON object.
    pub async fn blob_status(&self) -> Result<serde_json::Value> {
        let Self {
            http, base: server, ..
        } = self;
        let resp = http
            .get(format!("{server}/api/blob-status"))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<serde_json::Value>().await?)
    }

    /// Dead content-addressed references (`GET /api/blob-verify`): blobs a live deployment/function
    /// references but that are missing from the backend. Returns the raw `{ "dead_references": [...] }`.
    pub async fn blob_verify(&self) -> Result<serde_json::Value> {
        let Self {
            http, base: server, ..
        } = self;
        let resp = http
            .get(format!("{server}/api/blob-verify"))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<serde_json::Value>().await?)
    }

    /// Guarded blob reconcile (`POST /api/blob-reconcile`, `System·Admin`, PLAN-clone-robustness #4):
    /// bless an index↔object size drift by re-writing each in-scope object so its declared size
    /// matches its body. Dry-run unless `apply`; `include_primary` is the audited opt-in to also
    /// reconcile baseline/primary objects (default der/-only). Returns the JSON report object.
    pub async fn blob_reconcile(
        &self,
        prefix: Option<&str>,
        apply: bool,
        include_primary: bool,
    ) -> Result<serde_json::Value> {
        let Self {
            http, base: server, ..
        } = self;
        let body = serde_json::json!({
            "prefix": prefix,
            "apply": apply,
            "include_primary": include_primary,
        });
        let resp = http
            .post(format!("{server}/api/blob-reconcile"))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "blob reconcile refused ({status}): {}",
                text.trim()
            )));
        }
        Ok(resp.json::<serde_json::Value>().await?)
    }

    /// Hash a local file and upload it as a blob; returns its content-address.
    pub async fn put_file_blob(&self, path: &std::path::Path) -> Result<String> {
        let hash = hash_file(path).await?;
        self.upload_blob(&hash, path).await?;
        Ok(hash)
    }

    /// Hash an in-memory blob (sha256-hex, identical to [`hash_file`]) and upload it; returns its
    /// content-address. For a bundle the CLI assembles in memory — e.g. `project migrate` reading a
    /// migrations directory — rather than a file already on disk.
    pub async fn put_bytes_blob(&self, bytes: Vec<u8>) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hex::encode(hasher.finalize());
        let Self {
            http, base: server, ..
        } = self;
        http.put(format!("{server}/api/blobs/{hash}"))
            .body(bytes)
            .send()
            .await?
            .error_for_status()?;
        Ok(hash)
    }

    /// Mint a scoped, short-lived S3 upload credential for a project+site's blob container
    /// (`POST /api/blob-mint-upload`, gated `BlobUpload·Write`). The project is host-forced from the
    /// token/context; the operator names `site`, `container`, exactly one of `key`/`prefix`, the
    /// perms (empty ⇒ write-only), the constraints, and `ttl_seconds` (clamped to the operator ceiling
    /// server-side). Returns the self-describing [`MintUploadResult`] (presigned-put or
    /// temp-credentials).
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_upload(
        &self,
        site: &str,
        container: &str,
        key: Option<&str>,
        prefix: Option<&str>,
        perms: &[String],
        ttl_seconds: u64,
        content_type: Option<&str>,
        max_bytes: Option<u64>,
        require_sha256: bool,
    ) -> Result<MintUploadResult> {
        let seg = project_seg(&self.project, "blob-mint-upload");
        let Self {
            http, base: server, ..
        } = self;
        let body = serde_json::json!({
            "site": site,
            "container": container,
            "key": key,
            "prefix": prefix,
            "perms": perms,
            "content_type": content_type,
            "max_bytes": max_bytes,
            "require_sha256": require_sha256,
            "create_only": key.is_some(), // a single-key (UGC) credential defaults create-only
            "ttl_seconds": ttl_seconds,
        });
        let resp = http
            .post(format!("{server}/api/{seg}"))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Refused(format!(
                "mint-upload refused ({status}): {}",
                body.trim()
            )))
        }
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
    /// non-empty project or the reserved `default`. On a `409` refusal, the server's
    /// enumerated body is returned as [`ClientError::Refused`] so the CLI can print it
    /// verbatim (with a `--force` hint) rather than the opaque generic HTTP error.
    pub async fn delete_project(&self, name: &str) -> Result<()> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let resp = client
            .delete(format!("{server}/api/projects/{name}"))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::CONFLICT {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(body.trim_end().to_string()));
        }
        resp.error_for_status()?;
        Ok(())
    }

    /// Fetch the **teardown plan** for a project (`DELETE /api/projects/<name>?dry_run=true`)
    /// — a preview of everything a force-delete would remove. Mutates nothing.
    pub async fn project_teardown_plan(&self, name: &str) -> Result<serde_json::Value> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .delete(format!("{server}/api/projects/{name}"))
            .query(&[("dry_run", "true")])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Force-delete a project (`DELETE /api/projects/<name>?force=true`): cascade the
    /// teardown of everything it owns and remove the project. Returns the executed
    /// teardown report.
    pub async fn force_delete_project(&self, name: &str) -> Result<serde_json::Value> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        Ok(client
            .delete(format!("{server}/api/projects/{name}"))
            .query(&[("force", "true")])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// `boatramp project prune <name>` — GC a project's PROVABLY-orphaned control-plane state
    /// (`Project·Admin` on the target). `apply == false` is the safe dry-run: `GET
    /// /api/project-prune?project=<name>` reports exactly what an apply would remove and mutates
    /// NOTHING. `apply == true` is `POST …` and deletes exactly that set. Returns the typed plan
    /// (dry-run or executed). A non-2xx surfaces the server's refusal text.
    pub async fn project_prune(
        &self,
        name: &str,
        apply: bool,
    ) -> Result<boatramp_core::project_prune::ProjectPrunePlan> {
        let Self {
            http: client,
            base: server,
            ..
        } = self;
        let url = format!("{server}/api/project-prune");
        let req = if apply {
            client.post(&url)
        } else {
            client.get(&url)
        };
        let resp = req.query(&[("project", name)]).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Refused(format!(
                "project prune refused ({status}): {}",
                body.trim_end()
            )));
        }
        Ok(resp.json().await?)
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
    use boatramp_server::{Auth, require_auth};

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

    /// Reproduce-first for the `project migrate` trigger path: a managed backend that answers
    /// not-ready (`503` + `Retry-After`) twice, then returns a clean `MigrationReport` — the
    /// trigger must BLOCK on the shared readiness wait, then succeed once ready (3 attempts). A
    /// `no_wait` policy against an always-not-ready route fails FAST (one attempt) with the hint.
    /// (MUTATION PROOF: drop the wait in `managed_wait::send_with_ready_wait` and the waits-then-
    /// succeeds case fails on the first 503.)
    #[tokio::test]
    async fn migrate_trigger_waits_through_pending_then_succeeds() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let apply_hits = Arc::new(AtomicUsize::new(0));
        let apply_route = Arc::clone(&apply_hits);
        let dryrun_hits = Arc::new(AtomicUsize::new(0));
        let dryrun_route = Arc::clone(&dryrun_hits);

        let app = axum::Router::new()
            .route(
                "/api/migrate/appdb/apply",
                axum::routing::post(move || {
                    let hits = Arc::clone(&apply_route);
                    async move {
                        let n = hits.fetch_add(1, Ordering::SeqCst);
                        if n < 2 {
                            (
                                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                                [(axum::http::header::RETRY_AFTER, "0")],
                                "managed database not ready\n",
                            )
                                .into_response()
                        } else {
                            (
                                reqwest::StatusCode::OK,
                                r#"{"newly_applied":[],"already_applied":[],"pending":[],"failed":null}"#,
                            )
                                .into_response()
                        }
                    }
                }),
            )
            .route(
                "/api/migrate/appdb/dry-run",
                axum::routing::post(move || {
                    let hits = Arc::clone(&dryrun_route);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        (
                            reqwest::StatusCode::SERVICE_UNAVAILABLE,
                            [(axum::http::header::RETRY_AFTER, "0")],
                            "managed database not ready\n",
                        )
                            .into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let cp = ControlPlane::new(
            format!("http://127.0.0.1:{}", addr.port()),
            build_client(None, None, None, None),
            boatramp_core::project::DEFAULT_PROJECT.into(),
        );

        // Waits through two not-ready answers, then applies.
        let report = cp
            .migrate_trigger(
                "appdb",
                "apply",
                &"a".repeat(64),
                None,
                crate::managed_wait::WaitPolicy::new(std::time::Duration::from_secs(10)),
            )
            .await
            .expect("the migrate trigger waits then succeeds");
        assert!(report.newly_applied.is_empty());
        assert_eq!(
            apply_hits.load(Ordering::SeqCst),
            3,
            "two not-ready attempts, then the applied one"
        );

        // `no_wait` surfaces the not-ready 503 immediately (one attempt) with the cure hint.
        let err = cp
            .migrate_trigger(
                "appdb",
                "dry-run",
                &"a".repeat(64),
                None,
                crate::managed_wait::WaitPolicy::no_wait(),
            )
            .await
            .expect_err("no_wait fails fast on a not-ready backend");
        let msg = err.to_string();
        assert!(
            msg.contains("--wait-ready-secs"),
            "the refusal hints the wait cure: {msg}"
        );
        assert_eq!(
            dryrun_hits.load(Ordering::SeqCst),
            1,
            "no_wait makes exactly one attempt"
        );
    }

    // ---- clone/from long-transfer resilience (the v0.65 `error decoding response body` fix) ----

    /// The stream-driver classifies each terminal shape correctly. The LOAD-BEARING case is the
    /// severed mid-stream body — the reported `error decoding response body` — which must be a
    /// RESUMABLE `Interrupted` (carrying the blobs-still-to-transfer the plan observed), NOT a fatal
    /// error. Pre-fix, the same `chunk?` turned this into `ClientError::Http(..)` and failed the
    /// whole clone.
    #[tokio::test]
    async fn drive_clone_ndjson_classifies_a_severed_stream_as_resumable() {
        use boatramp_core::project_export::{CloneEvent, ClonePlan, ImportReport};

        let plan = ClonePlan {
            source_project: "src".into(),
            target_project: "dst".into(),
            blobs_total: 10,
            blobs_present: 0,
            blobs_to_transfer: 10,
            ..Default::default()
        };
        let plan_line = format!(
            "{}\n",
            serde_json::to_string(&CloneEvent::Plan(plan)).unwrap()
        );
        let report_line = format!(
            "{}\n",
            serde_json::to_string(&CloneEvent::Report(ImportReport {
                blobs: 10,
                ..Default::default()
            }))
            .unwrap()
        );

        // A complete stream (plan + terminal report) converges to Applied.
        let full = futures::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(plan_line.clone().into_bytes()),
            Ok(report_line.into_bytes()),
        ]);
        match drive_clone_ndjson(full, "dst").await {
            CloneAttemptOutcome::Applied { report, .. } => assert_eq!(report.blobs, 10),
            other => panic!("a complete stream must be Applied, got {other:?}"),
        }

        // A transport error mid-stream (`error decoding response body`) is a RESUMABLE Interrupted
        // carrying the blobs still to transfer — the exact bug shape.
        let severed = futures::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(plan_line.clone().into_bytes()),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "error decoding response body",
            )),
        ]);
        match drive_clone_ndjson(severed, "dst").await {
            CloneAttemptOutcome::Interrupted { remaining, .. } => assert_eq!(remaining, Some(10)),
            other => panic!("a severed stream must be a resumable Interrupted, got {other:?}"),
        }

        // A clean end BEFORE the terminal report is ALSO a resumable Interrupted (truncated).
        let truncated = futures::stream::iter(vec![Ok::<Vec<u8>, std::io::Error>(
            plan_line.clone().into_bytes(),
        )]);
        match drive_clone_ndjson(truncated, "dst").await {
            CloneAttemptOutcome::Interrupted { remaining, .. } => assert_eq!(remaining, Some(10)),
            other => panic!("a truncated stream must be a resumable Interrupted, got {other:?}"),
        }

        // A terminal Error event is a REAL failure (Fatal) — never retried.
        let errored = futures::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(plan_line.into_bytes()),
            Ok(format!(
                "{}\n",
                serde_json::to_string(&CloneEvent::Error {
                    message: "restore blew up".into()
                })
                .unwrap()
            )
            .into_bytes()),
        ]);
        match drive_clone_ndjson(errored, "dst").await {
            CloneAttemptOutcome::Fatal(m) => assert!(m.contains("restore blew up"), "{m}"),
            other => panic!("a terminal Error event must be Fatal, got {other:?}"),
        }
    }

    /// The give-up policy abandons a transfer ONLY after the stall budget of consecutive
    /// NO-progress interruptions — a transfer that keeps shrinking its remaining-to-transfer is
    /// resumed indefinitely.
    #[test]
    fn clone_resume_step_gives_up_only_without_progress() {
        // No forward progress (same `remaining` every attempt) → stall climbs to the cap → give up.
        let mut stall = 0u32;
        let mut best = Some(100usize);
        let mut gave_up = false;
        for _ in 0..CLONE_RESUME_MAX_STALLED_ATTEMPTS {
            let (s, b, g) = clone_resume_step(stall, best, Some(100));
            stall = s;
            best = b;
            gave_up = g;
        }
        assert!(
            gave_up,
            "a stuck transfer must give up after {CLONE_RESUME_MAX_STALLED_ATTEMPTS} no-progress tries"
        );

        // Forward progress (shrinking `remaining`) resets the stall every time → never gives up,
        // even across far more interruptions than the cap.
        let mut stall = 0u32;
        let mut best = None;
        let mut remaining = 1000usize;
        for _ in 0..(CLONE_RESUME_MAX_STALLED_ATTEMPTS * 3) {
            remaining = remaining.saturating_sub(10);
            let (s, b, g) = clone_resume_step(stall, best, Some(remaining));
            stall = s;
            best = b;
            assert!(
                !g,
                "a progressing transfer must never give up (remaining={remaining}, stall={stall})"
            );
        }
        assert_eq!(stall, 0, "forward progress keeps the stall counter at zero");
    }

    /// END-TO-END through the REAL `project_clone_from` + `reqwest`: a mock `/clone/from` node whose
    /// FIRST response is severed mid-stream (the bug's `error decoding response body`) and whose
    /// second completes. The client must RE-ISSUE and converge to `Applied` — pre-fix it failed the
    /// whole clone on the first severed body.
    #[tokio::test]
    async fn project_clone_from_resumes_after_a_severed_stream() {
        use axum::response::IntoResponse;
        use boatramp_core::project_export::{CloneEvent, ClonePlan, ImportReport, ManagedRestore};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let count = Arc::new(AtomicUsize::new(0));

        async fn handler(
            axum::extract::State(count): axum::extract::State<Arc<AtomicUsize>>,
            _req: axum::extract::Request,
        ) -> axum::response::Response {
            let n = count.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // Attempt 1: plan + a heartbeat, then SEVER the body mid-stream (no terminal report).
                let plan = ClonePlan {
                    source_project: "src".into(),
                    target_project: "dst".into(),
                    blobs_total: 10,
                    blobs_present: 0,
                    blobs_to_transfer: 10,
                    ..Default::default()
                };
                let lines = vec![
                    Ok::<Vec<u8>, std::io::Error>(
                        format!(
                            "{}\n",
                            serde_json::to_string(&CloneEvent::Plan(plan)).unwrap()
                        )
                        .into_bytes(),
                    ),
                    Ok(format!(
                        "{}\n",
                        serde_json::to_string(&CloneEvent::Progress {
                            bytes_transferred: 1,
                            elapsed_secs: 0,
                        })
                        .unwrap()
                    )
                    .into_bytes()),
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "severed mid-transfer",
                    )),
                ];
                let mut resp =
                    axum::body::Body::from_stream(futures::stream::iter(lines)).into_response();
                resp.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/x-ndjson"),
                );
                resp
            } else {
                // Resume attempt: the diff shows forward progress (7 present) and the stream completes.
                let plan = ClonePlan {
                    source_project: "src".into(),
                    target_project: "dst".into(),
                    blobs_total: 10,
                    blobs_present: 7,
                    blobs_to_transfer: 3,
                    ..Default::default()
                };
                let report = ImportReport {
                    blobs: 3,
                    ..Default::default()
                };
                format!(
                    "{}\n{}\n",
                    serde_json::to_string(&CloneEvent::Plan(plan)).unwrap(),
                    serde_json::to_string(&CloneEvent::Report(report)).unwrap(),
                )
                .into_response()
            }
        }

        let app = axum::Router::new()
            .route(
                "/api/projects/{target}/clone/from",
                axum::routing::post(handler),
            )
            .with_state(count.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://127.0.0.1:{}", addr.port());

        let cp = ControlPlane::new(base.clone(), http_client(None), "dst".into());
        let outcome = cp
            .project_clone_from(
                "dst",
                &base,
                Some("src"),
                b"srctok",
                true,  // apply
                false, // verify
                true,  // overwrite
                false, // force
                true,  // data_only
                Some(ManagedRestore::ShadowSwap),
                false, // skip_control_plane_kv
                false, // drop_soft_deleted
                MismatchFlags::default(),
            )
            .await
            .expect("the clone must RESUME past the severed first attempt and converge to Applied");
        match outcome {
            CloneOutcome::Applied { report, .. } => assert_eq!(report.blobs, 3),
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "the client must re-issue the clone after the severed first attempt"
        );
    }
}
