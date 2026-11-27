//! The reverse-proxy data plane: stream a request to an absolute upstream URL
//! or a gateway-selected upstream pool (with SSRF guards, address pinning,
//! retry, and websocket/upgrade tunnelling), plus the compute-backend wake
//! path (scale-from-zero) that warms a parked replica before dispatch. Pulls
//! the serve scope in via `use super::*`.

use super::*;
use boatramp_core::project::ProjectRef;

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http;
use boatramp_http::h1::{BodyReader, Conn, chunked, encode_request_head};
use bytes::Bytes;
use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Reverse-proxy a GET to an absolute upstream URL, streaming the response.
///
/// Guarded against SSRF: only `http`/`https`, the host must pass the deploy
/// config's `proxy_allow` list, and every resolved address must be public
/// (private/loopback/link-local/metadata targets are refused).
pub(super) async fn proxy(
    request: Request,
    url: &str,
    config: &DeployConfig,
    client_ip: IpAddr,
) -> Response {
    // SSRF: validate scheme + allow-list, and pin the verified address so the
    // actual connection cannot be re-resolved to an internal host (no TOCTOU).
    let (parsed, addr, host) = match check_proxy_target(url, config).await {
        Ok(resolved) => resolved,
        Err(reason) => {
            tracing::warn!(%url, reason, "proxy target refused");
            return (StatusCode::FORBIDDEN, "proxy target not allowed\n").into_response();
        }
    };
    let https = parsed.scheme() == "https";
    let client = match pinned_client(&host, addr, https) {
        Ok(client) => client,
        Err(_) => return (StatusCode::BAD_GATEWAY, "proxy client error\n").into_response(),
    };

    let (parts, body) = request.into_parts();
    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();

    // Build the upstream request against the pinned absolute URI. hyper sets Host
    // from the URI authority (the real upstream host), so we drop the client's Host.
    let uri: axum::http::Uri = match parsed.as_str().parse() {
        Ok(uri) => uri,
        Err(_) => return (StatusCode::BAD_GATEWAY, "proxy client error\n").into_response(),
    };
    let mut builder = Request::builder().method(parts.method).uri(uri);
    let out_headers = builder
        .headers_mut()
        .expect("fresh request builder has no error");
    // Forward request headers minus hop-by-hop and Host. `append` mirrors reqwest's
    // header semantics (preserves any inbound X-Forwarded-* chain).
    for (name, value) in &parts.headers {
        if name == header::HOST || is_hop_by_hop(name) {
            continue;
        }
        out_headers.append(name.clone(), value.clone());
    }
    if let Ok(v) = HeaderValue::from_str(&client_ip.to_string()) {
        out_headers.append(HeaderName::from_static("x-forwarded-for"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&scheme) {
        out_headers.append(HeaderName::from_static("x-forwarded-proto"), v);
    }
    if let Some(host_header) = parts.headers.get(header::HOST) {
        out_headers.append(
            HeaderName::from_static("x-forwarded-host"),
            host_header.clone(),
        );
    }
    let req = match builder.body(body) {
        Ok(req) => req,
        Err(_) => return (StatusCode::BAD_GATEWAY, "proxy client error\n").into_response(),
    };

    match client.send(req).await {
        Ok(resp) => {
            let status = resp.status();
            // Pass response headers through, minus hop-by-hop. A known `Content-Length` is
            // KEPT so the serving stack can frame the re-streamed body with it (a proxied
            // download keeps progress + range); `append` preserves REPEATED headers —
            // notably every `Set-Cookie` (see `forward_response_headers`).
            let mut headers = HeaderMap::new();
            forward_response_headers(resp.headers(), &[], &mut headers);
            // Stream the upstream body straight to the client off the pooled connection —
            // no hyper connection task, no intermediate copy (see [`ClientBody`]).
            (status, headers, Body::from_stream(resp.into_body())).into_response()
        }
        Err(UpstreamError::Timeout) => {
            tracing::warn!(%url, "proxy request timed out");
            (StatusCode::GATEWAY_TIMEOUT, "upstream timeout\n").into_response()
        }
        Err(UpstreamError::Failed) => (StatusCode::BAD_GATEWAY, "upstream error\n").into_response(),
        // Unreachable on the absolute-URL path (buffering is never enabled on `pinned_client`),
        // but mapped for exhaustiveness and so the shared `send` seam has one 413/408/503 contract.
        Err(UpstreamError::PayloadTooLarge) => {
            (StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n").into_response()
        }
        Err(UpstreamError::RequestBodyTimeout) => {
            (StatusCode::REQUEST_TIMEOUT, "request body read timed out\n").into_response()
        }
        Err(UpstreamError::BufferingOverloaded) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "node buffering capacity reached\n",
        )
            .into_response(),
    }
}

/// Connection-level (hop-by-hop) headers that must not be forwarded end to end.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    const HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    HOP.contains(&name.as_str())
}

/// Copy an upstream response's headers into the downstream `out` map, **preserving every
/// repeated header**. This is load-bearing for authentication: HTTP permits multiple
/// `Set-Cookie` fields and a login flow relies on it — a 303 from an upstream like Gitea
/// carries several distinct cookies at once (the session cookie plus a CSRF cookie, often
/// more). A [`HeaderMap::insert`] would collapse the repeats to the **last** value, silently
/// dropping the session `Set-Cookie`, so the browser never establishes the session and is
/// bounced back to the login page. [`HeaderMap::append`] keeps each value as a separate
/// field, matching how the request leg (and the `splice` fast-path) already forward headers.
///
/// Drops hop-by-hop headers (including `Transfer-Encoding`, so a chunked upstream re-frames
/// downstream) plus any header named in the upstream's `header_down.remove`. A known
/// `Content-Length` is KEPT: the serving stack now frames the re-streamed body with it (a
/// declared-length streaming body), so a proxied download keeps its length — and the h1
/// writer is defensive if the upstream's length and body ever disagree.
fn forward_response_headers(upstream_headers: &HeaderMap, remove: &[String], out: &mut HeaderMap) {
    for (name, value) in upstream_headers {
        if is_hop_by_hop(name) || remove.iter().any(|h| name.as_str().eq_ignore_ascii_case(h)) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
}

/// Validate a proxy target against the SSRF policy and return the parsed URL,
/// a verified public socket address to pin, and the host. `Err` carries a short
/// reason for logging.
async fn check_proxy_target(
    url: &str,
    config: &DeployConfig,
) -> Result<(reqwest::Url, SocketAddr, String), &'static str> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "unparsable url")?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("scheme not http(s)"),
    }
    let host = parsed.host_str().ok_or("missing host")?.to_string();
    if !config.proxy_host_allowed(&host) {
        return Err("host not in proxy_allow");
    }
    // Resolve, require every address public, and keep one to pin the connection.
    let port = parsed.port_or_known_default().unwrap_or(80);
    let mut pinned = None;
    for addr in tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| "dns resolution failed")?
    {
        if !boatramp_core::access::is_global_ip(addr.ip()) {
            return Err("resolves to a non-public address");
        }
        pinned.get_or_insert(addr);
    }
    let addr = pinned.ok_or("no addresses resolved")?;
    Ok((parsed, addr, host))
}

/// Default cap for an upstream connection's H1 read buffer. Each connection retains
/// one, so at proxy fan-out this is the dominant proxy-path resident set; 32 KiB is
/// the knee (profiled) — far below hyper's 400 KiB default, at a few percent read
/// overhead. Operators can override it per upstream (`read_buffer_bytes`).
const DEFAULT_UPSTREAM_READ_BUFFER: usize = 32 * 1024;

/// Default hard cap on a buffered request body (`buffer_requests`), used when an upstream sets
/// no `max_buffer_bytes`. 1 GiB covers a large registry layer while bounding the temp space a
/// single length-unknown upload can hold; the operator raises it per upstream for larger layers,
/// or lowers it on a space-tight node. This bounds BOTH memory and disk: the body is streamed to
/// a temp file (so RSS stays flat regardless of size) and the running total is checked before
/// every write, so a single request can never spill past this (→ 413), and total exposure is this
/// cap × the number of concurrent buffered uploads.
const DEFAULT_MAX_BUFFER_BYTES: u64 = 1024 * 1024 * 1024;

/// Default read-idle timeout for a buffered (length-unknown) request body: the longest a single
/// inbound body read (`data.next()`) may stall during buffering before the buffering is aborted
/// (`408 Request Timeout`). Matches the inbound serve read-timeout default
/// ([`boatramp_http::h1::DEFAULT_READ_TIMEOUT`], 30 s): a legitimate upload hands the proxy body
/// bytes continuously, so it never idles this long, while a stalled peer is dropped promptly
/// instead of pinning a connection slot + its temp file. Independent of `request_timeout_ms` (which
/// bounds only the upstream write + response head, AFTER buffering), and of the connection's
/// idle-timeout (which never fires on an ACTIVELY-trickling stream). Per-upstream overridable via
/// `buffer_read_timeout_ms`.
const DEFAULT_BUFFER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Default minimum sustained inbound throughput for a buffered (length-unknown) request body, in
/// bytes/sec. This is the throughput-aware backstop the per-read idle timeout cannot provide — a
/// slow-loris that trickles JUST often enough to keep resetting the read-idle timer (e.g. one byte
/// every few seconds) never idles, but it also cannot sustain this floor, so the rate check cuts it
/// (`408 Request Timeout`). Crucially, unlike the flat whole-phase wall-clock budget it replaces, a
/// throughput floor lets a steadily-progressing upload of ANY total size finish: the old flat 120 s
/// cap falsely `408`'d a 1 GiB layer trickling at a legitimate-but-slow 5 MB/s (~200 s > 120 s),
/// implying an ~8.5 MB/s floor just to complete. 1 KiB/s is ~7× below a 56k dial-up link yet far
/// above any byte-trickle, so it discriminates a drip from a slow-but-real upload. Per-upstream
/// overridable via `buffer_min_rate_bytes_per_sec`; `0` disables the floor (read-idle only).
const DEFAULT_BUFFER_MIN_RATE_BYTES_PER_SEC: u64 = 1024;

/// Default trailing window over which [`DEFAULT_BUFFER_MIN_RATE_BYTES_PER_SEC`] is averaged. The
/// rate check fires once per elapsed window: a body that failed to deliver `floor × window` bytes in
/// the just-elapsed window is below the floor and aborted. 30 s smooths over a brief pause (a legit
/// upload that stutters then catches up averages out) while reacting to a sustained rate drop within
/// ~1–2 windows. Per-upstream overridable via `buffer_min_rate_window_ms`.
const DEFAULT_BUFFER_MIN_RATE_WINDOW: Duration = Duration::from_secs(30);

/// Default for the absolute whole-phase wall-clock ceiling: **`Some(1 hour)` — ON**. The throughput
/// floor (above) is the primary slow-client backstop, but on its own it leaves a residual TIME bound
/// gap: a client that drips at just over the floor (e.g. ~1.1 KiB/s) clears the rate check AND never
/// trips the read-idle timer, so with no ceiling it could hold a connection slot + up to
/// `max_buffer_bytes` of temp spill for `max_buffer_bytes ÷ floor` ≈ **12 days** (1 GiB ÷ 1 KiB/s)
/// before the `413` cap finally fires. A sane default ceiling restores a per-connection time bound.
///
/// The ceiling is anchored to a REALISTIC minimum legitimate rate, NOT to the floor: at 1 h with the
/// 1 GiB cap a legitimate upload only false-`408`s if it sustains below ~291 KiB/s for a FULL hour —
/// no real registry push does (a 1 GiB layer at 1 MB/s finishes in ~18 min). This is far less
/// aggressive than the v0.73.0 flat 120 s cap it effectively restores (which false-positived a 5 MB/s
/// 1 GiB upload at ~200 s); 1 h does not. An operator may raise, lower, or explicitly DISABLE it per
/// upstream via `buffer_total_timeout_ms` (`0` → off) — see [`UpstreamClient::with_buffering`].
/// Disabling it is an opt-in choice for a rare genuinely-huge/slow-link upstream, and it re-exposes
/// the drip-holds-a-slot-for-days window above, so it may only be done alongside the throughput floor
/// (the config validator refuses "floor disabled + ceiling off").
const DEFAULT_BUFFER_TOTAL_TIMEOUT: Option<Duration> = Some(Duration::from_secs(3600));

/// Default node-wide cap on CONCURRENT request-buffering operations (across every listener and
/// upstream). This is the structural total-exposure bound the per-request guards cannot provide:
/// each in-flight buffered upload holds up to `max_buffer_bytes` of temp spill, so without a node
/// aggregate cap the only ceiling on simultaneous buffering is the listener `max_conns` — worst-case
/// spill would be `max_conns × max_buffer_bytes`. With this cap, worst-case spill is bounded by
/// `limit × max_buffer_bytes` and further buffering fails fast with `503 Service Unavailable` (a
/// LOCAL pre-dial refusal — it never contacts a backend, so it does not touch passive health). The
/// blob/storage upload path has its own `max_concurrent_uploads` ([`crate::limits`]); this is the
/// independent gateway-buffering analog. 128 is a defensible default: at the 1 GiB cap default it
/// bounds node spill at ~128 GiB worst case, while being far above any realistic concurrent-registry-
/// push count. Operator-overridable via `serve.max_concurrent_buffering` (see
/// [`set_buffering_concurrency_limit`]).
const DEFAULT_MAX_CONCURRENT_BUFFERING: usize = 128;

/// The configured node-wide buffering-concurrency limit, read ONCE when [`BUFFER_SLOTS`] is first
/// initialized (the first buffering request). [`set_buffering_concurrency_limit`] stores the operator
/// value here at serve startup, before any request is served.
static BUFFER_SLOTS_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_CONCURRENT_BUFFERING);

/// Process-wide semaphore bounding concurrent request-buffering operations, shared across every
/// listener and upstream (like [`POOL`]). A buffering request acquires an OWNED permit BEFORE it
/// spills (before any pool checkout / dial) and holds it for the whole buffering + forward phase, so
/// the permit — and thus the temp spill it represents — is released on EVERY exit path by RAII drop
/// (success, every `408`/`413` abort, dial failure, client disconnect, panic). Sized from
/// [`BUFFER_SLOTS_LIMIT`] at first use.
static BUFFER_SLOTS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        Arc::new(tokio::sync::Semaphore::new(
            BUFFER_SLOTS_LIMIT
                .load(std::sync::atomic::Ordering::Relaxed)
                .max(1),
        ))
    });

/// Set the node-wide buffering-concurrency cap from the operator config. Call ONCE at serve startup,
/// before any request is served (buffering only happens while serving a request, so the cap is in
/// place before [`BUFFER_SLOTS`] is first read). `None` keeps the built-in default
/// ([`DEFAULT_MAX_CONCURRENT_BUFFERING`]); `Some(n)` sets `n` (clamped to ≥ 1 — the cap can be raised
/// or lowered, but never removed: it is a DoS bound that must always exist). A call after the
/// semaphore has already been initialized has no effect on the live count (logged), since the slot
/// count is fixed at first use.
pub(crate) fn set_buffering_concurrency_limit(limit: Option<usize>) {
    if let Some(n) = limit {
        BUFFER_SLOTS_LIMIT.store(n.max(1), std::sync::atomic::Ordering::Relaxed);
    }
}

/// Pool key for pinned upstream connections: the pinned resolution plus the per-upstream
/// options that determine how a connection is dialed (so a TLS and a plaintext connection,
/// or two different read-buffer sizes, never share a pool bucket).
#[derive(Clone, PartialEq, Eq, Hash)]
struct UpstreamClientKey {
    host: String,
    addr: SocketAddr,
    /// Whether the upstream leg is TLS (`https`/`wss`) — a pooled plaintext connection can
    /// never satisfy an `https` request, so it is part of the identity.
    https: bool,
    connect_timeout_ms: Option<u64>,
    request_timeout_ms: Option<u64>,
    tls_insecure: bool,
    read_buffer_bytes: Option<usize>,
}

/// One end of an established upstream HTTP/1.1 connection: plaintext TCP, or a rustls TLS
/// stream over TCP. The pool holds these and `boatramp_http::h1::Conn` drives the wire over
/// whichever transport this is. Delegating `AsyncRead`/`AsyncWrite` (rather than boxing to
/// `dyn`) keeps the hot read/write path monomorphic.
enum Upstream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// How an upstream request failed, mapped to a client-visible status.
#[derive(Debug)]
enum UpstreamError {
    /// The total-request deadline elapsed → `504 Gateway Timeout`.
    Timeout,
    /// Connect / handshake / protocol failure → `502 Bad Gateway`.
    Failed,
    /// A buffered (length-unknown) request body exceeded the upstream's `max_buffer_bytes`
    /// → `413 Payload Too Large`. Only reachable on a `buffer_requests` upstream.
    PayloadTooLarge,
    /// The inbound body read stalled or trickled while buffering a length-unknown request body — a
    /// single read idled past the upstream's `buffer_read_timeout_ms`, the body's sustained
    /// throughput fell below `buffer_min_rate_bytes_per_sec` over its window, or (if set) the
    /// optional `buffer_total_timeout_ms` absolute ceiling elapsed (a slow-trickle / slow-loris
    /// client). Mapped to `408 Request Timeout` — a 4xx, so (unlike a `504`) it is NOT recorded as a
    /// backend health failure: the fault is the client's, not the upstream's. Only reachable on a
    /// `buffer_requests` upstream.
    RequestBodyTimeout,
    /// The node-wide buffering-concurrency cap ([`BUFFER_SLOTS`]) is saturated — too many request
    /// bodies are already being buffered node-wide. Mapped to `503 Service Unavailable`. This is a
    /// LOCAL pre-dial refusal (raised BEFORE any pool checkout or dial), so it never contacts a
    /// backend and must NOT be recorded against passive health (carried out of the gateway path via
    /// [`LocalPreDialOverload`]). Only reachable on a `buffer_requests` upstream.
    BufferingOverloaded,
}

/// Internal, NEVER-serialized marker on a gateway response that reflects a LOCAL pre-dial condition
/// (node-wide buffering saturation → `503`). The gateway dispatch checks for it and SKIPS the
/// passive-health `record` for this request: no connection to the selected backend was ever
/// attempted, so the refusal is the node's, not the backend's, and must not count toward ejecting a
/// healthy backend. Lives only in the in-process `Response::extensions`; it is dropped before the
/// response is written to the client.
#[derive(Clone, Copy)]
struct LocalPreDialOverload;

/// An idle keep-alive upstream connection plus when it went idle (for the reap bound).
struct IdleConn {
    conn: Conn<Upstream>,
    idle_since: std::time::Instant,
}

/// How long an idle upstream connection is retained before it is reaped on the next
/// checkout — mirrors the previous hyper `pool_idle_timeout`, returning connection memory
/// promptly after a spike drains.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
/// Cap on idle connections retained per upstream key — bounds idle pool memory at fan-out.
const MAX_IDLE_PER_KEY: usize = 64;

/// Process-wide pool of idle keep-alive upstream connections, keyed by the pinned upstream
/// identity. Replaces hyper-util's internal connection pool: a cleanly drained keep-alive
/// response returns its connection here (see [`ClientBody`]), and the next request to the
/// same upstream checks one out instead of re-dialing + re-handshaking.
static POOL: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<UpstreamClientKey, Vec<IdleConn>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Check out a live idle connection for `key`, discarding any that have exceeded the idle
/// bound. Returns `None` when the pool has no fresh connection (the caller then dials).
fn pool_checkout(key: &UpstreamClientKey) -> Option<Conn<Upstream>> {
    let mut pool = POOL.lock().unwrap();
    let list = pool.get_mut(key)?;
    while let Some(idle) = list.pop() {
        if idle.idle_since.elapsed() < POOL_IDLE_TIMEOUT {
            return Some(idle.conn);
        }
        // Expired — drop it and try the next-most-recent.
    }
    None
}

/// Return a drained keep-alive connection to the pool for reuse. A connection with any
/// out-of-band leftover bytes (a pipelined byte past the body) is dropped, not pooled — the
/// message boundary can no longer be trusted for the next request.
fn pool_return(key: &UpstreamClientKey, conn: Conn<Upstream>) {
    if conn.buffered() != 0 {
        return;
    }
    let mut pool = POOL.lock().unwrap();
    let list = pool.entry(key.clone()).or_default();
    if list.len() < MAX_IDLE_PER_KEY {
        list.push(IdleConn {
            conn,
            idle_since: std::time::Instant::now(),
        });
    }
    // Over the cap: drop the connection (close it) rather than grow the idle set.
}

/// Cached rustls client configs for the upstream leg, keyed by `tls_insecure`. Building one
/// loads the webpki root store, so the two variants are cached and reused across dials.
static TLS_CLIENT_CONFIGS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<bool, Arc<rustls::ClientConfig>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn tls_client_config(tls_insecure: bool) -> Result<Arc<rustls::ClientConfig>, ()> {
    if let Some(cfg) = TLS_CLIENT_CONFIGS.lock().unwrap().get(&tls_insecure) {
        return Ok(cfg.clone());
    }
    let cfg = Arc::new(upstream_tls_config(tls_insecure)?);
    Ok(TLS_CLIENT_CONFIGS
        .lock()
        .unwrap()
        .entry(tls_insecure)
        .or_insert(cfg)
        .clone())
}

/// The request body, framed for the upstream write. Built once per request from the
/// forwarded headers + the inbound body stream; `None`/idempotent requests are retryable on
/// a stale pooled connection, bodied requests are not (the stream can't be replayed).
enum BodyPlan {
    /// No request body is written. The head may still carry an explicit `Content-Length: 0`
    /// (preserved when the client declared one — some upstreams require it); it never carries
    /// a `Transfer-Encoding`, so the empty-body framing stays unambiguous.
    None,
    /// A fixed-length body (the forwarded `Content-Length`) — forward the stream raw.
    Fixed,
    /// An unknown-length body — chunk-encode it, starting with this already-peeked chunk.
    Chunked(Bytes),
}

/// The inbound request-body data stream (from `axum::body::Body::into_data_stream`), boxed
/// so it can be threaded through the send path without a generic parameter. Only consumed
/// for `Fixed`/`Chunked` plans (never for the retryable `None` path).
type BodyData = Pin<Box<dyn Stream<Item = Result<Bytes, axum::Error>> + Send>>;

/// Time + throughput guards for buffering one length-unknown request body, all derived from the
/// per-upstream config (or the server defaults). Only consulted on the `buffer_requests` path.
#[derive(Clone, Copy)]
struct BufferGuards {
    /// Read-idle timeout: the longest a single inbound body read may stall before buffering aborts
    /// (`408`). Correctly catches a FULLY-stalled client (a read that never yields).
    read_idle: Duration,
    /// Minimum sustained inbound throughput (bytes/sec): if the body's average rate over a trailing
    /// [`BufferGuards::rate_window`] falls below this, buffering aborts (`408`). `0` DISABLES the
    /// floor (rely on `read_idle` only). This — not a flat wall-clock cap — is what lets a
    /// steadily-progressing upload of any size finish while still cutting a sub-floor drip-feed that
    /// never idles.
    min_rate_bytes_per_sec: u64,
    /// The trailing window over which `min_rate_bytes_per_sec` is averaged.
    rate_window: Duration,
    /// Absolute whole-phase wall-clock ceiling (defense-in-depth): a hard upper bound on total
    /// buffering time regardless of throughput. `None` = no ceiling (explicitly disabled); `Some` =
    /// the bound. The server default is now `Some(1 h)` (ON) — see [`DEFAULT_BUFFER_TOTAL_TIMEOUT`]
    /// for why — so this restores a per-connection time bound the throughput floor alone cannot. It
    /// is set high enough never to cut a legitimate upload.
    abs_ceiling: Option<Duration>,
}

/// A pinned upstream client: a handle over the shared connection pool for one upstream
/// identity. Cheap to clone (just the key); the connections live in [`POOL`].
#[derive(Clone)]
struct UpstreamClient {
    key: UpstreamClientKey,
    /// Opt-in: buffer a length-unknown request body to a bounded temp file and forward it with a
    /// `Content-Length` (default OFF — a length-unknown body forwards `chunked`). NOT part of the
    /// pool key: it changes only how THIS request's body is framed, never how a connection is
    /// dialed, so two upstreams differing only here may share pooled connections.
    buffer_requests: bool,
    /// Hard cap (bytes) on a buffered body before `413`; only read when `buffer_requests`.
    max_buffer_bytes: u64,
    /// Time + throughput guards for the buffering phase; only read when `buffer_requests`.
    buffer_guards: BufferGuards,
    /// The node-wide buffering-concurrency semaphore. Every handle built by [`cached_client`] clones
    /// the ONE process-wide [`BUFFER_SLOTS`] (so the cap is shared across all listeners/upstreams);
    /// the buffering path acquires an owned permit from it before spilling. Carried as a field (not
    /// read from the global directly in `send`) only so a test can inject a small semaphore.
    buffer_slots: Arc<tokio::sync::Semaphore>,
}

impl UpstreamClient {
    /// Turn request buffering on (or off) for this handle, with optional per-upstream overrides for
    /// the byte cap, the read-idle timeout, the throughput floor + its window, and the absolute
    /// whole-phase ceiling. Each `None` keeps the server default. A `0` throughput floor explicitly
    /// DISABLES the floor; a `0` absolute ceiling explicitly DISABLES the ceiling (the server default
    /// ceiling is now ON at 1 h, so `0` is the opt-out — see [`DEFAULT_BUFFER_TOTAL_TIMEOUT`]). A
    /// no-op when `enabled` is false — the handle keeps today's streaming semantics, and the guards
    /// are only consulted on the buffering path.
    fn with_buffering(
        mut self,
        enabled: bool,
        max_bytes: Option<u64>,
        read_timeout_ms: Option<u64>,
        min_rate_bytes_per_sec: Option<u64>,
        min_rate_window_ms: Option<u64>,
        total_timeout_ms: Option<u64>,
    ) -> Self {
        self.buffer_requests = enabled;
        if let Some(n) = max_bytes {
            self.max_buffer_bytes = n;
        }
        if let Some(ms) = read_timeout_ms {
            self.buffer_guards.read_idle = Duration::from_millis(ms);
        }
        if let Some(bps) = min_rate_bytes_per_sec {
            self.buffer_guards.min_rate_bytes_per_sec = bps;
        }
        if let Some(ms) = min_rate_window_ms {
            self.buffer_guards.rate_window = Duration::from_millis(ms);
        }
        // `None` keeps the server default (now `Some(1 h)`, ON); `Some(0)` explicitly DISABLES the
        // ceiling (the opt-out for a rare genuinely-huge/slow-link upstream); `Some(ms>0)` sets a
        // hard ceiling of that many ms.
        match total_timeout_ms {
            None => {}
            Some(0) => self.buffer_guards.abs_ceiling = None,
            Some(ms) => self.buffer_guards.abs_ceiling = Some(Duration::from_millis(ms)),
        }
        self
    }

    /// TEST-ONLY: inject a specific buffering-concurrency semaphore in place of the shared
    /// process-wide [`BUFFER_SLOTS`], so a test can drive saturation + the permit-release-on-abort
    /// paths against a small, isolated semaphore without perturbing the global one.
    #[cfg(test)]
    fn with_buffer_slots(mut self, slots: Arc<tokio::sync::Semaphore>) -> Self {
        self.buffer_slots = slots;
        self
    }

    /// Send `req` upstream and return the response with its body streamed straight back to
    /// the client — no hyper connection task, and no copy of the body between the upstream
    /// read buffer and the downstream writer. Enforces the per-upstream total-request
    /// timeout (to the response head) if set.
    async fn send(&self, req: Request<Body>) -> Result<Response<ClientBody>, UpstreamError> {
        let (mut parts, body) = req.into_parts();

        // Origin-form request target (path + query); `Host` from the pinned URI authority.
        let target = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        // We own framing: capture the declared length, then strip the framing headers and
        // set our own (so a forwarded `Content-Length`/`Transfer-Encoding` can't desync us).
        let declared_len = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::TRANSFER_ENCODING);
        // Drop `Expect` before forwarding. The gateway terminates the client's
        // `Expect: 100-continue` handshake on the inbound leg itself (the serve loop already
        // wrote the downstream `100 Continue` before invoking the handler), so re-forwarding
        // `Expect` double-negotiates — and makes a spec-compliant upstream (Go/nginx/Gitea)
        // emit its OWN interim `100 Continue`, which this single-shot client would otherwise
        // read as the final response head (a cross-request response desync). We own the
        // upstream-leg framing end to end, so the upstream must never be asked to interim-ack.
        // This is the single chokepoint for both the gateway (`proxy_upstream`) and the
        // absolute-URL (`proxy`) forward paths. (`read_response_head` also skips any interim
        // 1xx as defense-in-depth, e.g. an unsolicited `103 Early Hints`.)
        parts.headers.remove(header::EXPECT);
        if !parts.headers.contains_key(header::HOST)
            && let Some(auth) = parts.uri.authority()
            && let Ok(v) = HeaderValue::from_str(auth.as_str())
        {
            parts.headers.insert(header::HOST, v);
        }

        // Decide request-body framing. A declared length forwards the stream fixed; no
        // length peeks the body — empty ⇒ no body (a GET), non-empty ⇒ chunked.
        let mut data: BodyData = Box::pin(body.into_data_stream());
        // Node-wide buffering-concurrency permit (HIGH-2). Acquired below ONLY on the
        // `buffer_requests` spill path, BEFORE any pool checkout / dial, and held in this `send`
        // scope through the whole buffering + replay-forward phase. It is released by RAII drop on
        // EVERY exit — the `?`/`return` abort paths below, a dial failure, a client disconnect, or a
        // panic/cancel that unwinds this frame — so a temp-spill slot is never leaked. `None` on the
        // non-buffering path (no permit taken).
        let mut _buffer_permit: Option<tokio::sync::OwnedSemaphorePermit> = None;
        let plan = match declared_len {
            // A client-declared *zero*-length body. Re-emit the explicit `Content-Length: 0`
            // that was stripped above: a well-behaved upstream treats a missing length on a
            // bodied method as zero, but some REQUIRE the header's presence even when it is
            // zero and reject the request outright ("missing content-length header") if a proxy
            // drops it — notably a container registry's blob-upload finalize `PUT
            // …/blobs/…?digest=sha256:…` (empty body, `Content-Length: 0`), the Gitea-fronted
            // `docker push` this path was 400-looping. We still send NO body and NO
            // Transfer-Encoding, so the framing stays unambiguous: exactly one canonical
            // `Content-Length: 0`, never a `Content-Length`×`Transfer-Encoding` pair. Kept as
            // `BodyPlan::None` (not `Fixed`) so an idempotent empty request stays retryable on a
            // stale pooled connection.
            Some(0) => {
                parts
                    .headers
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(0u64));
                BodyPlan::None
            }
            Some(n) => {
                parts
                    .headers
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(n));
                BodyPlan::Fixed
            }
            None => match data.next().await {
                None => BodyPlan::None,
                Some(Ok(first)) if self.buffer_requests => {
                    // `buffer_requests` upstream (e.g. a container registry that rejects chunked
                    // uploads): read the whole length-unknown body to a bounded temp file, so we
                    // can forward it with a `Content-Length` instead of `Transfer-Encoding:
                    // chunked`. Bounded + spilled to disk (see `buffer_body_to_length_in`), so an
                    // untrusted upload can neither exhaust memory nor the disk — over the cap it is
                    // rejected `413`.
                    //
                    // FIRST claim a node-wide buffering slot (HIGH-2), BEFORE spilling and before any
                    // pool checkout / dial. When the node is already buffering its cap worth of
                    // uploads, fail fast with `503` (BufferingOverloaded) rather than pile on another
                    // `max_buffer_bytes` of temp spill. The owned permit is held in `_buffer_permit`
                    // for the rest of `send` (buffering + the replay forward), so the slot — and the
                    // spill it represents — is released by drop on every exit path.
                    _buffer_permit = Some(
                        self.buffer_slots
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| UpstreamError::BufferingOverloaded)?,
                    );
                    let (len, replay) = match buffer_body_to_length_in(
                        first,
                        &mut data,
                        self.max_buffer_bytes,
                        self.buffer_guards,
                        &std::env::temp_dir(),
                    )
                    .await
                    {
                        Ok(buffered) => buffered,
                        Err(BufferError::TooLarge) => return Err(UpstreamError::PayloadTooLarge),
                        // A slow-trickle / stalled client (read idled, throughput fell below the
                        // floor, or the optional absolute ceiling elapsed): buffering is aborted,
                        // `data` + the (unlinked) temp file drop here, the connection slot is
                        // released, and the client gets `408` (not a `504`, so a healthy upstream is
                        // never ejected for a client-side stall).
                        Err(BufferError::Timeout) => return Err(UpstreamError::RequestBodyTimeout),
                        Err(BufferError::Io) => return Err(UpstreamError::Failed),
                    };
                    // The `&mut data` borrow above has ended; swap in the temp-file replay stream
                    // and forward it fixed-length.
                    data = replay;
                    parts
                        .headers
                        .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
                    BodyPlan::Fixed
                }
                Some(Ok(first)) => {
                    parts.headers.insert(
                        header::TRANSFER_ENCODING,
                        HeaderValue::from_static("chunked"),
                    );
                    BodyPlan::Chunked(first)
                }
                Some(Err(_)) => return Err(UpstreamError::Failed),
            },
        };

        let head_bytes = encode_request_head(&parts.method, &target, &parts.headers);
        let method = parts.method.clone();

        // A bodyless idempotent request is safe to replay on a fresh connection if a pooled
        // one turns out to have been closed by the upstream (the request never reached it,
        // or the method is idempotent). A bodied request is not — its stream is consumed.
        let retryable = matches!(plan, BodyPlan::None) && is_idempotent(&method);
        if let Some(conn) = pool_checkout(&self.key) {
            match self.attempt(conn, &head_bytes, plan, data, &method).await {
                Ok(resp) => return Ok(resp),
                Err(UpstreamError::Timeout) => return Err(UpstreamError::Timeout),
                Err(UpstreamError::Failed) if retryable => {
                    // Fall through to a fresh dial — the pooled connection was stale.
                    let conn = self.dial().await.map_err(|()| UpstreamError::Failed)?;
                    return self
                        .attempt(
                            conn,
                            &head_bytes,
                            BodyPlan::None,
                            empty_body_data(),
                            &method,
                        )
                        .await;
                }
                Err(e) => return Err(e),
            }
        }
        let conn = self.dial().await.map_err(|()| UpstreamError::Failed)?;
        self.attempt(conn, &head_bytes, plan, data, &method).await
    }

    /// One attempt over `conn`: write the request head + body, read the response head, and
    /// wrap the response in a [`ClientBody`] that streams the body and returns the drained
    /// connection to the pool. Bounded by the per-upstream request timeout (to the head).
    async fn attempt(
        &self,
        mut conn: Conn<Upstream>,
        head_bytes: &[u8],
        plan: BodyPlan,
        mut data: BodyData,
        method: &Method,
    ) -> Result<Response<ClientBody>, UpstreamError> {
        let exchange = async {
            conn.write_all(head_bytes).await?;
            match plan {
                BodyPlan::None => {}
                BodyPlan::Fixed => {
                    while let Some(item) = data.next().await {
                        let chunk =
                            item.map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
                        conn.write_all(&chunk).await?;
                    }
                }
                BodyPlan::Chunked(first) => {
                    if !first.is_empty() {
                        conn.write_all(&chunked::encode(&first)).await?;
                    }
                    while let Some(item) = data.next().await {
                        let chunk =
                            item.map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
                        if !chunk.is_empty() {
                            conn.write_all(&chunked::encode(&chunk)).await?;
                        }
                    }
                    conn.write_all(&chunked::encode_last(&HeaderMap::new()))
                        .await?;
                }
            }
            conn.flush().await?;
            conn.read_response_head().await
        };

        let request_timeout = self.key.request_timeout_ms.map(Duration::from_millis);
        let head = match request_timeout {
            Some(dur) => match tokio::time::timeout(dur, exchange).await {
                Ok(result) => result,
                Err(_) => return Err(UpstreamError::Timeout),
            },
            None => exchange.await,
        }
        .map_err(|err| {
            tracing::warn!(error = %err, "upstream request failed");
            UpstreamError::Failed
        })?;

        let reader = BodyReader::r#for(method, &head);
        let keep_alive = reader.keep_alive_possible() && response_keep_alive(&head);
        let status = head.status;
        let headers = head.headers;
        let body = ClientBody {
            conn: Some(conn),
            reader,
            key: self.key.clone(),
            keep_alive,
        };
        let mut resp = http::Response::new(body);
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        Ok(resp)
    }

    /// Dial a fresh connection to the pinned address: connect TCP (the SSRF pin is now
    /// "connect to exactly `addr`", enforced by construction — no resolver to steer),
    /// disable Nagle, and TLS-handshake with SNI = the pinned host when the leg is `https`.
    async fn dial(&self) -> Result<Conn<Upstream>, ()> {
        let connect = TcpStream::connect(self.key.addr);
        let tcp = match self.key.connect_timeout_ms {
            Some(ms) => tokio::time::timeout(Duration::from_millis(ms), connect)
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?,
            None => connect.await.map_err(|_| ())?,
        };
        // Disable Nagle on the upstream leg (the inbound path already does): a proxied
        // request would otherwise pay the ~40 ms delayed-ACK stall.
        let _ = tcp.set_nodelay(true);
        let read_chunk = self
            .key
            .read_buffer_bytes
            .unwrap_or(DEFAULT_UPSTREAM_READ_BUFFER);
        let transport = if self.key.https {
            let cfg = tls_client_config(self.key.tls_insecure)?;
            let connector = tokio_rustls::TlsConnector::from(cfg);
            let server_name =
                rustls::pki_types::ServerName::try_from(self.key.host.clone()).map_err(|_| ())?;
            let tls = connector.connect(server_name, tcp).await.map_err(|_| ())?;
            Upstream::Tls(Box::new(tls))
        } else {
            Upstream::Plain(tcp)
        };
        Ok(Conn::with_read_chunk(transport, read_chunk))
    }
}

/// Whether a request method is safe to replay on a fresh connection after a stale pooled
/// connection failed before the response — the idempotent methods (RFC 9110 §9.2.2).
fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

/// Whether the upstream connection may be kept alive after this response: HTTP/1.1 defaults
/// to keep-alive unless `Connection: close`; HTTP/1.0 defaults to close unless
/// `Connection: keep-alive`.
fn response_keep_alive(head: &boatramp_http::h1::ResponseHead) -> bool {
    let conn = head
        .headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if conn.split(',').any(|t| t.trim() == "close") {
        return false;
    }
    if head.version == http::Version::HTTP_10 {
        return conn.split(',').any(|t| t.trim() == "keep-alive");
    }
    true
}

/// An empty request-body data stream — for the bodyless retry path, which never reads it.
fn empty_body_data() -> BodyData {
    Box::pin(futures::stream::empty())
}

/// Why bounded request-body buffering stopped short.
#[derive(Debug)]
enum BufferError {
    /// The body exceeded the upstream's `max_buffer_bytes` → `413 Payload Too Large`.
    TooLarge,
    /// The inbound body read stalled or trickled below the throughput floor: a single read idled
    /// past `read_idle`, the sustained rate fell below `min_rate_bytes_per_sec` over its window, or
    /// (if set) the optional absolute ceiling elapsed (a slow-trickle / slow-loris client) → `408
    /// Request Timeout`.
    Timeout,
    /// A temp-file I/O error (create/write/seek) or an inbound body-read error → `502 Bad Gateway`.
    Io,
}

/// Buffer a length-unknown request body — the already-peeked `first` chunk plus the rest of
/// `data` — to a **bounded, per-request temp file** in `dir`, returning `(content_length, replay)`
/// where `replay` streams the buffered bytes back so the body can be forwarded fixed-length.
///
/// This is the resource-sensitive seam (an untrusted upload body), designed so it cannot become a
/// memory, disk, or cross-tenant vector:
///
/// - **Bounded.** The running total is checked BEFORE every write; a body that would cross `max`
///   is rejected ([`BufferError::TooLarge`] → `413`) WITHOUT spilling past the bound. A single
///   request therefore spends at most `max` bytes of temp space, and total exposure across the
///   node is `max` × concurrent buffered uploads (itself bounded by the server's connection
///   limits). RSS stays flat regardless of body size — the body lives on disk, not in a `Vec`;
///   only one read/write chunk (≤ 64 KiB) is resident at a time.
/// - **Safe temp file.** [`tempfile::tempfile_in`] creates the spill file and immediately unlinks
///   it (or uses `O_TMPFILE`), so it has NO reachable directory entry: no guessable or shared
///   name, no symlink/TOCTOU target, and nothing another tenant or process can open by path. Each
///   call gets its own fresh file. Under the packaged systemd unit the spill dir is the service's
///   `PrivateTmp` (private to the boatramp process), so even the directory is not shared off-box.
/// - **Cleaned up on EVERY path.** Because the inode is unlinked at creation, its storage is
///   reclaimed the moment the owning handle closes — on success (the `replay` stream owns the
///   handle and drops after the forward), on the `413` / `408` / I/O-error returns here (the local
///   `file` drops), and on a panic or task-cancel (drop still runs). There is no unlink step to
///   forget on an error path, so no leak is possible.
/// - **Time + throughput bounded.** The inbound body read is NOT bounded by `request_timeout_ms`
///   (which wraps only the upstream write + response head, AFTER buffering) nor by the connection
///   idle timeout (which never fires on an actively-trickling stream). So this bounds the read
///   itself, with three independent guards ([`BufferGuards`]), each ending buffering at
///   [`BufferError::Timeout`] → `408`:
///   1. **Read-idle** — each `data.next()` may stall at most `read_idle`. Catches a FULLY-stalled
///      client (a read that never yields).
///   2. **Minimum throughput** — the body's average inbound rate over a trailing `rate_window` must
///      stay at or above `min_rate_bytes_per_sec`. Catches the slow-loris the read-idle guard alone
///      cannot: a drip-feed that trickles just often enough to keep resetting the idle timer never
///      idles, but it also cannot sustain the floor. Crucially, this is a RATE bound, not a flat
///      wall-clock cap, so a steadily-progressing upload of ANY total size finishes as long as it
///      clears the floor — a 1 GiB layer at a slow-but-real 5 MB/s is fine, where a flat 120 s cap
///      would falsely `408` it. `min_rate_bytes_per_sec == 0` disables this guard (read-idle only).
///   3. **Optional absolute ceiling** — if `abs_ceiling` is `Some`, a hard upper bound on total
///      buffering time regardless of throughput, as blunt defense-in-depth. `None` (the default) =
///      no ceiling, so it never false-positives a legitimate upload.
///
///   All three are enforced on the SAME reads, so they cover both the HTTP/2 END_STREAM-delimited
///   and the inbound-`chunked` body (both reach here through the one buffering loop).
///
/// NOTE: the spill store is `std::env::temp_dir()` in production. If an operator points that at a
/// RAM-backed `tmpfs`, buffering consumes RAM rather than disk — still hard-bounded by `max`, so
/// it cannot OOM unbounded, but size `max_buffer_bytes` accordingly.
async fn buffer_body_to_length_in(
    first: Bytes,
    data: &mut BodyData,
    max: u64,
    guards: BufferGuards,
    dir: &std::path::Path,
) -> Result<(u64, BodyData), BufferError> {
    use futures::StreamExt;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    // An unnamed temp file in `dir` — unlinked at creation, so there is no path to leak or race.
    let std_file = tempfile::tempfile_in(dir).map_err(|_| BufferError::Io)?;
    let mut file = tokio::fs::File::from_std(std_file);
    let mut total: u64 = 0u64;
    // The OPTIONAL absolute whole-phase ceiling, measured from buffering start (defense-in-depth;
    // `None` by default). The throughput floor — not this — is the primary slow-client backstop.
    let start = tokio::time::Instant::now();
    let abs_deadline = guards.abs_ceiling.map(|c| start + c);
    // Trailing-window anchor for the throughput floor: the time + byte count at the start of the
    // current window. Each time a full `rate_window` elapses we require that at least
    // `min_rate_bytes_per_sec × elapsed` bytes arrived in it, then slide the anchor forward.
    let rate_floor_on = guards.min_rate_bytes_per_sec > 0;
    let mut window_anchor_time = start;
    let mut window_anchor_bytes: u64 = 0;

    // Spill `first`, then each subsequent chunk, enforcing the cap BEFORE each write so the temp
    // file never grows past `max` even by one chunk, and bounding every inbound read in time.
    let mut chunk = first;
    loop {
        let would_be = total
            .checked_add(chunk.len() as u64)
            .filter(|n| *n <= max)
            .ok_or(BufferError::TooLarge)?;
        file.write_all(&chunk).await.map_err(|_| BufferError::Io)?;
        total = would_be;
        // Throughput floor (tumbling window): once a full window has elapsed since the anchor, the
        // body must have delivered at least `floor × elapsed` bytes within it — otherwise its
        // sustained rate is below the floor (a drip-feed that never idles) and buffering aborts.
        // Checked here, after a chunk lands, so a client that stops delivering is caught by the
        // read-idle guard below instead. The anchor then slides forward to start the next window.
        if rate_floor_on {
            let now = tokio::time::Instant::now();
            let elapsed = now.duration_since(window_anchor_time);
            if elapsed >= guards.rate_window {
                let got = u128::from(total - window_anchor_bytes);
                let required =
                    u128::from(guards.min_rate_bytes_per_sec) * elapsed.as_millis() / 1000;
                if got < required {
                    return Err(BufferError::Timeout);
                }
                window_anchor_time = now;
                window_anchor_bytes = total;
            }
        }
        // Bound the next read by the sooner of the per-read idle timeout and (if set) the absolute
        // ceiling. On elapse, the pending `data.next()` future is dropped and we return — `file`
        // (the unlinked temp inode) drops with the stack, so the spill is reclaimed and the slot
        // released.
        let idle_deadline = tokio::time::Instant::now() + guards.read_idle;
        let read_deadline = match abs_deadline {
            Some(abs) => idle_deadline.min(abs),
            None => idle_deadline,
        };
        match tokio::time::timeout_at(read_deadline, data.next()).await {
            Ok(Some(Ok(next))) => chunk = next,
            Ok(Some(Err(_))) => return Err(BufferError::Io),
            Ok(None) => break,
            Err(_elapsed) => return Err(BufferError::Timeout),
        }
    }
    file.flush().await.map_err(|_| BufferError::Io)?;
    // Rewind to replay the buffered body from the start.
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|_| BufferError::Io)?;

    // Stream the temp file back as the request body; the stream owns `file`, so the (unlinked)
    // temp file is reclaimed when the forward finishes and the stream drops.
    let replay = tokio_util::io::ReaderStream::with_capacity(file, 64 * 1024)
        .map(|r| r.map_err(axum::Error::new));
    Ok((total, Box::pin(replay)))
}

/// The reverse-proxy response body: streams the upstream response body straight to the
/// downstream client off the pooled connection, then — on a clean, fully-drained,
/// keep-alive response — returns that connection to [`POOL`] for reuse. A mid-body error
/// drops the connection (never pools it) and surfaces as a stream error, so the downstream
/// sees a truncated (aborted) body, never a clean end.
struct ClientBody {
    /// The driving connection, taken once the body ends (drained → pool, error → dropped).
    conn: Option<Conn<Upstream>>,
    reader: BodyReader,
    key: UpstreamClientKey,
    keep_alive: bool,
}

impl Stream for ClientBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(None);
        };
        match conn.poll_read_body_chunk(cx, &mut this.reader) {
            Poll::Ready(Ok(Some(chunk))) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(Ok(None)) => {
                // Body fully drained — return the connection to the pool if reusable.
                if let Some(conn) = this.conn.take()
                    && this.keep_alive
                {
                    pool_return(&this.key, conn);
                }
                Poll::Ready(None)
            }
            Poll::Ready(Err(e)) => {
                this.conn = None; // broken mid-body — drop, never pool
                Poll::Ready(Some(Err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A rustls client config for the upstream leg: webpki roots by default, or an
/// accept-anything verifier when the upstream is declared `tls_insecure`. ALPN is
/// pinned to HTTP/1.1 (the only protocol the native upstream client speaks).
fn upstream_tls_config(tls_insecure: bool) -> Result<rustls::ClientConfig, ()> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ())?;
    let mut config = if tls_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    // We dial rustls directly now (no hyper-rustls), so we own ALPN: offer HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The `tls_insecure` verifier — accepts any certificate and signature. Wired in
/// only when an operator explicitly declares an upstream `tls_insecure` (mirrors
/// reqwest's `danger_accept_invalid_certs`); never on the default path.
#[derive(Debug)]
struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A pinned upstream client handle for one upstream identity. The handle is just the pool
/// key (cheap to build + clone); the actual keep-alive connections live in [`POOL`] and are
/// shared across all handles with the same key. `host` was resolved to the pre-verified
/// `addr` (closing the SSRF DNS-rebinding window — the connection dials `addr` directly,
/// never re-resolving). Returns `Result` for call-site compatibility; it cannot fail.
fn cached_client(
    host: &str,
    addr: SocketAddr,
    connect_timeout_ms: Option<u64>,
    request_timeout_ms: Option<u64>,
    tls_insecure: bool,
    read_buffer_bytes: Option<usize>,
    https: bool,
) -> Result<UpstreamClient, ()> {
    Ok(UpstreamClient {
        key: UpstreamClientKey {
            host: host.to_string(),
            addr,
            https,
            connect_timeout_ms,
            request_timeout_ms,
            tls_insecure,
            read_buffer_bytes,
        },
        // Buffering is OFF unless the caller opts in via `with_buffering` (so the default path —
        // and the absolute-URL `proxy` path, which has no per-upstream config — is unchanged).
        buffer_requests: false,
        max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
        buffer_guards: BufferGuards {
            read_idle: DEFAULT_BUFFER_READ_TIMEOUT,
            min_rate_bytes_per_sec: DEFAULT_BUFFER_MIN_RATE_BYTES_PER_SEC,
            rate_window: DEFAULT_BUFFER_MIN_RATE_WINDOW,
            abs_ceiling: DEFAULT_BUFFER_TOTAL_TIMEOUT,
        },
        // Share the ONE process-wide buffering-concurrency semaphore across every handle.
        buffer_slots: BUFFER_SLOTS.clone(),
    })
}

/// A pinned client with no per-upstream overrides (the absolute-URL proxy path).
/// `https` selects the TLS vs plaintext transport — see [`cached_client`].
fn pinned_client(host: &str, addr: SocketAddr, https: bool) -> Result<UpstreamClient, ()> {
    cached_client(host, addr, None, None, false, None, https)
}

/// The request-independent resolution of a gateway upstream `target`: its parsed
/// URL prefix + base path, the pinned address, and the host. Memoized so the hot
/// path skips the per-request `Url::parse` + DNS `lookup_host` (profiled as a few
/// percent of proxy CPU on top of the address-pin re-check that stays per request).
#[derive(Clone)]
pub(crate) struct ResolvedTarget {
    /// The parsed target URL. Cloned + re-pathed per request (cheap) instead of
    /// re-parsed (the expensive `url::parser` pass the cache removes).
    pub(crate) parsed: reqwest::Url,
    /// The upstream host (for TLS SNI / the pinned client key / logs).
    pub(crate) host: String,
    /// The pre-verified pinned address. Re-checked against the (per-request)
    /// security posture on every use, so caching never relaxes the SSRF address gate.
    pub(crate) addr: SocketAddr,
    /// When this resolution was computed — re-resolved after [`RESOLVE_TTL`] so a
    /// DNS change (or a rebind attempt) is picked up on new connections.
    resolved_at: std::time::Instant,
}

/// How long a [`ResolvedTarget`] (its DNS resolution) is reused before a fresh
/// `lookup_host`. Bounds the DNS-change / rebind-detection window; connections are
/// pinned to the resolved address for their lifetime regardless.
const RESOLVE_TTL: Duration = Duration::from_secs(15);

/// Cache of resolved gateway targets, keyed by the upstream target string.
static RESOLVED_TARGETS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, ResolvedTarget>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Resolve a gateway `target` to a [`ResolvedTarget`], from the cache when a fresh
/// entry exists, else by parsing + resolving + SSRF-validating every resolved
/// address (so a hostname can't DNS-rebind to an internal target). `Err` is a
/// ready-to-return error response.
pub(crate) async fn resolve_target(
    target: &str,
    policy: GatewayTargetPolicy,
    posture: &boatramp_core::security::SecurityPosture,
) -> Result<ResolvedTarget, Response> {
    if let Some(hit) = RESOLVED_TARGETS.lock().unwrap().get(target)
        && hit.resolved_at.elapsed() < RESOLVE_TTL
    {
        return Ok(hit.clone());
    }
    let parsed = reqwest::Url::parse(target).map_err(|_| {
        tracing::warn!(target = %target, "gateway upstream target unparsable");
        (StatusCode::BAD_GATEWAY, "bad gateway upstream\n").into_response()
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err((
                StatusCode::BAD_GATEWAY,
                "gateway upstream scheme not http(s)\n",
            )
                .into_response());
        }
    }
    let Some(host) = parsed.host_str().map(str::to_string) else {
        return Err((StatusCode::BAD_GATEWAY, "gateway upstream missing host\n").into_response());
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let mut chosen = None;
    for addr in tokio::net::lookup_host((host.as_str(), port))
        .await
        .into_iter()
        .flatten()
    {
        // Refuse cloud-metadata always, and apply the tier's address rule — checked post-resolution
        // so a hostname can't DNS-rebind to an internal target (a project `discover`/DNS target that
        // resolves private is refused here by `ProjectRaw`, no special-casing).
        if !gateway_addr_allowed_for(addr.ip(), policy, posture) {
            tracing::warn!(
                %host, ip = %addr.ip(),
                "gateway upstream refused: address not permitted by security posture"
            );
            return Err((StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response());
        }
        chosen.get_or_insert(addr);
    }
    let Some(addr) = chosen else {
        return Err((
            StatusCode::BAD_GATEWAY,
            "gateway upstream did not resolve\n",
        )
            .into_response());
    };
    let resolved = ResolvedTarget {
        parsed,
        host,
        addr,
        resolved_at: std::time::Instant::now(),
    };
    {
        let mut cache = RESOLVED_TARGETS.lock().unwrap();
        // Keyed by operator-configured target strings (a bounded set), but cap + clear
        // anyway so a long-lived process that churns upstream URLs can't grow it without
        // bound.
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(target.to_string(), resolved.clone());
    }
    Ok(resolved)
}

/// The cloud-metadata service address — refused even for a declared gateway
/// upstream (defense in depth).
pub(super) const CLOUD_METADATA_IPV4: std::net::Ipv4Addr =
    std::net::Ipv4Addr::new(169, 254, 169, 254);

/// The resolved operator security posture carried in the request extensions
/// (inserted by [`router_with`]); falls back to the strict `multi-tenant`
/// default if absent (e.g. a router built without the layer in a test).
fn request_posture(request: &Request) -> boatramp_core::security::SecurityPosture {
    request
        .extensions()
        .get::<boatramp_core::security::SecurityPosture>()
        .copied()
        .unwrap_or_default()
}

/// Whether a resolved gateway-upstream address is permitted under `posture`.
/// The cloud-metadata endpoint is **always** refused (defense in
/// depth). Any other non-global address — loopback / private / link-local /
/// unique-local / CGNAT — is refused for a **site-declared** upstream unless the
/// operator opted in via `allow_site_private_upstreams`. Site config is
/// `site-write`, so without this gate a site writer could point the edge at
/// internal services; the operator posture is the authority.
pub(super) fn gateway_addr_allowed(
    ip: IpAddr,
    posture: &boatramp_core::security::SecurityPosture,
) -> bool {
    gateway_addr_allowed_for(ip, GatewayTargetPolicy::Operator, posture)
}

/// Which tier's authority governs a gateway upstream — and therefore which address rule binds it
/// (symmetric two-tier gateway, cap-req gateway). Derived once per request from the resolved route
/// match ([`boatramp_core::gateway::resolve_gateway`]) in `serve_resolved`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum GatewayTargetPolicy {
    /// A site/operator-declared upstream (or a project route referencing a `shared` site upstream):
    /// the operator authorized the reach, so the node posture is the authority (today's behavior).
    Operator,
    /// A project-declared upstream with a RAW target (static/pool/DNS): the project tier may only
    /// reach **public** hosts — this is POSTURE-INDEPENDENT (`allow_site_private_upstreams` is never
    /// consulted), so a project can never self-grant private reach (RESTRICTION 1, the bright line).
    ProjectRaw,
    /// A project-declared upstream bound to the project's **own compute workload**: the resolved
    /// replica address is private by design and admitted here, safe because the `(project, workload)`
    /// resolver is project-scoped (a project can only name its own workloads).
    ProjectOwnWorkload,
}

/// Whether a resolved gateway-upstream address is permitted under `policy` + `posture`. The
/// cloud-metadata endpoint is **always** refused (defense in depth). See [`GatewayTargetPolicy`] for
/// the per-tier rule. `gateway_addr_allowed` is the `Operator` arm (site-tier, posture-gated).
pub(crate) fn gateway_addr_allowed_for(
    ip: IpAddr,
    policy: GatewayTargetPolicy,
    posture: &boatramp_core::security::SecurityPosture,
) -> bool {
    if ip == IpAddr::V4(CLOUD_METADATA_IPV4) {
        return false;
    }
    match policy {
        // Public-only, POSTURE-INDEPENDENT — the project tier never authorizes private reach.
        GatewayTargetPolicy::ProjectRaw => boatramp_core::access::is_global_ip(ip),
        // A project-scoped own-workload replica (private by design); safe via project-scoped resolution.
        GatewayTargetPolicy::ProjectOwnWorkload => true,
        // Site-declared reach: the operator posture is the authority (unchanged behavior).
        GatewayTargetPolicy::Operator => {
            posture.allow_site_private_upstreams || boatramp_core::access::is_global_ip(ip)
        }
    }
}

/// Proxy to a **declared gateway upstream**: a private address is
/// permitted *because the operator declared this upstream*, but the target is
/// still resolved once and pinned (no TOCTOU), the scheme is http(s)-only, and
/// the cloud-metadata address is always refused. Applies the upstream's
/// strip-prefix, host-header override, header rewrites, and timeouts.
/// Forward a request through a declared gateway upstream, picking a backend from
/// its pool (round-robin/random over the healthy set) and retrying the next
/// candidate on a backend failure — but only for body-less idempotent requests,
/// since a sent body can't be replayed. Each attempt's
/// outcome feeds passive health so future requests route around a dead backend.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_gateway(
    request: Request,
    site: &str,
    // The serving project, for the tier-aware runtime-state key (a project upstream and a site
    // upstream can share a name). `None` ⇒ the default project / an operator upstream.
    project: Option<&str>,
    upstream_name: &str,
    upstream: &boatramp_core::gateway::Upstream,
    // The tier's address policy (operator posture-gated / project public-only / project own-compute).
    policy: GatewayTargetPolicy,
    request_path: &str,
    client_ip: IpAddr,
    // When the upstream is compute-backed (`upstream.compute`), the caller passes
    // the workload's live healthy replica endpoints here; otherwise `None` and
    // the static/DNS pool is used.
    compute_backends: Option<Vec<String>>,
    // FA-8: per-replica region tags (endpoint URL → region) for a compute-backed
    // `LbPolicy::Nearest` pool, derived from node placement; merged over the
    // upstream's static `regions` so nearest-replica routing works without a manual
    // `--region` map. `None`/empty for non-nearest or non-compute pools.
    compute_regions: Option<std::collections::BTreeMap<String, String>>,
) -> Response {
    // Read the security posture once from the original request — the retry path
    // below rebuilds the request (dropping extensions), so we thread the resolved
    // (Copy) posture into the proxy fns rather than re-reading it per attempt.
    let posture = request_posture(&request);
    // Runtime-state key: an operator upstream keys on (site, name) as before; a project upstream
    // keys on (site, project, name) so its health/discovery pool can never collide with a site
    // upstream of the same name (the `\u{1}`-prefixed qualifier can't appear in a plain name).
    let project_state_name;
    let state = match policy {
        GatewayTargetPolicy::Operator => gateway::upstream_state(site, upstream_name),
        GatewayTargetPolicy::ProjectRaw | GatewayTargetPolicy::ProjectOwnWorkload => {
            project_state_name = format!("p\u{1}{}\u{1}{}", project.unwrap_or(""), upstream_name);
            gateway::upstream_state(site, &project_state_name)
        }
    };
    // Arm active probing (no-op unless the upstream has active_health) so the
    // background prober has a current config snapshot.
    state.arm_active_probe(upstream);
    let now = std::time::Instant::now();
    // Merge compute-derived replica regions into the upstream so the nearest LB
    // sees them (a per-request clone only when there are regions to add).
    let merged_upstream = compute_regions.filter(|r| !r.is_empty()).map(|regions| {
        let mut u = upstream.clone();
        u.regions.extend(regions);
        u
    });
    let upstream = merged_upstream.as_ref().unwrap_or(upstream);
    let backends =
        compute_backends.unwrap_or_else(|| state.backends(upstream, &gateway::SystemResolver, now));
    if backends.is_empty() {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream has no backends\n",
        )
            .into_response();
    }
    // FA-8: extract the client's region from the configured edge header (set by a
    // CDN/edge, e.g. `fly-region` / `cf-ipcountry`), driving `LbPolicy::Nearest`.
    // Unset header ⇒ no client region ⇒ Nearest degrades to health-first order.
    let client_region = upstream
        .client_region_header
        .as_deref()
        .and_then(|name| request.headers().get(name))
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let candidates = state.candidates(&backends, upstream, now, client_region.as_deref());

    // Retry across backends only when the request body is replayable (none) —
    // GET/HEAD with no declared/streamed body. Otherwise use a single backend.
    if !gateway_retryable(&request) || candidates.len() == 1 {
        let target = &candidates[0];
        let response = proxy_upstream(
            request,
            upstream,
            target,
            request_path,
            client_ip,
            policy,
            posture,
        )
        .await;
        // A node-wide buffering-overload `503` is a LOCAL pre-dial refusal (no backend was
        // contacted), so it must not count against this backend's passive health. Every other
        // outcome feeds passive health as before.
        if response
            .extensions()
            .get::<LocalPreDialOverload>()
            .is_none()
        {
            state.record(
                target,
                !response.status().is_server_error(),
                upstream.passive_health,
                now,
            );
        }
        return response;
    }

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let mut last: Option<Response> = None;
    for target in &candidates {
        let mut attempt = axum::http::Request::new(Body::empty());
        *attempt.method_mut() = method.clone();
        *attempt.uri_mut() = uri.clone();
        *attempt.headers_mut() = headers.clone();
        let response = proxy_upstream(
            attempt,
            upstream,
            target,
            request_path,
            client_ip,
            policy,
            posture,
        )
        .await;
        // A node-wide buffering-overload `503` is a LOCAL pre-dial refusal — don't fault the backend
        // and don't advance to the next candidate (the node, not this backend, is saturated). In
        // practice this never fires on the retry path (it is reached only for body-less idempotent
        // requests, which are never buffered), but guard it for correctness.
        if response
            .extensions()
            .get::<LocalPreDialOverload>()
            .is_some()
        {
            return response;
        }
        let ok = !response.status().is_server_error();
        state.record(target, ok, upstream.passive_health, now);
        if ok {
            return response;
        }
        last = Some(response);
    }
    last.unwrap_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "gateway: all upstream backends failed\n",
        )
            .into_response()
    })
}

/// The live healthy replica endpoints of a compute workload **in `project`**, as
/// upstream URLs. Empty (→ 502) when no healthy replica exists. Project-scoped so a
/// non-default tenant's compute upstream resolves against its own replica state (not
/// `default`), closing the project-blind resolution that 502'd / never woke it.
pub(super) async fn compute_endpoints(
    deploy: &DeployStore,
    project: &str,
    workload: &str,
) -> Vec<String> {
    deploy
        .list_replica_states(ProjectRef::new(project), workload)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|state| state.healthy)
        .map(|state| state.endpoint.url())
        .collect()
}

/// The region of each healthy replica endpoint of a compute workload (FA-8), as
/// `endpoint-url → region`, denormalized from the replica's node placement. Feeds
/// the nearest-replica LB; replicas whose node had no region are omitted
/// (region-neutral).
pub(super) async fn compute_endpoint_regions(
    deploy: &DeployStore,
    project: &str,
    workload: &str,
) -> std::collections::BTreeMap<String, String> {
    deploy
        .list_replica_states(ProjectRef::new(project), workload)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|state| state.healthy)
        .filter_map(|state| state.region.map(|region| (state.endpoint.url(), region)))
        .collect()
}

/// How long a wake-from-zero request waits for the parked replica to be restored
/// and serving before giving up. A safety ceiling for a *failed*
/// restore, not a normal-path bound — a real resume is well under this, so the
/// cold start stays invisible to the client.
pub(super) const COMPUTE_WAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `workload` has a replica parked in the [`Zero`] phase — i.e. there's
/// something to wake (vs. a genuinely down/undeployed workload, which should just
/// 502 rather than hold the request).
///
/// [`Zero`]: boatramp_core::compute::ReplicaPhase::Zero
pub(super) async fn has_parked_replica(
    deploy: &DeployStore,
    project: &str,
    workload: &str,
) -> bool {
    deploy
        .list_replica_states(ProjectRef::new(project), workload)
        .await
        .unwrap_or_default()
        .iter()
        .any(|state| state.phase == boatramp_core::compute::ReplicaPhase::Zero)
}

/// Hold a wake-from-zero request: poll the workload's healthy endpoints until one
/// appears (the reconcile loop restored the parked replica) or `timeout` elapses.
/// Returns the (possibly still-empty, on timeout) pool.
pub(super) async fn await_warm(
    deploy: &DeployStore,
    project: &str,
    workload: &str,
    timeout: std::time::Duration,
) -> Vec<String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let pool = compute_endpoints(deploy, project, workload).await;
        if !pool.is_empty() || std::time::Instant::now() >= deadline {
            return pool;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Production [`PullSpawner`](boatramp_core::compute::PullSpawner): runs each workload's
/// background image pull on the tokio runtime, keeping the pull off the serial reconcile pass.
struct TokioPullSpawner;

impl boatramp_core::compute::PullSpawner for TokioPullSpawner {
    fn spawn_pull(
        &self,
        fut: futures::future::BoxFuture<'static, ()>,
    ) -> Box<dyn boatramp_core::compute::PullTaskHandle> {
        Box::new(TokioPullTask(tokio::spawn(fut)))
    }
}

/// A handle to a tokio-spawned pull task; `abort` cancels it (idempotent, a no-op once done).
struct TokioPullTask(tokio::task::JoinHandle<()>);

impl boatramp_core::compute::PullTaskHandle for TokioPullTask {
    fn abort(&self) {
        self.0.abort();
    }
}

/// Spawn the leader-gated compute reconcile loop:
/// every `tick`, while `is_leader()`, run one [`reconcile_once`] pass over the
/// backend registry + node inventory to converge each workload's replicas. A
/// no-op while not leader or with an empty registry. Detached for the server's
/// lifetime; the same leader-gating pattern as cron/cert issuance.
#[allow(clippy::too_many_arguments)]
pub fn spawn_compute_reconcile(
    deploy: DeployStore,
    backends: boatramp_core::compute::BackendRegistry,
    nodes: Vec<boatramp_core::compute::Node>,
    policy: boatramp_core::compute::BackendPolicy,
    is_leader: CronLeaderGate,
    tick: std::time::Duration,
    idle_timeout: std::time::Duration,
    resolver: Option<std::sync::Arc<dyn boatramp_core::compute::ComputeBindingResolver>>,
    managed_db: Option<std::sync::Arc<dyn boatramp_core::compute::ManagedDbEnvResolver>>,
    registry_auth: Option<std::sync::Arc<dyn boatramp_core::registry_auth::RegistryAuthResolver>>,
    snapshot_store: Option<std::sync::Arc<dyn boatramp_core::compute::SnapshotStore>>,
    tuning: boatramp_core::compute::BinPackTuning,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // drive scale-to-zero from the gateway's per-workload activity —
        // a workload idle for `idle_timeout` is slept, a requested one is woken.
        let activity = gateway::GatewayActivitySource::new(idle_timeout);
        // Decouple each workload's OCI image pull (`materialize`) from the serial reconcile
        // critical path: this coordinator — OWNED for the loop's lifetime so pull state (in
        // flight / ready / failed) persists across ticks — runs each pull as a background task
        // and lets `reconcile_once` POLL it, so one tenant's big/slow pull can't stall the
        // reconcile of every other workload on the node.
        let pull =
            boatramp_core::compute::PullCoordinator::new(std::sync::Arc::new(TokioPullSpawner));
        let mut interval = tokio::time::interval(tick);
        loop {
            // Periodic convergence, or an immediate wake-from-zero nudge from the
            // serving path — whichever comes first.
            tokio::select! {
                _ = interval.tick() => {}
                _ = gateway::await_reconcile_wake() => {}
            }
            if !is_leader() {
                continue;
            }
            match boatramp_core::compute::reconcile_once(
                &deploy,
                &backends,
                &nodes,
                &policy,
                &activity,
                resolver.as_deref(),
                managed_db.as_deref(),
                registry_auth.as_deref(),
                snapshot_store.as_deref(),
                tuning,
                Some(&pull),
            )
            .await
            {
                Ok(report) if !report.errors.is_empty() => tracing::warn!(
                    launched = report.launched,
                    stopped = report.stopped,
                    errors = ?report.errors,
                    "compute reconcile: partial",
                ),
                Ok(report) if report.launched + report.stopped > 0 => tracing::info!(
                    launched = report.launched,
                    stopped = report.stopped,
                    "compute reconcile",
                ),
                Ok(_) => {}
                Err(err) => tracing::warn!(%err, "compute reconcile tick failed"),
            }
        }
    })
}

/// Whether a request can be safely retried against another backend: a body-less
/// idempotent method, so re-sending replays nothing. Conservative on purpose.
fn gateway_retryable(request: &Request) -> bool {
    matches!(*request.method(), Method::GET | Method::HEAD)
        && request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_none_or(|v| v.as_bytes() == b"0")
        && !request.headers().contains_key(header::TRANSFER_ENCODING)
}

async fn proxy_upstream(
    request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    target: &str,
    request_path: &str,
    client_ip: IpAddr,
    policy: GatewayTargetPolicy,
    posture: boatramp_core::security::SecurityPosture,
) -> Response {
    // WebSocket / generic HTTP upgrade: bridge the upgraded connection both ways.
    // reqwest can't upgrade, so this uses a hyper client conn.
    if is_upgrade_request(request.headers()) {
        return proxy_upgrade(
            request,
            upstream,
            target,
            request_path,
            client_ip,
            policy,
            posture,
        )
        .await;
    }
    // A `unix:/path` target forwards over a unix-domain socket.
    if let Some(socket_path) = target.strip_prefix("unix:") {
        // A unix-socket upstream can reach local admin sockets (Docker/containerd/SSH-agent). It is
        // NEVER a "public host", so the project tier may not use one — a project upstream to a unix
        // socket is refused regardless of posture (RESTRICTION 1). The site tier may, with operator
        // opt-in.
        if !matches!(policy, GatewayTargetPolicy::Operator) {
            tracing::warn!(
                %target,
                "gateway upstream refused: a project-tier upstream may not target a unix socket"
            );
            return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
        }
        // Site config is `site-write`; a unix-socket upstream can reach local
        // admin sockets (Docker/containerd/SSH-agent), so it requires operator
        // opt-in.
        if !posture.allow_site_unix_upstreams {
            tracing::warn!(
                %target,
                "gateway upstream refused: unix-socket upstreams disabled by security posture"
            );
            return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
        }
        #[cfg(unix)]
        {
            return proxy_upstream_unix(request, upstream, socket_path, request_path, client_ip)
                .await;
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            return (
                StatusCode::NOT_IMPLEMENTED,
                "unix-socket upstreams are only supported on unix\n",
            )
                .into_response();
        }
    }
    // Resolve + pin the declared target (parse + DNS), served from the cache when a
    // fresh entry exists — the parse and `lookup_host` are request-independent.
    let resolved = match resolve_target(target, policy, &posture).await {
        Ok(resolved) => resolved,
        Err(resp) => return resp,
    };
    // Re-apply the tier-aware SSRF address gate on every request against the pinned address —
    // caching the resolution never relaxes it (posture is per-request).
    if !gateway_addr_allowed_for(resolved.addr.ip(), policy, &posture) {
        tracing::warn!(
            host = %resolved.host, ip = %resolved.addr.ip(),
            "gateway upstream refused: address not permitted by security posture"
        );
        return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
    }
    let host = resolved.host.as_str();
    let addr = resolved.addr;

    // Build the upstream URL: target base path + forwarded (strip-prefixed) path
    // + the original query — cloning the cached parse rather than re-parsing.
    let mut target = resolved.parsed.clone();
    let base = target.path().trim_end_matches('/').to_string();
    let forwarded = upstream.forward_path(request_path);
    target.set_path(&format!("{base}{forwarded}"));
    let (mut parts, body) = request.into_parts();
    target.set_query(parts.uri.query());

    // A client pinned to the resolved address, with the upstream's TLS + timeouts —
    // reused across requests via the cache, NOT rebuilt per request.
    if upstream.tls_insecure {
        tracing::warn!(%host, "gateway upstream TLS verification disabled (tls_insecure)");
    }
    let https = resolved.parsed.scheme() == "https";
    let client = match cached_client(
        host,
        addr,
        upstream.connect_timeout_ms,
        upstream.request_timeout_ms,
        upstream.tls_insecure,
        upstream.read_buffer_bytes.map(|n| n as usize),
        https,
    ) {
        Ok(client) => client,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway client error\n").into_response(),
    };
    // Opt this upstream into request buffering when configured (registry-fronting parity): a
    // length-unknown body is spilled to a bounded temp file and forwarded with a Content-Length,
    // with the inbound read bounded by a read-idle timeout + a minimum-throughput floor (and an
    // optional absolute ceiling) so a stalled or drip-feed client cannot pin a connection slot + its
    // temp file, while a steadily-progressing upload of any size still completes.
    let client = client.with_buffering(
        upstream.buffer_requests,
        upstream.max_buffer_bytes,
        upstream.buffer_read_timeout_ms,
        upstream.buffer_min_rate_bytes_per_sec,
        upstream.buffer_min_rate_window_ms,
        upstream.buffer_total_timeout_ms,
    );

    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    let requested_host = parts.headers.get(header::HOST).cloned();

    let uri: axum::http::Uri = match target.as_str().parse() {
        Ok(uri) => uri,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway client error\n").into_response(),
    };
    let mut builder = Request::builder().method(parts.method.clone()).uri(uri);
    let out_headers = builder
        .headers_mut()
        .expect("fresh request builder has no error");
    for (name, value) in &parts.headers {
        // hyper sets Host from the URI (or our override below); drop the client Host
        // + hop-by-hop, and any header the upstream removes.
        if name == header::HOST
            || is_hop_by_hop(name)
            || upstream
                .header_up
                .remove
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        out_headers.append(name.clone(), value.clone());
    }
    if let Ok(v) = HeaderValue::from_str(&client_ip.to_string()) {
        out_headers.append(HeaderName::from_static("x-forwarded-for"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&scheme) {
        out_headers.append(HeaderName::from_static("x-forwarded-proto"), v);
    }
    if let Some(h) = &requested_host {
        out_headers.append(HeaderName::from_static("x-forwarded-host"), h.clone());
    }
    // Host header (see `Upstream::host_forward` for the single-source precedence):
    //  - Fixed:  the operator-configured `host_header` value.
    //  - PreserveClient: the client's own inbound Host, forwarded unchanged.
    //  - UpstreamAuthority (default): leave Host unset here, so `UpstreamClient::send` fills it from
    //    the pinned URI authority (the upstream's own host) — unchanged behavior.
    // This is a forward-leg-only decision; the site/route was already matched on the client's
    // verified domain, so no header here can change which upstream was selected.
    match upstream.host_forward() {
        boatramp_core::gateway::HostForward::Fixed(hh) => {
            if let Ok(v) = HeaderValue::from_str(hh) {
                out_headers.insert(header::HOST, v);
            }
        }
        boatramp_core::gateway::HostForward::PreserveClient => {
            if let Some(h) = &requested_host {
                out_headers.insert(header::HOST, h.clone());
            }
        }
        boatramp_core::gateway::HostForward::UpstreamAuthority => {}
    }
    // Request header set/overrides (skip any that are malformed rather than
    // failing the whole request).
    for (name, value) in &upstream.header_up.set {
        if let (Ok(n), Ok(v)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_str(value),
        ) {
            out_headers.append(n, v);
        }
    }
    parts.headers.clear(); // release; not used past here
    let req = match builder.body(body) {
        Ok(req) => req,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway client error\n").into_response(),
    };

    match client.send(req).await {
        Ok(resp) => {
            let status = resp.status();
            let mut headers = HeaderMap::new();
            forward_response_headers(resp.headers(), &upstream.header_down.remove, &mut headers);
            // Response header set/overrides.
            for (name, value) in &upstream.header_down.set {
                set_header_str(&mut headers, name, value);
            }
            (status, headers, Body::from_stream(resp.into_body())).into_response()
        }
        Err(UpstreamError::Timeout) => {
            tracing::warn!(%host, "gateway upstream request timed out");
            (StatusCode::GATEWAY_TIMEOUT, "upstream timeout\n").into_response()
        }
        Err(UpstreamError::Failed) => (StatusCode::BAD_GATEWAY, "upstream error\n").into_response(),
        Err(UpstreamError::PayloadTooLarge) => {
            tracing::warn!(%host, "gateway upstream request body exceeded the buffer_requests cap");
            (StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n").into_response()
        }
        // A 4xx (client-side stall), so passive health does NOT count it against the backend.
        Err(UpstreamError::RequestBodyTimeout) => {
            tracing::warn!(%host, "gateway upstream request body read timed out while buffering (slow client)");
            (StatusCode::REQUEST_TIMEOUT, "request body read timed out\n").into_response()
        }
        // Node-wide buffering saturation: a LOCAL pre-dial refusal (no backend was contacted). Tag
        // it so `dispatch_gateway` skips the passive-health record — a `503` here must never eject a
        // healthy backend (unlike a backend-origin `503`, which flows through the `Ok` arm above and
        // IS counted).
        Err(UpstreamError::BufferingOverloaded) => {
            tracing::warn!(%host, "gateway refused request buffering: node-wide buffering-concurrency cap reached");
            let mut resp = (
                StatusCode::SERVICE_UNAVAILABLE,
                "node buffering capacity reached; retry shortly\n",
            )
                .into_response();
            resp.extensions_mut().insert(LocalPreDialOverload);
            resp
        }
    }
}

/// Insert a header from string name/value, ignoring an invalid name/value
/// (operator-supplied header rewrites shouldn't 500 the response).
fn set_header_str(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

/// Proxy to a gateway upstream over a **unix-domain socket**:
/// `target = unix:/path/to.sock`. Drives a hyper HTTP/1 client connection over
/// the `UnixStream`; applies the same strip-prefix / host / header / X-Forwarded
/// handling as the TCP path and streams both bodies.
#[cfg(unix)]
async fn proxy_upstream_unix(
    request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    socket_path: &str,
    request_path: &str,
    client_ip: IpAddr,
) -> Response {
    let stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(socket = socket_path, %err, "gateway unix upstream unreachable");
            return (
                StatusCode::BAD_GATEWAY,
                "gateway unix upstream unreachable\n",
            )
                .into_response();
        }
    };
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "gateway unix handshake failed\n").into_response();
        }
    };
    // Drive the connection in the background for the lifetime of the exchange.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (parts, body) = request.into_parts();
    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    // Origin-form request URI: the strip-prefixed path + the original query.
    let forwarded = upstream.forward_path(request_path);
    let uri = match parts.uri.query() {
        Some(q) => format!("{forwarded}?{q}"),
        None => forwarded.into_owned(),
    };
    // Host: fixed override, the client's own Host (preserve), or `localhost` (the unix default, which
    // has no authority of its own). Forward-leg only — never a routing input.
    let host = match upstream.host_forward() {
        boatramp_core::gateway::HostForward::Fixed(hh) => hh.to_string(),
        boatramp_core::gateway::HostForward::PreserveClient => parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| "localhost".to_string()),
        boatramp_core::gateway::HostForward::UpstreamAuthority => "localhost".to_string(),
    };

    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(uri);
    for (name, value) in &parts.headers {
        if name == header::HOST
            || is_hop_by_hop(name)
            || upstream
                .header_up
                .remove
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder
        .header(header::HOST, &host)
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", scheme);
    for (name, value) in &upstream.header_up.set {
        builder = builder.header(name, value);
    }
    let upstream_req = match builder.body(body) {
        Ok(req) => req,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway unix request error\n").into_response(),
    };

    match sender.send_request(upstream_req).await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut headers = HeaderMap::new();
            forward_response_headers(resp.headers(), &upstream.header_down.remove, &mut headers);
            for (name, value) in &upstream.header_down.set {
                set_header_str(&mut headers, name, value);
            }
            (status, headers, Body::new(resp.into_body())).into_response()
        }
        Err(err) => {
            tracing::warn!(socket = socket_path, %err, "gateway unix upstream request failed");
            (StatusCode::BAD_GATEWAY, "upstream error\n").into_response()
        }
    }
}

/// Whether the request asks for an HTTP upgrade (`Connection: upgrade` +
/// `Upgrade: …`), e.g. a WebSocket handshake.
pub(super) fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| {
            c.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    connection_upgrade && headers.contains_key(header::UPGRADE)
}

/// Map a TCP upstream URL scheme to the upgrade transport: `Some(false)` = plaintext
/// (`http`/`ws`), `Some(true)` = TLS (`https`/`wss`), `None` = unsupported.
fn upgrade_transport(scheme: &str) -> Option<bool> {
    match scheme {
        "http" | "ws" => Some(false),
        "https" | "wss" => Some(true),
        _ => None,
    }
}

/// The `Host` to forward on an upgrade (WebSocket) request, by the upstream's
/// [`host_forward`](boatramp_core::gateway::Upstream::host_forward) precedence: a fixed
/// `host_header`, the client's own inbound Host (`preserve_host`), or `default_host` (the resolved
/// upstream authority, or `localhost` for a unix socket) when neither is set. Forward-leg only — the
/// route was already matched on the client's verified domain.
fn upgrade_host(
    upstream: &boatramp_core::gateway::Upstream,
    client_headers: &HeaderMap,
    default_host: &str,
) -> String {
    match upstream.host_forward() {
        boatramp_core::gateway::HostForward::Fixed(hh) => hh.to_string(),
        boatramp_core::gateway::HostForward::PreserveClient => client_headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| default_host.to_string()),
        boatramp_core::gateway::HostForward::UpstreamAuthority => default_host.to_string(),
    }
}

/// Proxy an HTTP **upgrade** (WebSocket) to a gateway upstream: forward the
/// handshake over a hyper client connection and, on `101`, bridge the two
/// upgraded byte streams in both directions. Supports `http`/`ws` (plaintext),
/// `https`/`wss` (TLS), and `unix:` upstreams.
async fn proxy_upgrade(
    mut request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    target: &str,
    request_path: &str,
    client_ip: IpAddr,
    policy: GatewayTargetPolicy,
    posture: boatramp_core::security::SecurityPosture,
) -> Response {
    // Register interest in the client-side upgrade (our own mechanism — the inbound
    // connection is served by boatramp-http's serve loop, not hyper) before the request
    // is moved. Absent only if the request lacked upgrade intent (shouldn't happen — the
    // caller gated on `is_upgrade_request`).
    let Some(client_on_upgrade) = boatramp_http::on_upgrade(&mut request) else {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upgrade: no client upgrade handle\n",
        )
            .into_response();
    };
    let method = request.method().clone();
    let req_headers = request.headers().clone();
    let query = request.uri().query().map(str::to_string);
    let forwarded = upstream.forward_path(request_path);
    let uri = match &query {
        Some(q) => format!("{forwarded}?{q}"),
        None => forwarded.into_owned(),
    };

    // Unix-socket upstream — operator-tier only, operator opt-in (see `proxy_upstream`). A project
    // tier upstream may not reach a unix socket (not a public host).
    if let Some(socket_path) = target.strip_prefix("unix:") {
        if !matches!(policy, GatewayTargetPolicy::Operator) {
            tracing::warn!(
                %target,
                "gateway upgrade refused: a project-tier upstream may not target a unix socket"
            );
            return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
        }
        if !posture.allow_site_unix_upstreams {
            tracing::warn!(
                %target,
                "gateway upgrade refused: unix-socket upstreams disabled by security posture"
            );
            return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
        }
        #[cfg(unix)]
        {
            let stream = match tokio::net::UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(_) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        "gateway unix upstream unreachable\n",
                    )
                        .into_response();
                }
            };
            let host = upgrade_host(upstream, &req_headers, "localhost");
            return upgrade_over(
                hyper_util::rt::TokioIo::new(stream),
                method,
                uri,
                req_headers,
                host,
                upstream,
                client_ip,
                client_on_upgrade,
            )
            .await;
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            return (
                StatusCode::NOT_IMPLEMENTED,
                "unix upstreams are unix-only\n",
            )
                .into_response();
        }
    }

    // TCP (http/ws) upstream: resolve + pin (private allowed; metadata refused).
    let parsed = match reqwest::Url::parse(target) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_GATEWAY, "bad gateway upstream\n").into_response(),
    };
    // http/ws → plaintext; https/wss → TLS. Anything else is unsupported.
    let tls = match upgrade_transport(parsed.scheme()) {
        Some(tls) => tls,
        None => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                "gateway upgrade supports http/ws, https/wss, or unix upstreams\n",
            )
                .into_response();
        }
    };
    let Some(host) = parsed.host_str().map(str::to_string) else {
        return (StatusCode::BAD_GATEWAY, "gateway upstream missing host\n").into_response();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addr = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut chosen = None;
            for addr in addrs {
                // Cloud-metadata always refused; the tier's address rule applies (see
                // `proxy_upstream` / `gateway_addr_allowed_for`).
                if !gateway_addr_allowed_for(addr.ip(), policy, &posture) {
                    tracing::warn!(
                        %host, ip = %addr.ip(),
                        "gateway upgrade refused: address not permitted by security posture"
                    );
                    return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n")
                        .into_response();
                }
                chosen.get_or_insert(addr);
            }
            chosen
        }
        Err(_) => None,
    };
    let Some(addr) = addr else {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream did not resolve\n",
        )
            .into_response();
    };
    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "gateway upstream unreachable\n").into_response();
        }
    };
    let host_hdr = upgrade_host(upstream, &req_headers, &host);
    // `wss`/`https`: complete the TLS handshake to the upstream first, then run the
    // WebSocket upgrade over the encrypted stream. SNI + cert verification use the
    // resolved upstream host against the platform's webpki roots.
    if tls {
        let server_name = match rustls::pki_types::ServerName::try_from(host) {
            Ok(name) => name,
            Err(_) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    "gateway upstream host invalid for TLS\n",
                )
                    .into_response();
            }
        };
        let tls_stream = match tls_connector().connect(server_name, stream).await {
            Ok(s) => s,
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "gateway TLS handshake failed\n").into_response();
            }
        };
        return upgrade_over(
            hyper_util::rt::TokioIo::new(tls_stream),
            method,
            uri,
            req_headers,
            host_hdr,
            upstream,
            client_ip,
            client_on_upgrade,
        )
        .await;
    }
    upgrade_over(
        hyper_util::rt::TokioIo::new(stream),
        method,
        uri,
        req_headers,
        host_hdr,
        upstream,
        client_ip,
        client_on_upgrade,
    )
    .await
}

/// A process-wide TLS client connector for `wss`/`https` gateway upstreams, built once
/// from the platform's webpki roots (server auth only; the gateway never presents a
/// client cert). Cheap to clone (an `Arc` inside).
fn tls_connector() -> tokio_rustls::TlsConnector {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<std::sync::Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Pin the `ring` provider explicitly (the tree standardizes on ring via reqwest);
        // `aws-lc-rs` is also present transitively, so the default provider is ambiguous.
        std::sync::Arc::new(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    });
    tokio_rustls::TlsConnector::from(config.clone())
}

/// Drive a hyper HTTP/1 client connection (with upgrades) over `io`, forward the
/// upgrade handshake, and on `101` bridge the upgraded streams both ways.
#[allow(clippy::too_many_arguments)]
async fn upgrade_over<I>(
    io: I,
    method: Method,
    uri: String,
    req_headers: HeaderMap,
    host: String,
    upstream: &boatramp_core::gateway::Upstream,
    client_ip: IpAddr,
    client_on_upgrade: boatramp_http::OnUpgrade,
) -> Response
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway handshake failed\n").into_response(),
    };
    // `with_upgrades` keeps the connection alive for the upgraded stream.
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(uri);
    // Forward all headers (the handshake NEEDS Connection/Upgrade/Sec-WebSocket-*),
    // replacing Host and honoring the upstream's header rewrites.
    for (name, value) in &req_headers {
        if name == header::HOST
            || upstream
                .header_up
                .remove
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder
        .header(header::HOST, &host)
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", "http");
    for (name, value) in &upstream.header_up.set {
        builder = builder.header(name, value);
    }
    let upstream_req = match builder.body(Body::empty()) {
        Ok(req) => req,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway request error\n").into_response(),
    };

    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(resp) => resp,
        Err(_) => return (StatusCode::BAD_GATEWAY, "upstream error\n").into_response(),
    };

    if upstream_resp.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
        // Bridge the two upgraded connections once both sides flip. The client side is
        // our own `Upgraded` (already a tokio stream, delivered by the serve loop after it
        // writes our 101); the upstream side is hyper's (the upstream *client* stays hyper).
        let upstream_on_upgrade = hyper::upgrade::on(&mut upstream_resp);
        tokio::spawn(async move {
            if let (Ok(mut client_io), Ok(upstream_io)) =
                (client_on_upgrade.await, upstream_on_upgrade.await)
            {
                let mut upstream_io = hyper_util::rt::TokioIo::new(upstream_io);
                let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
            }
        });
        // Return the upstream's 101 (with its Upgrade/Sec-WebSocket-Accept headers).
        // `append` preserves repeated headers (no hop-by-hop filter here — the upgrade
        // handshake legitimately needs `Connection`/`Upgrade` forwarded).
        let mut headers = HeaderMap::new();
        for (name, value) in upstream_resp.headers() {
            headers.append(name.clone(), value.clone());
        }
        return (StatusCode::SWITCHING_PROTOCOLS, headers, Body::empty()).into_response();
    }

    // Upstream declined the upgrade — this is an ordinary (non-101) response, so pass it
    // through like the normal reverse-proxy path. A known `Content-Length` is KEPT (not
    // stripped): the serving stack frames the re-streamed body with it so a proxied
    // known-length download keeps progress + range, and a registry blob `HEAD` relays its
    // `content-length` — matching the v0.70.0 response-path CL-preserve fix (stripping it
    // here was a latent inconsistency). The strip is NOT needed for upgrade framing: this
    // branch is reached only when the upstream did NOT switch protocols, and the 101 path
    // above forwards headers verbatim. `append` preserves REPEATED headers — notably every
    // `Set-Cookie` (see `forward_response_headers`).
    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        headers.append(name.clone(), value.clone());
    }
    (status, headers, Body::new(upstream_resp.into_body())).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repro for the proxy small-response stall: drive `cached_client` against a
    /// local keep-alive upstream (TCP_NODELAY on, so any stall is on *our* client
    /// leg) and measure warm per-request latency. A Nagle / delayed-ACK / flush
    /// stall shows as tens of ms; healthy loopback is well under 10 ms.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn upstream_client_small_request_is_prompt() {
        use axum::serve::ListenerExt;
        use std::time::Instant;

        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { axum::body::Bytes::from(vec![7u8; 1024]) }),
        );
        let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = raw.local_addr().unwrap();
        let listener = raw.tap_io(|s| {
            let _ = s.set_nodelay(true);
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!("http://127.0.0.1:{}/", addr.port());
        let mut worst = 0f64;
        for i in 0..30 {
            let req = Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .body(Body::empty())
                .unwrap();
            let start = Instant::now();
            let resp = match client.send(req).await {
                Ok(resp) => resp,
                Err(err) => panic!("send failed at iter {i}: {err:?}"),
            };
            let body = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
                .await
                .unwrap();
            assert_eq!(body.len(), 1024);
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            eprintln!("iter {i}: {ms:.2}ms");
            if i > 1 {
                worst = worst.max(ms); // skip the first couple (cold connect)
            }
        }
        assert!(
            worst < 15.0,
            "warm upstream request latency {worst:.1}ms — Nagle/flush stall on the native upstream client"
        );
    }

    #[test]
    fn upgrade_transport_maps_scheme_to_tls() {
        // Plaintext schemes.
        assert_eq!(upgrade_transport("http"), Some(false));
        assert_eq!(upgrade_transport("ws"), Some(false));
        // TLS schemes (wss/https).
        assert_eq!(upgrade_transport("https"), Some(true));
        assert_eq!(upgrade_transport("wss"), Some(true));
        // Anything else is unsupported for an upgrade.
        assert_eq!(upgrade_transport("ftp"), None);
        assert_eq!(upgrade_transport("unix"), None);
        assert_eq!(upgrade_transport(""), None);
    }

    /// Bind an ephemeral upstream serving `app`, with `TCP_NODELAY` (any stall would be
    /// on our client leg). Returns the address.
    async fn spawn_upstream(app: axum::Router) -> SocketAddr {
        use axum::serve::ListenerExt;
        let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = raw.local_addr().unwrap();
        let listener = raw.tap_io(|s| {
            let _ = s.set_nodelay(true);
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        addr
    }

    /// The plaintext pool key with no overrides (matches `pinned_client(host, addr, false)`).
    fn plain_key(addr: SocketAddr) -> UpstreamClientKey {
        UpstreamClientKey {
            host: "127.0.0.1".to_string(),
            addr,
            https: false,
            connect_timeout_ms: None,
            request_timeout_ms: None,
            tls_insecure: false,
            read_buffer_bytes: None,
        }
    }

    /// A large response proxies back byte-for-byte over the native client, and its
    /// keep-alive connection is returned to the pool (a second request reuses it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_large_get_byte_identical_and_pools_connection() {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let served = big.clone();
        let app = axum::Router::new().route(
            "/big",
            axum::routing::get(move || {
                let b = served.clone();
                async move { axum::body::Bytes::from(b) }
            }),
        );
        let addr = spawn_upstream(app).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!("http://127.0.0.1:{}/big", addr.port());

        for round in 0..2 {
            let req = Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .body(Body::empty())
                .unwrap();
            let resp = client.send(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
                .await
                .unwrap();
            assert_eq!(
                body.as_ref(),
                big.as_slice(),
                "body mismatch on round {round}"
            );
            // After a fully drained keep-alive response the connection is back in the pool,
            // and it never grows past one for a single serial caller.
            let idle = POOL
                .lock()
                .unwrap()
                .get(&plain_key(addr))
                .map_or(0, Vec::len);
            assert_eq!(
                idle, 1,
                "expected exactly one pooled connection after round {round}"
            );
        }
    }

    /// A request body with a declared `Content-Length` is forwarded fixed-length and the
    /// upstream echoes it back unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_forwards_fixed_length_request_body() {
        let app = axum::Router::new().route(
            "/echo",
            axum::routing::post(|body: axum::body::Bytes| async move { body }),
        );
        let addr = spawn_upstream(app).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!("http://127.0.0.1:{}/echo", addr.port());
        let payload = vec![b'p'; 4096];

        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header(header::CONTENT_LENGTH, payload.len())
            .body(Body::from(payload.clone()))
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let echoed = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
            .await
            .unwrap();
        assert_eq!(echoed.as_ref(), payload.as_slice());
    }

    /// A request body of unknown length is chunk-encoded to the upstream, which echoes the
    /// reassembled bytes back unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_forwards_chunked_request_body() {
        let app = axum::Router::new().route(
            "/echo",
            axum::routing::post(|body: axum::body::Bytes| async move { body }),
        );
        let addr = spawn_upstream(app).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!("http://127.0.0.1:{}/echo", addr.port());

        // No Content-Length header + a streamed body ⇒ the client picks chunked framing.
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"the quick ")),
            Ok(Bytes::from_static(b"brown fox ")),
            Ok(Bytes::from_static(b"jumps")),
        ];
        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .body(Body::from_stream(futures::stream::iter(chunks)))
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let echoed = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
            .await
            .unwrap();
        assert_eq!(echoed.as_ref(), b"the quick brown fox jumps".as_slice());
    }

    /// Regression (gateway login / Set-Cookie drop): a login response carries SEVERAL
    /// distinct `Set-Cookie` fields at once. `forward_response_headers` must keep EVERY one
    /// as a separate header — a `HeaderMap::insert` (the prior behavior) collapsed the repeats
    /// to the last value, silently dropping the session cookie so the browser was bounced back
    /// to the login page. Hop-by-hop headers + the upstream's `header_down.remove` are dropped;
    /// a known `Content-Length` is now KEPT (preserved so the re-streamed body keeps its
    /// length); other repeated headers survive too.
    #[test]
    fn forward_response_headers_preserves_repeated_set_cookie() {
        // A Gitea-shaped login 303's header set: five distinct cookies, plus a hop-by-hop
        // header, a Content-Length, and a to-be-removed header, and a repeated Vary.
        let mut upstream = HeaderMap::new();
        upstream.append(header::LOCATION, HeaderValue::from_static("/"));
        for cookie in [
            "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
            "_csrf=csrftok; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax",
            "lang=en-US; Path=/; Max-Age=2147483647",
            "i_like_gitea=likeit; Path=/; HttpOnly; Secure",
            "macaron_flash=; Path=/; Max-Age=0; HttpOnly",
        ] {
            upstream.append(header::SET_COOKIE, HeaderValue::from_static(cookie));
        }
        upstream.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        upstream.append(header::VARY, HeaderValue::from_static("Cookie"));
        upstream.append(header::CONNECTION, HeaderValue::from_static("keep-alive")); // hop-by-hop
        upstream.append(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        upstream.append(
            HeaderName::from_static("x-internal"),
            HeaderValue::from_static("secret"),
        );

        let mut out = HeaderMap::new();
        forward_response_headers(&upstream, &["x-internal".to_string()], &mut out);

        // Every distinct Set-Cookie survives, as SEPARATE fields (never comma-joined).
        let cookies: Vec<&str> = out
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies.len(),
            5,
            "all five Set-Cookie fields must survive; got {cookies:?}"
        );
        assert!(
            cookies.iter().any(|c| c.starts_with("session=")),
            "the session cookie must not be dropped; got {cookies:?}"
        );
        assert!(
            cookies.iter().any(|c| c.starts_with("_csrf=")),
            "the CSRF cookie must survive; got {cookies:?}"
        );
        // No single field smuggles two cookies (a comma-join corruption).
        for c in &cookies {
            assert!(
                !(c.contains("session=") && c.contains("_csrf=")),
                "Set-Cookie fields must not be comma-joined: {c:?}"
            );
        }
        // Other repeated headers survive too.
        assert_eq!(out.get_all(header::VARY).iter().count(), 2);
        // Hop-by-hop + header_down.remove targets are dropped.
        assert!(!out.contains_key(header::CONNECTION));
        assert!(!out.contains_key(HeaderName::from_static("x-internal")));
        // A known Content-Length is now PRESERVED (U29: the re-streamed body keeps its
        // length so the downstream frames it with Content-Length, not chunked).
        assert_eq!(
            out.get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("0"),
            "a known Content-Length must be preserved for the re-streamed body"
        );
    }

    /// End-to-end over the real upstream codec: a raw mock upstream emits an actual
    /// `303 See Other` login response with five distinct `Set-Cookie` lines on the wire; the
    /// native client parses it and `forward_response_headers` relays it. Asserts all five
    /// cookies reach the downstream map intact and separate — the faithful shape of the
    /// `cad.tokenfield.ai` → Gitea login that v0.63.1's edge broke.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gateway_login_303_relays_all_set_cookie_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const RESP: &[u8] = b"HTTP/1.1 303 See Other\r\n\
Location: /\r\n\
Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax\r\n\
Set-Cookie: _csrf=csrftok; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax\r\n\
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647\r\n\
Set-Cookie: i_like_gitea=likeit; Path=/; HttpOnly; Secure\r\n\
Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

        let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = raw.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = raw.accept().await {
                let _ = sock.set_nodelay(true);
                // Drain the request head, then emit the raw login 303.
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(RESP).await;
                let _ = sock.flush().await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!("http://127.0.0.1:{}/user/login", addr.port());
        let req = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        // Relay the upstream response headers exactly as `proxy_upstream` does.
        let mut out = HeaderMap::new();
        forward_response_headers(resp.headers(), &[], &mut out);

        let cookies: Vec<&str> = out
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies.len(),
            5,
            "the client must receive all five Set-Cookie fields from the 303; got {cookies:?}"
        );
        assert!(cookies.iter().any(|c| c.starts_with("session=")));
        assert!(cookies.iter().any(|c| c.starts_with("_csrf=")));
    }

    // --- bodied upload forward path (docker registry blob PUT through the gateway) -------
    //
    // These exercise the fallback (non-splice) forwarder that every bodied request takes:
    // the native upstream client `UpstreamClient::send` (driven identically by `proxy_upstream`
    // and the absolute-URL `proxy`). A raw one-shot upstream reads the forwarded request off
    // the wire — head *and* body, honoring the framing the client emitted — so the assertions
    // are on the actual bytes gitea would receive, not on an assumption.

    /// Decode a complete HTTP/1.1 `chunked` body buffer into its payload bytes.
    fn decode_chunked_body(mut data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(nl) = data.windows(2).position(|w| w == b"\r\n") {
            let size_hex = data[..nl].split(|&b| b == b';').next().unwrap_or(&[]);
            let size =
                usize::from_str_radix(std::str::from_utf8(size_hex).unwrap_or("0").trim(), 16)
                    .unwrap_or(0);
            data = &data[nl + 2..];
            if size == 0 {
                break; // terminal chunk
            }
            if data.len() < size {
                break;
            }
            out.extend_from_slice(&data[..size]);
            data = &data[(size + 2).min(data.len())..]; // skip chunk data + its trailing CRLF
        }
        out
    }

    /// A raw one-shot upstream: accept one connection, read the full request (head, then the
    /// body per its declared framing — fixed `Content-Length` or `chunked`), reply with
    /// `response`, and hand back the captured `(head_text, decoded_body)`. Faithful to a real
    /// origin — the framing is read off the wire, never assumed.
    async fn capture_upstream(
        response: &'static [u8],
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<(String, Vec<u8>)>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = raw.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = raw.accept().await else {
                return;
            };
            let _ = sock.set_nodelay(true);
            let mut buf: Vec<u8> = Vec::new();
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                let mut tmp = [0u8; 4096];
                match sock.read(&mut tmp).await {
                    Ok(0) => break buf.len(),
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let lower = head.to_ascii_lowercase();
            let mut raw_body: Vec<u8> = buf[head_end..].to_vec();
            let body = if let Some(cl) = lower
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                while raw_body.len() < cl {
                    let mut tmp = [0u8; 4096];
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => raw_body.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                raw_body.truncate(cl);
                raw_body
            } else if lower.contains("transfer-encoding:") && lower.contains("chunked") {
                // Read until the terminal `0\r\n\r\n` the client emits (`chunked::encode_last`).
                while !raw_body.ends_with(b"0\r\n\r\n") {
                    let mut tmp = [0u8; 4096];
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => raw_body.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                decode_chunked_body(&raw_body)
            } else {
                Vec::new()
            };
            let _ = sock.write_all(response).await;
            let _ = sock.flush().await;
            let _ = tx.send((head, body));
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, rx)
    }

    /// Reproduce-first (the reported incident): a `docker push` to a Gitea-fronted registry
    /// 400-loops on the blob-upload finalize `PUT …/blobs/…?digest=sha256:…`. That PUT carries
    /// an **empty body with an explicit `Content-Length: 0`**, and the registry REQUIRES the
    /// header's presence — it answers `missing content-length header for request` if it is
    /// absent. The forwarder stripped the inbound `Content-Length` and, on the zero-length arm,
    /// never re-emitted it, so Gitea saw no length and rejected the push. This drives a
    /// Gitea-shaped upstream that returns `400` unless the forwarded head carries a
    /// `Content-Length`; the forwarded PUT must therefore arrive with `Content-Length: 0` and
    /// the client must see the `201`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_preserves_zero_content_length_on_blob_put() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        const MISSING_CL: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 44\r\nConnection: close\r\n\r\nmissing content-length header for request: x";

        let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = raw.local_addr().unwrap();
        let (head_tx, head_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = raw.accept().await else {
                return;
            };
            let _ = sock.set_nodelay(true);
            let mut buf = Vec::new();
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                let mut tmp = [0u8; 2048];
                match sock.read(&mut tmp).await {
                    Ok(0) => break buf.len(),
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            // Gitea's registry contract: the blob PUT must carry a Content-Length header.
            let resp = if head.to_ascii_lowercase().contains("content-length:") {
                OK
            } else {
                MISSING_CL
            };
            let _ = sock.write_all(resp).await;
            let _ = sock.flush().await;
            let _ = head_tx.send(head);
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/abc?digest=sha256:deadbeef",
            addr.port()
        );
        // The finalize PUT exactly as docker/containerd sends it: empty body, explicit CL: 0.
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .header(header::CONTENT_LENGTH, 0)
            .body(Body::empty())
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "the Gitea-shaped registry rejected the blob PUT — the forwarder dropped Content-Length: 0"
        );

        let head = head_rx.await.unwrap();
        assert!(
            head.to_ascii_lowercase().contains("content-length: 0"),
            "the forwarded blob PUT must preserve the client's explicit Content-Length: 0; got head:\n{head}"
        );
        // Anti-smuggling invariant: exactly one framing header, and never a chunked body.
        assert_eq!(
            head.to_ascii_lowercase().matches("content-length:").count(),
            1,
            "exactly one Content-Length must be emitted; got head:\n{head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("transfer-encoding"),
            "a zero-length body must not be re-framed as chunked (no CL×TE); got head:\n{head}"
        );
    }

    /// A non-empty `Content-Length` PUT body (a monolithic blob upload) forwards fixed-length:
    /// the upstream receives the exact bytes under a single `Content-Length: N` framing, never
    /// re-chunked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_forwards_content_length_put_body_intact() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, rx) = capture_upstream(OK).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/u1",
            addr.port()
        );
        let blob = vec![0xABu8; 9000];

        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .header(header::CONTENT_LENGTH, blob.len())
            .body(Body::from(blob.clone()))
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        // Drain the response so the exchange completes before we read the capture.
        let _ = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
            .await
            .unwrap();

        let (head, body) = rx.await.unwrap();
        let lower = head.to_ascii_lowercase();
        assert_eq!(
            body, blob,
            "the upstream must receive the blob bytes intact"
        );
        assert!(
            lower.contains(&format!("content-length: {}", blob.len())),
            "a fixed-length body must forward its Content-Length; got head:\n{head}"
        );
        assert!(
            !lower.contains("transfer-encoding"),
            "a Content-Length body must not be re-chunked (no CL×TE); got head:\n{head}"
        );
    }

    /// A chunked PUT body (a streamed layer upload with no declared length) forwards as
    /// `Transfer-Encoding: chunked`: the upstream reassembles the exact bytes, and the head
    /// carries chunked framing with no spurious `Content-Length` (no CL×TE ambiguity).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_forwards_chunked_put_body_intact() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, rx) = capture_upstream(OK).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/u2",
            addr.port()
        );

        // No Content-Length + a streamed body ⇒ the client frames it chunked.
        let parts: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"layer-")),
            Ok(Bytes::from_static(b"segment-")),
            Ok(Bytes::from_static(b"payload")),
        ];
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .body(Body::from_stream(futures::stream::iter(parts)))
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let _ = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
            .await
            .unwrap();

        let (head, body) = rx.await.unwrap();
        let lower = head.to_ascii_lowercase();
        assert_eq!(
            body, b"layer-segment-payload",
            "the upstream must reassemble the chunked body intact"
        );
        assert!(
            lower.contains("transfer-encoding: chunked"),
            "a length-unknown streamed body must forward chunked; got head:\n{head}"
        );
        assert!(
            !lower.contains("content-length"),
            "a chunked body must not also carry a Content-Length (no CL×TE); got head:\n{head}"
        );
    }

    // --- request buffering (buffer_requests): registry-fronting over HTTP/2 ----------------
    //
    // The v0.73.0 fix. A `docker push` over the edge's HTTP/2 arrives END_STREAM-delimited with
    // no Content-Length, so the h2→h1 forward leg would frame it `Transfer-Encoding: chunked` —
    // which a Gitea/OCI registry rejects on a blob PUT ("missing content-length header"). With
    // `buffer_requests` the forward leg buffers the body to a bounded temp file, computes its
    // length, and forwards it fixed-length. Default-off leaves the chunked path unchanged (see
    // `native_client_forwards_chunked_put_body_intact`, above).

    /// With `buffer_requests` ON, a length-unknown streamed body (no `Content-Length`) is buffered
    /// and forwarded FIXED-LENGTH: the upstream receives the exact bytes under a single
    /// `Content-Length: N` and NO `Transfer-Encoding`, which is what the registry blob PUT needs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_buffers_length_unknown_body_to_fixed_length() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, rx) = capture_upstream(OK).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            .with_buffering(true, Some(16 * 1024 * 1024), None, None, None, None);
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/u4",
            addr.port()
        );

        // No Content-Length + a streamed body ⇒ WITHOUT buffering this would forward chunked.
        let parts: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"layer-")),
            Ok(Bytes::from_static(b"segment-")),
            Ok(Bytes::from_static(b"payload")),
        ];
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .body(Body::from_stream(futures::stream::iter(parts)))
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let _ = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
            .await
            .unwrap();

        let (head, body) = rx.await.unwrap();
        let lower = head.to_ascii_lowercase();
        assert_eq!(
            body, b"layer-segment-payload",
            "the upstream must receive the buffered body intact"
        );
        assert!(
            lower.contains(&format!(
                "content-length: {}",
                "layer-segment-payload".len()
            )),
            "a buffered body must forward a computed Content-Length; got head:\n{head}"
        );
        assert!(
            !lower.contains("transfer-encoding"),
            "a buffered body must NOT be chunked (that is the bug being fixed); got head:\n{head}"
        );
    }

    /// DoS guard: with `buffer_requests` ON, a length-unknown body that exceeds `max_buffer_bytes`
    /// is REJECTED (`PayloadTooLarge` → `413`) rather than buffered without bound — so an untrusted
    /// upload can neither exhaust memory nor fill the disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_buffer_requests_rejects_body_over_cap() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        // Bind an upstream so a (buggy) forward would succeed loudly rather than hang; the guard
        // must trip before any dial, so the upstream is never actually contacted.
        let (addr, _rx) = capture_upstream(OK).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            .with_buffering(true, Some(8), None, None, None, None); // 8-byte cap
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/u5",
            addr.port()
        );

        // 15 bytes with no declared length — over the 8-byte cap.
        let parts: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"aaaaa")),
            Ok(Bytes::from_static(b"bbbbb")),
            Ok(Bytes::from_static(b"ccccc")),
        ];
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .body(Body::from_stream(futures::stream::iter(parts)))
            .unwrap();
        match client.send(req).await {
            Err(UpstreamError::PayloadTooLarge) => {}
            Ok(_) => panic!("a body over the buffer cap must be rejected, not forwarded"),
            Err(e) => panic!("expected PayloadTooLarge, got {e:?}"),
        }
    }

    /// Unit on the bounded-buffer helper: it spills to an UNNAMED temp file and leaves nothing
    /// behind on ANY exit path. Success path — the body replays intact and the dir stays empty
    /// (the file is unlinked at creation, so no directory entry ever appears). Over-cap path —
    /// `TooLarge`, and still nothing is left behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffer_body_to_length_in_is_bounded_and_leaves_no_tempfile() {
        fn dir_entry_count(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).unwrap().count()
        }

        // --- success: an under-cap body round-trips and leaves no file ---
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(dir_entry_count(tmp.path()), 0);
        let first = Bytes::from_static(b"hello ");
        let rest: Vec<Result<Bytes, axum::Error>> = vec![
            Ok(Bytes::from_static(b"brave ")),
            Ok(Bytes::from_static(b"world")),
        ];
        let mut data: BodyData = Box::pin(futures::stream::iter(rest));
        let (len, replay) =
            buffer_body_to_length_in(first, &mut data, 1024, permissive_guards(), tmp.path())
                .await
                .expect("an under-cap body buffers");
        assert_eq!(len, b"hello brave world".len() as u64);
        // Unlinked at creation — the dir shows no entry even while the handle is live.
        assert_eq!(
            dir_entry_count(tmp.path()),
            0,
            "no named temp file is ever created (crash-safe: unlinked at creation)"
        );
        let buffered = axum::body::to_bytes(Body::from_stream(replay), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            buffered.as_ref(),
            b"hello brave world",
            "the buffered body replays intact"
        );
        assert_eq!(
            dir_entry_count(tmp.path()),
            0,
            "nothing is left behind after the replay stream drops"
        );

        // --- over-cap: rejected, still nothing left behind ---
        let first = Bytes::from_static(b"0123456789");
        let rest: Vec<Result<Bytes, axum::Error>> = vec![Ok(Bytes::from_static(b"abcdef"))];
        let mut data: BodyData = Box::pin(futures::stream::iter(rest));
        let err = buffer_body_to_length_in(first, &mut data, 12, permissive_guards(), tmp.path())
            .await
            .err();
        assert!(
            matches!(err, Some(BufferError::TooLarge)),
            "an over-cap body is rejected with TooLarge"
        );
        assert_eq!(
            dir_entry_count(tmp.path()),
            0,
            "the over-cap error path leaves no temp file"
        );
    }

    // --- request-buffering slow-client guards: read-idle + throughput floor + optional ceiling ----
    //
    // The `buffer_requests` loop reads an untrusted body to a temp file BEFORE the upstream
    // write, so it is bounded by neither `request_timeout_ms` (which wraps only `attempt`, after
    // buffering) nor the connection idle timeout (which never fires on an actively-trickling
    // stream). A 1-byte-per-few-seconds trickle therefore held a connection slot + a growing temp
    // file indefinitely (live-gate: >160 s, no timeout). The guard is three-part: a per-read idle
    // timeout (a fully-stalled client), a MINIMUM-THROUGHPUT floor over a trailing window (a
    // drip-feed that never idles — AND, unlike the flat wall-clock cap it replaces, one that does
    // NOT false-`408` a slow-but-steadily-progressing large upload), and an OPTIONAL absolute
    // ceiling (blunt defense-in-depth, off by default). Any of the three aborts with
    // `BufferError::Timeout` → `UpstreamError::RequestBodyTimeout` → `408` (a 4xx, so passive health
    // never ejects the healthy backend for a client-side stall), dropping the temp file.

    /// Permissive guards for the direct-helper unit tests: a long read-idle, throughput floor OFF,
    /// no absolute ceiling — so a test that is not about timing never trips one, and a test that IS
    /// overrides only the single guard it exercises.
    fn permissive_guards() -> BufferGuards {
        BufferGuards {
            read_idle: Duration::from_secs(30),
            min_rate_bytes_per_sec: 0,
            rate_window: Duration::from_secs(30),
            abs_ceiling: None,
        }
    }

    /// A single inbound read that STALLS (never yields the next chunk) past the read-idle timeout
    /// aborts buffering with `Timeout` — and, because the temp inode is unlinked at creation, the
    /// spill dir is left empty (no leak). Throughput floor off + no ceiling, so it is provably the
    /// per-read idle timeout that fires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffer_body_to_length_in_aborts_on_read_idle_stall() {
        fn dir_entry_count(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).unwrap().count()
        }
        let tmp = tempfile::tempdir().unwrap();
        // First chunk arrives, then the body stalls forever (the slow-loris "hold").
        let first = Bytes::from_static(b"trickle-start");
        let mut data: BodyData = Box::pin(futures::stream::pending::<Result<Bytes, axum::Error>>());
        let started = std::time::Instant::now();
        let err = buffer_body_to_length_in(
            first,
            &mut data,
            1 << 30, // 1 GiB cap — not the bound under test
            BufferGuards {
                read_idle: Duration::from_millis(60), // the bound under test
                min_rate_bytes_per_sec: 0,            // floor off — isolate read-idle
                rate_window: Duration::from_secs(30),
                abs_ceiling: None,
            },
            tmp.path(),
        )
        .await
        .err();
        assert!(
            matches!(err, Some(BufferError::Timeout)),
            "a stalled inbound read must abort buffering with Timeout, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the read-idle timeout (60ms) must have fired promptly"
        );
        assert_eq!(
            dir_entry_count(tmp.path()),
            0,
            "the timeout path drops the temp file (unlinked at creation) — no leak"
        );
    }

    /// A body that trickles steadily BELOW the throughput floor — each read well within the
    /// read-idle timeout (it never idles), but its sustained rate under the floor — aborts with
    /// `Timeout`. This is the slow-loris the per-read timeout alone cannot stop; the throughput
    /// floor catches it, with NO flat wall-clock cap in play. The temp file is dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffer_body_to_length_in_aborts_on_sub_floor_drip() {
        fn dir_entry_count(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).unwrap().count()
        }
        let tmp = tempfile::tempdir().unwrap();
        // ~1 byte / 20ms ≈ 50 B/s — never idles (20ms ≪ the 5s read-idle), but far below the
        // 10 KiB/s floor: exactly the trickle that evades a per-read timeout.
        let trickle = futures::stream::unfold(0u32, |i| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((Ok::<Bytes, axum::Error>(Bytes::from_static(b"x")), i + 1))
        });
        let first = Bytes::from_static(b"start");
        let mut data: BodyData = Box::pin(trickle);
        let started = std::time::Instant::now();
        let err = buffer_body_to_length_in(
            first,
            &mut data,
            1 << 30, // 1 GiB cap — never reached at this trickle
            BufferGuards {
                read_idle: Duration::from_secs(5), // never fires (each read ~20ms)
                min_rate_bytes_per_sec: 10_000,    // 10 KiB/s floor — the bound under test
                rate_window: Duration::from_millis(100), // short window so the test is quick
                abs_ceiling: None,                 // no flat cap — the floor alone must cut it
            },
            tmp.path(),
        )
        .await
        .err();
        assert!(
            matches!(err, Some(BufferError::Timeout)),
            "a sub-floor drip must abort via the throughput floor, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the throughput floor (one ~100ms window), not a long wall-clock cap, must have fired"
        );
        assert_eq!(
            dir_entry_count(tmp.path()),
            0,
            "the throughput-floor abort path drops the temp file — no leak"
        );
    }

    /// REGRESSION (the v0.73.0 false-positive this fix closes): a slow-but-STEADILY-PROGRESSING
    /// upload that stays ABOVE the throughput floor COMPLETES, even though it spans many rate
    /// windows — where the old flat whole-phase wall-clock cap would have `408`'d it the moment
    /// total buffering time crossed the cap, regardless of its steady progress. The body buffers
    /// intact and the computed length is exact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffer_body_to_length_in_completes_slow_but_steady_upload() {
        let tmp = tempfile::tempdir().unwrap();
        // 8 chunks of 2 KiB, one every 50ms ≈ 40 KiB/s — comfortably above the 2 KiB/s floor, but
        // running ~400ms across ~4 of the 100ms rate windows, so the throughput guard is actually
        // exercised (and passes) on each window boundary rather than never firing.
        const CHUNK: usize = 2000;
        const N: usize = 8;
        let steady = futures::stream::unfold(0usize, |i| async move {
            if i >= N {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            Some((
                Ok::<Bytes, axum::Error>(Bytes::from(vec![b'y'; CHUNK])),
                i + 1,
            ))
        });
        let first = Bytes::from(vec![b's'; CHUNK]);
        let mut data: BodyData = Box::pin(steady);
        let (len, replay) = buffer_body_to_length_in(
            first,
            &mut data,
            1 << 30, // generous cap — not the point
            BufferGuards {
                read_idle: Duration::from_secs(2), // never fires (each read ~50ms)
                min_rate_bytes_per_sec: 2000,      // 2 KiB/s floor — the body clears it
                rate_window: Duration::from_millis(100), // multiple windows elapse over the upload
                abs_ceiling: None,                 // no flat cap (that was the bug)
            },
            tmp.path(),
        )
        .await
        .expect("a steady above-floor upload must complete, not 408");
        let expected = (CHUNK * (N + 1)) as u64;
        assert_eq!(
            len, expected,
            "the computed Content-Length covers the whole body"
        );
        let buffered = axum::body::to_bytes(Body::from_stream(replay), 1 << 24)
            .await
            .unwrap();
        assert_eq!(
            buffered.len() as u64,
            expected,
            "the slow-but-steady body replays intact"
        );
    }

    /// The OPTIONAL absolute ceiling (defense-in-depth): when an operator sets it, it caps total
    /// buffering time regardless of throughput — even a fast, non-idling upload is cut once the
    /// ceiling elapses. Throughput floor off here, so it is provably the ceiling that fires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffer_body_to_length_in_absolute_ceiling_aborts() {
        fn dir_entry_count(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).unwrap().count()
        }
        let tmp = tempfile::tempdir().unwrap();
        // A brisk stream (a chunk every 40ms, forever) that never idles and would clear any floor —
        // only the absolute ceiling can stop it.
        let brisk = futures::stream::unfold(0u32, |i| async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            Some((
                Ok::<Bytes, axum::Error>(Bytes::from_static(b"chunk")),
                i + 1,
            ))
        });
        let first = Bytes::from_static(b"start");
        let mut data: BodyData = Box::pin(brisk);
        let started = std::time::Instant::now();
        let err = buffer_body_to_length_in(
            first,
            &mut data,
            1 << 30,
            BufferGuards {
                read_idle: Duration::from_secs(5), // never fires (each read ~40ms)
                min_rate_bytes_per_sec: 0,         // floor off — isolate the ceiling
                rate_window: Duration::from_secs(30),
                abs_ceiling: Some(Duration::from_millis(100)), // the bound under test
            },
            tmp.path(),
        )
        .await
        .err();
        assert!(
            matches!(err, Some(BufferError::Timeout)),
            "the absolute ceiling must abort even a brisk upload, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the 100ms ceiling, not the 5s read-idle, must have fired"
        );
        assert_eq!(
            dir_entry_count(tmp.path()),
            0,
            "the ceiling abort path drops the temp file — no leak"
        );
    }

    /// End to end through `UpstreamClient::send`: a `buffer_requests` upstream whose client stalls
    /// mid-body (first chunk then silence) is rejected with `UpstreamError::RequestBodyTimeout`
    /// (→ `408`), NOT forwarded and NOT a `504`/`5xx` (so passive health never faults the backend).
    /// The guard trips during buffering, before any pool checkout or dial, so no upstream slot is
    /// taken — the upstream bound here is never contacted. Contrast
    /// `native_client_buffers_length_unknown_body_to_fixed_length`, which runs with the DEFAULT
    /// timeouts and shows a normal fast body is unaffected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_buffer_requests_aborts_on_stalled_body() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, _rx) = capture_upstream(OK).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            // Short read-idle so the fully-stalled body trips quickly; throughput floor disabled
            // (`Some(0)`) and no absolute ceiling, so this isolates the read-idle guard.
            .with_buffering(true, Some(16 * 1024 * 1024), Some(60), Some(0), None, None);
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/u6",
            addr.port()
        );

        // A streamed body with no Content-Length that yields one chunk then stalls forever.
        let body_stream = futures::stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"trickle-start"))
        })
        .chain(futures::stream::pending::<Result<Bytes, std::io::Error>>());
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .body(Body::from_stream(body_stream))
            .unwrap();
        match client.send(req).await {
            Err(UpstreamError::RequestBodyTimeout) => {}
            Ok(_) => panic!("a stalled buffered body must be rejected, not forwarded"),
            Err(e) => panic!("expected RequestBodyTimeout, got {e:?}"),
        }
    }

    // --- node-wide buffering-concurrency semaphore (HIGH-2) --------------------------------
    //
    // The gateway buffering path does NOT go through `max_concurrent_uploads` (that gates only the
    // blob/storage path), so without a node aggregate cap the only bound on concurrent buffering was
    // the listener `max_conns` — worst-case spill = `max_conns × max_buffer_bytes`. A process-wide
    // semaphore ([`BUFFER_SLOTS`]) now bounds concurrent buffering: a request acquires an OWNED permit
    // BEFORE spilling (before any dial) and holds it for the whole buffering + forward phase; when
    // saturated, buffering fails fast with `503` (`BufferingOverloaded`). The permit MUST be released
    // on EVERY exit (success, 413, 408, dial failure, disconnect, panic) via RAII drop — these tests
    // drive a small injected semaphore to prove saturation → 503 and no-leak on each abort path.

    /// Build a length-unknown (no `Content-Length`) streamed `PUT` request — the body shape that
    /// takes the `buffer_requests` spill path.
    fn streamed_put(uri: &str, chunks: Vec<&'static [u8]>) -> Request<Body> {
        let parts: Vec<Result<Bytes, std::io::Error>> = chunks
            .into_iter()
            .map(|c| Ok(Bytes::from_static(c)))
            .collect();
        Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(Body::from_stream(futures::stream::iter(parts)))
            .unwrap()
    }

    /// When the node-wide buffering semaphore is saturated, a further buffering request fails fast
    /// with `BufferingOverloaded` (→ `503`) BEFORE any dial — and once a slot frees, the next request
    /// is admitted and forwarded normally (the permit is reusable).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gateway_buffering_cap_503_when_saturated_then_reusable() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, _rx) = capture_upstream(OK).await;
        // A single-slot semaphore, with its only permit held — simulating a concurrent buffering op.
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let held = sem.clone().try_acquire_owned().expect("the one slot");
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            .with_buffering(true, Some(16 * 1024 * 1024), None, None, None, None)
            .with_buffer_slots(sem.clone());
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/sat",
            addr.port()
        );

        // Saturated → fail fast with 503, before the body is spilled or any dial happens.
        match client.send(streamed_put(&uri, vec![b"layer"])).await {
            Err(UpstreamError::BufferingOverloaded) => {}
            Ok(_) => panic!("a saturated buffering path must 503, not forward"),
            Err(e) => panic!("expected BufferingOverloaded, got {e:?}"),
        }

        // Free the slot; the next buffering request is admitted and forwarded (the capture upstream
        // accepts exactly this one connection and answers 201).
        drop(held);
        assert_eq!(sem.available_permits(), 1, "the freed slot is back");
        let resp = client
            .send(streamed_put(&uri, vec![b"layer-", b"payload"]))
            .await
            .expect("an admitted buffering request forwards");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let _ = axum::body::to_bytes(Body::from_stream(resp.into_body()), 1 << 20)
            .await
            .unwrap();
        // The permit was released after the forward completed — the slot is free again.
        assert_eq!(
            sem.available_permits(),
            1,
            "the buffering permit is released on the success path"
        );
    }

    /// The buffering permit is released on EVERY abort path — `413` (over-cap), `408` (read-idle),
    /// and the success path — so a slot is never leaked. After each, the single-slot semaphore is
    /// back to one permit and the slot is reusable (a held permit then forces the next request to
    /// `503`, proving the count is genuinely restored).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gateway_buffering_permit_released_on_every_abort_path() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        // One bound upstream; the 413/408 abort paths never dial it, so the one-accept limit is fine.
        let (addr, _rx) = capture_upstream(OK).await;
        let sem = Arc::new(tokio::sync::Semaphore::new(1));

        // --- 413 over-cap: aborts BEFORE dial; the permit drops on the early return ---
        let over_cap = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            .with_buffering(true, Some(8), None, None, None, None) // 8-byte cap
            .with_buffer_slots(sem.clone());
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/big",
            addr.port()
        );
        match over_cap
            .send(streamed_put(&uri, vec![b"aaaaa", b"bbbbb", b"ccccc"]))
            .await
        {
            Err(UpstreamError::PayloadTooLarge) => {}
            Ok(_) => panic!("an over-cap buffered body must 413, not forward"),
            Err(e) => panic!("expected PayloadTooLarge, got {e:?}"),
        }
        assert_eq!(
            sem.available_permits(),
            1,
            "the permit is released on the 413 over-cap abort path"
        );

        // --- 408 read-idle: a stalled body aborts; the permit drops on the early return ---
        let stalls = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            // 60ms read-idle; floor off + ceiling default — isolate the read-idle abort.
            .with_buffering(
                true,
                Some(16 * 1024 * 1024),
                Some(60),
                Some(0),
                None,
                Some(0),
            )
            .with_buffer_slots(sem.clone());
        let stalled_body = futures::stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"trickle-start"))
        })
        .chain(futures::stream::pending::<Result<Bytes, std::io::Error>>());
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .body(Body::from_stream(stalled_body))
            .unwrap();
        match stalls.send(req).await {
            Err(UpstreamError::RequestBodyTimeout) => {}
            Ok(_) => panic!("a stalled buffered body must 408, not forward"),
            Err(e) => panic!("expected RequestBodyTimeout, got {e:?}"),
        }
        assert_eq!(
            sem.available_permits(),
            1,
            "the permit is released on the 408 read-idle abort path"
        );

        // --- reusable: the restored permit really is a working slot. Hold it, and the next buffering
        // request must 503 (saturated); release it and the count returns. ---
        let held = sem.clone().try_acquire_owned().expect("the restored slot");
        let saturated = cached_client("127.0.0.1", addr, None, None, false, None, false)
            .unwrap()
            .with_buffering(true, Some(16 * 1024 * 1024), None, None, None, None)
            .with_buffer_slots(sem.clone());
        match saturated.send(streamed_put(&uri, vec![b"x"])).await {
            Err(UpstreamError::BufferingOverloaded) => {}
            Ok(_) => panic!("a saturated buffering path must 503 once the slot is held"),
            Err(e) => panic!("expected BufferingOverloaded once the slot is held, got {e:?}"),
        }
        drop(held);
        assert_eq!(
            sem.available_permits(),
            1,
            "the slot frees again after release"
        );
    }

    // --- interim 1xx / Expect double-negotiation (response-desync class) -------------------

    /// PRIMARY fix: the gateway terminates the downstream `Expect: 100-continue` handshake
    /// itself, so the forwarded upstream request must NOT carry `Expect` — otherwise a
    /// spec-compliant upstream emits its own interim `100 Continue` that the single-shot
    /// native client would read as the final response. The forwarded head must have no
    /// `Expect` (and must still preserve the explicit `Content-Length: 0`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_strips_expect_before_forwarding() {
        const OK: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, rx) = capture_upstream(OK).await;
        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let uri = format!(
            "http://127.0.0.1:{}/v2/team/repo/blobs/uploads/u3",
            addr.port()
        );

        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .header(header::EXPECT, "100-continue")
            .header(header::CONTENT_LENGTH, 0)
            .body(Body::empty())
            .unwrap();
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let (head, _body) = rx.await.unwrap();
        let lower = head.to_ascii_lowercase();
        assert!(
            !lower.contains("expect"),
            "the forwarded request must not carry Expect (the gateway owns the 100-continue handshake); got head:\n{head}"
        );
        assert!(
            lower.contains("content-length: 0"),
            "the zero-length PUT must still preserve Content-Length: 0; got head:\n{head}"
        );
    }

    /// Reproduce-first (response-desync, defense-in-depth): an upstream that emits an interim
    /// `100 Continue` before the real response (Go/nginx/Gitea do, and `103 Early Hints` is
    /// unsolicited) must not corrupt the native client. `read_response_head` must SKIP the
    /// interim and return the real response, keeping the pooled connection byte-aligned so the
    /// NEXT request reused on that SAME keep-alive connection gets ITS own response — not a
    /// desynced one. The stub accepts exactly ONE connection and serves both requests on it,
    /// so request #2 succeeding proves the connection was reused clean (no fresh dial, no
    /// desync). Without the 1xx-skip the client returns the `100` as request #1's response and
    /// this fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_client_skips_interim_1xx_and_reuses_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = raw.local_addr().unwrap();
        tokio::spawn(async move {
            // Exactly ONE connection is ever accepted: request #2 must reuse it.
            let Ok((mut sock, _)) = raw.accept().await else {
                return;
            };
            let _ = sock.set_nodelay(true);
            // Read one request head (CRLFCRLF), discarding it.
            async fn read_head(sock: &mut tokio::net::TcpStream) -> bool {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        return true;
                    }
                    let mut tmp = [0u8; 1024];
                    match sock.read(&mut tmp).await {
                        Ok(0) => return false,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => return false,
                    }
                }
            }
            // Request #1: an interim 100, THEN the real keep-alive 201 (so the connection pools).
            if !read_head(&mut sock).await {
                return;
            }
            let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            let _ = sock
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nfirst")
                .await;
            let _ = sock.flush().await;
            // Request #2 on the SAME connection: a distinct response (then close).
            if !read_head(&mut sock).await {
                return;
            }
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
                )
                .await;
            let _ = sock.flush().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = cached_client("127.0.0.1", addr, None, None, false, None, false).unwrap();
        let base = format!("http://127.0.0.1:{}", addr.port());

        // Request #1 — the interim 100 must be skipped; the real 201/"first" is the response.
        let req1 = Request::builder()
            .method(Method::GET)
            .uri(format!("{base}/one"))
            .body(Body::empty())
            .unwrap();
        let resp1 = client.send(req1).await.unwrap();
        assert_eq!(
            resp1.status(),
            StatusCode::CREATED,
            "the interim 100 Continue leaked out as the response instead of the real 201"
        );
        let body1 = axum::body::to_bytes(Body::from_stream(resp1.into_body()), 1 << 20)
            .await
            .unwrap();
        assert_eq!(body1.as_ref(), b"first");

        // Request #2 — reuses the (clean) pooled connection; must get ITS own response.
        let req2 = Request::builder()
            .method(Method::GET)
            .uri(format!("{base}/two"))
            .body(Body::empty())
            .unwrap();
        let resp2 = client.send(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = axum::body::to_bytes(Body::from_stream(resp2.into_body()), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            body2.as_ref(),
            b"second",
            "request #2 got a desynced response — the pooled connection was left misaligned by the interim 1xx"
        );
    }
}
