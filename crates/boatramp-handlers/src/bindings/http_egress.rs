//! The host-mediated **HTTP-request-to-a-runtime-host** binding (`boatramp:handlers/http-egress`,
//! BR-REQ-3): the ERGONOMIC sibling of `tcp-egress`'s `connect-tls` runtime-host path (BR-REQ-2).
//! `connect-tls` hands the guest a RAW TLS byte stream, so an HTTP call (an OIDC token POST, a JWKS
//! GET to a per-tenant issuer) means the guest hand-rolls HTTP/1.1. This verb lets the guest name a
//! host + a request (method, path, headers, body) and the HOST owns the HTTP framing — one request,
//! one buffered response — so every guest, in any language, gets outbound HTTP for free.
//!
//! # Security model — reused, not forked ([[consolidate-duplicates-dont-parallelize]])
//! The dial reuses the EXACT SAME gate the gated `wasi:sockets` outbound-TCP capability and
//! `tcp-egress`'s `connect-tls` runtime-host path drive: [`crate::engine::resolve_and_gate_tcp_egress`]
//! runs the SAME `allow_guest_tcp_egress`/`allow_guest_dynamic_egress` posture, the per-component
//! `dynamic_egress_hosts` name allowlist, the `is_global_ip` SSRF floor on EVERY resolved candidate,
//! and the one-shot resolve-then-pin DNS-rebind choke. TLS is terminated STRICT with the SAME verifying
//! rustls `ClientConfig` ([`crate::engine::guest_egress_client_config`]: webpki ⊕ the operator's
//! `extra_roots`, an explicit `aws-lc-rs` provider, full certificate verification) a guest's own
//! `wasi:http`/`connect-tls` egress uses. The capability REUSES the `wasi:sockets` grant (see
//! `boatramp`'s `capability_token`) — no new grant kind, no new posture knob, no new allowlist: one
//! operator config authorizes BOTH the raw `connect-tls` dial and this HTTP verb.
//!
//! # HTTPS-only + bounded
//! There is no cleartext verb: the host always terminates TLS strict (the runtime-host path is HTTPS
//! only, exactly like `connect-tls` — `connect-plaintext` never consults the dynamic allowlist). The
//! host supplies the framing headers (`host`, `connection: close`, `content-length`) and refuses a
//! guest-supplied copy of them. The response read is bounded by a per-call timeout AND a byte cap
//! ([`HttpEgressHost::max_response_bytes`]) so a hostile runtime host can neither hang nor OOM the
//! host. Redirects are NOT followed — a 3xx is returned as-is; a guest re-calls for the new host,
//! which is itself re-gated — so the host never auto-follows a redirect to an un-gated host.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;

use crate::engine::{
    TcpEgressResolveError, guest_egress_client_config, resolve_and_gate_tcp_egress,
};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/http-egress-host",
        imports: { default: async },
    });
}

use generated::boatramp::handlers::{http_egress, http_egress_types};
pub use http_egress_types::{Header, HttpError, Request, Response};

/// Hard cap on the fully-buffered response size (status line + headers + body) a single
/// `emit-http-dynamic` call will accept before refusing with `response-too-large`. A runtime-host
/// response in the BR-REQ-3 use cases (an OIDC token JSON, a JWKS document) is a few KB; 8 MiB is a
/// generous ceiling that still bounds a hostile host's ability to drive the host to OOM. The engine
/// passes this into every per-invocation [`HttpEgressHost`]; a test overrides it to a tiny value to
/// exercise the cap cheaply.
pub(crate) const DEFAULT_MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// EXPLICIT bound on the number of RESPONSE headers the host will parse (Security review N1): a
/// hostile response head cannot OOM/hang the host because the host — not an implicit hyper default —
/// sets this. Set on the `conn::http1` client builder via `max_headers`; an oversized header COUNT
/// yields hyper's `Parse::TooLarge`, which this binding maps to `response-too-large`. The value
/// matches hyper 1.10.1's own default (100) so legitimate IdP/JWKS responses are unaffected, but it is
/// now boatramp-set + gate-asserted + pinned against a hyper default change (a future bump can't
/// silently widen it). A JWKS / OIDC token / discovery response carries a handful of headers.
pub(crate) const MAX_HTTP_RESPONSE_HEADERS: usize = 100;

/// EXPLICIT bound on the RESPONSE HEAD buffer (status line + all header bytes) the host will buffer
/// while parsing (Security review N1) — the companion to [`MAX_HTTP_RESPONSE_HEADERS`] that bounds a
/// SINGLE oversized header LINE (or an oversized head overall), not just the header count. Set on the
/// `conn::http1` client builder via `max_buf_size`; an oversized head yields hyper's `Parse::TooLarge`
/// → `response-too-large`. The value matches hyper 1.10.1's own default (`8192 + 4096 * 100` ≈ 408
/// KiB — hyper's `DEFAULT_MAX_BUFFER_SIZE`) so nothing legitimate regresses, but it is now boatramp-set
/// rather than inherited silently. hyper's floor for this knob is 8192; this is well above it.
pub(crate) const MAX_HTTP_HEAD_BYTES: usize = 8192 + 4096 * 100;

/// Fixed, non-verbose reason strings (Security review L1 parity with `tcp-egress`): a raw
/// `io::Error`/rustls `Display`/hyper error (which can echo OS-specific detail, or an internal
/// address/port resolved from a domain allowlist entry) never reaches the guest.
const REASON_CONNECT_FAILED: &str = "connect failed";
const REASON_TLS_CONFIG: &str = "tls configuration error";
const REASON_INVALID_SNI: &str = "invalid sni";
const REASON_TLS_HANDSHAKE: &str = "tls handshake failed";
const REASON_BAD_RESPONSE: &str = "malformed response";
const REASON_CONNECTION_DROPPED: &str = "connection dropped";
const REASON_INTERNAL: &str = "internal error";

/// Request headers the HOST owns and sets itself (framing / hop-by-hop). A guest-supplied copy of any
/// of these is DROPPED — never forwarded — so the guest cannot smuggle a conflicting `content-length`
/// (request smuggling), re-point the `host` virtual-host target away from the gated authority, or keep
/// the connection alive past the single buffered response. Lower-cased for case-insensitive matching.
const HOST_OWNED_HEADERS: [&str; 4] = ["host", "connection", "content-length", "transfer-encoding"];

/// Per-invocation view of the `http-egress` capability (BR-REQ-3): the SAME gate inputs the
/// `TcpEgressHost` carries (posture / dynamic-posture / SSRF-private / static + dynamic allowlists /
/// trust roots / connect timeout), plus the response read timeout and byte cap this HTTP verb adds.
/// The engine copies these from itself and from this invocation's `Bindings` at `new_store` time (see
/// `HandlerEngine::build_linker`). Carries NO resource table — the response is a plain record, not a
/// `wasi:io` resource.
pub struct HttpEgressHost {
    /// The node posture's `allow_guest_tcp_egress` (the static IP-allowlist leg). Reused verbatim —
    /// the gate admits a candidate via EITHER the static IP path OR the dynamic name path, so a host
    /// statically allowlisted at `IP:port` is reachable over this verb too (identical to `connect-tls`).
    enabled: bool,
    /// The node posture's `allow_guest_dynamic_egress` (BR-REQ-2): gates the runtime-resolved-host
    /// request against `dynamic_hosts`. INDEPENDENT of `enabled`.
    dynamic_enabled: bool,
    allow_private: bool,
    allowlist: Arc<[String]>,
    /// The per-component `dynamic_egress_hosts` allowlist (BR-REQ-2): `host-glob:port` entries whose
    /// NAME a guest-supplied host is matched against (resolve-then-SSRF-floor still applies). Empty ⇒
    /// the runtime-host path is deny-all. Host-authoritative — never guest-supplied.
    dynamic_hosts: Arc<[String]>,
    extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    /// Bounds DNS resolve + gate + TCP connect + TLS handshake (mirrors `tcp-egress`'s per-dial
    /// connect timeout).
    connect_timeout: Duration,
    /// Bounds the request send + the full (capped) response read, so a slowloris upstream cannot ride
    /// the whole invocation budget.
    response_timeout: Duration,
    /// Cap on the fully-buffered response size — see [`DEFAULT_MAX_HTTP_RESPONSE_BYTES`].
    max_response_bytes: usize,
}

impl HttpEgressHost {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        enabled: bool,
        allow_private: bool,
        allowlist: Arc<[String]>,
        extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
        connect_timeout: Duration,
        response_timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            enabled,
            // Deny-by-default (BR-REQ-2): the runtime-resolved-host path is off + empty until
            // `with_dynamic` opts it in.
            dynamic_enabled: false,
            dynamic_hosts: Arc::from(Vec::new()),
            allow_private,
            allowlist,
            extra_roots,
            connect_timeout,
            response_timeout,
            max_response_bytes,
        }
    }

    /// Layer the BR-REQ-2 dynamic (runtime-resolved-host) egress config onto this host: the posture
    /// (`allow_guest_dynamic_egress`) + the per-component `dynamic_egress_hosts` allowlist. Off +
    /// empty (the `new` default) ⇒ the runtime-host path stays deny-all.
    #[must_use]
    pub fn with_dynamic(mut self, enabled: bool, hosts: Arc<[String]>) -> Self {
        self.dynamic_enabled = enabled;
        self.dynamic_hosts = hosts;
        self
    }
}

/// The host-internal, already-validated outbound request: method/path/headers/body distilled from the
/// guest `request` record, with the host-owned framing headers stripped. Built BEFORE the gate so a
/// malformed request fails fast without consuming any egress budget.
struct PreparedRequest {
    method: http::Method,
    /// Origin-form request target (`/path?query`), host-supplied scheme/authority.
    target: http::uri::PathAndQuery,
    headers: http::HeaderMap,
    body: Bytes,
}

impl http_egress::Host for HttpEgressHost {
    async fn emit_http_dynamic(
        &mut self,
        host: String,
        port: u16,
        request: Request,
    ) -> Result<Response, HttpError> {
        let port = if port == 0 { 443 } else { port };
        // (1) Validate + distil the guest request (invalid-request on a bad method/header/path) —
        // before any gate or connect.
        let prepared = prepare_request(request)?;

        // (2) Resolve + gate under the connect timeout. The WHOLE resolve + gate + connect + TLS
        // handshake runs under ONE `connect_timeout`, then the send + capped response read under the
        // `response_timeout` — the same bounded discipline the `tcp-egress` dial uses.
        let dialed = tokio::time::timeout(self.connect_timeout, self.gate_and_connect(&host, port))
            .await
            .map_err(|_| HttpError::Timeout)
            .and_then(|r| r)?;

        // (3) Send + read the bounded response under the response timeout.
        let host_header = host_header_value(&host, port);
        let max = response_cap(self.max_response_bytes);
        tokio::time::timeout(
            self.response_timeout,
            round_trip(dialed, prepared, host_header, max),
        )
        .await
        .map_err(|_| HttpError::Timeout)
        .and_then(|r| r)
    }
}

impl HttpEgressHost {
    /// Resolve `host`, run the SHARED egress gate (posture + static/dynamic allowlist + SSRF floor +
    /// one-shot DNS-rebind pin), connect to a checked+pinned address, and terminate TLS strict —
    /// returning the TLS-wrapped stream ready for HTTP/1 framing. No timeout of its own; the caller
    /// wraps it in the single `connect_timeout`.
    async fn gate_and_connect(&self, host: &str, port: u16) -> Result<Dialed, HttpError> {
        // The IDENTICAL call `connect-tls` makes — EITHER the static IP path OR the dynamic name path
        // admits; both are connect-only + SSRF-floored by the same `is_global_ip`. Fail-closed.
        let checked = resolve_and_gate_tcp_egress(
            host,
            port,
            &self.allowlist,
            self.allow_private,
            self.enabled,
            &self.dynamic_hosts,
            self.dynamic_enabled,
        )
        .await
        .map_err(|e| match e {
            TcpEgressResolveError::DnsFailure => HttpError::DnsFailure,
            TcpEgressResolveError::RefusedByGate => HttpError::RefusedByGate,
        })?;
        // Cap the gate-checked candidate fan-out this call ATTEMPTS (parity with `tcp-egress`'s
        // `MAX_DIAL_CANDIDATES`), so a many-homed / broad target can't multiply TCP SYNs unboundedly.
        let candidates = &checked[..checked.len().min(MAX_DIAL_CANDIDATES)];
        let tcp = connect_checked(candidates).await?;

        // ANTI-HOLLOW MUTATION SEAM (`tcpegress-gate-mutation` / cfg(test) only — NEVER a shipped
        // build): `skip_tls_wrap` hands back the RAW TCP stream with NO TLS handshake, so the CI gate
        // can prove a REAL HTTPS round trip goes RED when the TLS wrap is skipped. Not a backdoor — it
        // only reads a test env var behind a never-shipped cargo feature.
        if httpegress_mutation().as_deref() == Some("skip_tls_wrap") {
            #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
            return Ok(Dialed::RawMutation(tcp));
        }

        let tls = handshake_tls(tcp, host, &self.extra_roots).await?;
        Ok(Dialed::Tls(Box::new(tls)))
    }
}

/// Cap how many gate-checked candidate addresses one call ATTEMPTS — mirrors `tcp-egress`'s
/// `MAX_DIAL_CANDIDATES` (Security review M1).
const MAX_DIAL_CANDIDATES: usize = 8;

/// The effective response byte cap, with the `skip_response_cap` anti-hollow mutation lifting it to
/// unbounded so the CI gate can prove the cap is load-bearing (an oversized response is returned OK
/// under the mutation instead of refused — the gate test's `response-too-large` assertion flips RED).
fn response_cap(configured: usize) -> usize {
    if httpegress_mutation().as_deref() == Some("skip_response_cap") {
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        return usize::MAX;
    }
    configured
}

/// The effective RESPONSE-HEADER COUNT cap (N1), with the `skip_head_bound` anti-hollow mutation
/// RAISING it (not to `usize::MAX` — hyper reserves a header buffer sized by this, so an unbounded
/// value would itself OOM; a large-but-safe 100_000 is enough to admit the gate's oversized-head mock)
/// so the CI gate can prove the EXPLICIT `max_headers` bound is load-bearing: with the bound lifted,
/// the oversized-header response is accepted and the gate's "must error" assertion flips RED.
fn head_header_cap() -> usize {
    if httpegress_mutation().as_deref() == Some("skip_head_bound") {
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        return 100_000;
    }
    MAX_HTTP_RESPONSE_HEADERS
}

/// The effective RESPONSE-HEAD BUFFER cap (N1), raised by the SAME `skip_head_bound` mutation so an
/// oversized single header LINE is also accepted under the mutation — the companion to
/// [`head_header_cap`] for the head-byte bound (`max_buf_size`).
fn head_buf_cap() -> usize {
    if httpegress_mutation().as_deref() == Some("skip_head_bound") {
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        return 64 * 1024 * 1024;
    }
    MAX_HTTP_HEAD_BYTES
}

/// A host-dialed, (normally) TLS-terminated outbound connection ready for HTTP/1 framing.
enum Dialed {
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
    RawMutation(tokio::net::TcpStream),
}

/// Validate the guest request and distil it into a [`PreparedRequest`], stripping the host-owned
/// framing headers. `invalid-request` on a bad method token, a non-representable header name/value, or
/// a bad path.
fn prepare_request(request: Request) -> Result<PreparedRequest, HttpError> {
    let method = http::Method::from_bytes(request.method.as_bytes())
        .map_err(|_| HttpError::InvalidRequest("invalid method".to_string()))?;

    // Origin-form target. An empty path is sent as `/`.
    let raw_target = if request.path.is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    let target = http::uri::PathAndQuery::try_from(raw_target)
        .map_err(|_| HttpError::InvalidRequest("invalid path".to_string()))?;

    let mut headers = http::HeaderMap::new();
    for Header { name, value } in request.headers {
        // Drop the host-owned framing headers (request-smuggling / virtual-host-retarget / keep-alive
        // defenses) — never forward a guest copy.
        if HOST_OWNED_HEADERS
            .iter()
            .any(|owned| name.eq_ignore_ascii_case(owned))
        {
            continue;
        }
        let hname = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpError::InvalidRequest("invalid header name".to_string()))?;
        let hval = http::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| HttpError::InvalidRequest("invalid header value".to_string()))?;
        headers.append(hname, hval);
    }

    Ok(PreparedRequest {
        method,
        target,
        headers,
        body: Bytes::from(request.body),
    })
}

/// The `Host` header value for the gated authority: bare host for the default HTTPS port, `host:port`
/// otherwise. The guest's own `host` header was already stripped — the host sets this itself so the
/// virtual-host target always matches the gated authority.
fn host_header_value(host: &str, port: u16) -> String {
    if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Connect to the first of the already-gate-CHECKED `addrs` to succeed. NEVER resolves any hostname
/// again (the DNS-rebind pin). Carries no timeout of its own — the caller's single connect timeout
/// bounds it.
async fn connect_checked(addrs: &[SocketAddr]) -> Result<tokio::net::TcpStream, HttpError> {
    for addr in addrs {
        if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
            return Ok(s);
        }
    }
    Err(HttpError::ConnectFailed(REASON_CONNECT_FAILED.to_string()))
}

/// Terminate TLS STRICT over the connected `tcp` — the ONLY mode this path honors. Reuses
/// [`guest_egress_client_config`] (webpki ⊕ operator `extra_roots`, full verification — the SAME
/// config a guest's own `wasi:http` egress gets), verifying the peer certificate against `sni`.
async fn handshake_tls(
    tcp: tokio::net::TcpStream,
    sni: &str,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, HttpError> {
    let tls_config = guest_egress_client_config(extra_roots)
        .map_err(|_| HttpError::TlsFailure(REASON_TLS_CONFIG.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| HttpError::TlsFailure(REASON_INVALID_SNI.to_string()))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|_| HttpError::TlsFailure(REASON_TLS_HANDSHAKE.to_string()))
}

/// Frame + send the request over the dialed connection and read the bounded response. Dispatches on
/// the TLS vs (mutation-only) raw stream so each branch stays a concrete `S` for the generic HTTP/1
/// driver (no trait-object boxing).
async fn round_trip(
    dialed: Dialed,
    prepared: PreparedRequest,
    host_header: String,
    max_response_bytes: usize,
) -> Result<Response, HttpError> {
    use wasmtime_wasi_http::io::TokioIo;
    match dialed {
        Dialed::Tls(tls) => {
            http1_round_trip(
                TokioIo::new(*tls),
                prepared,
                host_header,
                max_response_bytes,
            )
            .await
        }
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        Dialed::RawMutation(tcp) => {
            http1_round_trip(TokioIo::new(tcp), prepared, host_header, max_response_bytes).await
        }
    }
}

/// Map a hyper client error to the guest-visible `http-error`. A response-HEAD-too-large parse error
/// (too many headers past `max_headers`, or a head past `max_buf_size`) is surfaced as the semantic
/// `response-too-large` (the same outcome as an over-cap BODY), so a hostile head is refused with a
/// clear reason rather than an opaque transport error; anything else is the generic `other` with a
/// fixed, non-verbose reason (Security review L1 — never raw hyper/OS detail to the guest).
fn map_hyper_error(err: hyper::Error) -> HttpError {
    if err.is_parse_too_large() {
        HttpError::ResponseTooLarge
    } else {
        HttpError::Other(REASON_CONNECTION_DROPPED.to_string())
    }
}

/// The HTTP/1 client tail over an already-connected (TLS-terminated) stream: handshake, build the
/// origin-form request (host-set `Host` + `Connection: close`, guest method/path/headers/body), send,
/// and read the FULLY-BUFFERED response with a hard byte cap. `Connection: close` keeps it a single
/// request/response with no pooled keep-alive state.
async fn http1_round_trip<S>(
    io: S,
    prepared: PreparedRequest,
    host_header: String,
    max_response_bytes: usize,
) -> Result<Response, HttpError>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use http_body_util::{Full, Limited};

    // EXPLICIT response-head bounds (Security review N1): the "a hostile response head can't OOM/hang
    // the host" property is boatramp-SET here, not inherited from a hyper default — an oversized header
    // COUNT (`max_headers`) or an oversized head BYTE size (`max_buf_size`) yields hyper's
    // `Parse::TooLarge`, which this binding maps to `response-too-large`. Pinned against a hyper
    // default change; gate-asserted below. The bodies are separately capped by `Limited`.
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .max_headers(head_header_cap())
        .max_buf_size(head_buf_cap())
        .handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(map_hyper_error)?;
    // Drive the connection concurrently for the duration of this single request/response. The handle
    // aborts the driver task when it drops (at function return), so neither a completed round trip nor
    // an early error (e.g. the response-size cap firing) leaves the connection task running.
    let _conn_task = wasmtime_wasi::runtime::spawn(async move {
        let _ = conn.await;
    });

    // Build the request: origin-form target, host-owned framing headers, then the guest headers.
    let mut builder = http::Request::builder()
        .method(prepared.method)
        .uri(http::Uri::from(prepared.target));
    {
        let hmap = builder
            .headers_mut()
            .ok_or_else(|| HttpError::Other(REASON_INTERNAL.to_string()))?;
        hmap.insert(
            http::header::HOST,
            http::header::HeaderValue::from_str(&host_header)
                .map_err(|_| HttpError::InvalidRequest("invalid host".to_string()))?,
        );
        hmap.insert(
            http::header::CONNECTION,
            http::header::HeaderValue::from_static("close"),
        );
        for (name, value) in &prepared.headers {
            hmap.append(name.clone(), value.clone());
        }
    }
    let req = builder
        .body(Full::new(prepared.body))
        .map_err(|_| HttpError::InvalidRequest("invalid request".to_string()))?;

    // The response HEAD is parsed here; an oversized head (too many headers, or a head beyond the
    // buffer) surfaces as a hyper `Parse::TooLarge`, mapped to `response-too-large` by `map_hyper_error`.
    let resp = sender.send_request(req).await.map_err(map_hyper_error)?;

    let status = resp.status().as_u16();
    let headers: Vec<Header> = resp
        .headers()
        .iter()
        .map(|(name, value)| Header {
            name: name.as_str().to_string(),
            // A received header value is bytes; surface it as a lossless-where-possible string. Values
            // are overwhelmingly ASCII; non-UTF-8 bytes are lossily replaced (never raw-injected).
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect();

    // Read the body with a hard byte cap. `Limited` errors the moment the cap is exceeded, so the host
    // never buffers an unbounded (hostile) body — it refuses with `response-too-large`.
    let body = match Limited::new(resp.into_body(), max_response_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(err) => {
            // The overflow is a `http_body_util::LengthLimitError`; anything else is a transport error.
            if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                return Err(HttpError::ResponseTooLarge);
            }
            return Err(HttpError::Other(REASON_BAD_RESPONSE.to_string()));
        }
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// The active `http-egress` anti-hollow gate mutation (BR-REQ-3), or `None`. Present ONLY under
/// `cfg(test)` (this crate's own gate) or the `tcpegress-gate-mutation` feature (the SAME lane the
/// `tcp-egress` gate mutations use); a shipped build has NEITHER, so the TLS wrap + the response cap
/// below are unconditional and this is a dead `None`. Recognized values: `skip_tls_wrap` (hand back
/// the raw TCP stream, so a REAL HTTPS round trip goes RED), `skip_response_cap` (lift the body byte
/// cap, so the oversized-BODY refusal goes RED), and `skip_head_bound` (raise the explicit
/// `max_headers`/`max_buf_size` response-HEAD bounds (N1), so the oversized-HEAD refusal goes RED).
/// The SHARED gate checks (posture / allowlist / SSRF) are proven RED by the EXISTING
/// `BOATRAMP_TCPEGRESS_MUTATION` seam in `engine::resolve_and_gate_tcp_egress`, which this verb drives
/// verbatim. NOT a backdoor — it only reads a test env var.
#[cfg(any(test, feature = "tcpegress-gate-mutation"))]
fn httpegress_mutation() -> Option<String> {
    std::env::var("BOATRAMP_HTTPEGRESS_MUTATION").ok()
}
#[cfg(not(any(test, feature = "tcpegress-gate-mutation")))]
#[inline]
fn httpegress_mutation() -> Option<String> {
    None
}

/// Add the `http-egress` interface to `linker`, resolving the per-invocation [`HttpEgressHost`] view
/// via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = HttpEgressHost;
}

pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> HttpEgressHost,
) -> wasmtime::Result<()> {
    http_egress::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::http_egress::Host as _;
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// Mint a throwaway CA + a `localhost` leaf signed by it (mirrors `tcp_egress`'s `ca_and_leaf`).
    fn ca_and_leaf() -> (
        CertificateDer<'static>,
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
    ) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let ca_der = ca_cert.der().clone();
        let chain = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (ca_der, chain, key)
    }

    fn server_tls_config(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> rustls::ServerConfig {
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap()
    }

    /// A one-shot loopback rustls TLS server that speaks a canned HTTP/1.1 response. Accepts one
    /// connection, completes the TLS handshake, reads the request head (through the blank line), then
    /// writes `response_bytes` and closes. Returns its bound port.
    async fn spawn_tls_http_server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        response_bytes: Vec<u8>,
    ) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls_config(chain, key)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(tcp).await
            {
                // Read the request head up to the CRLFCRLF (good enough for a test; the request has no
                // body of interest to the mock).
                let mut buf = [0u8; 2048];
                let mut seen = Vec::new();
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            seen.extend_from_slice(&buf[..n]);
                            if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tls.write_all(&response_bytes).await;
                let _ = tls.shutdown().await;
            }
        });
        port
    }

    /// A 200 response carrying a known header + body, framed `Connection: close` (read-to-close).
    fn ok_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nx-mock: hello\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    /// A 200 response whose HEAD carries `count` distinct headers — used to exceed the explicit
    /// `max_headers` bound (N1). With `count` beyond the host's `MAX_HTTP_RESPONSE_HEADERS` the host's
    /// head parse must refuse (hyper `Parse::TooLarge` → `response-too-large`) rather than OOM/hang.
    fn many_header_response(count: usize) -> Vec<u8> {
        let mut head =
            String::from("HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 2\r\n");
        for i in 0..count {
            head.push_str(&format!("x-pad-{i}: v\r\n"));
        }
        head.push_str("\r\nok");
        head.into_bytes()
    }

    /// Build an `HttpEgressHost` with an EMPTY static IP allowlist (the tests exercise the DYNAMIC
    /// runtime-host path only), the given dynamic allowlist + postures + SSRF-private flag + trust
    /// roots + response byte cap. Generous timeouts so only the gate / cap / TLS decides the outcome.
    fn host_with(
        dynamic_hosts: Vec<String>,
        posture: bool,
        dynamic_posture: bool,
        allow_private: bool,
        extra_roots: Vec<CertificateDer<'static>>,
        max_response_bytes: usize,
    ) -> HttpEgressHost {
        HttpEgressHost::new(
            posture,
            allow_private,
            Arc::from(Vec::new()),
            Arc::from(extra_roots),
            Duration::from_secs(5),
            Duration::from_secs(5),
            max_response_bytes,
        )
        .with_dynamic(dynamic_posture, Arc::from(dynamic_hosts))
    }

    fn simple_get() -> Request {
        Request {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![],
            body: vec![],
        }
    }

    /// A REAL end-to-end round trip over loopback TLS: the host dials `localhost`, terminates TLS
    /// strict against the throwaway CA, sends the request, and returns the mock's parsed status +
    /// headers + body. `allow_private` is on (loopback would otherwise be SSRF-floored).
    #[tokio::test]
    async fn emit_http_dynamic_real_round_trip_returns_response() {
        let (ca, chain, key) = ca_and_leaf();
        let port = spawn_tls_http_server(chain, key, ok_response("world")).await;
        let mut host = host_with(
            vec![format!("localhost:{port}")],
            false, // static posture off — proves the DYNAMIC path alone admits
            true,
            true,
            vec![ca],
            DEFAULT_MAX_HTTP_RESPONSE_BYTES,
        );
        let resp = host
            .emit_http_dynamic("localhost".to_string(), port, simple_get())
            .await
            .expect("allowlisted runtime host must round-trip");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"world".to_vec());
        assert!(
            resp.headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("x-mock") && h.value == "hello"),
            "the mock's response header must come back"
        );
    }

    /// The CI-hard, mutation-verified gate. Drives the REAL `emit-http-dynamic` host path (not a unit
    /// shim of the gate) across every security dimension and prints `HTTP-EGRESS DYNAMIC GATE OK`.
    /// MUTATION-VERIFIED:
    ///   * `BOATRAMP_TCPEGRESS_MUTATION=admit_unallowlisted_dynamic` flips the non-allowlisted deny (B);
    ///   * `BOATRAMP_TCPEGRESS_MUTATION=drop_dynamic_posture` flips the posture-off deny (C);
    ///   * `BOATRAMP_HTTPEGRESS_MUTATION=skip_tls_wrap` fails the real round trip — HTTPS is load-bearing (A);
    ///   * `BOATRAMP_HTTPEGRESS_MUTATION=skip_response_cap` flips the oversized-response refusal (E).
    /// A pass under any of these mutations = a hollow gate. Each call that actually connects gets its
    /// OWN freshly-spawned one-shot server; the gate-refused dimensions (B/C/D) never connect.
    #[tokio::test]
    async fn http_egress_dynamic_gate() {
        let body = "world";

        // (A) allowlisted runtime host → the response returns (REAL loopback-TLS round trip). The
        // static posture is OFF (`false`) throughout — the DYNAMIC path alone admits. `skip_tls_wrap`
        // breaks this (plaintext bytes to a TLS peer ⇒ no 200).
        let (ca, chain, key) = ca_and_leaf();
        let port = spawn_tls_http_server(chain, key, ok_response(body)).await;
        let mut ok = host_with(
            vec![format!("localhost:{port}")],
            false,
            true,
            true,
            vec![ca],
            DEFAULT_MAX_HTTP_RESPONSE_BYTES,
        );
        let resp = ok
            .emit_http_dynamic("localhost".to_string(), port, simple_get())
            .await
            .expect("allowlisted host must round-trip");
        assert_eq!(resp.status, 200, "allowlisted host returns the response");
        assert_eq!(resp.body, body.as_bytes().to_vec());

        // (B) NON-allowlisted runtime host → refused-by-gate before any connect (allow_private on, so
        // ONLY the name-allowlist can deny). `admit_unallowlisted_dynamic` flips this.
        let mut not_allow = host_with(
            vec!["other.example:443".to_string()],
            false,
            true,
            true,
            vec![],
            DEFAULT_MAX_HTTP_RESPONSE_BYTES,
        );
        assert!(
            matches!(
                not_allow
                    .emit_http_dynamic("localhost".to_string(), 443, simple_get())
                    .await,
                Err(HttpError::RefusedByGate)
            ),
            "a non-allowlisted runtime host must be refused by the gate"
        );

        // (C) dynamic posture OFF → deny-all even for a name-matched host (allow_private on, so ONLY
        // the posture can deny). `drop_dynamic_posture` flips this.
        let mut no_posture = host_with(
            vec!["localhost:443".to_string()],
            false,
            false,
            true,
            vec![],
            DEFAULT_MAX_HTTP_RESPONSE_BYTES,
        );
        assert!(
            matches!(
                no_posture
                    .emit_http_dynamic("localhost".to_string(), 443, simple_get())
                    .await,
                Err(HttpError::RefusedByGate)
            ),
            "dynamic posture off must deny-all (fail-closed)"
        );

        // (D) SSRF floor: a name-allowlisted but NON-global peer (loopback here, standing in for a
        // metadata/private IdP host) with allow_private OFF → refused-by-gate before any connect. The
        // `is_global_ip` floor is mutation-proven by its own tests; here it must still bite.
        let mut ssrf = host_with(
            vec!["localhost:443".to_string()],
            false,
            true,
            false,
            vec![],
            DEFAULT_MAX_HTTP_RESPONSE_BYTES,
        );
        assert!(
            matches!(
                ssrf.emit_http_dynamic("localhost".to_string(), 443, simple_get())
                    .await,
                Err(HttpError::RefusedByGate)
            ),
            "a name-allowlisted but non-global host must still be refused by the SSRF floor"
        );

        // (E) oversized response → response-too-large (a tiny 2-byte cap; the mock's 5-byte body
        // exceeds it). Fresh server. `skip_response_cap` flips this to an Ok.
        let (ca2, chain2, key2) = ca_and_leaf();
        let port2 = spawn_tls_http_server(chain2, key2, ok_response(body)).await;
        let mut capped = host_with(
            vec![format!("localhost:{port2}")],
            false,
            true,
            true,
            vec![ca2],
            2,
        );
        assert!(
            matches!(
                capped
                    .emit_http_dynamic("localhost".to_string(), port2, simple_get())
                    .await,
                Err(HttpError::ResponseTooLarge)
            ),
            "a response over the byte cap must be refused, never truncated-and-returned"
        );

        // (F) oversized response HEAD (N1): a response with more headers than the explicit
        // `MAX_HTTP_RESPONSE_HEADERS` bound must be refused (hyper `Parse::TooLarge` →
        // `response-too-large`) — NOT a hang, NOT OOM, NOT a success. Fresh server; the mock emits
        // 100_000 - 1 fewer than the mutation cap (so the mutation admits it) but well over the 100
        // real cap. `skip_head_bound` flips this to an Ok (proving the explicit `max_headers` is
        // load-bearing, not an implicit hyper default).
        let (ca3, chain3, key3) = ca_and_leaf();
        let head_port = spawn_tls_http_server(chain3, key3, many_header_response(500)).await;
        let mut head_host = host_with(
            vec![format!("localhost:{head_port}")],
            false,
            true,
            true,
            vec![ca3],
            DEFAULT_MAX_HTTP_RESPONSE_BYTES,
        );
        assert!(
            matches!(
                head_host
                    .emit_http_dynamic("localhost".to_string(), head_port, simple_get())
                    .await,
                Err(HttpError::ResponseTooLarge)
            ),
            "a response head with more headers than the explicit cap must be refused (no OOM/hang)"
        );

        println!("HTTP-EGRESS DYNAMIC GATE OK");
    }

    /// Host-owned framing headers supplied by the guest are DROPPED (request-smuggling / virtual-host
    /// retarget defense): a guest `content-length` / `host` / `connection` never reaches the wire.
    #[tokio::test]
    async fn host_owned_headers_are_stripped() {
        let prepared = prepare_request(Request {
            method: "POST".to_string(),
            path: "/x".to_string(),
            headers: vec![
                Header {
                    name: "Content-Length".to_string(),
                    value: "999".to_string(),
                },
                Header {
                    name: "Host".to_string(),
                    value: "evil.example".to_string(),
                },
                Header {
                    name: "Connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                Header {
                    name: "X-Keep".to_string(),
                    value: "yes".to_string(),
                },
            ],
            body: b"hi".to_vec(),
        })
        .expect("valid request");
        assert!(prepared.headers.get("content-length").is_none());
        assert!(prepared.headers.get("host").is_none());
        assert!(prepared.headers.get("connection").is_none());
        assert_eq!(
            prepared
                .headers
                .get("x-keep")
                .map(http::HeaderValue::as_bytes),
            Some(b"yes".as_slice()),
            "a non-framing guest header is kept"
        );
    }

    /// A bad method token / header value is `invalid-request`, before any gate or connect.
    #[tokio::test]
    async fn malformed_request_is_invalid_request() {
        assert!(matches!(
            prepare_request(Request {
                method: "BAD METHOD".to_string(),
                path: "/".to_string(),
                headers: vec![],
                body: vec![],
            }),
            Err(HttpError::InvalidRequest(_))
        ));
        assert!(matches!(
            prepare_request(Request {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![Header {
                    name: "x".to_string(),
                    value: "bad\nvalue".to_string()
                }],
                body: vec![],
            }),
            Err(HttpError::InvalidRequest(_))
        ));
    }
}
