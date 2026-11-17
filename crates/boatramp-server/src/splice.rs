//! Kernel `splice()` fast-path for plaintext HTTP/1.1 reverse-proxy responses.
//!
//! A reverse proxy that forwards a large response body normally pays for it
//! twice in userspace — one `read` from the upstream socket and one `writev` to
//! the client socket per chunk. When both legs are plaintext HTTP/1.1 and the
//! body is passed through unchanged, Linux `splice()` moves the body
//! **kernel-to-kernel** (socket → pipe → socket) with no userspace copy, the way
//! nginx/HAProxy do. Profiled on a 100 KB proxy cell this lifts throughput ~40 %.
//!
//! ## How it stays safe to run by default
//!
//! The fast-path must never change *what* is served — only *how* the bytes move.
//! So it wraps the plaintext listener and, for each new connection, **peeks**
//! (non-consuming) the first request and asks [`classify`] whether the normal
//! serving pipeline would proxy it to a single plaintext-HTTP gateway upstream.
//! `classify` reuses the *same* pure routing functions the pipeline uses
//! ([`route::resolve_ctx`], [`route::match_handler`], `gateway.match_route`) in
//! the same precedence, and returns a plan **only** when the answer is an
//! unambiguous gateway proxy. Anything else — redirects, handlers, SSE, static,
//! access rules, HTTPS-redirect, multi-backend/compute/HTTPS upstreams, non-GET,
//! request bodies — yields `None` and the connection is handed back to the
//! untouched serving stack (boatramp-http's `serve_connection`), byte-for-byte as
//! before. The peek is off the accept path (a spawned task), so a silent or slow
//! client can never stall the loop.
//!
//! Non-Linux targets compile the module but [`splice_body`] is unavailable, so
//! every connection classifies as fallback and behaviour is identical to before.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;

use axum::http::{self, HeaderMap, Method};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use boatramp_core::deploy::DeployStore;
use boatramp_core::gateway::Upstream;
use boatramp_core::route::{self, Outcome};
use boatramp_core::security::SecurityPosture;

use crate::proxy;

/// The largest request head we will peek before giving up and falling back — a
/// normal proxy request head is well under this.
const MAX_HEAD: usize = 16 * 1024;
/// Hop-by-hop request/response headers that must not be forwarded end to end.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Shared context the classifier needs: the store, the resolved security posture
/// (SSRF gate), and the live daemon runtime — read per request for the catch-all
/// `default_site` (host resolution parity) and the console mount (so a console
/// request is deferred to the router, not proxied).
#[derive(Clone)]
pub struct SpliceCtx {
    pub deploy: DeployStore,
    pub posture: SecurityPosture,
    pub daemon: Option<Arc<crate::DaemonRuntime>>,
    /// Idle read timeout for the splice fast-path's own socket reads once a connection is
    /// served: the per-request client head read on a kept-alive connection (N-1), every
    /// buffered upstream read via [`UpstreamConn::fill`] (N-5), and the upstream-readable
    /// wait inside the fixed-length (Content-Length) kernel-`splice()` zero-copy path
    /// ([`splice_body`] — the last N-5 sibling, so a trusted upstream that declares a
    /// Content-Length, delivers part, then stalls without closing is bounded too). Set to
    /// [`boatramp_http::h1::DEFAULT_READ_TIMEOUT`] so a slow-loris / stalled peer on the
    /// fast-path is bounded exactly like the normal [`boatramp_http::serve_connection`] path
    /// the fast-path bypasses. (Request #1's non-consuming peek is separately bounded by
    /// [`PEEK_TIMEOUT`].) It bounds only no-progress stalls — a transfer moving bytes is never
    /// affected (the splice idle timeout resets on each `splice()` that moves `> 0` bytes).
    pub read_timeout: std::time::Duration,
}

/// A resolved plan to splice one connection's requests: the pinned upstream and
/// the per-request rewrite inputs. Held for the life of the client connection.
struct SplicePlan {
    resolved: proxy::ResolvedTarget,
    upstream: Upstream,
    /// The site's gateway is keyed by route; kept to recompute `forward_path` per
    /// request (a keep-alive client may send different paths under the same route).
    site: String,
    project: String,
    /// The single plaintext-HTTP backend string this connection is pinned to. A
    /// subsequent keep-alive request is re-classified ([`SplicePlan::reverify`]) and is
    /// only served on this pinned upstream connection when it still resolves to *this*
    /// exact backend — otherwise the connection falls back to the userspace router.
    target: String,
}

/// How long to wait for a connection's first request head before giving up on the
/// fast-path and handing it to the normal server (which has its own timeouts).
const PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The plaintext serve loop: accept connections and, off the accept path, peek
/// each one's first request. Splice-eligible connections are handled by
/// [`splice_conn`]; every other connection is served by the normal axum `router`
/// through boatramp-http's `serve_connection` dispatcher. Returns when `shutdown`
/// resolves (in-flight connections are dropped by the caller's drain deadline).
pub async fn serve<S>(
    tcp: TcpListener,
    ctx: SpliceCtx,
    serve: impl Into<crate::ServeInput>,
    shutdown: S,
) -> io::Result<()>
where
    S: std::future::Future<Output = ()> + Send,
{
    let serve = serve.into();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = tcp.accept() => {
                let (mut io, peer) = match accepted {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::debug!(%err, "splice serve: accept error");
                        continue;
                    }
                };
                crate::disable_nagle(&mut io);
                let ctx = ctx.clone();
                let serve = serve.clone();
                // Classify off the accept path so a slow/silent client can't stall
                // the loop; a peek timeout bounds how long we hold before falling back.
                tokio::spawn(async move {
                    // On a slow head (timeout) fall back — the normal server has its
                    // own header-read timeout.
                    let eligible = tokio::time::timeout(PEEK_TIMEOUT, peek_classify(&io, &ctx))
                        .await
                        .unwrap_or_default();
                    match eligible {
                        Some(plan) => {
                            if let Err(err) = splice_conn(io, peer, plan, ctx, serve).await {
                                tracing::debug!(%peer, %err, "splice connection ended");
                            }
                        }
                        // The peek did not consume, so the fallback reads the full request.
                        None => serve_fallback(io, peer, serve).await,
                    }
                });
            }
        }
    }
}

/// A reader that replays a buffered prefix (bytes already read off the socket)
/// before yielding the underlying stream — so a request head consumed by the
/// splice loop can be handed intact to the fallback serve loop. Writes pass
/// straight through.
struct Rewind {
    pre: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl tokio::io::AsyncRead for Rewind {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.pre[start..start + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Rewind {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Serve one non-spliced connection with the normal axum `router` through the
/// unified [`boatramp_http`] dispatcher (h1, or h2c via the preface sniff) —
/// injecting the peer as `ConnectInfo<SocketAddr>` (which handlers read for IP
/// rules / rate limiting / access logs) and owning HTTP upgrades (WebSocket handler
/// routes). Generic over the IO so a [`Rewind`] (mid-connection fallback) serves
/// identically to a raw socket.
async fn serve_fallback<IO>(io: IO, peer: SocketAddr, serve: crate::ServeInput)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    crate::http_serve::serve_router_conn(io, peer, serve).await;
}

/// Replay `head` + `leftover` (already consumed off `client`) and serve the rest of
/// the connection with the normal `router` — used when a keep-alive connection
/// turns out to carry a non-spliceable request after one or more spliced responses,
/// so nothing (including a non-idempotent POST) is dropped.
async fn fall_back(
    head: Vec<u8>,
    leftover: Vec<u8>,
    client: TcpStream,
    peer: SocketAddr,
    serve: crate::ServeInput,
) -> io::Result<()> {
    let mut pre = head;
    pre.extend_from_slice(&leftover);
    let rewind = Rewind {
        pre,
        pos: 0,
        inner: client,
    };
    serve_fallback(rewind, peer, serve).await;
    Ok(())
}

/// Peek (non-consuming) the first request head and classify it. `Some` only when
/// the normal pipeline would proxy it to a single plaintext-HTTP gateway upstream.
async fn peek_classify(io: &TcpStream, ctx: &SpliceCtx) -> Option<SplicePlan> {
    let mut buf = vec![0u8; MAX_HEAD];
    loop {
        io.readable().await.ok()?;
        // Peek without consuming so a fallback connection still reads the full
        // request through the fallback serve loop.
        let n = match io.peek(&mut buf).await {
            Ok(0) => return None, // client closed
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return None,
        };
        if let Some(end) = find_head_end(&buf[..n]) {
            return classify(&buf[..end], ctx).await;
        }
        if n >= MAX_HEAD {
            return None; // oversized head → let axum handle it
        }
        // else: partial head, peek again once more data arrives
        tokio::task::yield_now().await;
    }
}

/// A fast-path-eligible request head, parsed by the **hardened** [`boatramp_http::h1`]
/// request parser (not an ad-hoc `str::split`). The parser rejects bare CR/LF
/// terminators, validates header-field names (tchar) and values (no CTL/DEL), resolves
/// the body framing per RFC 9112 §6, and refuses a `Content-Length`×`Transfer-Encoding`
/// conflict — so a smuggled header (`X: y\nTransfer-Encoding: chunked`) can never reach
/// [`build_upstream_head`] and be re-emitted to a lenient upstream (F-4).
struct FastReq {
    method: Method,
    /// Origin-form request target (path + query) to forward.
    target: String,
    /// The validated request headers (a [`HeaderMap`] — every value already proven free
    /// of embedded CR/LF, so re-emitting it verbatim cannot inject a header line).
    headers: HeaderMap,
}

/// Parse **and** gate a request head for the splice fast path with the hardened h1
/// parser. `Some` only for an idempotent, body-less `GET`/`HEAD` over HTTP/1.1 with no
/// `Upgrade`/`Expect` and no declared body framing. This is the full header-framing guard
/// and it is applied to **every** request — the first (via [`classify`]) *and* every
/// subsequent keep-alive request (via [`splice_conn`]) — closing the F-6 gap where a
/// split request #2 could carry a `Content-Length`/`Transfer-Encoding` the first-request
/// guard never re-checked.
fn parse_fastpath_request(head: &[u8]) -> Option<FastReq> {
    use boatramp_http::h1::{BodyFraming, ParseResult, parse_request_head};
    // Incomplete (truncated) or Reject (bare CR/LF, bad name/value, conflicting framing,
    // obs-fold, missing/duplicate Host, …) → never intercept; hand to the router.
    let ParseResult::Complete { head, .. } = parse_request_head(head) else {
        return None;
    };
    // HTTP/1.0 keep-alive semantics differ (default-close) — the old ad-hoc path fell
    // back on 1.0 and so do we.
    if head.version != http::Version::HTTP_11 {
        return None;
    }
    // Only idempotent, body-less requests: a request body would need forwarding (and
    // splicing) upstream too, and non-GET/HEAD may not be safe to retry.
    if !matches!(head.method, Method::GET | Method::HEAD) {
        return None;
    }
    // A declared request body (Content-Length or Transfer-Encoding) is out of scope and a
    // desync surface — fall back. The hardened parser already rejected CL×TE outright.
    if head.framing != BodyFraming::Empty {
        return None;
    }
    // An upgrade or an Expect negotiation is not a plain proxyable GET/HEAD.
    if head.headers.contains_key(http::header::UPGRADE)
        || head.headers.contains_key(http::header::EXPECT)
    {
        return None;
    }
    // Reconstruct the origin-form target (path + query) to forward.
    let target = head
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| head.uri.path().to_string());
    Some(FastReq {
        method: head.method,
        target,
        headers: head.headers,
    })
}

/// A site classified as a pure single-backend plaintext-HTTP gateway proxy for one
/// request — everything [`classify`] resolves except the SSRF address pin (which is done
/// once, on the first request, and the connection is then reused). Returned by
/// [`classify_site`] so the first-request path and the per-request re-verification path
/// ([`SplicePlan::reverify`]) run the **identical** decision and cannot drift.
struct Classified {
    project: String,
    site: String,
    upstream: Upstream,
    /// The single `http://` backend string the route resolves to.
    target: String,
}

/// Run the full routing decision for one request against the live config: reserved-path
/// defer, console mount, host→site, site access-rule/transport/handler/stream
/// preconditions, manifest route precedence, and the gateway single-plaintext-backend
/// check. Returns `Some` only for an unambiguous pure-proxy outcome. Shared by the
/// first-request [`classify`] and the per-request [`SplicePlan::reverify`] so both apply
/// the same guard (anti-desync on keep-alive).
async fn classify_site(
    ctx: &SpliceCtx,
    host: &str,
    target_path: &str,
    path: &str,
    method: &Method,
) -> Option<Classified> {
    // Reserved control-plane / system routes are matched by the app router *before* the
    // `serve_by_host` fallback where the gateway lives — so a site's catch-all (`/**`)
    // never actually handles them. Never intercept these; the router must.
    if is_reserved_path(path) {
        return None;
    }
    // The live daemon config: the catch-all `default_site` and (with the console
    // feature) the console mount, both consulted below.
    let eff = ctx.daemon.as_ref().map(|d| d.effective());
    // The embedded console middleware runs before the gateway fallback; defer any
    // request it would serve to the router. (Only wired with the `console` feature.)
    #[cfg(feature = "console")]
    if let Some(eff) = &eff
        && crate::console::would_intercept(eff, host, path)
    {
        return None;
    }

    // Resolve host → (project, site), matching serve_by_host: an explicit domain
    // wins; otherwise the configured catch-all default_site (default project).
    let (project, site) = match ctx.deploy.resolve_site_by_host(host).await.ok()? {
        Some(owner) => (owner.project, owner.site),
        None => (
            boatramp_core::project::ProjectRef::DEFAULT
                .as_str()
                .to_string(),
            eff.as_ref().and_then(|e| e.default_site.clone())?,
        ),
    };
    let project_ref = boatramp_core::project::ProjectRef::new(&project);
    let cfg = ctx
        .deploy
        .get_site_config_cached(project_ref, &site)
        .await
        .ok()??;

    // Front-of-pipeline preconditions that would preempt the gateway. Be
    // conservative: fall back if any is even possibly in play.
    // 1. Site access rules (WAF/IP/rate/basic-auth) run before content — and
    //    re-running them here would double-count rate limits, so we fall back.
    let a = &cfg.access;
    // `trusted_proxies` changes how the client IP (and thus X-Forwarded-For) is
    // resolved; the fast-path forwards the raw peer, so fall back when it's set.
    let permissive = a.basic_auth.is_none()
        && a.rate_limit.is_none()
        && a.ip.allow.is_empty()
        && a.ip.deny.is_empty()
        && a.trusted_proxies.is_empty()
        && a.waf == Default::default();
    if !permissive {
        return None;
    }
    // 2. Transport (HTTPS) redirect: a plaintext request to an https-only site is
    //    redirected, not proxied.
    if boatramp_core::config::transport_redirect(
        &cfg.security,
        &cfg.domains,
        "http",
        host,
        target_path,
    )
    .is_some()
    {
        return None;
    }
    // 3. Handler-enabled sites may carry stream/handler routes that preempt the
    //    gateway; keep the fast-path to pure proxy sites.
    if cfg.handlers.is_some() {
        return None;
    }

    // The current deployment's routing config: a redirect/rewrite/proxy outcome or
    // a matching handler preempts the gateway (route precedence). Reuse the exact
    // pipeline functions so this can't drift.
    let manifest = ctx
        .deploy
        .current_manifest(project_ref, &site)
        .await
        .ok()??;
    let ctx_default = boatramp_core::predicate::RequestContext::default();
    let resolved = route::resolve_ctx(&manifest.config, &manifest.files, path, &ctx_default);
    match resolved.outcome {
        // A redirect short-circuits the pipeline; a manifest-declared proxy diverges
        // from the gateway path. Either preempts — fall back.
        Outcome::Redirect { .. } | Outcome::Proxy { .. } => return None,
        // File (static) / NotFound are fine: the gateway wins over static files.
        Outcome::File { .. } | Outcome::NotFound { .. } => {}
    }
    if route::match_handler(&manifest.config.handlers, method.as_str(), path).is_some() {
        return None;
    }
    // A site declaring SSE stream routes is not a pure proxy (a stream can preempt
    // the gateway, or 404 when handlers are off) — fall back conservatively.
    if !manifest.config.streams.is_empty() {
        return None;
    }

    // Now the gateway decision — identical to serve_resolved.
    let gw = cfg.gateway.as_ref().filter(|g| g.is_enabled())?;
    let route_match = gw.match_route(path)?;
    let upstream = gw.upstreams.get(&route_match.upstream)?;
    // Only a single, static, plaintext-HTTP backend: no compute wake, no LB across
    // backends, no HTTPS (can't splice ciphertext), no unix socket, no DNS
    // discovery/active-health rerouting.
    if upstream.compute.is_some() || upstream.discover.is_some() || upstream.active_health.is_some()
    {
        return None;
    }
    let backends = upstream.static_backends();
    if backends.len() != 1 {
        return None;
    }
    let target = backends[0];
    if !target.starts_with("http://") {
        return None;
    }
    Some(Classified {
        project,
        site,
        upstream: upstream.clone(),
        target: target.to_string(),
    })
}

/// Decide whether the pipeline would reverse-proxy this request to a single
/// plaintext-HTTP gateway upstream — and, if so, resolve+pin it. Conservative by
/// construction: any uncertainty or advanced feature returns `None` (fall back).
async fn classify(head: &[u8], ctx: &SpliceCtx) -> Option<SplicePlan> {
    // No kernel splice off Linux → never intercept; everything serves as before.
    if !splice_supported() {
        return None;
    }
    let req = parse_fastpath_request(head)?;
    let host = req
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port)
        .unwrap_or("");
    let path = path_only(&req.target);
    let c = classify_site(ctx, host, &req.target, path, &req.method).await?;
    // Resolve + SSRF-pin exactly like the userspace proxy path. The splice fast-path
    // serves only a SITE gateway upstream (operator tier), so the operator address
    // policy applies.
    let resolved_target = proxy::resolve_target(
        &c.target,
        proxy::GatewayTargetPolicy::Operator,
        &ctx.posture,
    )
    .await
    .ok()?;
    if !proxy::gateway_addr_allowed(resolved_target.addr.ip(), &ctx.posture) {
        return None;
    }
    Some(SplicePlan {
        resolved: resolved_target,
        upstream: c.upstream,
        site: c.site,
        project: c.project,
        target: c.target,
    })
}

/// Handle a splice-eligible connection: for each request, forward the head and
/// splice the response body upstream→client. A subsequent request on the same
/// keep-alive connection that is no longer splice-eligible (a POST, an API path, a
/// different route) is not dropped — the already-read head is replayed and the
/// whole connection is handed to the normal `router` (boatramp-http's serve loop)
/// from that point on.
async fn splice_conn(
    mut client: TcpStream,
    peer: SocketAddr,
    plan: SplicePlan,
    ctx: SpliceCtx,
    serve: crate::ServeInput,
) -> io::Result<()> {
    let mut upstream = UpstreamConn::connect(plan.resolved.addr, ctx.read_timeout).await?;
    let client_ip: IpAddr = peer.ip();
    loop {
        // Read (consuming) the client request head, bounded by the idle read timeout so a
        // slow-loris that dribbles request #2 (or stalls between keep-alive requests) is
        // dropped rather than pinning the client socket + the pinned upstream + this task
        // indefinitely (N-1) — the same bound the normal server applies to its head read.
        let (head, leftover) = match read_head(&mut client, ctx.read_timeout).await? {
            Some(v) => v,
            None => return Ok(()), // client closed / idled out between keep-alive requests
        };
        // Re-check eligibility per request with the **hardened** parser (a keep-alive
        // client could change path/method, or smuggle a framing header on request #2).
        // This re-runs the FULL header-framing guard every request (F-4, F-6). A pipelined
        // request (non-empty leftover) also falls back. On anything not a clean splice,
        // hand the connection — with the head we already read replayed — to the normal
        // server so nothing is lost.
        let req = match (leftover.is_empty())
            .then(|| parse_fastpath_request(&head))
            .flatten()
        {
            Some(v) => v,
            None => return fall_back(head, leftover, client, peer, serve).await,
        };
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(strip_port)
            .unwrap_or("");
        let path = path_only(&req.target);
        // Re-run the full routing decision (reserved-path defer, host→site, access/
        // transport/handler/stream preconditions, gateway single-backend) against the
        // live config, and require it still pins to THIS exact upstream connection
        // (F-6: a redeploy, a changed Host, or a reserved path on request #2 must not
        // ride the pinned splice). Otherwise fall back.
        if plan
            .reverify(&ctx, host, &req.target, path, &req.method)
            .await
            .is_none()
        {
            return fall_back(head, leftover, client, peer, serve).await;
        }
        // Honor a client `Connection: close`: serve this one request, then close
        // (HTTP/1.1 defaults to keep-alive otherwise).
        let client_close = header_has_token(&req.headers, http::header::CONNECTION, "close");
        // Build + send the upstream request head (from the validated HeaderMap).
        let up_head = build_upstream_head(&plan, &req, client_ip);
        upstream.write_all(&up_head).await?;
        // Read the final upstream response head, forwarding + skipping any 1xx interim
        // responses (F-5: a 100/103 is not the final response — never body-frame it).
        let resp = match upstream
            .read_final_response_head(&mut client, &req.method)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()), // upstream closed before a final response
            Err(e) => {
                // A malformed upstream response head is a desync risk: refuse (fail closed).
                let _ = client.write_all(BAD_GATEWAY).await;
                return Err(e);
            }
        };
        // Resolve the response body framing with strict RFC 9112 §6 logic — reject a
        // Content-Length×Transfer-Encoding conflict, multiple Transfer-Encoding fields, or
        // a non-last `chunked` (F-2: these are the response CL.TE desync / cache-poisoning
        // vectors). An ambiguous response is answered 502 + close, never forwarded.
        let framing = match resolve_response_framing(resp.status, &req.method, &resp.headers) {
            Ok(f) => f,
            Err(_) => {
                let _ = client.write_all(BAD_GATEWAY).await;
                return Ok(());
            }
        };
        // Build + send the downstream response head: strip hop-by-hop, keep chunked TE for
        // the verbatim passthrough, and DROP Content-Length when forwarding chunked
        // (F-2: never emit CL+TE to the client). Apply the upstream's header_down ops.
        let out_head = build_downstream_head(&resp, &plan.upstream, &framing);
        client.write_all(&out_head).await?;
        // Forward EXACTLY the framed body — streaming (F-1: never buffer a whole chunk)
        // and never past this response's end (F-3: a trailing injected response is not
        // forwarded as the client's next response). `clean` is false if the upstream
        // already buffered bytes past this response.
        let clean = upstream.forward_body(&mut client, &framing).await?;
        if matches!(framing, RespFraming::CloseDelimited) {
            return Ok(()); // the close IS the frame; the connection is spent
        }
        if !clean {
            return Ok(()); // buffered trailing bytes (desync) → close, don't reuse
        }
        if resp.close || client_close {
            return Ok(());
        }
        // Keep-alive reuse: a compliant upstream is silent until it receives the next
        // request. Any bytes readable NOW (before we send request N+1) are unsolicited —
        // a queued/injected response — so close rather than forward them later (F-3).
        if upstream.has_unsolicited_bytes().await? {
            return Ok(());
        }
    }
}

impl SplicePlan {
    /// Re-verify that a subsequent keep-alive request still classifies as a pure proxy to
    /// **this exact pinned backend** under the live config. Runs the same decision as the
    /// first-request [`classify`] (via [`classify_site`]) — so a redeploy that adds access
    /// rules / handlers / streams, a changed `Host`, a reserved path, or a route change all
    /// force a fall back rather than riding the pinned splice connection. Cheap: the config
    /// + manifest are content-hash cached.
    async fn reverify(
        &self,
        ctx: &SpliceCtx,
        host: &str,
        target_path: &str,
        path: &str,
        method: &Method,
    ) -> Option<()> {
        let c = classify_site(ctx, host, target_path, path, method).await?;
        // Must still pin to the same (project, site) AND the same single backend string —
        // else the pinned upstream connection is pointed at the wrong origin.
        (c.project == self.project && c.site == self.site && c.target == self.target).then_some(())
    }
}

/// A `502 Bad Gateway` sent to the client when an upstream response is malformed or
/// framing-ambiguous (fail closed; the connection is then dropped).
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// Whether a header's value carries `token` as a comma-separated element (case-
/// insensitive) — e.g. `Connection: keep-alive, close`.
fn header_has_token(headers: &HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|v| {
        v.to_str()
            .is_ok_and(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    })
}

// ---- request/response head building + framing ------------------------------

/// Build the upstream request head bytes from the **validated** [`FastReq`] headers:
/// rewritten path, forwarded headers minus hop-by-hop + Host, plus the X-Forwarded chain,
/// matching the userspace proxy. Because every header value came through the hardened h1
/// parser (no embedded CR/LF, no CTL), re-emitting it verbatim cannot inject a header line
/// — closing the request-smuggling vector (F-4). Built as raw bytes so an opaque (obs-text,
/// non-UTF-8) header value round-trips unchanged.
fn build_upstream_head(plan: &SplicePlan, req: &FastReq, client_ip: IpAddr) -> Vec<u8> {
    // Upstream path: the target's base path + the (strip-prefixed) request path +
    // original query.
    let base = plan.resolved.parsed.path().trim_end_matches('/');
    let (req_path, query) = match req.target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (req.target.as_str(), None),
    };
    let forwarded = plan.upstream.forward_path(req_path);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    out.extend_from_slice(req.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(base.as_bytes());
    out.extend_from_slice(forwarded.as_bytes());
    if let Some(q) = query {
        out.push(b'?');
        out.extend_from_slice(q.as_bytes());
    }
    out.extend_from_slice(b" HTTP/1.1\r\n");
    // Host: the upstream's own authority (explicit override, else the target host).
    let host = plan
        .upstream
        .host_header
        .as_deref()
        .unwrap_or(plan.resolved.host.as_str());
    push_header(&mut out, "host", host.as_bytes());
    for (name, value) in req.headers.iter() {
        let lname = name.as_str(); // HeaderName is always lowercase
        if lname == "host"
            || HOP_BY_HOP.contains(&lname)
            || plan
                .upstream
                .header_up
                .remove
                .iter()
                .any(|h| lname.eq_ignore_ascii_case(h))
        {
            continue;
        }
        push_header(&mut out, lname, value.as_bytes());
    }
    push_header(
        &mut out,
        "x-forwarded-for",
        client_ip.to_string().as_bytes(),
    );
    push_header(&mut out, "x-forwarded-proto", b"http");
    // Preserve the inbound X-Forwarded-Host (the original client Host), matching the
    // userspace proxy. (The client's own X-Forwarded-For, if any, was forwarded in the
    // header loop above and our hop is appended after it — the same append-not-strip
    // behavior as `proxy.rs`; see the F-7 parity note in the module tests.)
    if let Some(h) = req.headers.get(http::header::HOST) {
        push_header(&mut out, "x-forwarded-host", h.as_bytes());
    }
    for (name, value) in &plan.upstream.header_up.set {
        push_header(&mut out, name, value.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Append `name: value\r\n` to a head buffer (raw bytes).
fn push_header(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

/// Build the downstream response head for the client from the parsed upstream response:
/// drop hop-by-hop + the upstream's `header_down.remove`, apply `header_down.set`. When
/// forwarding a chunked body the `Transfer-Encoding: chunked` header is **kept** (so a
/// keep-alive client can delimit the verbatim chunk framing) and `Content-Length` is
/// **stripped** (RFC 9112 §6.1 — never emit CL+TE to the client; F-2). For a non-chunked
/// body `Transfer-Encoding` is stripped as a normal hop-by-hop header and `Content-Length`
/// is preserved (we forward exactly that many octets).
fn build_downstream_head(resp: &FinalResp, upstream: &Upstream, framing: &RespFraming) -> Vec<u8> {
    let status = resp.status;
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    let mut out: Vec<u8> = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    let is_chunked = matches!(framing, RespFraming::Chunked);
    for (name, value) in resp.headers.iter() {
        let lk = name.as_str(); // always lowercase
        // Drop Content-Length when forwarding chunked (defense in depth — a CL+TE response
        // was already rejected by `resolve_response_framing`).
        if is_chunked && lk == "content-length" {
            continue;
        }
        let is_hop = HOP_BY_HOP.contains(&lk)
            || upstream
                .header_down
                .remove
                .iter()
                .any(|h| lk.eq_ignore_ascii_case(h));
        if is_hop {
            // Keep the chunked Transfer-Encoding for the verbatim passthrough; strip every
            // other hop-by-hop header (and any header_down.remove target).
            if !(is_chunked && lk == "transfer-encoding") {
                continue;
            }
        }
        push_header(&mut out, lk, value.as_bytes());
    }
    for (name, value) in &upstream.header_down.set {
        push_header(&mut out, name, value.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// How an upstream response body is framed, for forwarding (RFC 9112 §6, receiver side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RespFraming {
    /// No body is forwarded (HEAD / 204 / 304 / CONNECT-2xx).
    None,
    /// A fixed-length body of this many octets.
    Length(u64),
    /// A chunked body — forwarded framing-verbatim until the terminating 0-chunk.
    Chunked,
    /// Framed by connection close.
    CloseDelimited,
}

/// Resolve how to forward an upstream response body, with the **same strict** CL×TE logic
/// the request parser's `resolve_framing` enforces (RFC 9112 §6.3). `Err(())` on any
/// desync-risk framing — both `Content-Length` and `Transfer-Encoding` present, multiple
/// `Transfer-Encoding` fields, or `Transfer-Encoding` whose final coding is not `chunked`
/// — so the proxy answers 502 + close instead of forwarding an ambiguously-framed response
/// a downstream could re-interpret (cache poisoning / response CL.TE desync; F-2).
///
/// 1xx is handled by the caller (never reaches here).
fn resolve_response_framing(
    status: u16,
    method: &Method,
    headers: &HeaderMap,
) -> Result<RespFraming, ()> {
    // No-body statuses (RFC 9110 §6.4.1) override the framing headers.
    if *method == Method::HEAD
        || status == 204
        || status == 304
        || (*method == Method::CONNECT && (200..300).contains(&status))
    {
        return Ok(RespFraming::None);
    }
    // Gather Content-Length tokens (split each field on commas) and Transfer-Encoding
    // field values — mirroring the request-side resolver.
    let mut cl_tokens: Vec<&[u8]> = Vec::new();
    for v in headers.get_all(http::header::CONTENT_LENGTH) {
        for tok in v.as_bytes().split(|&b| b == b',') {
            cl_tokens.push(trim_ows_bytes(tok));
        }
    }
    let te_values: Vec<&[u8]> = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .map(http::HeaderValue::as_bytes)
        .collect();
    let cl_present = !cl_tokens.is_empty();
    let te_present = !te_values.is_empty();
    // Both framing headers present is THE response CL/TE desync surface — never reconcile.
    if cl_present && te_present {
        return Err(());
    }
    if te_present {
        // Multiple Transfer-Encoding *fields* is a TE.TE desync vector (first-vs-last
        // disagreement) — reject rather than combine.
        if te_values.len() != 1 {
            return Err(());
        }
        let codings: Vec<Vec<u8>> = te_values[0]
            .split(|&b| b == b',')
            .map(|t| trim_ows_bytes(t).to_ascii_lowercase())
            .collect();
        if codings.iter().any(std::vec::Vec::is_empty) {
            return Err(());
        }
        let chunked_count = codings
            .iter()
            .filter(|c| c.as_slice() == b"chunked")
            .count();
        let last_is_chunked = codings.last().map(|c| c.as_slice() == b"chunked") == Some(true);
        // `chunked` must appear exactly once and be the final coding (else no determinable
        // length — a desync setup).
        if chunked_count != 1 || !last_is_chunked {
            return Err(());
        }
        return Ok(RespFraming::Chunked);
    }
    if cl_present {
        // Exactly one Content-Length token (any duplication, even identical, is ambiguous).
        if cl_tokens.len() != 1 {
            return Err(());
        }
        let tok = cl_tokens[0];
        if tok.is_empty() || !tok.iter().all(u8::is_ascii_digit) {
            return Err(());
        }
        let n = std::str::from_utf8(tok)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(())?;
        return Ok(RespFraming::Length(n));
    }
    Ok(RespFraming::CloseDelimited)
}

/// Trim leading + trailing OWS (SP / HTAB) from a byte slice.
fn trim_ows_bytes(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if *first == b' ' || *first == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = v {
        if *last == b' ' || *last == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

// ---- low-level IO helpers --------------------------------------------------

/// Read until CRLFCRLF from `s`; returns `(head_incl_terminator, bytes_read_past_head)`.
///
/// `read_timeout` is a per-read **idle** timeout — reset on every successful read, exactly
/// like `boatramp_http`'s own [`serve_connection`](boatramp_http::serve_connection) head
/// read — so a legitimately slow-but-progressing client is treated the same as it would be
/// on the normal server path, while a stalled one is bounded. On expiry with no bytes
/// buffered the connection is idle between keep-alive requests → a clean `None` (drop, like
/// the normal server). On expiry mid-head (a partial head then silence — slow-loris) it is a
/// `TimedOut` error so the caller closes the connection (N-1).
async fn read_head(
    s: &mut TcpStream,
    read_timeout: std::time::Duration,
) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    use tokio::io::AsyncReadExt;
    let mut acc: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 8192];
    loop {
        let n = match tokio::time::timeout(read_timeout, s.read(&mut tmp)).await {
            Ok(r) => r?,
            Err(_elapsed) => {
                return if acc.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "client head read timed out",
                    ))
                };
            }
        };
        if n == 0 {
            return if acc.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid-head"))
            };
        }
        acc.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_head_end(&acc) {
            let head = acc[..end].to_vec();
            let rest = acc[end..].to_vec();
            return Ok(Some((head, rest)));
        }
        if acc.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
    }
}

/// Byte index just past a CRLFCRLF, if present.
fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

// ---- the pinned upstream connection + framed body forwarder ----------------

/// The response-head overread / un-forwarded upstream byte buffer is capped: anything
/// that cannot complete a chunk-size line or the terminal-chunk trailer section within
/// this bound (a dripped size line, an endless trailer section) is a fail-closed error.
const MAX_CHUNK_META: usize = 16 * 1024;

/// A final (non-1xx) upstream response head, reduced to what the forwarder needs.
struct FinalResp {
    status: u16,
    headers: HeaderMap,
    /// The upstream asked to close after this response (`Connection: close`).
    close: bool,
}

/// One pinned upstream HTTP/1.1 connection: the socket plus a buffer of bytes read past
/// the current message boundary (a response-head overread, or the start of the body). The
/// buffer is the key to the anti-desync invariant — the forwarder consumes from it exactly
/// up to each response's framed end and never forwards a byte it has not accounted for.
struct UpstreamConn {
    sock: TcpStream,
    buf: Vec<u8>,
    /// Idle read timeout applied to every upstream read (via [`UpstreamConn::fill`]): a
    /// non-conformant (trusted) upstream that stalls — a dripped response head, an endless
    /// close-delimited body, a stalled chunk — fails closed instead of pinning the task
    /// forever (N-5). Mirrors the client-side `read_head` bound (same value).
    read_timeout: std::time::Duration,
}

impl UpstreamConn {
    async fn connect(addr: SocketAddr, read_timeout: std::time::Duration) -> io::Result<Self> {
        let sock = TcpStream::connect(addr).await?;
        sock.set_nodelay(true).ok();
        Ok(Self {
            sock,
            buf: Vec::with_capacity(16 * 1024),
            read_timeout,
        })
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.sock.write_all(bytes).await
    }

    /// Read one more chunk of bytes from the socket into `buf`; returns the count (0 = the
    /// upstream closed its side). Bounded by a per-read idle timeout (reset each call) so a
    /// stalled upstream — holding the connection open without delivering the rest of a
    /// response — fails closed rather than hanging the forwarder task (N-5). Every upstream
    /// read in the forwarder (`read_response_head`, the chunked fill loop, `forward_to_close`)
    /// routes through here, so one bound covers them all.
    async fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 16 * 1024];
        let n = match tokio::time::timeout(self.read_timeout, self.sock.read(&mut tmp)).await {
            Ok(r) => r?,
            Err(_elapsed) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream read timed out",
                ));
            }
        };
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// Parse one response head off the front of `buf` with the **hardened** h1 response
    /// parser, consuming it from `buf` and leaving the body prefix behind. `None` = the
    /// upstream closed before a head; a malformed head is a hard `Err` (fail closed).
    async fn read_response_head(&mut self) -> io::Result<Option<boatramp_http::h1::ResponseHead>> {
        use boatramp_http::h1::{RespParse, parse_response_head};
        loop {
            match parse_response_head(&self.buf) {
                RespParse::Complete { head, consumed } => {
                    self.buf.drain(..consumed);
                    return Ok(Some(head));
                }
                RespParse::Reject => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed upstream response head",
                    ));
                }
                RespParse::Incomplete => {
                    if self.fill().await? == 0 {
                        return if self.buf.is_empty() {
                            Ok(None)
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "upstream closed mid response head",
                            ))
                        };
                    }
                }
            }
        }
    }

    /// Read the **final** response head, forwarding each interim `1xx` head (no body) to
    /// the client and continuing — a `100 Continue` / `103 Early Hints` is not the final
    /// response, so it must never be body-framed or treated as close-delimited (F-5).
    async fn read_final_response_head(
        &mut self,
        client: &mut TcpStream,
        _method: &Method,
    ) -> io::Result<Option<FinalResp>> {
        loop {
            let head = match self.read_response_head().await? {
                Some(h) => h,
                None => return Ok(None),
            };
            let status = head.status.as_u16();
            if (100..200).contains(&status) {
                // Interim response: forward the head verbatim-ish (hop-by-hop stripped),
                // never a body, then read the next head from the same connection.
                let out = build_interim_head(&head);
                client.write_all(&out).await?;
                continue;
            }
            let close = header_has_token(&head.headers, http::header::CONNECTION, "close");
            return Ok(Some(FinalResp {
                status,
                headers: head.headers,
                close,
            }));
        }
    }

    /// Forward exactly the framed response body to `client`. Returns `Ok(true)` when the
    /// upstream is clean for keep-alive reuse (no bytes buffered past this response),
    /// `Ok(false)` when trailing bytes were seen (a desync — the caller then closes).
    async fn forward_body(
        &mut self,
        client: &mut TcpStream,
        framing: &RespFraming,
    ) -> io::Result<bool> {
        match framing {
            // No body: any buffered bytes are unsolicited (not a body — HEAD/204/304).
            RespFraming::None => Ok(self.buf.is_empty()),
            RespFraming::Length(total) => self.forward_length(client, *total).await,
            RespFraming::Chunked => self.forward_chunked(client).await,
            RespFraming::CloseDelimited => {
                self.forward_to_close(client).await?;
                Ok(true)
            }
        }
    }

    /// Forward a fixed-length body of `total` octets: drain up to `total` from `buf`, then
    /// `splice()` the remainder socket→client (zero-copy on Linux). Forwards EXACTLY
    /// `total` bytes — a `buf` that already holds more than `total` means the upstream
    /// appended bytes past this response (desync) → those are NOT forwarded (F-3).
    async fn forward_length(&mut self, client: &mut TcpStream, total: u64) -> io::Result<bool> {
        let from_buf = usize::try_from(total)
            .unwrap_or(usize::MAX)
            .min(self.buf.len());
        if from_buf > 0 {
            client.write_all(&self.buf[..from_buf]).await?;
        }
        let trailing = self.buf.len() > from_buf; // bytes past the CL body already buffered
        self.buf.drain(..from_buf);
        let remaining = total - from_buf as u64;
        if remaining > 0 {
            // `from_buf == buf.len()` here (we took all of buf), so nothing is stranded.
            // Pass the same per-read idle timeout the rest of the forwarder uses (N-5): it
            // bounds a STALL on the upstream-readable wait inside `splice_body` without
            // touching the zero-copy move itself (the splice() syscall is unchanged).
            splice_body(&self.sock, &*client, remaining as usize, self.read_timeout).await?;
        }
        Ok(!trailing)
    }

    /// Forward a **chunked** body framing-verbatim, STREAMING each chunk's payload rather
    /// than buffering it (F-1: a 2 GB or hostile `7fff…` chunk is moved in read-sized
    /// slices, never retained), and stopping EXACTLY at the terminating 0-chunk's end
    /// (F-3: a second response appended after it is never forwarded). Returns `Ok(false)`
    /// if bytes remain buffered past the terminal chunk (desync → close).
    async fn forward_chunked(&mut self, client: &mut TcpStream) -> io::Result<bool> {
        loop {
            // 1) Pull a complete chunk-size line to the front of `buf` (bounded).
            let (size, line_len) = loop {
                match parse_chunk_size_line(&self.buf) {
                    SizeLine::Got { size, line_len } => break (size, line_len),
                    SizeLine::Reject => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed chunk-size line",
                        ));
                    }
                    SizeLine::Incomplete => {
                        if self.buf.len() > MAX_CHUNK_META {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "chunk-size line exceeds bound",
                            ));
                        }
                        if self.fill().await? == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "upstream closed before a chunk-size line",
                            ));
                        }
                    }
                }
            };
            if size == 0 {
                // Terminal chunk: forward `0CRLF` + trailers + final CRLF, then stop.
                return self.forward_terminal_chunk(client).await;
            }
            // 2) Forward the size-line + `size` payload octets + the trailing CRLF
            //    verbatim, streaming (never buffering the whole payload).
            self.forward_chunk_body(client, line_len, size).await?;
        }
    }

    /// Stream one data chunk verbatim: `line_len` size-line bytes already at the front of
    /// `buf`, then `size` payload octets, then a CRLF — forwarding in read-sized slices and
    /// validating the terminating CRLF. The whole payload is never held in memory at once.
    async fn forward_chunk_body(
        &mut self,
        client: &mut TcpStream,
        line_len: usize,
        size: usize,
    ) -> io::Result<()> {
        // Total verbatim bytes for this chunk: size-line + payload + CRLF. Checked so a
        // near-`usize::MAX` declared size is a fail-closed error, not an overflow panic.
        let payload_end = line_len
            .checked_add(size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?; // index where the trailing CRLF begins
        let chunk_total = payload_end
            .checked_add(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
        let mut pos = 0usize; // bytes of THIS chunk already forwarded
        while pos < chunk_total {
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed mid chunk",
                ));
            }
            let avail = self.buf.len().min(chunk_total - pos);
            // Validate the chunk's terminating CRLF as it passes (positions payload_end,
            // payload_end+1) — a malformed terminator is a fail-closed error.
            for i in 0..avail {
                match pos + i {
                    p if p == payload_end && self.buf[i] != b'\r' => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bad chunk terminator",
                        ));
                    }
                    p if p == payload_end + 1 && self.buf[i] != b'\n' => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bad chunk terminator",
                        ));
                    }
                    _ => {}
                }
            }
            client.write_all(&self.buf[..avail]).await?;
            self.buf.drain(..avail);
            pos += avail;
        }
        Ok(())
    }

    /// Forward the terminating 0-chunk (+ trailer section + final CRLF) verbatim, validated
    /// by the hardened `next_chunk` (which rejects a framing-sensitive trailer / obs-fold),
    /// and STOP there. Returns `Ok(false)` if bytes remain buffered past it (a second,
    /// injected response — never forwarded as the client's next response; F-3).
    async fn forward_terminal_chunk(&mut self, client: &mut TcpStream) -> io::Result<bool> {
        use boatramp_http::h1::chunked::{ChunkStep, next_chunk};
        loop {
            match next_chunk(&self.buf) {
                ChunkStep::Last { end } => {
                    client.write_all(&self.buf[..end]).await?;
                    self.buf.drain(..end);
                    return Ok(self.buf.is_empty());
                }
                ChunkStep::Data { .. } => {
                    // Unreachable (the size was 0), but fail closed rather than trust it.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected data chunk at terminator",
                    ));
                }
                ChunkStep::Reject(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed terminal chunk",
                    ));
                }
                ChunkStep::Incomplete => {
                    if self.buf.len() > MAX_CHUNK_META {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "terminal chunk / trailers exceed bound",
                        ));
                    }
                    if self.fill().await? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "upstream closed before the terminating chunk",
                        ));
                    }
                }
            }
        }
    }

    /// Forward a close-delimited body: the buffered prefix, then everything until the
    /// upstream closes its side (the close *is* the frame, so this terminates and the
    /// connection is spent). Each read goes through [`UpstreamConn::fill`], so it inherits
    /// the idle read timeout — a non-conformant upstream that holds a no-Content-Length
    /// connection open without ever closing fails closed instead of pinning this task
    /// forever (N-5), rather than the previous unbounded `tokio::io::copy`.
    async fn forward_to_close(&mut self, client: &mut TcpStream) -> io::Result<()> {
        loop {
            if !self.buf.is_empty() {
                client.write_all(&self.buf).await?;
                self.buf.clear();
            }
            if self.fill().await? == 0 {
                return Ok(()); // upstream closed → the close delimits the body
            }
        }
    }

    /// Whether the upstream has bytes ready to read **right now** — between responses, before
    /// the next request is sent, so any such bytes are unsolicited (a queued/injected
    /// response; F-3). Non-blocking: a non-ready socket reports no pending bytes.
    async fn has_unsolicited_bytes(&self) -> io::Result<bool> {
        if !self.buf.is_empty() {
            return Ok(true);
        }
        std::future::poll_fn(|cx| {
            let mut probe = [0u8; 1];
            let mut rb = tokio::io::ReadBuf::new(&mut probe);
            match self.sock.poll_peek(cx, &mut rb) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(!rb.filled().is_empty())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                // Not readable now ⇒ nothing buffered between responses.
                Poll::Pending => Poll::Ready(Ok(false)),
            }
        })
        .await
    }
}

/// Build an interim (`1xx`) response head to forward to the client: the status line + all
/// headers minus hop-by-hop, no body.
fn build_interim_head(head: &boatramp_http::h1::ResponseHead) -> Vec<u8> {
    let status = head.status.as_u16();
    let reason = head.status.canonical_reason().unwrap_or("");
    let mut out: Vec<u8> = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in head.headers.iter() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        push_header(&mut out, name.as_str(), value.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The outcome of parsing a chunk-size line off the front of a buffer.
enum SizeLine {
    /// A complete `<hex>[;ext]CRLF` line: the decoded `size` and the line's total byte
    /// length (through the CRLF).
    Got { size: usize, line_len: usize },
    /// No complete CRLF-terminated line yet — read more (bounded by the caller).
    Incomplete,
    /// Malformed (bare CR/LF, non-hex / overflowing size, oversized line) — fail closed.
    Reject,
}

/// Largest chunk-size line (`<hex>;<ext>`) accepted — matches the h1 codec's bound.
const MAX_CHUNK_SIZE_LINE: usize = 1024;

/// Parse just the chunk-size line (not the payload) from the front of `buf`, so the
/// payload can be **streamed** rather than buffered. Enforces strict CRLF framing and the
/// hardened size rules (1..=16 hex digits, no `0x`/sign, `usize`-bounded).
fn parse_chunk_size_line(buf: &[u8]) -> SizeLine {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        return SizeLine::Incomplete;
    };
    // Strict CRLF: the byte before LF must be CR, and no bare CR inside the line.
    if nl == 0 || buf[nl - 1] != b'\r' {
        return SizeLine::Reject;
    }
    let line = &buf[..nl - 1];
    if line.contains(&b'\r') || line.len() > MAX_CHUNK_SIZE_LINE {
        return SizeLine::Reject;
    }
    // Strip an optional chunk-extension (`;...`); the size is the hex prefix.
    let size_bytes = match line.iter().position(|&b| b == b';') {
        Some(i) => &line[..i],
        None => line,
    };
    let size_bytes = trim_ows_bytes(size_bytes);
    if size_bytes.is_empty()
        || size_bytes.len() > 16
        || !size_bytes.iter().all(u8::is_ascii_hexdigit)
    {
        return SizeLine::Reject;
    }
    let Ok(s) = std::str::from_utf8(size_bytes) else {
        return SizeLine::Reject;
    };
    let Ok(size64) = u64::from_str_radix(s, 16) else {
        return SizeLine::Reject;
    };
    let Ok(size) = usize::try_from(size64) else {
        return SizeLine::Reject;
    };
    SizeLine::Got {
        size,
        line_len: nl + 1,
    }
}

/// Move exactly `n` bytes `src`→`dst` via `splice()` — no userspace copy of the
/// payload. Linux only; unavailable elsewhere (callers never reach it because
/// [`classify`] resolves nothing on non-Linux — see [`splice_supported`]).
///
/// `read_timeout` is a per-read **idle** timeout on the upstream (`src`) side only —
/// reset on every iteration, i.e. after every `splice()` that moves `> 0` bytes — so a
/// transfer making progress is never affected and only a genuine no-progress stall is
/// bounded. It wraps the `READABLE` readiness `.await` ONLY; the `splice()` syscall that
/// performs the zero-copy move is untouched (no throughput change). It is the fixed-length
/// (Content-Length) sibling of the N-5 idle bound [`UpstreamConn::fill`] applies to every
/// other upstream read: a trusted upstream that declares `Content-Length: N`, delivers part
/// of the body, then stalls without closing is failed closed (`TimedOut` → the caller closes
/// the client) instead of pinning this task forever. The client (`dst`) write-readiness wait
/// is deliberately NOT bounded here — client backpressure is throughput, not an upstream stall.
#[cfg(target_os = "linux")]
async fn splice_body(
    src: &TcpStream,
    dst: &TcpStream,
    mut n: usize,
    read_timeout: std::time::Duration,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::ptr;
    use tokio::io::Interest;

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (pr, pw) = (fds[0], fds[1]);
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let result = async {
        while n > 0 {
            let want = n.min(1 << 16);
            // src socket → pipe (into an empty pipe, so only src readiness blocks).
            // Bound ONLY the readable-readiness wait with the per-read idle timeout: a
            // fresh timeout is created each iteration, so it is reset on every successful
            // splice() that moves bytes (`n -= in_n` then loop) and fires only when no
            // bytes move within the window (the upstream stalled without closing). The
            // splice() syscall inside the closure is unchanged — zero-copy is preserved.
            let in_n = match tokio::time::timeout(
                read_timeout,
                src.async_io(Interest::READABLE, || {
                    let r = unsafe {
                        libc::splice(src_fd, ptr::null_mut(), pw, ptr::null_mut(), want, flags)
                    };
                    if r < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(r as usize)
                    }
                }),
            )
            .await
            {
                Ok(r) => r?,
                Err(_elapsed) => {
                    // Idle stall: the upstream owes Content-Length bytes but delivered none
                    // within the window. Fail closed so the caller closes the client (which
                    // signals the truncation) rather than pinning this task forever (N-5).
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream splice read timed out",
                    ));
                }
            };
            if in_n == 0 {
                // Upstream closed before delivering Content-Length: the response is
                // truncated. Fail so the caller closes the client connection (which
                // signals the truncation) rather than looping and leaving the client
                // waiting forever for the promised bytes.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed before content-length",
                ));
            }
            // pipe → dst socket, draining fully before refilling
            let mut left = in_n;
            while left > 0 {
                let out_n = dst
                    .async_io(Interest::WRITABLE, || {
                        let r = unsafe {
                            libc::splice(pr, ptr::null_mut(), dst_fd, ptr::null_mut(), left, flags)
                        };
                        if r < 0 {
                            Err(io::Error::last_os_error())
                        } else {
                            Ok(r as usize)
                        }
                    })
                    .await?;
                left -= out_n;
            }
            n -= in_n;
        }
        Ok(())
    }
    .await;
    unsafe {
        libc::close(pr);
        libc::close(pw);
    }
    result
}

#[cfg(not(target_os = "linux"))]
async fn splice_body(
    _src: &TcpStream,
    _dst: &TcpStream,
    _n: usize,
    _read_timeout: std::time::Duration,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice is linux-only",
    ))
}

/// Whether the kernel splice fast-path is available on this target.
pub fn splice_supported() -> bool {
    cfg!(target_os = "linux")
}

// ---- small string helpers --------------------------------------------------

fn strip_port(host: &str) -> &str {
    host.rsplit_once(':')
        .filter(|(h, _)| !h.contains(':') || h.starts_with('['))
        .map(|(h, _)| h)
        .unwrap_or(host)
        .trim_start_matches('[')
        .trim_end_matches(']')
}

fn path_only(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Paths served by an app-level route (which is matched *before* the host-routing
/// fallback, so a site gateway never handles them). Kept in sync with the routes
/// registered in `routes.rs`; the splice fast-path defers all of these to the
/// router. Conservative: covers the whole prefix even for exact routes like
/// `/healthz` (a `/healthz/x` under a gateway would just take the normal path).
fn is_reserved_path(path: &str) -> bool {
    const RESERVED: &[&str] = &[
        "/healthz",
        "/readyz",
        "/api/",
        "/_sites/",
        "/_deploy/",
        "/_webhooks/",
        "/.well-known/boatramp-",
        "/mcp",
    ];
    RESERVED.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_paths_defer_to_the_router() {
        // Control-plane / system routes must never be spliced (the app router serves
        // them before the gateway fallback).
        for p in [
            "/api/sites",
            "/healthz",
            "/readyz",
            "/_sites/x",
            "/_deploy/abc",
            "/_webhooks/hook",
            "/.well-known/boatramp-domain-verification/tok",
            "/mcp",
        ] {
            assert!(is_reserved_path(p), "{p} should be reserved");
        }
        // A gateway/static path is not reserved.
        for p in [
            "/",
            "/b/100k",
            "/index.html",
            "/assets/app.js",
            "/.well-known/acme-challenge/x",
        ] {
            assert!(!is_reserved_path(p), "{p} should not be reserved");
        }
    }

    /// Parse a response head into the forwarder's [`FinalResp`] for the head-building /
    /// framing unit tests (the hardened h1 response parser is the production path).
    fn final_resp(bytes: &[u8]) -> FinalResp {
        use boatramp_http::h1::{RespParse, parse_response_head};
        let RespParse::Complete { head, .. } = parse_response_head(bytes) else {
            panic!(
                "response head did not parse: {:?}",
                String::from_utf8_lossy(bytes)
            );
        };
        FinalResp {
            status: head.status.as_u16(),
            close: header_has_token(&head.headers, http::header::CONNECTION, "close"),
            headers: head.headers,
        }
    }

    #[test]
    fn fastpath_request_gate_only_http11_bodyless_get_head() {
        let req = parse_fastpath_request(
            b"GET /b/100k?x=1 HTTP/1.1\r\nHost: a.example\r\nAccept: */*\r\n\r\n",
        )
        .expect("valid GET");
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.target, "/b/100k?x=1");
        assert_eq!(
            req.headers.get(http::header::HOST).unwrap().as_bytes(),
            b"a.example"
        );
        // HTTP/1.0 is rejected (different keep-alive semantics → fall back).
        assert!(parse_fastpath_request(b"GET / HTTP/1.0\r\nHost: a\r\n\r\n").is_none());
        // A declared body (Content-Length or Transfer-Encoding) is rejected (not body-less).
        assert!(
            parse_fastpath_request(b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n")
                .is_none()
        );
        assert!(
            parse_fastpath_request(
                b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_none()
        );
        // Upgrade / Expect are rejected.
        assert!(
            parse_fastpath_request(b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n")
                .is_none()
        );
        assert!(
            parse_fastpath_request(b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n")
                .is_none()
        );
        // POST is not idempotent/body-less-eligible.
        assert!(
            parse_fastpath_request(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n")
                .is_none()
        );
    }

    /// Reproduce-first (F-4, request smuggling): a header carrying a bare `\n` (or bare `\r`)
    /// would, re-emitted verbatim to the upstream, smuggle a second header line past the
    /// framing guard (`X: y\nTransfer-Encoding: chunked`). The hardened h1 parser rejects a
    /// bare CR/LF, so such a request is never classified eligible. Pre-fix the ad-hoc
    /// `str::split("\r\n")` parser missed the embedded `\n` and `build_upstream_head`
    /// re-emitted it.
    #[test]
    fn fastpath_request_rejects_bare_crlf_header_smuggling() {
        // A bare LF embedded in a header value → reject (would smuggle a TE header).
        assert!(
            parse_fastpath_request(
                b"GET / HTTP/1.1\r\nHost: a\r\nX: y\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_none()
        );
        // A bare CR embedded in a header value → reject.
        assert!(
            parse_fastpath_request(
                b"GET / HTTP/1.1\r\nHost: a\r\nX: y\rTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_none()
        );
        // A bare-LF-terminated request line → reject.
        assert!(parse_fastpath_request(b"GET / HTTP/1.1\nHost: a\r\n\r\n").is_none());
        // Sanity: the same request without the bare LF (the two headers properly CRLF-framed)
        // is rejected too, because it then carries a Transfer-Encoding (a declared body).
        assert!(
            parse_fastpath_request(
                b"GET / HTTP/1.1\r\nHost: a\r\nX: y\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_none()
        );
    }

    #[test]
    fn response_framing_is_resolved_strictly() {
        // A plain Content-Length response frames by length.
        assert_eq!(
            resolve_response_framing(
                200,
                &Method::GET,
                &final_resp(b"HTTP/1.1 200 OK\r\nContent-Length: 102400\r\n\r\n").headers,
            ),
            Ok(RespFraming::Length(102400))
        );
        // Transfer-Encoding: chunked frames chunked.
        assert_eq!(
            resolve_response_framing(
                200,
                &Method::GET,
                &final_resp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").headers,
            ),
            Ok(RespFraming::Chunked)
        );
        // HEAD / 204 / 304 never carry a body regardless of headers.
        assert_eq!(
            resolve_response_framing(
                200,
                &Method::HEAD,
                &final_resp(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n").headers,
            ),
            Ok(RespFraming::None)
        );
        assert_eq!(
            resolve_response_framing(
                204,
                &Method::GET,
                &final_resp(b"HTTP/1.1 204 No Content\r\n\r\n").headers,
            ),
            Ok(RespFraming::None)
        );
        // No framing headers → close-delimited.
        assert_eq!(
            resolve_response_framing(
                200,
                &Method::GET,
                &final_resp(b"HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\n").headers,
            ),
            Ok(RespFraming::CloseDelimited)
        );
        // F-2: CL+TE, multiple TE, and non-last chunked are all rejected (502/close).
        assert!(
            resolve_response_framing(
                200,
                &Method::GET,
                &final_resp(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .headers,
            )
            .is_err()
        );
        assert!(
            resolve_response_framing(
                200,
                &Method::GET,
                &final_resp(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .headers,
            )
            .is_err()
        );
        assert!(
            resolve_response_framing(
                200,
                &Method::GET,
                &final_resp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n").headers,
            )
            .is_err()
        );
    }

    #[test]
    fn strip_port_handles_ipv6_and_default() {
        assert_eq!(strip_port("host.example:8080"), "host.example");
        assert_eq!(strip_port("host.example"), "host.example");
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("127.0.0.1:9000"), "127.0.0.1");
    }

    #[test]
    fn downstream_head_drops_hop_by_hop_keeps_length() {
        let up = Upstream::default();
        // A Content-Length response: hop-by-hop (Connection) stripped, CL kept.
        let resp = final_resp(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\n\r\n",
        );
        let text =
            String::from_utf8(build_downstream_head(&resp, &up, &RespFraming::Length(3))).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.to_ascii_lowercase().contains("content-length: 3\r\n"));
        assert!(
            text.to_ascii_lowercase()
                .contains("content-type: text/plain")
        );
        assert!(!text.to_ascii_lowercase().contains("connection:"));
    }

    /// F-2: a chunked response that ALSO carries Content-Length must be forwarded with the
    /// Content-Length STRIPPED (RFC 9112 §6.1) so a downstream preferring CL cannot desync.
    /// (The both-headers response is rejected by `resolve_response_framing`; this guards the
    /// defense-in-depth strip in `build_downstream_head` for the chunked-forward path.)
    #[test]
    fn downstream_head_strips_content_length_when_chunked() {
        let up = Upstream::default();
        // Parse a chunked response (without the conflicting CL, which the hardened response
        // parser would otherwise accept as two separate fields) then force the chunked
        // framing to exercise the CL strip with a CL present in the map.
        let resp = final_resp(
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
        );
        let text =
            String::from_utf8(build_downstream_head(&resp, &up, &RespFraming::Chunked)).unwrap();
        // The chunked Transfer-Encoding is kept (so the client can delimit the body)…
        assert!(
            text.to_ascii_lowercase()
                .contains("transfer-encoding: chunked"),
            "chunked passthrough must keep Transfer-Encoding: {text}"
        );
        // …but Content-Length is stripped (no CL+TE to the client).
        assert!(
            !text.to_ascii_lowercase().contains("content-length:"),
            "Content-Length must be stripped when forwarding chunked (F-2): {text}"
        );
    }

    #[test]
    fn head_end_index() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nBODY"), Some(18));
        assert_eq!(find_head_end(b"partial\r\nno end"), None);
    }

    #[test]
    fn chunk_size_line_parses_and_rejects() {
        // A normal size line + an extension.
        assert!(matches!(
            parse_chunk_size_line(b"5\r\nhello"),
            SizeLine::Got {
                size: 5,
                line_len: 3
            }
        ));
        assert!(matches!(
            parse_chunk_size_line(b"a;ext=1\r\n...."),
            SizeLine::Got {
                size: 10,
                line_len: 9
            }
        ));
        // The terminal 0-chunk.
        assert!(matches!(
            parse_chunk_size_line(b"0\r\n\r\n"),
            SizeLine::Got {
                size: 0,
                line_len: 3
            }
        ));
        // No CRLF yet → Incomplete.
        assert!(matches!(parse_chunk_size_line(b"5"), SizeLine::Incomplete));
        // Bare LF (no CR) is a hard reject (anti-smuggling).
        assert!(matches!(parse_chunk_size_line(b"5\n"), SizeLine::Reject));
        // Non-hex / too-long size → reject.
        assert!(matches!(
            parse_chunk_size_line(b"xyz\r\n"),
            SizeLine::Reject
        ));
        assert!(matches!(
            parse_chunk_size_line(b"11111111111111111\r\n"),
            SizeLine::Reject
        ));
    }

    /// Regression (reproduce-first): a `Transfer-Encoding: chunked` upstream that keeps
    /// its connection alive must not hang an HTTP/1.1 keep-alive client. Pre-fix the
    /// fast-path (1) stripped `Transfer-Encoding` from the response head (hop-by-hop) —
    /// so the client saw no framing header and treated the body as close-delimited — and
    /// (2) relayed the body with `relay_to_close` (`tokio::io::copy`), which waits for the
    /// *upstream* to close; a keep-alive upstream never does, so the client was left
    /// waiting forever for a connection close that never came. `Content-Length` responses
    /// (spliced by count) and HTTP/1.0 clients (rejected → userspace fallback) both
    /// worked, which is why only chunked-over-keep-alive hung.
    ///
    /// This drives `splice_conn` directly: the chunked relay is userspace (not kernel
    /// splice), so the exact production seam reproduces on every target, not only where
    /// `splice()` engages. The client reads the response with boatramp's own HTTP/1.1
    /// client codec, so framing is taken from the response head exactly as a real client
    /// (curl `--http1.1`) would — pre-fix the body read blocks until the timeout fires.
    #[tokio::test]
    async fn chunked_keepalive_upstream_does_not_hang_the_client() {
        use boatramp_core::config::{DomainConfig, SiteConfig};
        use boatramp_core::deploy::{DeployStore, Manifest};
        use boatramp_core::gateway::{GatewayConfig, GatewayRoute, Upstream};
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::security::SecurityProfile;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // A chunked KEEP-ALIVE upstream: it sends a complete chunked response (including
        // the terminating 0-chunk) and then holds the connection open forever (never
        // closes), exactly like a real keep-alive origin.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    let resp: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
                                        5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
                    if s.write_all(resp).await.is_err() {
                        return;
                    }
                    // Keep-alive: never close; block reading a next request that never comes.
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        // A gateway site whose single plaintext-HTTP backend is the chunked upstream.
        let deploy = DeployStore::new(
            Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir())),
            Arc::new(MemoryKv::new()),
        );
        let cfg = SiteConfig {
            domains: DomainConfig {
                primary: Some("test.local".into()),
                ..Default::default()
            },
            gateway: Some(GatewayConfig {
                upstreams: std::iter::once((
                    "backend".to_string(),
                    Upstream {
                        target: format!("http://{up_addr}"),
                        ..Default::default()
                    },
                ))
                .collect(),
                routes: vec![GatewayRoute {
                    matches: "/**".into(),
                    upstream: "backend".into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        deploy
            .set_site_config(ProjectRef::DEFAULT, "www", &cfg)
            .await
            .unwrap();
        // The per-request re-verification ([`SplicePlan::reverify`]) re-runs the full
        // routing decision (host→site + manifest), so a manifest must be activated.
        let id = deploy.put_manifest(&Manifest::default()).await.unwrap();
        deploy
            .activate(ProjectRef::DEFAULT, "www", &id)
            .await
            .unwrap();

        let posture = SecurityProfile::Dev.preset();
        let resolved = proxy::resolve_target(
            &format!("http://{up_addr}"),
            proxy::GatewayTargetPolicy::Operator,
            &posture,
        )
        .await
        .unwrap();
        let plan = SplicePlan {
            resolved,
            upstream: Upstream {
                target: format!("http://{up_addr}"),
                ..Default::default()
            },
            site: "www".to_string(),
            project: ProjectRef::DEFAULT.as_str().to_string(),
            target: format!("http://{up_addr}"),
        };
        let ctx = SpliceCtx {
            deploy,
            posture,
            daemon: None,
            read_timeout: boatramp_http::h1::DEFAULT_READ_TIMEOUT,
        };

        // A client <-> `splice_conn` socket pair over loopback.
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let mut client = TcpStream::connect(front_addr).await.unwrap();
        let (server_side, peer) = front.accept().await.unwrap();
        let serve: crate::ServeInput = axum::Router::new().into();
        tokio::spawn(async move {
            let _ = splice_conn(server_side, peer, plan, ctx, serve).await;
        });

        // An HTTP/1.1 keep-alive client (no `Connection: close` — the exact repro).
        client
            .write_all(b"GET /page HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();

        // Read the response as a real HTTP/1.1 client would: framing comes from the
        // response head. Pre-fix the head carries neither `Transfer-Encoding` nor
        // `Content-Length` → close-delimited → the body read blocks until the connection
        // closes, which never happens → the timeout fires. Post-fix the head carries
        // `Transfer-Encoding: chunked` → the body de-chunks to a clean end.
        let read = timeout(Duration::from_secs(5), async move {
            let mut conn = boatramp_http::h1::Conn::new(client);
            let head = conn.read_response_head().await.unwrap();
            let mut reader = boatramp_http::h1::BodyReader::r#for(&axum::http::Method::GET, &head);
            let mut body = Vec::new();
            while let Some(chunk) = conn.read_body_chunk(&mut reader).await.unwrap() {
                body.extend_from_slice(&chunk);
            }
            (head, body)
        })
        .await;

        let (head, body) = read.expect(
            "chunked keep-alive upstream left the HTTP/1.1 client hanging \
             (no end-of-response was signalled)",
        );
        assert_eq!(head.status, axum::http::StatusCode::OK);
        // The response must be self-delimiting so a keep-alive client knows where the
        // body ends: the chunked framing must be preserved end to end.
        assert!(
            head.headers
                .contains_key(axum::http::header::TRANSFER_ENCODING),
            "Transfer-Encoding must be preserved so the client can delimit the chunked \
             body: {:?}",
            head.headers
        );
        assert_eq!(body, b"hello world", "de-chunked body mismatch");
    }

    /// Deploy a gateway site (host `test.local`, route `/**` → `up_addr`) + build a pinned
    /// [`SplicePlan`]/[`SpliceCtx`] for the cross-platform tests that drive `splice_conn`
    /// directly. (The per-request re-verification re-runs the full routing decision, so a
    /// resolvable host→site + an activated manifest are required.)
    async fn direct_plan_ctx(up_addr: SocketAddr) -> (SplicePlan, SpliceCtx) {
        use boatramp_core::config::{DomainConfig, SiteConfig};
        use boatramp_core::deploy::{DeployStore, Manifest};
        use boatramp_core::gateway::{GatewayConfig, GatewayRoute, Upstream};
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::security::SecurityProfile;

        let deploy = DeployStore::new(
            Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir())),
            Arc::new(MemoryKv::new()),
        );
        let cfg = SiteConfig {
            domains: DomainConfig {
                primary: Some("test.local".into()),
                ..Default::default()
            },
            gateway: Some(GatewayConfig {
                upstreams: std::iter::once((
                    "backend".to_string(),
                    Upstream {
                        target: format!("http://{up_addr}"),
                        ..Default::default()
                    },
                ))
                .collect(),
                routes: vec![GatewayRoute {
                    matches: "/**".into(),
                    upstream: "backend".into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        deploy
            .set_site_config(ProjectRef::DEFAULT, "www", &cfg)
            .await
            .unwrap();
        let id = deploy.put_manifest(&Manifest::default()).await.unwrap();
        deploy
            .activate(ProjectRef::DEFAULT, "www", &id)
            .await
            .unwrap();
        let posture = SecurityProfile::Dev.preset();
        let resolved = proxy::resolve_target(
            &format!("http://{up_addr}"),
            proxy::GatewayTargetPolicy::Operator,
            &posture,
        )
        .await
        .unwrap();
        let plan = SplicePlan {
            resolved,
            upstream: Upstream {
                target: format!("http://{up_addr}"),
                ..Default::default()
            },
            site: "www".to_string(),
            project: ProjectRef::DEFAULT.as_str().to_string(),
            target: format!("http://{up_addr}"),
        };
        let ctx = SpliceCtx {
            deploy,
            posture,
            daemon: None,
            read_timeout: boatramp_http::h1::DEFAULT_READ_TIMEOUT,
        };
        (plan, ctx)
    }

    /// Spawn `splice_conn` with `plan`/`ctx` behind a loopback socket pair; the fallback
    /// `serve` is an EMPTY router (so a request that falls back is answered 404, not proxied
    /// — letting a test tell "spliced to the upstream" apart from "fell back"). Returns the
    /// client end of the connection.
    async fn spawn_splice_conn(plan: SplicePlan, ctx: SpliceCtx) -> TcpStream {
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let client = TcpStream::connect(front_addr).await.unwrap();
        let (server_side, peer) = front.accept().await.unwrap();
        let serve: crate::ServeInput = axum::Router::new().into();
        tokio::spawn(async move {
            let _ = splice_conn(server_side, peer, plan, ctx, serve).await;
        });
        client
    }

    /// Reproduce-first (F-3, response-queue desync): a second response the upstream appends
    /// right after a chunked response's terminating 0-chunk must NOT be forwarded to the
    /// client as its next response (cross-user cache/response poisoning on a pooled conn).
    /// Pre-fix `relay_chunked` wrote the body prefix — which held the injected response — to
    /// the client *before* parsing, so the injection leaked through. The fix forwards EXACTLY
    /// up to the terminal chunk and closes on trailing bytes.
    #[tokio::test]
    async fn chunked_trailing_injected_response_is_not_forwarded_to_the_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    // A complete chunked response, then — in the SAME burst — an injected
                    // second response. A compliant proxy forwards only the first.
                    let resp: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
                        5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n\
                        HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nPWNEDPWNED";
                    let _ = s.write_all(resp).await;
                    // Hold the connection open (keep-alive), as a pooled origin would.
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let (plan, ctx) = direct_plan_ctx(up_addr).await;
        let mut client = spawn_splice_conn(plan, ctx).await;
        client
            .write_all(b"GET /p HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let read = timeout(Duration::from_secs(5), client.read_to_end(&mut out)).await;
        assert!(read.is_ok(), "client hung after the chunked response");
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("PWNED"),
            "an injected response appended after the 0-chunk leaked to the client (F-3): {text}"
        );
        // The legitimate chunked body is still delivered (framing forwarded verbatim).
        assert!(
            text.contains("hello") && text.contains("world"),
            "the legitimate chunked body was not delivered: {text}"
        );
    }

    /// Reproduce-first (F-1, OOM/unbounded buffer): a hostile upstream that opens an endless
    /// chunk-size line (hex digits, never a CRLF) must be failed closed at a bounded buffer,
    /// not buffered without limit. Pre-fix `relay_chunked` appended every byte to `pending`
    /// until a chunk completed — an unterminated size line grew it without bound. The fix
    /// caps the size-line/meta buffer and errors past it.
    #[tokio::test]
    async fn hostile_unbounded_chunk_size_line_is_bounded_not_buffered() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        let written = Arc::new(AtomicU64::new(0));
        let written_up = written.clone();
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                let written_up = written_up.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    if s.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // An endless chunk-size line: valid hex digits, never a CRLF. Bounded by
                    // a hard 8 MiB cap so the test terminates even if the proxy (buggily)
                    // keeps buffering.
                    let block = [b'a'; 8192];
                    let mut sent = 0u64;
                    while sent < 8 * 1024 * 1024 {
                        if s.write_all(&block).await.is_err() {
                            break; // the proxy closed the connection (bounded — the fix)
                        }
                        sent += block.len() as u64;
                        written_up.store(sent, Ordering::Relaxed);
                    }
                });
            }
        });

        let (plan, ctx) = direct_plan_ctx(up_addr).await;
        let mut client = spawn_splice_conn(plan, ctx).await;
        client
            .write_all(b"GET /p HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let read = timeout(Duration::from_secs(10), client.read_to_end(&mut out)).await;
        assert!(
            read.is_ok(),
            "client hung on a hostile unbounded chunk-size line"
        );
        // The forwarder must have failed closed after a BOUNDED read, closing the upstream —
        // not consumed/buffered the whole hostile stream. (The margin is generous to absorb
        // in-flight TCP send/receive buffering; the buggy path buffers the full 8 MiB.)
        let total = written.load(Ordering::Relaxed);
        assert!(
            total < 2 * 1024 * 1024,
            "the forwarder buffered an unbounded chunk-size line ({total} bytes) instead of \
             failing closed at the bound (F-1)"
        );
    }

    /// Reproduce-first (F-5, 1xx hang): a `1xx` interim upstream response (100/103) must be
    /// forwarded and the NEXT response read as the final one — never treated as the final
    /// (no CL/TE → close-delimited → hang on a keep-alive upstream). Pre-fix `head_only`
    /// only covered HEAD/204/304, so a 1xx fell into `relay_to_close` and hung.
    #[tokio::test]
    async fn interim_1xx_response_is_forwarded_then_the_final_is_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    // A 103 interim, then the final 200 — then HOLD the connection open
                    // (keep-alive). Pre-fix the 103 is framed as close-delimited and the
                    // relay waits forever for a close that never comes.
                    let resp: &[u8] =
                        b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>; rel=preload\r\n\r\n\
                        HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
                    let _ = s.write_all(resp).await;
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let (plan, ctx) = direct_plan_ctx(up_addr).await;
        let mut client = spawn_splice_conn(plan, ctx).await;
        client
            .write_all(b"GET /p HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let read = timeout(Duration::from_secs(5), client.read_to_end(&mut out)).await;
        assert!(
            read.is_ok(),
            "client hung — a 1xx interim response was mis-framed as the final (F-5)"
        );
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("103 Early Hints"),
            "the interim 1xx was not forwarded: {text}"
        );
        assert!(
            text.contains("200 OK") && text.contains("hello"),
            "the final response was not delivered after the 1xx: {text}"
        );
    }

    /// Reproduce-first (F-6, subsequent-request guard): the full header-framing guard must
    /// run on EVERY keep-alive request, so a `GET` carrying `Content-Length` on request #2
    /// is NOT spliced (it would forward the CL to the upstream with no body — a desync). It
    /// must fall back to the userspace router instead. Pre-fix request #2 re-checked only
    /// method + route and the CL was deemed eligible.
    #[tokio::test]
    async fn get_with_content_length_on_request_two_falls_back_not_spliced() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => {}
                        }
                        // A distinctive body so a test can tell an upstream (spliced) reply
                        // apart from a userspace-fallback (404) reply. Head + body in one
                        // write so the body is in-buffer (no kernel splice needed → the
                        // forwarder's framing logic runs on every target).
                        let _ = s
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nUPSTREAM-BODY",
                            )
                            .await;
                    }
                });
            }
        });

        let (plan, ctx) = direct_plan_ctx(up_addr).await;
        let mut client = spawn_splice_conn(plan, ctx).await;
        // Request 1: a clean GET — spliced to the upstream.
        client
            .write_all(b"GET /a HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();
        let r1 = read_one_response(&mut client).await;
        assert!(
            r1.contains("UPSTREAM-BODY"),
            "request 1 was not spliced to the upstream: {r1}"
        );
        // Request 2: a GET carrying a Content-Length — must fall back (not be spliced). CL:0
        // (no body) keeps `leftover` empty, so the header-framing guard in
        // `parse_fastpath_request` is the SOLE gate that must reject it (any declared length
        // is rejected the same way). The empty fallback router answers 404, so the reply is
        // NOT the upstream body.
        client
            .write_all(
                b"GET /b HTTP/1.1\r\nHost: test.local\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut rest = Vec::new();
        let read = timeout(Duration::from_secs(5), client.read_to_end(&mut rest)).await;
        assert!(read.is_ok(), "request 2 hung (desync)");
        let text = String::from_utf8_lossy(&rest);
        assert!(
            text.starts_with("HTTP/1.1 "),
            "request 2 got no HTTP response: {text}"
        );
        assert!(
            !text.contains("UPSTREAM-BODY"),
            "a GET with Content-Length was spliced to the upstream on request #2 (F-6): {text}"
        );
    }

    /// Regression (real serve path, Linux): the whole plaintext fast-path — `serve` →
    /// `peek_classify`/`classify` → `splice_conn` — must stream a chunked keep-alive
    /// upstream to an HTTP/1.1 keep-alive client without hanging. Gated to Linux because
    /// the classifier only intercepts where kernel `splice()` is available; on every other
    /// target each connection takes the (already-correct) userspace serve fallback, so this
    /// exact production path is Linux-only. (The cross-platform seam coverage is
    /// [`chunked_keepalive_upstream_does_not_hang_the_client`], which drives `splice_conn`
    /// directly.)
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn serve_loop_streams_a_chunked_keepalive_upstream_without_hanging() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // A chunked keep-alive upstream that never closes (holds the connection open after
        // the response, as a real keep-alive origin does).
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    let resp: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
                                        5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
                    if s.write_all(resp).await.is_err() {
                        return;
                    }
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let addr = spawn_gateway_serve(up_addr).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        // HTTP/1.1 keep-alive (no `Connection: close` — the exact reported repro).
        client
            .write_all(b"GET /anything HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();
        let read = timeout(Duration::from_secs(5), async move {
            let mut conn = boatramp_http::h1::Conn::new(client);
            let head = conn.read_response_head().await.unwrap();
            let mut reader = boatramp_http::h1::BodyReader::r#for(&axum::http::Method::GET, &head);
            let mut body = Vec::new();
            while let Some(chunk) = conn.read_body_chunk(&mut reader).await.unwrap() {
                body.extend_from_slice(&chunk);
            }
            (head, body)
        })
        .await;
        let (head, body) =
            read.expect("serve loop hung streaming a chunked keep-alive upstream over keep-alive");
        assert_eq!(head.status, axum::http::StatusCode::OK);
        assert!(
            head.headers
                .contains_key(axum::http::header::TRANSFER_ENCODING),
            "Transfer-Encoding must be preserved end to end: {:?}",
            head.headers
        );
        assert_eq!(body, b"hello world", "de-chunked body mismatch");
    }

    /// End-to-end over real sockets: the serve loop reverse-proxies a gateway route
    /// (spliced on Linux, userspace-proxied elsewhere — same bytes) and defers a
    /// reserved control-plane route to the app router. Exercises `serve`,
    /// `peek_classify`, `classify`, `splice_conn`/`splice_body`, and `serve_fallback`.
    #[tokio::test]
    async fn serve_loop_proxies_gateway_and_defers_reserved_routes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A tiny keep-alive upstream returning a fixed Content-Length body.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => {}
                        }
                        let body = b"hello-from-upstream";
                        let head =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        if s.write_all(head.as_bytes()).await.is_err()
                            || s.write_all(body).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let addr = spawn_gateway_serve(up_addr).await;

        async fn req(addr: SocketAddr, raw: &str) -> String {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(raw.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            c.read_to_end(&mut out).await.unwrap();
            String::from_utf8_lossy(&out).into_owned()
        }

        // A gateway-routed GET is reverse-proxied — the upstream body reaches the client.
        let resp = req(
            addr,
            "GET /anything HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("hello-from-upstream"),
            "proxy body missing: {resp}"
        );
        // A reserved control-plane route is served by the app router, not proxied.
        let hz = req(
            addr,
            "GET /healthz HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            hz.starts_with("HTTP/1.1 200") && hz.to_ascii_lowercase().contains("ok"),
            "healthz fallback: {hz}"
        );
    }

    /// Stand up a `serve` loop in front of a deployed gateway site `www` (host
    /// `test.local`, route `/**`) that reverse-proxies to `up_addr`. Returns the
    /// client-facing address. Shared by the serve-loop tests below.
    async fn spawn_gateway_serve(up_addr: SocketAddr) -> SocketAddr {
        use boatramp_core::config::{DomainConfig, SiteConfig};
        use boatramp_core::deploy::{DeployStore, Manifest};
        use boatramp_core::gateway::{GatewayConfig, GatewayRoute, Upstream};
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::security::SecurityProfile;

        // Blob storage is unused on the gateway path (an empty manifest); an
        // FsStorage under the temp dir is a convenient no-touch backend.
        let deploy = DeployStore::new(
            Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir())),
            Arc::new(MemoryKv::new()),
        );
        let cfg = SiteConfig {
            domains: DomainConfig {
                primary: Some("test.local".into()),
                ..Default::default()
            },
            gateway: Some(GatewayConfig {
                upstreams: std::iter::once((
                    "backend".to_string(),
                    Upstream {
                        target: format!("http://{up_addr}"),
                        ..Default::default()
                    },
                ))
                .collect(),
                routes: vec![GatewayRoute {
                    matches: "/**".into(),
                    upstream: "backend".into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        deploy
            .set_site_config(ProjectRef::DEFAULT, "www", &cfg)
            .await
            .unwrap();
        let id = deploy.put_manifest(&Manifest::default()).await.unwrap();
        deploy
            .activate(ProjectRef::DEFAULT, "www", &id)
            .await
            .unwrap();

        let posture = SecurityProfile::Dev.preset();
        // The dev posture must be on the router too, so the userspace fallback path
        // (used off Linux, where splice is unavailable) also permits the loopback
        // upstream — the tests then exercise the same routing on every target.
        let router = crate::router_with(
            deploy.clone(),
            crate::Auth::disabled(),
            crate::HandlerRuntime::disabled(),
            crate::ServerOptions {
                posture,
                ..Default::default()
            },
        );
        let ctx = SpliceCtx {
            deploy,
            posture,
            daemon: None,
            read_timeout: boatramp_http::h1::DEFAULT_READ_TIMEOUT,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(listener, ctx, router, std::future::pending::<()>()).await;
        });
        addr
    }

    /// Read exactly one HTTP/1.1 response (head + `Content-Length` body) off `c`,
    /// so a keep-alive connection can carry a follow-up request without the reader
    /// blocking forever on a socket that stays open.
    async fn read_one_response(c: &mut TcpStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let head_end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            let n = c.read(&mut tmp).await.unwrap();
            if n == 0 {
                return String::from_utf8_lossy(&buf).into_owned();
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let content_length = String::from_utf8_lossy(&buf[..head_end])
            .to_ascii_lowercase()
            .split("\r\n")
            .find_map(|l| l.strip_prefix("content-length:").map(str::to_owned))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < head_end + content_length {
            let n = c.read(&mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Regression (chaos): if the upstream announces a `Content-Length` then closes
    /// before delivering it, the client connection must be *closed* — signalling the
    /// truncation — never left blocked waiting for bytes that will never arrive. A
    /// fault-injection run once hung the client here for 5s; this guards the
    /// `splice_body` early-EOF fix on Linux and the userspace fallback elsewhere.
    #[tokio::test]
    async fn upstream_dying_mid_body_closes_the_client_instead_of_hanging() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // Upstream: promise 1 MiB, deliver 16 bytes, then vanish.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\ntruncated-body!!",
                        )
                        .await;
                    // Drop `s`: the upstream closes still owing 1 MiB - 16 bytes.
                });
            }
        });

        let addr = spawn_gateway_serve(up_addr).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET /anything HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        // The property under test: this completes (peer closed); it must NOT hang.
        let read = timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
        assert!(
            read.is_ok(),
            "client was left hanging after the upstream truncated the body"
        );
        // On the splice path the partial bytes are deterministically relayed before
        // the close (the fallback may reset without flushing, so gate this to Linux).
        #[cfg(target_os = "linux")]
        {
            let text = String::from_utf8_lossy(&out);
            assert!(
                text.contains("truncated-body!!"),
                "splice path must relay the partial body before closing: {text}"
            );
        }
    }

    /// Regression (chaos): after a GET is served on the fast path, a follow-up
    /// request on the same keep-alive connection that is *not* splice-eligible (a
    /// POST) must not be dropped — the connection rewinds into the userspace
    /// fallback and the request still gets a real HTTP response. Guards the
    /// mid-connection `Rewind` handoff.
    #[tokio::test]
    async fn non_eligible_request_after_spliced_get_falls_back_not_dropped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // Keep-alive upstream returning a fixed-length body for every request.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => {}
                        }
                        let body = b"ok";
                        let head =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        if s.write_all(head.as_bytes()).await.is_err()
                            || s.write_all(body).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let addr = spawn_gateway_serve(up_addr).await;
        let mut c = TcpStream::connect(addr).await.unwrap();

        // 1) A splice-eligible GET (keep-alive: no Connection: close).
        c.write_all(b"GET /anything HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();
        let first = read_one_response(&mut c).await;
        assert!(
            first.starts_with("HTTP/1.1 200"),
            "GET not proxied: {first}"
        );

        // 2) A POST on the SAME connection is not splice-eligible → it must fall
        //    back, not be silently dropped. Require *a* status line back in bound.
        c.write_all(b"POST /anything HTTP/1.1\r\nHost: test.local\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut rest = Vec::new();
        let read = timeout(Duration::from_secs(5), c.read_to_end(&mut rest)).await;
        assert!(
            read.is_ok(),
            "POST after a spliced GET was dropped (client hung)"
        );
        let text = String::from_utf8_lossy(&rest);
        assert!(
            text.starts_with("HTTP/1.1 "),
            "POST after a spliced GET got no HTTP response: {text}"
        );
    }

    /// Reproduce-first (N-1, slow-loris keep-alive DoS): once a connection is served, the
    /// per-request client head read on keep-alive request #2+ must be bounded by the read
    /// timeout. A client that completes one valid eligible GET then dribbles request #2 (a
    /// partial head, then silence) must be CLOSED after ~the timeout — not left pinning the
    /// client socket, the pinned upstream connection, and this task indefinitely. Pre-fix
    /// `read_head(&mut client)` awaited with no timeout (only request #1's non-consuming peek
    /// was bounded, by `PEEK_TIMEOUT`), so request #2's read hung forever.
    ///
    /// Drives `splice_conn` directly (the client head read is userspace on every target, not
    /// only where kernel `splice()` engages), with a short injected `read_timeout` so the
    /// assertion is a tight wall-clock bound: pre-fix the read never returns and the outer
    /// timeout fires; post-fix the connection closes ~`read_timeout` after the stall.
    #[tokio::test]
    async fn slowloris_keepalive_request_two_is_closed_by_the_read_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // A keep-alive upstream: head+body in one write (no kernel splice needed → the
        // forwarder runs on every target) and holds the connection open between requests.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => {}
                        }
                        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let (plan, mut ctx) = direct_plan_ctx(up_addr).await;
        // A short idle read timeout so the test is a tight wall-clock bound (production uses
        // DEFAULT_READ_TIMEOUT; the value is just threaded through).
        ctx.read_timeout = Duration::from_millis(500);
        let mut client = spawn_splice_conn(plan, ctx).await;

        // Request 1: a clean keep-alive GET (no `Connection: close`) — served, loop returns
        // to the (now-bounded) client head read for request #2.
        client
            .write_all(b"GET /a HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();
        let r1 = read_one_response(&mut client).await;
        assert!(r1.contains("ok"), "request 1 was not served: {r1}");

        // Request 2: dribble a PARTIAL head (no terminating CRLFCRLF), then stall forever.
        client
            .write_all(b"GET /b HTTP/1.1\r\nHost: test.local\r\n")
            .await
            .unwrap();
        // The property under test: the connection is closed by the read timeout (read_to_end
        // completes) rather than hanging. Pre-fix this read_to_end never returns → the outer
        // timeout fires → `read.is_err()` → the assert fails (the reproduce-first witness).
        let mut rest = Vec::new();
        let read = timeout(Duration::from_secs(5), client.read_to_end(&mut rest)).await;
        assert!(
            read.is_ok(),
            "a slow-loris keep-alive request #2 was NOT closed by the read timeout — the \
             client/upstream/task are pinned indefinitely (N-1)"
        );
    }

    /// Reproduce-first (N-5, stalled-upstream hang, same class): a non-conformant (trusted)
    /// upstream that sends a no-Content-Length (close-delimited) response head + a partial
    /// body then holds the connection open forever — never sending EOF — must be bounded by
    /// the idle read timeout, failing closed (closing the client) rather than pinning the
    /// forwarder task. Pre-fix `forward_to_close` used an unbounded `tokio::io::copy` that
    /// waits for an upstream EOF that never comes.
    ///
    /// Drives `splice_conn` directly (the close-delimited relay is userspace on every target).
    #[tokio::test]
    async fn stalled_close_delimited_upstream_is_closed_by_the_read_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // Upstream: a close-delimited response (no CL, no TE, no `Connection: close`) with a
        // partial body, then HOLD the connection open forever (never close, never send more).
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial-body",
                        )
                        .await;
                    // Never close, never send the rest — a stalled close-delimited origin.
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let (plan, mut ctx) = direct_plan_ctx(up_addr).await;
        ctx.read_timeout = Duration::from_millis(500);
        let mut client = spawn_splice_conn(plan, ctx).await;
        client
            .write_all(b"GET /p HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        // Pre-fix `forward_to_close` waits for an upstream EOF that never arrives → the client
        // read_to_end hangs → the outer timeout fires. Post-fix the idle read timeout closes
        // the connection ~`read_timeout` after the stall.
        let read = timeout(Duration::from_secs(5), client.read_to_end(&mut out)).await;
        assert!(
            read.is_ok(),
            "a stalled close-delimited upstream left the forwarder (and the client) hanging — \
             no idle read timeout on the upstream leg (N-5)"
        );
        // The partial body it DID send is forwarded before the fail-closed close.
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("partial-body"),
            "the partial close-delimited body was not forwarded before closing: {text}"
        );
    }

    /// Reproduce-first (N-5 last sibling, fixed-length splice stall): a trusted upstream that
    /// declares `Content-Length: N`, delivers part of the body, then holds the connection open
    /// sending nothing more (never closing) must be bounded by the idle read timeout on the
    /// splice fast-path's own upstream-readable wait — the client is CLOSED ~`read_timeout`
    /// after the stall, not pinned forever. This is the Content-Length kernel-`splice()`
    /// zero-copy path (`forward_length` → `splice_body`); pre-fix its `async_io(READABLE)`
    /// readiness wait had NO timeout (the N-1/N-5 fix bounded every other upstream read but
    /// deliberately left this perf-critical path), so the splice awaited the promised bytes
    /// forever.
    ///
    /// Linux-only: this exercises the real kernel `splice()` move (off Linux the move is
    /// unsupported and the path is never reached). Drives `splice_conn` directly with a short
    /// injected `read_timeout` so the assertion is a tight wall-clock bound.
    ///
    /// Mutation proof: revert the `tokio::time::timeout(..)` wrap around the `READABLE` wait in
    /// `splice_body` and this `read_to_end` never returns → the outer 5s timeout fires →
    /// `read.is_err()` → the assertion fails (the test hangs to its outer bound).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stalled_length_splice_upstream_is_closed_by_the_read_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};

        // Upstream: declare a 1 MiB Content-Length, deliver a 12-byte partial body, then HOLD
        // the connection open forever — never close, never send the remaining ~1 MiB. The
        // forwarder drains the 12 buffered bytes and enters `splice_body` for the remainder,
        // which is where the (pre-fix unbounded) upstream-readable wait stalls.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\npartial-body",
                        )
                        .await;
                    // Never close, never send the rest — a stalled fixed-length origin.
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let (plan, mut ctx) = direct_plan_ctx(up_addr).await;
        // A short idle read timeout so the test is a tight wall-clock bound (production uses
        // DEFAULT_READ_TIMEOUT; the value is just threaded through to `splice_body`).
        ctx.read_timeout = Duration::from_millis(500);
        let mut client = spawn_splice_conn(plan, ctx).await;
        client
            .write_all(b"GET /p HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        // The property under test: the client is closed by the idle timeout (read_to_end
        // completes) rather than hanging forever waiting for the promised 1 MiB.
        let read = timeout(Duration::from_secs(5), client.read_to_end(&mut out)).await;
        assert!(
            read.is_ok(),
            "a stalled fixed-length (Content-Length) upstream left the splice fast-path (and the \
             client) hanging — no idle read timeout on the splice upstream-readable wait (N-5 \
             sibling)"
        );
        // The partial body it DID send is forwarded before the fail-closed close.
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("partial-body"),
            "the partial fixed-length body was not forwarded before closing: {text}"
        );
    }

    /// No-regression (fixed-length splice to completion + keep-alive reuse): a full
    /// `Content-Length` body larger than the buffered prefix is moved end-to-end through the
    /// kernel-`splice()` zero-copy path, and the connection is REUSED for a second request.
    /// Guards that the idle-timeout wrap does not disturb the normal full-body CL path.
    ///
    /// Linux-only: exercises the real kernel `splice()` move. Uses the production
    /// `DEFAULT_READ_TIMEOUT` (the transfer makes continuous progress → the idle timeout never
    /// fires).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn full_length_body_splices_to_completion_and_keepalive_reuse_works() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const BODY: usize = 100 * 1024; // 100 KiB: exceeds the fill buffer → the splice path runs

        // Keep-alive upstream: a full fixed-length body per request, connection held open.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        // Read one full request head, then answer.
                        loop {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                                Ok(_) => break,
                            }
                        }
                        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\n\r\n");
                        let body = vec![b'x'; BODY];
                        if s.write_all(head.as_bytes()).await.is_err()
                            || s.write_all(&body).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let (plan, ctx) = direct_plan_ctx(up_addr).await; // production DEFAULT_READ_TIMEOUT
        let mut client = spawn_splice_conn(plan, ctx).await;

        // Request 1 (keep-alive: no `Connection: close`) — full body spliced to completion.
        client
            .write_all(b"GET /a HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();
        let r1 = read_one_response(&mut client).await;
        assert!(
            r1.starts_with("HTTP/1.1 200"),
            "request 1 not served: {:.80}",
            r1
        );
        let body1 = &r1[r1.find("\r\n\r\n").unwrap() + 4..];
        assert_eq!(
            body1.len(),
            BODY,
            "request 1 body was not spliced to completion ({} of {BODY} bytes)",
            body1.len()
        );

        // Request 2 on the SAME connection — the keep-alive reuse path after a clean splice.
        client
            .write_all(b"GET /b HTTP/1.1\r\nHost: test.local\r\n\r\n")
            .await
            .unwrap();
        let r2 = read_one_response(&mut client).await;
        assert!(
            r2.starts_with("HTTP/1.1 200"),
            "request 2 not served: {:.80}",
            r2
        );
        let body2 = &r2[r2.find("\r\n\r\n").unwrap() + 4..];
        assert_eq!(
            body2.len(),
            BODY,
            "request 2 body (keep-alive reuse) was not spliced to completion ({} of {BODY} bytes)",
            body2.len()
        );
    }

    /// No-regression (slow-but-progressing fixed-length splice): a transfer that makes steady
    /// progress — each slice well within the idle window, but the WHOLE transfer taking longer
    /// than the idle window — must complete untruncated. This proves the splice idle timeout is
    /// reset on every `splice()` that moves bytes (per-read idle), NOT a bound on total transfer
    /// duration: a genuinely slow-but-progressing upstream is never affected.
    ///
    /// Linux-only: exercises the real kernel `splice()` move. `read_timeout` is 400 ms; the
    /// upstream sends eight 8 KiB slices with 120 ms gaps (each gap < 400 ms, total ≈ 1 s >
    /// 400 ms) — so a (buggy) total-duration bound would time out mid-transfer and truncate.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn slow_but_progressing_length_splice_is_not_timed_out() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, sleep, timeout};

        const SLICE: usize = 8 * 1024;
        const SLICES: usize = 8;
        const BODY: usize = SLICE * SLICES; // 64 KiB

        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => continue,
                            Ok(_) => break,
                        }
                    }
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\n\r\n");
                    if s.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let slice = vec![b'y'; SLICE];
                    for _ in 0..SLICES {
                        // Gap before each slice: < read_timeout individually, but the sum of
                        // the gaps exceeds read_timeout — only a per-read idle reset survives.
                        sleep(Duration::from_millis(120)).await;
                        if s.write_all(&slice).await.is_err() {
                            return;
                        }
                    }
                    // Hold open; the client sent `Connection: close`, so the forwarder closes.
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let (plan, mut ctx) = direct_plan_ctx(up_addr).await;
        ctx.read_timeout = Duration::from_millis(400);
        let mut client = spawn_splice_conn(plan, ctx).await;
        client
            .write_all(b"GET /s HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let read = timeout(Duration::from_secs(10), client.read_to_end(&mut out)).await;
        assert!(read.is_ok(), "slow-but-progressing splice transfer hung");
        let text = String::from_utf8_lossy(&out);
        let body_len = text.len() - (text.find("\r\n\r\n").unwrap() + 4);
        assert_eq!(
            body_len, BODY,
            "a slow-but-progressing fixed-length body was truncated ({body_len} of {BODY} bytes) — \
             the splice idle timeout must reset on each splice() that moves bytes, not bound the \
             total transfer duration"
        );
    }

    // ---- property-based fuzzing of the fast-path parsers --------------------
    // The fast-path is default-on, so its byte parsers must be panic-free on
    // adversarial input, and must never let a request/response through in a way
    // that could desync the upstream (HTTP request smuggling).
    proptest::proptest! {
        #[test]
        fn parsers_never_panic_on_arbitrary_bytes(data: Vec<u8>) {
            // The only requirement: no panic / no hang on any input.
            let _ = parse_fastpath_request(&data);
            let _ = parse_chunk_size_line(&data);
            let _ = find_head_end(&data);
        }

        #[test]
        fn parsers_never_panic_on_arbitrary_ascii(s in ".{0,4096}") {
            let _ = parse_fastpath_request(s.as_bytes());
            let _ = parse_chunk_size_line(s.as_bytes());
        }

        // Desync guard (F-2): any response advertising BOTH Content-Length and chunked
        // Transfer-Encoding is REJECTED outright (fail closed) — never resolved to a
        // forwardable framing a downstream could re-interpret.
        #[test]
        fn cl_plus_te_response_is_rejected(len in 0u64..1_000_000) {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            let resp = final_resp(head.as_bytes());
            proptest::prop_assert!(
                resolve_response_framing(resp.status, &Method::GET, &resp.headers).is_err(),
                "CL+TE must be rejected (desync guard)"
            );
        }

        // A well-formed GET head always round-trips its method + target through the
        // hardened fast-path parser.
        #[test]
        fn wellformed_get_head_roundtrips(path in "/[a-zA-Z0-9_/.-]{0,64}", host in "[a-z][a-z0-9.-]{0,32}") {
            let head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n");
            let parsed = parse_fastpath_request(head.as_bytes());
            proptest::prop_assert!(parsed.is_some());
            let req = parsed.unwrap();
            proptest::prop_assert_eq!(req.method, Method::GET);
            proptest::prop_assert_eq!(&req.target, &path);
            proptest::prop_assert_eq!(req.headers.get(http::header::HOST).unwrap().as_bytes(), host.as_bytes());
        }
    }
}
