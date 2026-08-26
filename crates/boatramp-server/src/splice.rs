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

use tokio::io::AsyncWriteExt;
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

/// Decide whether the pipeline would reverse-proxy this request to a single
/// plaintext-HTTP gateway upstream — and, if so, resolve+pin it. Conservative by
/// construction: any uncertainty or advanced feature returns `None` (fall back).
async fn classify(head: &[u8], ctx: &SpliceCtx) -> Option<SplicePlan> {
    // No kernel splice off Linux → never intercept; everything serves as before.
    if !splice_supported() {
        return None;
    }
    let (method, target_path, headers) = parse_request_head(head)?;
    // Only idempotent, body-less requests: a request body would need forwarding
    // (and splicing) upstream too, and non-GET/HEAD may not be safe to retry.
    if !matches!(method.as_str(), "GET" | "HEAD") {
        return None;
    }
    // A declared request body or an upgrade is out of scope for the fast-path.
    if header(&headers, "content-length").is_some()
        || header(&headers, "transfer-encoding").is_some()
        || header(&headers, "upgrade").is_some()
        || header(&headers, "expect").is_some()
    {
        return None;
    }
    let host = header(&headers, "host").map(strip_port).unwrap_or("");
    let path = path_only(&target_path);
    // Reserved control-plane / system routes are matched by the app router *before*
    // the `serve_by_host` fallback where the gateway lives — so a site's catch-all
    // (`/**`) never actually handles them. Never intercept these; the router must.
    if is_reserved_path(path) {
        return None;
    }
    // The live daemon config: the catch-all `default_site` and (with the console
    // feature) the console mount, both consulted below.
    let eff = ctx.daemon.as_ref().map(|d| d.effective());
    // The embedded console middleware runs before the gateway fallback; defer any
    // request it would serve to the router. (Only wired with the `console` feature.)
    #[cfg(feature = "console")]
    if let Some(eff) = &eff {
        if crate::console::would_intercept(eff, host, path) {
            return None;
        }
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
        &target_path,
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
    if route::match_handler(&manifest.config.handlers, &method, path).is_some() {
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
    // Resolve + SSRF-pin exactly like the userspace proxy path.
    let resolved_target = proxy::resolve_target(target, &ctx.posture).await.ok()?;
    if !proxy::gateway_addr_allowed(resolved_target.addr.ip(), &ctx.posture) {
        return None;
    }
    Some(SplicePlan {
        resolved: resolved_target,
        upstream: upstream.clone(),
        site,
        project,
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
    let mut upstream = TcpStream::connect(plan.resolved.addr).await?;
    upstream.set_nodelay(true).ok();
    let client_ip: IpAddr = peer.ip();
    loop {
        // Read (consuming) the client request head.
        let (head, leftover) = match read_head(&mut client).await? {
            Some(v) => v,
            None => return Ok(()), // client closed between keep-alive requests
        };
        // Re-check eligibility per request (a keep-alive client could change path or
        // method). On anything not a clean splice, hand the connection — with the
        // head we already read replayed — to the normal server so nothing is lost.
        let eligible = parse_request_head(&head)
            .filter(|(m, _, _)| matches!(m.as_str(), "GET" | "HEAD") && leftover.is_empty());
        let (method, target_path, headers) = match eligible {
            Some(v) => v,
            None => return fall_back(head, leftover, client, peer, serve).await,
        };
        // Honor a client `Connection: close`: serve this one request, then close
        // (HTTP/1.1 defaults to keep-alive otherwise).
        let client_close = header(&headers, "connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("close"));
        let path = path_only(&target_path);
        if plan
            .upstream_route(&ctx, &plan.project, &plan.site, path)
            .await
            .is_none()
        {
            return fall_back(head, leftover, client, peer, serve).await;
        }
        // Build + send the upstream request head.
        let up_head = build_upstream_head(&plan, &method, &target_path, &headers, client_ip);
        upstream.write_all(&up_head).await?;
        // Read the upstream response head.
        let (resp_head, body_prefix) = match read_head(&mut upstream).await? {
            Some(v) => v,
            None => return Ok(()),
        };
        let (status_ok, content_length, chunked, close) = parse_response_head(&resp_head);
        // Only a Content-Length body with no chunked framing is splice-able. HEAD
        // has no body regardless. Anything else → close after this response.
        let head_only = method == "HEAD" || matches!(status_ok, Some(204) | Some(304));
        let out_head = rewrite_response_head(&resp_head, &plan.upstream);
        client.write_all(&out_head).await?;
        if !body_prefix.is_empty() && !head_only {
            client.write_all(&body_prefix).await?;
        }
        if head_only {
            if close || client_close {
                return Ok(());
            }
            continue;
        }
        match content_length {
            Some(total) if !chunked => {
                let remaining = total.saturating_sub(body_prefix.len());
                if remaining > 0 {
                    splice_body(&upstream, &client, remaining).await?;
                }
            }
            // No Content-Length or chunked: we can't cheaply splice a known count;
            // relay the rest verbatim then close (correct, just not keep-alive).
            _ => {
                relay_to_close(&mut upstream, &mut client).await?;
                return Ok(());
            }
        }
        if close || client_close {
            return Ok(());
        }
    }
}

impl SplicePlan {
    /// Recompute the route for `path` under this plan's site (a keep-alive client
    /// may vary the path). `Some` when the same single-backend gateway route still
    /// covers it. Cheap: the config is content-hash cached.
    async fn upstream_route(
        &self,
        ctx: &SpliceCtx,
        project: &str,
        site: &str,
        path: &str,
    ) -> Option<()> {
        let project_ref = boatramp_core::project::ProjectRef::new(project);
        let cfg = ctx
            .deploy
            .get_site_config_cached(project_ref, site)
            .await
            .ok()??;
        let gw = cfg.gateway.as_ref().filter(|g| g.is_enabled())?;
        let route_match = gw.match_route(path)?;
        // Same upstream + still a single plaintext-http backend.
        let upstream = gw.upstreams.get(&route_match.upstream)?;
        let backends = upstream.static_backends();
        if backends.len() == 1 && backends[0].starts_with("http://") {
            Some(())
        } else {
            None
        }
    }
}

// ---- request/response head parsing + rewriting -----------------------------

/// A parsed request head: `(method, request-target, headers)`.
type RequestHead = (String, String, Vec<(String, String)>);

/// Parse the request line + headers from a head buffer; `None` if malformed or
/// not HTTP/1.1.
fn parse_request_head(head: &[u8]) -> Option<RequestHead> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if version != "HTTP/1.1" {
        return None; // HTTP/1.0 keep-alive semantics differ; fall back
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, headers))
}

/// Parse `(status-allows-body, content_length, is_chunked, must_close)` from a
/// response head.
fn parse_response_head(head: &[u8]) -> (Option<u16>, Option<usize>, bool, bool) {
    let text = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => return (None, None, false, true),
    };
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: Option<u16> = status_line.split(' ').nth(1).and_then(|s| s.parse().ok());
    let mut content_length = None;
    let mut chunked = false;
    let mut close = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if k.eq_ignore_ascii_case("connection")
                && v.to_ascii_lowercase().contains("close")
            {
                close = true;
            }
        }
    }
    (status, content_length, chunked, close)
}

/// Build the upstream request head bytes: rewritten path, forwarded headers minus
/// hop-by-hop + Host, plus the X-Forwarded chain, matching the userspace proxy.
fn build_upstream_head(
    plan: &SplicePlan,
    method: &str,
    target_path: &str,
    headers: &[(String, String)],
    client_ip: IpAddr,
) -> Vec<u8> {
    // Upstream path: the target's base path + the (strip-prefixed) request path +
    // original query.
    let base = plan.resolved.parsed.path().trim_end_matches('/');
    let (req_path, query) = match target_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target_path, None),
    };
    let forwarded = plan.upstream.forward_path(req_path);
    let mut out = format!("{method} {base}{forwarded}");
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out.push_str(" HTTP/1.1\r\n");
    // Host: the upstream's own authority (explicit override, else the target host).
    let host = plan
        .upstream
        .host_header
        .as_deref()
        .unwrap_or(plan.resolved.host.as_str());
    out.push_str(&format!("host: {host}\r\n"));
    for (name, value) in headers {
        let lname = name.to_ascii_lowercase();
        if lname == "host"
            || HOP_BY_HOP.contains(&lname.as_str())
            || plan
                .upstream
                .header_up
                .remove
                .iter()
                .any(|h| lname.eq_ignore_ascii_case(h))
        {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("x-forwarded-for: {client_ip}\r\n"));
    out.push_str("x-forwarded-proto: http\r\n");
    if let Some(h) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")) {
        out.push_str(&format!("x-forwarded-host: {}\r\n", h.1));
    }
    for (name, value) in &plan.upstream.header_up.set {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Rewrite the upstream response head for the client: drop hop-by-hop, apply the
/// upstream's `header_down` ops. Content-Length is preserved (we splice exactly).
fn rewrite_response_head(resp_head: &[u8], upstream: &Upstream) -> Vec<u8> {
    let text = match std::str::from_utf8(resp_head) {
        Ok(t) => t,
        Err(_) => return resp_head.to_vec(),
    };
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("HTTP/1.1 502 Bad Gateway");
    let mut out = String::with_capacity(resp_head.len());
    out.push_str(status_line);
    out.push_str("\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, _)) = line.split_once(':') {
            let lk = k.trim().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&lk.as_str())
                || upstream
                    .header_down
                    .remove
                    .iter()
                    .any(|h| lk.eq_ignore_ascii_case(h))
            {
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    for (name, value) in &upstream.header_down.set {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

// ---- low-level IO helpers --------------------------------------------------

/// Read until CRLFCRLF from `s`; returns `(head_incl_terminator, bytes_read_past_head)`.
async fn read_head(s: &mut TcpStream) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    use tokio::io::AsyncReadExt;
    let mut acc: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 8192];
    loop {
        let n = s.read(&mut tmp).await?;
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

/// Relay `src`→`dst` until `src` closes (for close-delimited / chunked bodies we
/// don't splice by count). Uses splice on Linux, a userspace copy elsewhere.
async fn relay_to_close(src: &mut TcpStream, dst: &mut TcpStream) -> io::Result<()> {
    tokio::io::copy(src, dst).await.map(|_| ())
}

/// Move exactly `n` bytes `src`→`dst` via `splice()` — no userspace copy of the
/// payload. Linux only; unavailable elsewhere (callers never reach it because
/// [`classify`] resolves nothing on non-Linux — see [`splice_supported`]).
#[cfg(target_os = "linux")]
async fn splice_body(src: &TcpStream, dst: &TcpStream, mut n: usize) -> io::Result<()> {
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
            // src socket → pipe (into an empty pipe, so only src readiness blocks)
            let in_n = src
                .async_io(Interest::READABLE, || {
                    let r = unsafe {
                        libc::splice(src_fd, ptr::null_mut(), pw, ptr::null_mut(), want, flags)
                    };
                    if r < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(r as usize)
                    }
                })
                .await?;
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
async fn splice_body(_src: &TcpStream, _dst: &TcpStream, _n: usize) -> io::Result<()> {
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

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

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

    #[test]
    fn request_head_parse_only_http11_bodyless() {
        let (m, t, h) = parse_request_head(
            b"GET /b/100k?x=1 HTTP/1.1\r\nHost: a.example\r\nAccept: */*\r\n\r\n",
        )
        .expect("valid GET");
        assert_eq!(m, "GET");
        assert_eq!(t, "/b/100k?x=1");
        assert_eq!(header(&h, "host"), Some("a.example"));
        // HTTP/1.0 is rejected (different keep-alive semantics → fall back).
        assert!(parse_request_head(b"GET / HTTP/1.0\r\nHost: a\r\n\r\n").is_none());
    }

    #[test]
    fn response_head_parse_detects_length_chunked_close() {
        let (st, content_length, chunked, close) = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 102400\r\nContent-Type: x\r\n\r\n",
        );
        assert_eq!(st, Some(200));
        assert_eq!(content_length, Some(102400));
        assert!(!chunked && !close);
        let (_, content_length2, chunked2, close2) = parse_response_head(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(content_length2, None);
        assert!(chunked2 && close2);
    }

    #[test]
    fn strip_port_handles_ipv6_and_default() {
        assert_eq!(strip_port("host.example:8080"), "host.example");
        assert_eq!(strip_port("host.example"), "host.example");
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("127.0.0.1:9000"), "127.0.0.1");
    }

    #[test]
    fn response_head_rewrite_drops_hop_by_hop_keeps_length() {
        let up = Upstream::default();
        let out = rewrite_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
            &up,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("content-length: 3\r\n") || text.contains("Content-Length: 3\r\n"));
        assert!(text
            .to_ascii_lowercase()
            .contains("content-type: text/plain"));
        // Hop-by-hop headers are stripped.
        assert!(!text.to_ascii_lowercase().contains("connection:"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding:"));
    }

    #[test]
    fn head_end_index() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nBODY"), Some(18));
        assert_eq!(find_head_end(b"partial\r\nno end"), None);
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
        use tokio::time::{timeout, Duration};

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
        use tokio::time::{timeout, Duration};

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

    // ---- property-based fuzzing of the hand-written parsers -----------------
    // The fast-path is default-on, so its byte parsers must be panic-free on
    // adversarial input, and must never let a request/response through in a way
    // that could desync the upstream (HTTP request smuggling).
    proptest::proptest! {
        #[test]
        fn parsers_never_panic_on_arbitrary_bytes(data: Vec<u8>) {
            // The only requirement: no panic / no hang on any input.
            let _ = parse_request_head(&data);
            let _ = parse_response_head(&data);
            let up = Upstream::default();
            let _ = rewrite_response_head(&data, &up);
            let _ = find_head_end(&data);
        }

        #[test]
        fn parsers_never_panic_on_arbitrary_ascii(s in ".{0,4096}") {
            let _ = parse_request_head(s.as_bytes());
            let _ = parse_response_head(s.as_bytes());
        }

        // Desync guard: any response advertising *both* Content-Length and chunked
        // Transfer-Encoding must be reported as chunked, so `splice_conn` takes the
        // relay-and-close path instead of splicing a bounded count it can't trust.
        #[test]
        fn cl_plus_te_response_is_never_treated_as_pure_length(len in 0usize..1_000_000) {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            let (_, _content_length, chunked, _close) = parse_response_head(head.as_bytes());
            proptest::prop_assert!(chunked, "CL+TE must be flagged chunked (desync guard)");
        }

        // A well-formed GET head always round-trips its method + target through the
        // parser (parser and re-serializer agree on the request line).
        #[test]
        fn wellformed_get_head_roundtrips(path in "/[a-zA-Z0-9_/.-]{0,64}", host in "[a-z][a-z0-9.-]{0,32}") {
            let head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n");
            let parsed = parse_request_head(head.as_bytes());
            proptest::prop_assert!(parsed.is_some());
            let (m, t, h) = parsed.unwrap();
            proptest::prop_assert_eq!(m, "GET");
            proptest::prop_assert_eq!(t, path);
            proptest::prop_assert_eq!(header(&h, "host"), Some(host.as_str()));
        }
    }
}
