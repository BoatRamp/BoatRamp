//! The request-serving pipeline: host-based routing (`serve_by_host`), the
//! by-name admin route, preview and ACME domain-challenge serving, access
//! control (auth gate, basic-auth, rate-limit), request-context building, and
//! the resolve -> entry -> static/handler/proxy dispatch that streams the
//! chosen response. Pulls the shared response helpers and backends in via
//! `use super::*`.

use super::*;

/// A request's network identity, threaded into the serving pipeline for
/// access control: the socket peer plus the shared rate limiter.
struct Visitor<'a> {
    peer: IpAddr,
    limiter: &'a dyn RateLimitStore,
}

/// Serve under the explicit by-name admin/testing route `/_sites/<site>/...`.
/// The catch-all captures `<site>` or `<site>/<path...>`. Accepts any method so a
/// proxy rewrite can forward non-`GET` requests. This route is not host-routed and
/// does not serve a root-mounted site — for that, use host routing (see the
/// addressing docs).
pub(super) async fn serve_sites(
    State(deploy): State<DeployStore>,
    Extension(limiter): Extension<Arc<dyn RateLimitStore>>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let raw = request.uri().path();
    let rest = raw
        .strip_prefix("/_sites/")
        .unwrap_or("")
        .trim_start_matches('/');
    let (site, path) = rest.split_once('/').unwrap_or((rest, ""));
    if site.is_empty() {
        return not_found();
    }
    let (site, request_path) = (site.to_string(), format!("/{path}"));
    let visitor = Visitor {
        peer: peer.ip(),
        limiter: limiter.as_ref(),
    };
    // The explicit `/_sites/<name>/` admin/testing route is not host-routed, so
    // transport/canonical redirects don't apply.
    serve_request(
        &deploy,
        &site,
        &request_path,
        request,
        &visitor,
        &handlers,
        false,
    )
    .await
}

/// The root-key-signed bootstrap-TLS identity attestation (base64url
/// `COSE_Sign1`), carried as an extension for [`serve_bootstrap_identity`].
#[derive(Clone)]
pub(super) struct BootstrapAttestation(pub(super) Option<String>);

/// `GET /.well-known/boatramp-bootstrap-identity` — serve the root-key attestation
/// of this node's `--tls rpk` control-plane TLS key. Public + unauthenticated: a
/// signed statement that reveals nothing (the TLS public key is already presented
/// in the handshake). A client pinning only the root key verifies it (root
/// signature + validity), extracts the attested TLS key, and pins it. `404` when
/// no attestation is set (not `--tls rpk`, or a verify-only node with no issuer).
pub(super) async fn serve_bootstrap_identity(
    Extension(att): Extension<BootstrapAttestation>,
) -> Response {
    match att.0 {
        Some(a) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            a,
        )
            .into_response(),
        None => not_found(),
    }
}

/// Serve a pending **HTTP domain-ownership challenge** from the edge, *before*
/// host routing — the fix for the verify-before-attach chicken-and-egg. A host
/// pointed at this server but not yet attached to any site (so it would
/// otherwise fall through to `default_site` and 404 its own challenge) fetches
/// its token here, letting `domain verify` succeed with no prior deploy. Returns
/// the token for a matching `(Host, token)` pending HTTP challenge, else `404`.
///
/// Gated by the `domain_verify_self_serve` posture knob (on by default). It only
/// ever echoes back a random token to the very host that owns the pending
/// challenge, so it leaks nothing and needs no auth (like an ACME http-01
/// challenge). Mounted on both the main router and the `:80` redirect router, so
/// the plain-HTTP probe is answered directly instead of 308-redirected to an
/// HTTPS endpoint that may have no cert yet.
pub(super) async fn serve_domain_challenge(
    State(deploy): State<DeployStore>,
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !posture.domain_verify_self_serve {
        return not_found();
    }
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port)
    else {
        return not_found();
    };
    match deploy
        .find_pending_http_challenge(host, &token, now_unix())
        .await
    {
        Ok(Some(v)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            v.token,
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(err) => deploy_error_response(err),
    }
}

/// Virtualhost fallback: resolve the site from the `Host` header, serve the
/// request path. Catches everything not matched by `/healthz`, `/api/*`, or the
/// explicit `/_sites/*` route.
#[allow(clippy::too_many_arguments)] // axum extractors, not a real parameter list
pub(super) async fn serve_by_host(
    State(deploy): State<DeployStore>,
    Extension(limiter): Extension<Arc<dyn RateLimitStore>>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Extension(implicit): Extension<ImplicitRouting>,
    Extension(preview_auth): Extension<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    // Catch-all site + preview protection are read live from the daemon-config
    // runtime, so `config set default_site …` / `protect_previews …` take effect
    // without a restart.
    let effective = daemon.effective();
    let preview_policy = PreviewPolicy {
        protect: effective.protect_previews,
    };
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port)
        .map(str::to_string)
    else {
        return not_found();
    };
    let request_path = request.uri().path().to_string();
    // Wildcard preview host form `<id>.deploy.<site-host>`: the deploy id rides
    // as a subdomain (an unguessable content-hash capability, like the path form
    // `<site-host>/_deploy/<id>/…`). The remaining host resolves the site, and
    // the deployment is served with a preview-scoped binding identity. Falls
    // through to normal virtualhost routing when the host isn't a preview host.
    if let Some((id_prefix, site_host)) = parse_deploy_host(&host) {
        if let Some(blocked) =
            preview_auth_gate(preview_policy, &preview_auth, request.headers()).await
        {
            return blocked;
        }
        return serve_host_preview(
            &deploy,
            &handlers,
            peer.ip(),
            &request_path,
            request,
            id_prefix,
            site_host,
        )
        .await;
    }
    match deploy.resolve_site_by_host(&host).await {
        Ok(Some(site)) => {
            let visitor = Visitor {
                peer: peer.ip(),
                limiter: limiter.as_ref(),
            };
            // Host-routed: transport/canonical redirects + HSTS apply.
            serve_request(
                &deploy,
                &site,
                &request_path,
                request,
                &visitor,
                &handlers,
                true,
            )
            .await
        }
        // Unmatched host — no verified, attached virtualhost. Resolution order:
        //   (0) mandatory verification — a **non-local** host that isn't verified
        //       gets the "verification pending" page (421), never a fallback;
        //   (A) implicit first-label routing — `<site>.host` names a served site;
        //   the configured catch-all `default_site` (explicit operator intent).
        // (A) runs only when `implicit` is on (dev / single-tenant / a loopback
        // bind). There is deliberately no implicit *sole-site* auto-default: an
        // operator makes a site the catch-all explicitly with `default_site`.
        Ok(None) => {
            // (0) Strict gate (DV-2): a non-local public host that matched no
            // verified virtualhost is refused with the holding page — so
            // `default_site`/implicit never silently serve an unverified host.
            // Local hosts (localhost/*.localhost/*.local/IPs) and a fleet with the
            // gate off (`[security] require_domain_verification = false`, or an
            // admin `domain add --unverified` that attached the host above) pass.
            if effective.posture.require_domain_verification && !is_local_host(&host, implicit.0) {
                return verification_pending_page(&deploy, &host).await;
            }
            // (A) First host label naming a served site: `blog.localhost` → `blog`.
            if implicit.0 {
                let label = host.split('.').next().unwrap_or("");
                if !label.is_empty() && matches!(deploy.current_id(label).await, Ok(Some(_))) {
                    let visitor = Visitor {
                        peer: peer.ip(),
                        limiter: limiter.as_ref(),
                    };
                    return serve_request(
                        &deploy,
                        label,
                        &request_path,
                        request,
                        &visitor,
                        &handlers,
                        true,
                    )
                    .await;
                }
            }
            match effective.default_site.as_deref() {
                Some(site) => {
                    let visitor = Visitor {
                        peer: peer.ip(),
                        limiter: limiter.as_ref(),
                    };
                    serve_request(
                        &deploy,
                        site,
                        &request_path,
                        request,
                        &visitor,
                        &handlers,
                        true,
                    )
                    .await
                }
                None => not_found(),
            }
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Serve a wildcard-host preview: resolve `id_prefix` to a full deployment id
/// and `site_host` to a site, then run the deployment with a **preview-scoped**
/// binding identity (like [`serve_preview`], but reached by subdomain). Handlers
/// run only when the host resolves to a real site; otherwise the preview serves
/// static content only. No visitor access control — the unguessable id is the
/// capability (consistent with the path-form preview).
#[allow(clippy::too_many_arguments)]
async fn serve_host_preview(
    deploy: &DeployStore,
    handlers: &HandlerRuntime,
    peer: IpAddr,
    request_path: &str,
    request: Request,
    id_prefix: &str,
    site_host: &str,
) -> Response {
    let id = match deploy.resolve_manifest_id(id_prefix).await {
        Ok(Some(id)) => id,
        Ok(None) => return not_found(),
        Err(err) => return deploy_error_response(err),
    };
    let site = match deploy.resolve_site_by_host(site_host).await {
        Ok(site) => site,
        Err(err) => return deploy_error_response(err),
    };
    let site_config = match &site {
        Some(site) => match deploy.get_site_config(site).await {
            Ok(config) => config,
            Err(err) => return deploy_error_response(err),
        },
        None => None,
    };
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            serve_resolved(
                deploy,
                &manifest,
                request_path,
                request,
                peer,
                site.as_deref(),
                site_config.as_ref(),
                handlers,
                Some(&id),
            )
            .await
        }
        Ok(None) => not_found(),
        Err(err) => deploy_error_response(err),
    }
}

/// Run the serving pipeline for a resolved `site` and request path: apply the
/// deploy config (redirects, rewrites/SPA, clean URLs, custom 404, headers,
/// cache) via [`route::resolve`], then HTTP correctness (conditional `304`,
/// `Range`/`206`, `ETag`).
async fn serve_request(
    deploy: &DeployStore,
    site: &str,
    request_path: &str,
    request: Request,
    visitor: &Visitor<'_>,
    handlers: &HandlerRuntime,
    host_routed: bool,
) -> Response {
    // Load the site config once (for access policy + client-IP resolution).
    let site_config = match deploy.get_site_config(site).await {
        Ok(config) => config,
        Err(err) => return deploy_error_response(err),
    };

    // Transport redirects + HSTS. The effective scheme
    // honors `X-Forwarded-Proto` **only from a configured trusted proxy**
    // — otherwise a direct HTTP client could forge `…: https` to
    // skip the HTTPS redirect. For an untrusted/direct peer the scheme is the
    // listener's own (TLS ⇒ `https`, else `http`). Host-routed traffic only.
    let listener_scheme = if request
        .extensions()
        .get::<ServedOverTls>()
        .map(|s| s.0)
        .unwrap_or(false)
    {
        "https"
    } else {
        "http"
    };
    let peer_trusted = site_config
        .as_ref()
        .map(|c| c.access.is_trusted_proxy(visitor.peer))
        .unwrap_or(false);
    let effective_scheme = if peer_trusted {
        request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(listener_scheme)
            .to_string()
    } else {
        listener_scheme.to_string()
    };
    // Captured before the request body is consumed, for on-the-fly compression.
    #[cfg(feature = "compression")]
    let accept_encoding = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // Site-tier security response headers, applied (host-routed only) after the
    // response is built: HSTS (HTTPS only), plus opt-in CSP / X-Frame-Options.
    let mut security_headers: Vec<(HeaderName, String)> = Vec::new();
    if host_routed {
        if let Some(cfg) = site_config.as_ref() {
            let host = request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(strip_port)
                .unwrap_or("");
            let path_and_query = request
                .uri()
                .path_and_query()
                .map(axum::http::uri::PathAndQuery::as_str)
                .unwrap_or(request_path);
            if let Some(target) = boatramp_core::config::transport_redirect(
                &cfg.security,
                &cfg.domains,
                &effective_scheme,
                host,
                path_and_query,
            ) {
                return redirect_to(&target);
            }
            // HSTS only over HTTPS (it's meaningless / ignored over plain HTTP).
            if effective_scheme == "https" {
                if let Some(hsts) = cfg.security.hsts.as_ref() {
                    security_headers.push((
                        HeaderName::from_static("strict-transport-security"),
                        hsts.header_value(),
                    ));
                }
            }
            // CSP + X-Frame-Options apply on either scheme, when configured.
            if let Some(csp) = cfg.security.csp.as_deref() {
                security_headers.push((header::CONTENT_SECURITY_POLICY, csp.to_string()));
            }
            if let Some(frame) = cfg.security.frame_options.as_deref() {
                security_headers.push((header::X_FRAME_OPTIONS, frame.to_string()));
            }
        }
    }

    let access = site_config.as_ref().map(|c| &c.access);

    // Resolve the real client IP, honoring X-Forwarded-For only from a
    // configured trusted proxy.
    let trusted = access.map(|a| a.trusted_proxies.as_slice()).unwrap_or(&[]);
    let forwarded_for = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let client_ip = boatramp_core::access::resolve_client_ip(visitor.peer, forwarded_for, trusted);

    // Visitor access control (WAF → IP rules → rate limit → basic auth) runs
    // before any content is read.
    if let Some(access) = access {
        if let Some(denied) = enforce_access(
            access,
            site,
            request.headers(),
            request_path,
            client_ip,
            visitor.limiter,
        )
        .await
        {
            return denied;
        }
    }

    let manifest = match deploy.current_manifest(site).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return not_found(),
        Err(err) => return deploy_error_response(err),
    };
    let mut response = serve_resolved(
        deploy,
        &manifest,
        request_path,
        request,
        client_ip,
        Some(site),
        site_config.as_ref(),
        handlers,
        None,
    )
    .await;
    // Site-tier security headers (HSTS / CSP / X-Frame-Options), computed above.
    for (name, value) in security_headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
    // On-the-fly compression (opt-in per site; covers dynamic + variant-less
    // static responses). A no-op without the `compression` feature.
    #[cfg(feature = "compression")]
    let response = match site_config.as_ref() {
        Some(cfg) if cfg.compression.enabled => maybe_compress(
            response,
            accept_encoding.as_deref(),
            cfg.compression.min_size,
        ),
        _ => response,
    };
    response
}

/// When previews are protected, require a valid control-plane token. Returns
/// `Some(401)` to block, `None` to allow. "Any valid token" (no scope needed).
async fn preview_auth_gate(
    policy: PreviewPolicy,
    auth: &Auth,
    headers: &HeaderMap,
) -> Option<Response> {
    if !policy.protect {
        return None;
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let ok = match bearer {
        Some(token) => auth.verify_bearer(token).await,
        None => false,
    };
    (!ok).then(|| {
        (
            StatusCode::UNAUTHORIZED,
            "preview requires a valid bearer token\n",
        )
            .into_response()
    })
}

/// A `301 Moved Permanently` to `target` (transport/canonical redirects).
fn redirect_to(target: &str) -> Response {
    match HeaderValue::from_str(target) {
        Ok(location) => (
            StatusCode::MOVED_PERMANENTLY,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bad redirect target\n").into_response(),
    }
}

/// A standalone router for a plain `:80` listener that permanently redirects
/// every request to its HTTPS equivalent. Bound alongside the HTTPS listener so
/// plain-HTTP visitors are upgraded even when boatramp terminates TLS itself.
///
/// It does serve one thing directly rather than redirecting: the HTTP
/// domain-ownership challenge (`/.well-known/boatramp-domain-verification/…`).
/// That probe arrives on plain `:80` for a host that may have no cert yet, so a
/// 308 to HTTPS would bounce it to an endpoint that can't answer — the token
/// must be served here. (ACME's own challenges use ALPN-01/DNS-01, so there is
/// no `/.well-known/acme-challenge` to serve.)
pub fn http_redirect_router(
    deploy: DeployStore,
    posture: boatramp_core::security::SecurityPosture,
) -> Router {
    Router::new()
        .route(
            "/.well-known/boatramp-domain-verification/:token",
            get(serve_domain_challenge),
        )
        .fallback(redirect_http_to_https)
        .with_state(deploy)
        .layer(Extension(posture))
}

/// 308-redirect any request to `https://<host><path-and-query>` (308 preserves
/// the method/body, unlike 301).
async fn redirect_http_to_https(req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port)
        .unwrap_or("");
    if host.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing Host header\n").into_response();
    }
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        .unwrap_or("/");
    match HeaderValue::from_str(&format!("https://{host}{path_and_query}")) {
        Ok(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "invalid host\n").into_response(),
    }
}

/// Evaluate a site's [`AccessConfig`] against an already-resolved `client_ip`.
/// Returns `Some(response)` to short-circuit (403/429/401), or `None` to allow.
/// Order: WAF → IP rules → rate limit → basic auth. `async` because the
/// cluster-wide rate-limit store does a KV round-trip.
async fn enforce_access(
    access: &AccessConfig,
    site: &str,
    req_headers: &HeaderMap,
    path: &str,
    client_ip: IpAddr,
    limiter: &dyn RateLimitStore,
) -> Option<Response> {
    if !access.is_enforced() {
        return None;
    }
    // WAF (user-agent rules + anomaly scoring) is the outermost filter: a blocked
    // request shouldn't reach rate limiting or auth.
    if access.waf.is_enabled() {
        let header_str = |name| req_headers.get(name).and_then(|v| v.to_str().ok());
        let waf_req = boatramp_core::waf::WafRequest {
            user_agent: header_str(header::USER_AGENT),
            accept: header_str(header::ACCEPT),
            path,
        };
        if let boatramp_core::waf::WafVerdict::Block(reason) =
            boatramp_core::waf::evaluate(&access.waf, &waf_req)
        {
            tracing::debug!(%client_ip, site, %reason, "request blocked by WAF");
            return Some((StatusCode::FORBIDDEN, "forbidden\n").into_response());
        }
    }
    if !access.ip.allows(client_ip) {
        tracing::debug!(%client_ip, site, "request blocked by IP rules");
        return Some((StatusCode::FORBIDDEN, "forbidden\n").into_response());
    }
    if let Some(limit) = &access.rate_limit {
        if !limiter.check(site, client_ip, limit).await {
            return Some(too_many_requests());
        }
    }
    if let Some(basic) = &access.basic_auth {
        if !verify_basic_auth(basic, req_headers) {
            return Some(basic_auth_challenge(basic));
        }
    }
    None
}

/// Verify an HTTP `Authorization: Basic` header against the site credentials.
fn verify_basic_auth(basic: &BasicAuth, req_headers: &HeaderMap) -> bool {
    use base64::Engine;
    let Some(encoded) = req_headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    match text.split_once(':') {
        Some((user, pass)) => basic.verify(user, pass),
        None => false,
    }
}

/// `401` with a `WWW-Authenticate: Basic` challenge.
fn basic_auth_challenge(basic: &BasicAuth) -> Response {
    let realm = basic.realm.replace(['"', '\\'], "");
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("Basic realm=\"{realm}\", charset=\"UTF-8\""))
    {
        headers.insert(header::WWW_AUTHENTICATE, value);
    }
    (
        StatusCode::UNAUTHORIZED,
        headers,
        "authentication required\n",
    )
        .into_response()
}

/// `429 Too Many Requests` with a `Retry-After`.
fn too_many_requests() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        "rate limit exceeded\n",
    )
        .into_response()
}

/// Serve an immutable deployment by id under `/_deploy/<id>/...`. Like
/// [`serve_sites`], a single catch-all captures `<id>` or `<id>/<path...>`, so
/// `/_deploy/<id>`, `/_deploy/<id>/`, and `/_deploy/<id>/about` all route here.
pub(super) async fn serve_preview(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Extension(preview_auth): Extension<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let preview_policy = PreviewPolicy {
        protect: daemon.effective().protect_previews,
    };
    if let Some(blocked) = preview_auth_gate(preview_policy, &preview_auth, request.headers()).await
    {
        return blocked;
    }
    let raw = request.uri().path();
    let rest = raw
        .strip_prefix("/_deploy/")
        .unwrap_or("")
        .trim_start_matches('/');
    let (id, path) = rest.split_once('/').unwrap_or((rest, ""));
    if id.is_empty() {
        return not_found();
    }
    let (id, request_path) = (id.to_string(), format!("/{path}"));
    // When the preview is reached via the *site's own hostname*
    // (`site.example.com/_deploy/<id>/…`), resolve that site so handlers can run
    // — with **preview-scoped** bindings (`Some(&id)` below) so they never touch
    // the live site's kv/blob/sql. Reached via any other host
    // (no site resolves), handlers stay off — the preview serves static only.
    let site = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port);
    let site = match site {
        Some(host) => match deploy.resolve_site_by_host(host).await {
            Ok(site) => site,
            Err(err) => return deploy_error_response(err),
        },
        None => None,
    };
    let site_config = match &site {
        Some(site) => match deploy.get_site_config(site).await {
            Ok(config) => config,
            Err(err) => return deploy_error_response(err),
        },
        None => None,
    };
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            serve_resolved(
                &deploy,
                &manifest,
                &request_path,
                request,
                peer.ip(),
                site.as_deref(),
                site_config.as_ref(),
                &handlers,
                Some(&id),
            )
            .await
        }
        Ok(None) => not_found(),
        Err(err) => deploy_error_response(err),
    }
}

/// Run the deploy-config routing pipeline against a resolved `manifest`, then
/// stream the chosen entry (or proxy). `client_ip` is the resolved visitor
/// address (for proxy `X-Forwarded-For`).
/// Build the [`RequestContext`](boatramp_core::predicate::RequestContext) a
/// conditional-routing `when` predicate reads from the live request. Only called
/// when the deployment actually has conditional rules, so the non-conditional hot
/// path never pays for it.
fn build_request_context(request: &Request) -> boatramp_core::predicate::RequestContext {
    use boatramp_core::predicate::RequestContext;
    let headers = request.headers();
    let mut hmap: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, value) in headers {
        if let Ok(v) = value.to_str() {
            hmap.entry(name.as_str().to_ascii_lowercase())
                .and_modify(|e| {
                    e.push_str(", ");
                    e.push_str(v);
                })
                .or_insert_with(|| v.to_string());
        }
    }
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();
    let cookies = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(parse_cookie_header)
        .unwrap_or_default();
    let query = request
        .uri()
        .query()
        .map(parse_query_string)
        .unwrap_or_default();
    let accept_languages = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|h| h.to_str().ok())
        .map(RequestContext::parse_accept_language)
        .unwrap_or_default();
    RequestContext {
        method: request.method().as_str().to_ascii_uppercase(),
        host,
        headers: hmap,
        cookies,
        query,
        accept_languages,
    }
}

/// Parse a `Cookie` header into name→value pairs (first value wins).
pub(super) fn parse_cookie_header(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .fold(std::collections::BTreeMap::new(), |mut m, (k, v)| {
            m.entry(k).or_insert(v);
            m
        })
}

/// Parse a URL query string into key→value pairs (first value wins), with
/// `application/x-www-form-urlencoded` decoding (`+` → space, `%XX` → byte) so a
/// condition compares against the real value.
pub(super) fn parse_query_string(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .fold(std::collections::BTreeMap::new(), |mut m, (k, v)| {
            m.entry(k).or_insert(v);
            m
        })
}

/// Decode a `application/x-www-form-urlencoded` component: `+` → space, `%XX` →
/// the byte, everything else verbatim. Invalid `%` escapes are left as-is;
/// non-UTF-8 results are lossily replaced.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Merge conditional-routing `Vary` header names into a response, so a per-visitor
/// (language/cookie/header) redirect or page is never shared across visitors by a
/// downstream cache. A no-op when `vary` is empty (the non-conditional case).
pub(super) fn apply_vary(mut response: Response, vary: &[String]) -> Response {
    if vary.is_empty() {
        return response;
    }
    let mut names: Vec<String> = response
        .headers()
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for v in vary {
        if !names.iter().any(|n| n == v) {
            names.push(v.clone());
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&names.join(", ")) {
        response.headers_mut().insert(header::VARY, hv);
    }
    response
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "handlers"), allow(unused_variables))]
async fn serve_resolved(
    deploy: &DeployStore,
    manifest: &Manifest,
    request_path: &str,
    request: Request,
    client_ip: IpAddr,
    site: Option<&str>,
    site_config: Option<&SiteConfig>,
    handlers: &HandlerRuntime,
    // `Some(deploy_id)` when serving a by-id preview, so handler bindings get a
    // preview-scoped identity; `None` for live serving.
    preview: Option<&str>,
) -> Response {
    // Evaluate conditional (`when`) routing against the request. The request
    // context is built only when the deploy has conditional rules, and `vary`
    // carries the request dimensions those conditions read (applied to the
    // response below so a per-language/-cookie outcome isn't wrongly cached).
    let ctx = if manifest.config.redirects.iter().any(|r| r.when.is_some())
        || manifest.config.rewrites.iter().any(|r| r.when.is_some())
    {
        build_request_context(&request)
    } else {
        boatramp_core::predicate::RequestContext::default()
    };
    let route::ResolveResult { outcome, vary } =
        route::resolve_ctx(&manifest.config, &manifest.files, request_path, &ctx);
    // Routing precedence: redirects win over handlers, which
    // win over rewrites/static. A redirect short-circuits below; otherwise a
    // matching handler is dispatched in preference to the file/rewrite outcome.
    #[cfg(feature = "handlers")]
    if !matches!(outcome, Outcome::Redirect { .. }) {
        if let Some(site) = site {
            if let Some(handler) = route::match_handler(
                &manifest.config.handlers,
                request.method().as_str(),
                request_path,
            ) {
                return apply_vary(
                    dispatch_handler(
                        handlers,
                        deploy,
                        manifest,
                        site,
                        request_path,
                        site_config,
                        handler,
                        request,
                        client_ip,
                        preview,
                    )
                    .await,
                    &vary,
                );
            }
            // No handler matched: a GET to a configured SSE stream route fans out
            // its messaging topics. Streams are GET-only.
            if request.method() == Method::GET {
                if let Some(stream) = manifest
                    .config
                    .streams
                    .iter()
                    .find(|s| route_matches(&s.route, request_path))
                {
                    if let (Some(inner), Some(site_handlers)) = (
                        handlers.inner.as_ref(),
                        site_config
                            .and_then(|c| c.handlers.as_ref())
                            .filter(|h| h.enabled),
                    ) {
                        // A `websocket` stream upgraded by the client is served
                        // bidirectionally (WebSocket fan-out);
                        // otherwise it's SSE. Build the upgrade from the request
                        // parts (consuming the body, which isn't `Sync`, so it is
                        // never held across the dispatch await).
                        if stream.websocket && is_upgrade_request(request.headers()) {
                            use axum::extract::FromRequestParts;
                            let (mut parts, _body) = request.into_parts();
                            return apply_vary(
                                match axum::extract::ws::WebSocketUpgrade::from_request_parts(
                                    &mut parts,
                                    &(),
                                )
                                .await
                                {
                                    Ok(ws) => {
                                        serve_ws_stream(
                                            inner,
                                            site,
                                            site_handlers,
                                            stream,
                                            ws,
                                            client_ip,
                                            preview,
                                        )
                                        .await
                                    }
                                    Err(rejection) => rejection.into_response(),
                                },
                                &vary,
                            );
                        }
                        // Pull the only field needed from the request as an owned
                        // value: `&Request` is not `Send` (the body isn't `Sync`),
                        // so it must not be held across the dispatch await.
                        let after = request
                            .headers()
                            .get("last-event-id")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string);
                        return apply_vary(
                            serve_stream(
                                inner,
                                site,
                                site_handlers,
                                stream,
                                after,
                                client_ip,
                                preview,
                            )
                            .await,
                            &vary,
                        );
                    }
                    // A stream route on a site with handlers disabled / no runtime
                    // is not served (deny by default).
                    return apply_vary(not_found(), &vary);
                }
            }
        }
    }
    // Gateway: an operator-declared route forwards to a private
    // upstream. Independent of the handlers feature; runs after redirects/
    // handlers and **wins over static files** (the operator declared it). Access
    // control already ran up front; only declared upstreams reach private addrs.
    if !matches!(outcome, Outcome::Redirect { .. }) {
        if let Some(gw) = site_config
            .and_then(|c| c.gateway.as_ref())
            .filter(|g| g.is_enabled())
        {
            if let Some(route) = gw.match_route(request_path) {
                return apply_vary(
                    match gw.upstreams.get(&route.upstream) {
                        Some(upstream) => {
                            // A compute-backed upstream resolves its pool live from
                            // the workload's healthy replica endpoints. Record
                            // the request as activity so the reconcile loop
                            // keeps the workload warm / wakes it, and only sleeps it
                            // once genuinely idle.
                            let (compute_backends, compute_regions) = match &upstream.compute {
                                Some(workload) => {
                                    gateway::record_activity(workload);
                                    let mut pool = compute_endpoints(deploy, workload).await;
                                    // Wake-from-zero: no live replica but one
                                    // is parked → nudge the reconcile loop to restore it
                                    // and hold this request until it's serving. The cold
                                    // start is invisible to the client; only a genuine
                                    // restore failure (timeout) falls through to 502.
                                    if pool.is_empty() && has_parked_replica(deploy, workload).await
                                    {
                                        gateway::wake_reconcile();
                                        pool = await_warm(deploy, workload, COMPUTE_WAKE_TIMEOUT)
                                            .await;
                                    }
                                    // FA-8: for a nearest-region pool, tag each replica
                                    // endpoint with its node's region (from placement).
                                    let regions = if upstream.lb
                                        == boatramp_core::gateway::LbPolicy::Nearest
                                    {
                                        Some(compute_endpoint_regions(deploy, workload).await)
                                    } else {
                                        None
                                    };
                                    (Some(pool), regions)
                                }
                                None => (None, None),
                            };
                            dispatch_gateway(
                                request,
                                site.unwrap_or(""),
                                &route.upstream,
                                upstream,
                                request_path,
                                client_ip,
                                compute_backends,
                                compute_regions,
                            )
                            .await
                        }
                        None => (
                            StatusCode::BAD_GATEWAY,
                            "gateway route references an unknown upstream\n",
                        )
                            .into_response(),
                    },
                    &vary,
                );
            }
        }
    }
    let response = match outcome {
        Outcome::Redirect { location, status } => redirect(status, &location),
        Outcome::Proxy { url } => proxy(request, &url, &manifest.config, client_ip).await,
        Outcome::File {
            path: served,
            entry,
        } => {
            // Static content answers only GET/HEAD; other methods are 405.
            if !matches!(*request.method(), Method::GET | Method::HEAD) {
                return apply_vary(method_not_allowed(), &vary);
            }
            serve_entry(
                deploy,
                &manifest.config,
                request_path,
                &served,
                &entry,
                request.headers(),
                StatusCode::OK,
            )
            .await
        }
        Outcome::NotFound { error } => match error {
            Some((served, entry)) => {
                serve_entry(
                    deploy,
                    &manifest.config,
                    request_path,
                    &served,
                    &entry,
                    request.headers(),
                    StatusCode::NOT_FOUND,
                )
                .await
            }
            None => not_found(),
        },
    };
    apply_vary(response, &vary)
}

/// `405` for a non-`GET`/`HEAD` request to static content.
fn method_not_allowed() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
    (
        StatusCode::METHOD_NOT_ALLOWED,
        headers,
        "method not allowed\n",
    )
        .into_response()
}

/// Stream a resolved entry, applying conditional/range/headers. `base_status` is
/// `200` for a normal hit and `404` for a custom error document.
#[allow(clippy::too_many_arguments)]
async fn serve_entry(
    deploy: &DeployStore,
    config: &DeployConfig,
    request_path: &str,
    served_path: &str,
    entry: &FileEntry,
    req_headers: &HeaderMap,
    base_status: StatusCode,
) -> Response {
    let is_range = base_status == StatusCode::OK && req_headers.contains_key(header::RANGE);

    // Content-encoding negotiation. Range requests are served from the identity
    // representation (Range over a compressed variant is intentionally avoided).
    let chosen = if is_range {
        None
    } else {
        negotiate_encoding(entry, req_headers)
    };
    let (blob_hash, blob_size, encoding) = match chosen {
        Some((enc, variant)) => (variant.hash.as_str(), variant.size, Some(enc)),
        None => (entry.hash.as_str(), entry.size, None),
    };
    // ETag is per-representation (identity vs br vs gzip differ in bytes).
    let etag = format!("\"{blob_hash}\"");

    // Conditional GET — content hash is a strong validator.
    if base_status == StatusCode::OK && if_none_match(req_headers, &etag) {
        let mut headers = response_headers(config, request_path, served_path, entry, &etag);
        set_content_encoding(&mut headers, encoding);
        return (StatusCode::NOT_MODIFIED, headers).into_response();
    }

    // Range request (identity only).
    if is_range {
        if let Some(spec) = req_headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
        {
            match parse_ranges(spec, entry.size) {
                // A single range → `206` with `Content-Range`, streamed.
                Some(ranges) if ranges.len() == 1 => {
                    let (offset, len) = ranges[0];
                    let object = match deploy.open_blob_range(&entry.hash, offset, Some(len)).await
                    {
                        Ok(object) => object,
                        Err(err) => return deploy_error_response(err),
                    };
                    let mut headers =
                        response_headers(config, request_path, served_path, entry, &etag);
                    set_header(&mut headers, header::CONTENT_LENGTH, &len.to_string());
                    set_header(
                        &mut headers,
                        header::CONTENT_RANGE,
                        &format!("bytes {}-{}/{}", offset, offset + len - 1, entry.size),
                    );
                    return (
                        StatusCode::PARTIAL_CONTENT,
                        headers,
                        Body::from_stream(object.body),
                    )
                        .into_response();
                }
                // Several ranges → `206 multipart/byteranges`, streamed.
                Some(ranges) if ranges.len() <= MAX_RANGES => {
                    return multipart_byteranges(
                        deploy,
                        config,
                        request_path,
                        served_path,
                        entry,
                        &etag,
                        &ranges,
                    )
                    .await;
                }
                // Too many ranges: ignore `Range`, serve the full `200` body.
                Some(_) => {}
                // Malformed / wholly unsatisfiable → `416`.
                None => {
                    let mut headers = HeaderMap::new();
                    set_header(
                        &mut headers,
                        header::CONTENT_RANGE,
                        &format!("bytes */{}", entry.size),
                    );
                    return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
                }
            }
        }
    }

    // Full body (identity or negotiated variant).
    let object = match deploy.open_blob(blob_hash).await {
        Ok(object) => object,
        Err(err) => return deploy_error_response(err),
    };
    let mut headers = response_headers(config, request_path, served_path, entry, &etag);
    set_header(&mut headers, header::CONTENT_LENGTH, &blob_size.to_string());
    set_content_encoding(&mut headers, encoding);
    (base_status, headers, Body::from_stream(object.body)).into_response()
}
