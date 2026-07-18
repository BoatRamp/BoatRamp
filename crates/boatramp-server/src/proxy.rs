//! The reverse-proxy data plane: stream a request to an absolute upstream URL
//! or a gateway-selected upstream pool (with SSRF guards, address pinning,
//! retry, and websocket/upgrade tunnelling), plus the compute-backend wake
//! path (scale-from-zero) that warms a parked replica before dispatch. Pulls
//! the serve scope in via `use super::*`.

use super::*;

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
    let client = match pinned_client(&host, addr) {
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

    let mut upstream = client.request(parts.method, parsed);
    // Forward request headers minus hop-by-hop and Host (reqwest sets Host).
    for (name, value) in &parts.headers {
        if name == header::HOST || is_hop_by_hop(name) {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    upstream = upstream
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", scheme);
    if let Some(host_header) = parts.headers.get(header::HOST) {
        upstream = upstream.header("x-forwarded-host", host_header);
    }
    upstream = upstream.body(reqwest::Body::wrap_stream(body.into_data_stream()));

    match upstream.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            // Pass response headers through, minus hop-by-hop + content-length
            // (we re-stream, so let the framing be recomputed).
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if is_hop_by_hop(name) || name == header::CONTENT_LENGTH {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
            (status, headers, Body::from_stream(resp.bytes_stream())).into_response()
        }
        Err(err) => {
            tracing::warn!(%url, error = %err, "proxy request failed");
            (StatusCode::BAD_GATEWAY, "upstream error\n").into_response()
        }
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

/// Build a one-off client that resolves `host` to the pre-verified `addr`,
/// closing the SSRF DNS-rebinding window (the kernel never re-resolves).
fn pinned_client(host: &str, addr: SocketAddr) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().resolve(host, addr).build()
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
    if ip == IpAddr::V4(CLOUD_METADATA_IPV4) {
        return false;
    }
    posture.allow_site_private_upstreams || boatramp_core::access::is_global_ip(ip)
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
    upstream_name: &str,
    upstream: &boatramp_core::gateway::Upstream,
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
    let state = gateway::upstream_state(site, upstream_name);
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
        let response =
            proxy_upstream(request, upstream, target, request_path, client_ip, posture).await;
        state.record(
            target,
            !response.status().is_server_error(),
            upstream.passive_health,
            now,
        );
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
        let response =
            proxy_upstream(attempt, upstream, target, request_path, client_ip, posture).await;
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

/// The live healthy replica endpoints of a compute workload, as upstream URLs.
/// Empty (→ 502) when no healthy replica exists.
pub(super) async fn compute_endpoints(deploy: &DeployStore, workload: &str) -> Vec<String> {
    deploy
        .list_replica_states(workload)
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
    workload: &str,
) -> std::collections::BTreeMap<String, String> {
    deploy
        .list_replica_states(workload)
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
pub(super) async fn has_parked_replica(deploy: &DeployStore, workload: &str) -> bool {
    deploy
        .list_replica_states(workload)
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
    workload: &str,
    timeout: std::time::Duration,
) -> Vec<String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let pool = compute_endpoints(deploy, workload).await;
        if !pool.is_empty() || std::time::Instant::now() >= deadline {
            return pool;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Spawn the leader-gated compute reconcile loop:
/// every `tick`, while `is_leader()`, run one [`reconcile_once`] pass over the
/// backend registry + node inventory to converge each workload's replicas. A
/// no-op while not leader or with an empty registry. Detached for the server's
/// lifetime; the same leader-gating pattern as cron/cert issuance.
pub fn spawn_compute_reconcile(
    deploy: DeployStore,
    backends: boatramp_core::compute::BackendRegistry,
    nodes: Vec<boatramp_core::compute::Node>,
    policy: boatramp_core::compute::BackendPolicy,
    is_leader: CronLeaderGate,
    tick: std::time::Duration,
    idle_timeout: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // drive scale-to-zero from the gateway's per-workload activity —
        // a workload idle for `idle_timeout` is slept, a requested one is woken.
        let activity = gateway::GatewayActivitySource::new(idle_timeout);
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
                &deploy, &backends, &nodes, &policy, &activity,
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
    posture: boatramp_core::security::SecurityPosture,
) -> Response {
    // WebSocket / generic HTTP upgrade: bridge the upgraded connection both ways.
    // reqwest can't upgrade, so this uses a hyper client conn.
    if is_upgrade_request(request.headers()) {
        return proxy_upgrade(request, upstream, target, request_path, client_ip, posture).await;
    }
    // A `unix:/path` target forwards over a unix-domain socket.
    if let Some(socket_path) = target.strip_prefix("unix:") {
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
    // Resolve + pin the declared target (private allowed; metadata refused).
    let parsed = match reqwest::Url::parse(target) {
        Ok(url) => url,
        Err(_) => {
            tracing::warn!(target = %target, "gateway upstream target unparsable");
            return (StatusCode::BAD_GATEWAY, "bad gateway upstream\n").into_response();
        }
    };
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                "gateway upstream scheme not http(s)\n",
            )
                .into_response()
        }
    }
    let Some(host) = parsed.host_str().map(str::to_string) else {
        return (StatusCode::BAD_GATEWAY, "gateway upstream missing host\n").into_response();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let pinned = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut chosen = None;
            for addr in addrs {
                // Refuse cloud-metadata always, and (unless the operator opts in)
                // any non-global address — checked post-resolution so a hostname
                // can't DNS-rebind to an internal target.
                if !gateway_addr_allowed(addr.ip(), &posture) {
                    tracing::warn!(
                        %host, ip = %addr.ip(),
                        "gateway upstream refused: address not permitted by security posture"
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
    let Some(addr) = pinned else {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream did not resolve\n",
        )
            .into_response();
    };

    // Build the upstream URL: target base path + forwarded (strip-prefixed) path
    // + the original query.
    let mut target = parsed.clone();
    let base = target.path().trim_end_matches('/').to_string();
    let forwarded = upstream.forward_path(request_path);
    target.set_path(&format!("{base}{forwarded}"));
    let (mut parts, body) = request.into_parts();
    target.set_query(parts.uri.query());

    // A client pinned to the resolved address, with the upstream's TLS + timeouts.
    let mut builder = reqwest::Client::builder().resolve(&host, addr);
    if let Some(ms) = upstream.connect_timeout_ms {
        builder = builder.connect_timeout(Duration::from_millis(ms));
    }
    if let Some(ms) = upstream.request_timeout_ms {
        builder = builder.timeout(Duration::from_millis(ms));
    }
    if upstream.tls_insecure {
        tracing::warn!(%host, "gateway upstream TLS verification disabled (tls_insecure)");
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = match builder.build() {
        Ok(client) => client,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway client error\n").into_response(),
    };

    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    let requested_host = parts.headers.get(header::HOST).cloned();

    let mut up = client.request(parts.method.clone(), target);
    for (name, value) in &parts.headers {
        // reqwest sets Host from the URL (or our override below); drop the
        // client Host + hop-by-hop, and any header the upstream removes.
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
        up = up.header(name, value);
    }
    up = up
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", scheme);
    if let Some(h) = &requested_host {
        up = up.header("x-forwarded-host", h);
    }
    // Host header: explicit override, else the upstream's own host.
    if let Some(hh) = &upstream.host_header {
        up = up.header(header::HOST, hh);
    }
    // Request header set/overrides.
    for (name, value) in &upstream.header_up.set {
        up = up.header(name, value);
    }
    up = up.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    parts.headers.clear(); // release; not used past here

    match up.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || upstream
                        .header_down
                        .remove
                        .iter()
                        .any(|h| name.as_str().eq_ignore_ascii_case(h))
                {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
            // Response header set/overrides.
            for (name, value) in &upstream.header_down.set {
                set_header_str(&mut headers, name, value);
            }
            (status, headers, Body::from_stream(resp.bytes_stream())).into_response()
        }
        Err(err) => {
            tracing::warn!(%host, error = %err, "gateway upstream request failed");
            (StatusCode::BAD_GATEWAY, "upstream error\n").into_response()
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
            return (StatusCode::BAD_GATEWAY, "gateway unix handshake failed\n").into_response()
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
    let host = upstream
        .host_header
        .clone()
        .unwrap_or_else(|| "localhost".to_string());

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
            for (name, value) in resp.headers() {
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || upstream
                        .header_down
                        .remove
                        .iter()
                        .any(|h| name.as_str().eq_ignore_ascii_case(h))
                {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
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

/// Proxy an HTTP **upgrade** (WebSocket) to a gateway upstream: forward the
/// handshake over a hyper client connection and, on `101`, bridge the two
/// upgraded byte streams in both directions. Supports `http`
/// (ws) and `unix:` upstreams; `https` (wss) upgrade isn't wired yet.
async fn proxy_upgrade(
    mut request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    target: &str,
    request_path: &str,
    client_ip: IpAddr,
    posture: boatramp_core::security::SecurityPosture,
) -> Response {
    // Register interest in the client-side upgrade before the request is moved.
    let client_on_upgrade = hyper::upgrade::on(&mut request);
    let method = request.method().clone();
    let req_headers = request.headers().clone();
    let query = request.uri().query().map(str::to_string);
    let forwarded = upstream.forward_path(request_path);
    let uri = match &query {
        Some(q) => format!("{forwarded}?{q}"),
        None => forwarded.into_owned(),
    };

    // Unix-socket upstream — operator opt-in only (see `proxy_upstream`).
    if let Some(socket_path) = target.strip_prefix("unix:") {
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
                        .into_response()
                }
            };
            let host = upstream
                .host_header
                .clone()
                .unwrap_or_else(|| "localhost".to_string());
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
    if parsed.scheme() != "http" {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "gateway upgrade supports http (ws) or unix upstreams\n",
        )
            .into_response();
    }
    let Some(host) = parsed.host_str().map(str::to_string) else {
        return (StatusCode::BAD_GATEWAY, "gateway upstream missing host\n").into_response();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addr = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut chosen = None;
            for addr in addrs {
                // Cloud-metadata always refused; non-global refused unless the
                // operator opted in (see `proxy_upstream`).
                if !gateway_addr_allowed(addr.ip(), &posture) {
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
            return (StatusCode::BAD_GATEWAY, "gateway upstream unreachable\n").into_response()
        }
    };
    let host_hdr = upstream.host_header.clone().unwrap_or(host);
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
    client_on_upgrade: hyper::upgrade::OnUpgrade,
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
        // Bridge the two upgraded connections once both sides flip.
        let upstream_on_upgrade = hyper::upgrade::on(&mut upstream_resp);
        tokio::spawn(async move {
            if let (Ok(client_io), Ok(upstream_io)) =
                (client_on_upgrade.await, upstream_on_upgrade.await)
            {
                let mut client_io = hyper_util::rt::TokioIo::new(client_io);
                let mut upstream_io = hyper_util::rt::TokioIo::new(upstream_io);
                let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
            }
        });
        // Return the upstream's 101 (with its Upgrade/Sec-WebSocket-Accept headers).
        let mut headers = HeaderMap::new();
        for (name, value) in upstream_resp.headers() {
            headers.insert(name.clone(), value.clone());
        }
        return (StatusCode::SWITCHING_PROTOCOLS, headers, Body::empty()).into_response();
    }

    // Upstream declined the upgrade — pass its response through.
    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        if name == header::CONTENT_LENGTH {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    (status, headers, Body::new(upstream_resp.into_body())).into_response()
}
