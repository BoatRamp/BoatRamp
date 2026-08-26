//! Differential test for the serve hot-path bypass (`FastServe`): the security-critical
//! proof that dispatching an eligible request straight to `serve_by_host` is
//! **byte-identical** to routing it through the full axum router, and that the classifier
//! never steals a request an explicit route (or the console) owns.
//!
//! Two halves:
//! 1. **Classifier** — `FastServe::eligible` must return `false` for every reserved route
//!    (`/api*`, `/_*`, `/.well-known/*`, `/healthz`, `/readyz`, `/mcp*`) and every non
//!    GET/HEAD method, and `true` only for a plain site GET/HEAD. Excluding too much only
//!    forgoes the speedup; excluding too little would route a control-plane request into
//!    `serve_by_host` — this is the guard against that.
//! 2. **Byte-identity** — for every eligible request, `router.oneshot(req)` and
//!    `fast.dispatch(req)` produce the same status, headers, and body. Includes a
//!    gateway-upstream GET under a **permissive** posture: it passes only if the bypass
//!    re-inserts the security posture the SSRF gate reads (a missing posture would fail
//!    closed to the strict default and 502 the private upstream the router allows).

#![cfg(test)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use boatramp_core::config::{DeployConfig, DomainConfig, HeaderRule, Redirect, SiteConfig};
use boatramp_core::deploy::{sha256_hex, DeployStore, FileEntry, Manifest};
use boatramp_core::gateway::{GatewayConfig, GatewayRoute, Upstream};
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_core::security::SecurityProfile;
use boatramp_core::ByteStream;
use futures::StreamExt as _;

use crate::{Auth, FastServe, HandlerRuntime, ServerOptions};

const PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40000);

/// A file entry + its content, ready to `put_blob`.
fn file(bytes: &'static [u8], content_type: &str) -> FileEntry {
    FileEntry {
        hash: sha256_hex(bytes),
        size: bytes.len() as u64,
        content_type: Some(content_type.to_string()),
        variants: BTreeMap::new(),
    }
}

async fn put_blob(deploy: &DeployStore, bytes: &'static [u8]) {
    let hash = sha256_hex(bytes);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();
}

/// Build a request identical for both paths: a `Host`, method, path, and the peer as
/// `ConnectInfo` (the router extracts it; the fast path passes `PEER` explicitly — both
/// resolve to the same peer). An explicit `x-request-id` keeps the id deterministic.
fn mk(host: &str, method: Method, path: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, host.parse().unwrap());
    req.headers_mut()
        .insert("x-request-id", "fixed-test-id".parse().unwrap());
    req.extensions_mut().insert(ConnectInfo(PEER));
    req
}

/// Collect a response into `(status, sorted headers, body)` for structural comparison.
/// `content-length` / `transfer-encoding` are excluded: those are transport-framing
/// headers the `boatramp_http` codec derives from the body at the wire (both paths pass
/// through it in production), and axum's `Router` service auto-adds `content-length: 0`
/// to an empty-body response as a courtesy the fast path leaves to the codec. The body
/// bytes are compared separately, so the effective length is still validated exactly.
async fn collect(resp: Response) -> (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let status = resp.status();
    let mut headers: Vec<(String, Vec<u8>)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "content-length" | "transfer-encoding"))
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

/// A tiny keep-alive upstream returning a fixed `Content-Length` body, for the gateway
/// site. Returns its address.
async fn spawn_upstream() -> SocketAddr {
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = up.local_addr().unwrap();
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
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    if s.write_all(head.as_bytes()).await.is_err()
                        || s.write_all(body).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// A store with a static site on `app.local` (clean URLs, custom 404, a redirect, a JS
/// header rule) and a gateway site on `gw.local` proxying to `up_addr`. Both hosts are
/// `.local`, so the domain-verification gate passes without a challenge.
async fn seed(up_addr: SocketAddr) -> DeployStore {
    let deploy = DeployStore::new(
        Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir())),
        Arc::new(MemoryKv::new()),
    );

    // Static site content.
    const INDEX: &[u8] = b"<h1>home</h1>";
    const ABOUT: &[u8] = b"<h1>about</h1>";
    const NF: &[u8] = b"<h1>nope</h1>";
    const BIG: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz-the-big-file-body-x";
    const JS: &[u8] = b"export const id = (x) => x;";
    for b in [INDEX, ABOUT, NF, BIG, JS] {
        put_blob(&deploy, b).await;
    }
    let mut files = BTreeMap::new();
    files.insert("index.html".to_string(), file(INDEX, "text/html"));
    files.insert("about.html".to_string(), file(ABOUT, "text/html"));
    files.insert("404.html".to_string(), file(NF, "text/html"));
    files.insert("big.txt".to_string(), file(BIG, "text/plain"));
    files.insert("app.js".to_string(), file(JS, "text/javascript"));
    let config = DeployConfig {
        clean_urls: true,
        error_documents: BTreeMap::from([(404, "/404.html".to_string())]),
        redirects: vec![Redirect {
            from: "/old".to_string(),
            to: "/new".to_string(),
            status: 301,
            when: None,
        }],
        headers: vec![HeaderRule {
            matches: "**.js".to_string(),
            set: BTreeMap::from([("Cache-Control".to_string(), "immutable".to_string())]),
            unset: vec![],
        }],
        ..DeployConfig::default()
    };
    let manifest = Manifest {
        files,
        config,
        ..Default::default()
    };
    deploy
        .set_site_config(
            ProjectRef::DEFAULT,
            "static",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("app.local".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .activate(ProjectRef::DEFAULT, "static", &id)
        .await
        .unwrap();

    // Gateway site → the loopback upstream (a private address the permissive Dev posture
    // allows; the strict default would refuse it — that is the posture-parity probe).
    deploy
        .set_site_config(
            ProjectRef::DEFAULT,
            "gw",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("gw.local".into()),
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
            },
        )
        .await
        .unwrap();
    let gw_id = deploy.put_manifest(&Manifest::default()).await.unwrap();
    deploy
        .activate(ProjectRef::DEFAULT, "gw", &gw_id)
        .await
        .unwrap();

    deploy
}

/// Build the router + fast handle from one shared state (the exact `serve_with` wiring),
/// under a permissive Dev posture.
fn build(deploy: DeployStore) -> (axum::Router, FastServe) {
    crate::router_with_fast(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            posture: SecurityProfile::Dev.preset(),
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn classifier_excludes_every_reserved_route_and_non_read_method() {
    let up = spawn_upstream().await;
    let deploy = seed(up).await;
    let (_router, fast) = build(deploy);

    // Eligible: a plain site GET/HEAD the router would send to its `serve_by_host` fallback.
    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/about"),
        (Method::GET, "/app.js"),
        (Method::GET, "/big.txt"),
        (Method::GET, "/old"),
        (Method::GET, "/deep/nested/path"),
        (Method::HEAD, "/"),
    ] {
        assert!(
            fast.eligible(&mk("app.local", method.clone(), path)),
            "expected eligible: {method} {path}"
        );
    }

    // Reserved routes — the router owns these; the bypass must defer.
    for path in [
        "/api",
        "/api/",
        "/api/sites",
        "/api/projects/acme/sites/blog",
        "/_sites/static/",
        "/_deploy/abc/",
        "/_webhooks/x",
        "/.well-known/acme-challenge/tok",
        "/.well-known/boatramp-bootstrap-identity",
        "/healthz",
        "/readyz",
        "/mcp",
        "/mcp/messages",
    ] {
        assert!(
            !fast.eligible(&mk("app.local", Method::GET, path)),
            "reserved route must not be eligible: {path}"
        );
    }

    // Non-read methods are never eligible (even on a site path).
    for method in [
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::OPTIONS,
    ] {
        assert!(
            !fast.eligible(&mk("app.local", method.clone(), "/")),
            "non-read method must not be eligible: {method}"
        );
    }
}

#[tokio::test]
async fn fast_path_is_byte_identical_to_the_router_for_every_eligible_request() {
    let up = spawn_upstream().await;
    let deploy = seed(up).await;
    let (router, fast) = build(deploy);

    // Static-site requests: full status + headers + body must match exactly.
    for (host, method, path) in [
        ("app.local", Method::GET, "/"),
        ("app.local", Method::GET, "/about"),  // clean URL
        ("app.local", Method::GET, "/app.js"), // header rule (Cache-Control)
        ("app.local", Method::GET, "/big.txt"),
        ("app.local", Method::GET, "/old"), // 301 redirect
        ("app.local", Method::GET, "/does-not-exist"), // custom 404
        ("app.local", Method::HEAD, "/"),
        // An unmatched public host — both paths return the same verification/holding
        // outcome (there is no default site), exercised through one implementation.
        ("nope.local", Method::GET, "/"),
    ] {
        let probe = mk(host, method.clone(), path);
        assert!(
            fast.eligible(&probe),
            "test bug: {method} {host}{path} should be eligible"
        );
        let via_router = collect(
            router
                .clone()
                .oneshot(mk(host, method.clone(), path))
                .await
                .unwrap(),
        )
        .await;
        let via_fast = collect(fast.dispatch(mk(host, method.clone(), path), PEER).await).await;
        assert_eq!(
            via_router, via_fast,
            "fast path diverged from router for {method} {host}{path}"
        );
    }

    // Gateway-upstream GET under the permissive posture: the response must match, and in
    // particular must be a 200 proxied from the upstream (a bypass that dropped the
    // posture would fail closed to the strict default and 502 the private upstream).
    let via_router = collect(
        router
            .clone()
            .oneshot(mk("gw.local", Method::GET, "/anything"))
            .await
            .unwrap(),
    )
    .await;
    let via_fast = collect(
        fast.dispatch(mk("gw.local", Method::GET, "/anything"), PEER)
            .await,
    )
    .await;
    assert_eq!(
        via_router.0,
        StatusCode::OK,
        "router should proxy the private upstream under the permissive posture"
    );
    assert_eq!(via_router.0, via_fast.0, "gateway status diverged");
    assert_eq!(via_router.2, via_fast.2, "gateway body diverged");
    assert_eq!(
        via_fast.2, b"hello-from-upstream",
        "fast path did not proxy"
    );
}
