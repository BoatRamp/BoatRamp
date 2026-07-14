//! HTTP conformance suite for the serving pipeline + control-plane auth +
//! visitor access control. Drives the real `router()` over an in-memory
//! `Storage` + `KvStore` via `tower::oneshot`, so it exercises routing,
//! conditional/range/compression negotiation, header rules, virtualhosts,
//! token auth, and access control end to end.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use boatramp_core::access::{AccessConfig, BasicAuth, IpRules};
use boatramp_core::authz::GrantedRole;
use boatramp_core::config::{
    DeployConfig, DomainConfig, HeaderRule, Hsts, Redirect, SecurityConfig, SiteConfig,
};
use boatramp_core::cose::{self, Claims, LocalSigner, Signer, TokenAlg};
use boatramp_core::deploy::{sha256_hex, DeployStore, FileEntry, Manifest, Variant};
use boatramp_core::domain_verify::{DomainProbe, DomainVerification, VerifyError};
use boatramp_core::gateway::{GatewayConfig, GatewayRoute, HeaderOps, PassiveHealth, Upstream};
use boatramp_core::kv::MemoryKv;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_server::{router, router_with, Auth, HandlerRuntime, ServerLimits, ServerOptions};
use futures::StreamExt;
use tower::ServiceExt;

// ---- in-memory Storage -----------------------------------------------------

#[derive(Default)]
struct MemStorage {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait::async_trait]
impl Storage for MemStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        let bytes = self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
        Ok(stream_object(key, bytes))
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        let bytes = self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
        let start = (offset as usize).min(bytes.len());
        let end = match len {
            Some(n) => (start + n as usize).min(bytes.len()),
            None => bytes.len(),
        };
        Ok(stream_object(key, bytes[start..end].to_vec()))
    }

    async fn put(
        &self,
        key: &str,
        mut body: ByteStream,
        _meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk?);
        }
        let size = buf.len() as u64;
        self.objects.lock().unwrap().insert(key.to_string(), buf);
        Ok(ObjectMeta {
            key: key.to_string(),
            size: Some(size),
            ..Default::default()
        })
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let map = self.objects.lock().unwrap();
        let bytes = map
            .get(key)
            .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
        Ok(ObjectMeta {
            key: key.to_string(),
            size: Some(bytes.len() as u64),
            ..Default::default()
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| ObjectMeta {
                key: k.clone(),
                size: Some(v.len() as u64),
                ..Default::default()
            })
            .collect())
    }
}

fn stream_object(key: &str, bytes: Vec<u8>) -> GetObject {
    let size = bytes.len() as u64;
    let body: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
    GetObject {
        meta: ObjectMeta {
            key: key.to_string(),
            size: Some(size),
            ..Default::default()
        },
        body,
    }
}

// ---- seeding ---------------------------------------------------------------

const BIG: &[u8] = &[b'x'; 100];
const JS_IDENTITY: &[u8] = b"console.log('hello world from boatramp');";
const JS_BR: &[u8] = b"<<fake-brotli-bytes>>";

fn file(bytes: &[u8], content_type: Option<&str>) -> (String, FileEntry) {
    let hash = sha256_hex(bytes);
    (
        hash.clone(),
        FileEntry {
            hash,
            size: bytes.len() as u64,
            content_type: content_type.map(String::from),
            variants: BTreeMap::new(),
        },
    )
}

async fn seed() -> DeployStore {
    let deploy = DeployStore::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));

    let put = |bytes: &'static [u8]| {
        let deploy = deploy.clone();
        async move {
            let hash = sha256_hex(bytes);
            let stream: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            deploy.put_blob(&hash, stream).await.unwrap();
            hash
        }
    };

    let (index_hash, index_entry) = file(b"<h1>home</h1>", Some("text/html"));
    let (about_hash, about_entry) = file(b"<h1>about</h1>", Some("text/html"));
    let (nf_hash, nf_entry) = file(b"<h1>nope</h1>", Some("text/html"));
    let (big_hash, big_entry) = file(BIG, Some("text/plain"));
    let (_js_hash, mut js_entry) = file(JS_IDENTITY, Some("text/javascript"));
    js_entry.variants.insert(
        "br".to_string(),
        Variant {
            hash: sha256_hex(JS_BR),
            size: JS_BR.len() as u64,
        },
    );

    put(b"<h1>home</h1>").await;
    put(b"<h1>about</h1>").await;
    put(b"<h1>nope</h1>").await;
    put(BIG).await;
    put(JS_IDENTITY).await;
    put(JS_BR).await;

    let mut files = BTreeMap::new();
    files.insert("index.html".to_string(), index_entry);
    files.insert("about.html".to_string(), about_entry);
    files.insert("404.html".to_string(), nf_entry);
    files.insert("big.txt".to_string(), big_entry);
    files.insert("app.js".to_string(), js_entry);

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
    // sanity: the hashes we recorded match the blobs we stored.
    assert_eq!(index_hash, sha256_hex(b"<h1>home</h1>"));
    assert_eq!(about_hash, sha256_hex(b"<h1>about</h1>"));
    assert_eq!(nf_hash, sha256_hex(b"<h1>nope</h1>"));
    assert_eq!(big_hash, sha256_hex(BIG));

    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("test", &id).await.unwrap();
    deploy
}

// ---- request helpers -------------------------------------------------------

async fn send(
    deploy: &DeployStore,
    req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    send_as(deploy, Auth::disabled(), req, [127, 0, 0, 1]).await
}

async fn send_as(
    deploy: &DeployStore,
    auth: Auth,
    mut req: Request<Body>,
    ip: [u8; 4],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let addr = SocketAddr::from((ip, 40000));
    req.extensions_mut().insert(ConnectInfo(addr));
    let response = router(deploy.clone(), auth, HandlerRuntime::disabled())
        .oneshot(req)
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

/// Like [`send`], but with a `single-tenant` posture that **permits** site-declared
/// private/loopback and unix-socket gateway upstreams. The gateway tests proxy to
/// local dev upstreams, which the strict `multi-tenant` default refuses;
/// those refusals have their own negative tests.
async fn send_gw(
    deploy: &DeployStore,
    mut req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let options = ServerOptions {
        posture: boatramp_core::security::SecurityProfile::SingleTenant.preset(),
        ..Default::default()
    };
    let response = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        options,
    )
    .oneshot(req)
    .await
    .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

/// A token [`Auth`] over a fresh keypair plus a token minted from it carrying
/// `roles`. The default RBAC policy applies (the `MemoryKv` has no
/// `authz/policy`); no TTL, so the mint timestamp is irrelevant.
async fn token_auth(roles: &[GrantedRole]) -> (Auth, String) {
    let signer = LocalSigner::generate(TokenAlg::Es256);
    let claims = Claims {
        roles: roles.to_vec(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: None,
        now_unix: 0,
    };
    let token = cose::mint(&claims, &signer).await.expect("mint token");
    let auth = Auth::with_key(signer.public_key(), Arc::new(MemoryKv::new()));
    (auth, token)
}

/// Set `Authorization: Bearer <token>` on a request.
fn with_bearer(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    req
}

/// Attach a `ConnectInfo` extension (the router's middleware expects one) for
/// tests that drive `router_with(...).oneshot(...)` directly.
#[cfg(feature = "oidc")]
fn with_conn(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    req
}

/// A request with a JSON body (for the control-plane PUT/POST endpoints).
fn json_request(method: &str, uri: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post(uri: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

// ---- tests -----------------------------------------------------------------

#[tokio::test]
async fn index_clean_urls_and_security_header() {
    let deploy = seed().await;
    let (status, headers, body) = send(&deploy, get("/_sites/test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

    // clean URL: /about -> about.html
    let (status, _, body) = send(&deploy, get("/_sites/test/about")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>about</h1>");
}

#[tokio::test]
async fn by_name_route_serves_site() {
    // Sites are reachable by name at `/_sites/<name>/…` (admin/testing).
    let deploy = seed().await;
    let (status, _, body) = send(&deploy, get("/_sites/test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");

    let (status, _, body) = send(&deploy, get("/_sites/test/about")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>about</h1>");

    // The old `/sites/<name>/` prefix is gone (no legacy alias).
    let (status, _, _) = send(&deploy, get("/sites/test/")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn redirect_and_custom_404() {
    let deploy = seed().await;
    let (status, headers, _) = send(&deploy, get("/_sites/test/old")).await;
    assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(headers[header::LOCATION], "/new");

    let (status, _, body) = send(&deploy, get("/_sites/test/does-not-exist")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, b"<h1>nope</h1>"); // custom error document
}

#[tokio::test]
async fn conditional_304() {
    let deploy = seed().await;
    let (_, headers, _) = send(&deploy, get("/_sites/test/")).await;
    let etag = headers[header::ETAG].to_str().unwrap().to_string();

    let mut req = get("/_sites/test/");
    req.headers_mut()
        .insert(header::IF_NONE_MATCH, etag.parse().unwrap());
    let (status, _, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
}

#[tokio::test]
async fn range_206_and_416() {
    let deploy = seed().await;
    let mut req = get("/_sites/test/big.txt");
    req.headers_mut()
        .insert(header::RANGE, "bytes=0-9".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body.len(), 10);
    assert_eq!(headers[header::CONTENT_RANGE], "bytes 0-9/100");

    let mut req = get("/_sites/test/big.txt");
    req.headers_mut()
        .insert(header::RANGE, "bytes=500-600".parse().unwrap());
    let (status, _, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
}

#[tokio::test]
async fn multi_range_206_multipart_byteranges() {
    let deploy = seed().await; // big.txt is 100 bytes
    let mut req = get("/_sites/test/big.txt");
    req.headers_mut()
        .insert(header::RANGE, "bytes=0-9,20-29,90-".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;

    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    let ct = headers[header::CONTENT_TYPE].to_str().unwrap().to_string();
    assert!(
        ct.starts_with("multipart/byteranges; boundary="),
        "got {ct}"
    );
    // Content-Length is computed up front and matches the streamed body.
    let declared: usize = headers[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(declared, body.len());

    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Content-Range: bytes 0-9/100"));
    assert!(text.contains("Content-Range: bytes 20-29/100"));
    assert!(text.contains("Content-Range: bytes 90-99/100"));
    let boundary = ct.rsplit("boundary=").next().unwrap();
    assert!(
        text.contains(&format!("--{boundary}--")),
        "closing boundary"
    );
}

/// Spawn a local mock HTTP upstream that echoes its path and the `Host` it saw.
/// Returns the bound port (loopback — a "private" address the gateway permits
/// only because it is a declared upstream).
async fn spawn_mock_upstream() -> u16 {
    let app = axum::Router::new().fallback(|req: Request<Body>| async move {
        let path = req.uri().path().to_string();
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let mut resp = axum::response::Response::new(Body::from(format!("UP:{path}")));
        resp.headers_mut()
            .insert("x-upstream", "mock".parse().unwrap());
        resp.headers_mut()
            .insert("x-saw-host", host.parse().unwrap());
        resp
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    port
}

/// Gateway: a declared upstream forwards a matching route to a private
/// (loopback) backend, applying strip-prefix, host-header override, and a
/// response header rewrite.
#[tokio::test]
async fn gateway_proxies_to_declared_upstream() {
    let port = spawn_mock_upstream().await;
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("gw.local".into()),
                    ..Default::default()
                },
                gateway: Some(GatewayConfig {
                    upstreams: BTreeMap::from([(
                        "backend".to_string(),
                        Upstream {
                            target: format!("http://127.0.0.1:{port}"),
                            host_header: Some("internal.example".into()),
                            strip_prefix: Some("/app".into()),
                            header_down: HeaderOps {
                                set: BTreeMap::from([(
                                    "x-via".to_string(),
                                    "boatramp".to_string(),
                                )]),
                                remove: Vec::new(),
                            },
                            ..Default::default()
                        },
                    )]),
                    routes: vec![GatewayRoute {
                        matches: "/app/**".into(),
                        upstream: "backend".into(),
                    }],
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Host-routed `/app/foo` → upstream `/foo` (strip-prefix), with the host
    // override and the injected response header.
    let mut req = get("/app/foo");
    req.headers_mut()
        .insert(header::HOST, "gw.local".parse().unwrap());
    let (status, headers, body) = send_gw(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-upstream"], "mock");
    assert_eq!(String::from_utf8_lossy(&body), "UP:/foo");
    assert_eq!(headers["x-saw-host"], "internal.example");
    assert_eq!(headers["x-via"], "boatramp");

    // A path outside the gateway routes falls through to normal serving (404
    // here — no such file): the gateway doesn't capture everything.
    let mut req = get("/not-proxied");
    req.headers_mut()
        .insert(header::HOST, "gw.local".parse().unwrap());
    let (status, headers, _) = send(&deploy, req).await;
    assert!(!headers.contains_key("x-upstream"));
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Under the strict `multi-tenant` default, a site-declared upstream
/// resolving to a private/loopback address is refused. Site config is
/// `site-write`; only the operator posture can permit private upstreams.
#[tokio::test]
async fn gateway_refuses_site_private_upstream_under_multi_tenant() {
    let port = spawn_mock_upstream().await; // listens on 127.0.0.1 (non-global)
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("gw.local".into()),
                    ..Default::default()
                },
                gateway: Some(GatewayConfig {
                    upstreams: BTreeMap::from([(
                        "backend".to_string(),
                        Upstream {
                            target: format!("http://127.0.0.1:{port}"),
                            ..Default::default()
                        },
                    )]),
                    routes: vec![GatewayRoute {
                        matches: "/app/**".into(),
                        upstream: "backend".into(),
                    }],
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut req = get("/app/foo");
    req.headers_mut()
        .insert(header::HOST, "gw.local".parse().unwrap());
    // `send` uses the default multi-tenant posture → the loopback upstream is
    // refused before any connection (so the live mock is never reached).
    let (status, _, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Under the strict `multi-tenant` default, a site-declared `unix:`
/// socket upstream is refused (it could reach local admin sockets such as the
/// Docker/containerd/SSH-agent socket); it needs operator opt-in via the posture.
#[tokio::test]
async fn gateway_refuses_site_unix_upstream_under_multi_tenant() {
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("unix.local".into()),
                    ..Default::default()
                },
                gateway: Some(GatewayConfig {
                    upstreams: BTreeMap::from([(
                        "backend".to_string(),
                        Upstream {
                            target: "unix:/tmp/boatramp-should-not-connect.sock".to_string(),
                            ..Default::default()
                        },
                    )]),
                    routes: vec![GatewayRoute {
                        matches: "/svc/**".into(),
                        upstream: "backend".into(),
                    }],
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut req = get("/svc/hello");
    req.headers_mut()
        .insert(header::HOST, "unix.local".parse().unwrap());
    // Refused before connecting — the socket path is never touched.
    let (status, _, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A mock upstream that tags every response with `x-backend: <port>`, so a test
/// can tell which pool member served it.
async fn spawn_tagged_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().fallback(move |_req: Request<Body>| async move {
        let mut resp = axum::response::Response::new(Body::from("ok"));
        resp.headers_mut()
            .insert("x-backend", port.to_string().parse().unwrap());
        resp
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    port
}

/// A TCP port nothing is listening on (bind then drop), for failover tests.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Gateway: a backend **pool** is load-balanced round-robin across healthy
/// members, and a body-less request fails over to another backend when one is
/// dead (the dead member is then ejected by passive health).
#[tokio::test]
async fn gateway_load_balances_and_fails_over_a_pool() {
    let a = spawn_tagged_upstream().await;
    let b = spawn_tagged_upstream().await;
    let dead = free_port().await;
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("pool.local".into()),
                    ..Default::default()
                },
                gateway: Some(GatewayConfig {
                    upstreams: BTreeMap::from([
                        (
                            "lbpool".to_string(),
                            Upstream {
                                targets: vec![
                                    format!("http://127.0.0.1:{a}"),
                                    format!("http://127.0.0.1:{b}"),
                                ],
                                ..Default::default()
                            },
                        ),
                        (
                            "failover".to_string(),
                            Upstream {
                                targets: vec![
                                    format!("http://127.0.0.1:{dead}"),
                                    format!("http://127.0.0.1:{a}"),
                                ],
                                max_retries: 1,
                                passive_health: Some(PassiveHealth {
                                    max_fails: 1,
                                    fail_timeout_ms: 60_000,
                                }),
                                ..Default::default()
                            },
                        ),
                    ]),
                    routes: vec![
                        GatewayRoute {
                            matches: "/lb/**".into(),
                            upstream: "lbpool".into(),
                        },
                        GatewayRoute {
                            matches: "/fail/**".into(),
                            upstream: "failover".into(),
                        },
                    ],
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Round-robin spreads requests across both healthy backends.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..6 {
        let mut req = get("/lb/x");
        req.headers_mut()
            .insert(header::HOST, "pool.local".parse().unwrap());
        let (status, headers, _) = send_gw(&deploy, req).await;
        assert_eq!(status, StatusCode::OK);
        seen.insert(headers["x-backend"].to_str().unwrap().to_string());
    }
    assert_eq!(seen.len(), 2, "both backends served: {seen:?}");

    // Failover: a body-less GET retries past the dead backend to the live one.
    for _ in 0..3 {
        let mut req = get("/fail/y");
        req.headers_mut()
            .insert(header::HOST, "pool.local".parse().unwrap());
        let (status, headers, _) = send_gw(&deploy, req).await;
        assert_eq!(status, StatusCode::OK, "failover keeps the request alive");
        assert_eq!(headers["x-backend"], a.to_string());
    }
}

/// Spawn a mock HTTP/1 upstream on a unix-domain socket; echoes its path.
async fn spawn_unix_mock(path: std::path::PathBuf) {
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        let path = req.uri().path().to_string();
                        let resp = hyper::Response::builder()
                            .header("x-upstream", "unixmock")
                            .body(http_body_util::Full::<bytes::Bytes>::new(
                                bytes::Bytes::from(format!("UNIX:{path}")),
                            ))
                            .unwrap();
                        Ok::<_, std::convert::Infallible>(resp)
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
}

/// Gateway: a `unix:/path` upstream forwards over a unix-domain socket.
#[tokio::test]
async fn gateway_proxies_to_unix_socket_upstream() {
    let sock = std::env::temp_dir().join(format!("br-gw-{}.sock", std::process::id()));
    spawn_unix_mock(sock.clone()).await;
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("unix.local".into()),
                    ..Default::default()
                },
                gateway: Some(GatewayConfig {
                    upstreams: BTreeMap::from([(
                        "sock".to_string(),
                        Upstream {
                            target: format!("unix:{}", sock.display()),
                            strip_prefix: Some("/svc".into()),
                            ..Default::default()
                        },
                    )]),
                    routes: vec![GatewayRoute {
                        matches: "/svc/**".into(),
                        upstream: "sock".into(),
                    }],
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut req = get("/svc/hello");
    req.headers_mut()
        .insert(header::HOST, "unix.local".parse().unwrap());
    let (status, headers, body) = send_gw(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-upstream"], "unixmock");
    assert_eq!(String::from_utf8_lossy(&body), "UNIX:/hello"); // strip_prefix applied
    let _ = std::fs::remove_file(&sock);
}

/// A raw TCP "WebSocket-ish" upstream: reads the request headers, replies `101
/// Switching Protocols`, then echoes every byte (enough to exercise the bridge
/// without real WS framing).
async fn spawn_ws_echo_upstream() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                // Read request headers up to the blank line.
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                            Connection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n";
                if stream.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // Echo loop over the upgraded connection.
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&tmp[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Gateway: a WebSocket upgrade is forwarded to the upstream and, on `101`,
/// the two connections are bridged both ways. Served over a real listener
/// (upgrades need a live connection, not `oneshot`).
#[tokio::test]
async fn gateway_bridges_websocket_upgrade() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream_port = spawn_ws_echo_upstream().await;
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("ws.local".into()),
                    ..Default::default()
                },
                gateway: Some(GatewayConfig {
                    upstreams: BTreeMap::from([(
                        "ws".to_string(),
                        Upstream {
                            target: format!("http://127.0.0.1:{upstream_port}"),
                            ..Default::default()
                        },
                    )]),
                    routes: vec![GatewayRoute {
                        matches: "/ws/**".into(),
                        upstream: "ws".into(),
                    }],
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Serve boatramp over a real TCP listener (axum::serve enables upgrades).
    // Single-tenant posture so the loopback ws upstream is permitted.
    let gw_options = ServerOptions {
        posture: boatramp_core::security::SecurityProfile::SingleTenant.preset(),
        ..Default::default()
    };
    let app = router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        gw_options,
    )
    .into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Raw upgrade handshake through boatramp.
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let handshake = "GET /ws/echo HTTP/1.1\r\nHost: ws.local\r\nConnection: Upgrade\r\n\
                     Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n";
    client.write_all(handshake.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = client.read(&mut tmp).await.unwrap();
        assert_ne!(n, 0, "connection closed before 101");
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
        "expected 101, got: {}",
        String::from_utf8_lossy(&head)
    );

    // The bridge is live: bytes round-trip through boatramp to the echo upstream.
    client.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
}

#[tokio::test]
async fn compression_negotiation_and_header_rules() {
    let deploy = seed().await;
    // No Accept-Encoding -> identity, with the header-rule cache-control.
    let (status, headers, body) = send(&deploy, get("/_sites/test/app.js")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, JS_IDENTITY);
    assert_eq!(headers[header::CACHE_CONTROL], "immutable");
    assert_eq!(headers[header::VARY], "accept-encoding");

    // Accept-Encoding: br -> serve the br variant blob.
    let mut req = get("/_sites/test/app.js");
    req.headers_mut()
        .insert(header::ACCEPT_ENCODING, "br".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_ENCODING], "br");
    assert_eq!(body, JS_BR);
}

#[tokio::test]
async fn non_get_to_static_is_405() {
    let deploy = seed().await;
    let (status, headers, _) = send(&deploy, post("/_sites/test/")).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers[header::ALLOW], "GET, HEAD");
}

#[tokio::test]
async fn virtualhost_routing() {
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("test.local".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut req = get("/");
    req.headers_mut()
        .insert(header::HOST, "test.local".parse().unwrap());
    let (status, _, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");
}

#[tokio::test]
async fn transport_redirects_and_hsts() {
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("test.local".into()),
                    aliases: vec!["www.test.local".into()],
                    canonical_redirect: true,
                    ..Default::default()
                },
                security: SecurityConfig {
                    https_redirect: true,
                    hsts: Some(Hsts::default()),
                    csp: Some("default-src 'self'".into()),
                    frame_options: Some("DENY".into()),
                },
                // The test peer (127.0.0.1) is a trusted proxy, so its
                // `X-Forwarded-Proto` is honored.
                access: AccessConfig {
                    trusted_proxies: vec!["127.0.0.1".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // An exact alias over http → one 301 to the canonical host on HTTPS.
    let mut req = get("/page?q=1");
    req.headers_mut()
        .insert(header::HOST, "www.test.local".parse().unwrap());
    req.headers_mut()
        .insert("x-forwarded-proto", "http".parse().unwrap());
    let (status, headers, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(headers[header::LOCATION], "https://test.local/page?q=1");

    // The canonical host over http → HTTPS upgrade only.
    let mut req = get("/");
    req.headers_mut()
        .insert(header::HOST, "test.local".parse().unwrap());
    req.headers_mut()
        .insert("x-forwarded-proto", "http".parse().unwrap());
    let (status, headers, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(headers[header::LOCATION], "https://test.local/");

    // The canonical host over https → served, with HSTS.
    let mut req = get("/");
    req.headers_mut()
        .insert(header::HOST, "test.local".parse().unwrap());
    req.headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");
    assert_eq!(
        headers["strict-transport-security"],
        "max-age=31536000; includeSubDomains"
    );
    // Opt-in CSP + X-Frame-Options, plus the blanket Referrer-Policy default.
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "default-src 'self'"
    );
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(
        headers[header::REFERRER_POLICY],
        "strict-origin-when-cross-origin"
    );
}

/// A direct (untrusted) client cannot forge `X-Forwarded-Proto:
/// https` to skip the HTTPS redirect — the header is honored only from a
/// configured trusted proxy. Here there are none, so the forged header is
/// ignored and the (plain-HTTP) listener scheme drives the redirect.
#[tokio::test]
async fn forwarded_proto_ignored_from_untrusted_peer() {
    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("test.local".into()),
                    ..Default::default()
                },
                security: SecurityConfig {
                    https_redirect: true,
                    ..Default::default()
                },
                // No trusted_proxies → the peer's X-Forwarded-Proto is not honored.
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut req = get("/");
    req.headers_mut()
        .insert(header::HOST, "test.local".parse().unwrap());
    req.headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    // `send` uses peer 127.0.0.1, which is not a trusted proxy here.
    let (status, headers, _) = send(&deploy, req).await;
    assert_eq!(
        status,
        StatusCode::MOVED_PERMANENTLY,
        "a forged X-Forwarded-Proto must not skip the HTTPS redirect"
    );
    assert_eq!(headers[header::LOCATION], "https://test.local/");
}

#[tokio::test]
async fn control_plane_requires_token() {
    let deploy = seed().await;
    let (auth, token) = token_auth(&[GrantedRole::global("admin")]).await;

    // No token -> 401.
    let (status, _, _) = send_as(
        &deploy,
        auth.clone(),
        get("/api/sites/test/current"),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Valid admin token -> 200.
    let req = with_bearer(get("/api/sites/test/current"), &token);
    let (status, _, _) = send_as(&deploy, auth, req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);

    // Public serving is never token-gated.
    let (status, _, _) = send(&deploy, get("/_sites/test/")).await;
    assert_eq!(status, StatusCode::OK);
}

/// A delegatable admin token attenuated **offline** to read-only is narrowed at
/// the HTTP layer: it may read but not write, even though its root roles are admin
/// (the caveat subtracts from the RBAC decision).
#[tokio::test]
async fn delegated_credential_is_narrowed_at_the_http_layer() {
    let deploy = seed().await;
    let root = LocalSigner::generate(TokenAlg::Es256);
    let holder = LocalSigner::generate(TokenAlg::Es256);
    let claims = Claims {
        roles: vec![GrantedRole::global("admin")],
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: None,
        now_unix: 0,
    };
    let root_token = cose::mint_delegatable(&claims, &holder.public_key(), &root)
        .await
        .unwrap();
    let read_only = cose::attenuate(
        &root_token,
        &holder,
        &cose::Caveats::restrict(None, true, None),
        None,
        0,
    )
    .await
    .unwrap();
    let auth = Auth::with_key(root.public_key(), Arc::new(MemoryKv::new()));

    // The delegated credential may READ (admin root, read action allowed).
    let req = with_bearer(get("/api/sites/test/current"), &read_only);
    let (status, _, _) = send_as(&deploy, auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);

    // …but the read_only caveat blocks a write, despite the admin root roles.
    let put = Request::builder()
        .method("PUT")
        .uri("/api/sites/test/config")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let put = with_bearer(put, &read_only);
    let (status, _, _) = send_as(&deploy, auth, put, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Granular RBAC at the HTTP layer: a `viewer:test` token may read the site
/// but not write its config or touch another site.
#[tokio::test]
async fn control_plane_enforces_granular_rights() {
    let deploy = seed().await;
    let (auth, token) = token_auth(&[GrantedRole::scoped("viewer", "test")]).await;

    // viewer can read its site's current deployment.
    let req = with_bearer(get("/api/sites/test/current"), &token);
    let (status, _, _) = send_as(&deploy, auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);

    // …but cannot write the site config (needs site:write).
    let put = Request::builder()
        .method("PUT")
        .uri("/api/sites/test/config")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let put = with_bearer(put, &token);
    let (status, _, _) = send_as(&deploy, auth.clone(), put, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // …and cannot read a different site.
    let req = with_bearer(get("/api/sites/other/current"), &token);
    let (status, _, _) = send_as(&deploy, auth, req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// `whoami` reports the caller's own roles (any valid token), and 401s without
/// one.
#[tokio::test]
async fn auth_whoami_reports_roles() {
    let deploy = seed().await;
    let (auth, token) = token_auth(&[GrantedRole::scoped("publisher", "blog")]).await;

    let req = with_bearer(get("/api/auth/whoami"), &token);
    let (status, _, body) = send_as(&deploy, auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);
    let who: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(who["auth_enabled"], serde_json::json!(true));
    assert_eq!(
        who["roles"],
        serde_json::json!([{"name": "publisher", "target": "blog"}])
    );

    // No token → 401.
    let (status, _, _) = send_as(&deploy, auth, get("/api/auth/whoami"), [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// `whoami` validates the token's TTL/revocation/caveats — not just
/// its signature — so an expired (or revoked) token discloses no roles.
#[tokio::test]
async fn whoami_rejects_expired_token() {
    let deploy = seed().await;
    // Build the auth + an expired token from the *same* keypair (so the
    // signature is valid; only the TTL fails).
    let signer = LocalSigner::generate(TokenAlg::Es256);
    let auth = Auth::with_key(signer.public_key(), Arc::new(MemoryKv::new()));
    // TTL of 1s, issued at the epoch → long expired by now.
    let expired = cose::mint(
        &Claims {
            roles: vec![GrantedRole::global("admin")],
            kind: cose::KIND_ROLE.to_string(),
            ttl_secs: Some(1),
            now_unix: 0,
        },
        &signer,
    )
    .await
    .expect("mint");

    let req = with_bearer(get("/api/auth/whoami"), &expired);
    let (status, _, _) = send_as(&deploy, auth, req, [127, 0, 0, 1]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an expired token must not disclose its roles via whoami"
    );
}

/// The RBAC policy endpoint (`/api/authz/policy`): admin get/put with
/// validation, and admin-only access.
#[tokio::test]
async fn authz_policy_endpoint() {
    let deploy = seed().await;
    let (admin_auth, admin) = token_auth(&[GrantedRole::global("admin")]).await;

    // GET returns the built-in default (the `admin` role is present).
    let req = with_bearer(get("/api/authz/policy"), &admin);
    let (status, _, body) = send_as(&deploy, admin_auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);
    let policy: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(policy["roles"]["admin"].is_array());

    // PUT a valid custom policy → 204; GET reflects it (default replaced).
    let custom = serde_json::json!({
        "version": 1,
        "roles": { "editor": [ {"resource": "site", "action": "write", "scope": "role_target"} ] }
    });
    let put = json_request("PUT", "/api/authz/policy", &custom);
    let (status, _, _) = send_as(
        &deploy,
        admin_auth.clone(),
        with_bearer(put, &admin),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let req = with_bearer(get("/api/authz/policy"), &admin);
    let (status, _, body) = send_as(&deploy, admin_auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);
    let policy: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(policy["roles"]["editor"].is_array());
    assert!(policy["roles"]["admin"].is_null(), "default was replaced");

    // PUT an invalid policy (unsafe role name) → 400, nothing stored.
    let bad = serde_json::json!({ "version": 1, "roles": { "ev\"il": [] } });
    let put = json_request("PUT", "/api/authz/policy", &bad);
    let (status, _, _) = send_as(
        &deploy,
        admin_auth,
        with_bearer(put, &admin),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A site-scoped viewer can't touch the policy (needs system·admin).
    let (viewer_auth, viewer) = token_auth(&[GrantedRole::scoped("viewer", "test")]).await;
    let req = with_bearer(get("/api/authz/policy"), &viewer);
    let (status, _, _) = send_as(&deploy, viewer_auth, req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The compute control-plane API (`/api/compute`): admin CRUD over workloads,
/// admin-scoped.
#[tokio::test]
async fn compute_api_crud() {
    let deploy = seed().await;
    let (auth, admin) = token_auth(&[GrantedRole::global("admin")]).await;

    // PUT a workload (spec content-addressed server-side).
    let body = serde_json::json!({
        "spec": {
            "version": 1,
            "rootfs": "a".repeat(64),
            "kernel": "b".repeat(64),
            "vcpus": 1,
            "mem_mib": 256,
            "port": 8080
        },
        "replicas": 2
    });
    let put = with_bearer(json_request("PUT", "/api/compute/api", &body), &admin);
    let (status, _, rbody) = send_as(&deploy, auth.clone(), put, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    assert_eq!(created["spec"].as_str().unwrap().len(), 64);

    // GET it back.
    let req = with_bearer(get("/api/compute/api"), &admin);
    let (status, _, body) = send_as(&deploy, auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);
    let workload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(workload["name"], "api");
    assert_eq!(workload["replicas"], 2);

    // List shows it.
    let req = with_bearer(get("/api/compute"), &admin);
    let (status, _, body) = send_as(&deploy, auth.clone(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Delete it.
    let del = Request::builder()
        .method("DELETE")
        .uri("/api/compute/api")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send_as(
        &deploy,
        auth.clone(),
        with_bearer(del, &admin),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A viewer can't manage compute (admin-scoped).
    let (vauth, vtok) = token_auth(&[GrantedRole::scoped("viewer", "test")]).await;
    let req = with_bearer(get("/api/compute"), &vtok);
    let (status, _, _) = send_as(&deploy, vauth, req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn access_control_basic_auth_and_ip() {
    let deploy = seed().await;

    // Basic auth required.
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                access: AccessConfig {
                    basic_auth: Some(BasicAuth {
                        realm: "Members".into(),
                        users: BTreeMap::from([(
                            "u".to_string(),
                            boatramp_core::access::hash_password("p"),
                        )]),
                    }),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (status, headers, _) = send(&deploy, get("/_sites/test/")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .contains("Members"));

    // With credentials -> 200.
    let creds = base64_encode("u:p");
    let mut req = get("/_sites/test/");
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Basic {creds}").parse().unwrap(),
    );
    let (status, _, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");

    // IP deny: block the test client (127.0.0.1).
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                access: AccessConfig {
                    ip: IpRules {
                        deny: vec!["127.0.0.1".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (status, _, _) = send_as(
        &deploy,
        Auth::disabled(),
        get("/_sites/test/"),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

// ---- WebAssembly handler dispatch ------------------------------------------

/// End-to-end: a deploy declaring a `wasi:http` + `wasi:keyvalue` handler is
/// served through the real `router()`. The component (the `kv-counter` fixture)
/// increments a per-site counter and returns it; routing → dispatch → engine →
/// kv binding all run, and the counter persists across requests under the
/// site's `hkv/{site}/` prefix.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn handler_route_dispatches_through_engine() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    // Store the component as a content-addressed blob.
    let hash = sha256_hex(KV_COUNTER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    // A deployment whose `/count` route is served by the component.
    let mut files = BTreeMap::new();
    files.insert(
        "handlers/counter.wasm".to_string(),
        FileEntry {
            hash: hash.clone(),
            size: KV_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let config = DeployConfig {
        handlers: vec![HandlerConfig {
            route: "/count".to_string(),
            methods: Vec::new(),
            component: "handlers/counter.wasm".to_string(),
            imports: vec!["wasi:keyvalue".to_string()],
            limits: None,
            env: BTreeMap::new(),
        }],
        ..Default::default()
    };
    let manifest = Manifest {
        files,
        config,
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();

    // Site grants the keyvalue capability.
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["wasi:keyvalue".to_string()],
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    // Two requests: the counter persists across invocations.
    for expected in ["hits=1\n", "hits=2\n"] {
        let mut req = Request::builder()
            .method("GET")
            .uri("/_sites/blog/count")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(&body[..], expected.as_bytes());
    }

    // The counter landed under the site's handler-kv prefix.
    use boatramp_core::kv::KvStore;
    assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"2".to_vec()));
}

// ---- function invoke API (FA-3) --------------------------------------------

/// Deploy a top-level function straight into the store: upload `component` as a
/// content-addressed blob and store a `Function` whose single active version is
/// it. Returns the component hash (= the version id).
#[cfg(feature = "handlers")]
async fn deploy_test_function(
    deploy: &DeployStore,
    name: &str,
    component: &[u8],
    imports: Vec<String>,
) -> String {
    use boatramp_core::function::{Function, FunctionConfig, Lifecycle, Owner};
    let hash = sha256_hex(component);
    let bytes = component.to_vec();
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();
    let config = FunctionConfig {
        imports,
        ..Default::default()
    };
    let f = Function::new(
        name,
        Owner::Project("default".into()),
        &hash,
        config,
        Lifecycle::Independent,
        0,
    );
    deploy.put_function(&f).await.unwrap();
    hash
}

/// Build a `POST /api/functions/<name>/invoke` request with an optional
/// `?mode=` and `Idempotency-Key`.
#[cfg(feature = "handlers")]
fn invoke_request(name: &str, mode: Option<&str>, idem: Option<&str>) -> Request<Body> {
    let uri = match mode {
        Some(m) => format!("/api/functions/{name}/invoke?mode={m}"),
        None => format!("/api/functions/{name}/invoke"),
    };
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(key) = idem {
        builder = builder.header("idempotency-key", key);
    }
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40100))));
    req
}

/// Sync invoke runs the component inline and returns its response; a repeated
/// `Idempotency-Key` replays the first outcome instead of running again (proven
/// by the counter fixture advancing only once).
#[cfg(feature = "handlers")]
#[tokio::test]
async fn function_invoke_sync_and_idempotency() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_test_function(&deploy, "counter", KV_COUNTER, vec!["wasi:keyvalue".into()]).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    // Two plain sync invokes run twice — the counter advances 1 → 2.
    for expected in ["hits=1\n", "hits=2\n"] {
        let resp = app
            .clone()
            .oneshot(invoke_request("counter", None, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], expected.as_bytes());
    }

    // Same idempotency key twice → the second replays the first (still hits=3).
    let mut seen = Vec::new();
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(invoke_request("counter", None, Some("k-1")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        seen.push(String::from_utf8_lossy(&body).into_owned());
    }
    assert_eq!(seen, vec!["hits=3\n".to_string(), "hits=3\n".to_string()]);

    // A fresh key runs again — hits=4, so exactly one run happened per key.
    let resp = app
        .clone()
        .oneshot(invoke_request("counter", None, Some("k-2")))
        .await
        .unwrap();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"hits=4\n");

    // Invoking an unknown function is a 404.
    let resp = app
        .clone()
        .oneshot(invoke_request("ghost", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Async invoke returns `202` + an invocation id, the scheduler drains it, and a
/// poll reports `succeeded` with the captured result.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn function_invoke_async_drains_and_polls() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_test_function(&deploy, "counter", KV_COUNTER, vec!["wasi:keyvalue".into()]).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    // Drain worker: the scheduler tick processes queued invocations.
    let _scheduler = runtime.spawn_scheduler(deploy.clone());
    let app = router(deploy, Auth::disabled(), runtime);

    // Enqueue → 202 + a queued record.
    let resp = app
        .clone()
        .oneshot(invoke_request("counter", Some("async"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let queued: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(queued["status"], "queued");
    let id = queued["id"].as_str().unwrap().to_string();

    // Poll until the drain settles it (first scheduler tick fires immediately).
    let final_status = poll_invocation(&app, "counter", &id).await;
    assert_eq!(final_status["status"], "succeeded");
    assert_eq!(final_status["result"]["status"], 200);
    // The captured body is base64 of "hits=1\n".
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(final_status["result"]["body_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(&decoded[..], b"hits=1\n");
}

/// A durable invocation whose component can't run (a non-Wasm blob → a compile
/// failure = a delivery failure) is retried up to the cap, then dead-lettered
/// (`failed`, `attempts == MAX`).
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn function_invoke_async_dead_letters_on_repeated_failure() {
    use boatramp_handlers::{HandlerEngine, Limits};

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    // A blob that is present but is not a valid Wasm component: every run
    // compile-fails → a 500 → a retryable delivery failure.
    deploy_test_function(&deploy, "broken", b"not a wasm component", Vec::new()).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let _scheduler = runtime.spawn_scheduler(deploy.clone());
    let app = router(deploy, Auth::disabled(), runtime);

    let resp = app
        .clone()
        .oneshot(invoke_request("broken", Some("async"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let queued: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id = queued["id"].as_str().unwrap().to_string();

    let final_status = poll_invocation(&app, "broken", &id).await;
    assert_eq!(final_status["status"], "failed");
    assert_eq!(final_status["attempts"], 5); // MAX_INVOKE_ATTEMPTS
}

/// Deploy a top-level function with a usage `quota` set (FA-4).
#[cfg(feature = "handlers")]
async fn deploy_quota_function(
    deploy: &DeployStore,
    name: &str,
    component: &[u8],
    quota: boatramp_core::function::FunctionQuota,
) -> String {
    use boatramp_core::function::{Function, FunctionConfig, Lifecycle, Owner};
    let hash = sha256_hex(component);
    let bytes = component.to_vec();
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();
    let config = FunctionConfig {
        quota,
        ..Default::default()
    };
    let f = Function::new(
        name,
        Owner::Project("default".into()),
        &hash,
        config,
        Lifecycle::Independent,
        0,
    );
    deploy.put_function(&f).await.unwrap();
    hash
}

/// Fetch a function's usage aggregate via `GET /usage`.
#[cfg(feature = "handlers")]
async fn fetch_usage(app: &axum::Router, name: &str) -> serde_json::Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/functions/{name}/usage"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// The rate-limit quota admits up to `max_invocations` per window, then fails
/// closed with `429`; metering counts only the admitted+run invocations.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn function_invoke_quota_returns_429_and_meters_admitted() {
    use boatramp_core::function::FunctionQuota;
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_quota_function(
        &deploy,
        "limited",
        HTTP_200,
        FunctionQuota {
            max_invocations: Some(2),
            window_secs: Some(3600),
            max_concurrent: None,
        },
    )
    .await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    // First two admitted, third rate-limited (fail-closed).
    for expect in [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let resp = app
            .clone()
            .oneshot(invoke_request("limited", None, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), expect);
    }

    // Usage reflects only the two that ran.
    let usage = fetch_usage(&app, "limited").await;
    assert_eq!(usage["invocations"], 2);
    assert_eq!(usage["successes"], 2);
}

/// Metering accumulates per invocation and is tenant-isolated (one function's
/// usage never bleeds into another's).
#[cfg(feature = "handlers")]
#[tokio::test]
async fn function_invoke_meters_usage_per_function() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_test_function(&deploy, "alpha", HTTP_200, Vec::new()).await;
    deploy_test_function(&deploy, "beta", HTTP_200, Vec::new()).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    // Invoke alpha three times, beta once.
    for _ in 0..3 {
        let resp = app
            .clone()
            .oneshot(invoke_request("alpha", None, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = app
        .clone()
        .oneshot(invoke_request("beta", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let alpha = fetch_usage(&app, "alpha").await;
    assert_eq!(alpha["invocations"], 3);
    assert_eq!(alpha["successes"], 3);
    let beta = fetch_usage(&app, "beta").await;
    assert_eq!(beta["invocations"], 1);
    // A never-invoked function reports a zeroed aggregate, not a 404.
    let ghost = fetch_usage(&app, "ghost").await;
    assert_eq!(ghost["invocations"], 0);
}

// ---- signed webhook ingress (FA-5) -----------------------------------------

/// Deploy a function that declares a `webhook` verified by `secret_env` (FA-5).
#[cfg(feature = "handlers")]
async fn deploy_webhook_function(
    deploy: &DeployStore,
    name: &str,
    component: &[u8],
    secret_env: &str,
) -> String {
    use boatramp_core::function::{Function, FunctionConfig, Lifecycle, Owner, WebhookConfig};
    let hash = sha256_hex(component);
    let bytes = component.to_vec();
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();
    let config = FunctionConfig {
        webhook: Some(WebhookConfig {
            secret_env: secret_env.to_string(),
            algorithm: Default::default(),
            signature_header: None,
            max_body_bytes: None,
        }),
        ..Default::default()
    };
    let f = Function::new(
        name,
        Owner::Project("default".into()),
        &hash,
        config,
        Lifecycle::Independent,
        0,
    );
    deploy.put_function(&f).await.unwrap();
    hash
}

/// `HMAC-SHA256(body, secret)` as lowercase hex (mirrors the server's verifier).
#[cfg(feature = "handlers")]
fn hmac_sha256_hex(secret: &[u8], body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// A `POST /_webhooks/<name>` request with an optional signature header.
#[cfg(feature = "handlers")]
fn webhook_request(name: &str, body: &[u8], sig: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/_webhooks/{name}"));
    if let Some(s) = sig {
        builder = builder.header("x-boatramp-signature", s);
    }
    let mut req = builder.body(Body::from(body.to_vec())).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40200))));
    req
}

/// The webhook endpoint verifies the HMAC signature before dispatch: a valid
/// signature (bare or `sha256=`-prefixed) invokes the function; a bad or missing
/// one is `401`; a function without a webhook config is `404`.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn function_webhook_verifies_signature_before_dispatch() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let secret_env = "BOATRAMP_TEST_WEBHOOK_SECRET";
    std::env::set_var(secret_env, "s3cr3t-key");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_webhook_function(&deploy, "hook", HTTP_200, secret_env).await;
    // A plain function (no webhook config) for the 404 case.
    deploy_test_function(&deploy, "plain", HTTP_200, Vec::new()).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    let body = br#"{"event":"push"}"#;
    let sig = hmac_sha256_hex(b"s3cr3t-key", body);

    // Valid signature → the function runs (200).
    let resp = app
        .clone()
        .oneshot(webhook_request("hook", body, Some(&sig)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The GitHub-style `sha256=` prefix is accepted.
    let resp = app
        .clone()
        .oneshot(webhook_request(
            "hook",
            body,
            Some(&format!("sha256={sig}")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A wrong signature is rejected before the guest runs.
    let resp = app
        .clone()
        .oneshot(webhook_request("hook", body, Some("00deadbeef")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A signature over a *different* body is rejected (tamper).
    let good_for_other = hmac_sha256_hex(b"s3cr3t-key", b"other");
    let resp = app
        .clone()
        .oneshot(webhook_request("hook", body, Some(&good_for_other)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Missing signature header → 401.
    let resp = app
        .clone()
        .oneshot(webhook_request("hook", body, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A function without a webhook config → 404 (even with a plausible signature).
    let resp = app
        .clone()
        .oneshot(webhook_request("plain", body, Some(&sig)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---- workflow orchestration (FA-6) -----------------------------------------

/// `PUT /api/workflows/<name>` with a step DAG (asserts 200 or returns the status).
#[cfg(feature = "handlers")]
async fn define_workflow(app: &axum::Router, name: &str, steps: serde_json::Value) -> StatusCode {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/workflows/{name}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "steps": steps })).unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// Start a run (`POST .../runs`) and return its id.
#[cfg(feature = "handlers")]
async fn start_run(app: &axum::Router, name: &str) -> String {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/workflows/{name}/runs"))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40300))));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let run: serde_json::Value = serde_json::from_slice(&body).unwrap();
    run["id"].as_str().unwrap().to_string()
}

/// Poll a run until terminal (`succeeded`/`failed`).
#[cfg(feature = "handlers")]
async fn poll_run(app: &axum::Router, name: &str, id: &str) -> serde_json::Value {
    for _ in 0..120 {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/workflows/{name}/runs/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let run: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if matches!(run["status"].as_str(), Some("succeeded") | Some("failed")) {
            return run;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("workflow run {id} never terminated");
}

/// A 3-step chain (a → b → c) runs every step in order and the run succeeds.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn workflow_chain_runs_to_completion() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_test_function(&deploy, "counter", KV_COUNTER, vec!["wasi:keyvalue".into()]).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let _scheduler = runtime.spawn_scheduler(deploy.clone());
    let app = router(deploy, Auth::disabled(), runtime);

    let steps = serde_json::json!([
        { "id": "a", "function": "counter" },
        { "id": "b", "function": "counter", "depends_on": ["a"] },
        { "id": "c", "function": "counter", "depends_on": ["b"] },
    ]);
    assert_eq!(define_workflow(&app, "chain", steps).await, StatusCode::OK);
    let id = start_run(&app, "chain").await;

    let run = poll_run(&app, "chain", &id).await;
    assert_eq!(run["status"], "succeeded");
    for step in ["a", "b", "c"] {
        assert_eq!(run["steps"][step]["status"], "succeeded");
    }
}

/// A fan-out + fan-in DAG (root → {x,y,z} → join) runs the barrier join only once
/// all three parallel branches have completed, and the run succeeds.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn workflow_fan_out_and_join_completes() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_test_function(&deploy, "noop", HTTP_200, Vec::new()).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let _scheduler = runtime.spawn_scheduler(deploy.clone());
    let app = router(deploy, Auth::disabled(), runtime);

    let steps = serde_json::json!([
        { "id": "root", "function": "noop" },
        { "id": "x", "function": "noop", "depends_on": ["root"] },
        { "id": "y", "function": "noop", "depends_on": ["root"] },
        { "id": "z", "function": "noop", "depends_on": ["root"] },
        { "id": "join", "function": "noop", "depends_on": ["x", "y", "z"] },
    ]);
    assert_eq!(define_workflow(&app, "fan", steps).await, StatusCode::OK);
    let id = start_run(&app, "fan").await;

    let run = poll_run(&app, "fan", &id).await;
    assert_eq!(run["status"], "succeeded");
    for step in ["root", "x", "y", "z", "join"] {
        assert_eq!(run["steps"][step]["status"], "succeeded");
    }
}

/// A failing step fails the run and triggers reverse-order compensation of the
/// steps that already succeeded.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workflow_failing_step_triggers_compensation() {
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy_test_function(&deploy, "ok", HTTP_200, Vec::new()).await;
    deploy_test_function(&deploy, "comp", HTTP_200, Vec::new()).await;
    // A non-Wasm blob → the step function compile-fails → a step failure.
    deploy_test_function(&deploy, "bad", b"not a wasm component", Vec::new()).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let _scheduler = runtime.spawn_scheduler(deploy.clone());
    let app = router(deploy, Auth::disabled(), runtime);

    // a (ok, compensate=comp) → b (bad). b fails → run fails, a compensated.
    let steps = serde_json::json!([
        { "id": "a", "function": "ok", "compensate": "comp" },
        { "id": "b", "function": "bad", "depends_on": ["a"] },
    ]);
    assert_eq!(define_workflow(&app, "saga", steps).await, StatusCode::OK);
    let id = start_run(&app, "saga").await;

    let run = poll_run(&app, "saga", &id).await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["steps"]["b"]["status"], "failed");
    assert_eq!(run["steps"]["a"]["status"], "compensated");
}

/// The define endpoint validates the DAG: a cycle is a `400`.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn workflow_define_rejects_a_cycle() {
    use boatramp_handlers::{HandlerEngine, Limits};

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    let steps = serde_json::json!([
        { "id": "a", "function": "f", "depends_on": ["b"] },
        { "id": "b", "function": "f", "depends_on": ["a"] },
    ]);
    assert_eq!(
        define_workflow(&app, "cyclic", steps).await,
        StatusCode::BAD_REQUEST
    );
}

/// Poll `GET /api/functions/<name>/invocations/<id>` until it reaches a terminal
/// state (`succeeded`/`failed`), up to a generous ceiling (the scheduler ticks
/// every 500 ms; a dead-letter needs five ticks).
#[cfg(feature = "handlers")]
async fn poll_invocation(app: &axum::Router, name: &str, id: &str) -> serde_json::Value {
    for _ in 0..120 {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/functions/{name}/invocations/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let record: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if matches!(
            record["status"].as_str(),
            Some("succeeded") | Some("failed")
        ) {
            return record;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("invocation {id} never reached a terminal state");
}

/// Flipping the active deployment while traffic is in flight drops zero
/// requests (graceful drain). Handlers are instantiated per
/// request off a clone of the compiled component, so an activation just routes
/// *new* requests to the new deployment — in-flight invocations finish. We hold
/// 100 concurrent requests open while repeatedly flipping between two
/// deployments and assert every response is 200.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activation_during_traffic_drops_no_requests() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(KV_COUNTER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "handlers/counter.wasm".to_string(),
        FileEntry {
            hash: hash.clone(),
            size: KV_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let handler = HandlerConfig {
        route: "/count".to_string(),
        methods: Vec::new(),
        component: "handlers/counter.wasm".to_string(),
        imports: vec!["wasi:keyvalue".to_string()],
        limits: None,
        env: BTreeMap::new(),
    };
    // Two distinct deployments serving the same handler. B adds a (non-matching)
    // redirect so its manifest hashes differently — a real `current` flip.
    let manifest_a = Manifest {
        files: files.clone(),
        config: DeployConfig {
            handlers: vec![handler.clone()],
            ..Default::default()
        },
        ..Default::default()
    };
    let manifest_b = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![handler],
            redirects: vec![Redirect {
                from: "/old".to_string(),
                to: "/new".to_string(),
                status: 301,
                when: None,
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id_a = deploy.put_manifest(&manifest_a).await.unwrap();
    let id_b = deploy.put_manifest(&manifest_b).await.unwrap();
    assert_ne!(id_a, id_b, "deployments must be distinct for a real flip");
    deploy.activate("blog", &id_a).await.unwrap();

    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["wasi:keyvalue".to_string()],
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Generous concurrency cap so responses reflect the dispatch path, not the
    // engine's backpressure (which would 503 rather than drop).
    let engine = HandlerEngine::new(
        Limits {
            max_concurrency: 512,
            ..Limits::default()
        },
        16,
    )
    .unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy.clone(), Auth::disabled(), runtime);

    // Flip the active deployment back and forth while requests are in flight.
    let flipper = {
        let deploy = deploy.clone();
        let (id_a, id_b) = (id_a.clone(), id_b.clone());
        tokio::spawn(async move {
            for i in 0..40 {
                let id = if i % 2 == 0 { &id_b } else { &id_a };
                deploy.activate("blog", id).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
    };

    let mut handles = Vec::new();
    for _ in 0..100 {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let mut req = Request::builder()
                .method("GET")
                .uri("/_sites/blog/count")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            app.oneshot(req).await.unwrap().status()
        }));
    }

    flipper.await.unwrap();
    for handle in handles {
        assert_eq!(
            handle.await.unwrap(),
            StatusCode::OK,
            "a request was dropped during deployment activation"
        );
    }
}

/// A by-id preview reached via the site's own hostname runs its handlers, but
/// with **preview-scoped** bindings: the kv state lands under a preview prefix,
/// never the live site's. The deployment is never activated —
/// previews serve any deployment by id.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn preview_runs_handlers_scoped_off_live_state() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_core::kv::KvStore;
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(KV_COUNTER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "handlers/counter.wasm".to_string(),
        FileEntry {
            hash: hash.clone(),
            size: KV_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/count".to_string(),
                methods: Vec::new(),
                component: "handlers/counter.wasm".to_string(),
                imports: vec!["wasi:keyvalue".to_string()],
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    // Stored but never activated — a preview serves it by id.
    let id = deploy.put_manifest(&manifest).await.unwrap();

    // The site answers on blog.local and grants keyvalue to handlers.
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("blog.local".into()),
                    ..Default::default()
                },
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["wasi:keyvalue".to_string()],
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    // Two preview requests via the site hostname; the counter persists.
    for expected in ["hits=1\n", "hits=2\n"] {
        let mut req = Request::builder()
            .method("GET")
            .uri(format!("/_deploy/{id}/count"))
            .header(header::HOST, "blog.local")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(&body[..], expected.as_bytes());
    }

    // The counter landed under the *preview* prefix, leaving live state untouched.
    assert_eq!(
        kv.get(&format!("hkv/blog/_preview/{id}/hits"))
            .await
            .unwrap(),
        Some(b"2".to_vec())
    );
    assert_eq!(
        kv.get("hkv/blog/hits").await.unwrap(),
        None,
        "preview must not write the live site's kv"
    );
}

/// The activation compile-gate refuses to flip a deployment whose component
/// fails to compile — the broken deploy never goes live.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn activation_refuses_broken_component() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    // A component blob that is not valid wasm.
    let garbage: &[u8] = b"definitely not a wasm component";
    let hash = sha256_hex(garbage);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(garbage)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "handlers/bad.wasm".to_string(),
        FileEntry {
            hash,
            size: garbage.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/x".to_string(),
                methods: Vec::new(),
                component: "handlers/bad.wasm".to_string(),
                imports: Vec::new(),
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: Vec::new(),
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, None);
    let app = router(deploy.clone(), Auth::disabled(), runtime);

    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/sites/blog/deployments/{id}/activate"))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    // Nothing flipped: the site has no current deployment.
    assert_eq!(deploy.current_id("blog").await.unwrap(), None);
}

/// Activation is refused when a handler requests an import the site does not
/// allow (the resolution rule), even though the component itself compiles.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn activation_refuses_disallowed_import() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(KV_COUNTER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "handlers/counter.wasm".to_string(),
        FileEntry {
            hash,
            size: KV_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/count".to_string(),
                methods: Vec::new(),
                component: "handlers/counter.wasm".to_string(),
                imports: vec!["wasi:keyvalue".to_string()],
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    // Handlers enabled, but keyvalue NOT in the allow-list.
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: Vec::new(),
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, None);
    let app = router(deploy.clone(), Auth::disabled(), runtime);

    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/sites/blog/deployments/{id}/activate"))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(deploy.current_id("blog").await.unwrap(), None);
}

/// A component larger than the posture's `max_component_bytes` is
/// refused at activation — checked against the manifest size before any read.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn activation_refuses_oversized_component() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(KV_COUNTER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "handlers/counter.wasm".to_string(),
        FileEntry {
            hash,
            size: KV_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/count".to_string(),
                methods: Vec::new(),
                component: "handlers/counter.wasm".to_string(),
                imports: vec!["wasi:keyvalue".to_string()],
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    // Handlers enabled with the import allowed, so the *size* gate is what fires.
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["wasi:keyvalue".to_string()],
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, None);
    runtime.set_max_component_bytes(16); // KV_COUNTER is far larger than 16 bytes
    let app = router(deploy.clone(), Auth::disabled(), runtime);

    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/sites/blog/deployments/{id}/activate"))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(deploy.current_id("blog").await.unwrap(), None);
}

/// A component serving requests with **sql** end to end through the
/// real `router()` — routing → dispatch → engine → sql binding → per-site libsql
/// database. Each request inserts a row in one transaction (committed by the
/// engine on success), so the running count grows.
#[cfg(feature = "handlers")]
#[tokio::test]
async fn handler_route_with_sql_dispatches_through_engine() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const SQL_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/sql-counter.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(SQL_COUNTER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(SQL_COUNTER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "handlers/sql.wasm".to_string(),
        FileEntry {
            hash,
            size: SQL_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/count".to_string(),
                methods: Vec::new(),
                component: "handlers/sql.wasm".to_string(),
                imports: vec!["sql".to_string()],
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["sql".to_string()],
                    max_memory_mb: None,
                    max_timeout_ms: None,
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Per-site embedded libsql databases under a temp dir (single-node mode).
    let sql_dir = std::env::temp_dir().join(format!("boatramp-conf-sql-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sql_dir);
    let sql: Arc<dyn boatramp_core::sql::SqlBackends> =
        Arc::new(boatramp_storage::LibsqlSqlBackends::local(&sql_dir));

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, Some(sql), None);
    let app = router(deploy.clone(), Auth::disabled(), runtime);

    // Activation pre-check passes (sql allowed + offered + component compiles).
    let mut activate = Request::builder()
        .method("POST")
        .uri(format!("/api/sites/blog/deployments/{id}/activate"))
        .body(Body::empty())
        .unwrap();
    activate
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    assert_eq!(
        app.clone().oneshot(activate).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    for expected in ["rows=1\n", "rows=2\n"] {
        let mut req = Request::builder()
            .method("GET")
            .uri("/_sites/blog/count")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(&body[..], expected.as_bytes());
    }

    let _ = std::fs::remove_dir_all(&sql_dir);
}

/// A site's `maxTimeoutMs` cap is applied per invocation: a looping handler is
/// killed at the site cap, not the engine's (much larger) default — verified by
/// both the 504 and the fast turnaround.
// Multi-thread runtime: the guest busy-loops, so the engine's epoch-ticker task
// must run on another thread to advance the deadline (a current-thread runtime
// would starve the ticker and hang).
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_site_timeout_cap_applies() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    // The http-200 fixture loops forever on `/loop`.
    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    let hash = sha256_hex(HTTP_200);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(HTTP_200)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "h.wasm".to_string(),
        FileEntry {
            hash,
            size: HTTP_200.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/loop".to_string(),
                methods: Vec::new(),
                component: "h.wasm".to_string(),
                imports: Vec::new(),
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: Vec::new(),
                    max_memory_mb: None,
                    max_timeout_ms: Some(50), // far below the engine's 10s default
                    max_concurrency: None,
                    max_fuel: None,
                    secrets: BTreeMap::new(),
                    background_aliases: Vec::new(),
                    max_stream_connections: None,
                    max_log_rate: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    deploy.activate("blog", &id).await.unwrap();

    // Engine default timeout is 10s; the site caps it to 50ms.
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    let mut req = Request::builder()
        .method("GET")
        .uri("/_sites/blog/loop")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let start = std::time::Instant::now();
    let response = app.oneshot(req).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    // The cap (50ms), not the 10s default, fired.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "timed out after {elapsed:?}; the per-site cap did not apply"
    );
}

// ---- SSE topic streams -----------------------------------------------------

/// End-to-end: a deploy declaring an SSE `stream` route is served through the
/// real `router()`. A GET opens a `text/event-stream`; messages published to the
/// (scope-namespaced) topic fan out as SSE events — UTF-8 verbatim, binary as a
/// base64 `.b64` event — each carrying the durable id as the SSE `id:`.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_route_fans_out_text_and_binary_events() {
    use boatramp_core::config::{HandlersSiteConfig, StreamConfig};
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_handlers::{HandlerEngine, Limits};
    use std::time::Duration;

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    // A deployment whose `/events` route is an SSE stream over `orders/created`.
    let manifest = Manifest {
        files: BTreeMap::new(),
        config: DeployConfig {
            streams: vec![StreamConfig {
                route: "/events".to_string(),
                topics: vec!["orders/created".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let log = Arc::new(LogMessaging::new(storage.clone(), kv.clone()));
    let messaging: Arc<dyn Messaging> = log.clone();
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, Some(messaging));
    let app = router(deploy, Auth::disabled(), runtime);

    let mut req = Request::builder()
        .method("GET")
        .uri("/_sites/blog/events")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream")));

    // The subscription is registered by the time the response head is returned,
    // so a publish now reaches this connection.
    let mut body = response.into_body().into_data_stream();

    // UTF-8 payload → verbatim under the topic's event name.
    log.publish("blog/orders/created", b"hello").await.unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("timed out waiting for text event")
        .expect("stream ended")
        .expect("body error");
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("event: orders/created"), "got: {text:?}");
    assert!(text.contains("data: hello"), "got: {text:?}");
    assert!(text.contains("id: "), "event must carry an id: {text:?}");

    // Binary payload → base64 under a `{topic}.b64` event.
    log.publish("blog/orders/created", &[0xff, 0xfe, 0x00])
        .await
        .unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("timed out waiting for binary event")
        .expect("stream ended")
        .expect("body error");
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("event: orders/created.b64"), "got: {text:?}");
    assert!(
        text.contains(&base64_encode_bytes(&[0xff, 0xfe, 0x00])),
        "got: {text:?}"
    );
}

#[cfg(feature = "handlers")]
fn base64_encode_bytes(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The per-site SSE connection cap (`maxStreamConnections`) is enforced: with a
/// cap of 1, a second concurrent connection to the same scope is refused with
/// `503` while the first is still open.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_per_site_connection_cap_returns_503() {
    use boatramp_core::config::{HandlersSiteConfig, StreamConfig};
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_handlers::{HandlerEngine, Limits};

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let manifest = Manifest {
        files: BTreeMap::new(),
        config: DeployConfig {
            streams: vec![StreamConfig {
                route: "/events".to_string(),
                topics: vec!["orders/created".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    max_stream_connections: Some(1),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let messaging: Arc<dyn Messaging> = Arc::new(LogMessaging::new(storage.clone(), kv.clone()));
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, Some(messaging));
    let app = router(deploy, Auth::disabled(), runtime);

    let open = |ip: [u8; 4]| {
        let app = app.clone();
        async move {
            let mut req = Request::builder()
                .method("GET")
                .uri("/_sites/blog/events")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from((ip, 40000))));
            app.oneshot(req).await.unwrap()
        }
    };

    // First connection holds the only permit (kept alive — not dropped).
    let first = open([127, 0, 0, 1]).await;
    assert_eq!(first.status(), StatusCode::OK);

    // Second connection (different IP, so the per-IP cap isn't the limiter) is
    // refused by the per-site cap.
    let second = open([127, 0, 0, 2]).await;
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Dropping the first releases its permit; a new connection then succeeds.
    drop(first);
    let third = open([127, 0, 0, 3]).await;
    assert_eq!(third.status(), StatusCode::OK);
}

/// WebSocket fan-out: a `websocket` stream route bridges both
/// ways — a publish to its topic reaches the client, and a message the client
/// sends is published to the configured `publish_topic`. Served over a real
/// listener (the upgrade needs a live connection, not `oneshot`).
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_stream_fans_out_and_publishes() {
    use boatramp_core::config::{HandlersSiteConfig, StreamConfig};
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_handlers::{HandlerEngine, Limits};
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    // `/ws` is a WebSocket stream: it fans out `events` and publishes client
    // messages to `ingest`.
    let manifest = Manifest {
        files: BTreeMap::new(),
        config: DeployConfig {
            streams: vec![StreamConfig {
                route: "/ws".to_string(),
                topics: vec!["events".to_string()],
                websocket: true,
                publish_topic: Some("ingest".to_string()),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let log = Arc::new(LogMessaging::new(storage.clone(), kv.clone()));
    let messaging: Arc<dyn Messaging> = log.clone();
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, Some(messaging));
    let app = router(deploy, Auth::disabled(), runtime)
        .into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Subscribe to the publish topic up front so the client→server direction is
    // observable (live broadcast only delivers post-subscribe messages).
    let mut ingest = log.subscribe("blog/ingest", None);

    let url = format!("ws://127.0.0.1:{port}/_sites/blog/ws");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("websocket connects");

    // server→client: the subscription is registered in the upgrade task, so give
    // it a beat, then a publish reaches the client.
    tokio::time::sleep(Duration::from_millis(150)).await;
    log.publish("blog/events", b"hello-ws").await.unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("recv within timeout")
        .expect("a frame")
        .expect("ok frame");
    let data = msg.into_data();
    assert_eq!(&data[..], b"hello-ws", "downstream fan-out");

    // client→server: a message the client sends is published to `blog/ingest`.
    ws.send(Message::Text("from-client".into())).await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), ingest.next())
        .await
        .expect("publish within timeout")
        .expect("an event");
    assert_eq!(&event.payload[..], b"from-client", "upstream publish");
}

/// The operator DLQ endpoint (`POST …/_boatramp/dlq`) redrives and purges a
/// consumer topic's dead-letter queue, namespacing the topic to the site.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_dlq_endpoint_redrives_and_purges() {
    use boatramp_core::config::HandlersSiteConfig;
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_handlers::{HandlerEngine, Limits};
    use std::time::Duration;

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let log = Arc::new(LogMessaging::new(storage.clone(), kv.clone()));
    let messaging: Arc<dyn Messaging> = log.clone();
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, Some(messaging));
    let app = router(deploy, Auth::disabled(), runtime);

    // Force a dead letter on the site-namespaced topic `blog/orders` (publish,
    // then claim past max_attempts=1).
    log.publish("blog/orders", b"poison").await.unwrap();
    for _ in 0..2 {
        let _ = log
            .claim("blog/orders", Duration::ZERO, 10, 1)
            .await
            .unwrap();
    }
    assert_eq!(log.dead_letter_count("blog/orders").await.unwrap(), 1);

    // Redrive via the endpoint: the topic is given scope-relative (`orders`).
    let dlq = |action: &str| {
        let body = serde_json::json!({ "topic": "orders", "action": action });
        Request::builder()
            .method("POST")
            .uri("/api/sites/blog/_boatramp/dlq")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };
    let response = app.clone().oneshot(dlq("redrive")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["affected"], 1);
    assert_eq!(log.dead_letter_count("blog/orders").await.unwrap(), 0);
    assert_eq!(
        log.backlog("blog/orders").await.unwrap(),
        1,
        "requeued live"
    );

    // Dead-letter it again, then purge via the endpoint.
    for _ in 0..2 {
        let _ = log
            .claim("blog/orders", Duration::ZERO, 10, 1)
            .await
            .unwrap();
    }
    assert_eq!(log.dead_letter_count("blog/orders").await.unwrap(), 1);
    let response = app.oneshot(dlq("purge")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["affected"], 1);
    assert_eq!(log.dead_letter_count("blog/orders").await.unwrap(), 0);
    assert_eq!(
        log.backlog("blog/orders").await.unwrap(),
        0,
        "purge drops it"
    );
}

// ---- operator / metrics endpoints ------------------------------------------

/// The operator endpoint reports per-handler invocation stats, consumer backlog
/// + dead-letter counts, and the Prometheus exporter renders the same counters.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_endpoint_reports_invocation_and_consumer_stats() {
    use boatramp_core::config::{ConsumerConfig, HandlerConfig, HandlersSiteConfig};
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_handlers::{HandlerEngine, Limits};

    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");
    const EVENT_CONSUMER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/event-consumer.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    // Store both components.
    let counter_hash = sha256_hex(KV_COUNTER);
    let consumer_hash = sha256_hex(EVENT_CONSUMER);
    for bytes in [KV_COUNTER, EVENT_CONSUMER] {
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(bytes)) }).boxed();
        deploy.put_blob(&sha256_hex(bytes), stream).await.unwrap();
    }

    let mut files = BTreeMap::new();
    files.insert(
        "counter.wasm".to_string(),
        FileEntry {
            hash: counter_hash,
            size: KV_COUNTER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    files.insert(
        "consumer.wasm".to_string(),
        FileEntry {
            hash: consumer_hash,
            size: EVENT_CONSUMER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/count".to_string(),
                methods: Vec::new(),
                component: "counter.wasm".to_string(),
                imports: vec!["wasi:keyvalue".to_string()],
                limits: None,
                env: BTreeMap::new(),
            }],
            consumers: vec![ConsumerConfig {
                topic: "orders/created".to_string(),
                component: "consumer.wasm".to_string(),
                imports: vec!["wasi:keyvalue".to_string()],
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["wasi:keyvalue".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let log = Arc::new(LogMessaging::new(storage.clone(), kv.clone()));
    let messaging: Arc<dyn Messaging> = log.clone();
    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, Some(messaging));
    let app = router(deploy, Auth::disabled(), runtime);

    // Drive one handler invocation (records an http metric).
    let mut req = Request::builder()
        .method("GET")
        .uri("/_sites/blog/count")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // Two queued messages on the consumer topic → backlog 2 (router() runs no
    // background scheduler, so nothing drains them).
    log.publish("blog/orders/created", b"a").await.unwrap();
    log.publish("blog/orders/created", b"b").await.unwrap();

    // Operator stats endpoint.
    let req = Request::builder()
        .method("GET")
        .uri("/api/sites/blog/_boatramp/handlers")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let stats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let handlers = stats["handlers"].as_array().unwrap();
    let count_handler = handlers
        .iter()
        .find(|h| h["trigger"] == "http" && h["route"] == "/count")
        .expect("a /count http handler stat");
    assert_eq!(count_handler["invocations"], 1);
    assert_eq!(count_handler["ok"], 1);
    let consumers = stats["consumers"].as_array().unwrap();
    let consumer = consumers
        .iter()
        .find(|c| c["topic"] == "orders/created")
        .expect("a consumer stat");
    assert_eq!(consumer["backlog"], 2);
    assert_eq!(consumer["dead_letters"], 0);

    // Prometheus exporter renders the same counter.
    let req = Request::builder()
        .method("GET")
        .uri("/api/metrics")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("boatramp_handler_invocations_total"),
        "got: {text}"
    );
    assert!(text.contains("route=\"/count\""), "got: {text}");
}

/// End-to-end guest log capture: a handler that prints
/// to stdout/stderr has that output captured by the host and served back via
/// the per-site logs endpoint, with stream filtering.
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_logs_captured_and_served() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    let hash = sha256_hex(HTTP_200);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(HTTP_200)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "h.wasm".to_string(),
        FileEntry {
            hash,
            size: HTTP_200.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/log".to_string(),
                methods: Vec::new(),
                component: "h.wasm".to_string(),
                imports: Vec::new(),
                limits: None,
                env: BTreeMap::new(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    // Invoke the handler; it prints to stdout + stderr before responding.
    let mut req = Request::builder()
        .method("GET")
        .uri("/_sites/blog/log")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Drain the body so the guest task is guaranteed complete (and its stdio
    // stream dropped/flushed) before we read the captured logs.
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"logged\n");

    // All captured lines.
    let req = Request::builder()
        .method("GET")
        .uri("/api/sites/blog/_boatramp/logs")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let logs: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = logs["entries"].as_array().unwrap();
    let lines: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| (e["stream"].as_str().unwrap(), e["line"].as_str().unwrap()))
        .collect();
    assert!(
        lines.contains(&("stdout", "hello to stdout")),
        "captured: {lines:?}"
    );
    assert!(
        lines.contains(&("stderr", "hello to stderr")),
        "captured: {lines:?}"
    );

    // Stream filter: only stderr.
    let req = Request::builder()
        .method("GET")
        .uri("/api/sites/blog/_boatramp/logs?stream=stderr")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let logs: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = logs["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|e| e["stream"] == "stderr"));
}

// ---- wildcard preview host form --------------------------------------------

/// The wildcard preview host form `<id>.deploy.<site-host>` serves a specific
/// (non-current) deployment by id-prefix, resolving the site from the remaining
/// host — distinct from the live site served at the bare host.
#[tokio::test]
async fn preview_host_form_serves_deployment_by_id() {
    let deploy = DeployStore::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));

    // Two deployments with distinct index content.
    let put = |bytes: &'static [u8]| {
        let deploy = deploy.clone();
        async move {
            let hash = sha256_hex(bytes);
            let stream: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            deploy.put_blob(&hash, stream).await.unwrap();
            hash
        }
    };
    let mk = |hash: String, bytes: &[u8]| {
        let mut files = BTreeMap::new();
        files.insert(
            "index.html".to_string(),
            FileEntry {
                hash,
                size: bytes.len() as u64,
                content_type: Some("text/html".into()),
                variants: BTreeMap::new(),
            },
        );
        Manifest {
            files,
            config: DeployConfig::default(),
            ..Default::default()
        }
    };
    let h1 = put(b"v1").await;
    let h2 = put(b"v2").await;
    let id1 = deploy.put_manifest(&mk(h1, b"v1")).await.unwrap();
    let id2 = deploy.put_manifest(&mk(h2, b"v2")).await.unwrap();

    // Site `blog` answers to example.com; current deployment is v2.
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("example.com".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    deploy.activate("blog", &id2).await.unwrap();

    let app = router(deploy, Auth::disabled(), HandlerRuntime::disabled());
    let get_host = |app: axum::Router, host: &str| {
        let host = host.to_string();
        async move {
            let mut req = Request::builder()
                .method("GET")
                .uri("/")
                .header(header::HOST, host)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            let response = app.oneshot(req).await.unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, body.to_vec())
        }
    };

    // Bare host → current (v2).
    let (status, body) = get_host(app.clone(), "example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"v2");

    // Preview host form with an id prefix → the older deployment (v1).
    let prefix = &id1[..16];
    let (status, body) = get_host(app.clone(), &format!("{prefix}.deploy.example.com")).await;
    assert_eq!(status, StatusCode::OK, "preview host should serve by id");
    assert_eq!(body, b"v1");

    // A bogus id prefix under the preview host → 404.
    let (status, _) = get_host(app, "deadbeef.deploy.example.com").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Sandbox + env injection: a handler sees its
/// declared `env` but NOT the host's environment (no passthrough).
#[cfg(feature = "handlers")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_env_injected_host_env_not_inherited() {
    use boatramp_core::config::{HandlerConfig, HandlersSiteConfig};
    use boatramp_handlers::{HandlerEngine, Limits};

    const HTTP_200: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

    let storage = Arc::new(MemStorage::default());
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(storage.clone(), kv.clone());
    let hash = sha256_hex(HTTP_200);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(HTTP_200)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "h.wasm".to_string(),
        FileEntry {
            hash,
            size: HTTP_200.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/env".to_string(),
                methods: Vec::new(),
                component: "h.wasm".to_string(),
                imports: Vec::new(),
                limits: None,
                env: BTreeMap::from([("GREETING".to_string(), "hello".to_string())]),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate("blog", &id).await.unwrap();
    deploy
        .set_site_config(
            "blog",
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv, storage, None, None);
    let app = router(deploy, Auth::disabled(), runtime);

    let mut req = Request::builder()
        .method("GET")
        .uri("/_sites/blog/env")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    // Declared env is visible; the host's PATH (always set in the test process)
    // is not — the guest gets only what the deploy/site granted.
    assert_eq!(text, "greeting=hello path_leaked=false", "got: {text}");
}

// ---- domain ownership verification -----------------------------------------

/// A scripted ownership probe: returns canned TXT/HTTP results so the
/// verification *endpoints* can be driven without live DNS/HTTP. The inner
/// state is shared across router clones (it rides as an `Arc`).
#[derive(Clone, Default)]
struct ScriptedProbe {
    http_body: Arc<Mutex<String>>,
    txt: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl DomainProbe for ScriptedProbe {
    async fn lookup_txt(&self, _name: &str) -> Result<Vec<String>, VerifyError> {
        Ok(self.txt.lock().unwrap().clone())
    }
    async fn fetch_http(&self, _url: &str) -> Result<String, VerifyError> {
        Ok(self.http_body.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn domain_verification_flow_gates_attachment() {
    let deploy = seed().await;
    let probe = ScriptedProbe::default();
    let app = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            probe: Some(Arc::new(probe.clone())),
            ..Default::default()
        },
    );

    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let mut req = req;
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
    };

    // 1. Start an HTTP-token challenge — the host is NOT attached yet.
    let (status, body) = send(post(
        "/api/sites/test/domains/app.example.com/verification?method=http",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge: DomainVerification = serde_json::from_slice(&body).unwrap();
    assert!(!challenge.verified);
    assert_eq!(challenge.host, "app.example.com");
    let cfg = deploy.get_site_config("test").await.unwrap();
    assert!(
        cfg.is_none_or(|c| c.domains.primary.is_none()),
        "unverified host must not be attached"
    );

    // 2. Check while the token is absent → fails, still not attached.
    let (status, body) = send(post(
        "/api/sites/test/domains/app.example.com/verification/check",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["passed"], serde_json::json!(false));
    assert_eq!(result["attached"], serde_json::json!(false));

    // 3. Publish the token, re-check → passes and attaches as the primary.
    *probe.http_body.lock().unwrap() = challenge.token.clone();
    let (status, body) = send(post(
        "/api/sites/test/domains/app.example.com/verification/check",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["passed"], serde_json::json!(true));
    assert_eq!(result["attached"], serde_json::json!(true));

    // The host now routes and is in the site config.
    assert_eq!(
        deploy
            .resolve_site_by_host("app.example.com")
            .await
            .unwrap()
            .as_deref(),
        Some("test")
    );
    let cfg = deploy.get_site_config("test").await.unwrap().unwrap();
    assert_eq!(cfg.domains.primary.as_deref(), Some("app.example.com"));

    // 4. The challenge is listed (verified); deleting it drops the record.
    let (status, body) = send(get("/api/sites/test/domain-verifications")).await;
    assert_eq!(status, StatusCode::OK);
    let list: Vec<DomainVerification> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].verified);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/sites/test/domains/app.example.com/verification")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = send(get("/api/sites/test/domain-verifications")).await;
    let list: Vec<DomainVerification> = serde_json::from_slice(&body).unwrap();
    assert!(list.is_empty());
}

// ---- operational request limits --------------------------------------------

#[tokio::test]
async fn upload_size_limit_rejects_oversize_blob() {
    let deploy = seed().await;
    let app = router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            limits: ServerLimits {
                max_upload_bytes: Some(8),
                ..Default::default()
            },
            ..Default::default()
        },
    );

    let put = |bytes: &'static [u8]| {
        let app = app.clone();
        async move {
            let hash = sha256_hex(bytes);
            // Real HTTP clients send Content-Length for a sized body; the
            // in-process `oneshot` path doesn't add it, so set it explicitly to
            // exercise the up-front size check (the path production hits).
            let mut req = Request::builder()
                .method("PUT")
                .uri(format!("/api/blobs/{hash}"))
                .header(header::CONTENT_LENGTH, bytes.len())
                .body(Body::from(bytes))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            app.oneshot(req).await.unwrap().status()
        }
    };

    // A 12-byte body exceeds the 8-byte cap → rejected up front (Content-Length).
    assert_eq!(put(b"hello world!").await, StatusCode::PAYLOAD_TOO_LARGE);
    // A 5-byte body is under the cap and stores (hash matches its own bytes).
    assert_eq!(put(b"hello").await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn cache_control_smart_defaults_for_assets_and_html() {
    let deploy = DeployStore::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));
    let js: &'static [u8] = b"console.log(1)";
    let html: &'static [u8] = b"<h1>hi</h1>";
    for bytes in [js, html] {
        let hash = sha256_hex(bytes);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
    }
    let mut files = BTreeMap::new();
    files.insert(
        "assets/app.a1b2c3d4.js".to_string(),
        file(js, Some("text/javascript")).1,
    );
    files.insert("index.html".to_string(), file(html, Some("text/html")).1);
    let id = deploy
        .put_manifest(&Manifest {
            files,
            ..Default::default()
        })
        .await
        .unwrap();
    deploy.activate("fp", &id).await.unwrap();

    // Fingerprinted asset → immutable, no config or header rule needed.
    let (status, headers, _) = send(&deploy, get("/_sites/fp/assets/app.a1b2c3d4.js")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );

    // HTML entry → must-revalidate so a new deploy is picked up.
    let (status, headers, _) = send(&deploy, get("/_sites/fp/index.html")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "public, max-age=0, must-revalidate"
    );
}

// ---- blob integrity scrub + activate cache coherence -----------------------

#[tokio::test]
async fn scrub_detects_corrupted_blob() {
    let storage = Arc::new(MemStorage::default());
    let deploy = DeployStore::new(storage.clone(), Arc::new(MemoryKv::new()));
    let bytes: &'static [u8] = b"genuine content";
    let hash = sha256_hex(bytes);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    // A healthy store scrubs clean.
    let report = deploy.scrub_blobs().await.unwrap();
    assert_eq!(report.checked, 1);
    assert!(report.is_clean());

    // Corrupt the stored bytes under the same key (bit-rot / tampering).
    let key = storage
        .objects
        .lock()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    storage
        .objects
        .lock()
        .unwrap()
        .insert(key, b"tampered!".to_vec());

    let report = deploy.scrub_blobs().await.unwrap();
    assert_eq!(report.checked, 1);
    assert!(!report.is_clean());
    assert_eq!(report.mismatched.len(), 1);
    assert_eq!(report.mismatched[0].expected, hash);
    assert_ne!(report.mismatched[0].actual, hash);
}

#[tokio::test]
async fn activate_is_visible_immediately_through_cache() {
    use boatramp_core::kv::CachedKv;

    let storage = Arc::new(MemStorage::default());
    // Wrap KV in the same write-through LRU `serve` uses, to prove activate is
    // coherent (no stale current-pointer after a re-deploy).
    let kv = Arc::new(CachedKv::new(Arc::new(MemoryKv::new()), 256));
    let deploy = DeployStore::new(storage.clone(), kv);

    let publish = |body: &'static [u8]| {
        let deploy = deploy.clone();
        async move {
            let hash = sha256_hex(body);
            let stream: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(body)) }).boxed();
            deploy.put_blob(&hash, stream).await.unwrap();
            let mut files = BTreeMap::new();
            files.insert("index.html".to_string(), file(body, Some("text/html")).1);
            deploy
                .put_manifest(&Manifest {
                    files,
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    let a = publish(b"<h1>A</h1>").await;
    let b = publish(b"<h1>B</h1>").await;

    deploy.activate("s", &a).await.unwrap();
    // First read caches `current/s`.
    let m = deploy.current_manifest("s").await.unwrap().unwrap();
    assert_eq!(m.id().unwrap(), a);

    // Re-activate: the write-through cache must now reflect B, not stale A.
    deploy.activate("s", &b).await.unwrap();
    let m = deploy.current_manifest("s").await.unwrap().unwrap();
    assert_eq!(m.id().unwrap(), b);
}

#[tokio::test]
async fn http_redirect_router_upgrades_to_https() {
    use boatramp_core::domain_verify::VerificationMethod;
    use boatramp_core::security::SecurityPosture;
    use boatramp_server::http_redirect_router;

    // A pending HTTP challenge on a host attached to no site (created near "now"
    // so it is within the challenge TTL when the handler checks it).
    let deploy = seed().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let v = deploy
        .start_domain_verification("docs", "docs.example", VerificationMethod::Http, now)
        .await
        .unwrap();

    let app = http_redirect_router(deploy, SecurityPosture::default());

    // A normal request is 308-upgraded to HTTPS (port stripped, path+query kept).
    let mut req = Request::builder()
        .uri("/path?q=1")
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, "example.com:8080".parse().unwrap());
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        resp.headers()[header::LOCATION],
        "https://example.com/path?q=1"
    );

    // …but the domain-ownership challenge is served directly on :80 (never
    // redirected), so an unattached host can verify before it has a cert.
    let mut req = Request::builder()
        .uri(format!(
            "/.well-known/boatramp-domain-verification/{}",
            v.token
        ))
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, "docs.example".parse().unwrap());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.as_ref(), v.token.as_bytes());
}

/// The self-serve edge route on the **main** router: a pending HTTP challenge is
/// served before host routing, so a host that isn't attached to any site (and
/// would otherwise fall through to the default site and 404 its own challenge)
/// verifies itself. Wrong tokens and DNS-method challenges are never served.
#[tokio::test]
async fn self_serve_domain_challenge_before_host_routing() {
    use boatramp_core::domain_verify::VerificationMethod;

    let deploy = seed().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let v = deploy
        .start_domain_verification("docs", "docs.example", VerificationMethod::Http, now)
        .await
        .unwrap();

    // Matching (Host, token) → 200 + the token, ahead of the `serve_by_host`
    // fallback (which would have served the default site / 404).
    let mut req = Request::builder()
        .uri(format!(
            "/.well-known/boatramp-domain-verification/{}",
            v.token
        ))
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, "docs.example".parse().unwrap());
    let (status, _, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, v.token.as_bytes());

    // A wrong token for the same host → 404 (never leaks the real token).
    let mut req = Request::builder()
        .uri("/.well-known/boatramp-domain-verification/deadbeefdeadbeefdeadbeefdeadbeef")
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, "docs.example".parse().unwrap());
    let (status, _, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A DNS-method challenge is never served over the HTTP edge route.
    let dv = deploy
        .start_domain_verification("d2", "dns.example", VerificationMethod::Dns, now)
        .await
        .unwrap();
    let mut req = Request::builder()
        .uri(format!(
            "/.well-known/boatramp-domain-verification/{}",
            dv.token
        ))
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, "dns.example".parse().unwrap());
    let (status, _, _) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A raw `PUT /config` that introduces a **new** domain is refused until that
/// domain's ownership is verified — so a site-writer can't squat an unowned
/// host by listing it directly (the verify→attach flow stays the only way in).
#[tokio::test]
async fn put_config_gate_requires_verified_new_domain() {
    use boatramp_core::domain_verify::VerificationMethod;

    let deploy = seed().await;
    let (auth, token) = token_auth(&[GrantedRole::scoped("publisher", "docs")]).await;

    let put_config = |token: &str| {
        let body = serde_json::json!({ "domains": { "primary": "unowned.example" } });
        let req = Request::builder()
            .method("PUT")
            .uri("/api/sites/docs/config")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        with_bearer(req, token)
    };

    // Unverified → 403.
    let (status, _, _) = send_as(&deploy, auth.clone(), put_config(&token), [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Prove ownership, then the same PUT is accepted.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    deploy
        .start_domain_verification("docs", "unowned.example", VerificationMethod::Http, now)
        .await
        .unwrap();
    deploy
        .mark_domain_verified("docs", "unowned.example")
        .await
        .unwrap();
    let (status, _, _) = send_as(&deploy, auth, put_config(&token), [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// The bootstrap-TLS identity endpoint serves the root-key attestation verbatim
/// and unauthenticated when set, and `404`s when not (`--tls rpk` off / no issuer).
#[tokio::test]
async fn bootstrap_identity_endpoint_serves_the_attestation() {
    let deploy = seed().await;
    let get_att = |opts: ServerOptions| {
        let deploy = deploy.clone();
        async move {
            let mut req = Request::builder()
                .uri("/.well-known/boatramp-bootstrap-identity")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            let resp = router_with(deploy, Auth::disabled(), HandlerRuntime::disabled(), opts)
                .oneshot(req)
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
    };

    // With an attestation set → 200 + the blob verbatim.
    let (status, body) = get_att(ServerOptions {
        bootstrap_attestation: Some("attestation-blob-abc".into()),
        ..Default::default()
    })
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"attestation-blob-abc");

    // Without one → 404.
    let (status, _) = get_att(ServerOptions::default()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- OIDC → token exchange -------------------------------------------------

#[cfg(feature = "oidc")]
#[tokio::test]
async fn oidc_exchange_mints_a_token() {
    use boatramp_server::OidcVerifier;
    use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use std::collections::HashMap;

    // An HS256 verifier exercises the same validate→claim path RS256 uses.
    let secret = b"conformance-oidc-secret-0123456789";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["https://issuer.test"]);
    validation.validate_aud = false;
    let mut keys = HashMap::new();
    keys.insert("k1".to_string(), DecodingKey::from_secret(secret));
    let verifier = Arc::new(OidcVerifier::new(keys, validation, "scope"));

    let deploy = seed().await;
    let signer = LocalSigner::generate(TokenAlg::Es256);
    let public = signer.public_key();
    let app = router_with(
        deploy,
        Auth::with_key(public, Arc::new(MemoryKv::new())),
        HandlerRuntime::disabled(),
        ServerOptions {
            issuer: Some(Arc::new(signer) as Arc<dyn boatramp_core::cose::Signer>),
            oidc_verifier: Some(verifier),
            ..Default::default()
        },
    );

    // An IdP JWT whose `scope` claim names the `admin` role.
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("k1".to_string());
    let claims = serde_json::json!({
        "iss": "https://issuer.test",
        "exp": 4_102_444_800i64,
        "scope": "admin"
    });
    let jwt = encode(&jwt_header, &claims, &EncodingKey::from_secret(secret)).unwrap();

    // Exchange the JWT for a short-TTL token.
    let exchange = with_conn(
        Request::builder()
            .method("POST")
            .uri("/api/auth/exchange")
            .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
            .body(Body::empty())
            .unwrap(),
    );
    let resp = app.clone().oneshot(exchange).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = parsed["token"].as_str().expect("exchange returns a token");

    // The minted (admin) token authorizes the control plane.
    let req = with_conn(with_bearer(get("/api/sites/test/current"), token));
    let status = app.clone().oneshot(req).await.unwrap().status();
    assert_eq!(status, StatusCode::OK);

    // A bogus JWT is rejected by the exchange.
    let bad = with_conn(
        Request::builder()
            .method("POST")
            .uri("/api/auth/exchange")
            .header(header::AUTHORIZATION, "Bearer not.a.jwt")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(
        app.oneshot(bad).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn unmatched_host_serves_default_site() {
    let deploy = seed().await; // site "test" with an index
    let app = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            default_site: Some("test".to_string()),
            ..Default::default()
        },
    );
    let send = |host: &'static str| {
        let app = app.clone();
        async move {
            let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
            req.headers_mut()
                .insert(header::HOST, host.parse().unwrap());
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
    };

    // A host that matches no domain falls back to the default site, not 404.
    let (status, body) = send("nope.example.org").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");
}

#[tokio::test]
async fn unmatched_host_without_default_is_404() {
    let deploy = seed().await;
    let app = router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions::default(),
    );
    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    req.headers_mut()
        .insert(header::HOST, "nope.example.org".parse().unwrap());
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---- implicit host routing (first-label / sole-site) -----------------------

/// Publish and activate a one-file site named `site` whose `/` serves `body`.
async fn publish_site(deploy: &DeployStore, site: &str, body: &'static [u8]) {
    let hash = sha256_hex(body);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(body)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();
    let (_h, entry) = file(body, Some("text/html"));
    let mut files = BTreeMap::new();
    files.insert("index.html".to_string(), entry);
    let manifest = Manifest {
        files,
        config: DeployConfig::default(),
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy.activate(site, &id).await.unwrap();
}

/// A `GET /` against `app` with the given `Host`, returning `(status, body)`.
async fn get_host(app: axum::Router, host: &'static str) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    req.headers_mut()
        .insert(header::HOST, host.parse().unwrap());
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn implicit_first_label_routes_to_named_site() {
    // Two sites, implicit routing on: the first host label names a served site,
    // resolved at root with no domain registered (`blog.localhost` → site `blog`).
    let deploy = seed().await; // site "test" (home)
    publish_site(&deploy, "blog", b"<h1>blog</h1>").await;
    let app = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            implicit_routing: true,
            ..Default::default()
        },
    );

    let (status, body) = get_host(app.clone(), "blog.localhost").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>blog</h1>");

    let (status, body) = get_host(app.clone(), "test.localhost").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");

    // A label that names no site 404s — implicit routing is not a wildcard.
    let (status, _) = get_host(app, "ghost.localhost").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn implicit_sole_site_served_at_root() {
    // One site, implicit on, no default_site: an unmatched host (whose label names
    // no site) still serves the sole site — the zero-config single-site case.
    let deploy = seed().await; // only "test"
    let app = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            implicit_routing: true,
            ..Default::default()
        },
    );
    let (status, body) = get_host(app, "random.example").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");

    // Publishing a second site turns the sole-site default off (ambiguous): an
    // unmatched, non-site-label host now 404s.
    publish_site(&deploy, "blog", b"<h1>blog</h1>").await;
    let app = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            implicit_routing: true,
            ..Default::default()
        },
    );
    let (status, _) = get_host(app, "random.example").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn implicit_routing_off_is_strict() {
    // The strict (multi-tenant) default ⇒ implicit_routing false: a site's name as
    // a host label does not resolve; only an explicit domain / default_site do.
    let deploy = seed().await; // site "test"
    let app = router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions::default(),
    );
    let (status, _) = get_host(app, "test.localhost").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn explicit_domain_beats_implicit_first_label() {
    // Precedence: a registered domain wins over first-label routing, even when the
    // label names a different site. `blog.example.com` is registered to "test", so
    // it serves "test" — not the site literally named "blog".
    let deploy = seed().await; // "test" (home)
    publish_site(&deploy, "blog", b"<h1>blog</h1>").await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("blog.example.com".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let app = router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions {
            implicit_routing: true,
            ..Default::default()
        },
    );
    let (status, body) = get_host(app, "blog.example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, b"<h1>home</h1>",
        "explicit domain wins over the label"
    );
}

// ---- dynamic daemon config -------------------------------------------------

#[tokio::test]
async fn daemon_config_default_site_hot_swaps() {
    let deploy = seed().await; // site "test" serves <h1>home</h1>
    let app = router_with(
        deploy.clone(),
        Auth::disabled(),
        HandlerRuntime::disabled(),
        ServerOptions::default(),
    );
    // Baseline: an unmatched host 404s (no default_site configured).
    assert_eq!(
        get_host(app.clone(), "nope.example").await.0,
        StatusCode::NOT_FOUND
    );

    // PUT a dynamic default_site → 200 with a generation.
    let body = serde_json::json!({ "version": 1, "default_site": "test" }).to_string();
    let mut put = Request::builder()
        .method("PUT")
        .uri("/api/daemon/config")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    put.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Hot-swapped: the same running server now serves the default site — no restart.
    let (status, body) = get_host(app.clone(), "nope.example").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"<h1>home</h1>");

    // /healthz reports the config generation hash (convergence signal).
    let mut hz = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    hz.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let hzresp = app.oneshot(hz).await.unwrap();
    let hzbody = to_bytes(hzresp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert!(
        hzbody.starts_with(b"ok gen="),
        "healthz reports the generation, got {:?}",
        String::from_utf8_lossy(&hzbody)
    );
}

#[tokio::test]
async fn daemon_config_rejects_ceiling_violation() {
    // A dynamic upload cap above the posture ceiling is rejected (validate-before-
    // commit), leaving the stored config unchanged.
    let deploy = seed().await;
    let options = ServerOptions {
        // multi-tenant posture ⇒ a finite max_upload_bytes ceiling.
        posture: boatramp_core::security::SecurityProfile::MultiTenant.preset(),
        ..Default::default()
    };
    let app = router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        options,
    );
    let body = serde_json::json!({ "version": 1, "max_upload_bytes": 0 }).to_string(); // 0 = unlimited > ceiling
    let mut put = Request::builder()
        .method("PUT")
        .uri("/api/daemon/config")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    put.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---- configurable WAF ------------------------------------------------------

#[tokio::test]
async fn waf_blocks_by_user_agent_and_anomaly() {
    use boatramp_core::waf::{AnomalyRules, UserAgentRules, WafConfig};

    let deploy = seed().await;
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                // Attach a domain so the host fallback resolves to this site and
                // its access policy (incl. WAF) runs.
                domains: DomainConfig {
                    primary: Some("test.local".into()),
                    ..Default::default()
                },
                access: AccessConfig {
                    waf: WafConfig {
                        user_agent: UserAgentRules {
                            enabled: true,
                            deny: vec!["(?i)evilbot".into()],
                            allow: Vec::new(),
                        },
                        anomaly: AnomalyRules {
                            enabled: true,
                            threshold: 1,
                            suspicious_paths: vec!["/.env".into()],
                            suspicious_path_score: 1,
                            ..Default::default()
                        },
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let send = |path: &'static str, ua: Option<&'static str>| {
        let deploy = deploy.clone();
        async move {
            let mut req = Request::builder().uri(path).body(Body::empty()).unwrap();
            req.headers_mut()
                .insert(header::HOST, "test.local".parse().unwrap());
            if let Some(ua) = ua {
                req.headers_mut()
                    .insert(header::USER_AGENT, ua.parse().unwrap());
            }
            send(&deploy, req).await.0
        }
    };

    // A denied UA is blocked.
    assert_eq!(
        send("/", Some("Mozilla EvilBot/9")).await,
        StatusCode::FORBIDDEN
    );
    // A suspicious path trips the anomaly score (threshold 1).
    assert_eq!(
        send("/.env", Some("Mozilla/5.0")).await,
        StatusCode::FORBIDDEN
    );
    // A normal request is served (WAF allows it).
    assert_eq!(send("/", Some("Mozilla/5.0")).await, StatusCode::OK);
}

#[tokio::test]
async fn oversized_variant_is_not_served() {
    // A "br" variant that isn't smaller than identity is a decompression-bomb
    // smell; the server must fall back to identity.
    let deploy = DeployStore::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));
    let identity: &'static [u8] = b"hello world";
    // A real but *oversized* "br" variant blob (bigger than identity).
    let variant_bytes: &'static [u8] = b"this is a bogus, oversized br variant payload";
    for bytes in [identity, variant_bytes] {
        let hash = sha256_hex(bytes);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
    }
    let hash = sha256_hex(identity);

    let mut entry = FileEntry {
        hash: hash.clone(),
        size: identity.len() as u64,
        content_type: Some("application/javascript".into()),
        variants: BTreeMap::new(),
    };
    // The "br" variant is larger than identity (≥ identity → rejected).
    entry.variants.insert(
        "br".to_string(),
        Variant {
            hash: sha256_hex(variant_bytes),
            size: variant_bytes.len() as u64,
        },
    );
    let mut files = BTreeMap::new();
    files.insert("a.js".to_string(), entry);
    let id = deploy
        .put_manifest(&Manifest {
            files,
            ..Default::default()
        })
        .await
        .unwrap();
    deploy.activate("v", &id).await.unwrap();

    let mut req = get("/_sites/v/a.js");
    req.headers_mut()
        .insert(header::ACCEPT_ENCODING, "br".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !headers.contains_key(header::CONTENT_ENCODING),
        "identity served, not the oversized variant"
    );
    assert_eq!(body, identity);
}

#[tokio::test]
async fn protected_previews_require_a_token() {
    let deploy = seed().await;
    let id = deploy
        .current_manifest("test")
        .await
        .unwrap()
        .unwrap()
        .id()
        .unwrap();
    let (auth, token) = token_auth(&[GrantedRole::global("admin")]).await;
    let app = router_with(
        deploy,
        auth,
        HandlerRuntime::disabled(),
        ServerOptions {
            protect_previews: true,
            ..Default::default()
        },
    );
    let send = |bearer: Option<String>| {
        let app = app.clone();
        let uri = format!("/_deploy/{id}/");
        async move {
            let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            if let Some(b) = bearer {
                req.headers_mut().insert(
                    header::AUTHORIZATION,
                    format!("Bearer {b}").parse().unwrap(),
                );
            }
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
            app.oneshot(req).await.unwrap().status()
        }
    };
    // No token → 401; a bogus token → 401; a valid token → served.
    assert_eq!(send(None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(Some("nope".to_string())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(send(Some(token)).await, StatusCode::OK);
}

// ---- on-the-fly compression ------------------------------------------------

#[cfg(feature = "compression")]
#[tokio::test]
async fn on_the_fly_compression_for_variantless_responses() {
    use boatramp_core::config::CompressionConfig;

    let deploy = seed().await; // index.html (text/html) has no precompressed variant
    deploy
        .set_site_config(
            "test",
            &SiteConfig {
                domains: DomainConfig {
                    primary: Some("test.local".into()),
                    ..Default::default()
                },
                compression: CompressionConfig {
                    enabled: true,
                    min_size: 1, // compress even the tiny seed index
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    req.headers_mut()
        .insert(header::HOST, "test.local".parse().unwrap());
    req.headers_mut()
        .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
    assert!(headers[header::VARY]
        .to_str()
        .unwrap()
        .to_ascii_lowercase()
        .contains("accept-encoding"));
    // The body is gzip-framed (magic bytes) and differs from the identity bytes.
    assert_ne!(body, b"<h1>home</h1>");
    assert_eq!(&body[..2], &[0x1f, 0x8b], "gzip magic");

    // Without Accept-Encoding, the identity body is served unchanged.
    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    req.headers_mut()
        .insert(header::HOST, "test.local".parse().unwrap());
    let (status, headers, body) = send(&deploy, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::CONTENT_ENCODING));
    assert_eq!(body, b"<h1>home</h1>");
}

// ---- push cache invalidation -----------------------------------------------

#[tokio::test]
async fn cache_invalidate_endpoint_pops_keys() {
    use boatramp_core::kv::{CachedKv, KvStore, MemoryKv};

    // A cache over a shared backend; the endpoint must pop a key so the next
    // read sees a value a "peer" wrote directly to the backing store.
    let backing = Arc::new(MemoryKv::new());
    backing
        .put("current/site", b"dep-1".to_vec())
        .await
        .unwrap();
    let cache: Arc<dyn KvStore> = Arc::new(CachedKv::new(backing.clone(), 64));
    let deploy = DeployStore::new(Arc::new(MemStorage::default()), cache.clone());

    // Warm the cache, then a peer changes the backing store under it.
    assert_eq!(
        cache.get("current/site").await.unwrap(),
        Some(b"dep-1".to_vec())
    );
    backing
        .put("current/site", b"dep-2".to_vec())
        .await
        .unwrap();
    assert_eq!(
        cache.get("current/site").await.unwrap(),
        Some(b"dep-1".to_vec())
    ); // still cached

    // Push invalidation for that key, through the real router over this deploy.
    let req = Request::builder()
        .method("POST")
        .uri("/api/cache/invalidate")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"keys":["current/site"]}"#))
        .unwrap();
    let (status, _, _) = send_as(&deploy, Auth::disabled(), req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The next read now sees the peer's value (the key was popped).
    assert_eq!(
        cache.get("current/site").await.unwrap(),
        Some(b"dep-2".to_vec())
    );
}

#[tokio::test]
async fn list_sites_endpoint() {
    let deploy = seed().await; // site "test" has a current deployment
    deploy
        .set_site_config(
            "configured",
            &SiteConfig::default(), // a site with config but no deployment
        )
        .await
        .unwrap();

    let (status, _, body) = send(&deploy, get("/api/sites")).await;
    assert_eq!(status, StatusCode::OK);
    let mut sites: Vec<String> = serde_json::from_slice(&body).unwrap();
    sites.sort();
    assert_eq!(sites, vec!["configured".to_string(), "test".to_string()]);

    // RBAC: listing all sites needs system·read — an admin token may, a
    // site-scoped viewer may not.
    let (admin_auth, admin_token) = token_auth(&[GrantedRole::global("admin")]).await;
    let req = with_bearer(get("/api/sites"), &admin_token);
    let (status, _, _) = send_as(&deploy, admin_auth, req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::OK);

    let (viewer_auth, viewer_token) = token_auth(&[GrantedRole::scoped("viewer", "test")]).await;
    let req = with_bearer(get("/api/sites"), &viewer_token);
    let (status, _, _) = send_as(&deploy, viewer_auth, req, [127, 0, 0, 1]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---- CORS for the control-plane API (ServerOptions::cors_allowed_origins) ---
//
// The dogfood console is same-origin (no CORS); these cover the
// separately-hosted-console case where the operator sets an allowlist.

const ALLOWED_ORIGIN: &str = "https://console.example.com";

/// Build the app with a CORS `allowlist`; with an empty list CORS stays off.
fn cors_app(deploy: &DeployStore, auth: Auth, allowlist: &[&str]) -> axum::Router {
    router_with(
        deploy.clone(),
        auth,
        HandlerRuntime::disabled(),
        ServerOptions {
            cors_allowed_origins: allowlist.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
    )
}

/// Drive one request through `app`, attaching the `ConnectInfo` the middleware
/// expects, and return the status + response headers.
async fn cors_send(
    app: axum::Router,
    mut req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap) {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.oneshot(req).await.unwrap();
    (resp.status(), resp.headers().clone())
}

/// A preflight `OPTIONS` is answered with `204` + the allow-headers **above the
/// auth layer** — it carries no `Authorization`, so it must not 401/405.
#[tokio::test]
async fn cors_preflight_is_answered_before_auth() {
    let deploy = seed().await;
    let (auth, _) = token_auth(&[GrantedRole::global("admin")]).await;
    let app = cors_app(&deploy, auth, &[ALLOWED_ORIGIN]);

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api/sites")
        .header(header::ORIGIN, ALLOWED_ORIGIN)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
        .body(Body::empty())
        .unwrap();
    let (status, headers) = cors_send(app, req).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], ALLOWED_ORIGIN);
    assert_eq!(
        headers[header::ACCESS_CONTROL_ALLOW_METHODS],
        "GET, POST, PUT, DELETE, OPTIONS"
    );
    // The browser's requested headers are echoed back.
    assert_eq!(
        headers[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "authorization"
    );
    assert!(headers.contains_key(header::ACCESS_CONTROL_MAX_AGE));
}

/// An actual API request from an allowed origin gets the origin echoed back,
/// with `Vary: Origin`.
#[tokio::test]
async fn cors_actual_request_echoes_allowed_origin() {
    let deploy = seed().await;
    let (auth, admin) = token_auth(&[GrantedRole::global("admin")]).await;
    let app = cors_app(&deploy, auth, &[ALLOWED_ORIGIN]);

    let mut req = with_bearer(get("/api/auth/whoami"), &admin);
    req.headers_mut()
        .insert(header::ORIGIN, ALLOWED_ORIGIN.parse().unwrap());
    let (status, headers) = cors_send(app, req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], ALLOWED_ORIGIN);
    assert!(headers
        .get_all(header::VARY)
        .iter()
        .any(|v| v.as_bytes().eq_ignore_ascii_case(b"origin")));
}

/// A `*` allowlist permits any origin, echoing the specific origin (not literal
/// `*`), which keeps it `Vary`-correct.
#[tokio::test]
async fn cors_wildcard_allows_any_origin() {
    let deploy = seed().await;
    let (auth, admin) = token_auth(&[GrantedRole::global("admin")]).await;
    let app = cors_app(&deploy, auth, &["*"]);

    let mut req = with_bearer(get("/api/auth/whoami"), &admin);
    req.headers_mut()
        .insert(header::ORIGIN, "https://anything.example".parse().unwrap());
    let (status, headers) = cors_send(app, req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://anything.example"
    );
}

/// An origin outside the allowlist gets no `Access-Control-*` headers, so the
/// browser blocks the cross-origin read.
#[tokio::test]
async fn cors_disallowed_origin_gets_no_headers() {
    let deploy = seed().await;
    let (auth, admin) = token_auth(&[GrantedRole::global("admin")]).await;
    let app = cors_app(&deploy, auth, &[ALLOWED_ORIGIN]);

    let mut req = with_bearer(get("/api/auth/whoami"), &admin);
    req.headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let (status, headers) = cors_send(app, req).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

/// With the default (empty) allowlist the CORS layer is never installed, so an
/// `Origin` request is served with no `Access-Control-*` headers — the
/// same-origin dogfood behavior is unchanged.
#[tokio::test]
async fn cors_off_by_default_no_headers() {
    let deploy = seed().await;
    let (auth, admin) = token_auth(&[GrantedRole::global("admin")]).await;
    let app = router_with(
        deploy.clone(),
        auth,
        HandlerRuntime::disabled(),
        ServerOptions::default(),
    );

    let mut req = with_bearer(get("/api/auth/whoami"), &admin);
    req.headers_mut()
        .insert(header::ORIGIN, ALLOWED_ORIGIN.parse().unwrap());
    let (status, headers) = cors_send(app, req).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}
