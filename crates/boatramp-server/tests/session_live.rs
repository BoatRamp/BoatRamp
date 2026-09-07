//! Live capability gate for the duplex/resumable **session** capability
//! (`boatramp:handlers/session`, PLAN-session-primitive Stage 6). Unlike the per-store /
//! delivery-model unit tests (each in its own store, no wasm), this drives the REAL serving
//! pipeline — `router()` → `serve_resolved` → the session GET/POST routes → the engine re-entering
//! a REAL compiled guest component (`session-echo.wasm`) — over an in-memory control plane, and
//! asserts the end-to-end contract the primitive promises:
//!
//!   1. **Duplex**: a `POST` inbound frame re-enters the guest, whose `send` lands an outbound frame
//!      that the `GET` SSE stream delivers (base64 `data:`, monotonic `id:`) — opaque bytes intact.
//!   2. **Resume via checkpoint**: the guest rehydrates a counter from its `checkpoint` on each
//!      re-entry (mechanism B — no in-memory state survives), so the echo count advances across
//!      separate POSTs; proven by the second echo being `#2` even though each re-entry is fresh.
//!   3. **Resume from cursor**: a reconnect with `Last-Event-ID: 1` replays only frames past cursor
//!      1 (not the whole history).
//!   4. **At-least-once dedup**: a retried `POST` with the same `Idempotency-Key` is delivered once
//!      (the guest does not double-echo).
//!   5. **Guest-initiated close**: a `cancel` frame closes the session; the SSE emits a terminal
//!      `event: close`, and a further `POST` is `410 Gone`.
//!   6. **Input hardening**: a malformed session id is rejected `400` before any work.
//!
//! `#[ignore]`d (per the anti-`#[ignore]`-as-evidence rule it is wired into
//! `.github/workflows/capability.yml` as a HARD GATE that greps the success marker, so a silent
//! skip fails the job). Run locally with:
//!   `cargo test -p boatramp-server --features session --test session_live -- --ignored --nocapture`

#![cfg(feature = "session")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine;
use boatramp_core::config::{DeployConfig, HandlersSiteConfig, SessionConfig, SiteConfig};
use boatramp_core::deploy::{sha256_hex, DeployStore, FileEntry, Manifest};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::ByteStream;
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_server::{router, Auth, HandlerRuntime};
use boatramp_storage::FsStorage;
use futures::StreamExt;
use tower::ServiceExt;

const SESSION_ECHO: &[u8] =
    include_bytes!("../../boatramp-handlers/tests/fixtures/session-echo.wasm");

const SITE: &str = "agentsite";
const ROUTE: &str = "/agent";

type App = axum::Router;

/// Build the live app: a real engine + runtime serving a deployment whose `/agent` route is a
/// session backed by the compiled `session-echo` component, on a handlers-enabled site.
async fn live_app() -> (App, Arc<MemoryKv>) {
    let kv = Arc::new(MemoryKv::new());
    // A unique temp dir per run so parallel/local runs don't collide on blobs.
    let dir = std::env::temp_dir().join(format!("br-session-live-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(SESSION_ECHO);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(SESSION_ECHO)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "session/echo.wasm".to_string(),
        FileEntry {
            hash,
            size: SESSION_ECHO.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let config = DeployConfig {
        sessions: vec![SessionConfig {
            route: ROUTE.to_string(),
            component: "session/echo.wasm".to_string(),
            imports: vec!["session".to_string()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let manifest = Manifest {
        files,
        config,
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .activate(ProjectRef::DEFAULT, SITE, &id)
        .await
        .unwrap();
    deploy
        .set_site_config(
            ProjectRef::DEFAULT,
            SITE,
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["session".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    (router(deploy, Auth::disabled(), runtime), kv)
}

fn req(method: &str, uri: &str, body: &'static [u8]) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .unwrap();
    r.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    r
}

/// POST one inbound frame; returns `(status, body-text)`.
async fn post(app: &App, uri: &str, body: &'static [u8]) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req("POST", uri, body)).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Open the SSE stream and collect its bytes for `dur` (the stream is otherwise unending), then
/// drop it (releasing the connection permits). Returns the decoded event-stream text.
async fn get_sse(app: &App, uri: &str, last_event_id: Option<&str>) -> String {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(id) = last_event_id {
        builder = builder.header("last-event-id", id);
    }
    let mut r = builder.body(Body::empty()).unwrap();
    r.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40001))));
    let resp = app.clone().oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "SSE open should be 200");
    let mut stream = resp.into_body().into_data_stream();
    let mut acc: Vec<u8> = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(1500), async {
        while let Some(Ok(chunk)) = stream.next().await {
            acc.extend_from_slice(&chunk);
        }
    })
    .await;
    String::from_utf8_lossy(&acc).into_owned()
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// Read the persisted session record for cross-checking (the store type is crate-private, so parse
/// the JSON generically). `None` if the session was reaped/never opened.
async fn record(kv: &MemoryKv, id: &str) -> Option<serde_json::Value> {
    let key = format!("session/{}/{id}", ProjectRef::DEFAULT.as_str());
    kv.get(&key)
        .await
        .unwrap()
        .map(|b| serde_json::from_slice(&b).unwrap())
}

#[tokio::test]
#[ignore = "capability gate: run via capability.yml or with --ignored"]
async fn session_capability_duplex_resume_dedup_and_close() {
    let (app, kv) = live_app().await;
    let base = format!("/_sites/{SITE}{ROUTE}");

    // ---- 1. Duplex: POST re-enters the guest, which echoes an outbound frame ----
    let s1 = format!("{base}?id=S1");
    assert_eq!(post(&app, &s1, b"hello").await.0, StatusCode::ACCEPTED);
    let rec = record(&kv, "S1").await.expect("session S1 persisted");
    let outbound = rec["state"]["outbound"].as_array().unwrap();
    assert_eq!(outbound.len(), 1, "one outbound frame buffered");
    assert_eq!(outbound[0]["cursor"].as_u64(), Some(1));
    // The checkpoint persisted the running count (1) as 4 LE bytes.
    let cp = rec["state"]["checkpoint"].as_array().unwrap();
    assert_eq!(
        cp.first().and_then(serde_json::Value::as_u64),
        Some(1),
        "count=1 checkpointed"
    );

    // ---- SSE delivers the buffered frame: base64(echo#1:hello) with id: 1 ----
    let sse = get_sse(&app, &s1, None).await;
    assert!(
        sse.contains("event: frame"),
        "sse had no frame event: {sse}"
    );
    assert!(sse.contains("id: 1"), "sse missing cursor id: {sse}");
    assert!(
        sse.contains(&b64("echo#1:hello")),
        "sse missing echoed payload: {sse}"
    );

    // ---- 2. Resume via checkpoint: a fresh re-entry resumes the count → echo #2 ----
    assert_eq!(post(&app, &s1, b"world").await.0, StatusCode::ACCEPTED);
    let rec = record(&kv, "S1").await.unwrap();
    let outbound = rec["state"]["outbound"].as_array().unwrap();
    let cursor2 = outbound
        .iter()
        .find(|f| f["cursor"].as_u64() == Some(2))
        .unwrap();
    let payload2: Vec<u8> = cursor2["payload"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(
        payload2,
        b"echo#2:world",
        "count must resume from the checkpoint (got {:?})",
        String::from_utf8_lossy(&payload2)
    );

    // ---- 3. Resume from cursor: reconnect with Last-Event-ID: 1 → only cursor 2 ----
    let sse = get_sse(&app, &s1, Some("1")).await;
    assert!(sse.contains("id: 2"), "resume missing cursor 2: {sse}");
    assert!(
        sse.contains(&b64("echo#2:world")),
        "resume missing payload: {sse}"
    );
    assert!(
        !sse.contains(&b64("echo#1:hello")),
        "resume must NOT redeliver acked cursor 1: {sse}"
    );

    // ---- 4. At-least-once dedup: a retried POST with the same key is delivered once ----
    let s1_idem = format!("{base}?id=S1&idem=K1");
    assert_eq!(post(&app, &s1_idem, b"dupe").await.0, StatusCode::ACCEPTED);
    let after_first = record(&kv, "S1").await.unwrap()["state"]["out_cursor"]
        .as_u64()
        .unwrap();
    let (status, body) = post(&app, &s1_idem, b"dupe").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "retried POST should be deduped: {body}"
    );
    let after_dup = record(&kv, "S1").await.unwrap()["state"]["out_cursor"]
        .as_u64()
        .unwrap();
    assert_eq!(
        after_first, after_dup,
        "a deduped POST must not re-run the guest"
    );

    // ---- 5. Guest-initiated close: `cancel` closes; SSE emits close; further POST is 410 ----
    assert_eq!(post(&app, &s1, b"cancel").await.0, StatusCode::ACCEPTED);
    let sse = get_sse(&app, &s1, None).await;
    assert!(
        sse.contains("event: close"),
        "no close event after cancel: {sse}"
    );
    assert!(sse.contains("client cancel"), "close reason missing: {sse}");
    assert_eq!(
        post(&app, &s1, b"again").await.0,
        StatusCode::GONE,
        "a POST to a closed session must be 410"
    );

    // ---- 6. Input hardening: a malformed session id is rejected before any work ----
    let bad = format!("{base}?id=has%2Fslash");
    assert_eq!(
        post(&app, &bad, b"x").await.0,
        StatusCode::BAD_REQUEST,
        "an invalid session id must be rejected 400"
    );
    // A distinct id under the same route opens its own independent session.
    let s2 = format!("{base}?id=S2");
    assert_eq!(post(&app, &s2, b"solo").await.0, StatusCode::ACCEPTED);
    assert!(record(&kv, "S2").await.is_some());

    // The single success marker the capability job greps for — printed ONLY after every
    // assertion above passed against the real compiled guest + serving pipeline.
    println!(
        "SESSION CAPABILITY GATE OK: duplex send/recv, checkpoint-resume, cursor-resume, \
         idempotent redelivery, guest close, and id hardening all held end to end."
    );
}
