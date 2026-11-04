//! Live end-to-end gate for the **Connect / gRPC-web SERVER-STREAM** transport over the host's
//! existing live-topic **fan-out** (luigi BR-REQ-1, PLAN-connect-grpc §7 / IU-4).
//!
//! This proves the IU-4 host deliverable: a configured stream route, served over the ACTUAL
//! hand-rolled HTTP/1.1 stack (`boatramp_http::serve_connection` via `serve_plaintext_listener`),
//! frames each delivered messaging payload as a **length-prefixed Connect/gRPC-web envelope data
//! frame** (instead of an SSE `event:` line) when the client opens the stream with a
//! Connect/gRPC-web streaming content-type (`stream.rs::serve_connect_stream`). The fan-out, the
//! per-subscriber authorization, the permits and the idle timeout are the SAME ones the SSE path
//! uses — only the on-wire framing of each payload differs (PLAN §7: server-streaming =
//! framing-on-the-existing-fan-out).
//!
//! The substrate is a real [`LogMessaging`] backend (its live `subscribe` delivers an at-most-once
//! broadcast with a recent-event ring). The test plays the PLAN §7 **producer**: a background task
//! publishes a monotonically-increasing `Tick` protobuf to the scope-namespaced topic. A client
//! then POSTs the server-stream RPC and reads the chunked response incrementally, asserting each
//! delivered chunk is one envelope data frame that decodes back to a `Tick` with a strictly
//! increasing `seq` — i.e. the framing survived the real stack uncorrupted and live ordering held.
//!
//! Three properties, all asserted at the real socket:
//!   1. **Connect streaming (`application/connect+proto`)** frames each payload as `[flags=0][u32
//!      len][payload]`, and the payload decodes to the published `Tick`.
//!   2. **gRPC-web (`application/grpc-web+proto`)** frames identically, and — with on-the-fly
//!      compression ON + `Accept-Encoding: gzip` — comes back with NO `content-encoding` (the host
//!      residual, commit `2f5aa2d0`, must never HTTP-compress a framed body on the fan-out path
//!      either; it would mangle the envelope framing).
//!   3. **Per-subscriber authz gates the Connect path too**: a `Scoped` stream route POSTed with no
//!      bearer is `401` BEFORE any byte is framed (the same `authorize_stream_topics` the SSE/WS
//!      paths run — a Connect content-type can't smuggle past it).
//!
//! `#[ignore]`d (real loopback sockets + a live publisher, timing-sensitive like the other socket
//! live gates) and run in its OWN dedicated `live gate (connect-server-stream)` CI job with
//! `--include-ignored`; the gate greps the `CONNECT SERVER-STREAM FANOUT LIVE OK` marker + the pass
//! count, so a silent skip / compile-out fails the merge (the ignore-gated-tests-not-evidence
//! discipline). No wasm toolchain needed — the fan-out serve path has no guest in the loop.
#![cfg(all(feature = "handlers", feature = "compression"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use boatramp_core::config::{
    CompressionConfig, DeployConfig, HandlerGraphqlTokenClaims, HandlersSiteConfig, SiteConfig,
    StreamAuthz, StreamConfig, StreamMembership,
};
use boatramp_core::deploy::{DeployStore, Manifest};
use boatramp_core::kv::MemoryKv;
use boatramp_core::messaging::{LogMessaging, Messaging};
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_server::{Auth, HandlerRuntime, router, serve_plaintext_listener};
use boatramp_storage::FsStorage;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const SITE: &str = "tickersite";
/// The broadcast Connect server-stream RPC: `/{package}.{Service}/{Method}`.
const TICKER_ROUTE: &str = "/pms.v1.Ticker/Subscribe";
/// The config topic the ticker fans out (scope-relative).
const TICKER_TOPIC: &str = "ticks";
/// A scoped Connect server-stream route — used only to prove authz gates the Connect path (401).
const SECURE_ROUTE: &str = "/pms.v1.Secure/Watch";

/// Build the live app: a real engine + runtime over a `LogMessaging` backend (live broadcast),
/// serving a deployment with one broadcast Connect server-stream route + one scoped route, on a
/// handlers-enabled site with on-the-fly compression ON. Returns the app and the messaging handle
/// (so the test can play producer and publish to the fan-out topic).
async fn live_app() -> (axum::Router, Arc<LogMessaging>) {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-connect-ss-live-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    // The live-broadcast messaging substrate the SSE/Connect fan-out rides.
    let messaging: Arc<LogMessaging> = Arc::new(LogMessaging::new(storage.clone(), kv.clone()));

    let config = DeployConfig {
        streams: vec![
            // Broadcast (unauthenticated) server-stream: the framing proof.
            StreamConfig {
                route: TICKER_ROUTE.to_string(),
                topics: vec![TICKER_TOPIC.to_string()],
                websocket: false,
                publish_topic: None,
                authz: None,
            },
            // Scoped server-stream: authz must gate the Connect path (401 without a bearer).
            StreamConfig {
                route: SECURE_ROUTE.to_string(),
                topics: vec!["secure/{room}/events".to_string()],
                websocket: false,
                publish_topic: None,
                authz: Some(StreamAuthz::Scoped {
                    token_claims: HandlerGraphqlTokenClaims {
                        issuer: "https://idp.example".to_string(),
                        jwks_env: Some("IDP_JWKS".to_string()),
                        ..Default::default()
                    },
                    membership: vec![StreamMembership::Claim {
                        param: "room".to_string(),
                        claim: "rooms".to_string(),
                    }],
                }),
            },
        ],
        ..Default::default()
    };
    let manifest = Manifest {
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
                    allow_imports: vec![],
                    ..Default::default()
                }),
                // Compression ON (min_size 0) so the gRPC-web case actively exercises the host
                // residual's never-compress-a-framed-body guard on the fan-out path.
                compression: CompressionConfig {
                    enabled: true,
                    min_size: 0,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(
        engine,
        kv.clone(),
        storage,
        None,
        Some(messaging.clone() as Arc<dyn Messaging>),
    );
    (router(deploy, Auth::disabled(), runtime), messaging)
}

async fn spawn_server(app: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = serve_plaintext_listener(listener, app, std::future::pending::<()>()).await;
    });
    addr
}

/// The scope-namespaced topic the fan-out subscribes to: `{project}/{site}/{config topic}` — where
/// a producer must publish for a `default`-project site (`ProjectRef::qualified` prefixes the
/// project for every project, `default` included).
fn namespaced_topic() -> String {
    let scope = ProjectRef::new("default").qualified(SITE);
    format!("{scope}/{TICKER_TOPIC}")
}

// ---- tiny protobuf codec for `Tick { int64 seq = 1; string note = 2; }` -------------------------

fn encode_tick(seq: i64, note: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // field 1, varint (wire type 0): tag 0x08
    out.push(0x08);
    encode_varint(seq as u64, &mut out);
    // field 2, LEN (wire type 2): tag 0x12
    if !note.is_empty() {
        out.push(0x12);
        encode_varint(note.len() as u64, &mut out);
        out.extend_from_slice(note.as_bytes());
    }
    out
}

/// Decode the `int64 seq = 1` out of a `Tick` message (ignores the `note`).
fn decode_tick_seq(msg: &[u8]) -> i64 {
    assert!(!msg.is_empty(), "empty Tick message");
    assert_eq!(
        msg[0], 0x08,
        "expected Tick field #1 (int64 seq) varint tag 0x08, got {:#x}",
        msg[0]
    );
    let (seq, _) = decode_varint(&msg[1..]);
    seq as i64
}

fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn decode_varint(buf: &[u8]) -> (u64, usize) {
    let mut v = 0u64;
    let mut shift = 0;
    let mut i = 0;
    loop {
        let byte = buf[i];
        v |= ((byte & 0x7f) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (v, i)
}

/// One Connect/gRPC-web envelope frame: `flags`, a big-endian `u32` length, then `payload`.
fn encode_envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(flags);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ---- incremental HTTP/1.1 chunked reader (the response body never ends until we drop) -----------

/// Read the HTTP response head (status line + headers, lowercased) off a buffered reader, stopping
/// at the blank line. Leaves the reader positioned at the first body byte.
async fn read_http_head<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> (u16, Vec<(String, String)>) {
    let mut status = 0u16;
    let mut headers = Vec::new();
    let mut first = true;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.expect("read head line");
        assert!(n != 0, "connection closed before end of head");
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of head
        }
        if first {
            status = trimmed
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("no status in {trimmed:?}"));
            first = false;
        } else if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    (status, headers)
}

/// Read one HTTP/1.1 chunk (its payload) off a buffered reader; `None` at the terminal 0-size
/// chunk. Each fan-out payload is written as its own chunk, so one chunk == one envelope frame.
async fn read_one_chunk<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<Vec<u8>> {
    let mut size_line = String::new();
    let n = reader.read_line(&mut size_line).await.ok()?;
    if n == 0 {
        return None;
    }
    let hex = size_line.trim().split(';').next().unwrap_or("").trim();
    let size = usize::from_str_radix(hex, 16).ok()?;
    if size == 0 {
        return None;
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload).await.ok()?;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await.ok()?;
    Some(payload)
}

/// Decode one envelope frame from the front of `buf`: `(flags, payload)`.
fn decode_envelope(buf: &[u8]) -> (u8, Vec<u8>) {
    assert!(buf.len() >= 5, "short envelope prefix: {} bytes", buf.len());
    let flags = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    assert!(buf.len() >= 5 + len, "envelope payload overruns the chunk");
    (flags, buf[5..5 + len].to_vec())
}

/// Open a Connect server-stream POST and read `want` envelope **data** frames, asserting each
/// decodes to a `Tick` with a strictly increasing `seq`. Returns the response headers (so the
/// caller can assert content-type / no content-encoding). Drops the socket when done (ending the
/// stream on the server side).
async fn read_stream_frames(
    addr: SocketAddr,
    route: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    want: usize,
) -> Vec<(String, String)> {
    let stream = TcpStream::connect(addr).await.expect("connect loopback");
    let (rd, mut wr) = stream.into_split();
    // One enveloped request message (the host drains it without decoding — scope rides route +
    // bearer; PLAN §11.2). We keep the write half open (streaming response), so no Connection: close.
    let body = encode_envelope(0, &encode_tick(0, "req"));
    let path = format!("/_sites/{SITE}{route}");
    let mut req = Vec::new();
    req.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    req.extend_from_slice(b"Host: localhost\r\n");
    req.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    for (k, v) in extra_headers {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(&body);
    wr.write_all(&req).await.expect("write request");
    wr.flush().await.ok();

    let mut reader = BufReader::new(rd);
    let (status, headers) =
        tokio::time::timeout(Duration::from_secs(15), read_http_head(&mut reader))
            .await
            .expect("head within 15s");
    assert_eq!(
        status, 200,
        "server-stream head is 200; headers: {headers:?}"
    );

    let mut last_seq = i64::MIN;
    for i in 0..want {
        let chunk = tokio::time::timeout(Duration::from_secs(15), read_one_chunk(&mut reader))
            .await
            .expect("frame within 15s")
            .unwrap_or_else(|| panic!("stream ended before frame {i}"));
        let (flags, payload) = decode_envelope(&chunk);
        assert_eq!(flags, 0, "frame {i} is an envelope DATA frame (flags=0)");
        let seq = decode_tick_seq(&payload);
        assert!(
            seq > last_seq,
            "frame {i}: Tick seq must strictly increase (live ordering); got {seq} after {last_seq}"
        );
        last_seq = seq;
    }
    // Drop the read half by returning; the write half drops here, closing the stream server-side.
    drop(wr);
    headers
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// POST a scoped server-stream route with no bearer and return the HTTP status (expected 401).
async fn connect_status_no_bearer(addr: SocketAddr, route: &str, content_type: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).await.expect("connect loopback");
    let body = encode_envelope(0, &encode_tick(0, "req"));
    let path = format!("/_sites/{SITE}{route}");
    let mut req = Vec::new();
    req.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    req.extend_from_slice(b"Host: localhost\r\n");
    req.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    req.extend_from_slice(b"Connection: close\r\n\r\n");
    req.extend_from_slice(&body);
    stream.write_all(&req).await.expect("write request");
    stream.flush().await.ok();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut raw))
        .await
        .expect("response within 15s")
        .expect("read response");
    let head = String::from_utf8_lossy(&raw);
    let status_line = head.lines().next().unwrap_or("");
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status in {status_line:?}"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: serves a real Connect/gRPC-web server-stream over the host fan-out on a loopback \
            socket with a live publisher; run via --include-ignored in the \
            `live gate (connect-server-stream)` job"]
async fn connect_server_stream_fanout_frames_live() {
    let (app, messaging) = live_app().await;
    let addr = spawn_server(app).await;

    // The PLAN §7 producer: a background task publishes a monotonically-increasing Tick to the
    // scope-namespaced fan-out topic until the test is done. Running continuously removes the
    // subscribe/publish race — a subscriber attaching mid-stream still catches the live feed.
    let stop = Arc::new(AtomicBool::new(false));
    let publisher = {
        let messaging = messaging.clone();
        let stop = stop.clone();
        let topic = namespaced_topic();
        tokio::spawn(async move {
            let mut seq: i64 = 1;
            while !stop.load(Ordering::Relaxed) {
                let _ = messaging.publish(&topic, &encode_tick(seq, "tick")).await;
                seq += 1;
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        })
    };

    // 1) Connect streaming: each delivered payload is one envelope data frame decoding to a Tick.
    let headers = read_stream_frames(addr, TICKER_ROUTE, "application/connect+proto", &[], 3).await;
    assert!(
        header(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/connect+proto"),
        "connect+proto server-stream echoes its content-type; headers: {headers:?}"
    );

    // 2) gRPC-web: frames identically, and WITH compression on + Accept-Encoding: gzip the framed
    //    body must NOT be HTTP-compressed (the host residual applies to the fan-out path too).
    let headers = read_stream_frames(
        addr,
        TICKER_ROUTE,
        "application/grpc-web+proto",
        &[("Accept-Encoding", "gzip")],
        3,
    )
    .await;
    assert!(
        header(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/grpc-web+proto"),
        "grpc-web+proto server-stream echoes its content-type; headers: {headers:?}"
    );
    assert!(
        header(&headers, "content-encoding").is_none(),
        "HOST RESIDUAL: a framed gRPC-web server-stream body must never be HTTP-compressed (it \
         would mangle the envelope framing), even with compression on + Accept-Encoding: gzip; \
         headers: {headers:?}"
    );

    // 3) Per-subscriber authz gates the Connect path: a Scoped route without a bearer is 401,
    //    refused by the SAME authorize_stream_topics the SSE/WS paths use, BEFORE any framing — a
    //    Connect content-type cannot smuggle past it.
    let status = connect_status_no_bearer(addr, SECURE_ROUTE, "application/connect+proto").await;
    assert_eq!(
        status, 401,
        "a scoped Connect server-stream with no bearer must be 401 (authz runs before framing)"
    );

    stop.store(true, Ordering::Relaxed);
    publisher.abort();

    // The marker the CI gate greps — reached only after Connect + gRPC-web framing round-tripped
    // over the real hand-rolled HTTP stack on the live fan-out, the residual held, and authz gated.
    println!("CONNECT SERVER-STREAM FANOUT LIVE OK");
}
