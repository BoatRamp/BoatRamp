//! Live end-to-end gate for a **guest-driven Connect / gRPC-web SERVER-STREAM** (luigi BR-REQ-1,
//! PLAN-connect-grpc §6-§8 / IU-3+IU-4) — the direct mirror of the Connect-UNARY gate.
//!
//! A REAL compiled guest component (`connect-ticker.wasm`, built from the shim repo's
//! `examples/connect-ticker` on the `boatramp-connect` serving shim, with GENERATED prost messages)
//! serves one server-stream RPC `POST /connect.ticker.v1.Ticker/Subscribe` via
//! `boatramp_connect::serve_server_stream`: it decodes the request, then yields N `Tick`s onto the
//! shim's incremental `ResponseStream` (the §8 `#[handler(stream)]` arm), which the host drains
//! chunk-by-chunk over the ACTUAL hand-rolled HTTP/1.1 stack (`boatramp_http::serve_connection` via
//! `serve_plaintext_listener`). The shim frames each `Tick` as a length-prefixed envelope data
//! frame and writes the terminal end frame when the body returns — proving the shared
//! `boatramp-connect-frame` codec end-to-end over the real engine + serving path.
//!
//! Two shapes, both guest-driven server-streams, asserted at the real socket:
//!   1. **Connect streaming (`application/connect+proto`)**: N data frames decoding to `Tick`s with
//!      `seq` 1..N, then a Connect **EndStream** frame (`flags & 0x02`, payload `{}` for ok).
//!   2. **gRPC-web (`application/grpc-web+proto`) with compression ON + `Accept-Encoding: gzip`**: N
//!      data frames + a gRPC-web **trailers** frame (`flags & 0x80`, `grpc-status: 0`), and NO
//!      `content-encoding` on the response (the host residual must never HTTP-compress a framed
//!      streaming body — it would mangle the envelope framing).
//!
//! `#[ignore]`d (real loopback sockets, timing-sensitive like the other socket live gates) and run
//! in its OWN dedicated `live gate (connect-server-stream)` CI job with `--include-ignored`; the
//! gate greps the `CONNECT SERVER-STREAM GUEST LIVE OK` marker + the pass count, so a silent skip /
//! compile-out fails the merge (the ignore-gated-tests-not-evidence discipline). The fixture is
//! `include_bytes!`-embedded (prebuilt + committed), so it runs on musl with no wasm toolchain.
//!
//! Regenerate the fixture (a `boatramp-connect` / shim WIT / `.proto` change ⇒ rebuild) from the
//! shim repo:
//! ```sh
//! just codegen   # if the .proto changed
//! cargo build --release -p connect-ticker-example --target wasm32-wasip2
//! cp target/wasm32-wasip2/release/connect_ticker_example.wasm \
//!    ../boatramp/crates/boatramp-server/tests/fixtures/connect-ticker.wasm
//! ```
#![cfg(all(feature = "handlers", feature = "compression"))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boatramp_core::ByteStream;
use boatramp_core::config::{
    CompressionConfig, DeployConfig, HandlerConfig, HandlersSiteConfig, SiteConfig,
};
use boatramp_core::deploy::{DeployStore, FileEntry, Manifest, sha256_hex};
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_server::{Auth, HandlerRuntime, router, serve_plaintext_listener};
use boatramp_storage::FsStorage;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CONNECT_TICKER: &[u8] = include_bytes!("fixtures/connect-ticker.wasm");

const SITE: &str = "tickersite";
/// The Connect server-stream RPC path — both the deploy handler route and the guest's own
/// `#[handler(route = …, stream)]`.
const RPC_PATH: &str = "/connect.ticker.v1.Ticker/Subscribe";
/// How many ticks the request asks for (`SubscribeRequest { uint32 count = 1 }`).
const WANT_TICKS: i64 = 4;

/// Build the live app: a real engine + runtime serving a deployment whose server-stream route is
/// the compiled `connect-ticker` component (STREAMING handler), on a handlers-enabled site with
/// on-the-fly compression ON.
async fn live_app() -> axum::Router {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-connect-ss-guest-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(CONNECT_TICKER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(CONNECT_TICKER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "connect/ticker.wasm".to_string(),
        FileEntry {
            hash,
            size: CONNECT_TICKER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let config = DeployConfig {
        handlers: vec![HandlerConfig {
            route: RPC_PATH.to_string(),
            methods: vec!["POST".to_string()],
            component: "connect/ticker.wasm".to_string(),
            imports: vec![],
            // The guest drives an incremental ResponseStream — serve it on the streaming lane.
            streaming: true,
            limits: None,
            env: BTreeMap::new(),
            secrets: vec![],
            no_secrets: false,
            invoke_targets: vec![],
            stats_topics: vec![],
            tenant_secret_names: vec![],
            upload_containers: vec![],
            blobstore_containers: vec![],
            egress_allowlist: vec![],
            dns_publish_zones: vec![],
            dns_publish_ns_targets: vec![],
            tenancy: None,
            token_claims: None,
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
                    allow_imports: vec![],
                    ..Default::default()
                }),
                // Compression ON so the gRPC-web case actively exercises the host residual's
                // never-compress-a-framed-body guard on the guest-streaming path.
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
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    router(deploy, Auth::disabled(), runtime)
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

// ---- tiny protobuf + envelope codec (no boatramp-connect dependency in the host test) -----------

/// Encode `SubscribeRequest { uint32 count = 1 }` — field 1, varint (wire type 0): tag 0x08.
fn encode_subscribe(count: u32) -> Vec<u8> {
    let mut out = vec![0x08u8];
    encode_varint(count as u64, &mut out);
    out
}

/// Decode the `int64 seq = 1` out of a `Tick` message (ignores the `note` at field 2).
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

fn encode_envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(flags);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode all envelope frames `[flags, u32 len, payload]*` from a framed body.
fn decode_envelopes(mut buf: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    while buf.len() >= 5 {
        let flags = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            break;
        }
        frames.push((flags, buf[5..5 + len].to_vec()));
        buf = &buf[5 + len..];
    }
    frames
}

/// Issue one Connect server-stream `POST` and read the whole (bounded) framed response to EOF.
/// Returns `(status, headers lowercased, body)`.
async fn connect_stream_call(
    addr: SocketAddr,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("connect loopback");
    let path = format!("/_sites/{SITE}{RPC_PATH}");
    let mut req = Vec::new();
    req.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    req.extend_from_slice(b"Host: localhost\r\n");
    req.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    for (k, v) in extra_headers {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    req.extend_from_slice(b"Connection: close\r\n\r\n");
    req.extend_from_slice(&body);
    stream.write_all(&req).await.expect("write request");
    stream.flush().await.ok();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut raw))
        .await
        .expect("response within 15s")
        .expect("read response");
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let sep = find_subslice(raw, b"\r\n\r\n").expect("response has a header/body separator");
    let head = std::str::from_utf8(&raw[..sep]).expect("utf8 response head");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status code in {status_line:?}"));
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let body_raw = &raw[sep + 4..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        dechunk(body_raw)
    } else if let Some(cl) = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
    {
        body_raw[..cl.min(body_raw.len())].to_vec()
    } else {
        body_raw.to_vec()
    };
    (status, headers, body)
}

fn dechunk(mut buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = find_subslice(buf, b"\r\n") {
        let size_line = std::str::from_utf8(&buf[..nl]).unwrap_or("");
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).unwrap_or(0);
        buf = &buf[nl + 2..];
        if size == 0 {
            break;
        }
        if buf.len() < size {
            out.extend_from_slice(buf);
            break;
        }
        out.extend_from_slice(&buf[..size]);
        buf = &buf[size..];
        if buf.len() >= 2 {
            buf = &buf[2..]; // trailing CRLF after the chunk data
        }
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Assert the `want` leading data frames decode to `Tick`s with `seq` 1..=want.
fn assert_tick_data_frames(frames: &[(u8, Vec<u8>)], want: i64) {
    for (i, (flags, payload)) in frames.iter().take(want as usize).enumerate() {
        assert_eq!(*flags, 0, "frame {i} is an envelope DATA frame (flags=0)");
        assert_eq!(
            decode_tick_seq(payload),
            (i as i64) + 1,
            "data frame {i} decodes to Tick seq {}",
            i + 1
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: serves a real guest-driven Connect/gRPC-web server-stream over the hand-rolled \
            HTTP stack on a loopback socket; run via --include-ignored in the \
            `live gate (connect-server-stream)` job"]
async fn connect_server_stream_guest_round_trips_over_the_http_stack() {
    let app = live_app().await;
    let addr = spawn_server(app).await;

    // ---- 1. Connect streaming: N data frames (Ticks 1..N) + a Connect EndStream frame -----------
    let (status, headers, body) = connect_stream_call(
        addr,
        "application/connect+proto",
        &[],
        encode_envelope(0, &encode_subscribe(WANT_TICKS as u32)),
    )
    .await;
    assert_eq!(
        status, 200,
        "server-stream head is 200 (headers: {headers:?})"
    );
    assert!(
        header(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/connect+proto"),
        "connect+proto server-stream echoes its content-type; headers: {headers:?}"
    );
    let frames = decode_envelopes(&body);
    assert_eq!(
        frames.len() as i64,
        WANT_TICKS + 1,
        "connect server-stream = {WANT_TICKS} data frames + 1 EndStream frame; got {} frame(s): {frames:?}",
        frames.len()
    );
    assert_tick_data_frames(&frames, WANT_TICKS);
    let (end_flags, end_payload) = &frames[WANT_TICKS as usize];
    assert_ne!(
        end_flags & 0x02,
        0,
        "the last frame is a Connect EndStream frame (flag 0x02)"
    );
    assert_eq!(
        end_payload, b"{}",
        "a clean (ok) Connect EndStream payload is the empty object"
    );

    // ---- 2. gRPC-web WITH compression ON + Accept-Encoding: gzip (the host residual) ------------
    let (status, headers, body) = connect_stream_call(
        addr,
        "application/grpc-web+proto",
        &[("Accept-Encoding", "gzip")],
        encode_envelope(0, &encode_subscribe(WANT_TICKS as u32)),
    )
    .await;
    assert_eq!(
        status, 200,
        "gRPC-web server-stream head is 200 (headers: {headers:?})"
    );
    assert!(
        header(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/grpc-web+proto"),
        "grpc-web+proto server-stream echoes its content-type; headers: {headers:?}"
    );
    assert!(
        header(&headers, "content-encoding").is_none(),
        "HOST RESIDUAL: a framed gRPC-web streaming body must never be HTTP-compressed (it would \
         mangle the envelope framing), even with compression on + Accept-Encoding: gzip; \
         headers: {headers:?}"
    );
    let frames = decode_envelopes(&body);
    assert_eq!(
        frames.len() as i64,
        WANT_TICKS + 1,
        "grpc-web server-stream = {WANT_TICKS} data frames + 1 trailers frame; got {} frame(s): {frames:?}",
        frames.len()
    );
    assert_tick_data_frames(&frames, WANT_TICKS);
    let (tr_flags, tr_payload) = &frames[WANT_TICKS as usize];
    assert_ne!(
        tr_flags & 0x80,
        0,
        "the last frame is a gRPC-web trailers frame (MSB flag 0x80)"
    );
    assert!(
        String::from_utf8_lossy(tr_payload).contains("grpc-status: 0"),
        "the gRPC-web trailers frame carries grpc-status: 0 (a clean stream); got: {:?}",
        String::from_utf8_lossy(tr_payload)
    );

    // The marker the CI gate greps — reached only after BOTH guest-driven server-stream shapes
    // round-tripped over the real hand-rolled HTTP stack and the framing survived the compression
    // negotiation path.
    println!("CONNECT SERVER-STREAM GUEST LIVE OK");
}
