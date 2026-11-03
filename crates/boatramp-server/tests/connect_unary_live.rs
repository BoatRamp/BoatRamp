//! Live end-to-end gate for the **Connect / gRPC-web UNARY** transport (luigi BR-REQ-1,
//! PLAN-connect-grpc §9 IU-1). Proves a REAL Connect-unary round trip through the boatramp serving
//! path over the **actual hand-rolled HTTP/1.1 stack** (`boatramp_http::serve_connection`, driven
//! by [`boatramp_server::serve_plaintext_listener`]) — not an in-process `oneshot`, and not the
//! engine seam alone.
//!
//! A REAL compiled guest component (`connect-greeter.wasm`) serves one unary RPC
//! `POST /connect.greeter.v1.Greeter/SayHello` via `boatramp_connect::serve_unary` (built from the
//! shim repo's `examples/connect-greeter`, which depends on the `boatramp-connect` serving shim).
//! It is deployed through a real [`DeployStore`] + [`router`], bound to a loopback socket, and
//! driven with a hand-written HTTP/1.1 Connect-unary request over a client `TcpStream`.
//!
//! Two shapes, both unary, asserted at the real socket:
//!
//!   1. **Bare Connect-unary (`application/proto`)**: one bare protobuf message in, one bare
//!      protobuf message out. Proves the host round-trips a Connect-unary call unmangled and the
//!      reply decodes (`hello, <name>!`).
//!   2. **gRPC-web (`application/grpc-web+proto`) with on-the-fly compression ON + `Accept-Encoding:
//!      gzip`**: exercises the HOST RESIDUAL (boatramp commit `2f5aa2d0`) — a framed grpc-web body
//!      carries length-prefixed envelope frames and negotiates compression per-message via the
//!      envelope flag, so the host must NEVER apply HTTP `Content-Encoding` (it would mangle the
//!      framing). The gate asserts there is no `content-encoding` header and the raw body still
//!      decodes as `[data frame][grpc-status: 0 trailers frame]`. If a future edit added
//!      `application/grpc-web+proto` to the compressible allowlist (regressing the residual), the
//!      body would arrive gzipped and the frame decode below would fail — so this assertion is
//!      load-bearing. (The companion unit test `content::compression_tests` locks the
//!      `is_compressible` predicate itself; this gate proves the whole serve path honors it.)
//!
//! `#[ignore]`d because it drives real loopback sockets (timing-sensitive under per-push runner
//! load, like the other socket live gates). The CI `live gate (connect-unary)` job runs it with
//! `--include-ignored` and greps the `CONNECT UNARY LIVE OK` marker + the pass count, so a silent
//! skip / compile-out fails the merge (the `ignore-gated-tests-not-evidence` discipline).
//!
//! Neither the `boatramp-connect` shim API nor the host residual is touched by this gate — it is a
//! pure test + fixture addition.
//!
//! Regenerate the fixture (a `boatramp-connect` / shim WIT change ⇒ rebuild) from the shim repo:
//! ```sh
//! (cd examples/connect-greeter && cargo build --release --target wasm32-wasip2)
//! cp target/wasm32-wasip2/release/connect_greeter_example.wasm \
//!    ../boatramp/crates/boatramp-server/tests/fixtures/connect-greeter.wasm
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

const CONNECT_GREETER: &[u8] = include_bytes!("fixtures/connect-greeter.wasm");

const SITE: &str = "greetersite";
/// The Connect RPC path — `/{package}.{Service}/{Method}` — both the deploy handler route and the
/// guest's own `#[handler(route = …)]`.
const RPC_PATH: &str = "/connect.greeter.v1.Greeter/SayHello";

/// Build the live app: a real engine + runtime serving a deployment whose RPC route is the
/// compiled `connect-greeter` component, on a handlers-enabled site with on-the-fly compression ON.
async fn live_app() -> axum::Router {
    let kv = Arc::new(MemoryKv::new());
    // A unique temp dir per run so parallel/local runs don't collide on blobs.
    let dir = std::env::temp_dir().join(format!("br-connect-live-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(CONNECT_GREETER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(CONNECT_GREETER)) })
            .boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "connect/greeter.wasm".to_string(),
        FileEntry {
            hash,
            size: CONNECT_GREETER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let config = DeployConfig {
        // HandlerConfig has no `Default`, so spell every field (least-privilege: no imports, no
        // secrets, no egress, no tenancy — the greeter is a pure transport echo).
        handlers: vec![HandlerConfig {
            route: RPC_PATH.to_string(),
            methods: vec!["POST".to_string()],
            component: "connect/greeter.wasm".to_string(),
            imports: vec![],
            streaming: false,
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
                // On-the-fly compression ON (min_size 0 ⇒ every eligible 200 is a candidate) so the
                // gRPC-web case actively exercises the host residual's never-compress-framed-bodies
                // guard rather than passing because compression was simply off.
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

/// Bind a loopback socket and serve `app` over the real hand-rolled HTTP stack; return its address.
/// The server task runs until the test process exits (a never-resolving shutdown).
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

// ---- a tiny self-contained Connect/protobuf client (no boatramp-connect dependency) -------------

/// Encode `message { string field = 1; }` on the protobuf wire: field 1, wire-type 2 (LEN) ⇒ tag
/// byte `0x0A`, a varint length, then the UTF-8 bytes. (A single non-empty string field is the
/// whole greeter message; proto3 omits an empty string, so every value here is non-empty.)
fn encode_string_msg(s: &str) -> Vec<u8> {
    let mut out = vec![0x0Au8];
    encode_varint(s.len() as u64, &mut out);
    out.extend_from_slice(s.as_bytes());
    out
}

/// Decode the `string field = 1` out of a protobuf message produced by the greeter.
fn decode_string_msg(msg: &[u8]) -> String {
    assert!(!msg.is_empty(), "empty protobuf message");
    assert_eq!(
        msg[0], 0x0A,
        "expected protobuf field #1 LEN tag (0x0A), got {:#x}",
        msg[0]
    );
    let (len, used) = decode_varint(&msg[1..]);
    let start = 1 + used;
    let end = start + len as usize;
    assert!(msg.len() >= end, "protobuf string overruns the message");
    String::from_utf8(msg[start..end].to_vec()).expect("utf8 greeting")
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

/// Encode one Connect/gRPC-web envelope frame: `flags`, a big-endian `u32` length, then `payload`.
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

/// Issue one Connect-unary `POST` to the RPC over a raw HTTP/1.1 client connection (`Connection:
/// close`, so the full response is read to EOF). Returns `(status, headers lowercased, body)`.
async fn connect_unary_call(
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

/// Parse a raw HTTP/1.1 response: status line + headers + decoded body (handling `chunked` transfer
/// encoding and `Content-Length`).
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

/// De-chunk a `Transfer-Encoding: chunked` body already fully in memory.
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: serves a real Connect-unary round trip over the hand-rolled HTTP stack on a \
            loopback socket; run via --include-ignored in the `live gate (connect-unary)` job"]
async fn connect_unary_round_trips_over_the_http_stack() {
    let app = live_app().await;
    let addr = spawn_server(app).await;

    // ---- 1. Bare Connect-unary (application/proto): one message in, one bare message out --------
    let (status, headers, body) = connect_unary_call(
        addr,
        "application/proto",
        &[],
        encode_string_msg("boatramp"),
    )
    .await;
    assert_eq!(
        status, 200,
        "bare Connect-unary should be 200 (headers: {headers:?})"
    );
    assert!(
        header(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/proto"),
        "bare unary response echoes application/proto; headers: {headers:?}"
    );
    assert_eq!(
        decode_string_msg(&body),
        "hello, boatramp!",
        "bare unary greeting round-trips the request name"
    );

    // ---- 2. gRPC-web unary WITH compression ON + Accept-Encoding: gzip (the host residual) ------
    let gw_req = encode_envelope(0, &encode_string_msg("grpcweb"));
    let (status, headers, body) = connect_unary_call(
        addr,
        "application/grpc-web+proto",
        &[("Accept-Encoding", "gzip")],
        gw_req,
    )
    .await;
    assert_eq!(
        status, 200,
        "gRPC-web unary head is always 200 (headers: {headers:?})"
    );
    assert!(
        header(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/grpc-web+proto"),
        "gRPC-web response echoes application/grpc-web+proto; headers: {headers:?}"
    );
    assert!(
        header(&headers, "content-encoding").is_none(),
        "HOST RESIDUAL (2f5aa2d0): a framed gRPC-web body must never be HTTP-compressed (it would \
         mangle the envelope framing), even with compression on + Accept-Encoding: gzip; \
         headers: {headers:?}"
    );
    let frames = decode_envelopes(&body);
    assert_eq!(
        frames.len(),
        2,
        "gRPC-web unary = one data frame + one trailers frame; got {} frame(s): {frames:?}",
        frames.len()
    );
    assert_eq!(
        frames[0].0, 0,
        "the first frame is a data frame (flags = 0)"
    );
    assert_eq!(
        decode_string_msg(&frames[0].1),
        "hello, grpcweb!",
        "the gRPC-web data frame decodes to the greeting (framing survived the real stack uncorrupted)"
    );
    assert_ne!(
        frames[1].0 & 0x80,
        0,
        "the second frame is a gRPC-web trailers frame (MSB flag 0x80)"
    );
    let trailers = String::from_utf8_lossy(&frames[1].1);
    assert!(
        trailers.contains("grpc-status: 0"),
        "the gRPC-web trailers frame carries grpc-status: 0 (a successful unary call); got: {trailers:?}"
    );

    // The marker the CI gate greps — reached only after BOTH unary shapes round-tripped over the
    // real hand-rolled HTTP stack and the framing survived the compression-negotiation path.
    println!("CONNECT UNARY LIVE OK");
}
