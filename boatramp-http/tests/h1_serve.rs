//! The HTTP/1.1 connection serving loop (`h1::serve_connection`) — the connection-loop
//! gate: keep-alive, pipelining, request-body decode (Content-Length + chunked), response
//! framing (fixed + chunked), HEAD/no-body, Connection: close, 100-continue, malformed →
//! 400, and hyper-client interop. Framing is asserted on the raw wire bytes; interop is
//! asserted by driving the server with a real hyper client.

use bytes::Bytes;
use boatramp_http::h1::serve_connection;
use boatramp_http::{response, Body, Handler, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The test application: exercises every response shape the loop must frame.
struct App;
impl Handler for App {
    async fn handle(&self, req: Request) -> Response {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        match (method.as_str(), path.as_str()) {
            ("GET", "/") => response(200, b"hello".to_vec()),
            ("HEAD", "/") => response(200, b"hello".to_vec()), // loop suppresses the body
            ("GET", "/big") => response(200, vec![b'x'; 100_000]),
            ("POST", "/echo") => response(200, req.into_body().collect().await.unwrap_or_default().to_vec()),
            // Stream the request body straight back — the response streams chunk-by-chunk
            // as the request body arrives, WITHOUT buffering the whole thing.
            ("POST", "/echo-stream") => {
                response(200, Body::try_stream(req.into_body().into_data_stream()))
            }
            ("GET", "/stream") => {
                let chunks = tokio_stream::iter(
                    (0..3u8).map(|i| Bytes::from(vec![b'a' + i; 4])),
                );
                response(200, Body::stream(chunks))
            }
            ("GET", "/stream-err") => {
                // One good chunk, then a mid-stream source failure.
                let chunks = tokio_stream::iter(vec![
                    Ok(Bytes::from_static(b"aaaa")),
                    Err(boatramp_http::BodyError),
                ]);
                response(200, Body::try_stream(chunks))
            }
            _ => response(404, Vec::new()),
        }
    }
}

/// Spawn `serve_connection(App)` over an in-memory duplex; return the client half.
fn spawn() -> tokio::io::DuplexStream {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_connection(server, App).await;
    });
    client
}

/// Write `req` then read the whole response stream (the server closes the connection
/// because `req` carries `Connection: close`), returning the raw response bytes.
async fn roundtrip_close(req: &[u8]) -> Vec<u8> {
    let mut c = spawn();
    c.write_all(req).await.unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    out
}

fn lower(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_lowercase()
}

#[tokio::test]
async fn get_is_content_length_framed() {
    let r = roundtrip_close(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    let text = String::from_utf8_lossy(&r);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(lower(&r).contains("content-length: 5\r\n"), "{text}");
    assert!(text.ends_with("hello"), "{text}");
    assert!(!lower(&r).contains("transfer-encoding"), "GET must be CL-framed: {text}");
}

#[tokio::test]
async fn large_get_reports_its_length() {
    let r = roundtrip_close(b"GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(lower(&r).contains("content-length: 100000\r\n"));
    // The body is exactly 100000 bytes after the CRLFCRLF.
    let head_end = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(r.len() - head_end, 100_000);
}

#[tokio::test]
async fn head_sends_headers_but_no_body() {
    let r = roundtrip_close(b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    let text = String::from_utf8_lossy(&r);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    // The accurate Content-Length is present, but there is no body after the head.
    assert!(lower(&r).contains("content-length: 5\r\n"), "{text}");
    let head_end = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(r.len(), head_end, "HEAD must not send a body: {text}");
}

#[tokio::test]
async fn post_content_length_body_reaches_the_handler() {
    let r = roundtrip_close(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    assert!(String::from_utf8_lossy(&r).ends_with("hello"), "echo failed: {:?}", lower(&r));
    assert!(lower(&r).contains("content-length: 5\r\n"));
}

#[tokio::test]
async fn post_chunked_body_is_decoded_for_the_handler() {
    let r = roundtrip_close(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
          5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    // The handler echoes the DECODED body ("hello world"), buffered → Content-Length: 11.
    assert!(String::from_utf8_lossy(&r).ends_with("hello world"), "{:?}", lower(&r));
    assert!(lower(&r).contains("content-length: 11\r\n"));
}

#[tokio::test]
async fn streamed_response_is_chunked_on_the_wire() {
    let r = roundtrip_close(b"GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    let text = lower(&r);
    assert!(text.contains("transfer-encoding: chunked\r\n"), "{text}");
    // Three 4-byte chunks then the terminating 0-chunk.
    let body_start = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body = String::from_utf8_lossy(&r[body_start..]);
    assert_eq!(body, "4\r\naaaa\r\n4\r\nbbbb\r\n4\r\ncccc\r\n0\r\n\r\n", "chunk framing: {body:?}");
}

#[tokio::test]
async fn streamed_body_error_truncates_without_a_clean_terminator() {
    // A source that fails mid-stream must NOT emit the terminating 0-chunk — the client
    // sees an incomplete chunked body (an error), never a clean end (silent truncation).
    let r = roundtrip_close(b"GET /stream-err HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    let text = lower(&r);
    assert!(text.contains("transfer-encoding: chunked\r\n"), "{text}");
    assert!(String::from_utf8_lossy(&r).contains("aaaa"), "first chunk should arrive: {text}");
    assert!(
        !r.ends_with(b"0\r\n\r\n"),
        "a mid-stream error must not frame a clean end (silent truncation): {text}"
    );
}

#[tokio::test]
async fn request_body_streams_through_before_it_is_complete() {
    use tokio::time::{timeout, Duration};
    // Prove the request body is NOT buffered: with a chunked echo-stream, the first
    // request chunk must come back in the response *before* we send the rest of the body.
    let mut c = spawn();
    c.write_all(
        b"POST /echo-stream HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    // Send only the first data chunk (not the terminator).
    c.write_all(b"5\r\nhello\r\n").await.unwrap();

    // The response head + the first echoed chunk must arrive though the request body is
    // still open — impossible if the server buffered the whole body first.
    let mut got = Vec::new();
    let deadline = Duration::from_secs(2);
    loop {
        let mut tmp = [0u8; 512];
        let n = timeout(deadline, c.read(&mut tmp)).await.unwrap().unwrap();
        got.extend_from_slice(&tmp[..n]);
        if String::from_utf8_lossy(&got).contains("hello") {
            break; // first chunk streamed back before we sent the terminator
        }
    }
    assert!(lower(&got).contains("transfer-encoding: chunked\r\n"), "{:?}", lower(&got));

    // Now finish the request; the echo completes + closes.
    c.write_all(b"6\r\n world\r\n0\r\n\r\n").await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    got.extend_from_slice(&rest);
    // The full echoed payload ("hello world") appears across the streamed chunks.
    let body_start = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let decoded = decode_chunked(&got[body_start..]);
    assert_eq!(decoded, b"hello world");
}

/// Minimal chunked-decoder for the test side (collect a chunked response body).
fn decode_chunked(mut buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        let size_line = &buf[..nl];
        let hex: String = String::from_utf8_lossy(size_line).trim().to_string();
        let size = usize::from_str_radix(hex.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        buf = &buf[nl + 1..];
        if size == 0 {
            break;
        }
        out.extend_from_slice(&buf[..size]);
        buf = &buf[size + 2..]; // skip data + CRLF
    }
    out
}

#[tokio::test]
async fn malformed_request_gets_400_and_close() {
    // Space before the colon — a header the parser rejects.
    let r = roundtrip_close(b"GET / HTTP/1.1\r\nHost : x\r\n\r\n").await;
    assert!(String::from_utf8_lossy(&r).starts_with("HTTP/1.1 400"), "{:?}", lower(&r));
}

#[tokio::test]
async fn keep_alive_serves_multiple_requests_then_pipelined() {
    let mut c = spawn();
    // Two keep-alive requests, then a third that closes — all sent up front (pipelined).
    c.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n\
          GET /big HTTP/1.1\r\nHost: x\r\n\r\n\
          GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    // Exactly three responses, in order.
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 3, "want 3 responses: {}", out.len());
    // The middle one is the 100000-byte body; the last ends with "hello".
    assert!(lower(&out).contains("content-length: 100000\r\n"));
    assert!(text.ends_with("hello"));
}

#[tokio::test]
async fn expect_100_continue_gets_an_interim_response_before_the_body() {
    use tokio::time::{timeout, Duration};
    let mut c = spawn();
    // Send only the head (with Expect) — NOT the body yet.
    c.write_all(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    // The server must answer 100 Continue before we send the body.
    let mut interim = [0u8; 25];
    let n = timeout(Duration::from_secs(2), c.read(&mut interim)).await.unwrap().unwrap();
    assert_eq!(&interim[..n], b"HTTP/1.1 100 Continue\r\n\r\n", "expected interim 100: {:?}", &interim[..n]);
    // Now send the body and read the final response.
    c.write_all(b"hello").await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    assert!(String::from_utf8_lossy(&rest).ends_with("hello"), "{:?}", lower(&rest));
}

#[tokio::test]
async fn hyper_client_interop_over_keep_alive() {
    use http_body_util::{BodyExt, Full};

    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_connection(server, App).await;
    });
    let io = hyper_util::rt::TokioIo::new(client);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Two requests on the same connection (keep-alive), via a real hyper client.
    for (path, expect) in [("/", "hello"), ("/echo?ignored=1", "")] {
        let req = hyper::Request::builder()
            .method(if path.starts_with("/echo") { "POST" } else { "GET" })
            .uri(format!("http://x{path}"))
            .header("host", "x")
            .body(Full::new(Bytes::from_static(b"")))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        if !expect.is_empty() {
            assert_eq!(&body[..], expect.as_bytes());
        }
    }
}
