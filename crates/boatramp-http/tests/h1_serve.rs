//! The HTTP/1.1 connection serving loop (`h1::serve_connection`) — the connection-loop
//! gate: keep-alive, pipelining, request-body decode (Content-Length + chunked), response
//! framing (fixed + chunked), HEAD/no-body, Connection: close, 100-continue, malformed →
//! 400, and hyper-client interop. Framing is asserted on the raw wire bytes; interop is
//! asserted by driving the server with a real hyper client.

use boatramp_http::h1::serve_connection;
use boatramp_http::{Body, Handler, Request, Response, response};
use bytes::Bytes;
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
            ("POST", "/echo") => response(
                200,
                req.into_body().collect().await.unwrap_or_default().to_vec(),
            ),
            // Stream the request body straight back — the response streams chunk-by-chunk
            // as the request body arrives, WITHOUT buffering the whole thing.
            ("POST", "/echo-stream") => {
                response(200, Body::try_stream(req.into_body().into_data_stream()))
            }
            ("GET", "/stream") => {
                let chunks = tokio_stream::iter((0..3u8).map(|i| Bytes::from(vec![b'a' + i; 4])));
                response(200, Body::stream(chunks))
            }
            // A declared-length streaming body (12 bytes across three 4-byte chunks) →
            // Content-Length framing, not chunked.
            ("GET", "/stream-sized") => {
                let chunks = tokio_stream::iter((0..3u8).map(|i| Bytes::from(vec![b'a' + i; 4])));
                response(200, Body::stream_sized(12, chunks))
            }
            // Declares 12 bytes but the stream yields only 8 — the writer must truncate at
            // the committed length and force-close (never pad, never desync).
            ("GET", "/stream-sized-short") => {
                let chunks = tokio_stream::iter((0..2u8).map(|i| Bytes::from(vec![b'a' + i; 4])));
                response(200, Body::stream_sized(12, chunks))
            }
            // Declares 12 bytes but the stream yields 16 — the writer must write exactly 12
            // and force-close (the excess would be read as the next response).
            ("GET", "/stream-sized-long") => {
                let chunks = tokio_stream::iter((0..4u8).map(|i| Bytes::from(vec![b'a' + i; 4])));
                response(200, Body::stream_sized(12, chunks))
            }
            // Reject WITHOUT reading the body, closing the connection (an early 413 shape).
            ("POST", "/reject") => {
                let mut r = response(413, b"too large".to_vec());
                r.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                r
            }
            // Answer 200 keep-alive WITHOUT reading the body (the body must still be drained
            // so a pipelined next request stays framed).
            ("POST", "/ignore") => response(200, b"ok".to_vec()),
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
    assert!(
        !lower(&r).contains("transfer-encoding"),
        "GET must be CL-framed: {text}"
    );
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
    assert!(
        String::from_utf8_lossy(&r).ends_with("hello"),
        "echo failed: {:?}",
        lower(&r)
    );
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
    assert!(
        String::from_utf8_lossy(&r).ends_with("hello world"),
        "{:?}",
        lower(&r)
    );
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
    assert_eq!(
        body, "4\r\naaaa\r\n4\r\nbbbb\r\n4\r\ncccc\r\n0\r\n\r\n",
        "chunk framing: {body:?}"
    );
}

#[tokio::test]
async fn declared_length_stream_is_content_length_framed() {
    // U29: a streaming body WITH a declared length is Content-Length-framed (not chunked),
    // so a proxied known-length download keeps its length. (The plain streaming case staying
    // chunked is covered by `streamed_response_is_chunked_on_the_wire`.)
    let r = roundtrip_close(b"GET /stream-sized HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    let text = lower(&r);
    assert!(text.contains("content-length: 12\r\n"), "{text}");
    assert!(
        !text.contains("transfer-encoding"),
        "a declared-length stream must NOT be chunked: {text}"
    );
    // The body is the 12 raw bytes — no chunk-size lines.
    let body_start = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&r[body_start..], b"aaaabbbbcccc", "raw (unchunked) body");
}

#[tokio::test]
async fn declared_length_underrun_force_closes_even_on_keep_alive() {
    // U29 safety: a declared-length body that under-runs its Content-Length must force-close
    // the connection (the length is already committed on the wire and can't be fulfilled) —
    // never pad it, and never let the next pipelined request desync. A keep-alive request
    // (no `Connection: close`) is used so the force-close is the ONLY thing that can prevent
    // the pipelined second request from being answered.
    let mut c = spawn();
    c.write_all(
        b"GET /stream-sized-short HTTP/1.1\r\nHost: x\r\n\r\n\
          GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert_eq!(
        text.matches("HTTP/1.1 200 OK").count(),
        1,
        "the under-running body must force-close, not serve the pipelined request: {text}"
    );
    assert!(lower(&out).contains("content-length: 12\r\n"), "{text}");
    // Only the 8 bytes the source produced are on the wire — truncated, not padded.
    let body_start = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(
        &out[body_start..],
        b"aaaabbbb",
        "truncated body, not padded"
    );
}

#[tokio::test]
async fn declared_length_overrun_writes_exactly_len_and_force_closes_even_on_keep_alive() {
    // U29 safety (the over-run counterpart to the under-run test above): a declared-length
    // body that OVER-runs its Content-Length must write exactly `len` bytes and then
    // force-close — the committed length is already on the wire, so the excess bytes would be
    // read by the client as the start of the next response (a response-smuggling desync). A
    // keep-alive request (no `Connection: close`) is used so the force-close is the ONLY thing
    // that can stop the pipelined second request from being answered.
    let mut c = spawn();
    c.write_all(
        b"GET /stream-sized-long HTTP/1.1\r\nHost: x\r\n\r\n\
          GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert_eq!(
        text.matches("HTTP/1.1 200 OK").count(),
        1,
        "the over-running body must force-close, not serve the pipelined request: {text}"
    );
    assert!(lower(&out).contains("content-length: 12\r\n"), "{text}");
    // Exactly the committed 12 bytes are on the wire — the 13th..16th bytes are truncated,
    // never written, so they can't be read as the next response.
    let body_start = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(
        &out[body_start..],
        b"aaaabbbbcccc",
        "exactly `len` (12) bytes, the over-run excess dropped"
    );
}

#[tokio::test]
async fn streamed_body_error_truncates_without_a_clean_terminator() {
    // A source that fails mid-stream must NOT emit the terminating 0-chunk — the client
    // sees an incomplete chunked body (an error), never a clean end (silent truncation).
    let r =
        roundtrip_close(b"GET /stream-err HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    let text = lower(&r);
    assert!(text.contains("transfer-encoding: chunked\r\n"), "{text}");
    assert!(
        String::from_utf8_lossy(&r).contains("aaaa"),
        "first chunk should arrive: {text}"
    );
    assert!(
        !r.ends_with(b"0\r\n\r\n"),
        "a mid-stream error must not frame a clean end (silent truncation): {text}"
    );
}

#[tokio::test]
async fn request_body_streams_through_before_it_is_complete() {
    use tokio::time::{Duration, timeout};
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
    assert!(
        lower(&got).contains("transfer-encoding: chunked\r\n"),
        "{:?}",
        lower(&got)
    );

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
        let size =
            usize::from_str_radix(hex.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
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
async fn closing_response_does_not_drain_the_abandoned_request_body() {
    use tokio::time::{Duration, timeout};
    // Declare a large body but send only a little of it, then stop. The handler answers
    // 413 + Connection: close WITHOUT reading the body. The server must write the response
    // and close PROMPTLY — it must NOT sit reading the ~1 MB we never send (U28). A drain
    // would block on the stalled body until the 30 s read timeout, past this 3 s bound.
    let mut c = spawn();
    c.write_all(b"POST /reject HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\npartial")
        .await
        .unwrap();
    let mut out = Vec::new();
    timeout(Duration::from_secs(3), c.read_to_end(&mut out))
        .await
        .expect("server drained the abandoned body instead of closing after the 413")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 413"),
        "{:?}",
        lower(&out)
    );
}

#[tokio::test]
async fn keepalive_response_still_consumes_an_unread_body() {
    // The flip side of U28: on a keep-alive response the body MUST still be consumed in
    // full, so a pipelined next request is framed from the right offset. The first POST's
    // handler ignores the body (no read), yet the body must be drained so the pipelined
    // GET is parsed correctly rather than from the body bytes.
    let mut c = spawn();
    c.write_all(
        b"POST /ignore HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello\
          GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert_eq!(
        text.matches("HTTP/1.1 200 OK").count(),
        2,
        "both the /ignore response and the pipelined GET must be answered: {text}"
    );
    assert!(
        text.ends_with("hello"),
        "the pipelined GET must be framed after the drained body: {text}"
    );
}

#[tokio::test]
async fn malformed_request_gets_400_and_close() {
    // Space before the colon — a header the parser rejects.
    let r = roundtrip_close(b"GET / HTTP/1.1\r\nHost : x\r\n\r\n").await;
    assert!(
        String::from_utf8_lossy(&r).starts_with("HTTP/1.1 400"),
        "{:?}",
        lower(&r)
    );
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
    assert_eq!(
        text.matches("HTTP/1.1 200 OK").count(),
        3,
        "want 3 responses: {}",
        out.len()
    );
    // The middle one is the 100000-byte body; the last ends with "hello".
    assert!(lower(&out).contains("content-length: 100000\r\n"));
    assert!(text.ends_with("hello"));
}

#[tokio::test]
async fn expect_100_continue_gets_an_interim_response_before_the_body() {
    use tokio::time::{Duration, timeout};
    let mut c = spawn();
    // Send only the head (with Expect) — NOT the body yet.
    c.write_all(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    // The server must answer 100 Continue before we send the body.
    let mut interim = [0u8; 25];
    let n = timeout(Duration::from_secs(2), c.read(&mut interim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &interim[..n],
        b"HTTP/1.1 100 Continue\r\n\r\n",
        "expected interim 100: {:?}",
        &interim[..n]
    );
    // Now send the body and read the final response.
    c.write_all(b"hello").await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    assert!(
        String::from_utf8_lossy(&rest).ends_with("hello"),
        "{:?}",
        lower(&rest)
    );
}

#[tokio::test]
async fn hyper_client_interop_over_keep_alive() {
    use http_body_util::{BodyExt, Full};

    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_connection(server, App).await;
    });
    let io = hyper_util::rt::TokioIo::new(client);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Two requests on the same connection (keep-alive), via a real hyper client.
    for (path, expect) in [("/", "hello"), ("/echo?ignored=1", "")] {
        let req = hyper::Request::builder()
            .method(if path.starts_with("/echo") {
                "POST"
            } else {
                "GET"
            })
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
