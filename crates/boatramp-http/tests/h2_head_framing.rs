//! Regression gate for the h2 HEAD-with-`Content-Length` framing bug: a `HEAD` response
//! that declares a `Content-Length` (the shape a reverse-proxied registry blob-`HEAD`
//! produces — the upstream relays `content-length: N` with no body) must be framed as
//! HEADERS (keeping that `content-length`) + END_STREAM and NO DATA. Before the fix the
//! h2 writer saw a declared-length body that yielded zero bytes, treated it as a
//! §8.1.2.6 UNDER-RUN, and `reset_local`'d the stream — RST_STREAM, dropping the already
//! queued HEADERS — so a real `HEAD /v2/.../blobs/<digest>` over HTTP/2 was reset instead
//! of completing.
//!
//! These tests drive the REAL h2 serving stack — the `serve_connection_mux` writer, over a
//! duplex, spoken to by the reference `h2` client (NOT an in-process tower `oneshot`, which
//! bypasses the writer and is exactly why this slipped through `conformance.rs`). The
//! handler reproduces the proxy's output shape: a `Body::StreamSized { len: N, .. }` whose
//! stream yields `N`/`M`/`0` bytes, with a `content-length: N` header — the same body
//! `RouterHandler::handle` frames from a proxied response that carried a `Content-Length`.
//!
//! Coverage:
//! - `head_with_content_length_completes_without_rst` — the real defect: a HEAD carries
//!   `content-length: N` + END_STREAM and NO RST, with zero DATA. FAILS on main (RST).
//! - `get_with_content_length_still_streams_body` — a GET on the same shape still streams
//!   all `N` bytes and keeps the `content-length` (the fix must not disturb the hot path).
//! - `get_under_run_still_resets` — the defensive §8.1.2.6 under-run RST is INTACT: a
//!   non-HEAD body that falls short of its declared length still resets the stream.

use boatramp_http::h2::{Body, BodyChunk, Handler, Request, Response, serve_connection_mux};
use bytes::Bytes;
use http::header::CONTENT_LENGTH;

/// The declared `Content-Length` the "upstream" reports for the blob (a HEAD relays it with
/// no body; a GET fills it).
const BLOB_LEN: usize = 4096;
/// A deliberately short body for the under-run case: fewer than `BLOB_LEN` bytes.
const SHORT_LEN: usize = 1024;

/// A registry-blob-shaped backend. Every response declares `content-length: BLOB_LEN` and a
/// `Body::StreamSized { len: BLOB_LEN, .. }` — mirroring `RouterHandler::handle`'s framing of
/// a proxied response that carried a `Content-Length` — but varies how many body bytes the
/// stream actually yields, keyed on method + path.
struct Blobs;

impl Handler for Blobs {
    async fn handle(&self, req: Request) -> Response {
        let is_head = req.method() == http::Method::HEAD;
        let path = req.uri().path().to_owned();

        // The bytes the stream yields: a HEAD relays zero (the upstream HEAD had no body); a
        // GET to the full blob yields all BLOB_LEN; the under-run path yields SHORT_LEN < N.
        let body_bytes = if is_head {
            0
        } else if path.ends_with("/under") {
            SHORT_LEN
        } else {
            BLOB_LEN
        };
        let chunk: Vec<BodyChunk> = if body_bytes == 0 {
            Vec::new()
        } else {
            vec![Ok(Bytes::from(vec![b'x'; body_bytes]))]
        };

        http::Response::builder()
            .status(200)
            // The declared length a reverse proxy relays from the upstream — KEPT on the wire
            // for every method (progress/range), suppressed as a body only for the HEAD.
            .header(CONTENT_LENGTH, BLOB_LEN)
            .body(Body::try_stream_sized(
                BLOB_LEN as u64,
                tokio_stream::iter(chunk),
            ))
            .unwrap()
    }
}

/// Stand up the real h2 writer (`serve_connection_mux`) over a duplex and return a reference
/// `h2` client speaking to it.
async fn connect() -> h2::client::SendRequest<Bytes> {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server_io, Blobs).await;
    });
    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request.ready().await.unwrap()
}

fn request(method: &str, path: &str) -> http::Request<()> {
    http::Request::builder()
        .method(method)
        .uri(format!("https://registry.example{path}"))
        .body(())
        .unwrap()
}

/// THE REGRESSION: a `HEAD` whose response declares `content-length: N` must complete as
/// HEADERS (with that `content-length`) + END_STREAM and NO DATA — never a RST. On main the
/// writer under-run-RST's this (the empty body is 0 < N), dropping the HEADERS, so a real
/// registry blob-HEAD over h2 is reset. The `.expect`s fire (RED) whichever way the
/// HEADERS/RST race lands on main; after the fix no reset occurs (GREEN).
#[tokio::test]
async fn head_with_content_length_completes_without_rst() {
    let mut client = connect().await;
    let (resp, _) = client
        .send_request(request("HEAD", "/v2/test/blobs/sha256:deadbeef"), true)
        .unwrap();

    let resp = resp
        .await
        .expect("HEAD must receive response HEADERS, not a RST_STREAM");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get(CONTENT_LENGTH)
            .expect("HEAD response must carry content-length"),
        &BLOB_LEN.to_string(),
        "the declared content-length must be relayed on a HEAD"
    );

    // The body stream must end cleanly (END_STREAM) with ZERO bytes — never an error (RST).
    let mut body = resp.into_body();
    let mut got = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("HEAD body must complete with END_STREAM, not a RST_STREAM");
        let _ = body.flow_control().release_capacity(chunk.len());
        got += chunk.len();
    }
    assert_eq!(got, 0, "a HEAD response must carry zero DATA bytes");
    assert!(
        body.is_end_stream(),
        "the HEAD stream must be closed by END_STREAM"
    );
}

/// The fix must not disturb the hot path: a GET on the same declared-length shape still
/// streams all `N` bytes and keeps the `content-length`. (Passes before and after the fix.)
#[tokio::test]
async fn get_with_content_length_still_streams_body() {
    let mut client = connect().await;
    let (resp, _) = client
        .send_request(request("GET", "/v2/test/blobs/sha256:deadbeef"), true)
        .unwrap();

    let resp = resp.await.expect("GET must receive response HEADERS");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get(CONTENT_LENGTH).unwrap(),
        &BLOB_LEN.to_string(),
        "a GET must keep the declared content-length"
    );

    let mut body = resp.into_body();
    let mut got = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("GET body must stream without a RST");
        let _ = body.flow_control().release_capacity(chunk.len());
        got += chunk.len();
    }
    assert_eq!(got, BLOB_LEN, "a GET must stream the full declared body");
}

/// The defensive §8.1.2.6 under-run RST must stay INTACT: a non-HEAD response whose body
/// yields fewer bytes than its declared `content-length` must still reset the stream — the
/// HEAD exemption must not weaken this. (A RST surfaces as an error either at the response
/// future or mid-body, depending on how the write race lands; either counts.)
#[tokio::test]
async fn get_under_run_still_resets() {
    let mut client = connect().await;
    let (resp, _) = client
        .send_request(request("GET", "/v2/test/blobs/under"), true)
        .unwrap();

    let reset = match resp.await {
        Err(_) => true,
        Ok(resp) => {
            assert_eq!(resp.status(), 200);
            let mut body = resp.into_body();
            let mut saw_error = false;
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(c) => {
                        let _ = body.flow_control().release_capacity(c.len());
                    }
                    Err(_) => {
                        saw_error = true;
                        break;
                    }
                }
            }
            saw_error
        }
    };
    assert!(
        reset,
        "a non-HEAD declared-length under-run must still RST the stream (defensive §8.1.2.6)"
    );
}
