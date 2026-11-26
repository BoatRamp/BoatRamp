//! Regression gate for the h2 `Expect: 100-continue` deadlock (prod: git-lfs uploads over
//! HTTP/2 hung forever). boatramp advertises h2-first in ALPN, so git-lfs negotiates h2 and
//! sends its PUT `HEADERS` with `expect: 100-continue`, then WAITS for an interim `100`
//! before sending any DATA. The h2 serve layer never emitted that `100`, so a body-reading
//! handler (a reverse-proxy forward leg's `data.next()`) blocked on a body that never came:
//! 0 bytes forwarded upstream, no response, the client timing out and retrying forever.
//!
//! The fix emits a genuine interim `100` — a `:status 100` HEADERS with NO END_STREAM, so the
//! stream stays open for the real final response — **lazily, on the handler's first body
//! read**, matching Go's `net/http2` server (`requestBody.Read` → `write100ContinueHeaders`)
//! and a Go/Caddy reverse proxy, which terminates the 100-continue handshake at the server
//! leg rather than relaying an upstream `100`.
//!
//! These tests drive the REAL h2 serving stack (`serve_connection_mux` over a duplex) with the
//! reference `h2` client — NOT an in-process `oneshot`, which bypasses the writer (the same
//! reason `h2_head_framing.rs` uses a real client). The client observes the interim `100` via
//! `ResponseFuture::poll_informational`.
//!
//! Coverage:
//! - `expect_continue_interim_100_then_body_flows` — THE defect: a client that withholds its
//!   DATA until it sees the `100` gets the `100`, then the body flows to a `200`. Without the
//!   fix the handler blocks on the body read, no `100` is ever sent, and the client's wait
//!   for `100` times out (RED via the deadlock timeout).
//! - `expect_continue_but_client_sends_body_eagerly_still_completes` — a client that ignores
//!   the handshake and streams its DATA without waiting still completes (a late, harmless
//!   `100`; no double-send, no hang).
//! - `bodied_request_without_expect_is_unchanged` — the common bodied path (no `Expect`) still
//!   streams to the handler and completes, with no spurious interim response.

use std::time::Duration;

use boatramp_http::h2::{Handler, Request, Response, response, serve_connection_mux};
use bytes::Bytes;

/// The upload body the client PUTs once it is cleared to continue.
const BODY: &[u8] = b"git-lfs-object-bytes";
/// Bound every await so a regression surfaces as a bounded failure, never a hung test run.
const DEADLOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// A reverse-proxy-shaped backend: it READS the full request body (the forward leg streaming
/// the upload upstream) BEFORE producing any response. That first body read is exactly what
/// must trigger the interim `100`; a handler that responded without reading the body would
/// never exercise the handshake.
struct ReadsBody;

impl Handler for ReadsBody {
    async fn handle(&self, req: Request) -> Response {
        let body = req.into_body().collect().await.unwrap_or_default();
        // Echo the received length back so the test can assert the body actually arrived.
        response(200, body.to_vec())
    }
}

/// Stand up the real h2 writer (`serve_connection_mux`) over a duplex and return a reference
/// `h2` client speaking to it.
async fn connect() -> h2::client::SendRequest<Bytes> {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server_io, ReadsBody).await;
    });
    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request.ready().await.unwrap()
}

/// A PUT carrying `expect: 100-continue` — the git-lfs upload shape.
fn put_expect_continue() -> http::Request<()> {
    http::Request::builder()
        .method("PUT")
        .uri("https://registry.example/v2/test/blobs/upload")
        .header(http::header::EXPECT, "100-continue")
        .body(())
        .unwrap()
}

async fn read_body(mut body: h2::RecvStream) -> Vec<u8> {
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("response body must stream without a RST");
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    got
}

/// THE REGRESSION: a client that holds back its body until it sees the interim `100` must
/// receive that `100`, then its body must flow to a `200`. On main the handler blocks on the
/// body read, boatramp never sends the `100`, and the client's wait for it hangs — caught
/// here by `DEADLOCK_TIMEOUT` (RED). With the fix the `100` arrives on the handler's first
/// body read (GREEN).
#[tokio::test]
async fn expect_continue_interim_100_then_body_flows() {
    let mut client = connect().await;
    // `false`: a body follows — do NOT end the stream on the HEADERS. The client then
    // withholds its DATA, exactly as a `100-continue` client does.
    let (mut resp, mut send) = client.send_request(put_expect_continue(), false).unwrap();

    // Wait for the interim `100` WITHOUT sending any body first. Without the fix this never
    // arrives (the handler is blocked reading a body we are withholding), so the timeout fires
    // and the `expect` below panics — the deadlock, made load-bearing.
    let informational = tokio::time::timeout(
        DEADLOCK_TIMEOUT,
        std::future::poll_fn(|cx| resp.poll_informational(cx)),
    )
    .await
    .expect("DEADLOCK: no `100 Continue` arrived — the client's body-withholding wait hung")
    .expect("the informational stream ended before any `100 Continue`")
    .expect("receiving the interim response failed");
    assert_eq!(
        informational.status(),
        100,
        "the interim response must be `100 Continue`"
    );

    // Cleared to continue: send the whole body + END_STREAM.
    send.send_data(Bytes::from_static(BODY), true).unwrap();

    // The real final response must still work after the interim `100`.
    let resp = resp
        .await
        .expect("final response must arrive after the interim `100`");
    assert_eq!(resp.status(), 200, "the handler's final response is a 200");
    assert_eq!(
        read_body(resp.into_body()).await,
        BODY,
        "the full upload body must reach the handler"
    );
}

/// A client that does not honor the handshake and streams its DATA immediately (without
/// waiting for the `100`) must still complete: the codec sends a late — and harmless — `100`
/// (never a second one) and the handler reads the already-buffered body. No double-send, no
/// hang. Bounded by `DEADLOCK_TIMEOUT` so a hang fails rather than stalls the suite.
#[tokio::test]
async fn expect_continue_but_client_sends_body_eagerly_still_completes() {
    let mut client = connect().await;
    let (resp, mut send) = client.send_request(put_expect_continue(), false).unwrap();
    // Eager: do NOT wait for the `100`; send the body straight away.
    send.send_data(Bytes::from_static(BODY), true).unwrap();

    let resp = tokio::time::timeout(DEADLOCK_TIMEOUT, resp)
        .await
        .expect("an eager (non-waiting) client must not hang")
        .expect("final response must arrive");
    assert_eq!(resp.status(), 200);
    assert_eq!(read_body(resp.into_body()).await, BODY);
}

/// The common case — a bodied request WITHOUT `Expect` — is unchanged: the body still streams
/// to the handler and the request completes, with no spurious interim response injected.
#[tokio::test]
async fn bodied_request_without_expect_is_unchanged() {
    let mut client = connect().await;
    let request = http::Request::builder()
        .method("PUT")
        .uri("https://registry.example/v2/test/blobs/upload")
        .body(())
        .unwrap();
    let (resp, mut send) = client.send_request(request, false).unwrap();
    send.send_data(Bytes::from_static(BODY), true).unwrap();

    let resp = tokio::time::timeout(DEADLOCK_TIMEOUT, resp)
        .await
        .expect("a plain bodied request must not hang")
        .expect("final response must arrive");
    assert_eq!(resp.status(), 200);
    assert_eq!(read_body(resp.into_body()).await, BODY);
}
