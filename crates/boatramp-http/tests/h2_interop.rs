//! M3 interop battery: exercise the paths h2spec doesn't stress — multiplexed
//! concurrent streams, request bodies, and large responses that span many DATA
//! frames and force the flow-controlled resume loop (the client's default 64 KiB
//! window makes the server stall and resume on WINDOW_UPDATE). Driven by the
//! reference `h2` client, so the responses are validated against a real peer.

use boatramp_http::h2::{Handler, Request, Response, response, serve_connection};
use bytes::Bytes;

struct App;

impl Handler for App {
    async fn handle(&self, req: Request) -> Response {
        let path = req.uri().path().to_owned();
        match path.as_str() {
            "/big" => response(200, vec![b'x'; 100_000]),
            "/echo" => response(
                200,
                req.into_body().collect().await.unwrap_or_default().to_vec(),
            ),
            p => response(200, format!("{} {}", req.method(), p).into_bytes()),
        }
    }
}

async fn connect() -> h2::client::SendRequest<Bytes> {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection(server_io, App).await;
    });
    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request.ready().await.unwrap()
}

async fn read_body(mut body: h2::RecvStream) -> Vec<u8> {
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    got
}

#[tokio::test]
async fn multiplexed_concurrent_streams() {
    let mut client = connect().await;
    let mut pending = Vec::new();
    for i in 0..25 {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://x/s{i}"))
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        pending.push((i, response));
        client = client.ready().await.unwrap();
    }
    for (i, response) in pending {
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            read_body(response.into_body()).await,
            format!("GET /s{i}").into_bytes()
        );
    }
}

#[tokio::test]
async fn large_response_spans_frames_and_resumes_on_window_updates() {
    let mut client = connect().await;
    let request = http::Request::builder()
        .method("GET")
        .uri("https://x/big")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    // 100 KB > the 64 KiB initial window: the server must stall then resume as the
    // client releases capacity. Getting all 100 KB back proves the resume loop works.
    let body = read_body(response.into_body()).await;
    assert_eq!(body.len(), 100_000);
    assert!(body.iter().all(|&b| b == b'x'));
}

#[tokio::test]
async fn request_body_is_delivered_to_the_handler() {
    let mut client = connect().await;
    let request = http::Request::builder()
        .method("POST")
        .uri("https://x/echo")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(Bytes::from_static(b"hello body"), true)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(read_body(response.into_body()).await, b"hello body");
}

// --- regression: the serial driver must flush a buffering transport before it idles ----
//
// The serial `conn.rs` driver (public API `boatramp_http::h2::serve_connection`) has the
// same latent bug the mux writer did (fixed in `tests/h2_mux.rs` ::
// `buffering_transport_body_tail_is_flushed_before_the_writer_idles`): it writes a
// response with `wire.write_all`, which only writes what the transport's `poll_write`
// *accepts*. A userspace-TLS stream accepts the plaintext but, when the TCP socket is
// backpressured, leaves the matching encrypted records queued in its own buffer and
// returns anyway. The serial driver is single-task — its only await-the-next-request
// point is the frame-header `read_exact` at the top of its loop — so once it has written
// a response's frames it parks there with no further `poll_write`/`poll_flush` scheduled,
// and the queued tail of the response (for a completed response no later frame comes)
// sits unsent forever while the peer hangs waiting for bytes the server considers
// "written". A 0-RTT loopback never fills the socket, so this is invisible on plaintext.
//
// `FlushGatedIo` models exactly that transport: `poll_write` delivers the first `budget`
// bytes to the peer inline (the socket had room) and then *buffers* everything else,
// surfacing it only on `poll_flush`. With the driver's pre-idle `wire.flush()` reverted
// this hangs to the timeout (the body's tail sits in the buffer forever); with it, the
// flush drains the buffer and the body completes. This asserts end-to-end delivery (the
// full body reaches the client) — it never inspects the flush call itself.

/// A handler returning `size` identity (uncompressed) bytes as a `Body::Bytes` — the
/// serial driver buffers the whole body and frames it out through the transport.
struct FixedBody(usize);
impl Handler for FixedBody {
    async fn handle(&self, _req: Request) -> Response {
        response(200, vec![b'x'; self.0])
    }
}

/// A transport wrapper that behaves like a buffering writer under backpressure: the read
/// side passes through; the write side delivers the first `budget` bytes inline and
/// buffers the rest until `poll_flush`. (Mirror of the mux test's `FlushGatedIo`.)
struct FlushGatedIo<IO> {
    inner: IO,
    budget: usize,
    staged: Vec<u8>,
}

impl<IO: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for FlushGatedIo<IO> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FlushGatedIo<IO> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.budget >= buf.len() {
            // Room in the "socket": deliver inline (a partial write is fine, the caller loops).
            let n = std::task::ready!(std::pin::Pin::new(&mut this.inner).poll_write(cx, buf))?;
            this.budget -= n;
            std::task::Poll::Ready(Ok(n))
        } else {
            // "Socket" full: accept the plaintext but queue it (like rustls' encrypted buffer),
            // and stop delivering inline until a flush drains it.
            this.budget = 0;
            this.staged.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.staged.is_empty() {
            let n = std::task::ready!(
                std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.staged)
            )?;
            this.staged.drain(..n);
        }
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn buffering_transport_body_tail_is_flushed_before_the_serial_driver_idles() {
    const BODY: usize = 200 * 1024;
    // Deliver the handshake + first ~140 KiB inline, then buffer the rest (the "socket"
    // fills) — so a > 128 KiB response leaves a tail stranded in the transport buffer.
    const BUDGET: usize = 140 * 1024;

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let gated = FlushGatedIo {
        inner: server_io,
        budget: BUDGET,
        staged: Vec::new(),
    };
    tokio::spawn(async move {
        let _ = serve_connection(gated, FixedBody(BODY)).await;
    });
    // A comfortable window so flow control is never the limiter — this is purely about the
    // transport flush.
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(1 << 20)
        .initial_connection_window_size(1 << 20)
        .max_frame_size(1 << 20);
    let (send_request, connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = send_request.ready().await.unwrap();

    let request = http::Request::builder()
        .method("GET")
        .uri("https://x/big")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let fut = read_body(response.into_body());
    let body = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect(
            "response tail stranded in the transport buffer — serial driver idled without flushing",
        );
    assert_eq!(body.len(), BODY, "the full body must reach the peer");
    assert!(body.iter().all(|&b| b == b'x'));
}

// --- regression: an error-path connection GOAWAY must also reach a buffering peer --------
//
// The connection-error teardown helper `goaway()` (`conn.rs`) writes a GOAWAY and then
// tears the connection down. That GOAWAY goes out via `wire.write_all` just like a response,
// so on a backpressured userspace-TLS writer its encrypted records sit queued in the
// transport buffer — and without a flush/shutdown the peer sees only a bare FIN/RST and
// never the diagnostic GOAWAY or its error code. The fix mirrors the invalid-preface and
// peer-GOAWAY paths: `goaway()` shuts the write side down (which flushes) after writing.
//
// This drives the oversize-frame path (a connection FRAME_SIZE_ERROR: the size check fires
// before any payload is read, so a single oversized frame header triggers it) through a
// zero-budget `FlushGatedIo` — every server write is staged until a flush drains it, the
// worst case for a buffering writer — and asserts the GOAWAY, with its error code, is
// delivered. The driver's pre-idle `wire.flush()` still delivers the server SETTINGS at the
// top of the loop, so only the error GOAWAY depends on the teardown flush under test; with
// `goaway()`'s `wire.shutdown()` reverted this run ends after SETTINGS and the GOAWAY stays
// stranded in the buffer.
#[tokio::test]
async fn error_goaway_is_flushed_through_a_buffering_transport() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let gated = FlushGatedIo {
        inner: server_io,
        budget: 0,
        staged: Vec::new(),
    };
    tokio::spawn(async move {
        let _ = serve_connection(gated, App).await;
    });

    // Preface, then one oversize frame header: declared length 65_536 > the 16_384 default
    // max frame size. (type/flags/stream are irrelevant — the size check fires first.)
    client_io.write_all(PREFACE).await.unwrap();
    let oversize_header = [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
    client_io.write_all(&oversize_header).await.unwrap();

    // Read until the server closes; with the fix the GOAWAY is flushed on teardown.
    let mut got = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client_io.read_to_end(&mut got),
    )
    .await
    .expect("server never closed the connection")
    .unwrap();

    // Walk the frames and require a GOAWAY carrying FRAME_SIZE_ERROR (0x6).
    let mut i = 0;
    let mut goaway_code = None;
    while i + 9 <= got.len() {
        let len = u32::from_be_bytes([0, got[i], got[i + 1], got[i + 2]]) as usize;
        let kind = got[i + 3];
        let payload_end = (i + 9 + len).min(got.len());
        let payload = &got[i + 9..payload_end];
        if kind == 0x7 && payload.len() >= 8 {
            // GOAWAY payload: last-stream-id (4 bytes) then error code (4 bytes).
            goaway_code = Some(u32::from_be_bytes([
                payload[4], payload[5], payload[6], payload[7],
            ]));
        }
        i += 9 + len;
    }
    assert_eq!(
        goaway_code,
        Some(0x6),
        "error GOAWAY (FRAME_SIZE_ERROR) stranded in the transport buffer — teardown idled without flushing",
    );
}
