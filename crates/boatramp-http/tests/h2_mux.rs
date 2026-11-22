//! M4c: the concurrent multiplexed driver (`serve_connection_mux`) must pass the
//! same functional battery as the serial driver — multiplexing, request bodies,
//! large flow-controlled responses — AND actually process streams concurrently
//! within one connection (the whole point). The `concurrent_streams_interleave`
//! test proves it: two requests whose handlers are interdependent complete only if
//! the driver keeps reading while a handler is parked — the serial driver would
//! deadlock. Driven by the reference `h2` client.

use std::sync::Arc;

use boatramp_http::h2::error::ErrorCode;
use boatramp_http::h2::frame::{self, FrameHeader, FrameType};
use boatramp_http::h2::hpack::Hpack;
use boatramp_http::h2::{
    CLIENT_PREFACE, Handler, Request, Response, response, serve_connection_mux,
};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, mpsc};

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
            // Forward the request body straight to the response, chunk by chunk, WITHOUT
            // buffering it — so a chunk echoes back as soon as the handler receives it.
            "/echo-stream" => response(
                200,
                boatramp_http::h2::Body::try_stream(req.into_body().into_data_stream()),
            ),
            p => response(200, format!("{} {}", req.method(), p).into_bytes()),
        }
    }
}

async fn connect_with<H: Handler>(handler: H) -> h2::client::SendRequest<Bytes> {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server_io, handler).await;
    });
    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request.ready().await.unwrap()
}

async fn connect() -> h2::client::SendRequest<Bytes> {
    connect_with(App).await
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

fn get(client: &mut h2::client::SendRequest<Bytes>, path: &str) -> h2::client::ResponseFuture {
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://x{path}"))
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    response
}

#[tokio::test]
async fn multiplexed_concurrent_streams() {
    let mut client = connect().await;
    let mut pending = Vec::new();
    for i in 0..25 {
        let response = get(&mut client, &format!("/s{i}"));
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
    let response = get(&mut client, "/big").await.unwrap();
    assert_eq!(response.status(), 200);
    // 100 KB > the 64 KiB initial window: the writer must stall then resume as the
    // client releases capacity.
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

/// U27: the request body must stream to the handler incrementally — the handler sees a
/// DATA chunk as soon as it arrives, NOT only after END_STREAM. Proven by echoing the
/// request body straight to the response: the first chunk comes back *before* the client
/// sends the rest of the body. With the old buffer-to-END_STREAM path the handler never
/// runs until the whole body is in, so the first echoed chunk could not arrive first.
#[tokio::test]
async fn request_body_streams_incrementally_to_the_handler() {
    use std::time::Duration;
    let mut client = connect().await;
    let request = http::Request::builder()
        .method("POST")
        .uri("https://x/echo-stream")
        .body(())
        .unwrap();
    // HEADERS without END_STREAM — the body follows in DATA frames.
    let (response, mut send) = client.send_request(request, false).unwrap();
    // Send ONLY the first chunk (not END_STREAM).
    send.send_data(Bytes::from_static(b"first-"), false)
        .unwrap();

    // The response head + the first echoed chunk must arrive while the request body is
    // still open — impossible if the server buffered the whole body first.
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response head must arrive before the body completes")
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), body.data())
        .await
        .expect("first echoed chunk must arrive before the request body is complete")
        .expect("a chunk")
        .unwrap();
    let _ = body.flow_control().release_capacity(first.len());
    assert_eq!(&first[..], b"first-");

    // Now finish the request; the rest echoes back and the stream ends.
    send.send_data(Bytes::from_static(b"second"), true).unwrap();
    let mut rest = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        rest.extend_from_slice(&chunk);
    }
    assert_eq!([&first[..], &rest[..]].concat(), b"first-second");
}

#[tokio::test]
async fn streamed_body_is_forwarded_chunk_by_chunk() {
    use boatramp_http::h2::Body;
    struct Streamer;
    impl Handler for Streamer {
        async fn handle(&self, _req: Request) -> Response {
            // 200 KiB across 200 chunks streamed over a bounded channel — bigger than
            // the 64 KiB flow-control window, so the writer must stream + resume on
            // WINDOW_UPDATE without ever holding the whole body. The channel is wrapped
            // as a pull `Stream` the driver polls directly.
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
            tokio::spawn(async move {
                for i in 0..200u32 {
                    let byte = b'a' + (i % 26) as u8;
                    if tx.send(Bytes::from(vec![byte; 1024])).await.is_err() {
                        break;
                    }
                }
            });
            response(
                200,
                Body::stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
            )
        }
    }
    let mut client = connect_with(Streamer).await;
    let response = get(&mut client, "/stream").await.unwrap();
    assert_eq!(response.status(), 200);
    let body = read_body(response.into_body()).await;
    assert_eq!(body.len(), 200 * 1024);
    // Spot-check the content survived the framing/streaming intact.
    assert!(body[..1024].iter().all(|&b| b == b'a'));
    assert!(body[1024..2048].iter().all(|&b| b == b'b'));
}

/// Backpressure: a client that opens a stream but never reads it (its flow-control
/// window stays closed) must NOT cause the driver to pull an unbounded streamed body
/// into memory. The driver must stop polling the source once its per-stream send
/// buffer fills, and resume only as the client releases capacity. Without
/// backpressure the driver drains all 10 000 chunks (10 MB) into the outbox.
#[tokio::test]
async fn slow_client_backpressures_a_large_streamed_body() {
    use boatramp_http::h2::Body;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_stream::StreamExt as _;

    struct Streamer(Arc<AtomicUsize>);
    impl Handler for Streamer {
        async fn handle(&self, _req: Request) -> Response {
            let pulled = self.0.clone();
            // 10 000 × 1 KiB = 10 MB, far larger than any window + backpressure bound.
            let src = tokio_stream::iter(0..10_000u32).map(move |_| {
                pulled.fetch_add(1, Ordering::SeqCst);
                Bytes::from(vec![b'y'; 1024])
            });
            response(200, Body::stream(src))
        }
    }

    let pulled = Arc::new(AtomicUsize::new(0));
    let mut client = connect_with(Streamer(pulled.clone())).await;
    let _response = get(&mut client, "/firehose").await.unwrap();
    assert_eq!(_response.status(), 200);
    // Do NOT read the body: the stream window stays closed. Give the handler task
    // ample time to drain the source if it's going to. `_response` is held so the
    // stream is not reset (backpressure, not cancellation, is what must stop it).
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let n = pulled.load(Ordering::SeqCst);
    assert!(
        n < 3000,
        "no backpressure: driver pulled {n}/10000 chunks into memory with a closed window"
    );
}

/// A client that resets a stream mid-body (here by abandoning it) must not wedge the
/// driver: a producer parked on backpressure is woken and stops, and the connection
/// keeps serving. Exercises the reset-while-a-producer-is-parked path.
#[tokio::test]
async fn client_reset_midstream_does_not_wedge_the_connection() {
    use boatramp_http::h2::Body;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio_stream::StreamExt as _;

    struct Mixed(Arc<AtomicUsize>);
    impl Handler for Mixed {
        async fn handle(&self, req: Request) -> Response {
            if req.uri().path() == "/ping" {
                return response(200, b"pong".to_vec());
            }
            let pulled = self.0.clone();
            let src = tokio_stream::iter(0..1_000_000u32).map(move |_| {
                pulled.fetch_add(1, Ordering::SeqCst);
                Bytes::from(vec![b'z'; 1024])
            });
            response(200, Body::stream(src))
        }
    }

    let pulled = Arc::new(AtomicUsize::new(0));
    let mut client = connect_with(Mixed(pulled.clone())).await;
    let resp = get(&mut client, "/stream").await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    // Read a few chunks (releasing capacity so the producer runs), then abandon the
    // stream → the client sends RST_STREAM, waking + stopping the producer.
    for _ in 0..5 {
        if let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
        }
    }
    drop(body);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let a = pulled.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let b = pulled.load(Ordering::SeqCst);
    assert!(
        b <= a + 2,
        "producer kept pulling after the client reset: {a} -> {b}"
    );

    // The connection is not wedged: a fresh request on it still round-trips.
    client = client.ready().await.unwrap();
    let ping = get(&mut client, "/ping").await.unwrap();
    assert_eq!(ping.status(), 200);
    assert_eq!(read_body(ping.into_body()).await, b"pong");
}

/// A streamed body whose source fails mid-stream must RST_STREAM the client, so a
/// truncated body is never framed as a clean end — which, with no `content-length`,
/// the client couldn't otherwise tell apart from success (silent corruption). The
/// error surfaces either as a failed response future (if it hits before HEADERS flush)
/// or as a reset partway through the body; both are "the client sees an error", which
/// is the property that matters. The source flushes two chunks first (realistic proxy
/// timing) so the common 200-then-reset path is exercised.
#[tokio::test]
async fn upstream_error_midstream_resets_the_client_not_a_clean_end() {
    use boatramp_http::h2::{Body, BodyChunk, BodyError};
    use std::time::Duration;

    struct Failing;
    impl Handler for Failing {
        async fn handle(&self, _req: Request) -> Response {
            let (tx, rx) = tokio::sync::mpsc::channel::<BodyChunk>(1);
            tokio::spawn(async move {
                let _ = tx.send(Ok(Bytes::from_static(b"aaaa"))).await;
                let _ = tx.send(Ok(Bytes::from_static(b"bbbb"))).await;
                // Let the writer flush HEADERS + the two DATA frames before failing.
                tokio::time::sleep(Duration::from_millis(30)).await;
                let _ = tx.send(Err(BodyError)).await;
            });
            response(
                200,
                Body::try_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
            )
        }
    }

    let mut client = connect_with(Failing).await;
    let mut saw_error = false;
    let mut got = Vec::new();
    match get(&mut client, "/dies").await {
        // Reset before HEADERS were delivered — the client still sees an error.
        Err(_) => saw_error = true,
        Ok(resp) => {
            assert_eq!(resp.status(), 200);
            let mut body = resp.into_body();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(c) => {
                        let _ = body.flow_control().release_capacity(c.len());
                        got.extend_from_slice(&c);
                    }
                    Err(_) => {
                        saw_error = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(
        saw_error,
        "mid-stream failure was framed as a clean end (silent truncation); got {} bytes",
        got.len()
    );
}

#[tokio::test]
async fn post_with_trailers_is_accepted() {
    let mut client = connect().await;
    let request = http::Request::builder()
        .method("POST")
        .uri("https://x/echo")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(Bytes::from_static(b"body"), false).unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-checksum", "abc".parse().unwrap());
    send.send_trailers(trailers).unwrap();
    // A trailers block (a second HEADERS after the body) must be accepted, not reset.
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(read_body(response.into_body()).await, b"body");
}

/// The concurrency proof. `/first`'s handler parks on a gate; `/second`'s handler
/// opens it. If the driver serialized streams (ran `/first`'s handler to completion
/// before reading `/second`), `/first` would park forever and this would time out.
/// It passes only because the reader keeps reading while `/first` is parked and
/// `/second` runs concurrently.
#[tokio::test]
async fn concurrent_streams_interleave() {
    struct Gated {
        gate: Arc<Notify>,
    }
    impl Handler for Gated {
        async fn handle(&self, req: Request) -> Response {
            match req.uri().path() {
                "/first" => {
                    self.gate.notified().await;
                    response(200, b"first".to_vec())
                }
                "/second" => {
                    self.gate.notify_one();
                    response(200, b"second".to_vec())
                }
                _ => response(404, Vec::new()),
            }
        }
    }

    let handler = Gated {
        gate: Arc::new(Notify::new()),
    };
    let mut client = connect_with(handler).await;
    let r1 = get(&mut client, "/first");
    client = client.ready().await.unwrap();
    let r2 = get(&mut client, "/second");

    let run = async {
        let resp1 = r1.await.unwrap();
        let resp2 = r2.await.unwrap();
        assert_eq!(resp1.status(), 200);
        assert_eq!(resp2.status(), 200);
        assert_eq!(read_body(resp1.into_body()).await, b"first");
        assert_eq!(read_body(resp2.into_body()).await, b"second");
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("interdependent streams must interleave — serial driver would deadlock");
}

/// The driver's initial SETTINGS advertises `SETTINGS_MAX_CONCURRENT_STREAMS = 256`
/// (§5.1.2) — the concurrency cap it also enforces (h2spec exercises the refusal;
/// this pins the advertisement so it can't silently drop back to "unlimited"). Read
/// as raw frames so it tests the wire bytes, not a client's interpretation.
#[tokio::test]
async fn advertises_max_concurrent_streams_setting() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server, App).await;
    });
    // Client connection preface — the server sends its SETTINGS in response.
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();

    // The server's first frame MUST be SETTINGS (type 0x4, stream 0).
    let mut hdr = [0u8; 9];
    client.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
    assert_eq!(hdr[3], 0x4, "first server frame is SETTINGS");
    assert_eq!(len % 6, 0, "SETTINGS length is a multiple of 6");
    let mut payload = vec![0u8; len];
    client.read_exact(&mut payload).await.unwrap();

    // Find SETTINGS_MAX_CONCURRENT_STREAMS (identifier 0x3).
    let max = payload.chunks(6).find_map(|e| {
        (u16::from_be_bytes([e[0], e[1]]) == 0x3)
            .then(|| u32::from_be_bytes([e[2], e[3], e[4], e[5]]))
    });
    assert_eq!(
        max,
        Some(256),
        "must advertise SETTINGS_MAX_CONCURRENT_STREAMS=256"
    );
}

// --- regression: >128 KiB single-chunk body must complete with END_STREAM ----------
//
// boatramp-requests #32: a static text asset > 128 KiB (served, in production, as a
// `Body::Stream` whose single item is the whole file — the http_serve bridge wraps every
// body as a one-item stream) stalled over HTTP/2 and never completed. The streamed-body
// path ends a response with a *separate zero-length END_STREAM DATA frame*. That frame is
// exempt from flow control (RFC 7540 §6.9.1) and the writer emits it regardless of the
// window — but the mux used to re-queue a stream for the writer only while its send window
// was open, so when the body's final bytes left the window at exactly 0 the END_STREAM
// marker was stranded in the outbox, the stream dropped out of the ready queue, and nothing
// ever re-drove it. The peer received the whole body but hung forever waiting for
// END_STREAM. The fix re-queues a stream whenever its next frame can make progress —
// including a zero-length (flow-control-exempt) END_STREAM frame — not only when the window
// is open.

/// Connect with an `h2` client configured with explicit flow-control windows and max
/// frame size, so a test can pin the exact window the server sees.
async fn connect_tuned<H: Handler>(
    handler: H,
    stream_window: u32,
    conn_window: u32,
    max_frame: u32,
) -> h2::client::SendRequest<Bytes> {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server_io, handler).await;
    });
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(stream_window)
        .initial_connection_window_size(conn_window)
        .max_frame_size(max_frame);
    let (send_request, connection) = builder.handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request.ready().await.unwrap()
}

/// A handler that returns `size` bytes as a `Body::Stream` whose single item is the whole
/// body (the production shape for a cached/mmapped static file), with a matching
/// `content-length` — so the mux appends a trailing zero-length END_STREAM frame.
struct SingleChunkStream(usize);
impl Handler for SingleChunkStream {
    async fn handle(&self, _req: Request) -> Response {
        let n = self.0;
        let src = tokio_stream::iter(std::iter::once(Bytes::from(vec![b'x'; n])));
        let mut r = response(200, boatramp_http::h2::Body::stream(src));
        r.headers_mut()
            .insert("content-length", n.to_string().parse().unwrap());
        r
    }
}

/// Reproduce-first (#32): a single body chunk larger than `MAX_OUT_FRAME` (128 KiB) must
/// be delivered in full *and* the stream closed with END_STREAM, even when the peer's
/// stream window is exactly consumed by the body (so the trailing END_STREAM marker lands
/// on a closed window).
///
/// The client grants a stream window EXACTLY equal to the body and never replenishes it
/// (the body is read but capacity is never released, so no stream WINDOW_UPDATE is sent).
/// A large connection window + max-frame make the server emit 128 KiB DATA frames and run
/// the stream window to 0 on the body's final byte — the exact condition that stranded the
/// END_STREAM frame. The body stream must END (not hang): with the re-queue fix reverted,
/// `data()` returns the whole 200 KiB and then blocks forever, tripping the timeout.
#[tokio::test]
async fn large_single_chunk_body_completes_with_end_stream() {
    const BODY: usize = 200 * 1024; // > MAX_OUT_FRAME (128 KiB)
    let mut client = connect_tuned(SingleChunkStream(BODY), BODY as u32, 1 << 20, 1 << 20).await;
    let response = get(&mut client, "/big").await.unwrap();
    assert_eq!(response.status(), 200);
    // Read the whole body WITHOUT releasing the stream window (no WINDOW_UPDATE), then
    // require the stream to END — i.e. END_STREAM must arrive on its own.
    let fut = async {
        let mut body = response.into_body();
        let mut got = 0usize;
        while let Some(chunk) = body.data().await {
            got += chunk.unwrap().len();
        }
        got
    };
    let got = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("END_STREAM never arrived: the >128 KiB single-chunk body stalled (#32)");
    assert_eq!(got, BODY, "the full >128 KiB body must be delivered");
}

/// Fairness: two concurrent >128 KiB single-chunk bodies, each with its stream window
/// exactly consumed by its body, must BOTH complete with END_STREAM — no starvation and
/// no deadlock when both streams need the flow-control-exempt END_STREAM re-queue.
#[tokio::test]
async fn two_large_single_chunk_bodies_both_complete() {
    const BODY: usize = 200 * 1024;
    // Shared connection window comfortably covers both bodies; each stream window is
    // exactly its body size and never replenished.
    let mut client = connect_tuned(SingleChunkStream(BODY), BODY as u32, 1 << 20, 1 << 20).await;
    let r1 = get(&mut client, "/a");
    client = client.ready().await.unwrap();
    let r2 = get(&mut client, "/b");

    let read_full = |resp: h2::client::ResponseFuture| async move {
        let response = resp.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut got = 0usize;
        while let Some(chunk) = body.data().await {
            got += chunk.unwrap().len();
        }
        got
    };

    let run = async move { tokio::join!(read_full(r1), read_full(r2)) };
    let (n1, n2) = tokio::time::timeout(std::time::Duration::from_secs(10), run)
        .await
        .expect("one of two concurrent >128 KiB single-chunk bodies stalled (#32)");
    assert_eq!((n1, n2), (BODY, BODY));
}

/// A >128 KiB single-chunk body under a *small* initial stream window must still stream
/// fully and end with END_STREAM: the body stalls and resumes across WINDOW_UPDATE frames
/// (the flow-controlled DATA path is unchanged), and the trailing END_STREAM marker is sent
/// once the body is drained. Here the client releases capacity, so those updates flow.
#[tokio::test]
async fn large_single_chunk_body_resumes_on_window_updates() {
    const BODY: usize = 200 * 1024;
    // Default-ish 64 KiB windows << body, so the server must stall and resume repeatedly.
    let mut client = connect_tuned(SingleChunkStream(BODY), 65_535, 65_535, 16_384).await;
    let response = get(&mut client, "/big").await.unwrap();
    assert_eq!(response.status(), 200);
    let fut = read_body(response.into_body());
    let body = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("windowed >128 KiB single-chunk body did not resume to completion");
    assert_eq!(body.len(), BODY);
    assert!(body.iter().all(|&b| b == b'x'));
}

/// Reproduce-first guard for the shape boatramp-requests #32 was reported to *still* stall on
/// (the identity-encoding static-serve path): a single-chunk streamed body LARGER than the
/// window, so a NON-EMPTY DATA remainder follows the first `MAX_OUT_FRAME` — and the window is
/// replenished *exactly* enough to finish the body, leaving the trailing zero-length END_STREAM
/// marker on a **closed** window. The original #32 tests only closed the window with the whole
/// body (no remainder) or replenished it generously (the END_STREAM marker kept an open window),
/// so neither exercised a non-empty remainder whose final bytes re-close the window onto the
/// END_STREAM marker.
///
/// The peer grants a stream window of exactly `MAX_OUT_FRAME` and a large connection window (so
/// the first DATA frame is a full 128 KiB and a 38 903-byte remainder is left), then — holding
/// capacity through that first window — releases EXACTLY the remainder in one WINDOW_UPDATE. The
/// body's final bytes drive the stream window back to 0, so the END_STREAM marker again lands on a
/// closed window, now behind a non-empty remainder that itself had to be re-driven by the
/// WINDOW_UPDATE. With the `build_batch` zero-length re-queue reverted this hangs to the timeout
/// (the END_STREAM marker is stranded and the stream never completes); with it, the body + the
/// END_STREAM marker are delivered in full.
#[tokio::test]
async fn large_body_nonempty_remainder_closes_window_on_end_stream() {
    const BODY: usize = 169_975; // 128 KiB first frame + a 38 903-byte non-empty remainder
    const WINDOW: u32 = 128 * 1024; // == MAX_OUT_FRAME: the first DATA frame consumes it whole
    // Large connection window + max-frame: the stream window is the sole limiter, and the first
    // DATA frame is a full MAX_OUT_FRAME so a *non-empty* remainder follows it.
    let mut client = connect_tuned(SingleChunkStream(BODY), WINDOW, 1 << 20, 1 << 20).await;
    let response = get(&mut client, "/big").await.unwrap();
    assert_eq!(response.status(), 200);
    let fut = async {
        let mut body = response.into_body();
        let mut got = 0usize;
        let mut released = false;
        while let Some(chunk) = body.data().await {
            got += chunk.unwrap().len();
            // Hold capacity through the whole first window, then grant EXACTLY the remainder:
            // the body's last bytes re-close the stream window at 0, stranding the trailing
            // END_STREAM marker there unless the writer re-queues a flow-control-exempt frame.
            if !released && got >= WINDOW as usize {
                let _ = body.flow_control().release_capacity(BODY - WINDOW as usize);
                released = true;
            }
        }
        got
    };
    let got = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("END_STREAM stranded on a closed window after a non-empty remainder (#32 shape)");
    assert_eq!(got, BODY, "the full >128 KiB body must be delivered");
}

// --- regression: the writer must flush a buffering transport before it idles ----------
//
// boatramp-requests #32 (real-RTT reproduction): a > 128 KiB identity asset over h2-*over-TLS*
// stalled part-way (at a variable byte count — 98 KiB, 128 KiB, …) only on a real / rate-limited
// / lossy path, never on a 0-RTT loopback. Root cause: `write_all_vectored` only writes what the
// transport's `poll_write` *accepts*. Userspace rustls accepts the plaintext but, when the TCP
// socket is backpressured, leaves the matching encrypted records queued in its own buffer and
// returns anyway; once the mux had drained the outbox it parked on `notify` with no further
// `poll_write`/`poll_flush` scheduled, so the queued tail of the response never reached the peer
// and the client hung waiting for bytes the server considered "written". A 0-RTT loopback never
// fills the socket, so the records always flushed inline and the bug was invisible there.
//
// `FlushGatedIo` models exactly that transport: `poll_write` delivers the first `budget` bytes
// to the peer inline (the socket had room) and then *buffers* everything else, surfacing it only
// on `poll_flush`. With the writer's pre-park flush reverted this hangs to the timeout (the body's
// tail sits in the buffer forever); with it, the flush drains the buffer and the body completes.

/// A transport wrapper that behaves like a buffering writer under backpressure: the read side
/// passes through; the write side delivers the first `budget` bytes inline and buffers the rest
/// until `poll_flush`.
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
async fn buffering_transport_body_tail_is_flushed_before_the_writer_idles() {
    const BODY: usize = 200 * 1024;
    // Deliver the handshake + first ~140 KiB inline, then buffer the rest (the "socket" fills) —
    // so a > 128 KiB response leaves a tail stranded in the transport buffer.
    const BUDGET: usize = 140 * 1024;

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let gated = FlushGatedIo {
        inner: server_io,
        budget: BUDGET,
        staged: Vec::new(),
    };
    tokio::spawn(async move {
        let _ = serve_connection_mux(gated, SingleChunkStream(BODY)).await;
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

    let response = get(&mut client, "/big").await.unwrap();
    assert_eq!(response.status(), 200);
    let fut = read_body(response.into_body());
    let body = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("response tail stranded in the transport buffer — writer idled without flushing");
    assert_eq!(body.len(), BODY, "the full body must reach the peer");
    assert!(body.iter().all(|&b| b == b'x'));
}

// ============================================================================
// Request-body RECEIVE flow control (the HIGH): a fast uploader must be backpressured
// into a slow/non-draining handler instead of buffering without bound in our process. The
// fix bounds the per-stream body channel AND gates the stream-level WINDOW_UPDATE on the
// handler *consuming* a chunk, so the peer's stream window closes when the handler stalls.
// ============================================================================

/// Constraint: a legitimate large upload (far bigger than the 64 KiB initial stream window)
/// to a *consuming* handler must complete, NOT deadlock. Consume-gated replenishment means
/// the window only reopens as the handler drains the body — so this round-trips only because
/// the handler draining the request keeps reopening the window. (`/echo` collects the whole
/// body and echoes it, so both the inbound window reopening and the response path are
/// exercised.)
#[tokio::test]
async fn large_upload_to_a_consuming_handler_round_trips() {
    let mut client = connect().await; // App: `/echo` collects + echoes the body
    let body = vec![b'q'; 256 * 1024]; // 256 KiB >> the 65 535-byte initial stream window
    let req = http::Request::builder()
        .method("POST")
        .uri("https://x/echo")
        .body(())
        .unwrap();
    let (resp_fut, mut send) = client.send_request(req, false).unwrap();
    send.send_data(Bytes::from(body.clone()), true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), resp_fut)
        .await
        .expect("a large upload to a draining handler must not deadlock")
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got = read_body(resp.into_body()).await;
    assert_eq!(
        got.len(),
        body.len(),
        "the whole upload must reach the handler"
    );
    assert_eq!(got, body, "the echoed body must match the upload");
}

// ---- raw-frame helpers (a conforming h2 client won't withhold reads or malform a body, so
// ---- these drive the frames directly — mirroring tests/h2_hardening.rs) ---------------

const F_END_STREAM: u8 = 0x1;
const F_END_HEADERS: u8 = 0x4;

/// Spawn the mux over an in-memory duplex with `handler`; return the client half.
fn raw_client<H: Handler>(handler: H) -> DuplexStream {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server, handler).await;
    });
    client
}

/// Client preface + an (empty) client SETTINGS frame.
async fn send_preface(c: &mut DuplexStream) {
    c.write_all(CLIENT_PREFACE).await.unwrap();
    let mut settings = Vec::new();
    frame::write_frame(&mut settings, FrameType::Settings, 0, 0, &[]);
    c.write_all(&settings).await.unwrap();
}

/// A `POST path` HPACK header block, optionally carrying a `content-length`.
fn post_block(path: &str, content_length: Option<u64>) -> Vec<u8> {
    let cl = content_length.map(|n| n.to_string());
    let mut fields: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":path", path.as_bytes()),
        (b":authority", b"x"),
    ];
    if let Some(cl) = cl.as_deref() {
        fields.push((b"content-length", cl.as_bytes()));
    }
    Hpack::new().encode(&fields)
}

/// Read one whole frame (header + payload), or `None` on EOF/error.
async fn read_frame(c: &mut DuplexStream) -> Option<(FrameHeader, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    c.read_exact(&mut hdr).await.ok()?;
    let h = FrameHeader::parse(&hdr);
    let mut payload = vec![0u8; h.length as usize];
    if h.length > 0 {
        c.read_exact(&mut payload).await.ok()?;
    }
    Some((h, payload))
}

/// Tally `(connection-level, stream-level)` WINDOW_UPDATE frames the server sends for `sid`
/// over `dur` (the connection never closes on its own, so it is bounded by the timeout).
async fn count_window_updates(
    c: &mut DuplexStream,
    sid: u32,
    dur: std::time::Duration,
) -> (u32, u32) {
    let mut conn = 0u32;
    let mut stream = 0u32;
    let _ = tokio::time::timeout(dur, async {
        while let Some((h, _)) = read_frame(c).await {
            if h.kind == FrameType::WindowUpdate {
                if h.stream_id == 0 {
                    conn += 1;
                } else if h.stream_id == sid {
                    stream += 1;
                }
            }
        }
    })
    .await;
    (conn, stream)
}

/// Scan server frames up to `dur` for a `RST_STREAM` on `sid`, returning its error code.
async fn wait_for_rst(
    c: &mut DuplexStream,
    sid: u32,
    dur: std::time::Duration,
) -> Option<ErrorCode> {
    tokio::time::timeout(dur, async {
        while let Some((h, payload)) = read_frame(c).await {
            if h.kind == FrameType::RstStream && h.stream_id == sid {
                return frame::parse_rst_stream(&payload).ok();
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// A handler that reads its whole request body and reports the outcome over a channel:
/// `Ok(n)` for a clean end after `n` bytes, `Err(())` if the body source surfaced a
/// `BodyError` (truncation / malformed framing). Lets a test assert the handler sees an
/// error, never a clean (truncated / over-run) body.
#[derive(Clone)]
struct BodyProbe(mpsc::UnboundedSender<Result<usize, ()>>);
impl Handler for BodyProbe {
    async fn handle(&self, req: Request) -> Response {
        use tokio_stream::StreamExt as _;
        let mut body = req.into_body().into_data_stream();
        let mut n = 0usize;
        let report = loop {
            match body.next().await {
                Some(Ok(chunk)) => n += chunk.len(),
                Some(Err(_)) => break Err(()),
                None => break Ok(n),
            }
        };
        let _ = self.0.send(report);
        response(200, b"ok".to_vec())
    }
}

/// A handler that never reads its request body and never drops it (parks forever) — so the
/// ONLY thing that can throttle an uploader is the withheld stream WINDOW_UPDATE.
struct NeverReads;
impl Handler for NeverReads {
    async fn handle(&self, _req: Request) -> Response {
        std::future::pending::<()>().await;
        unreachable!()
    }
}

/// A handler that drains its whole request body (consuming every chunk).
struct DrainAll;
impl Handler for DrainAll {
    async fn handle(&self, req: Request) -> Response {
        let _ = req.into_body().collect().await;
        response(200, b"ok".to_vec())
    }
}

/// Backpressure proof: a handler that never drains its body must NOT get a stream-level
/// WINDOW_UPDATE. The reader still replenishes the *connection* window eagerly (so a slow
/// stream never head-of-line blocks its siblings), but the per-stream window stays closed —
/// so a conforming uploader can send at most one initial window (64 KiB) before it is
/// throttled at the protocol level, bounding what we buffer. (With the old eager-per-DATA
/// replenishment the stream window reopened on every frame and nothing throttled the upload.)
#[tokio::test]
async fn non_draining_handler_withholds_the_stream_window_update() {
    let mut c = raw_client(NeverReads);
    send_preface(&mut c).await;
    let block = post_block("/sink", None);
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, FrameType::Headers, F_END_HEADERS, 1, &block); // no END_STREAM
    // Three small DATA frames (fit the 4-deep body channel, so the reader does not even
    // need to park): the handler consumes none of them.
    for _ in 0..3 {
        frame::write_frame(&mut buf, FrameType::Data, 0, 1, &[b'z'; 256]);
    }
    c.write_all(&buf).await.unwrap();

    let (conn, stream) =
        count_window_updates(&mut c, 1, std::time::Duration::from_millis(300)).await;
    assert!(
        conn >= 1,
        "the connection window must still be replenished eagerly (got {conn})"
    );
    assert_eq!(
        stream, 0,
        "a non-draining handler must get NO stream WINDOW_UPDATE — the window stays closed so \
         the uploader is backpressured (got {stream})"
    );
}

/// The complement: a handler that DOES drain its body gets stream-level WINDOW_UPDATE frames —
/// the window reopens as it consumes, so a legitimate upload is never deadlocked by the gate.
#[tokio::test]
async fn draining_handler_reopens_the_stream_window() {
    let mut c = raw_client(DrainAll);
    send_preface(&mut c).await;
    let block = post_block("/drain", None);
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, FrameType::Headers, F_END_HEADERS, 1, &block); // no END_STREAM
    for _ in 0..3 {
        frame::write_frame(&mut buf, FrameType::Data, 0, 1, &[b'z'; 256]);
    }
    c.write_all(&buf).await.unwrap();

    let (_conn, stream) =
        count_window_updates(&mut c, 1, std::time::Duration::from_millis(300)).await;
    assert!(
        stream >= 1,
        "a draining handler must get stream WINDOW_UPDATE frames as it consumes (consume-driven \
         replenishment) — else a large upload would deadlock (got {stream})"
    );
}

/// Smuggling (a): a stream RST mid-body must surface to the handler as an ERROR, never a
/// clean (truncated) end that a reverse-proxy handler would forward upstream as complete.
#[tokio::test]
async fn reset_midbody_surfaces_an_error_to_the_handler() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut c = raw_client(BodyProbe(tx));
    send_preface(&mut c).await;
    let block = post_block("/probe", None);
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, FrameType::Headers, F_END_HEADERS, 1, &block); // no END_STREAM
    frame::write_frame(&mut buf, FrameType::Data, 0, 1, b"partial-body"); // no END_STREAM
    buf.extend_from_slice(&frame::rst_stream(1, ErrorCode::Cancel));
    c.write_all(&buf).await.unwrap();

    let report = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the handler must observe the body ending")
        .expect("the probe must report");
    assert_eq!(
        report,
        Err(()),
        "a mid-body RST must surface as a BodyError, never a clean short read"
    );
}

/// Smuggling (b): DATA exceeding the declared `content-length` (§8.1.2.6) must reset the
/// stream AND surface an error to the handler — never a clean body.
#[tokio::test]
async fn data_over_content_length_errors_and_resets() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut c = raw_client(BodyProbe(tx));
    send_preface(&mut c).await;
    let block = post_block("/probe", Some(4)); // declares 4 bytes
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, FrameType::Headers, F_END_HEADERS, 1, &block); // no END_STREAM
    frame::write_frame(&mut buf, FrameType::Data, 0, 1, b"six666"); // 6 > 4 — over-run
    c.write_all(&buf).await.unwrap();

    let report = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the handler must observe the body ending")
        .expect("the probe must report");
    assert_eq!(
        report,
        Err(()),
        "an over-declared-length body must surface as a BodyError, never a clean body"
    );
    let code = wait_for_rst(&mut c, 1, std::time::Duration::from_secs(5)).await;
    assert_eq!(
        code,
        Some(ErrorCode::ProtocolError),
        "the over-run stream must be RST_STREAM(PROTOCOL_ERROR)"
    );
}

/// Smuggling (c): END_STREAM UNDER the declared `content-length` (§8.1.2.6) must reset the
/// stream AND surface an error to the handler — never a clean (short) body.
#[tokio::test]
async fn end_stream_under_content_length_errors_and_resets() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut c = raw_client(BodyProbe(tx));
    send_preface(&mut c).await;
    let block = post_block("/probe", Some(10)); // declares 10 bytes
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, FrameType::Headers, F_END_HEADERS, 1, &block); // no END_STREAM
    frame::write_frame(&mut buf, FrameType::Data, F_END_STREAM, 1, b"four"); // 4 < 10 + END_STREAM
    c.write_all(&buf).await.unwrap();

    let report = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the handler must observe the body ending")
        .expect("the probe must report");
    assert_eq!(
        report,
        Err(()),
        "an under-declared-length body must surface as a BodyError, never a clean short read"
    );
    let code = wait_for_rst(&mut c, 1, std::time::Duration::from_secs(5)).await;
    assert_eq!(
        code,
        Some(ErrorCode::ProtocolError),
        "the under-run stream must be RST_STREAM(PROTOCOL_ERROR)"
    );
}

/// A handler returning a declared-length (`StreamSized`) response whose body deliberately
/// MISMATCHES the committed `content-length`: it produces `produce` bytes but declares
/// `declared`.
struct SizedMismatch {
    declared: u64,
    produce: usize,
}
impl Handler for SizedMismatch {
    async fn handle(&self, _req: Request) -> Response {
        let body = Bytes::from(vec![b'x'; self.produce]);
        let chunks = tokio_stream::iter(std::iter::once(body));
        response(
            200,
            boatramp_http::h2::Body::stream_sized(self.declared, chunks),
        )
    }
}

/// Defense-in-depth parity (optional): an h2 `StreamSized` response that OVER-runs its
/// declared content-length must RST the stream, not frame bytes past the committed length.
/// (The h1 writer force-closes; the client's own §8.1.2.6 check is the backstop.)
#[tokio::test]
async fn h2_response_over_declared_length_resets_the_stream() {
    let mut c = raw_client(SizedMismatch {
        declared: 4,
        produce: 9,
    });
    send_preface(&mut c).await;
    let block = post_block("/over", None);
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        FrameType::Headers,
        F_END_HEADERS | F_END_STREAM,
        1,
        &block,
    );
    c.write_all(&buf).await.unwrap();
    let code = wait_for_rst(&mut c, 1, std::time::Duration::from_secs(5)).await;
    assert_eq!(
        code,
        Some(ErrorCode::InternalError),
        "an over-declared-length response body must RST, never frame bytes past the length"
    );
}

/// Parity (optional): an h2 `StreamSized` response that UNDER-runs its declared
/// content-length must RST the stream, not frame a clean END_STREAM on a short body.
#[tokio::test]
async fn h2_response_under_declared_length_resets_the_stream() {
    let mut c = raw_client(SizedMismatch {
        declared: 12,
        produce: 6,
    });
    send_preface(&mut c).await;
    let block = post_block("/under", None);
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        FrameType::Headers,
        F_END_HEADERS | F_END_STREAM,
        1,
        &block,
    );
    c.write_all(&buf).await.unwrap();
    let code = wait_for_rst(&mut c, 1, std::time::Duration::from_secs(5)).await;
    assert_eq!(
        code,
        Some(ErrorCode::InternalError),
        "an under-declared-length response body must RST, never a clean END_STREAM short body"
    );
}
