//! M4c: the concurrent multiplexed driver (`serve_connection_mux`) must pass the
//! same functional battery as the serial driver — multiplexing, request bodies,
//! large flow-controlled responses — AND actually process streams concurrently
//! within one connection (the whole point). The `concurrent_streams_interleave`
//! test proves it: two requests whose handlers are interdependent complete only if
//! the driver keeps reading while a handler is parked — the serial driver would
//! deadlock. Driven by the reference `h2` client.

use std::sync::Arc;

use boatramp_http::h2::{Handler, Request, Response, response, serve_connection_mux};
use bytes::Bytes;
use tokio::sync::Notify;

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
