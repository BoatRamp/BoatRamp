//! M4c: the concurrent multiplexed driver (`serve_connection_mux`) must pass the
//! same functional battery as the serial driver — multiplexing, request bodies,
//! large flow-controlled responses — AND actually process streams concurrently
//! within one connection (the whole point). The `concurrent_streams_interleave`
//! test proves it: two requests whose handlers are interdependent complete only if
//! the driver keeps reading while a handler is parked — the serial driver would
//! deadlock. Driven by the reference `h2` client.

use std::sync::Arc;

use bytes::Bytes;
use boatramp_http::h2::{response, serve_connection_mux, Handler, Request, Response};
use tokio::sync::Notify;

struct App;

impl Handler for App {
    async fn handle(&self, req: Request) -> Response {
        let path = req.uri().path().to_owned();
        match path.as_str() {
            "/big" => response(200, vec![b'x'; 100_000]),
            "/echo" => response(200, req.into_body().to_vec()),
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
        assert_eq!(read_body(response.into_body()).await, format!("GET /s{i}").into_bytes());
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
    send.send_data(Bytes::from_static(b"hello body"), true).unwrap();
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
            response(200, Body::stream(tokio_stream::wrappers::ReceiverStream::new(rx)))
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_stream::StreamExt as _;
    use boatramp_http::h2::Body;

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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio_stream::StreamExt as _;
    use boatramp_http::h2::Body;

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
    assert!(b <= a + 2, "producer kept pulling after the client reset: {a} -> {b}");

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
    use std::time::Duration;
    use boatramp_http::h2::{Body, BodyChunk, BodyError};

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
            response(200, Body::try_stream(tokio_stream::wrappers::ReceiverStream::new(rx)))
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
