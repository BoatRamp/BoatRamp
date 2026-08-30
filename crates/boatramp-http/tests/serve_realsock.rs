//! Connection-loop validation over **real TCP sockets** — the production gate. In-memory
//! duplex tests can't exercise TCP fragmentation, real read timeouts, concurrency at
//! scale, abrupt disconnects, or write backpressure; these do. Every connection is served
//! by the unified `serve_connection`, so this validates the exact path that will terminate
//! production traffic.

use std::net::SocketAddr;
use std::time::Duration;

use boatramp_http::{response, serve_connection_with, Body, Config, Handler, Request, Response};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A small app exercising the response shapes that matter over a socket.
#[derive(Clone, Copy)]
struct App;
impl Handler for App {
    async fn handle(&self, req: Request) -> Response {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        match (method.as_str(), path.as_str()) {
            ("GET", "/") => response(200, b"ok".to_vec()),
            ("GET", "/big") => response(200, vec![b'x'; 1_000_000]), // 1 MB fixed response
            ("POST", "/echo") => response(
                200,
                req.into_body().collect().await.unwrap_or_default().to_vec(),
            ),
            // Streams the request body straight back (no buffering).
            ("POST", "/echo-stream") => {
                response(200, Body::try_stream(req.into_body().into_data_stream()))
            }
            _ => response(404, Vec::new()),
        }
    }
}

/// Bind an ephemeral TCP listener and serve every accepted connection with the unified
/// `serve_connection` (given config). Returns the bound address.
async fn spawn_server(config: Config) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_connection_with(stream, App, config).await;
            });
        }
    });
    addr
}

// --- an h1 client over a real TCP socket (via hyper) -------------------------
async fn h1_get(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>,
    path: &str,
) -> (u16, Vec<u8>) {
    use http_body_util::{BodyExt, Full};
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://x{path}"))
        .header("host", "x")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

async fn connect_h1(
    addr: SocketAddr,
) -> hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

#[tokio::test]
async fn h1_keepalive_over_tcp() {
    let addr = spawn_server(Config::default()).await;
    let mut sender = connect_h1(addr).await;
    for _ in 0..10 {
        let (status, body) = h1_get(&mut sender, "/").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"ok");
    }
}

#[tokio::test]
async fn h2c_over_tcp() {
    let addr = spawn_server(Config::default()).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (h2, connection) = h2::client::handshake(stream).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut h2 = h2.ready().await.unwrap();
    let req = http::Request::builder().uri("http://x/").body(()).unwrap();
    let (resp, _) = h2.send_request(req, true).unwrap();
    let resp = resp.await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, b"ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_connections() {
    let addr = spawn_server(Config::default()).await;
    let mut handles = Vec::new();
    for _ in 0..24 {
        handles.push(tokio::spawn(async move {
            let mut sender = connect_h1(addr).await;
            for _ in 0..10 {
                let (status, body) = h1_get(&mut sender, "/").await;
                assert_eq!(status, 200);
                assert_eq!(body, b"ok");
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn slowloris_head_is_dropped_by_the_read_timeout() {
    // A short read timeout so the test is fast.
    let cfg = Config {
        sniff_timeout: Duration::from_millis(300),
        read_timeout: Duration::from_millis(300),
    };
    let addr = spawn_server(cfg).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    // A partial request head, then stall forever.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    // The server must close the connection (read → EOF) within a couple of timeouts.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("server did not close the slowloris connection in time")
        .unwrap();
    assert_eq!(n, 0, "expected EOF (server closed), got {n} bytes");
}

#[tokio::test]
async fn large_streaming_request_body_round_trips_over_tcp() {
    use http_body_util::{BodyExt, Full};
    let addr = spawn_server(Config::default()).await;
    let mut sender = connect_h1(addr).await;
    // 4 MiB body — far past any single TCP segment, so it exercises fragmentation +
    // streaming (echo-stream never buffers it whole).
    let payload = vec![b'z'; 4 * 1024 * 1024];
    let req = hyper::Request::builder()
        .method("POST")
        .uri("http://x/echo-stream")
        .header("host", "x")
        .body(Full::new(Bytes::from(payload.clone())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), payload.len());
    assert!(body.iter().all(|&b| b == b'z'));
}

#[tokio::test]
async fn client_disconnect_midrequest_does_not_wedge_the_server() {
    let addr = spawn_server(Config::default()).await;
    // Declare a big body, send a few bytes, then abruptly drop the socket.
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\npartial")
            .await
            .unwrap();
        // drop `stream` → RST/FIN mid-body.
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // A fresh connection must still be served — the server isn't wedged.
    let mut sender = connect_h1(addr).await;
    let (status, body) = h1_get(&mut sender, "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn client_disconnect_midresponse_is_graceful() {
    let addr = spawn_server(Config::default()).await;
    // Request the 1 MB response, read a little, then drop — the server's write fails and
    // the serve task ends without panicking or leaking.
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf).await.unwrap();
        // drop `stream` mid-response.
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The server still serves new connections.
    let mut sender = connect_h1(addr).await;
    let (status, _) = h1_get(&mut sender, "/").await;
    assert_eq!(status, 200);
}

// --- zero-copy `sendfile` static body -----------------------------------------

/// A non-repeating byte pattern so a wrong offset, a truncation, or a duplicated/
/// re-sent chunk is caught (an all-same-byte body would hide those).
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Serves one on-disk file as a [`Body::File`] (the `sendfile` fast-path) for `GET
/// /file`, opening a fresh handle per request (as the serving layer does).
#[derive(Clone)]
struct FileApp {
    path: std::sync::Arc<std::path::PathBuf>,
    len: u64,
}
impl Handler for FileApp {
    async fn handle(&self, _req: Request) -> Response {
        let file = std::fs::File::open(&*self.path).unwrap();
        response(200, Body::file(std::sync::Arc::new(file), 0, self.len))
    }
}

async fn spawn_file_server(app: FileApp) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let app = app.clone();
            tokio::spawn(async move {
                let _ = serve_connection_with(stream, app, Config::default()).await;
            });
        }
    });
    addr
}

/// Over a real plaintext TCP socket the h1 codec serves a `Body::File` via `sendfile`
/// (Linux) — the bytes the client receives must be byte-identical to the file, the
/// framing (`Content-Length`) exact, and the connection reusable afterwards (the
/// dup'd-fd `sendfile` must not disturb the original socket).
#[tokio::test]
async fn sendfile_large_static_over_tcp_is_byte_identical() {
    let content = pattern(1_000_000);
    let dir = std::env::temp_dir().join(format!("br-sendfile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blob");
    std::fs::write(&path, &content).unwrap();
    let addr = spawn_file_server(FileApp {
        path: std::sync::Arc::new(path),
        len: content.len() as u64,
    })
    .await;

    let mut sender = connect_h1(addr).await;
    // Two requests on one keep-alive connection: the second proves the socket survives
    // the `sendfile` (dup + async_io) intact.
    for _ in 0..2 {
        let (status, body) = h1_get(&mut sender, "/file").await;
        assert_eq!(status, 200);
        assert_eq!(
            body.len(),
            content.len(),
            "Content-Length / framing must match"
        );
        assert_eq!(
            body, content,
            "sendfile body must be byte-identical to the file"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same `Body::File` over **h2c** takes the read fallback (no HTTP/2 `sendfile`
/// analogue) — still byte-identical, which validates the region read used by every
/// non-`sendfile` transport (TLS, wrapped streams).
#[tokio::test]
async fn file_body_over_h2c_is_byte_identical_via_fallback() {
    let content = pattern(600_000);
    let dir = std::env::temp_dir().join(format!("br-sendfile-h2c-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blob");
    std::fs::write(&path, &content).unwrap();
    let addr = spawn_file_server(FileApp {
        path: std::sync::Arc::new(path),
        len: content.len() as u64,
    })
    .await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let (h2, connection) = h2::client::handshake(stream).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut h2 = h2.ready().await.unwrap();
    let req = http::Request::builder()
        .uri("http://x/file")
        .body(())
        .unwrap();
    let (resp, _) = h2.send_request(req, true).unwrap();
    let resp = resp.await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    assert_eq!(
        got, content,
        "h2c read-fallback body must be byte-identical"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_h1_and_h2_concurrent() {
    let addr = spawn_server(Config::default()).await;
    let mut handles = Vec::new();
    // Half h1, half h2c — all served by the same serve_connection, concurrently.
    for i in 0..16 {
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let mut sender = connect_h1(addr).await;
                for _ in 0..5 {
                    assert_eq!(h1_get(&mut sender, "/").await.0, 200);
                }
            } else {
                let stream = TcpStream::connect(addr).await.unwrap();
                let (h2, connection) = h2::client::handshake(stream).await.unwrap();
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                let mut h2 = h2.ready().await.unwrap();
                for _ in 0..5 {
                    let req = http::Request::builder().uri("http://x/").body(()).unwrap();
                    let (resp, _) = h2.send_request(req, true).unwrap();
                    assert_eq!(resp.await.unwrap().status(), 200);
                    h2 = h2.ready().await.unwrap();
                }
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}
