//! The HTTP/1.1 **client** codec (reverse-proxy upstream leg) validated two ways: a
//! differential oracle against `hyper`'s client on a matrix of response shapes (the two
//! must agree on status + framing + decoded body), and a round-trip against boatramp's own
//! `serve_connection` (what the proxy will actually talk to). The parser is a new
//! untrusted-input surface — an upstream's bytes — so it gets the same oracle treatment as
//! the request parser.

use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use boatramp_http::h1::client::{BodyReader, Conn};

/// Decode a scripted raw upstream response with **boatramp's** client codec: connect to a
/// listener that writes `raw` verbatim, then read the head + drain the body.
async fn decode_with_boatramp(raw: &'static [u8], method: &Method) -> (StatusCode, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Drain the request head so the write side isn't RST before we read it.
        let mut scratch = [0u8; 1024];
        let _ = sock.read(&mut scratch).await;
        sock.write_all(raw).await.unwrap();
        // Close, so a close-delimited body terminates.
        drop(sock);
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = Conn::new(stream);
    conn.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    conn.flush().await.unwrap();
    let head = conn.read_response_head().await.unwrap();
    let mut reader = BodyReader::r#for(method, &head);
    let mut body = Vec::new();
    while let Some(chunk) = conn.read_body_chunk(&mut reader).await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    (head.status, body)
}

/// Decode the same scripted response with **hyper's** client, for the differential oracle.
async fn decode_with_hyper(raw: &'static [u8], method: Method) -> (StatusCode, Vec<u8>) {
    use http_body_util::BodyExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut scratch = [0u8; 1024];
        let _ = sock.read(&mut scratch).await;
        sock.write_all(raw).await.unwrap();
        drop(sock);
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, http_body_util::Empty<Bytes>>(io)
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method(method)
        .uri("/")
        .header("host", "x")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

/// The response shapes that matter: fixed length, chunked (single + multi-chunk), empty,
/// a no-body status, and a close-delimited body. Boatramp's client and hyper must agree.
fn matrix() -> Vec<(&'static [u8], Method)> {
    vec![
        (
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello" as &[u8],
            Method::GET,
        ),
        (
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
            Method::GET,
        ),
        (
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            Method::GET,
        ),
        (
            b"HTTP/1.1 204 No Content\r\n\r\n",
            Method::GET,
        ),
        (
            b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n0123456789",
            Method::HEAD, // HEAD → no body despite the content-length
        ),
        (
            // Close-delimited: no content-length, no TE — body framed by EOF.
            b"HTTP/1.1 200 OK\r\n\r\nclose-delimited-body",
            Method::GET,
        ),
    ]
}

#[tokio::test]
async fn client_matches_hyper_across_response_shapes() {
    for (raw, method) in matrix() {
        let (mine_status, mine_body) = decode_with_boatramp(raw, &method).await;
        let (hyper_status, hyper_body) = decode_with_hyper(raw, method.clone()).await;
        assert_eq!(
            mine_status,
            hyper_status,
            "status disagreement on {:?}",
            String::from_utf8_lossy(raw)
        );
        assert_eq!(
            mine_body,
            hyper_body,
            "body disagreement on {:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

/// End-to-end against boatramp's own server: the client's request reaches the server and
/// the server's response decodes byte-identically back — the exact loop the proxy runs.
#[tokio::test]
async fn client_round_trips_against_boatramp_server() {
    use boatramp_http::{response, serve_connection, Body, Handler, Request, Response};

    #[derive(Clone, Copy)]
    struct App;
    impl Handler for App {
        async fn handle(&self, req: Request) -> Response {
            match req.uri().path() {
                "/fixed" => response(200, b"fixed-body".to_vec()),
                "/big" => response(200, vec![b'z'; 200_000]),
                "/chunked" => {
                    let s = tokio_stream::iter(vec![
                        Bytes::from_static(b"part-one "),
                        Bytes::from_static(b"part-two"),
                    ]);
                    response(200, Body::stream(s))
                }
                _ => response(404, Vec::new()),
            }
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = serve_connection(sock, App).await;
            });
        }
    });

    // Reuse one keep-alive connection for all three requests (the pool's hot path).
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = Conn::new(stream);
    for (path, expected) in [
        ("/fixed", b"fixed-body".to_vec()),
        ("/big", vec![b'z'; 200_000]),
        ("/chunked", b"part-one part-two".to_vec()),
    ] {
        let head_bytes = boatramp_http::h1::client::encode_request_head(&Method::GET, path, &{
            let mut h = http::HeaderMap::new();
            h.insert(http::header::HOST, "x".parse().unwrap());
            h
        });
        conn.write_all(&head_bytes).await.unwrap();
        conn.flush().await.unwrap();
        let head = conn.read_response_head().await.unwrap();
        assert_eq!(head.status, StatusCode::OK);
        let mut reader = BodyReader::r#for(&Method::GET, &head);
        let mut body = Vec::new();
        while let Some(chunk) = conn.read_body_chunk(&mut reader).await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, expected, "mismatch on {path}");
        // Connection stayed drained + reusable between requests.
        assert_eq!(conn.buffered(), 0);
    }
}
