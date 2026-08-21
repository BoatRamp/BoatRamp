//! M3 interop battery: exercise the paths h2spec doesn't stress — multiplexed
//! concurrent streams, request bodies, and large responses that span many DATA
//! frames and force the flow-controlled resume loop (the client's default 64 KiB
//! window makes the server stall and resume on WINDOW_UPDATE). Driven by the
//! reference `h2` client, so the responses are validated against a real peer.

use bytes::Bytes;
use boatramp_http::h2::{response, serve_connection, Handler, Request, Response};

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
        assert_eq!(read_body(response.into_body()).await, format!("GET /s{i}").into_bytes());
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
    send.send_data(Bytes::from_static(b"hello body"), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(read_body(response.into_body()).await, b"hello body");
}
