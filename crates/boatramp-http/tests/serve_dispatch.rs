//! The unified dispatcher (`serve_connection`) must route by the opening bytes: an
//! HTTP/1.1 request line → the h1 loop; the HTTP/2 client preface → the h2 mux driver.
//! Both are driven over one plaintext duplex through the SAME entry point.

use boatramp_http::{response, serve_connection, Handler, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct App;
impl Handler for App {
    async fn handle(&self, req: Request) -> Response {
        response(200, format!("ok {}", req.uri().path()).into_bytes())
    }
}

#[tokio::test]
async fn dispatches_http1() {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let _ = serve_connection(server, App).await;
    });
    client
        .write_all(b"GET /one HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.ends_with("ok /one"), "{text}");
}

#[tokio::test]
async fn dispatches_h2c_prior_knowledge() {
    let (client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let _ = serve_connection(server, App).await;
    });
    // The `h2` client sends the HTTP/2 preface, which the dispatcher sniffs → mux driver.
    let (h2, connection) = h2::client::handshake(client).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut h2 = h2.ready().await.unwrap();
    let req = http::Request::builder()
        .method("GET")
        .uri("http://x/two")
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
    assert_eq!(got, b"ok /two");
}
