//! End-to-end smoke test: drive the server with the reference `h2` client over an
//! in-memory duplex. This is also the seed of the M3 differential oracle.

use boatramp_http::h2::{response, serve_connection, Handler, Request, Response};

struct Echo;

impl Handler for Echo {
    async fn handle(&self, req: Request) -> Response {
        // Echo the method + path so we can assert the request was parsed.
        let body = format!("{} {}", req.method(), req.uri().path());
        let mut resp = response(200, body.into_bytes());
        resp.headers_mut()
            .insert("x-served-by", "boatramp-h2".parse().unwrap());
        resp
    }
}

#[tokio::test]
async fn get_roundtrips_through_the_reference_client() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    tokio::spawn(async move {
        let _ = serve_connection(server_io, Echo).await;
    });

    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request.ready().await.unwrap();

    let request = http::Request::builder()
        .method("GET")
        .uri("https://example.test/hello")
        .body(())
        .unwrap();
    let (response, _send_stream) = send_request.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-served-by")
            .map(http::HeaderValue::as_bytes),
        Some(&b"boatramp-h2"[..])
    );

    let mut body = response.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, b"GET /hello");
}
