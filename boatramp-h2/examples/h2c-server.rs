//! A plaintext (h2c, prior-knowledge) server for conformance testing:
//!   cargo run --example h2c-server   # then: h2spec -h 127.0.0.1 -p 8080
use boatramp_h2::{serve_connection, Handler, Request, Response};
use tokio::net::TcpListener;

struct Ok200;

impl Handler for Ok200 {
    async fn handle(&self, _req: Request) -> Response {
        Response::with_body(200, b"ok".to_vec())
    }
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&addr).await.expect("bind");
    eprintln!("boatramp-h2 h2c server on {addr}");
    loop {
        let (sock, _) = listener.accept().await.expect("accept");
        sock.set_nodelay(true).ok();
        tokio::spawn(async move {
            let _ = serve_connection(sock, Ok200).await;
        });
    }
}
