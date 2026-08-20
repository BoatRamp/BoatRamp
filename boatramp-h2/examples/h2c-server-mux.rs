//! A plaintext (h2c, prior-knowledge) server on the **concurrent multiplexed**
//! driver, for running h2spec against `serve_connection_mux`:
//!   cargo run --example h2c-server-mux   # then: h2spec -h 127.0.0.1 -p 8080
use boatramp_h2::{response, serve_connection_mux, Handler, Request, Response};
use tokio::net::TcpListener;

struct Ok200;

impl Handler for Ok200 {
    async fn handle(&self, _req: Request) -> Response {
        response(200, b"ok".to_vec())
    }
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&addr).await.expect("bind");
    eprintln!("boatramp-h2 h2c MUX server on {addr}");
    loop {
        let (sock, _) = listener.accept().await.expect("accept");
        sock.set_nodelay(true).ok();
        tokio::spawn(async move {
            let _ = serve_connection_mux(sock, Ok200).await;
        });
    }
}
