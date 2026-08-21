//! An h2c reverse proxy over the `Body::Splice` path: forwards each request to a
//! plaintext HTTP/1.1 upstream and streams the response body from the upstream
//! socket. On a plaintext (buffered) h2c connection the body is streamed through
//! userspace; the kernel-splice + kTLS zero-copy path is the `h2-tls-proxy` example.
//! For correctness testing:  cargo run --example h2c-proxy  then
//! curl --http2-prior-knowledge. Linux-only (the `Body::Splice` seam is Linux-gated).

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("h2c-proxy is Linux-only (the Body::Splice seam is Linux-gated)");
}

#[cfg(target_os = "linux")]
mod linux {
    use boatramp_http::h2::{response, serve_connection_tcp, Body, Handler, Request, Response};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn upstream() -> String {
        std::env::var("UPSTREAM").unwrap_or_else(|_| "127.0.0.1:9000".to_string())
    }

    struct Proxy;

    impl Handler for Proxy {
        async fn handle(&self, req: Request) -> Response {
            let mut up = match TcpStream::connect(upstream()).await {
                Ok(u) => u,
                Err(_) => return response(502, b"bad gateway".to_vec()),
            };
            up.set_nodelay(true).ok();
            let get = format!(
                "GET {} HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n",
                req.uri()
            );
            if up.write_all(get.as_bytes()).await.is_err() {
                return response(502, b"bad gateway".to_vec());
            }
            // Read the head one byte at a time so we never consume any body — the body
            // is then exactly `content-length` bytes still on the socket, which
            // Body::Splice reads.
            let head = read_head(&mut up).await;
            let status = parse_status(&head).unwrap_or(502);
            let clen = content_length(&head).unwrap_or(0);
            response(
                status,
                Body::Splice {
                    upstream: up,
                    len: clen,
                },
            )
        }
    }

    async fn read_head(up: &mut TcpStream) -> Vec<u8> {
        let mut head = Vec::with_capacity(256);
        let mut b = [0u8; 1];
        while up.read_exact(&mut b).await.is_ok() {
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") || head.len() > 16384 {
                break;
            }
        }
        head
    }

    fn parse_status(head: &[u8]) -> Option<u16> {
        let line = std::str::from_utf8(head).ok()?.lines().next()?;
        line.split(' ').nth(1)?.parse().ok()
    }

    fn content_length(head: &[u8]) -> Option<usize> {
        let s = std::str::from_utf8(head).ok()?;
        for line in s.split("\r\n") {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    return v.trim().parse().ok();
                }
            }
        }
        None
    }

    pub async fn run() {
        let addr = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let listener = TcpListener::bind(&addr).await.expect("bind");
        eprintln!("boatramp-h2 h2c proxy on {addr} -> {}", upstream());
        loop {
            let (sock, _) = listener.accept().await.expect("accept");
            sock.set_nodelay(true).ok();
            tokio::spawn(async move {
                let _ = serve_connection_tcp(sock, Proxy).await;
            });
        }
    }
}
