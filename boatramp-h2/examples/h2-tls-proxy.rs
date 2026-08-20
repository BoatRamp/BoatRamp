//! An HTTP/2-over-**kTLS** reverse proxy on the zero-copy `Body::Splice` path: the
//! rustls handshake hands the socket to the kernel TLS state machine, then each
//! response body is moved upstream→pipe→kTLS-socket with `splice()` (kernel encrypts
//! on TX) — only the 9-byte DATA headers touch userspace. This is the integrated
//! form of the spike, driven by the conformance-gated `boatramp-h2` server.
//!
//!   CERT=cert.pem KEY=key.pem UPSTREAM=127.0.0.1:9000 BIND=127.0.0.1:8443 \
//!     cargo run --release --example h2-tls-proxy
//!
//! Linux-only (kTLS + splice). A self-signed cert is fine for benchmarking:
//!   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 \
//!     -nodes -subj /CN=localhost

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("h2-tls-proxy is Linux-only (kTLS + splice)");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::sync::Arc;

    use boatramp_h2::{serve_connection_ktls, Body, Handler, Request, Response};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    fn upstream() -> String {
        std::env::var("UPSTREAM").unwrap_or_else(|_| "127.0.0.1:9000".to_string())
    }

    fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
        let mut r = io::BufReader::new(std::fs::File::open(path).expect("open cert"));
        rustls_pemfile::certs(&mut r)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse certs")
    }

    fn load_key(path: &str) -> PrivateKeyDer<'static> {
        let mut r = io::BufReader::new(std::fs::File::open(path).expect("open key"));
        rustls_pemfile::private_key(&mut r)
            .expect("parse key")
            .expect("no key")
    }

    struct Proxy;

    impl Handler for Proxy {
        async fn handle(&self, req: Request) -> Response {
            let mut up = match TcpStream::connect(upstream()).await {
                Ok(u) => u,
                Err(_) => return Response::with_body(502, b"bad gateway".to_vec()),
            };
            up.set_nodelay(true).ok();
            let get = format!(
                "GET {} HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n",
                String::from_utf8_lossy(&req.path)
            );
            if up.write_all(get.as_bytes()).await.is_err() {
                return Response::with_body(502, b"bad gateway".to_vec());
            }
            // Read the head one byte at a time so we never consume any body — the body
            // is then exactly `content-length` bytes still on the socket, which the
            // kernel splice path streams straight into the kTLS connection fd.
            let head = read_head(&mut up).await;
            let status = parse_status(&head).unwrap_or(502);
            let clen = content_length(&head).unwrap_or(0);
            Response {
                status,
                headers: Vec::new(),
                body: Body::Splice {
                    upstream: up,
                    len: clen,
                },
            }
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

    pub async fn run() -> io::Result<()> {
        let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
        let cert = std::env::var("CERT").expect("set CERT");
        let key = std::env::var("KEY").expect("set KEY");

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(load_certs(&cert), load_key(&key))
            .expect("cert");
        // kTLS needs the negotiated secrets; ALPN advertises h2 so a client speaks
        // HTTP/2 directly.
        cfg.enable_secret_extraction = true;
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = TcpListener::bind(&bind).await?;
        eprintln!("boatramp-h2 h2-tls proxy on {bind} -> {}", upstream());
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = serve_connection_ktls(sock, acceptor, Proxy).await;
            });
        }
    }
}
