//! An HTTP/2-over-TLS reverse proxy on the **concurrent multiplexed** driver
//! (`serve_connection_mux`) with **userspace rustls** (no kTLS) and a **pooled**
//! HTTP/1.1 upstream — the Envoy-style design the competitive study pointed to. This
//! is the M4c benchmark vehicle: it isolates the concurrency fix (multiplexing +
//! upstream reuse) from the kTLS/splice complexity.
//!
//!   CERT=cert.pem KEY=key.pem UPSTREAM=127.0.0.1:9000 BIND=127.0.0.1:8443 \
//!     cargo run --release --example h2-tls-proxy-mux
//!
//! Linux-only only because rustls/tokio-rustls are target-gated deps in this crate.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("h2-tls-proxy-mux needs the Linux-gated rustls deps");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::sync::{Arc, Mutex};

    use boatramp_http::h2::{response, serve_connection_mux, Handler, Request, Response};
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

    /// A pool of warm keep-alive HTTP/1.1 upstream connections, reused across requests
    /// (like Envoy's per-worker connection pool) instead of one connect per request.
    #[derive(Clone, Default)]
    struct Pool(Arc<Mutex<Vec<TcpStream>>>);

    impl Pool {
        fn take(&self) -> Option<TcpStream> {
            self.0.lock().unwrap().pop()
        }
        fn put(&self, conn: TcpStream) {
            self.0.lock().unwrap().push(conn);
        }
    }

    struct Proxy {
        pool: Pool,
    }

    impl Handler for Proxy {
        async fn handle(&self, req: Request) -> Response {
            let mut up = match self.pool.take() {
                Some(c) => c,
                None => match TcpStream::connect(upstream()).await {
                    Ok(c) => {
                        c.set_nodelay(true).ok();
                        c
                    }
                    Err(_) => return response(502, b"bad gateway".to_vec()),
                },
            };
            // HTTP/1.1 defaults to keep-alive, so the connection returns to the pool.
            let get = format!(
                "GET {} HTTP/1.1\r\nHost: b\r\n\r\n",
                req.uri()
            );
            if up.write_all(get.as_bytes()).await.is_err() {
                return response(502, b"bad gateway".to_vec());
            }
            match read_response(&mut up).await {
                Some((status, body)) => {
                    self.pool.put(up); // clean boundary → reuse
                    response(status, body)
                }
                None => response(502, b"bad gateway".to_vec()),
            }
        }
    }

    /// Read a full HTTP/1.1 response (head + exactly `content-length` body), leaving
    /// the connection at a clean message boundary for reuse.
    async fn read_response(up: &mut TcpStream) -> Option<(u16, Vec<u8>)> {
        let mut buf = Vec::with_capacity(8192);
        let mut tmp = [0u8; 8192];
        let head_end = loop {
            let n = up.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = find(&buf, b"\r\n\r\n") {
                break p + 4;
            }
            if buf.len() > 65536 {
                return None;
            }
        };
        let status = parse_status(&buf[..head_end])?;
        let clen = content_length(&buf[..head_end]).unwrap_or(0);
        let mut body = buf[head_end..].to_vec();
        while body.len() < clen {
            let n = up.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(clen);
        Some((status, body))
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
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
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let pool = Pool::default();

        let listener = TcpListener::bind(&bind).await?;
        eprintln!("boatramp-h2 h2-tls MUX proxy on {bind} -> {}", upstream());
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            sock.set_nodelay(true).ok();
            let acceptor = acceptor.clone();
            let pool = pool.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(sock).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let _ = serve_connection_mux(tls, Proxy { pool }).await;
            });
        }
    }
}
