//! The HTTP transport seam the client shim calls through.
//!
//! The protocol logic in [`crate`] is transport-agnostic: it builds an [`HttpRequest`] (URL, headers,
//! body) and parses the [`HttpResponse`] it gets back. The [`Transport`] trait is the one method a
//! caller must provide — so the shim runs over whatever HTTP client the environment already has:
//!
//! * the host `boatramp` CLI / a host service → a TLS-capable client (reqwest / ureq) — see the
//!   crate-level docs for the ~10-line impl;
//! * a guest making an outbound call (once this crate is vendored into the shim repo) → the shim's
//!   `wasi:http` outgoing-handler;
//! * the live gates + any plaintext/overlay dial → the dependency-free [`PlaintextHttpTransport`]
//!   shipped here.
//!
//! [`PlaintextHttpTransport`] speaks `http://` only (HTTP/1.1, `Connection: close`, read to EOF),
//! which is all the loopback live gate and an overlay-tunneled dial need; a `https://` URL is
//! refused with a clear error so a caller reaches for a TLS transport rather than silently failing.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// One outbound HTTP request the shim asks a [`Transport`] to perform. Always a `POST` to `url`
/// (Connect / gRPC-web RPCs are always `POST`), with `headers` and the raw `body`.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The absolute RPC URL, e.g. `http://host:port/_sites/site/pkg.Svc/Method`.
    pub url: String,
    /// Request headers (lowercase names). `content-length` is added by the transport.
    pub headers: Vec<(String, String)>,
    /// The request body (a bare protobuf message, or one length-prefixed envelope frame).
    pub body: Vec<u8>,
}

/// A fully-buffered HTTP response: the status, the lowercased headers, and the decoded body
/// (transfer-encoding and content-length already resolved). Buffering the whole body is correct for
/// unary and for a *bounded* server-stream (the response ends when the server closes / finishes the
/// stream); an unbounded stream would want an incremental transport — a later increment.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first value of `name` (a lowercase header name), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A failure performing the HTTP request/response (not an RPC-level error — that rides the response
/// body as a [`crate::Status`]).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// A socket / IO failure.
    #[error("io: {0}")]
    Io(String),
    /// The request URL could not be used by this transport.
    #[error("url: {0}")]
    Url(String),
    /// The HTTP response was malformed (no status line, bad framing, …).
    #[error("malformed http response: {0}")]
    Response(String),
    /// Any other transport failure (a custom transport's own error).
    #[error("transport: {0}")]
    Other(String),
}

/// The one seam a client transport implements: perform `req` and return the buffered response.
pub trait Transport {
    /// Send `req` and return the full buffered [`HttpResponse`], or a [`TransportError`].
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// Perform the request through a borrowed transport.
impl<T: Transport + ?Sized> Transport for &T {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        (**self).send(req)
    }
}

/// A dependency-free `http://` transport over `std::net::TcpStream` (HTTP/1.1, `Connection: close`,
/// read to EOF). It is the reference transport the live gates drive and is enough for a plaintext
/// or overlay-tunneled dial; a `https://` URL is refused (reach for a TLS-capable [`Transport`]).
#[derive(Debug, Clone, Default)]
pub struct PlaintextHttpTransport {
    /// An optional read timeout (so a hung stream fails rather than blocking forever).
    pub read_timeout: Option<Duration>,
}

impl PlaintextHttpTransport {
    /// A transport with no read timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport with the given read timeout.
    pub fn with_read_timeout(timeout: Duration) -> Self {
        Self {
            read_timeout: Some(timeout),
        }
    }
}

impl Transport for PlaintextHttpTransport {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let (host, port, path) = parse_http_url(&req.url)?;
        let mut stream = TcpStream::connect((host.as_str(), port))
            .map_err(|e| TransportError::Io(format!("connect {host}:{port}: {e}")))?;
        if let Some(t) = self.read_timeout {
            stream
                .set_read_timeout(Some(t))
                .map_err(|e| TransportError::Io(e.to_string()))?;
        }

        let mut raw = Vec::with_capacity(256 + req.body.len());
        raw.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
        raw.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        for (k, v) in &req.headers {
            // Guard against header injection from a caller-supplied value.
            if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
                return Err(TransportError::Other(format!(
                    "header {k:?} contains a CR/LF"
                )));
            }
            raw.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        raw.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
        raw.extend_from_slice(b"Connection: close\r\n\r\n");
        raw.extend_from_slice(&req.body);

        stream
            .write_all(&raw)
            .map_err(|e| TransportError::Io(format!("write: {e}")))?;
        stream
            .flush()
            .map_err(|e| TransportError::Io(format!("flush: {e}")))?;

        let mut resp_raw = Vec::new();
        stream
            .read_to_end(&mut resp_raw)
            .map_err(|e| TransportError::Io(format!("read: {e}")))?;
        parse_http_response(&resp_raw)
    }
}

/// Parse a `http://host[:port]/path` URL into `(host, port, path)`. `https://` is refused.
fn parse_http_url(url: &str) -> Result<(String, u16, String), TransportError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        if url.starts_with("https://") {
            TransportError::Url(format!(
                "PlaintextHttpTransport speaks http:// only; {url:?} is https — implement \
                     Transport over a TLS-capable client for production endpoints"
            ))
        } else {
            TransportError::Url(format!("expected an http:// URL, got {url:?}"))
        }
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| TransportError::Url(format!("bad port in {url:?}")))?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(TransportError::Url(format!("no host in {url:?}")));
    }
    Ok((host, port, path.to_string()))
}

/// Parse a raw HTTP/1.1 response buffer into [`HttpResponse`], resolving `chunked` transfer-encoding
/// and `content-length` (and read-to-EOF when neither is present, the `Connection: close` case).
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, TransportError> {
    let sep = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| TransportError::Response("no header/body separator".into()))?;
    let head = std::str::from_utf8(&raw[..sep])
        .map_err(|_| TransportError::Response("non-utf8 response head".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| TransportError::Response("no status line".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TransportError::Response(format!("no status code in {status_line:?}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    let body_raw = &raw[sep + 4..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        dechunk(body_raw)
    } else if let Some(cl) = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
    {
        body_raw[..cl.min(body_raw.len())].to_vec()
    } else {
        body_raw.to_vec()
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// De-chunk a `Transfer-Encoding: chunked` body already fully in memory.
fn dechunk(mut buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = find_subslice(buf, b"\r\n") {
        let size_line = std::str::from_utf8(&buf[..nl]).unwrap_or("");
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).unwrap_or(0);
        buf = &buf[nl + 2..];
        if size == 0 {
            break;
        }
        if buf.len() < size {
            out.extend_from_slice(buf);
            break;
        }
        out.extend_from_slice(&buf[..size]);
        buf = &buf[size..];
        if buf.len() >= 2 {
            buf = &buf[2..]; // trailing CRLF after the chunk data
        }
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_http() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:8080/_sites/s/pkg.Svc/M").unwrap(),
            ("127.0.0.1".into(), 8080, "/_sites/s/pkg.Svc/M".into())
        );
        assert_eq!(
            parse_http_url("http://example.com/x").unwrap(),
            ("example.com".into(), 80, "/x".into())
        );
    }

    #[test]
    fn parse_url_https_is_refused_clearly() {
        let err = parse_http_url("https://example.com/x").unwrap_err();
        assert!(matches!(err, TransportError::Url(_)));
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn parse_response_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/proto\r\nContent-Length: 3\r\n\r\nabcEXTRA";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"abc");
        assert_eq!(resp.header("content-type"), Some("application/proto"));
    }

    #[test]
    fn parse_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.body, b"abcde");
    }

    #[test]
    fn parse_response_read_to_eof() {
        // No content-length, no chunked (Connection: close) — body is everything after the head.
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/connect+proto\r\n\r\n\x00\x00\x00\x00\x02hi";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.body, b"\x00\x00\x00\x00\x02hi");
    }
}
