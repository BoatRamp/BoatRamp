//! Request/response types (the standard `http` crate), the [`Handler`] trait, and
//! RFC 7540 §8.1.2 request validation. Requests are decoded **straight into
//! `http::Request`** (a real `HeaderMap`, not an intermediate list), so an embedder —
//! or a reverse-proxy bridge handing the request to a tower/hyper service — pays no
//! per-request re-marshaling. The response is an `http::Response` whose body is a
//! [`Body`] (buffered, spliced, or streamed).

use std::future::Future;

use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};

use crate::error::{ErrorCode, H2Error};

/// A received HTTP/2 request: an `http::Request` whose (buffered) body is `Bytes`.
/// The h2 pseudo-headers are hoisted into the method / URI (path) / `Host` header.
pub type Request = http::Request<Bytes>;

/// A response to send: an `http::Response` whose body is a [`Body`].
pub type Response = http::Response<Body>;

/// A response body: buffered bytes; a stream `splice()`d directly from an upstream
/// socket into the (kTLS) client socket (Linux zero-copy); or a pull [`Stream`] of
/// `Bytes` chunks forwarded as DATA frames as they arrive (a reverse proxy streaming
/// an upstream response without buffering or copying it — the stream ending closes the
/// h2 stream). The driver **polls the stream directly** in the per-stream task, so a
/// bridge hands its upstream body straight in with no intermediate channel or producer
/// task. The concurrent [`crate::mux`] driver streams the last two natively; the serial
/// [`crate::conn`] driver buffers a `Stream` (it can't interleave).
///
/// [`Stream`]: tokio_stream::Stream
pub enum Body {
    Bytes(Vec<u8>),
    #[cfg(target_os = "linux")]
    Splice {
        upstream: tokio::net::TcpStream,
        len: usize,
    },
    Stream(std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Bytes> + Send>>),
}

impl Body {
    /// A streamed body from any pull [`Stream`](tokio_stream::Stream) of `Bytes`
    /// chunks — the driver polls it directly (no channel/task hop). Empty chunks are
    /// skipped; the stream ending signals END_STREAM.
    pub fn stream(chunks: impl tokio_stream::Stream<Item = Bytes> + Send + 'static) -> Self {
        Body::Stream(Box::pin(chunks))
    }

    /// The body length if known ahead of time. A [`Body::Stream`] has no known length
    /// (`0`) — HTTP/2 delimits it with END_STREAM, so callers must use [`is_empty`]
    /// rather than `len() == 0` to decide whether a body is present.
    ///
    /// [`is_empty`]: Body::is_empty
    pub fn len(&self) -> usize {
        match self {
            Body::Bytes(b) => b.len(),
            #[cfg(target_os = "linux")]
            Body::Splice { len, .. } => *len,
            Body::Stream(_) => 0,
        }
    }
    pub fn is_empty(&self) -> bool {
        match self {
            Body::Bytes(b) => b.is_empty(),
            #[cfg(target_os = "linux")]
            Body::Splice { len, .. } => *len == 0,
            Body::Stream(_) => false,
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::Bytes(Vec::new())
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body::Bytes(v)
    }
}
impl From<&[u8]> for Body {
    fn from(v: &[u8]) -> Self {
        Body::Bytes(v.to_vec())
    }
}

/// Build a [`Response`] with a status and body and no extra headers — a small
/// convenience over `http::Response::builder()` for handlers.
pub fn response(status: u16, body: impl Into<Body>) -> Response {
    let mut resp = http::Response::new(body.into());
    *resp.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
    resp
}

/// A request handler. The connection driver calls this once per request stream.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send;
}

/// Connection-specific header field names forbidden in HTTP/2 (RFC 7540 §8.1.2.2).
const FORBIDDEN: &[&[u8]] = &[
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// Build a validated [`Request`] from a decoded header list. Malformed requests are a
/// **stream** error of type PROTOCOL_ERROR (RFC 7540 §8.1.2.6) so one bad request
/// resets its stream without killing the connection. The body is set separately once
/// the request's DATA has arrived.
pub(crate) fn request_from_headers(
    id: u32,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Request, H2Error> {
    let bad = || H2Error::stream(id, ErrorCode::ProtocolError);
    let mut method: Option<Vec<u8>> = None;
    let mut path: Option<Vec<u8>> = None;
    let mut authority: Option<Vec<u8>> = None;
    let mut scheme = false;
    let mut seen_regular = false;
    let mut hdrs = HeaderMap::new();

    for (name, value) in headers {
        if name.is_empty() {
            return Err(bad());
        }
        // Field names MUST be lowercase (RFC 7540 §8.1.2).
        if name.iter().any(u8::is_ascii_uppercase) {
            return Err(bad());
        }
        if name[0] == b':' {
            // Pseudo-headers MUST precede regular headers (§8.1.2.1).
            if seen_regular {
                return Err(bad());
            }
            match name.as_slice() {
                b":method" if method.is_none() => method = Some(value),
                b":scheme" if !scheme => scheme = true,
                b":path" if path.is_none() => path = Some(value),
                b":authority" if authority.is_none() => authority = Some(value),
                // Duplicate or unknown pseudo-header → malformed.
                _ => return Err(bad()),
            }
        } else {
            seen_regular = true;
            if FORBIDDEN.contains(&name.as_slice()) {
                return Err(bad());
            }
            // TE, if present, MUST be exactly "trailers" (§8.1.2.2).
            if name == b"te" && value != b"trailers" {
                return Err(bad());
            }
            let hn = HeaderName::from_bytes(&name).map_err(|_| bad())?;
            let hv = HeaderValue::from_bytes(&value).map_err(|_| bad())?;
            hdrs.append(hn, hv);
        }
    }

    // :method, :scheme, :path are mandatory for non-CONNECT requests (§8.1.2.3).
    let (Some(method), true, Some(path)) = (method, scheme, path) else {
        return Err(bad());
    };
    if path.is_empty() {
        return Err(bad());
    }
    let method = Method::from_bytes(&method).map_err(|_| bad())?;
    // The :path is origin-form (e.g. `/x?y`); the URI carries just that. The
    // :authority rides as `Host`, which is what a gateway routes on.
    let uri = Uri::try_from(path.as_slice()).map_err(|_| bad())?;
    if let Some(auth) = authority {
        let hv = HeaderValue::from_bytes(&auth).map_err(|_| bad())?;
        hdrs.insert(header::HOST, hv);
    }

    let mut req = http::Request::new(Bytes::new());
    *req.method_mut() = method;
    *req.uri_mut() = uri;
    *req.version_mut() = Version::HTTP_2;
    *req.headers_mut() = hdrs;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        pairs.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect()
    }

    #[test]
    fn valid_request_parses() {
        let req = request_from_headers(
            1,
            h(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/x"),
                (b":authority", b"h"),
                (b"accept", b"*/*"),
            ]),
        )
        .unwrap();
        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().path(), "/x");
        assert_eq!(req.headers().get("accept").unwrap(), "*/*");
        assert_eq!(req.headers().get(header::HOST).unwrap(), "h");
    }

    #[test]
    fn malformed_requests_are_stream_protocol_errors() {
        let bad = H2Error::stream(1, ErrorCode::ProtocolError);
        // `http::Request` isn't `PartialEq`, so assert on the error (a stream reset).
        let err = |pairs: &[(&[u8], &[u8])]| request_from_headers(1, h(pairs)).unwrap_err();
        // uppercase header name
        assert_eq!(err(&[(b":Method", b"GET")]), bad);
        // pseudo after regular
        assert_eq!(err(&[(b"accept", b"x"), (b":method", b"GET")]), bad);
        // missing :path
        assert_eq!(err(&[(b":method", b"GET"), (b":scheme", b"https")]), bad);
        // connection-specific header
        assert_eq!(
            err(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b"connection", b"keep-alive"),
            ]),
            bad
        );
        // unknown pseudo-header
        assert_eq!(
            err(&[(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":bogus", b"x")]),
            bad
        );
    }
}
