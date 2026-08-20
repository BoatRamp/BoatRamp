//! Request/response types, the [`Handler`] trait, and RFC 7540 §8.1.2 request
//! validation (the "malformed request" rules the benchmark prototype skipped:
//! pseudo-header ordering, mandatory pseudo-headers, connection-specific headers).

use std::future::Future;

use crate::error::{ErrorCode, H2Error};

/// A received HTTP/2 request. Regular headers exclude the pseudo-headers, which are
/// hoisted into their own fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub method: Vec<u8>,
    pub scheme: Vec<u8>,
    pub authority: Option<Vec<u8>>,
    pub path: Vec<u8>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// A response to send. In M1 the body is buffered; the M4 splice seam replaces the
/// body-send path with a zero-copy `splice()` writer for the large-body proxy case.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
    pub fn with_body(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }
    pub fn header(mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
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

/// Build a validated [`Request`] from a decoded header list. Malformed requests are
/// a **stream** error of type PROTOCOL_ERROR (RFC 7540 §8.1.2.6) so one bad request
/// resets its stream without killing the connection.
pub(crate) fn request_from_headers(
    id: u32,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Request, H2Error> {
    let bad = || H2Error::stream(id, ErrorCode::ProtocolError);
    let mut req = Request::default();
    let (mut method, mut scheme, mut path) = (false, false, false);
    let mut seen_regular = false;

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
                b":method" if !method => {
                    method = true;
                    req.method = value;
                }
                b":scheme" if !scheme => {
                    scheme = true;
                    req.scheme = value;
                }
                b":path" if !path => {
                    path = true;
                    req.path = value;
                }
                b":authority" if req.authority.is_none() => req.authority = Some(value),
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
            req.headers.push((name, value));
        }
    }

    // :method, :scheme, :path are mandatory for non-CONNECT requests (§8.1.2.3).
    if !(method && scheme && path) || req.path.is_empty() {
        return Err(bad());
    }
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
        assert_eq!(req.method, b"GET");
        assert_eq!(req.path, b"/x");
        assert_eq!(req.headers, h(&[(b"accept", b"*/*")]));
    }

    #[test]
    fn malformed_requests_are_stream_protocol_errors() {
        let bad = H2Error::stream(1, ErrorCode::ProtocolError);
        // uppercase header name
        assert_eq!(request_from_headers(1, h(&[(b":Method", b"GET")])), Err(bad));
        // pseudo after regular
        assert_eq!(
            request_from_headers(1, h(&[(b"accept", b"x"), (b":method", b"GET")])),
            Err(bad)
        );
        // missing :path
        assert_eq!(
            request_from_headers(1, h(&[(b":method", b"GET"), (b":scheme", b"https")])),
            Err(bad)
        );
        // connection-specific header
        assert_eq!(
            request_from_headers(
                1,
                h(&[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"connection", b"keep-alive"),
                ])
            ),
            Err(bad)
        );
        // unknown pseudo-header
        assert_eq!(
            request_from_headers(
                1,
                h(&[(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":bogus", b"x")])
            ),
            Err(bad)
        );
    }
}
