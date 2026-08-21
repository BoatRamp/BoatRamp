//! HTTP/2 request decode (RFC 7540 §8.1.2): the pseudo-headers are hoisted **straight
//! into an `http::Request`** (a real `HeaderMap`, not an intermediate list), so a
//! reverse-proxy bridge hands the request to a tower/hyper service with no per-request
//! re-marshaling. The shared serving types ([`Request`]/[`Response`]/[`Body`]/
//! [`Handler`]) live at the crate root ([`crate::serving`]) and are re-exported here for
//! the h2 driver's internal use.

use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};

use crate::h2::error::{ErrorCode, H2Error};

pub use crate::serving::{response, Body, BodyChunk, BodyError, Handler, Request, Response};

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
