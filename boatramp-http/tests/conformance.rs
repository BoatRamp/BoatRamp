//! RFC 9112 conformance for the request-head parser: well-formed requests parse to the
//! expected method / target / body-framing, and clearly-malformed shapes are rejected.
//!
//! RED until `parse_request_head` is implemented — that is the point (TDD): the contract
//! is nailed down here before the parser exists.

use boatramp_http::h1::{parse_request_head, BodyFraming, ParseResult, RequestHead};

fn complete(buf: &[u8]) -> (RequestHead, usize) {
    match parse_request_head(buf) {
        ParseResult::Complete { head, consumed } => (head, consumed),
        other => panic!("expected Complete, got {other:?}"),
    }
}

fn framing(buf: &[u8]) -> BodyFraming {
    complete(buf).0.framing
}

fn is_reject(buf: &[u8]) -> bool {
    matches!(parse_request_head(buf), ParseResult::Reject(_))
}

fn is_incomplete(buf: &[u8]) -> bool {
    matches!(parse_request_head(buf), ParseResult::Incomplete)
}

#[test]
fn simple_get_has_no_body_and_consumes_the_whole_head() {
    let buf = b"GET /path?q=1 HTTP/1.1\r\nHost: example\r\nAccept: */*\r\n\r\n";
    let (head, consumed) = complete(buf);
    assert_eq!(head.method, http::Method::GET);
    assert_eq!(head.uri.path(), "/path");
    assert_eq!(head.uri.query(), Some("q=1"));
    assert_eq!(head.version, http::Version::HTTP_11);
    assert_eq!(head.headers.get("host").unwrap(), "example");
    assert_eq!(head.framing, BodyFraming::Empty);
    // A head-only buffer is fully consumed; the body (none here) begins at the end.
    assert_eq!(consumed, buf.len());
}

#[test]
fn content_length_gives_a_fixed_length_body() {
    assert_eq!(
        framing(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\n"),
        BodyFraming::Length(12)
    );
    // Zero-length is a valid explicit empty body.
    assert_eq!(
        framing(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
        BodyFraming::Length(0)
    );
}

#[test]
fn transfer_encoding_chunked_gives_a_chunked_body() {
    assert_eq!(
        framing(b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"),
        BodyFraming::Chunked
    );
    // Case-insensitive token, optional whitespace — still chunked.
    assert_eq!(
        framing(b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:  Chunked \r\n\r\n"),
        BodyFraming::Chunked
    );
}

#[test]
fn http_1_0_is_accepted_and_versioned() {
    let (head, _) = complete(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n");
    assert_eq!(head.version, http::Version::HTTP_10);
}

#[test]
fn a_partial_head_is_incomplete_not_a_reject() {
    assert!(is_incomplete(b"GET / HTTP/1.1\r\nHost: exa"));
    assert!(is_incomplete(b"GET / HTTP/1.1\r\n\r")); // one byte shy of CRLFCRLF
    assert!(is_incomplete(b"")); // empty
}

#[test]
fn malformed_request_lines_are_rejected() {
    assert!(is_reject(b"GET /\r\n\r\n")); // no version
    assert!(is_reject(b"GET  /  HTTP/1.1\r\n\r\n")); // double spaces in the request line
    assert!(is_reject(b"GET / HTTP/2.0\r\nHost: x\r\n\r\n")); // not an h1 version
    assert!(is_reject(b"G\x00ET / HTTP/1.1\r\n\r\n")); // NUL in the method
}

#[test]
fn malformed_headers_are_rejected() {
    // Missing colon.
    assert!(is_reject(b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n"));
    // Space before the colon (RFC 9112 §5.1 forbids it; a classic parser-divergence).
    assert!(is_reject(b"GET / HTTP/1.1\r\nHost : x\r\n\r\n"));
    // Control byte in the header value.
    assert!(is_reject(b"GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n"));
}
