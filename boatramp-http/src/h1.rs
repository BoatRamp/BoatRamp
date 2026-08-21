//! The HTTP/1.1 codec.
//!
//! The request-head parser here is the security-critical surface of a reverse proxy:
//! HTTP/1.1's Content-Length vs Transfer-Encoding ambiguity is *the* classic
//! request-smuggling / desync vector, and unlike HTTP/2 (which has h2spec) there is no
//! ready-made conformance oracle. So this codec is built **test-first**: the `tests/`
//! harness — a differential oracle against `hyper`, a curated smuggling corpus, RFC 9112
//! conformance cases, and a randomized fuzz smoke — is written and wired *before* the
//! parser, and [`parse_request_head`] is only promoted from the stub below once that
//! harness is green. See `../boatramp-h2/DESIGN-serving.md`.
//!
//! The design invariant the harness enforces: **fail closed.** Any framing ambiguity is
//! a [`Reject`], never a guess — so nothing a downstream could interpret differently is
//! ever forwarded.

use http::{HeaderMap, Method, Uri, Version};

/// How a request message body is delimited (RFC 9112 §6). A request (unlike a response)
/// has no close-delimited body; absence of both framing headers means *no* body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyFraming {
    /// No message body — no `Transfer-Encoding`, no `Content-Length`.
    Empty,
    /// A fixed-length body of exactly this many octets.
    Length(u64),
    /// A chunked-transfer-coded body, terminated by a zero-size chunk (+ trailers).
    Chunked,
}

/// A parsed request head: the request line + header fields, with the body framing
/// already resolved (so the caller knows exactly where the body — and thus the next
/// pipelined request — begins).
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub framing: BodyFraming,
}

/// Why a request was rejected. Every ambiguous or malformed framing maps to one of
/// these (→ a `400`/`close`), never to a silent normalization — that is the anti-
/// smuggling contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Malformed request line (method/target/version token shape).
    BadRequestLine,
    /// HTTP version not `1.0`/`1.1`, or otherwise unacceptable.
    BadVersion,
    /// Malformed header field (name token / value bytes / missing colon).
    BadHeader,
    /// Obsolete line folding (a header line starting with SP/HTAB) — RFC 9112 §5.2.
    ObsFold,
    /// Bare CR or bare LF used as a line terminator where CRLF is required.
    BareCrlf,
    /// `Content-Length` unparsable, or multiple `Content-Length` with differing values.
    BadContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` present (CL/TE desync risk), or a
    /// duplicated framing that can't be reconciled.
    ConflictingFraming,
    /// `Transfer-Encoding` present but its final coding is not `chunked` (a request with
    /// no determinable length) — RFC 9112 §6.3.
    BadTransferEncoding,
    /// A bound was exceeded (request line, header block, header count, chunk-size line).
    TooLarge,
    /// Malformed chunked framing (chunk-size not hex / overflow / bad terminator).
    BadChunk,
}

/// The outcome of parsing one request head from the front of a buffer.
#[derive(Debug)]
pub enum ParseResult {
    /// A complete head was parsed; `consumed` bytes were the head (the body, per
    /// [`RequestHead::framing`], begins at `consumed`).
    Complete { head: RequestHead, consumed: usize },
    /// The buffer does not yet contain a full head (no CRLFCRLF); read more.
    Incomplete,
    /// The head is malformed or ambiguous — reject the connection (fail closed).
    Reject(Reject),
}

/// Parse a single HTTP/1.x request head (request line + header fields, up to and
/// including the terminating CRLFCRLF) from the front of `buf`, resolving the body
/// framing per RFC 9112 §6.
///
/// **Contract (enforced by the `tests/` harness before this is implemented):**
/// - Byte-for-byte agreement with `hyper`'s HTTP/1 parser on well-formed input, or a
///   `Reject` where `hyper` also refuses — never *more* permissive on message boundaries.
/// - Every smuggling vector in `tests/smuggling.rs` returns `Reject` (fail closed).
/// - Panic-free and desync-free on arbitrary bytes (`tests/fuzz_smoke.rs`).
pub fn parse_request_head(buf: &[u8]) -> ParseResult {
    // STUB — intentionally unimplemented. The verification harness is red until the
    // parser lands (Stage 2 of DESIGN-serving.md). `Incomplete` is the safe placeholder:
    // it never claims to have parsed anything, so no test passes spuriously.
    let _ = buf;
    ParseResult::Incomplete
}

// ---- response framing (the sender side — boatramp's own output) --------------

/// How a *response* body is delimited on the wire (RFC 9112 §6, sender side). Unlike a
/// request, a response body may be **close-delimited** (framed by connection close).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFraming {
    /// No body is sent regardless of headers — a `HEAD` response, a `1xx`/`204`/`304`
    /// status, or a `CONNECT` 2xx (RFC 9110 §6.4.1 / RFC 9112 §6.3).
    None,
    /// A fixed-length body (`Content-Length`).
    Length(u64),
    /// A chunked-transfer-coded body.
    Chunked,
    /// Framed by connection close (HTTP/1.0-style; forces `Connection: close`).
    CloseDelimited,
}

/// Decide how a response body is framed, encoding the no-body rules: a `HEAD` request,
/// or a `1xx`/`204`/`304` status, has no body no matter what `Content-Length`/
/// `Transfer-Encoding` say. Otherwise `Transfer-Encoding: chunked` → chunked, else a
/// `Content-Length` → that length, else close-delimited.
pub fn response_framing(
    status: u16,
    request_method: &Method,
    headers: &HeaderMap,
) -> ResponseFraming {
    // STUB — the harness (tests/response_framing.rs) is red until implemented.
    let _ = (status, request_method, headers);
    ResponseFraming::None
}

/// Encode a response head — status line (`HTTP/1.1 <code> <reason>`) + header fields +
/// the terminating CRLFCRLF. The reason phrase is the registered one for the status.
pub fn encode_response_head(status: u16, headers: &HeaderMap) -> Vec<u8> {
    // STUB — see above.
    let _ = (status, headers);
    Vec::new()
}

/// Chunked-transfer coding — decode (the request-side smuggling surface: chunk-size
/// lines, extensions, trailers) and encode (response-side body framing).
pub mod chunked {
    use http::HeaderMap;

    /// The outcome of scanning a chunked body for its end.
    #[derive(Debug)]
    pub enum ChunkScan {
        /// The chunked body (all data chunks + the terminating 0-chunk + trailers +
        /// final CRLF) ends at this byte offset into the buffer.
        Complete { end: usize },
        /// More bytes are needed to reach the terminating chunk.
        Incomplete,
        /// Malformed chunk framing — reject (fail closed).
        Reject(super::Reject),
    }

    /// Scan a chunked message body starting at the front of `buf`, returning where it
    /// ends. Rejects a non-hex/overflowing chunk size, bad chunk terminators, an
    /// oversized chunk-size line, or a forbidden trailer field.
    pub fn scan(buf: &[u8]) -> ChunkScan {
        // STUB — see `parse_request_head`. Harness is red until implemented.
        let _ = buf;
        ChunkScan::Incomplete
    }

    /// Encode one non-terminal chunk: `<hex-size>CRLF<data>CRLF`. `data` must be
    /// non-empty (an empty chunk is the terminator — use [`encode_last`]).
    pub fn encode(data: &[u8]) -> Vec<u8> {
        // STUB.
        let _ = data;
        Vec::new()
    }

    /// Encode the terminating chunk: `0CRLF` + the trailer section + the final CRLF.
    pub fn encode_last(trailers: &HeaderMap) -> Vec<u8> {
        // STUB.
        let _ = trailers;
        Vec::new()
    }
}
