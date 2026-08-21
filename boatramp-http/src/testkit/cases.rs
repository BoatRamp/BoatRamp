//! The curated request-head corpus, grouped by protocol aspect — the auditable
//! completeness checklist. Each case is an input + the verdict `parse_request_head` must
//! produce. Combinatorial gaps (the full CL×TE matrix, whitespace/version permutations)
//! are filled by [`super::gen`]; chunk-body and response framing have their own suites.

use super::{Aspect::*, Case, Expect::*, Framing::*};

const fn c(
    aspect: super::Aspect,
    name: &'static str,
    input: &'static [u8],
    expect: super::Expect,
) -> Case {
    Case {
        aspect,
        name,
        input,
        expect,
    }
}

// ---- A. Request line (RFC 9112 §3) ------------------------------------------
pub const REQUEST_LINE: &[Case] = &[
    c(
        RequestLine,
        "GET origin-form",
        b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "path + query",
        b"GET /a?b=1&c=2 HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "unknown method (token)",
        b"PURGE /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "lowercase method is a valid token",
        b"get /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "HTTP/1.0",
        b"GET /a HTTP/1.0\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "OPTIONS asterisk-form",
        b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "absolute-form (proxy)",
        b"GET http://h/p HTTP/1.1\r\nHost: h\r\n\r\n",
        Accept(Empty),
    ),
    c(
        RequestLine,
        "one leading CRLF tolerated (RFC 9112 §2.2)",
        b"\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    // rejects
    c(
        RequestLine,
        "empty method",
        b" /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "method with non-tchar (comma)",
        b"GE,T /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "NUL in method",
        b"GE\x00T /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "double SP in request line",
        b"GET  /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "tab as request-line delimiter",
        b"GET\t/a HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "space in target",
        b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "control byte in target",
        b"GET /a\x01b HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "fragment in target",
        b"GET /a#f HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "asterisk-form for GET (only OPTIONS)",
        b"GET * HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "missing version",
        b"GET /a\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "not an h1 version (2.0)",
        b"GET /a HTTP/2.0\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "truncated version HTTP/1",
        b"GET /a HTTP/1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "version with extra dot",
        b"GET /a HTTP/1.1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "lowercase http name",
        b"GET /a http/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "leading-zero version",
        b"GET /a HTTP/01.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "space inside version token",
        b"GET /a HTTP /1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "bare-LF request line",
        b"GET /a HTTP/1.1\nHost: x\r\n\r\n",
        Reject,
    ),
    c(
        RequestLine,
        "leading space (not CRLF)",
        b" GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
        Reject,
    ),
    // incomplete
    c(
        RequestLine,
        "partial request line",
        b"GET /a HT",
        Incomplete,
    ),
];

// ---- B. Header field syntax (RFC 9110 §5, RFC 9112 §5) ----------------------
pub const HEADER_SYNTAX: &[Case] = &[
    c(
        HeaderSyntax,
        "simple header",
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Foo: bar\r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "empty value",
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Empty:\r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "OWS trimmed around value",
        b"GET / HTTP/1.1\r\nHost: x\r\nX:   v   \r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "internal spaces preserved",
        b"GET / HTTP/1.1\r\nHost: x\r\nX: a b c\r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "HTAB in value is allowed",
        b"GET / HTTP/1.1\r\nHost: x\r\nX: a\tb\r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "case-insensitive name",
        b"GET / HTTP/1.1\r\nHOST: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "no space after colon",
        b"GET / HTTP/1.1\r\nHost:x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        HeaderSyntax,
        "duplicate non-special header ok",
        b"GET / HTTP/1.1\r\nHost: x\r\nX: a\r\nX: b\r\n\r\n",
        Accept(Empty),
    ),
    // rejects
    c(
        HeaderSyntax,
        "missing colon",
        b"GET / HTTP/1.1\r\nHost: x\r\nBadHeader\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "space before colon",
        b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "tab before colon",
        b"GET / HTTP/1.1\r\nHost\t: x\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "space in name",
        b"GET / HTTP/1.1\r\nX Foo: v\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "non-tchar in name (@)",
        b"GET / HTTP/1.1\r\nX@Foo: v\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "empty name",
        b"GET / HTTP/1.1\r\n: v\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "control byte in value",
        b"GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "NUL in value",
        b"GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "bare CR in header block",
        b"GET / HTTP/1.1\r\nHost: x\rX: v\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "bare LF header separator",
        b"GET / HTTP/1.1\r\nHost: x\nX: v\r\n\r\n",
        Reject,
    ),
    c(
        HeaderSyntax,
        "obs-fold continuation",
        b"GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n b\r\n\r\n",
        Reject,
    ),
    // incomplete
    c(
        HeaderSyntax,
        "no CRLFCRLF yet",
        b"GET / HTTP/1.1\r\nHost: x\r\n",
        Incomplete,
    ),
];

// ---- C. Content-Length (RFC 9110 §8.6) --------------------------------------
pub const CONTENT_LENGTH: &[Case] = &[
    c(
        ContentLength,
        "zero",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        Accept(Length(0)),
    ),
    c(
        ContentLength,
        "positive",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\n",
        Accept(Length(12)),
    ),
    c(
        ContentLength,
        "leading zeros (valid DIGITs)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 007\r\n\r\n",
        Accept(Length(7)),
    ),
    c(
        ContentLength,
        "trailing OWS trimmed",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5 \r\n\r\n",
        Accept(Length(5)),
    ),
    c(
        ContentLength,
        "case-insensitive name",
        b"POST / HTTP/1.1\r\nHost: x\r\ncontent-length: 5\r\n\r\n",
        Accept(Length(5)),
    ),
    // rejects
    c(
        ContentLength,
        "empty value",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length:\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "plus sign",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "minus sign",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "decimal",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5.0\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "hex",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "internal space",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5 6\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "comma list differing",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 6\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "comma list same",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "u64 overflow",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999999999\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "duplicate differing",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        Reject,
    ),
    c(
        ContentLength,
        "duplicate same (still ambiguous)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        Reject,
    ),
];

// ---- C. Transfer-Encoding (RFC 9112 §6.1) -----------------------------------
pub const TRANSFER_ENCODING: &[Case] = &[
    c(TransferEncoding, "chunked", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", Accept(Chunked)),
    c(TransferEncoding, "Chunked (case)", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n", Accept(Chunked)),
    c(TransferEncoding, "trailing OWS", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked \r\n\r\n", Accept(Chunked)),
    c(TransferEncoding, "gzip then chunked (chunked final)", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", Accept(Chunked)),
    c(TransferEncoding, "case-insensitive name", b"POST / HTTP/1.1\r\nHost: x\r\ntransfer-encoding: chunked\r\n\r\n", Accept(Chunked)),
    // rejects
    c(TransferEncoding, "chunked not final", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", Reject),
    c(TransferEncoding, "no chunked (gzip only)", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n", Reject),
    c(TransferEncoding, "identity only", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\n\r\n", Reject),
    c(TransferEncoding, "duplicate TE both chunked", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", Reject),
    c(TransferEncoding, "duplicate TE last chunked", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n", Reject),
    c(TransferEncoding, "double chunked in one value", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", Reject),
    c(TransferEncoding, "chunked with junk suffix", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunkedX\r\n\r\n", Reject),
    c(TransferEncoding, "empty list element", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: ,chunked\r\n\r\n", Reject),
    // TE on an HTTP/1.0 request — chunked is 1.1-only, so this is a desync setup
    // (found by the randomized differential vs hyper).
    c(TransferEncoding, "chunked on HTTP/1.0", b"POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", Reject),
];

// ---- C. The CL×TE framing matrix (a few anchors; gen.rs does the full grid) --
pub const FRAMING_MATRIX: &[Case] = &[
    c(
        FramingMatrix,
        "neither → empty",
        b"POST / HTTP/1.1\r\nHost: x\r\n\r\n",
        Accept(Empty),
    ),
    c(
        FramingMatrix,
        "CL + TE:chunked",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
        Reject,
    ),
    c(
        FramingMatrix,
        "TE:chunked + CL (order swapped)",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n",
        Reject,
    ),
    c(
        FramingMatrix,
        "obfuscated TE name + CL",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding\t: chunked\r\nContent-Length: 6\r\n\r\n",
        Reject,
    ),
];

// ---- E. Host (RFC 9110 §7.2, RFC 9112 §3.2) ---------------------------------
pub const HOST: &[Case] = &[
    c(
        Host,
        "single Host",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        Accept(Empty),
    ),
    c(
        Host,
        "Host with port",
        b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
        Accept(Empty),
    ),
    c(
        Host,
        "missing Host in 1.1",
        b"GET / HTTP/1.1\r\n\r\n",
        Reject,
    ),
    c(
        Host,
        "duplicate Host",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        Reject,
    ),
    c(
        Host,
        "empty Host in 1.1",
        b"GET / HTTP/1.1\r\nHost: \r\n\r\n",
        Reject,
    ),
    c(
        Host,
        "HTTP/1.0 without Host is ok",
        b"GET / HTTP/1.0\r\n\r\n",
        Accept(Empty),
    ),
];

// ---- F. Connection / Expect (RFC 9110 §7.6.1, §10.1.1) ----------------------
pub const CONNECTION: &[Case] = &[
    c(
        Connection,
        "Connection: close",
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        Accept(Empty),
    ),
    c(
        Connection,
        "Connection: keep-alive",
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
        Accept(Empty),
    ),
    c(
        Connection,
        "Expect: 100-continue",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
        Accept(Length(3)),
    ),
];

// ---- G. Limits / DoS (bounds; concrete sizes live in tests/limits.rs) -------
pub const LIMITS: &[Case] = &[
    c(Limits, "empty buffer is incomplete", b"", Incomplete),
    c(Limits, "just CRLF is incomplete", b"\r\n", Incomplete),
];

/// Every per-aspect table — the full head-level checklist.
pub const ALL: &[&[Case]] = &[
    REQUEST_LINE,
    HEADER_SYNTAX,
    CONTENT_LENGTH,
    TRANSFER_ENCODING,
    FRAMING_MATRIX,
    HOST,
    CONNECTION,
    LIMITS,
];
