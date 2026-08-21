//! The request-smuggling corpus — the security bar for the h1 parser.
//!
//! Each input is a shape that a lenient or divergent parser would forward with an
//! ambiguous message boundary, letting an attacker desync a proxy from its upstream. The
//! contract is **fail closed**: every one must be `Reject`, so nothing a downstream could
//! frame differently is ever proxied. Vectors are the classic CL/TE / chunked desync set
//! (PortSwigger / HTTP-Garden). RED until the parser lands — that's the TDD point.

use boatramp_http::h1::{parse_request_head, ParseResult};

fn is_reject(buf: &[u8]) -> bool {
    matches!(parse_request_head(buf), ParseResult::Reject(_))
}

/// `(label, raw request)` — each MUST be rejected.
const SMUGGLING: &[(&str, &[u8])] = &[
    (
        "CL + TE both present (CL.TE / TE.CL desync)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ),
    (
        "TE + CL, TE first",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
    ),
    (
        "two Content-Length, differing",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
    ),
    (
        "two Content-Length, same value (still ambiguous — reject)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
    ),
    (
        "comma-listed Content-Length (5, 6)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 6\r\n\r\n",
    ),
    (
        "Content-Length not a number (+5)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\n",
    ),
    (
        "Content-Length hex (0x5)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\n\r\n",
    ),
    (
        "Content-Length with internal space (5 6)",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5 6\r\n\r\n",
    ),
    (
        "TE final coding not chunked (chunked, identity)",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
    ),
    (
        "TE gzip only (no determinable request length)",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
    ),
    (
        "two Transfer-Encoding, last chunked (TE list-fold smuggling)",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n",
    ),
    (
        "double chunked",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
    ),
    (
        "TE value not exactly chunked (chunkedX)",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunkedX\r\n\r\n",
    ),
    (
        "tab before the colon on Transfer-Encoding (name obfuscation)",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding\t: chunked\r\nContent-Length: 6\r\n\r\n",
    ),
    (
        "space before the colon on Content-Length",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\n",
    ),
    (
        "bare-LF header separator (LF smuggling)",
        b"POST / HTTP/1.1\r\nHost: x\nContent-Length: 6\r\n\r\n",
    ),
    (
        "bare-CR inside the header block",
        b"POST / HTTP/1.1\r\nHost: x\rContent-Length: 6\r\n\r\n",
    ),
    (
        "obs-fold continuation of Content-Length",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n 0\r\n\r\n",
    ),
];

#[test]
fn every_smuggling_vector_is_rejected() {
    let leaked: Vec<&str> = SMUGGLING
        .iter()
        .filter(|(_, raw)| !is_reject(raw))
        .map(|(label, _)| *label)
        .collect();
    assert!(
        leaked.is_empty(),
        "these smuggling vectors were NOT rejected (fail-OPEN — a desync risk):\n{leaked:#?}"
    );
}
