//! Chunked transfer-coding decode (RFC 9112 §7) — the other request-smuggling surface:
//! chunk-size lines, extensions, terminators, and trailers. Table-driven over
//! `chunked::scan`, which returns where a chunked body ends (and thus where the next
//! pipelined request begins). RED until implemented.

use boatramp_http::h1::chunked::{scan, ChunkScan};

#[derive(Debug, PartialEq, Eq)]
enum Out {
    Complete(usize),
    Incomplete,
    Reject,
}

fn out(buf: &[u8]) -> Out {
    match scan(buf) {
        ChunkScan::Complete { end } => Out::Complete(end),
        ChunkScan::Incomplete => Out::Incomplete,
        ChunkScan::Reject(_) => Out::Reject,
    }
}

/// `(name, body, expected)` — `Complete(n)` means the chunked body ends at offset `n`.
const CASES: &[(&str, &[u8], Out)] = &[
    ("empty body (0-chunk only)", b"0\r\n\r\n", Out::Complete(5)),
    ("one data chunk", b"5\r\nhello\r\n0\r\n\r\n", Out::Complete(15)),
    ("hex size lowercase (a=10)", b"a\r\n0123456789\r\n0\r\n\r\n", Out::Complete(20)),
    ("hex size uppercase (A=10)", b"A\r\n0123456789\r\n0\r\n\r\n", Out::Complete(20)),
    ("chunk extension ignored", b"5;ext=1\r\nhello\r\n0\r\n\r\n", Out::Complete(21)),
    ("trailer field", b"0\r\nX-Trailer: v\r\n\r\n", Out::Complete(19)),
    // incomplete
    ("missing terminating chunk", b"5\r\nhello\r\n", Out::Incomplete),
    ("partial chunk data", b"5\r\nhel", Out::Incomplete),
    ("size line without CRLF yet", b"5", Out::Incomplete),
    // rejects (fail closed)
    ("non-hex size", b"z\r\nhello\r\n0\r\n\r\n", Out::Reject),
    ("0x-prefixed size", b"0x5\r\nhello\r\n", Out::Reject),
    ("negative size", b"-5\r\nhello\r\n", Out::Reject),
    ("size overflow (17 hex digits)", b"1ffffffffffffffff\r\nx\r\n", Out::Reject),
    ("data not followed by CRLF", b"5\r\nhelloX0\r\n\r\n", Out::Reject),
    ("bare-LF chunk framing", b"5\nhello\n0\n\n", Out::Reject),
    ("forbidden trailer field (Content-Length)", b"0\r\nContent-Length: 5\r\n\r\n", Out::Reject),
    ("forbidden trailer field (Transfer-Encoding)", b"0\r\nTransfer-Encoding: chunked\r\n\r\n", Out::Reject),
];

#[test]
fn chunked_scan_matches_the_corpus() {
    let failures: Vec<String> = CASES
        .iter()
        .filter_map(|(name, body, expect)| {
            let got = out(body);
            (&got != expect).then(|| {
                format!(
                    "  {name:<40} body={:?}  expect={expect:?}  got={got:?}",
                    String::from_utf8_lossy(body)
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "chunked::scan: {}/{} case(s) failed:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}
