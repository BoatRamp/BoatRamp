//! Randomized invariants the h1 parser must satisfy on *any* input — the stable-CI
//! analogue of a cargo-fuzz target (the same discipline caught a real HPACK panic in the
//! h2 codec). Unlike the other three suites, these must hold even for the current stub
//! (they are safety invariants, not behavioral expectations), so they stay green
//! throughout — a regression here means the parser can panic or desync on adversarial
//! bytes.

use boatramp_http::h1::{parse_request_head, ParseResult};

proptest::proptest! {
    /// The parser must never panic and must never claim to have consumed more bytes than
    /// it was given (a desync/overrun) on arbitrary input.
    #[test]
    fn parse_request_head_is_panic_free_and_bounded(data: Vec<u8>) {
        match parse_request_head(&data) {
            ParseResult::Complete { consumed, .. } => {
                proptest::prop_assert!(consumed <= data.len(), "consumed past the buffer");
            }
            ParseResult::Incomplete | ParseResult::Reject(_) => {}
        }
    }

    /// Same, restricted to printable ASCII — the shape real (and adversarial) HTTP heads
    /// actually take, so the fuzzer spends its budget near the interesting boundary.
    #[test]
    fn parse_request_head_is_panic_free_on_ascii(s in ".{0,4096}") {
        let _ = parse_request_head(s.as_bytes());
    }

    /// The chunked scanner must be panic-free and bounded too.
    #[test]
    fn chunked_scan_is_panic_free_and_bounded(data: Vec<u8>) {
        use boatramp_http::h1::chunked::{scan, ChunkScan};
        match scan(&data) {
            ChunkScan::Complete { end } => {
                proptest::prop_assert!(end <= data.len(), "chunk scan ran past the buffer");
            }
            ChunkScan::Incomplete | ChunkScan::Reject(_) => {}
        }
    }
}
