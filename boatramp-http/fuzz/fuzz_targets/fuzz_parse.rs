#![no_main]
//! Panic-free + bounded: the parser must never panic and never claim to consume past the
//! buffer, on any input. The coverage-guided analogue of tests/fuzz_smoke.rs.
use boatramp_http::h1::{parse_request_head, ParseResult};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let ParseResult::Complete { consumed, .. } = parse_request_head(data) {
        assert!(consumed <= data.len(), "parser consumed past the buffer");
    }
});
