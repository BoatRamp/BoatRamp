#![no_main]
//! Panic-free + bounded for the chunked scanner on any input.
use boatramp_http::h1::chunked::{scan, ChunkScan};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let ChunkScan::Complete { end } = scan(data) {
        assert!(end <= data.len(), "chunk scan ran past the buffer");
    }
});
