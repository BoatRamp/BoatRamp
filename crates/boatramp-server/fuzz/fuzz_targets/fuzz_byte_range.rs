#![no_main]
//! Fuzz the HTTP `Range:` header parser on the blob/static-file serving path: the client
//! controls the header text completely, and the parser's arithmetic (`end - start + 1`, suffix
//! clamping against the resource size) must never panic on any spec/size combination — a
//! malformed or unsatisfiable spec is simply `None` (caller responds `416`).
//! The stable regression net lives in ../src/content.rs's own `parse_ranges_*` tests.
use boatramp_server::content::parse_ranges;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes pick the resource size `total` (the parser's bounds/clamping all depend on
    // it); the rest is the raw header text, exactly as a client would send it.
    if data.len() < 8 {
        return;
    }
    let (total_bytes, spec_bytes) = data.split_at(8);
    let total = u64::from_le_bytes(total_bytes.try_into().expect("8 bytes"));
    if let Ok(spec) = std::str::from_utf8(spec_bytes) {
        let _ = parse_ranges(spec, total);
    }
});
