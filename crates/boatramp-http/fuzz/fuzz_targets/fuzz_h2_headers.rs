#![no_main]
//! Fuzz the full attacker-controlled-bytes pipeline for an HTTP/2 request head: a raw HPACK
//! header block, decoded by [`Hpack::decode`] (fuzzed on its own by `fuzz_hpack`), then handed
//! to [`request_from_headers`] — the pseudo-header validation + `http::Request` construction
//! step `fuzz_hpack` doesn't reach. A decoded header list is still fully attacker-shaped (names,
//! values, ordering, duplicates, byte content), so this is the closer analogue to what the h2
//! driver actually does with one incoming HEADERS block.
use boatramp_http::h2::hpack::Hpack;
use boatramp_http::h2::http::request_from_headers;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut h = Hpack::new();
    if let Ok(pairs) = h.decode(data) {
        let _ = request_from_headers(1, pairs);
    }
});
