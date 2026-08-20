#![no_main]
//! Fuzz HPACK decode: the connection driver feeds it attacker-controlled header
//! blocks, so a malformed block must return an error, never panic (the underlying
//! codec asserts on over-limit dynamic-table-size updates — screened by `Hpack`).
use boatramp_h2::hpack::Hpack;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut h = Hpack::new();
    let _ = h.decode(data);
});
