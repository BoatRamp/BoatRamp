#![no_main]
//! Plan §2/§5/§6 (R5): feed arbitrary bytes into the hand-rolled SOCKS5 codec's greeting/auth +
//! request parse paths (the same `negotiate_auth` + `read_request` the real accept loop runs for
//! every client) and let `libfuzzer` hunt for a panic or unbounded-growth crash. All the harness
//! logic — including the reused current-thread runtime and the sink-backed in-memory stream — lives
//! in `boatramp_overlay_tunnel::socks::fuzz_one_request`'s own doc comment (shared with the stable,
//! non-nightly regression test next to it in-tree), so this target is deliberately a one-line call:
//! exactly one copy of that logic to reason about. Run with a nightly toolchain:
//!   cargo +nightly fuzz run fuzz_socks_codec
use boatramp_overlay_tunnel::socks::fuzz_one_request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_one_request(data);
});
