#![no_main]
//! Plan §3.5/§5/§6: feed arbitrary bytes into the `smoltcp` netstack's ingress path (the same
//! pre-scan + `Interface::poll()` the real poll loop in `tun::netstack::run` exercises for every
//! inbound frame) and let `libfuzzer` hunt for a panic or unbounded-growth crash. All the actual
//! logic — including the "raw bytes" vs. "anchored to a real allocated address" dual-variant
//! design that gives the fuzzer a realistic shot at the deeper `Established`/data-transfer code
//! paths — lives in `boatramp_overlay_tunnel::tun::netstack::fuzz_one_frame`'s own doc comment;
//! this target is deliberately a one-line call so there is exactly one copy of that logic to
//! reason about (shared with the stable, non-nightly regression test next to it in-tree).
use boatramp_overlay_tunnel::tun::netstack::fuzz_one_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_one_frame(data);
});
