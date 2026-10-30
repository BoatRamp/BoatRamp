#![no_main]
//! Fuzz the overlay circuit frame codec: every byte a peer sends over a resumable circuit link
//! reaches `XgressFrame::decode` (the transport has already stripped the 4-byte length prefix)
//! before the duplex pump interprets it as `Payload`/`Ack`/`Fin`. A malformed frame body must be
//! rejected with a `FrameError`, never panic.
use boatramp_overlay_proto::XgressFrame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = XgressFrame::decode(data);
});
