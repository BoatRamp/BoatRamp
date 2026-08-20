#![no_main]
//! Fuzz the frame parsers: attacker-controlled bytes must never panic the parser.
use boatramp_h2::frame::{self, FrameHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = frame::parse_settings(data);
    let _ = frame::parse_window_update(data);
    let _ = frame::parse_rst_stream(data);
    let _ = frame::parse_ping(data);
    let _ = frame::parse_priority(data);
    let _ = frame::parse_goaway(data);
    let _ = frame::strip_padding(data, true);
    let _ = frame::strip_padding(data, false);
    if data.len() >= frame::FRAME_HEADER_LEN {
        let _ = FrameHeader::parse(data);
    }
});
