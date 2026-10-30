#![no_main]
//! Fuzz the SETTINGS pipeline end-to-end: raw frame-payload bytes, through
//! [`frame::parse_settings`] (fuzzed on its own by `fuzz_frame`), into
//! [`h2::Settings::apply`] for every decoded `(id, value)` pair — the validation step
//! `fuzz_frame` doesn't reach (it only asserts the raw (id, value) decode never panics,
//! not what applying an attacker-chosen value to live connection state does).
use boatramp_http::h2::frame::parse_settings;
use boatramp_http::h2::Settings;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = parse_settings(data) {
        let mut settings = Settings::default();
        for (id, value) in entries {
            let _ = settings.apply(id, value);
        }
    }
});
