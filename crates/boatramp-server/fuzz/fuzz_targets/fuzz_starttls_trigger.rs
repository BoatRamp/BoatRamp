#![no_main]
//! Fuzz the STARTTLS trigger-line matcher: the one client-controlled line the host itself
//! inspects on a plaintext SMTP/IMAP/POP3 listener before upgrading to TLS — every other line of
//! the dialog is the guest's own protocol output, never parsed by the host (see
//! ../src/tcp_starttls.rs's module doc). Exercised against both grammar shapes boatramp ships:
//! untagged (SMTP `STARTTLS`, POP3 `STLS`) and tagged (IMAP `<tag> STARTTLS`).
//! The stable regression net lives in ../src/tcp_starttls.rs's own `match_trigger_*` tests.
use boatramp_server::tcp_starttls::{match_trigger, StarttlsGrammar};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let untagged = StarttlsGrammar {
        trigger: "STARTTLS".to_string(),
        response: "220 ready".to_string(),
        tag_capture: false,
    };
    let tagged = StarttlsGrammar {
        trigger: "STARTTLS".to_string(),
        response: "{tag} OK begin TLS".to_string(),
        tag_capture: true,
    };
    let _ = match_trigger(data, &untagged);
    let _ = match_trigger(data, &tagged);
});
