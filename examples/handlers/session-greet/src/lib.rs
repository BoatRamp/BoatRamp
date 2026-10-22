// A boatramp *session* guest that GREETS FIRST (mailroom cap-req 17): on the first re-entry that
// has not yet checkpointed `greeted`, it `send`s a banner before looking at any inbound frames —
// including a re-entry that carries NO frames at all, which is exactly the host's connect-time
// dispatch (`frames: []`, `resumed: none`), invoked once before the first inbound read. This
// mirrors a server-speaks-first protocol's opening line (IMAP `* OK`, SMTP `220`, POP3 `+OK`).
//
// State machine per re-entry:
//   - rehydrate `greeted: bool` from the 1-byte resume checkpoint (absent/empty == not greeted),
//   - if not yet greeted: `send` the banner, then treat the connection as greeted from here on,
//   - for each inbound frame (if any): `cancel` closes the session; anything else gets echoed back
//     prefixed `GOT:` (so a test can prove normal operation continues after the greeting),
//   - checkpoint the (now-)greeted flag, so ANY later re-entry on this SAME connection — including a
//     hypothetical redelivery of the connect dispatch — sees `greeted` already set and never sends
//     the banner twice. Double-greet is therefore impossible without a brand-new connection (a fresh,
//     unresumed checkpoint), exactly the host-side guarantee cap-req 17 relies on.
wit_bindgen::generate!({
    world: "boatramp:caps-example/session-greet",
    path: "wit",
    generate_all,
});

use boatramp::handlers::session;
use boatramp::handlers::session_types::{SessionError, SessionInput};
use exports::boatramp::handlers::session_handler::Guest;

/// The unsolicited connect-time banner — a stand-in for a real protocol's greeting line.
const GREETING: &[u8] = b"* OK session-greet ready\r\n";

struct Component;

impl Guest for Component {
    fn handle(input: SessionInput) -> Result<(), SessionError> {
        // `greeted` rehydrates from the resume checkpoint: `Some([1])` == already greeted on this
        // connection; `None` (never checkpointed — the very first re-entry, normally the host's
        // connect-time dispatch) or anything else == not yet greeted.
        let mut greeted = matches!(input.resumed.as_deref(), Some([1]));

        if !greeted {
            session::send(GREETING)?;
            greeted = true;
        }

        for frame in &input.frames {
            if frame.as_slice() == b"cancel" {
                session::close("client cancel")?;
                return Ok(());
            }
            let mut out = b"GOT:".to_vec();
            out.extend_from_slice(frame);
            session::send(&out)?;
        }

        // Persist the (now-)greeted flag so every later re-entry on this connection — a normal
        // inbound frame, or a would-be redelivered connect dispatch — sees it already set.
        session::checkpoint(&[greeted as u8])?;
        Ok(())
    }
}

export!(Component);
