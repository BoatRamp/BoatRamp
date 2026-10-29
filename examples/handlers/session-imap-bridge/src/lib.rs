// A boatramp *session* guest that escalates to a PERSISTENT connection splice (mailroom cap-req #22
// — the transparent imap-proxy bridge). It is SERVER-SPEAKS-FIRST (greets on the connect-time
// dispatch, like `session-greet`), then on a `BRIDGE <host> <port>` command it calls
// `session::promote-connection` to hand the connection off to the host's persistent duplex splice:
// the host dials the named upstream through the SAME egress/connect gate as `tcp-egress` (posture +
// the listener's `egress_allowlist` + the SSRF floor), writes the guest's preamble, then splices
// client <-> upstream for the rest of the connection's life. This stands in for an IMAP bridge that,
// having authenticated a not-yet-migrated user, replays the login to the legacy server and then goes
// transparent.
//
// State machine per re-entry:
//   - rehydrate `greeted: bool` from the 1-byte resume checkpoint (absent/empty == not greeted),
//   - if not yet greeted: `send` the banner (even on the empty connect-time batch),
//   - for each inbound frame:
//       * `BRIDGE <host> <port>`  -> promote-connection (plaintext) with a fixed preamble. On `ok`
//         the splice takes over and the guest simply returns (it is never re-entered again on this
//         connection). On `err` (e.g. the upstream is not allowlisted -> `not-authorized`,
//         fail-closed) reply `REFUSED` and stay in the session model.
//       * anything else          -> echo back prefixed `GOT:` (so a test can prove normal operation),
//   - checkpoint the (now-)greeted flag.
wit_bindgen::generate!({
    world: "boatramp:caps-example/session-imap-bridge",
    path: "wit",
    generate_all,
});

use boatramp::handlers::session;
use boatramp::handlers::session_types::{PromoteTls, SessionError, SessionInput};
use exports::boatramp::handlers::session_handler::Guest;

/// The unsolicited connect-time banner (server-speaks-first), like a real protocol's greeting line.
const GREETING: &[u8] = b"* OK session-imap-bridge ready\r\n";

/// The opaque preamble written to the (authorized) upstream BEFORE splicing — stands in for a
/// replayed, client-tagged `LOGIN`. A test's fake upstream asserts it arrives first.
const PREAMBLE: &[u8] = b"PREAMBLE\r\n";

struct Component;

impl Guest for Component {
    fn handle(input: SessionInput) -> Result<(), SessionError> {
        let mut greeted = matches!(input.resumed.as_deref(), Some([1]));
        if !greeted {
            session::send(GREETING)?;
            greeted = true;
        }

        for frame in &input.frames {
            let line = String::from_utf8_lossy(frame);
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("BRIDGE ") {
                let mut parts = rest.split_whitespace();
                let host = parts.next().unwrap_or("");
                let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                // Promote through the reused egress gate. `ok` => the host splices this connection to
                // the upstream for the rest of its life and never re-enters us; `err` => fail-closed,
                // we tell the client and carry on in the session model.
                match session::promote_connection(host, port, PromoteTls::Plaintext, None, PREAMBLE)
                {
                    Ok(()) => return Ok(()),
                    Err(_e) => {
                        session::send(b"REFUSED\r\n")?;
                    }
                }
                continue;
            }
            let mut out = b"GOT:".to_vec();
            out.extend_from_slice(frame);
            session::send(&out)?;
        }

        session::checkpoint(&[greeted as u8])?;
        Ok(())
    }
}

export!(Component);
