// A boatramp *session* guest: the engine re-enters `handle` once per inbound frame
// batch (mechanism B — no in-memory state survives a re-entry; only a `checkpoint`
// does). It maintains a running echo counter that it rehydrates from the resume
// checkpoint, and for each inbound frame:
//   - `cancel`  -> closes the session (guest-initiated close) and stops,
//   - anything  -> sends `echo#<n>:<frame>` back (the outbound duplex), opaque bytes.
// After the batch it checkpoints the counter, so a reconnect/re-entry resumes the
// count — proving the resume mechanism. Exercises send + checkpoint + resumed +
// close end to end for the session live-capability gate.
wit_bindgen::generate!({
    world: "boatramp:caps-example/session",
    path: "wit",
    generate_all,
});

use boatramp::handlers::session;
use boatramp::handlers::session_types::{SessionError, SessionInput};
use exports::boatramp::handlers::session_handler::Guest;

struct Component;

impl Guest for Component {
    fn handle(input: SessionInput) -> Result<(), SessionError> {
        // Rehydrate the running echo count from the resume checkpoint (4 LE bytes), else start at 0.
        let mut count: u32 = match input.resumed.as_deref() {
            Some(&[a, b, c, d]) => u32::from_le_bytes([a, b, c, d]),
            _ => 0,
        };
        for frame in &input.frames {
            // A `cancel` frame ends the session from the guest side.
            if frame.as_slice() == b"cancel" {
                session::close("client cancel")?;
                return Ok(());
            }
            count += 1;
            let mut out = format!("echo#{count}:").into_bytes();
            out.extend_from_slice(frame);
            session::send(&out)?;
        }
        // Persist the counter so the next re-entry resumes it (mechanism B).
        session::checkpoint(&count.to_le_bytes())?;
        Ok(())
    }
}

export!(Component);
