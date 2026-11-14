//! Guest authorizer for a `guest_mediated` stream (stream-authz hardening gate).
//!
//! The host invokes this TOP-LEVEL function once per subscribe with the connection's request
//! (`GET <stream-route-path>`, plus the bearer / the host-verified `x-boatramp-stream-principal`
//! when the stream sets `token_claims`). It returns the per-subscriber topic set to grant, or a
//! non-2xx to refuse — the host then CONFINES the returned set to the stream's declared `topics`
//! templates (the ceiling), so an over-broad returned topic is clamped, never widened.
//!
//! Behaviour keys off the LAST path segment of the connection path (the per-connection scope the
//! stream route captures, e.g. `/events/shared/<mailbox>` ⇒ `<mailbox>`):
//!   * `<mailbox> == "deny"` ⇒ **403** (refuse) — exercises the no-oracle denial.
//!   * otherwise ⇒ **200** with a JSON array of three topics, only ONE of which matches the
//!     declared template `shared/{mailbox}/events`:
//!        `["shared/<mailbox>/events", "shared/<mailbox>/secret", "evil/<mailbox>/events"]`
//!     The host must confine the grant to `["shared/<mailbox>/events"]` (the `secret` tail and the
//!     `evil` namespace are dropped) — the clamp the confinement test asserts.
wit_bindgen::generate!({
    world: "wasi:http/proxy",
    path: "wit",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        let path = request.path_with_query().unwrap_or_default();
        // The per-connection scope is the last non-empty path segment (the `{mailbox}` capture).
        let mailbox = path
            .split('?')
            .next()
            .unwrap_or("")
            .trim_end_matches('/')
            .rsplit('/')
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_string();

        if mailbox == "deny" {
            // Refuse: any non-2xx denies. The host maps this to a 403 with NO oracle (the same 403
            // a non-member or a non-existent scope gets).
            refuse(outparam, 403);
            return;
        }

        // Grant three topics; only `shared/<mailbox>/events` matches the declared template — the
        // other two (`.../secret`, `evil/...`) MUST be clamped by the host's confinement.
        let body = format!(
            "[\"shared/{m}/events\",\"shared/{m}/secret\",\"evil/{m}/events\"]",
            m = mailbox
        );
        respond(outparam, 200, body.as_bytes());
    }
}

fn respond(outparam: ResponseOutparam, status: u16, message: &[u8]) {
    let resp = OutgoingResponse::new(Fields::new());
    resp.set_status_code(status).unwrap();
    let body = resp.body().unwrap();
    ResponseOutparam::set(outparam, Ok(resp));
    let stream = body.write().unwrap();
    stream.blocking_write_and_flush(message).unwrap();
    drop(stream);
    OutgoingBody::finish(body, None).unwrap();
}

fn refuse(outparam: ResponseOutparam, status: u16) {
    let resp = OutgoingResponse::new(Fields::new());
    resp.set_status_code(status).unwrap();
    let body = resp.body().unwrap();
    ResponseOutparam::set(outparam, Ok(resp));
    OutgoingBody::finish(body, None).unwrap();
}

export!(Component);
