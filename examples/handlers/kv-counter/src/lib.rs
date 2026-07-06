// A wasi:http handler that uses wasi:keyvalue: each request atomically
// increments a "hits" counter in the default bucket and returns its new value.
// Exercises the engine's keyvalue host binding (open + atomics.increment) end
// to end. The host scopes the bucket to the calling site (hkv/{site}/).
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};
use wasi::keyvalue::{atomics, store};

struct Component;

impl Guest for Component {
    fn handle(_request: IncomingRequest, outparam: ResponseOutparam) {
        match count_hit() {
            Ok(hits) => respond(outparam, 200, format!("hits={hits}\n").as_bytes()),
            // Surface a binding failure (e.g. capability not granted) as a 500.
            Err(message) => respond(outparam, 500, message.as_bytes()),
        }
    }
}

fn count_hit() -> Result<u64, String> {
    let bucket = store::open("").map_err(|err| format!("open: {err:?}"))?;
    atomics::increment(&bucket, "hits", 1).map_err(|err| format!("increment: {err:?}"))
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

export!(Component);
