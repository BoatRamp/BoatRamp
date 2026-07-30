// A wasi:http handler that calls a sibling function through the boatramp
// `invoke` capability and returns the callee's response body. It invokes a
// function named `greeter` with a GET `/` and echoes what comes back, so a
// deployment can wire two functions together in-process (no network hop). The
// host gates which targets are callable (the `invoke_targets` allowlist) and
// caps call depth; an ungranted or disallowed call surfaces here as an error.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use boatramp::handlers::invoke;
use boatramp::handlers::invoke_types::{Error, InvokeRequest};
use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct Component;

impl Guest for Component {
    fn handle(_request: IncomingRequest, outparam: ResponseOutparam) {
        match call_greeter() {
            Ok(body) => respond(outparam, 200, &body),
            // A binding failure (capability not granted, target not allowed, the
            // callee erroring, a loop) is surfaced as a 500 with the reason.
            Err(message) => respond(outparam, 500, message.as_bytes()),
        }
    }
}

fn call_greeter() -> Result<Vec<u8>, String> {
    let request = InvokeRequest {
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let response = invoke::invoke("greeter", &request).map_err(describe)?;
    // Prefix the callee's body so the composition is visible in the response.
    let mut body = format!("greeter said ({}): ", response.status).into_bytes();
    body.extend_from_slice(&response.body);
    Ok(body)
}

fn describe(err: Error) -> String {
    match err {
        Error::AccessDenied => "invoke: capability not granted".to_string(),
        Error::TargetNotAllowed(t) => format!("invoke: target {t:?} not in the allowlist"),
        Error::NotFound(t) => format!("invoke: no function named {t:?}"),
        Error::LoopDetected => "invoke: call depth exceeded (loop guard)".to_string(),
        Error::Failed(reason) => format!("invoke: callee failed: {reason}"),
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

export!(Component);
