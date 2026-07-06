wit_bindgen::generate!({
    world: "wasi:http/proxy",
    path: "wit",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        // Branch on path so this one fixture exercises the engine's happy,
        // trap, timeout, and log-capture paths.
        let path = request.path_with_query().unwrap_or_default();
        match path.as_str() {
            "/panic" => panic!("boatramp test trap"), // -> HandlerError::Trap
            "/loop" => loop {
                // Spin forever -> the engine's epoch-deadline timeout fires.
                std::hint::spin_loop();
            },
            "/log" => {
                // Exercise host-side stdout/stderr capture.
                println!("hello to stdout");
                eprintln!("hello to stderr");
                respond(outparam, b"logged\n");
            }
            "/env" => {
                // Report a declared env var + whether a host var leaked through
                // (sandbox: the host env must NOT be inherited).
                let greeting = std::env::var("GREETING").unwrap_or_else(|_| "unset".into());
                let path_leaked = std::env::var("PATH").is_ok();
                respond(
                    outparam,
                    format!("greeting={greeting} path_leaked={path_leaked}").as_bytes(),
                );
            }
            _ => respond(outparam, b"hello from boatramp handler\n"),
        }
    }
}

fn respond(outparam: ResponseOutparam, message: &[u8]) {
    let resp = OutgoingResponse::new(Fields::new());
    resp.set_status_code(200).unwrap();
    let body = resp.body().unwrap();
    ResponseOutparam::set(outparam, Ok(resp));
    let stream = body.write().unwrap();
    stream.blocking_write_and_flush(message).unwrap();
    drop(stream);
    OutgoingBody::finish(body, None).unwrap();
}

export!(Component);
