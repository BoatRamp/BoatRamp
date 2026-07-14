//! A boatramp function: a `wasi:http` component. It answers every request with a
//! greeting — edit `handle` to do the real work. The same component runs behind a
//! route (a handler), invoked by name, on a schedule, or from a queue/webhook.

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
        let path = request.path_with_query().unwrap_or_else(|| "/".to_string());
        let message = format!("hello from your boatramp function ({path})\n");

        let response = OutgoingResponse::new(Fields::new());
        response.set_status_code(200).unwrap();
        let body = response.body().unwrap();
        ResponseOutparam::set(outparam, Ok(response));

        let stream = body.write().unwrap();
        stream.blocking_write_and_flush(message.as_bytes()).unwrap();
        drop(stream);
        OutgoingBody::finish(body, None).unwrap();
    }
}

export!(Component);
