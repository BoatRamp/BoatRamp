// A GraphQL federation **subgraph** guest: the `accounts` subgraph. It owns the `User`
// entity (keyed by `id`) and the `users` root field. boatramp's federation gateway
// dispatches the planned root fetch to this component over the in-process invoke path; it
// answers with two keyed users so the gateway can build `_entities` representations from
// the key + `__typename` it returns. A real subgraph is any GraphQL server exposing the
// federation contract (e.g. async-graphql); this fixture hand-answers the one root query
// the planner sends, which is all the serving-path end-to-end test exercises.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Component;

impl Guest for Component {
    fn handle(_request: IncomingRequest, outparam: ResponseOutparam) {
        // The gateway only ever sends this subgraph its root query (`{ users { … } }`),
        // so the answer is the keyed user list — each carries `__typename` + `id` so the
        // gateway can form the entity representations for the dependent `_entities` fetch.
        const USERS: &[u8] = br#"{"data":{"users":[{"__typename":"User","id":"1","name":"Alice"},{"__typename":"User","id":"2","name":"Bob"}]}}"#;
        respond(outparam, 200, USERS);
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
