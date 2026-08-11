// A GraphQL federation **subgraph** guest: the `reviews` subgraph. It resolves the
// `User.reviews` field the `accounts` subgraph does not own. boatramp's federation gateway
// dispatches a dependent `_entities` fetch to this component — a query whose
// `representations` variable holds one `{ __typename, id }` per user the gateway resolved
// upstream. This guest reads the request body, parses those representations, and resolves
// each **by its key, in representation order** (exactly what an async-graphql federation
// `_entities` resolver does), so the gateway can stitch each user to its own reviews.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest;
use serde_json::{json, Value};
use wasi::http::types::{
    Fields, IncomingBody, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        let body = read_body(request);
        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let query = req.get("query").and_then(Value::as_str).unwrap_or("");

        let out = if query.contains("_entities") {
            // Resolve each representation by its key, preserving order — the federation
            // `_entities` contract the gateway relies on to stitch positionally.
            let reprs = req
                .pointer("/variables/representations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let entities: Vec<Value> = reprs
                .iter()
                .map(|repr| {
                    let id = repr.get("id").and_then(Value::as_str).unwrap_or("");
                    json!({ "reviews": [ { "body": format!("review for {id}") } ] })
                })
                .collect();
            json!({ "data": { "_entities": entities } })
        } else {
            // The `topReviews` root field, were it ever queried directly.
            json!({ "data": { "topReviews": [ { "body": "a top review" } ] } })
        };

        respond(outparam, 200, out.to_string().as_bytes());
    }
}

/// Read the incoming request body fully into memory (a federation fetch is small).
fn read_body(request: IncomingRequest) -> Vec<u8> {
    let Ok(body) = request.consume() else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if let Ok(stream) = body.stream() {
        // `blocking_read` yields chunks until EOF, which it signals as an error
        // (`StreamError::Closed`); any error ends the read.
        while let Ok(chunk) = stream.blocking_read(8192) {
            if chunk.is_empty() {
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        drop(stream);
    }
    let _ = IncomingBody::finish(body);
    buf
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
