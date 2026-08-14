// A GraphQL federation **subgraph** guest: the `agent` subgraph. It owns a `Mutation` root
// field, `agent(input: String)`, so the federation-gateway *mutation* path can be exercised
// end to end. This is the fixture whose absence let a broken planner ship: the gateway once
// dispatched a Mutation to its subgraph as an anonymous *query*, so the Mutation-typed field
// never resolved (data:null), and it dropped the argument. This guest **echoes the argument
// it actually received** back to the caller, so the e2e test can prove the mutation keyword
// *and* the argument survived the whole router → planner → gateway → invoke path — something a
// canned-response fixture could not show.
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

        // The subgraph MUST have been sent a `mutation` operation — an anonymous/query op is
        // the shipped bug, and here it surfaces as an explicit error rather than silently
        // resolving, so the e2e assertion is unambiguous.
        if !query.trim_start().starts_with("mutation") {
            let err = json!({ "data": null, "errors": [
                { "message": format!("agent subgraph expected a `mutation`, got: {query}") }
            ] });
            respond(outparam, 200, err.to_string().as_bytes());
            return;
        }

        // The `input` argument must have arrived — inline in the query text, or as a
        // forwarded variable. Echo it so the caller can assert it survived end to end.
        let input = argument_value(query, &req).unwrap_or_else(|| "<missing>".to_string());
        let out = json!({ "data": { "agent": format!("ran:{input}") } });
        respond(outparam, 200, out.to_string().as_bytes());
    }
}

/// Extract the `agent(input: …)` value: the forwarded variable (`variables.input`) if the
/// query uses `$input`, else the inline string literal in the query text.
fn argument_value(query: &str, req: &Value) -> Option<String> {
    if query.contains("input: $") {
        return req
            .pointer("/variables/input")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    // Inline: `agent(input: "hi")` — pull the text between the first pair of quotes after
    // `input:`. A fixture parser, deliberately minimal (a real subgraph uses its GraphQL lib).
    let after = query.split("input:").nth(1)?;
    let start = after.find('"')? + 1;
    let end = after[start..].find('"')? + start;
    Some(after[start..end].to_string())
}

/// Read the incoming request body fully into memory (a federation fetch is small).
fn read_body(request: IncomingRequest) -> Vec<u8> {
    let Ok(body) = request.consume() else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if let Ok(stream) = body.stream() {
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
