// A wasi:http handler that runs a GraphQL operation against the project's composed
// supergraph through the boatramp `graphql` capability, returning the supergraph response.
// It forwards its own Authorization bearer (so each subgraph's field guards see this guest's
// principal) and returns the stitched `{data, errors}` JSON. The host gates the capability
// (deny-by-default), enforces the operation safelist, and caps call depth; a refusal surfaces
// here as an error.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use boatramp::handlers::graphql;
use boatramp::handlers::graphql_types::{GraphqlError, GraphqlRequest};
use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        // Forward this request's own Authorization to the supergraph (re-verified per subgraph).
        let bearer = request
            .headers()
            .get(&"authorization".to_string())
            .into_iter()
            .next()
            .and_then(|v| String::from_utf8(v).ok());
        match run_supergraph(bearer) {
            Ok(body) => respond(outparam, 200, &body),
            Err(message) => respond(outparam, 500, message.as_bytes()),
        }
    }
}

fn run_supergraph(bearer: Option<String>) -> Result<Vec<u8>, String> {
    let request = GraphqlRequest {
        query: "{ me { name reviews { body } } }".to_string(),
        variables: "{}".to_string(),
        operation_name: None,
        bearer,
    };
    graphql::run(&request).map_err(describe)
}

fn describe(err: GraphqlError) -> String {
    match err {
        GraphqlError::AccessDenied => "graphql: capability not granted".to_string(),
        GraphqlError::NotSafelisted => "graphql: operation not on the safelist".to_string(),
        GraphqlError::PlanFailed(reason) => format!("graphql: cannot plan: {reason}"),
        GraphqlError::DepthExceeded => "graphql: call depth exceeded (loop guard)".to_string(),
        GraphqlError::Failed(reason) => format!("graphql: run failed: {reason}"),
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
