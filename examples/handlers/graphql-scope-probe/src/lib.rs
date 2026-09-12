// A GraphQL federation **subgraph** guest whose one root field (`items`) is **host-tenancy-scoped**:
// it answers with the rows of a shared `items` table confined to the caller's resolved tenant via the
// raw-SQL `{scope}` marker (the host fills it with `tenant_id = <resolved tenant>`; with no resolved
// principal the statement fails closed, so it can never leak another tenant's rows).
//
// It exists to prove the v0.4.6 change: `graphql::run` propagates the caller's resolved **principal**
// to a federated sub-fetch, so this subgraph — reached over the supergraph with NO request bearer —
// still resolves its own-tenancy from the inherited principal (symmetric to `emit::invoke`). Driven by
// the `graphql_run_propagates_principal_to_subfetch` live gate.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use boatramp::handlers::sql_query;
use boatramp::handlers::sql_types::Value;
use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct Component;

impl Guest for Component {
    fn handle(_request: IncomingRequest, outparam: ResponseOutparam) {
        // The gateway sends this subgraph its planned root fetch (`{ items { __typename id } }`); we
        // answer with the host-scoped rows. A scoped read with no resolved principal errors (fails
        // closed) — surfaced as a data-less GraphQL error so the gate sees zero leaked rows, never a
        // silent success.
        let body = match scoped_items() {
            Ok(items) => format!(r#"{{"data":{{"items":[{items}]}}}}"#),
            Err(message) => {
                format!(r#"{{"data":{{"items":null}},"errors":[{{"message":{message:?}}}]}}"#)
            }
        };
        respond(outparam, 200, body.as_bytes());
    }
}

fn scoped_items() -> Result<String, String> {
    let db = sql_query::open("").map_err(|err| format!("open: {err:?}"))?;
    // `{scope}` is host-filled with `tenant_id = <the caller's resolved tenant>` — here the tenant
    // *inherited* from the `graphql::run` caller's principal (v0.4.6). No principal ⇒ fail closed.
    let result = db
        .query("SELECT id FROM items WHERE {scope} ORDER BY id", &[])
        .map_err(|err| format!("query: {err:?}"))?;
    let items: Vec<String> = result
        .rows
        .iter()
        .filter_map(|row| match row.values.first() {
            Some(Value::Text(id)) => Some(format!(r#"{{"__typename":"Item","id":{id:?}}}"#)),
            _ => None,
        })
        .collect();
    Ok(items.join(","))
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
