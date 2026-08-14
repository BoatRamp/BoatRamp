// A wasi:http handler that exercises **named** SQL binding dispatch + least-privilege authz:
// it opens the default (`""`) database AND a named (`product`) one, writes a distinct marker to
// each, reads each back (proving they are distinct backends), and asserts that opening an
// un-granted name (`privileged`) is denied. The response summarizes all three so a conformance
// test can assert the whole named-dispatch story from a real guest.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use boatramp::handlers::sql_query::{self, Database};
use boatramp::handlers::sql_types::Value;
use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct Component;

impl Guest for Component {
    fn handle(_request: IncomingRequest, outparam: ResponseOutparam) {
        match run() {
            Ok(summary) => respond(outparam, 200, summary.as_bytes()),
            Err(message) => respond(outparam, 500, message.as_bytes()),
        }
    }
}

/// Open `name`, write `marker` into a table, and read it back from the same handle.
fn write_then_read(name: &str, marker: &str) -> Result<String, String> {
    let db: Database = sql_query::open(name).map_err(|err| format!("open {name:?}: {err:?}"))?;
    db.execute("CREATE TABLE IF NOT EXISTS t (v TEXT)", &[])
        .map_err(|err| format!("create {name:?}: {err:?}"))?;
    db.execute(
        "INSERT INTO t (v) VALUES (?1)",
        &[Value::Text(marker.to_string())],
    )
    .map_err(|err| format!("insert {name:?}: {err:?}"))?;
    let result = db
        .query("SELECT v FROM t LIMIT 1", &[])
        .map_err(|err| format!("query {name:?}: {err:?}"))?;
    match result.rows.first().and_then(|row| row.values.first()) {
        Some(Value::Text(v)) => Ok(v.clone()),
        other => Err(format!("unexpected cell for {name:?}: {other:?}")),
    }
}

fn run() -> Result<String, String> {
    // The default and the named `product` database each hold their own distinct data.
    let default_v = write_then_read("", "from-default")?;
    let product_v = write_then_read("product", "from-product")?;
    // Fail-closed: `privileged` was never granted to this handler, so opening it must be denied.
    let privileged_denied = sql_query::open("privileged").is_err();
    Ok(format!(
        "default={default_v} product={product_v} privileged_denied={privileged_denied}\n"
    ))
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
