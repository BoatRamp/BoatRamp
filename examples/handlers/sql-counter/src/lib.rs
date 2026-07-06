// A wasi:http handler that uses the boatramp `sql` capability: each request
// inserts a row into a per-site table and returns the running row count.
// Exercises the engine's sql host binding (open + execute + query, one
// transaction per invocation) end to end. The host scopes the database to the
// calling site.
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
        match count_rows() {
            Ok(rows) => respond(outparam, 200, format!("rows={rows}\n").as_bytes()),
            // Surface a binding failure (e.g. capability not granted) as a 500.
            Err(message) => respond(outparam, 500, message.as_bytes()),
        }
    }
}

fn count_rows() -> Result<i64, String> {
    let db = sql_query::open("").map_err(|err| format!("open: {err:?}"))?;
    db.execute("CREATE TABLE IF NOT EXISTS hits (id INTEGER)", &[])
        .map_err(|err| format!("create: {err:?}"))?;
    db.execute("INSERT INTO hits (id) VALUES (?1)", &[Value::Integer(1)])
        .map_err(|err| format!("insert: {err:?}"))?;
    let result = db
        .query("SELECT count(*) FROM hits", &[])
        .map_err(|err| format!("query: {err:?}"))?;
    match result.rows.first().and_then(|row| row.values.first()) {
        Some(Value::Integer(n)) => Ok(*n),
        other => Err(format!("unexpected count cell: {other:?}")),
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
