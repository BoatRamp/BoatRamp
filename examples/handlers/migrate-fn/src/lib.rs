// A boatramp MIGRATION-FUNCTION guest. The orchestrator invokes it as a migration step with the
// step's `args` string as the request body; a live gate also invokes it as a NORMAL request to prove
// the context-gate. It dispatches on the first body token:
//
//   exec <sql>          run owner-role DDL/DML via migrate-ddl; 200 "exec-ok" / 500 "exec-err:<reason>"
//   query <sql>         run an owner-role verification query; 200 "<json>" / 500 "query-err:<reason>"
//   fail-after <sql>    run <sql> via migrate-ddl, then return 500 (a partial step that is NOT recorded)
//   sql-open            attempt sql-query::open(""); 200 "sql:present" / 200 "sql:absent" (binding-split)
//   (empty / other)     200 "noop"
//
// `<reason>` is the migrate-error kind: `not-a-migration` / `ledger-protected` / `txn-control` /
// `sql:<msg>` — so a gate can assert the exact refusal.
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use boatramp::handlers::migrate_ddl;
use boatramp::handlers::migrate_ddl_types::MigrateError;
use boatramp::handlers::sql_query;
use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        let body = read_body(request);
        let cmd = String::from_utf8_lossy(&body);
        let cmd = cmd.trim();
        let (verb, rest) = match cmd.split_once(' ') {
            Some((v, r)) => (v, r),
            None => (cmd, ""),
        };
        let (status, out): (u16, String) = match verb {
            "exec" => match migrate_ddl::exec(rest) {
                Ok(()) => (200, "exec-ok".to_string()),
                Err(e) => (500, format!("exec-err:{}", reason(&e))),
            },
            "query" => match migrate_ddl::query(rest) {
                Ok(json) => (200, json),
                Err(e) => (500, format!("query-err:{}", reason(&e))),
            },
            // Run the DDL, then FAIL: a partial step that must NOT be recorded (idempotent re-run).
            "fail-after" => match migrate_ddl::exec(rest) {
                Ok(()) => (500, "failed-after-partial-work".to_string()),
                Err(e) => (500, format!("exec-err:{}", reason(&e))),
            },
            // Binding-split probe: a migration invocation must have NO tenant sql binding.
            "sql-open" => match sql_query::open("") {
                Ok(_) => (200, "sql:present".to_string()),
                Err(_) => (200, "sql:absent".to_string()),
            },
            _ => (200, "noop".to_string()),
        };
        respond(outparam, status, out.as_bytes());
    }
}

fn reason(e: &MigrateError) -> String {
    match e {
        MigrateError::NotAMigration => "not-a-migration".to_string(),
        MigrateError::LedgerProtected => "ledger-protected".to_string(),
        MigrateError::TxnControl => "txn-control".to_string(),
        MigrateError::Sql(m) => format!("sql:{m}"),
    }
}

/// Drain the incoming request body to bytes (bounded loop; EOF is a closed stream).
fn read_body(request: IncomingRequest) -> Vec<u8> {
    let Ok(body) = request.consume() else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if let Ok(stream) = body.stream() {
        loop {
            match stream.blocking_read(64 * 1024) {
                Ok(chunk) if chunk.is_empty() => break,
                Ok(chunk) => buf.extend_from_slice(&chunk),
                Err(_) => break, // StreamError::Closed = EOF
            }
        }
    }
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
