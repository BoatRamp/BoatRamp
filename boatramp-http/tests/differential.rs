//! Differential oracle: the same raw byte stream is parsed by boatramp-http's h1 codec
//! and by hyper's HTTP/1 server, and the two must agree on how the stream splits into
//! request messages. A boundary disagreement between a proxy and its upstream *is* a
//! request-smuggling bug, so this is the primary correctness gate.
//!
//! Direction of the contract:
//! - On **well-formed** input (the corpus below) boatramp-http must parse the requests
//!   and agree with hyper on `(method, path, framing/body-length)` and the request
//!   count. (This is what makes the harness RED against the current stub — the stub
//!   parses nothing while hyper parses the requests.)
//! - boatramp-http may be *stricter* than hyper (reject where hyper accepts — see
//!   `smuggling.rs`); it must never be *more permissive* about message boundaries. That
//!   one-directional property is fuzzed in `fuzz_smoke.rs`.

use boatramp_http::h1::{parse_request_head, BodyFraming, ParseResult};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReqSummary {
    method: String,
    path: String,
    body_len: usize,
}

/// Parse the whole stream with hyper's HTTP/1 server, returning the requests it yields
/// (in order). Bodies are fully read so hyper advances to the next pipelined request.
async fn hyper_parse(bytes: &'static [u8]) -> Vec<ReqSummary> {
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, server) = tokio::io::duplex(1 << 16);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ReqSummary>();

    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let tx = tx.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let body_len = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes().len())
                .unwrap_or(0);
            let _ = tx.send(ReqSummary { method, path, body_len });
            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new()),
            ))
        }
    });

    let io = hyper_util::rt::TokioIo::new(server);
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);

    // Feed the request bytes, half-close so hyper sees EOF, and drain hyper's responses
    // so the duplex buffer never blocks it.
    let (mut rd, mut wr) = tokio::io::split(client);
    let driver = async move {
        let _ = wr.write_all(bytes).await;
        let _ = wr.shutdown().await;
        let mut sink = Vec::new();
        let _ = rd.read_to_end(&mut sink).await;
    };

    // A malformed stream makes `conn` error out; that's fine — we only want what hyper
    // parsed before it gave up. Bound the whole thing so a stalled parse can't hang.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let _ = tokio::join!(conn, driver);
    })
    .await;

    let mut out = Vec::new();
    while let Ok(s) = rx.try_recv() {
        out.push(s);
    }
    out
}

/// Parse the whole stream with boatramp-http's h1 codec: sequentially parse each request
/// head, then skip its body (per the resolved framing) to the next request. Returns the
/// requests it yields, or `Err` if it rejected / couldn't fully parse the stream.
fn boatramp_parse(mut buf: &[u8]) -> Result<Vec<ReqSummary>, ()> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (head, consumed) = match parse_request_head(buf) {
            ParseResult::Complete { head, consumed } => (head, consumed),
            // Trailing whitespace / a clean end between messages is fine.
            ParseResult::Incomplete if buf.iter().all(|b| *b == b'\r' || *b == b'\n') => break,
            _ => return Err(()),
        };
        let body_end = match head.framing {
            BodyFraming::Empty => consumed,
            BodyFraming::Length(n) => consumed + n as usize,
            BodyFraming::Chunked => match boatramp_http::h1::chunked::scan(&buf[consumed..]) {
                boatramp_http::h1::chunked::ChunkScan::Complete { end } => consumed + end,
                _ => return Err(()),
            },
        };
        if body_end > buf.len() {
            return Err(());
        }
        out.push(ReqSummary {
            method: head.method.to_string(),
            path: head.uri.path().to_string(),
            body_len: body_end - consumed,
        });
        buf = &buf[body_end..];
    }
    Ok(out)
}

/// Well-formed streams boatramp-http MUST parse and agree with hyper on.
const WELL_FORMED: &[&[u8]] = &[
    b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /a?q=1 HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n",
    b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
    b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    // pipelined: two requests back to back
    b"GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n",
    // pipelined with a body then a bodyless request
    b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /q HTTP/1.1\r\nHost: x\r\n\r\n",
];

#[tokio::test]
async fn boatramp_agrees_with_hyper_on_well_formed_streams() {
    let mut disagreements = Vec::new();
    for raw in WELL_FORMED {
        let ours = boatramp_parse(raw);
        let theirs = hyper_parse(raw).await;
        match ours {
            Ok(ours) if ours == theirs => {}
            other => disagreements.push(format!(
                "input {:?}\n  boatramp: {:?}\n  hyper:    {:?}",
                String::from_utf8_lossy(raw),
                other,
                theirs
            )),
        }
    }
    assert!(
        disagreements.is_empty(),
        "boatramp-http disagreed with hyper on well-formed streams:\n{}",
        disagreements.join("\n")
    );
}
