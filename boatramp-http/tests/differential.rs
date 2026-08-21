//! Layer 3: the differential oracle. The same raw bytes are parsed by boatramp-http and
//! by hyper's HTTP/1 server; a boundary disagreement between a proxy and its upstream is
//! a request-smuggling bug, so agreement is the strongest correctness signal we have.
//!
//! Two properties:
//! - **Sequence agreement** (RED on the stub): on well-formed, possibly-pipelined input,
//!   boatramp-http must split the stream into the same request sequence hyper does.
//! - **Never more permissive** (a security net, green even on the stub): across the whole
//!   corpus + generators, wherever boatramp *accepts* a request, hyper must accept the
//!   same method+path. boatramp may be *stricter* (reject where hyper accepts — that's
//!   the fail-closed direction), never looser about message boundaries.

use boatramp_http::h1::{parse_request_head, BodyFraming, ParseResult};
use boatramp_http::testkit::{self, gen, verdict, Verdict};

/// A request identity used for boundary agreement: `(method, path)`. Body *length* is
/// deliberately not compared — hyper reports the decoded body size while boatramp reports
/// raw framing bytes (they differ for chunked), and the boundary-correctness property is
/// captured by the request *sequence* (a wrong boundary desyncs the next request's
/// method/path or the count).
type Req = (String, String);

/// Parse a whole stream with hyper's HTTP/1 server; returns the requests it dispatches.
///
/// hyper dispatches a request as soon as it has a full head+body — it does NOT need
/// connection EOF — so we write the bytes and drain dispatched requests until the channel
/// is idle. (Half-closing the write instead makes hyper report `IncompleteMessage` and
/// dispatch nothing — a harness gotcha that would have made this oracle useless.)
async fn hyper_parse(bytes: Vec<u8>) -> Vec<Req> {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;

    let (client, server) = tokio::io::duplex(1 << 16);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Req>();

    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let tx = tx.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let _ = req.into_body().collect().await;
            let _ = tx.send((method, path));
            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new()),
            ))
        }
    });

    let io = hyper_util::rt::TokioIo::new(server);
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
    let conn_handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    let (_rd, mut wr) = tokio::io::split(client);
    let _ = wr.write_all(&bytes).await;

    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match tokio::time::timeout(std::time::Duration::from_millis(60), rx.recv()).await {
            Ok(Some(r)) => out.push(r),
            _ => break, // idle (no new dispatch) or the channel closed
        }
        if tokio::time::Instant::now() > deadline {
            break;
        }
    }
    drop(wr);
    conn_handle.abort();
    out
}

/// Whether hyper accepts the **head** of `bytes` — dispatches on head-completion WITHOUT
/// draining the body, so a request declaring a body it hasn't sent yet still counts as
/// "hyper accepted this head" (rather than "hyper is still waiting for the body", which a
/// body-collecting service can't distinguish from a rejection). Returns hyper's
/// `(method, path)` for the first request, or `None` if hyper rejected / parsed nothing.
async fn hyper_accepts_head(bytes: Vec<u8>) -> Option<Req> {
    use tokio::io::AsyncWriteExt;

    let (client, server) = tokio::io::duplex(1 << 16);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Req>();
    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let tx = tx.clone();
        // Dispatch on the head alone — do NOT touch the body.
        let _ = tx.send((req.method().to_string(), req.uri().path().to_string()));
        async move { Ok::<_, std::convert::Infallible>(hyper::Response::new(
            http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new()),
        )) }
    });
    let io = hyper_util::rt::TokioIo::new(server);
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
    let conn_handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    let (_rd, mut wr) = tokio::io::split(client);
    let _ = wr.write_all(&bytes).await;
    let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
        .await
        .ok()
        .flatten();
    drop(wr);
    conn_handle.abort();
    got
}

/// Parse a whole stream with boatramp-http: head + body-skip per framing, to the next
/// request. `Err` if it rejected / couldn't fully consume the stream.
fn boatramp_parse(mut buf: &[u8]) -> Result<Vec<Req>, ()> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (head, consumed) = match parse_request_head(buf) {
            ParseResult::Complete { head, consumed } => (head, consumed),
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
        out.push((head.method.to_string(), head.uri.path().to_string()));
        buf = &buf[body_end..];
    }
    Ok(out)
}

const WELL_FORMED: &[&[u8]] = &[
    b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /a?q=1 HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n",
    b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
    b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n",
    b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /q HTTP/1.1\r\nHost: x\r\n\r\n",
];

#[tokio::test]
async fn agrees_with_hyper_on_well_formed_streams() {
    let mut disagreements = Vec::new();
    for raw in WELL_FORMED {
        let ours = boatramp_parse(raw);
        let theirs = hyper_parse(raw.to_vec()).await;
        if ours.as_ref().map(|o| o == &theirs).unwrap_or(false) {
            continue;
        }
        disagreements.push(format!(
            "input {:?}\n  boatramp: {:?}\n  hyper:    {:?}",
            String::from_utf8_lossy(raw),
            ours,
            theirs
        ));
    }
    assert!(
        disagreements.is_empty(),
        "boatramp-http disagreed with hyper on well-formed streams:\n{}",
        disagreements.join("\n")
    );
}

#[tokio::test]
async fn boatramp_is_never_more_permissive_than_hyper() {
    // Every single-request input from the curated corpus + the generators.
    let mut inputs: Vec<Vec<u8>> = testkit::all().iter().map(|c| c.input.to_vec()).collect();
    inputs.extend(gen::all().into_iter().map(|g| g.input));

    let mut violations = Vec::new();
    for input in inputs {
        if let Verdict::Accept { method, path, .. } = verdict(&input) {
            let hyper = hyper_accepts_head(input.clone()).await;
            let hyper_ok = hyper
                .as_ref()
                .is_some_and(|(m, p)| *m == method && *p == path);
            if !hyper_ok {
                violations.push(format!(
                    "boatramp accepted where hyper did not (MORE PERMISSIVE): {:?}\n  hyper: {:?}",
                    String::from_utf8_lossy(&input),
                    hyper
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "boatramp-http was more permissive than hyper on {} input(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
