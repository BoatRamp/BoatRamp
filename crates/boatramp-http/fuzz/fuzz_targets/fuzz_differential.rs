#![no_main]
//! The differential smuggling target: for any input, if boatramp-http *accepts* a first
//! request, hyper must accept the same method+path. boatramp may be stricter (reject
//! where hyper accepts — the fail-closed direction), never more permissive about message
//! boundaries. A counterexample here is a candidate request-smuggling desync.
use boatramp_http::h1::{parse_request_head, ParseResult};
use libfuzzer_sys::fuzz_target;

fn hyper_first(bytes: Vec<u8>) -> Option<(String, String)> {
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async move {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(String, String)>();
        let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let tx = tx.clone();
            async move {
                let m = req.method().to_string();
                let p = req.uri().path().to_string();
                let _ = req.into_body().collect().await;
                let _ = tx.send((m, p));
                Ok::<_, std::convert::Infallible>(hyper::Response::new(
                    http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new()),
                ))
            }
        });
        let io = hyper_util::rt::TokioIo::new(server);
        let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
        let (mut rd, mut wr) = tokio::io::split(client);
        let driver = async move {
            let _ = wr.write_all(&bytes).await;
            let _ = wr.shutdown().await;
            let mut sink = Vec::new();
            let _ = rd.read_to_end(&mut sink).await;
        };
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            let _ = tokio::join!(conn, driver);
        })
        .await;
        rx.try_recv().ok()
    })
}

fuzz_target!(|data: &[u8]| {
    if let ParseResult::Complete { head, .. } = parse_request_head(data) {
        let ours = (head.method.to_string(), head.uri.path().to_string());
        match hyper_first(data.to_vec()) {
            Some(theirs) => assert_eq!(
                ours, theirs,
                "boatramp accepted a request hyper framed differently (smuggling desync)"
            ),
            None => panic!(
                "boatramp accepted {ours:?} but hyper rejected/parsed nothing (MORE PERMISSIVE)"
            ),
        }
    }
});
