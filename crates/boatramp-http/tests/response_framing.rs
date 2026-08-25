//! Response framing (RFC 9110 §6.4.1, RFC 9112 §6) — boatramp's *output* side. The
//! no-body rules (HEAD, 1xx/204/304, CONNECT-2xx) override the framing headers; otherwise
//! chunked (if `Transfer-Encoding`) else `Content-Length` else close-delimited. Plus the
//! response-head encoding (status line + reason). RED until implemented.

use boatramp_http::h1::{encode_response_head, response_framing, ResponseFraming};
use http::{HeaderMap, Method};

fn hdr(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(
            http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    h
}

#[test]
fn body_framing_selection() {
    use ResponseFraming::*;
    let cases: &[(&str, u16, Method, HeaderMap, ResponseFraming)] = &[
        (
            "200 + Content-Length",
            200,
            Method::GET,
            hdr(&[("content-length", "5")]),
            Length(5),
        ),
        (
            "200 + TE: chunked",
            200,
            Method::GET,
            hdr(&[("transfer-encoding", "chunked")]),
            Chunked,
        ),
        (
            "200 no framing headers → close",
            200,
            Method::GET,
            hdr(&[]),
            CloseDelimited,
        ),
        (
            "HEAD suppresses the body",
            200,
            Method::HEAD,
            hdr(&[("content-length", "5")]),
            None,
        ),
        (
            "204 has no body",
            204,
            Method::GET,
            hdr(&[("content-length", "5")]),
            None,
        ),
        (
            "304 has no body",
            304,
            Method::GET,
            hdr(&[("content-length", "5")]),
            None,
        ),
        ("1xx has no body", 100, Method::GET, hdr(&[]), None),
        (
            "CONNECT 2xx has no body",
            200,
            Method::CONNECT,
            hdr(&[("content-length", "5")]),
            None,
        ),
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|(name, status, method, headers, expect)| {
            let got = response_framing(*status, method, headers);
            (&got != expect).then(|| format!("  {name:<36} expect={expect:?}  got={got:?}"))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "response_framing: {}/{} failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn response_head_encodes_status_line_and_reason() {
    let out = encode_response_head(200, &hdr(&[("content-type", "text/plain")]));
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "status line: {text:?}"
    );
    assert!(text
        .to_ascii_lowercase()
        .contains("content-type: text/plain\r\n"));
    assert!(
        text.ends_with("\r\n\r\n"),
        "must end with CRLFCRLF: {text:?}"
    );

    let nf = encode_response_head(404, &HeaderMap::new());
    assert!(String::from_utf8_lossy(&nf).starts_with("HTTP/1.1 404 Not Found\r\n"));
}
