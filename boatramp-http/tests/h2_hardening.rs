//! M5 DoS hardening: raw-frame attack simulations proving the mux driver cuts off a
//! Rapid Reset flood (CVE-2023-44487) and a CONTINUATION flood (CVE-2024-27316) with
//! GOAWAY(ENHANCE_YOUR_CALM) instead of doing unbounded work. Uses raw h2 frames — a
//! well-behaved client library won't misbehave — so it drives the bytes directly.

use boatramp_http::h2::error::ErrorCode;
use boatramp_http::h2::frame::{self, FrameHeader, FrameType};
use boatramp_http::h2::hpack::Hpack;
use boatramp_http::h2::{response, serve_connection_mux, Handler, Request, Response, CLIENT_PREFACE};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

struct Ok200;
impl Handler for Ok200 {
    async fn handle(&self, _req: Request) -> Response {
        response(200, b"ok".to_vec())
    }
}

fn client() -> DuplexStream {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_connection_mux(server, Ok200).await;
    });
    client
}

/// A valid HPACK block for `GET https://x/`.
fn get_block() -> Vec<u8> {
    let mut enc = Hpack::new();
    enc.encode(&[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b":authority", b"x"),
    ])
}

async fn send_preface(c: &mut DuplexStream) {
    c.write_all(CLIENT_PREFACE).await.unwrap();
    let mut settings = Vec::new();
    frame::write_frame(&mut settings, FrameType::Settings, 0, 0, &[]);
    c.write_all(&settings).await.unwrap();
}

/// Read frames until a GOAWAY (returning its error code) or EOF (`None`).
async fn wait_for_goaway(c: &mut DuplexStream) -> Option<ErrorCode> {
    loop {
        let mut hdr = [0u8; 9];
        c.read_exact(&mut hdr).await.ok()?;
        let h = FrameHeader::parse(&hdr);
        let mut payload = vec![0u8; h.length as usize];
        if h.length > 0 {
            c.read_exact(&mut payload).await.ok()?;
        }
        if h.kind == FrameType::GoAway {
            let (_last, code, _dbg) = frame::parse_goaway(&payload).ok()?;
            return Some(code);
        }
    }
}

#[tokio::test]
async fn rapid_reset_flood_is_cut_off() {
    let mut c = client();
    send_preface(&mut c).await;
    let block = get_block();
    // Open a stream then immediately reset it, over and over — the Rapid Reset
    // pattern. Each reset frees the concurrency slot, so flow control never bounds it.
    let mut frames = Vec::new();
    for i in 0..300u32 {
        let sid = 1 + i * 2;
        frame::write_frame(
            &mut frames,
            FrameType::Headers,
            END_HEADERS | END_STREAM,
            sid,
            &block,
        );
        frames.extend_from_slice(&frame::rst_stream(sid, ErrorCode::Cancel));
    }
    c.write_all(&frames).await.unwrap();

    let code = tokio::time::timeout(std::time::Duration::from_secs(5), wait_for_goaway(&mut c))
        .await
        .expect("server must GOAWAY under a rapid-reset flood, not run unbounded work");
    assert_eq!(code, Some(ErrorCode::EnhanceYourCalm));
}

#[tokio::test]
async fn continuation_flood_is_cut_off() {
    let mut c = client();
    send_preface(&mut c).await;
    let block = get_block();
    // HEADERS without END_HEADERS, then an endless run of (empty) CONTINUATION frames
    // that never set END_HEADERS — the header block never completes.
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, FrameType::Headers, 0, 1, &block); // no END_HEADERS
    for _ in 0..200 {
        frame::write_frame(&mut buf, FrameType::Continuation, 0, 1, &[]); // no END_HEADERS
    }
    c.write_all(&buf).await.unwrap();

    let code = tokio::time::timeout(std::time::Duration::from_secs(5), wait_for_goaway(&mut c))
        .await
        .expect("server must GOAWAY under a CONTINUATION flood, not buffer/parse forever");
    assert_eq!(code, Some(ErrorCode::EnhanceYourCalm));
}

/// A modest number of resets (well under the allowance, low ratio) must NOT trip the
/// guard — legitimate clients cancel some streams.
#[tokio::test]
async fn a_few_resets_are_tolerated() {
    let mut c = client();
    send_preface(&mut c).await;
    let block = get_block();
    // Open 40 streams, reset 10 of them (25%). Below the 100 free allowance anyway.
    let mut frames = Vec::new();
    for i in 0..40u32 {
        let sid = 1 + i * 2;
        frame::write_frame(
            &mut frames,
            FrameType::Headers,
            END_HEADERS | END_STREAM,
            sid,
            &block,
        );
        if i % 4 == 0 {
            frames.extend_from_slice(&frame::rst_stream(sid, ErrorCode::Cancel));
        }
    }
    c.write_all(&frames).await.unwrap();

    // The server should keep serving (respond to the non-reset streams), not GOAWAY.
    // Expect NOT to see a GOAWAY within a short window.
    let got = tokio::time::timeout(std::time::Duration::from_millis(500), wait_for_goaway(&mut c)).await;
    assert!(
        got.is_err() || got.unwrap().is_none(),
        "a low reset ratio must not trip the rapid-reset guard"
    );
}
