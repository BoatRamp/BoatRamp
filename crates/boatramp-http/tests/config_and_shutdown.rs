//! v0.62.0 additions to `boatramp-http`:
//! - #7b configurable limits ([`H1Config`]/[`MuxConfig`] threaded through the serve paths),
//! - #7c the graceful-shutdown handle ([`GracefulShutdown`]) — h2 `GOAWAY` + drain,
//! - #7d the h1 close-notify fix (the serve loop shuts the write half down on exit).
//!
//! The limits default to the historical hardcoded values, so these tests prove the knobs
//! take effect only when set away from the default.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use boatramp_http::h1::{self, H1Config};
use boatramp_http::h2::error::ErrorCode;
use boatramp_http::h2::frame::{self, FrameHeader, FrameType};
use boatramp_http::h2::hpack::Hpack;
use boatramp_http::h2::{CLIENT_PREFACE, MuxConfig, serve_connection_mux_with};
use boatramp_http::{GracefulShutdown, Handler, Request, Response, response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

// ---------------------------------------------------------------- shared apps ----

#[derive(Clone, Copy)]
struct Ok200;
impl Handler for Ok200 {
    async fn handle(&self, req: Request) -> Response {
        if req.method() == http::Method::POST {
            let body = req.into_body().collect().await.unwrap_or_default().to_vec();
            response(200, body)
        } else {
            response(200, b"ok".to_vec())
        }
    }
}

// =============================================================== #7d close_notify

/// A transport wrapper that records whether `poll_shutdown` was ever driven — a stand-in
/// for a TLS stream, whose `shutdown` is what emits `close_notify`.
struct ShutdownTracker {
    inner: DuplexStream,
    shut: Arc<AtomicBool>,
}

impl AsyncRead for ShutdownTracker {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for ShutdownTracker {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shut.store(true, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn h1_shuts_stream_down_on_exit_so_tls_sends_close_notify() {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let shut = Arc::new(AtomicBool::new(false));
    let tracked = ShutdownTracker {
        inner: server,
        shut: shut.clone(),
    };
    let srv = tokio::spawn(async move { h1::serve_connection(tracked, Ok200).await });

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200 OK\r\n"),
        "{:?}",
        String::from_utf8_lossy(&out)
    );
    srv.await.unwrap().unwrap();
    assert!(
        shut.load(Ordering::SeqCst),
        "the h1 loop must shut the write half down on exit (TLS close_notify)"
    );
}

#[tokio::test]
async fn h1_keep_alive_still_pipelines_after_the_close_notify_fix() {
    // Regression guard: the shutdown-on-exit change must not break keep-alive/pipelining —
    // three requests on one connection, the last closing, must all be served in order.
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let shut = Arc::new(AtomicBool::new(false));
    let tracked = ShutdownTracker {
        inner: server,
        shut: shut.clone(),
    };
    let srv = tokio::spawn(async move { h1::serve_connection(tracked, Ok200).await });

    client
        .write_all(
            b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n\
              GET /b HTTP/1.1\r\nHost: x\r\n\r\n\
              GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert_eq!(
        text.matches("HTTP/1.1 200 OK").count(),
        3,
        "want 3 responses: {text}"
    );
    srv.await.unwrap().unwrap();
    // The stream is shut down exactly once — at the end, not between keep-alive requests.
    assert!(shut.load(Ordering::SeqCst));
}

// ============================================================= #7b h1 config knobs

#[tokio::test]
async fn h1_max_head_rejects_an_oversized_head_only_when_configured_small() {
    // A head whose single header far exceeds a small `max_head`.
    let big = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nX-Big: {}\r\nConnection: close\r\n\r\n",
        "a".repeat(1024)
    );

    // Default max_head (64 KiB) accepts it.
    let (mut c1, s1) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move { h1::serve_connection(s1, Ok200).await });
    c1.write_all(big.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    c1.read_to_end(&mut out).await.unwrap();
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"),
        "default config should accept a 1 KiB head: {:?}",
        String::from_utf8_lossy(&out)
    );

    // A small max_head (256) rejects it with 400.
    let cfg = H1Config {
        max_head: 256,
        ..H1Config::default()
    };
    let (mut c2, s2) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move { h1::serve_connection_with_config(s2, Ok200, cfg).await });
    c2.write_all(big.as_bytes()).await.unwrap();
    let mut out2 = Vec::new();
    c2.read_to_end(&mut out2).await.unwrap();
    assert!(
        String::from_utf8_lossy(&out2).starts_with("HTTP/1.1 400"),
        "max_head=256 should reject a 1 KiB head: {:?}",
        String::from_utf8_lossy(&out2)
    );
}

#[tokio::test]
async fn h1_body_limit_drops_an_oversized_body() {
    let cfg = H1Config {
        body_limit: Some(4),
        ..H1Config::default()
    };
    let (mut client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move { h1::serve_connection_with_config(server, Ok200, cfg).await });

    client
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhelloworld",
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    // The 10-byte body exceeds the 4-byte limit → it is never echoed back.
    assert!(
        !String::from_utf8_lossy(&out).contains("helloworld"),
        "an over-limit body must not be echoed: {:?}",
        String::from_utf8_lossy(&out)
    );
}

// ======================================================= #7c h2 graceful shutdown

/// Minimal raw-frame h2 client helpers (mirrors `tests/h2_hardening.rs`).
async fn send_preface(c: &mut DuplexStream) {
    c.write_all(CLIENT_PREFACE).await.unwrap();
    let mut settings = Vec::new();
    frame::write_frame(&mut settings, FrameType::Settings, 0, 0, &[]);
    c.write_all(&settings).await.unwrap();
}

fn get_block() -> Vec<u8> {
    let mut enc = Hpack::new();
    enc.encode(&[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b":authority", b"x"),
    ])
}

/// Read one frame (header + payload), bounded by `within`; `None` on timeout/EOF.
async fn read_frame(c: &mut DuplexStream, within: Duration) -> Option<(FrameHeader, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    tokio::time::timeout(within, c.read_exact(&mut hdr))
        .await
        .ok()?
        .ok()?;
    let h = FrameHeader::parse(&hdr);
    let mut payload = vec![0u8; h.length as usize];
    if h.length > 0 {
        c.read_exact(&mut payload).await.ok()?;
    }
    Some((h, payload))
}

struct SlowApp {
    started: Arc<tokio::sync::Notify>,
}
impl Handler for SlowApp {
    async fn handle(&self, _req: Request) -> Response {
        self.started.notify_one();
        tokio::time::sleep(Duration::from_millis(120)).await;
        response(200, b"done".to_vec())
    }
}

#[tokio::test]
async fn h2_graceful_shutdown_goaway_lets_in_flight_finish() {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let shutdown = GracefulShutdown::new();
    let started = Arc::new(tokio::sync::Notify::new());
    let app = SlowApp {
        started: started.clone(),
    };
    let sd = shutdown.clone();
    tokio::spawn(async move {
        serve_connection_mux_with(server, app, MuxConfig::default(), Some(sd)).await
    });

    send_preface(&mut client).await;
    // Open stream 1 with a GET that END_STREAMs.
    let block = get_block();
    let mut headers = Vec::new();
    frame::write_frame(&mut headers, FrameType::Headers, 0x1 | 0x4, 1, &block);
    client.write_all(&headers).await.unwrap();

    // Wait until the handler is running, then trigger the drain — so `last_opened` is 1.
    started.notified().await;
    shutdown.trigger();

    // Collect frames until the connection ends. We must see both a GOAWAY(NO_ERROR,
    // last=1) and the in-flight stream-1 response (HEADERS on stream 1).
    let mut goaway: Option<(u32, ErrorCode)> = None;
    let mut saw_stream1_headers = false;
    while let Some((h, payload)) = read_frame(&mut client, Duration::from_secs(2)).await {
        match h.kind {
            FrameType::GoAway => {
                let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                    & 0x7fff_ffff;
                let code = ErrorCode::from(u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]));
                goaway = Some((last, code));
            }
            FrameType::Headers if h.stream_id == 1 => saw_stream1_headers = true,
            _ => {}
        }
    }

    let (last, code) = goaway.expect("a GOAWAY must be sent on graceful shutdown");
    assert_eq!(code, ErrorCode::NoError, "graceful GOAWAY code");
    assert_eq!(last, 1, "GOAWAY last-stream-id = highest accepted stream");
    assert!(
        saw_stream1_headers,
        "the in-flight stream-1 request must still complete"
    );
}

// ============================================================ #7b h2 idle timeout

#[tokio::test]
async fn h2_idle_timeout_closes_an_idle_connection_with_goaway() {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let cfg = MuxConfig {
        idle_timeout: Some(Duration::from_millis(200)),
        ..MuxConfig::default()
    };
    tokio::spawn(async move { serve_connection_mux_with(server, Ok200, cfg, None).await });

    // Open the connection, then go idle (no streams) — the idle timeout must fire.
    send_preface(&mut client).await;

    let mut saw_goaway_no_error = false;
    while let Some((h, payload)) = read_frame(&mut client, Duration::from_secs(2)).await {
        if h.kind == FrameType::GoAway {
            let code = ErrorCode::from(u32::from_be_bytes([
                payload[4], payload[5], payload[6], payload[7],
            ]));
            assert_eq!(code, ErrorCode::NoError, "idle timeout → GOAWAY(NO_ERROR)");
            saw_goaway_no_error = true;
            break;
        }
    }
    assert!(
        saw_goaway_no_error,
        "an idle connection must be closed with a GOAWAY after the idle timeout"
    );
}
