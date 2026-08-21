//! The HTTP/1.1 connection serving loop — the runtime that turns the [`parse`](super::parse)r
//! into a server: read a request head, decode its body per framing, drive a
//! [`Handler`](crate::Handler), frame + write the response, and reuse the connection
//! (keep-alive + pipelining) until either side asks to close.
//!
//! Framing is **fail-closed** end to end: a malformed request head is answered `400` and
//! the connection closed (no attempt to resync — that is how h1 smuggling happens); a
//! streamed response whose source errors mid-body drops the connection without the
//! terminating chunk, so the client sees a truncated (error) body, never a clean end.

use std::time::Duration;

use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, Method, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;

use super::parse::{chunked, parse_request_head, BodyFraming, ParseResult};
use crate::{Body, BodyError, Handler, ReqBody};

/// Slowloris bound: how long we wait for a client to deliver a complete request head or
/// the next byte of its body before closing the connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve one HTTP/1.1 connection: drive `handler` over each request until the connection
/// closes. Returns `Ok(())` on a clean close (client EOF, `Connection: close`, or a
/// write failure) and `Err` only on an unexpected local IO error.
///
/// The request body **streams** to the handler: for each request the handler runs
/// concurrently with a body pump that feeds the request's [`ReqBody`] channel from the
/// connection as bytes arrive — so a large upload flows client → boatramp → upstream
/// without being buffered whole. Because HTTP/1.1 is one-request-at-a-time, the pump and
/// the handler share this task via [`tokio::join!`]; the pump owns the reader while the
/// handler owns only the channel, so the response write reclaims the connection after.
pub async fn serve_connection<IO, H>(io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    // Split the connection so the response can be written WHILE the request body is still
    // being read (a streaming reverse proxy: request body → upstream, upstream response →
    // client, both in flight). The pump owns the read half; the response write owns the
    // write half; the two run concurrently via `join!`.
    let (mut rd, mut wr) = tokio::io::split(io);
    // Unconsumed bytes; each request drains its head from the front, the pump drains the
    // body, leaving any pipelined bytes for the next iteration.
    let mut buf: Vec<u8> = Vec::with_capacity(8192);

    loop {
        // --- read + parse a request head (slowloris-bounded) ---------------------
        let (head, head_len) = loop {
            match parse_request_head(&buf) {
                ParseResult::Complete { head, consumed } => break (head, consumed),
                ParseResult::Reject(_) => {
                    // Malformed / ambiguous head → 400 and close (never resync).
                    let _ = write_status(&mut wr, 400, true).await;
                    return Ok(());
                }
                ParseResult::Incomplete => {
                    match tokio::time::timeout(READ_TIMEOUT, rd.read_buf(&mut buf)).await {
                        Ok(Ok(0)) => return Ok(()), // EOF on a request boundary → clean close
                        Ok(Ok(_)) => continue,
                        _ => return Ok(()), // read error / slowloris timeout → drop
                    }
                }
            }
        };

        let method = head.method.clone();
        let version = head.version;
        let framing = head.framing.clone();
        let client_close = wants_close(&head.headers, version);
        let expect_continue = head
            .headers
            .get_all(header::EXPECT)
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"));

        // Consume the head; `buf` now starts at the request body (or the next request).
        buf.drain(..head_len);

        // A body carries an interim 100-continue if the client asked for one.
        if !matches!(framing, BodyFraming::Empty)
            && expect_continue
            && write_all(&mut wr, b"HTTP/1.1 100 Continue\r\n\r\n").await.is_err()
        {
            return Ok(());
        }

        // A bounded channel backs the request's ReqBody stream; the pump feeds it from the
        // connection (backpressured by the channel capacity) and closes it at the body's
        // end so the handler's body stream terminates.
        let (tx, rx) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        let mut req = http::Request::new(ReqBody::from_stream(ReceiverStream::new(rx)));
        *req.method_mut() = head.method;
        *req.uri_mut() = head.uri;
        *req.version_mut() = head.version;
        *req.headers_mut() = head.headers;

        // Run { handler → write its response } concurrently with the body pump, so the
        // response streams out while the request body is still coming in.
        let respond = async {
            let resp = handler.handle(req).await;
            write_response(&mut wr, resp, &method, version, client_close).await
        };
        let ((result, resp_close), pump) =
            tokio::join!(respond, pump_body(&mut rd, &mut buf, framing, tx));

        if result.is_err() {
            return Ok(()); // client went away mid-response
        }
        // Close after this request if either side asked, or the request body framing was
        // bad/truncated (the connection boundary can no longer be trusted).
        if resp_close || pump.is_err() {
            return Ok(());
        }
    }
}

/// Stream the request body from the connection into `tx` (backpressured by the channel),
/// draining consumed bytes from `buf` so it ends at the next request. `Err(())` when the
/// body framing is malformed or the connection truncates mid-body (the caller then
/// closes); if the handler stops reading (its `ReqBody` was dropped), the rest is
/// discarded to the framing boundary so the connection can still be reused (`Ok`).
async fn pump_body<IO>(
    io: &mut IO,
    buf: &mut Vec<u8>,
    framing: BodyFraming,
    tx: mpsc::Sender<Result<Bytes, BodyError>>,
) -> Result<(), ()>
where
    IO: AsyncRead + Unpin,
{
    // Once the receiver is gone we stop sending but keep consuming, to preserve the
    // connection boundary for the next pipelined request.
    let mut sending = true;
    // Report a truncated / malformed body to the handler (if still listening) and fail.
    macro_rules! fail {
        () => {{
            if sending {
                let _ = tx.send(Err(BodyError)).await;
            }
            return Err(());
        }};
    }

    match framing {
        BodyFraming::Empty => Ok(()),
        BodyFraming::Length(n) => {
            let mut remaining = n as usize;
            while remaining > 0 {
                if buf.is_empty() {
                    match tokio::time::timeout(READ_TIMEOUT, io.read_buf(buf)).await {
                        Ok(Ok(0)) => fail!(), // truncated body
                        Ok(Ok(_)) => {}
                        _ => fail!(),
                    }
                }
                let take = remaining.min(buf.len());
                let chunk = Bytes::copy_from_slice(&buf[..take]);
                buf.drain(..take);
                remaining -= take;
                if sending && tx.send(Ok(chunk)).await.is_err() {
                    sending = false;
                }
            }
            Ok(())
        }
        BodyFraming::Chunked => loop {
            match chunked::next_chunk(buf) {
                chunked::ChunkStep::Data { data_start, data_end, next } => {
                    let chunk = Bytes::copy_from_slice(&buf[data_start..data_end]);
                    buf.drain(..next);
                    if sending && tx.send(Ok(chunk)).await.is_err() {
                        sending = false;
                    }
                }
                chunked::ChunkStep::Last { end } => {
                    buf.drain(..end);
                    return Ok(());
                }
                chunked::ChunkStep::Incomplete => {
                    match tokio::time::timeout(READ_TIMEOUT, io.read_buf(buf)).await {
                        Ok(Ok(0)) => fail!(),
                        Ok(Ok(_)) => {}
                        _ => fail!(),
                    }
                }
                chunked::ChunkStep::Reject(_) => fail!(),
            }
        },
    }
}

/// Whether the connection must close after this request: an explicit `Connection: close`,
/// or an HTTP/1.0 request without `Connection: keep-alive` (1.0 defaults to close).
fn wants_close(headers: &HeaderMap, version: Version) -> bool {
    let conn = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if conn.split(',').any(|t| t.trim() == "close") {
        return true;
    }
    if version == Version::HTTP_10 && !conn.split(',').any(|t| t.trim() == "keep-alive") {
        return true;
    }
    false
}

/// Write a bare status line + `Content-Length: 0` (for error/again-no-body responses),
/// optionally forcing `Connection: close`.
async fn write_status<IO>(io: &mut IO, status: u16, close: bool) -> std::io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    let conn = if close { "connection: close\r\n" } else { "" };
    let head = format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\n{conn}\r\n");
    write_all(io, head.as_bytes()).await
}

/// Frame + write one response. Returns `(io_result, must_close)`: `must_close` is true if
/// the response itself asked to close (or the framing forces it — a streamed body that
/// errored mid-stream). No-body rules (HEAD / 1xx / 204 / 304) suppress the body but keep
/// an accurate `Content-Length` where known.
async fn write_response<IO>(
    io: &mut IO,
    resp: crate::Response,
    method: &Method,
    _version: Version,
    client_close: bool,
) -> (std::io::Result<()>, bool)
where
    IO: AsyncWrite + Unpin,
{
    let (mut parts, body) = resp.into_parts();
    let status = parts.status.as_u16();
    let no_body = *method == Method::HEAD
        || (100..200).contains(&status)
        || status == 204
        || status == 304;

    // We own framing: drop any handler-set framing/hop-by-hop headers and set our own.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::TRANSFER_ENCODING);
    let resp_close = parts
        .headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().split(',').any(|t| t.trim() == "close"))
        .unwrap_or(false);
    parts.headers.remove(header::CONNECTION);

    // Decide framing from the body variant.
    enum Framing {
        Fixed(usize),
        Chunked,
    }
    let framing = match &body {
        Body::Bytes(v) => Framing::Fixed(v.len()),
        #[cfg(target_os = "linux")]
        Body::Splice { len, .. } => Framing::Fixed(*len),
        Body::Stream(_) => Framing::Chunked,
    };

    match &framing {
        Framing::Fixed(len) => {
            parts
                .headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from(*len as u64));
        }
        Framing::Chunked => {
            parts
                .headers
                .insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        }
    }
    let will_close = client_close || resp_close;
    if will_close {
        parts
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }

    // Status line + headers.
    let head = super::parse::encode_response_head(status, &parts.headers);
    if let Err(e) = write_all(io, &head).await {
        return (Err(e), true);
    }
    if no_body {
        return (Ok(()), will_close);
    }

    // Body.
    match body {
        Body::Bytes(v) => {
            if let Err(e) = write_all(io, &v).await {
                return (Err(e), true);
            }
        }
        #[cfg(target_os = "linux")]
        Body::Splice { mut upstream, len } => {
            // Userspace copy for now (the kTLS/splice fast-path is Stage 4). A fixed
            // Content-Length was already written, so copy exactly `len` bytes.
            let mut remaining = len;
            let mut chunk = [0u8; 32 * 1024];
            while remaining > 0 {
                let want = remaining.min(chunk.len());
                match upstream.read(&mut chunk[..want]).await {
                    Ok(0) => return (Ok(()), true), // upstream truncated → close
                    Ok(n) => {
                        if let Err(e) = write_all(io, &chunk[..n]).await {
                            return (Err(e), true);
                        }
                        remaining -= n;
                    }
                    Err(_) => return (Ok(()), true),
                }
            }
        }
        Body::Stream(mut stream) => {
            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) if chunk.is_empty() => {}
                    Ok(chunk) => {
                        if let Err(e) = write_all(io, &chunked::encode(&chunk)).await {
                            return (Err(e), true);
                        }
                    }
                    // Source failed mid-stream: abort WITHOUT the terminating 0-chunk, so
                    // the client sees a truncated chunked body (an error), not a clean end.
                    Err(_) => return (Ok(()), true),
                }
            }
            if let Err(e) = write_all(io, &chunked::encode_last(&HeaderMap::new())).await {
                return (Err(e), true);
            }
        }
    }
    (Ok(()), will_close)
}

async fn write_all<IO>(io: &mut IO, bytes: &[u8]) -> std::io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    io.write_all(bytes).await
}
