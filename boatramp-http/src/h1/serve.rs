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
use tokio_stream::StreamExt as _;

use super::parse::{chunked, parse_request_head, BodyFraming, ParseResult};
use crate::{Body, Handler};

/// Slowloris bound: how long we wait for a client to deliver a complete request head or
/// the next byte of its body before closing the connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a buffered request body (a DoS bound; a streaming request body is future work).
const MAX_BODY: usize = 64 * 1024 * 1024;

/// Serve one HTTP/1.1 connection: drive `handler` over each request until the connection
/// closes. Returns `Ok(())` on a clean close (client EOF, `Connection: close`, or a
/// write failure) and `Err` only on an unexpected local IO error.
pub async fn serve_connection<IO, H>(mut io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    // One growable buffer holds unconsumed bytes; each served request drains its head +
    // body from the front, leaving any pipelined bytes for the next iteration.
    let mut buf: Vec<u8> = Vec::with_capacity(8192);

    loop {
        // --- read + parse a request head (slowloris-bounded) ---------------------
        let (head, head_len) = loop {
            match parse_request_head(&buf) {
                ParseResult::Complete { head, consumed } => break (head, consumed),
                ParseResult::Reject(_) => {
                    // Malformed / ambiguous head → 400 and close (never resync).
                    let _ = write_status(&mut io, 400, true).await;
                    return Ok(());
                }
                ParseResult::Incomplete => {
                    match tokio::time::timeout(READ_TIMEOUT, io.read_buf(&mut buf)).await {
                        Ok(Ok(0)) => {
                            // EOF: clean only if it lands on a request boundary.
                            return Ok(());
                        }
                        Ok(Ok(_)) => continue,
                        // Read error or slowloris timeout → drop the connection.
                        _ => return Ok(()),
                    }
                }
            }
        };

        // Keep-alive intent + method are decided from the request before it is consumed.
        let method = head.method.clone();
        let version = head.version;
        let client_close = wants_close(&head.headers, version);
        let expect_continue = head
            .headers
            .get_all(header::EXPECT)
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"));

        // --- read + decode the request body per framing -------------------------
        let (body, body_consumed) = match head.framing {
            BodyFraming::Empty => (Bytes::new(), 0usize),
            BodyFraming::Length(n) => {
                let n = n as usize;
                if n > MAX_BODY {
                    let _ = write_status(&mut io, 413, true).await;
                    return Ok(());
                }
                if expect_continue
                    && write_all(&mut io, b"HTTP/1.1 100 Continue\r\n\r\n").await.is_err()
                {
                    return Ok(());
                }
                // Ensure head_len + n bytes are buffered.
                while buf.len() < head_len + n {
                    match tokio::time::timeout(READ_TIMEOUT, io.read_buf(&mut buf)).await {
                        Ok(Ok(0)) => return Ok(()), // truncated body → drop
                        Ok(Ok(_)) => {}
                        _ => return Ok(()),
                    }
                }
                (Bytes::copy_from_slice(&buf[head_len..head_len + n]), n)
            }
            BodyFraming::Chunked => {
                if expect_continue
                    && write_all(&mut io, b"HTTP/1.1 100 Continue\r\n\r\n").await.is_err()
                {
                    return Ok(());
                }
                loop {
                    match chunked::decode(&buf[head_len..]) {
                        chunked::ChunkDecode::Complete { data, end } => {
                            if data.len() > MAX_BODY {
                                let _ = write_status(&mut io, 413, true).await;
                                return Ok(());
                            }
                            break (Bytes::from(data), end);
                        }
                        chunked::ChunkDecode::Reject(_) => {
                            let _ = write_status(&mut io, 400, true).await;
                            return Ok(());
                        }
                        chunked::ChunkDecode::Incomplete => {
                            match tokio::time::timeout(READ_TIMEOUT, io.read_buf(&mut buf)).await {
                                Ok(Ok(0)) => return Ok(()),
                                Ok(Ok(_)) => {}
                                _ => return Ok(()),
                            }
                        }
                    }
                }
            }
        };

        // --- build the request + run the handler --------------------------------
        // (The body is buffered here; true request-body streaming is the next step.)
        let mut req = http::Request::new(crate::ReqBody::from_bytes(body));
        *req.method_mut() = head.method;
        *req.uri_mut() = head.uri;
        *req.version_mut() = head.version;
        *req.headers_mut() = head.headers;
        let resp = handler.handle(req).await;

        // --- frame + write the response -----------------------------------------
        let (result, must_close) =
            write_response(&mut io, resp, &method, version, client_close).await;
        if result.is_err() {
            return Ok(()); // client went away mid-response
        }
        if must_close {
            return Ok(());
        }

        // Drop the consumed head+body; keep any pipelined bytes for the next request.
        buf.drain(..head_len + body_consumed);
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
