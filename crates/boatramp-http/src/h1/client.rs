//! The HTTP/1.1 **client** codec — the mirror of [`super::parse`]/[`super::serve`]:
//! there boatramp is the server (parses a request line, frames a response); here it is
//! the client (encodes a request line, parses a status line, decodes a response body).
//! It backs the reverse-proxy upstream leg so the whole proxy path — inbound *and*
//! upstream — runs on one hand-rolled codec, with no hyper connection task or intermediate
//! body copy between the two.
//!
//! The split of concerns mirrors the server side: this module owns the **wire** (encode a
//! head, parse a head, decode a body per framing over an owned connection); the pool,
//! TLS dial, SSRF address pin, and connection reuse live in the proxy that drives it.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::parse::{
    chunked, next_line, response_framing, split_header, Line, ResponseFraming, MAX_HEAD,
};

/// Encode a request head: `METHOD request-target HTTP/1.1` + `headers` + the terminating
/// CRLFCRLF. `target` is the origin-form request target (path + query) the caller built
/// from the upstream URL; the caller owns framing — it must have set `Host` and any
/// `Content-Length`/`Transfer-Encoding` consistent with how it will write the body.
pub fn encode_request_head(method: &Method, target: &str, headers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + headers.len() * 32);
    out.extend_from_slice(method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A parsed response head: the status line + header fields. Body framing is resolved
/// separately by the caller (it depends on the *request* method) via [`BodyReader::for`].
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub version: Version,
    pub status: StatusCode,
    pub headers: HeaderMap,
}

/// The outcome of parsing one response head from the front of a buffer.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum RespParse {
    /// A complete head was parsed; the body (per framing) begins at `consumed`.
    Complete { head: ResponseHead, consumed: usize },
    /// The buffer does not yet contain a full head (no CRLFCRLF) — read more.
    Incomplete,
    /// The head is malformed — drop the connection (fail closed).
    Reject,
}

/// Parse a single HTTP/1.x response head (status line + header fields, up to and including
/// the terminating CRLFCRLF) from the front of `buf`. Enforces strict CRLF framing (the
/// same [`next_line`]/[`split_header`] the request parser uses), so a malformed status line
/// or header is a hard reject rather than a guess.
pub fn parse_response_head(buf: &[u8]) -> RespParse {
    let mut pos = 0usize;
    // status line: `HTTP/1.x SP status SP [reason]`.
    let (version, status) = match next_line(buf, pos) {
        Ok(Line::Got(line, next)) => match parse_status_line(line) {
            Some(v) => {
                pos = next;
                v
            }
            None => return RespParse::Reject,
        },
        Ok(Line::Incomplete) => {
            return if buf.len() > MAX_HEAD {
                RespParse::Reject
            } else {
                RespParse::Incomplete
            };
        }
        Err(_) => return RespParse::Reject,
    };

    let mut headers = HeaderMap::new();
    loop {
        if buf.len() > MAX_HEAD && pos >= MAX_HEAD {
            return RespParse::Reject;
        }
        match next_line(buf, pos) {
            Ok(Line::Got(line, next)) => {
                pos = next;
                if line.is_empty() {
                    break; // end of the header block
                }
                // Obs-fold (a header line starting with SP/HTAB) is rejected outright.
                if line[0] == b' ' || line[0] == b'\t' {
                    return RespParse::Reject;
                }
                let Ok((name, value)) = split_header(line) else {
                    return RespParse::Reject;
                };
                let (Ok(hn), Ok(hv)) = (
                    http::header::HeaderName::from_bytes(name),
                    http::header::HeaderValue::from_bytes(value),
                ) else {
                    return RespParse::Reject;
                };
                headers.append(hn, hv);
            }
            Ok(Line::Incomplete) => {
                return if buf.len() > MAX_HEAD {
                    RespParse::Reject
                } else {
                    RespParse::Incomplete
                };
            }
            Err(_) => return RespParse::Reject,
        }
    }

    RespParse::Complete {
        head: ResponseHead {
            version,
            status,
            headers,
        },
        consumed: pos,
    }
}

/// Parse a status line into `(version, status)`: `HTTP/1.x`, a 3-digit status code, and an
/// optional reason phrase (which may itself contain spaces). Returns `None` on any
/// malformed shape.
fn parse_status_line(line: &[u8]) -> Option<(Version, StatusCode)> {
    // Split into at most three fields on SP: version, code, reason (reason may hold SPs).
    let mut it = line.splitn(3, |&b| b == b' ');
    let ver = it.next()?;
    let code = it.next()?;
    // A reason phrase is optional; if present it is ignored (never trusted).
    let version = match ver {
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/1.0" => Version::HTTP_10,
        _ => return None,
    };
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: u16 = std::str::from_utf8(code).ok()?.parse().ok()?;
    let status = StatusCode::from_u16(n).ok()?;
    Some((version, status))
}

/// How a response body is read off the connection (RFC 9112 §6, receiver side). Built by
/// [`BodyReader::for`] from the request method + the response head, so the no-body rules
/// (HEAD / 1xx / 204 / 304) and close-delimited framing are resolved once.
#[derive(Debug)]
pub enum BodyReader {
    /// No body — done immediately.
    None,
    /// A fixed-length body: this many octets remain.
    Length(u64),
    /// A chunked body — decoded incrementally until the terminating 0-chunk.
    Chunked,
    /// Framed by connection close — read until EOF (the connection is not reusable).
    CloseDelimited,
}

impl BodyReader {
    /// Resolve how to read the response body for a request that used `method`, from the
    /// parsed response `head` — the receiver-side mirror of [`response_framing`].
    #[allow(clippy::should_implement_trait)] // `for` reads naturally here; not the `Fn` trait
    pub fn r#for(method: &Method, head: &ResponseHead) -> Self {
        match response_framing(head.status.as_u16(), method, &head.headers) {
            ResponseFraming::None => Self::None,
            ResponseFraming::Length(n) => Self::Length(n),
            ResponseFraming::Chunked => Self::Chunked,
            ResponseFraming::CloseDelimited => Self::CloseDelimited,
        }
    }

    /// Whether the connection may be reused once this body is fully drained. A
    /// close-delimited body ends *by* the close, so its connection is never reusable.
    pub fn keep_alive_possible(&self) -> bool {
        !matches!(self, Self::CloseDelimited)
    }
}

/// One end of an established upstream HTTP/1.1 connection: the transport plus a read buffer
/// holding bytes read past the current message boundary (response head overrun, or the tail
/// of a pipelined body). The proxy owns pooling + TLS; this drives the wire.
pub struct Conn<IO> {
    io: IO,
    /// Bytes read but not yet consumed — the response-body decoder drains this first, then
    /// refills from the socket. Kept as `BytesMut` so a fixed-length body chunk is handed
    /// out with `split_to().freeze()` (no copy) rather than copied into a fresh `Bytes`.
    buf: BytesMut,
    /// How much to reserve before each socket read (the per-connection read-buffer size —
    /// the proxy's `read_buffer_bytes`, defaulting to [`DEFAULT_READ_CHUNK`]).
    read_chunk: usize,
}

impl<IO> Conn<IO> {
    /// Wrap an established connection (fresh, empty read buffer) with the default read
    /// chunk size.
    pub fn new(io: IO) -> Self {
        Self::with_read_chunk(io, DEFAULT_READ_CHUNK)
    }

    /// Wrap an established connection, reserving `read_chunk` bytes per socket read — the
    /// proxy sets this from the per-upstream `read_buffer_bytes`.
    pub fn with_read_chunk(io: IO, read_chunk: usize) -> Self {
        Self {
            io,
            buf: BytesMut::with_capacity(read_chunk.max(4096)),
            read_chunk: read_chunk.max(4096),
        }
    }

    /// Deconstruct into the transport plus any buffered leftover — for returning a drained
    /// keep-alive connection to the pool. On a cleanly drained response the leftover is
    /// empty; a non-empty leftover means a pipelined byte the pool would have to preserve.
    pub fn into_parts(self) -> (IO, BytesMut) {
        (self.io, self.buf)
    }

    /// Whether the read buffer still holds unconsumed bytes (a drained keep-alive
    /// connection has none — anything left is out-of-band and makes reuse unsafe).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

/// Default per-connection read-buffer reservation — a large fixed-length body streams in a
/// few reads. Matches the proxy's default upstream read buffer.
const DEFAULT_READ_CHUNK: usize = 32 * 1024;

impl<IO: AsyncRead + Unpin> Conn<IO> {
    /// Reserve `read_chunk` spare bytes and read once from the transport into the buffer,
    /// returning the number of bytes read (`0` = EOF). Poll-based so the response-body
    /// [`http_body::Body`] driver can pull without an intermediate future.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        self.buf.reserve(self.read_chunk);
        let dst = self.buf.spare_capacity_mut();
        let mut rb = ReadBuf::uninit(dst);
        match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                // SAFETY: `poll_read` initialized exactly `n` bytes of the spare capacity.
                unsafe { self.buf.advance_mut(n) };
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll for the next response-body chunk per `reader` (see [`Conn::read_body_chunk`] for
    /// the semantics). This is the core the response [`http_body::Body`] polls directly; the
    /// async method below is a thin wrapper for tests + the head-read path.
    pub fn poll_read_body_chunk(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut BodyReader,
    ) -> Poll<std::io::Result<Option<Bytes>>> {
        loop {
            match reader {
                BodyReader::None => return Poll::Ready(Ok(None)),
                BodyReader::Length(remaining) => {
                    if *remaining == 0 {
                        return Poll::Ready(Ok(None));
                    }
                    if !self.buf.is_empty() {
                        let take = (*remaining).min(self.buf.len() as u64) as usize;
                        let chunk = self.buf.split_to(take).freeze();
                        *remaining -= take as u64;
                        return Poll::Ready(Ok(Some(chunk)));
                    }
                    match std::task::ready!(self.poll_fill(cx))? {
                        0 => return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into())),
                        _ => continue,
                    }
                }
                BodyReader::Chunked => match chunked::next_chunk(&self.buf) {
                    chunked::ChunkStep::Data {
                        data_start,
                        data_end,
                        next,
                    } => {
                        let mut frame = self.buf.split_to(next);
                        let data = frame.split_off(data_start).split_to(data_end - data_start);
                        return Poll::Ready(Ok(Some(data.freeze())));
                    }
                    chunked::ChunkStep::Last { end } => {
                        self.buf.advance(end);
                        return Poll::Ready(Ok(None));
                    }
                    chunked::ChunkStep::Incomplete => {
                        match std::task::ready!(self.poll_fill(cx))? {
                            0 => return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into())),
                            _ => continue,
                        }
                    }
                    chunked::ChunkStep::Reject(_) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "malformed upstream chunked body",
                        )));
                    }
                },
                BodyReader::CloseDelimited => {
                    if !self.buf.is_empty() {
                        return Poll::Ready(Ok(Some(self.buf.split().freeze())));
                    }
                    match std::task::ready!(self.poll_fill(cx))? {
                        0 => return Poll::Ready(Ok(None)), // clean EOF ends a close-delimited body
                        _ => return Poll::Ready(Ok(Some(self.buf.split().freeze()))),
                    }
                }
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Conn<IO> {
    /// Write raw bytes to the connection (a request head, or one body frame the caller has
    /// already encoded). Kept low-level so the proxy owns request-body framing (length vs
    /// chunked) while this owns the transport.
    pub async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.io.write_all(bytes).await
    }

    /// Flush the transport (call once after the request head + body are written, so a
    /// buffered TLS/`BufWriter` transport puts the request on the wire before we block on
    /// the response).
    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush().await
    }

    /// Read and parse the response head, leaving any body bytes already read in the buffer.
    /// A malformed head or an EOF before a complete head is an error (the connection is
    /// dropped, never reused).
    pub async fn read_response_head(&mut self) -> std::io::Result<ResponseHead> {
        loop {
            match parse_response_head(&self.buf) {
                RespParse::Complete { head, consumed } => {
                    let _ = self.buf.split_to(consumed);
                    return Ok(head);
                }
                RespParse::Reject => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "malformed upstream response head",
                    ));
                }
                RespParse::Incomplete => {
                    let n = std::future::poll_fn(|cx| self.poll_fill(cx)).await?;
                    if n == 0 {
                        return Err(std::io::ErrorKind::UnexpectedEof.into());
                    }
                }
            }
        }
    }

    /// Await the next response-body chunk per `reader`, or `Ok(None)` at the body's end — a
    /// thin async wrapper over [`Conn::poll_read_body_chunk`] for tests + non-`Body` callers.
    /// Fixed-length and chunked bodies hand out `Bytes` split from the read buffer (no
    /// copy); a truncated or malformed body is an error (the connection is dropped).
    pub async fn read_body_chunk(
        &mut self,
        reader: &mut BodyReader,
    ) -> std::io::Result<Option<Bytes>> {
        std::future::poll_fn(|cx| self.poll_read_body_chunk(cx, reader)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_get_request_head() {
        let mut h = HeaderMap::new();
        h.insert(http::header::HOST, "example.com".parse().unwrap());
        let out = encode_request_head(&Method::GET, "/path?q=1", &h);
        assert_eq!(
            out,
            b"GET /path?q=1 HTTP/1.1\r\nhost: example.com\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn parses_a_response_head_and_leaves_the_body() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc";
        match parse_response_head(raw) {
            RespParse::Complete { head, consumed } => {
                assert_eq!(head.status, StatusCode::OK);
                assert_eq!(head.version, Version::HTTP_11);
                assert_eq!(head.headers[http::header::CONTENT_LENGTH], "3");
                assert_eq!(&raw[consumed..], b"abc");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn reason_phrase_may_contain_spaces_and_be_absent() {
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 404 Not Found\r\n\r\n"),
            RespParse::Complete { .. }
        ));
        // No reason phrase, no trailing space.
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 204\r\n\r\n"),
            RespParse::Complete { .. }
        ));
    }

    #[test]
    fn incomplete_head_asks_for_more() {
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n"),
            RespParse::Incomplete
        ));
    }

    #[test]
    fn rejects_a_bad_status_line() {
        assert!(matches!(
            parse_response_head(b"HTTP/2 200 OK\r\n\r\n"),
            RespParse::Reject
        ));
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 20 OK\r\n\r\n"),
            RespParse::Reject
        ));
    }

    #[test]
    fn no_body_statuses_yield_a_none_reader() {
        let head = ResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::NO_CONTENT,
            headers: HeaderMap::new(),
        };
        assert!(matches!(
            BodyReader::r#for(&Method::GET, &head),
            BodyReader::None
        ));
        // A HEAD response with a content-length still has no body.
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_LENGTH, "10".parse().unwrap());
        let head = ResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers: h,
        };
        assert!(matches!(
            BodyReader::r#for(&Method::HEAD, &head),
            BodyReader::None
        ));
    }

    #[tokio::test]
    async fn reads_a_fixed_length_body_over_a_duplex() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        // The "server" writes a response head + a 5-byte body.
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
                .await
                .unwrap();
        });
        let mut conn = Conn::new(client);
        let head = conn.read_response_head().await.unwrap();
        let mut reader = BodyReader::r#for(&Method::GET, &head);
        let mut body = Vec::new();
        while let Some(chunk) = conn.read_body_chunk(&mut reader).await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn reads_a_chunked_body_over_a_duplex() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
                      5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let mut conn = Conn::new(client);
        let head = conn.read_response_head().await.unwrap();
        let mut reader = BodyReader::r#for(&Method::GET, &head);
        assert!(reader.keep_alive_possible());
        let mut body = Vec::new();
        while let Some(chunk) = conn.read_body_chunk(&mut reader).await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"hello world");
        // Fully drained: nothing left over, so the connection is reusable.
        assert_eq!(conn.buffered(), 0);
    }
}
