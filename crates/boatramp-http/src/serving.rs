//! The shared serving abstraction — the `Request`/`Response`/`Body`/`Handler` surface
//! both the [`h1`](crate::h1) and [`h2`](crate::h2) codecs produce/consume, and that the
//! unified serve dispatcher (Stage 3) will hand to a `tower::Service` (the axum Router).
//! These are the standard `http` crate types, so an embedder — or a reverse-proxy bridge
//! — pays no per-request re-marshaling.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio_stream::{Stream, StreamExt as _};

/// A received request: an `http::Request` whose body is a streamed [`ReqBody`]. The
/// pseudo-headers (h2) / request line (h1) are hoisted into the method / URI (path) /
/// `Host` header.
pub type Request = http::Request<ReqBody>;

/// A streamed request body. Its chunks are delivered as they arrive off the connection
/// (no whole-body buffering), so a reverse-proxy handler streams a large upload straight
/// through to the upstream. Implements [`http_body::Body`] so an axum/tower service
/// consumes it directly; [`collect`](ReqBody::collect) buffers it when a handler wants
/// the whole thing.
pub struct ReqBody(ReqBodyInner);

enum ReqBodyInner {
    /// No body.
    Empty,
    /// A single already-buffered chunk (an empty `Option` once yielded). Used by the h2
    /// driver, which accumulates DATA frames before dispatch, and for unit tests.
    Full(Option<Bytes>),
    /// A pull stream of body chunks (the h1 loop feeds this from the connection).
    Stream(Pin<Box<dyn Stream<Item = Result<Bytes, BodyError>> + Send>>),
}

impl ReqBody {
    /// An empty request body.
    pub fn empty() -> Self {
        Self(ReqBodyInner::Empty)
    }

    /// A request body that is already fully buffered in memory.
    pub fn from_bytes(bytes: Bytes) -> Self {
        if bytes.is_empty() {
            Self(ReqBodyInner::Empty)
        } else {
            Self(ReqBodyInner::Full(Some(bytes)))
        }
    }

    /// A request body streamed from a pull [`Stream`] of chunks — the driver feeds this
    /// from the connection as bytes arrive. A [`BodyError`] item aborts the body.
    pub fn from_stream(
        chunks: impl Stream<Item = Result<Bytes, BodyError>> + Send + 'static,
    ) -> Self {
        Self(ReqBodyInner::Stream(Box::pin(chunks)))
    }

    /// Consume the body as a pull [`Stream`] of chunks — a reverse-proxy handler forwards
    /// this straight to the upstream without buffering (the mirror of [`Body::try_stream`]
    /// on the response side).
    pub fn into_data_stream(self) -> Pin<Box<dyn Stream<Item = Result<Bytes, BodyError>> + Send>> {
        match self.0 {
            ReqBodyInner::Empty | ReqBodyInner::Full(None) => Box::pin(tokio_stream::empty()),
            ReqBodyInner::Full(Some(b)) => Box::pin(tokio_stream::once(Ok(b))),
            ReqBodyInner::Stream(s) => s,
        }
    }

    /// Buffer the whole body into `Bytes` (for a handler that wants it all at once, or a
    /// test). `Err` if the source failed mid-stream.
    pub async fn collect(self) -> Result<Bytes, BodyError> {
        match self.0 {
            ReqBodyInner::Empty => Ok(Bytes::new()),
            ReqBodyInner::Full(b) => Ok(b.unwrap_or_default()),
            ReqBodyInner::Stream(mut s) => {
                let mut buf = bytes::BytesMut::new();
                while let Some(item) = s.next().await {
                    buf.extend_from_slice(&item?);
                }
                Ok(buf.freeze())
            }
        }
    }
}

impl Default for ReqBody {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for ReqBody {
    // The stream variant holds a boxed trait object (not `Debug`); report the shape only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.0 {
            ReqBodyInner::Empty => "Empty",
            ReqBodyInner::Full(_) => "Full",
            ReqBodyInner::Stream(_) => "Stream",
        };
        write!(f, "ReqBody({kind})")
    }
}

impl http_body::Body for ReqBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, BodyError>>> {
        match &mut self.0 {
            ReqBodyInner::Empty => Poll::Ready(None),
            ReqBodyInner::Full(b) => Poll::Ready(b.take().map(|b| Ok(http_body::Frame::data(b)))),
            ReqBodyInner::Stream(s) => match s.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// A response to send: an `http::Response` whose body is a [`Body`].
pub type Response = http::Response<Body>;

/// A streamed body's source failed mid-stream (e.g. a reverse-proxy upstream dropped
/// the connection before delivering the whole body). Yielding this from a body
/// [`Stream`](tokio_stream::Stream) tells the driver to abort the client stream
/// (h2: RST_STREAM) rather than close it cleanly — so a truncated body is never framed as
/// complete (which, for a response with no `content-length`, the client can't detect).
#[derive(Debug, Clone, Default)]
pub struct BodyError;

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request/response body source failed mid-stream")
    }
}

// `std::error::Error` (with the `Display` above) lets `ReqBody` satisfy `http_body::Body`
// consumers that require `Error: Into<Box<dyn Error>>` — e.g. `axum::body::Body::new`,
// which the router bridge uses to hand a streamed request body to the axum Router.
impl std::error::Error for BodyError {}

/// A single streamed body chunk, or a mid-stream source failure ([`BodyError`]).
pub type BodyChunk = Result<Bytes, BodyError>;

/// A response body: buffered bytes, or a pull [`Stream`] of [`BodyChunk`]s forwarded as
/// it arrives (a reverse proxy streaming an upstream response without buffering or copying
/// it — the stream ending signals end-of-body; a [`BodyError`] item aborts the stream).
/// The driver **polls the stream directly**, so a bridge hands its upstream body straight
/// in with no intermediate channel or producer task. The concurrent
/// [`h2::mux`](crate::h2::mux) driver streams natively; the serial
/// [`h2::conn`](crate::h2::conn) driver buffers a `Stream` (it can't interleave).
///
/// [`Stream`]: tokio_stream::Stream
pub enum Body {
    Bytes(Vec<u8>),
    Stream(std::pin::Pin<Box<dyn tokio_stream::Stream<Item = BodyChunk> + Send>>),
    /// A `[offset, offset+len)` region of an open local file, for the zero-copy
    /// `sendfile` static path. Over a plaintext socket the h1 codec moves the bytes
    /// kernel-to-kernel (no userspace copy — what nginx/caddy do); any other
    /// transport (TLS, a wrapped/duplex stream, HTTP/2) reads the region and writes
    /// it normally, so the output is always identical — the file variant is a pure
    /// how-it-moves optimization. The serving layer only produces this for plaintext
    /// large static blobs. `len` is the content length (framing is fixed).
    File {
        // `Arc` so the source can ride an `http::Extensions` (which requires the value
        // be `Clone`) from the serving layer to the codec; `std::fs::File` is not `Clone`.
        file: std::sync::Arc<std::fs::File>,
        offset: u64,
        len: u64,
    },
}

impl Body {
    /// A streamed body from an **infallible** pull [`Stream`](tokio_stream::Stream) of
    /// `Bytes` chunks — the driver polls it directly (no channel/task hop). Empty
    /// chunks are skipped; the stream ending signals end-of-body.
    pub fn stream(chunks: impl tokio_stream::Stream<Item = Bytes> + Send + 'static) -> Self {
        Self::Stream(Box::pin(chunks.map(Ok)))
    }

    /// A streamed body from a **fallible** pull [`Stream`](tokio_stream::Stream) — a
    /// [`BodyError`] item mid-stream aborts the client stream (see [`BodyError`]).
    /// A reverse-proxy bridge uses this so an upstream failure isn't framed as a
    /// clean end.
    pub fn try_stream(
        chunks: impl tokio_stream::Stream<Item = BodyChunk> + Send + 'static,
    ) -> Self {
        Self::Stream(Box::pin(chunks))
    }

    /// The body length if known ahead of time. A [`Body::Stream`] has no known length
    /// (`0`) — it is delimited by end-of-stream, so callers must use [`is_empty`]
    /// rather than `len() == 0` to decide whether a body is present.
    ///
    /// [`is_empty`]: Body::is_empty
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            Self::Stream(_) => 0,
            Self::File { len, .. } => *len as usize,
        }
    }
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Bytes(b) => b.is_empty(),
            Self::Stream(_) => false,
            Self::File { len, .. } => *len == 0,
        }
    }

    /// A zero-copy static body: `[offset, offset+len)` of `file` (see [`Body::File`]).
    pub fn file(file: std::sync::Arc<std::fs::File>, offset: u64, len: u64) -> Self {
        Self::File { file, offset, len }
    }
}

/// Read a `[offset, offset+len)` region of a file into an owned buffer — the fallback
/// path for a [`Body::File`] on a transport that can't `sendfile` (TLS, HTTP/2, a
/// wrapped stream, or a non-Linux target). Reads through a private clone of the handle
/// so the original's cursor (and any concurrent reader) is untouched. Portable
/// (`Seek`+`Read`), so the codec builds on the release's Windows target too.
pub(crate) fn read_file_region(
    file: &std::fs::File,
    offset: u64,
    len: u64,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = file.try_clone()?;
    handle.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    handle.read_exact(&mut buf)?;
    Ok(buf)
}

impl Default for Body {
    fn default() -> Self {
        Self::Bytes(Vec::new())
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}
impl From<&[u8]> for Body {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(v.to_vec())
    }
}

/// Build a [`Response`] with a status and body and no extra headers — a small
/// convenience over `http::Response::builder()` for handlers.
pub fn response(status: u16, body: impl Into<Body>) -> Response {
    let mut resp = http::Response::new(body.into());
    *resp.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
    resp
}

/// A request handler. A connection driver calls this once per request.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send;
}
