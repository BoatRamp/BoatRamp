//! The shared serving abstraction — the `Request`/`Response`/`Body`/`Handler` surface
//! both the [`h1`](crate::h1) and [`h2`](crate::h2) codecs produce/consume, and that the
//! unified serve dispatcher (Stage 3) will hand to a `tower::Service` (the axum Router).
//! These are the standard `http` crate types, so an embedder — or a reverse-proxy bridge
//! — pays no per-request re-marshaling.

use std::future::Future;

use bytes::Bytes;
use tokio_stream::StreamExt as _;

/// A received request: an `http::Request` whose (buffered) body is `Bytes`. For h2 the
/// pseudo-headers are hoisted into the method / URI (path) / `Host` header.
pub type Request = http::Request<Bytes>;

/// A response to send: an `http::Response` whose body is a [`Body`].
pub type Response = http::Response<Body>;

/// A streamed body's source failed mid-stream (e.g. a reverse-proxy upstream dropped
/// the connection before delivering the whole body). Yielding this from a body
/// [`Stream`](tokio_stream::Stream) tells the driver to abort the client stream
/// (h2: RST_STREAM) rather than close it cleanly — so a truncated body is never framed as
/// complete (which, for a response with no `content-length`, the client can't detect).
#[derive(Debug, Clone, Default)]
pub struct BodyError;

/// A single streamed body chunk, or a mid-stream source failure ([`BodyError`]).
pub type BodyChunk = Result<Bytes, BodyError>;

/// A response body: buffered bytes; a stream `splice()`d directly from an upstream
/// socket into the (kTLS) client socket (Linux zero-copy); or a pull [`Stream`] of
/// [`BodyChunk`]s forwarded as it arrives (a reverse proxy streaming an upstream response
/// without buffering or copying it — the stream ending signals end-of-body; a
/// [`BodyError`] item aborts the stream). The driver **polls the stream directly**, so a
/// bridge hands its upstream body straight in with no intermediate channel or producer
/// task. The concurrent [`h2::mux`](crate::h2::mux) driver streams the last two natively;
/// the serial [`h2::conn`](crate::h2::conn) driver buffers a `Stream` (it can't interleave).
///
/// [`Stream`]: tokio_stream::Stream
pub enum Body {
    Bytes(Vec<u8>),
    #[cfg(target_os = "linux")]
    Splice {
        upstream: tokio::net::TcpStream,
        len: usize,
    },
    Stream(std::pin::Pin<Box<dyn tokio_stream::Stream<Item = BodyChunk> + Send>>),
}

impl Body {
    /// A streamed body from an **infallible** pull [`Stream`](tokio_stream::Stream) of
    /// `Bytes` chunks — the driver polls it directly (no channel/task hop). Empty
    /// chunks are skipped; the stream ending signals end-of-body.
    pub fn stream(chunks: impl tokio_stream::Stream<Item = Bytes> + Send + 'static) -> Self {
        Body::Stream(Box::pin(chunks.map(Ok)))
    }

    /// A streamed body from a **fallible** pull [`Stream`](tokio_stream::Stream) — a
    /// [`BodyError`] item mid-stream aborts the client stream (see [`BodyError`]).
    /// A reverse-proxy bridge uses this so an upstream failure isn't framed as a
    /// clean end.
    pub fn try_stream(
        chunks: impl tokio_stream::Stream<Item = BodyChunk> + Send + 'static,
    ) -> Self {
        Body::Stream(Box::pin(chunks))
    }

    /// The body length if known ahead of time. A [`Body::Stream`] has no known length
    /// (`0`) — it is delimited by end-of-stream, so callers must use [`is_empty`]
    /// rather than `len() == 0` to decide whether a body is present.
    ///
    /// [`is_empty`]: Body::is_empty
    pub fn len(&self) -> usize {
        match self {
            Body::Bytes(b) => b.len(),
            #[cfg(target_os = "linux")]
            Body::Splice { len, .. } => *len,
            Body::Stream(_) => 0,
        }
    }
    pub fn is_empty(&self) -> bool {
        match self {
            Body::Bytes(b) => b.is_empty(),
            #[cfg(target_os = "linux")]
            Body::Splice { len, .. } => *len == 0,
            Body::Stream(_) => false,
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::Bytes(Vec::new())
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body::Bytes(v)
    }
}
impl From<&[u8]> for Body {
    fn from(v: &[u8]) -> Self {
        Body::Bytes(v.to_vec())
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
