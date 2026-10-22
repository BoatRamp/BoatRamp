//! Guest log capture.
//!
//! Instead of inheriting the host's stdio, the engine pipes each invocation's
//! `stdout`/`stderr` into a host [`LogSink`], line-buffered and tagged by the
//! invocation's binding *scope* and which stream it came from. This is the
//! portable capture path — it catches `println!`/`eprintln!` and panic output
//! from any guest, regardless of language or whether the guest knows about a
//! logging interface. The concrete sink (a per-site bounded ring with a rate
//! cap) lives in the server.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

/// Which standard stream a captured line came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

impl LogStream {
    /// Stable tag for the API / log line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// A host sink for captured guest log lines. The server implements this over a
/// per-site bounded ring with a rate cap; the engine writes scope-tagged lines
/// as the guest emits them.
pub trait LogSink: Send + Sync {
    /// Append one captured line (newline already stripped) emitted by `scope`'s
    /// guest on `stream`.
    fn append(&self, scope: &str, stream: LogStream, line: &str);

    /// Append one captured line correlated with the request `request_id` (when the dispatch
    /// layer assigned one — the same id the `boatramp::access` line carries). Defaults to the
    /// untagged [`append`](Self::append); a sink that surfaces the id (the server's log store)
    /// overrides this.
    fn append_tagged(&self, scope: &str, request_id: Option<&str>, stream: LogStream, line: &str) {
        let _ = request_id;
        self.append(scope, stream, line);
    }
}

/// The logging capability handed to an invocation: where its captured output
/// goes, under what scope it is tagged, and the request it belongs to.
#[derive(Clone)]
pub struct LoggingBinding {
    pub(crate) sink: Arc<dyn LogSink>,
    pub(crate) scope: String,
    /// The request id captured lines are tagged with (for access-log correlation), when the
    /// dispatch layer assigned one. `None` for invocations with no request context.
    pub(crate) request_id: Option<String>,
}

/// Longest newline-free run buffered before it is force-flushed as one line, so
/// a guest spewing bytes without a newline can't grow host memory unbounded.
const MAX_LINE: usize = 16 * 1024;

/// A [`StdoutStream`] factory yielding line-buffering writers that forward to a
/// [`LogSink`]. One is installed per `stdout`/`stderr` of an invocation.
pub(crate) struct SinkStdout {
    sink: Arc<dyn LogSink>,
    scope: String,
    request_id: Option<String>,
    stream: LogStream,
}

impl SinkStdout {
    pub(crate) fn new(binding: &LoggingBinding, stream: LogStream) -> Self {
        Self {
            sink: binding.sink.clone(),
            scope: binding.scope.clone(),
            request_id: binding.request_id.clone(),
            stream,
        }
    }
}

impl IsTerminal for SinkStdout {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for SinkStdout {
    // wasmtime 49's `StdoutStream` is `AsyncWrite`-based (the WASIp2 `OutputStream` is derived from
    // it by the trait's default `p2_stream` adapter). We only provide the async sink.
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(SinkWriter {
            sink: self.sink.clone(),
            scope: self.scope.clone(),
            request_id: self.request_id.clone(),
            stream: self.stream,
            buf: Vec::new(),
        })
    }
}

/// The actual output stream: accumulates bytes and forwards complete lines.
struct SinkWriter {
    sink: Arc<dyn LogSink>,
    scope: String,
    request_id: Option<String>,
    stream: LogStream,
    buf: Vec<u8>,
}

impl SinkWriter {
    /// Forward every complete (`\n`-terminated) line in the buffer, then
    /// force-flush an over-long unterminated remainder.
    fn drain_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line[..line.len() - 1]);
            self.sink.append_tagged(
                &self.scope,
                self.request_id.as_deref(),
                self.stream,
                text.trim_end_matches('\r'),
            );
        }
        if self.buf.len() > MAX_LINE {
            let text = String::from_utf8_lossy(&self.buf);
            self.sink
                .append_tagged(&self.scope, self.request_id.as_deref(), self.stream, &text);
            self.buf.clear();
        }
    }
}

impl AsyncWrite for SinkWriter {
    // Capture is best-effort and synchronous: buffer, forward complete lines, and always report the
    // whole write accepted (never backpressure — a slow/absent sink must not stall or deadlock the
    // guest; the sink's own rate cap drops excess).
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buf.extend_from_slice(bytes);
        self.drain_lines();
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for SinkWriter {
    fn drop(&mut self) {
        // Flush a trailing, newline-less partial line when the stream closes at
        // the end of the invocation.
        if !self.buf.is_empty() {
            let text = String::from_utf8_lossy(&self.buf);
            self.sink.append_tagged(
                &self.scope,
                self.request_id.as_deref(),
                self.stream,
                text.trim_end_matches('\r'),
            );
        }
    }
}
