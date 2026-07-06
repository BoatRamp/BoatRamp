//! Guest log capture.
//!
//! Instead of inheriting the host's stdio, the engine pipes each invocation's
//! `stdout`/`stderr` into a host [`LogSink`], line-buffered and tagged by the
//! invocation's binding *scope* and which stream it came from. This is the
//! portable capture path — it catches `println!`/`eprintln!` and panic output
//! from any guest, regardless of language or whether the guest knows about a
//! logging interface. The concrete sink (a per-site bounded ring with a rate
//! cap) lives in the server.

use std::sync::Arc;

use bytes::Bytes;
use wasmtime_wasi::{async_trait, OutputStream, Pollable, StdoutStream, StreamResult};

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
            LogStream::Stdout => "stdout",
            LogStream::Stderr => "stderr",
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
}

/// The logging capability handed to an invocation: where its captured output
/// goes, and under what scope it is tagged.
#[derive(Clone)]
pub struct LoggingBinding {
    pub(crate) sink: Arc<dyn LogSink>,
    pub(crate) scope: String,
}

/// Longest newline-free run buffered before it is force-flushed as one line, so
/// a guest spewing bytes without a newline can't grow host memory unbounded.
const MAX_LINE: usize = 16 * 1024;

/// A [`StdoutStream`] factory yielding line-buffering writers that forward to a
/// [`LogSink`]. One is installed per `stdout`/`stderr` of an invocation.
pub(crate) struct SinkStdout {
    sink: Arc<dyn LogSink>,
    scope: String,
    stream: LogStream,
}

impl SinkStdout {
    pub(crate) fn new(binding: &LoggingBinding, stream: LogStream) -> Self {
        Self {
            sink: binding.sink.clone(),
            scope: binding.scope.clone(),
            stream,
        }
    }
}

impl StdoutStream for SinkStdout {
    fn stream(&self) -> Box<dyn OutputStream> {
        Box::new(SinkWriter {
            sink: self.sink.clone(),
            scope: self.scope.clone(),
            stream: self.stream,
            buf: Vec::new(),
        })
    }

    fn isatty(&self) -> bool {
        false
    }
}

/// The actual output stream: accumulates bytes and forwards complete lines.
struct SinkWriter {
    sink: Arc<dyn LogSink>,
    scope: String,
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
            self.sink
                .append(&self.scope, self.stream, text.trim_end_matches('\r'));
        }
        if self.buf.len() > MAX_LINE {
            let text = String::from_utf8_lossy(&self.buf);
            self.sink.append(&self.scope, self.stream, &text);
            self.buf.clear();
        }
    }
}

impl OutputStream for SinkWriter {
    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        self.buf.extend_from_slice(&bytes);
        self.drain_lines();
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        // Never apply backpressure — capture is best-effort and must not stall
        // (or deadlock) the guest; the sink's rate cap drops excess instead.
        Ok(usize::MAX)
    }
}

#[async_trait]
impl Pollable for SinkWriter {
    async fn ready(&mut self) {}
}

impl Drop for SinkWriter {
    fn drop(&mut self) {
        // Flush a trailing, newline-less partial line when the stream closes at
        // the end of the invocation.
        if !self.buf.is_empty() {
            let text = String::from_utf8_lossy(&self.buf);
            self.sink
                .append(&self.scope, self.stream, text.trim_end_matches('\r'));
        }
    }
}
