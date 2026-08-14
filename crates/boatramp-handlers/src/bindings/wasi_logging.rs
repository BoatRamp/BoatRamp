//! The `wasi:logging` host binding: a guest's structured `log(level, context, message)` calls
//! are captured into the same host [`LogSink`](crate::logging::LogSink) as its stdout/stderr,
//! with the level preserved (as a `[level]` prefix; `warn`/`error`/`critical` route to `stderr`,
//! the rest to `stdout`). Like stdio capture — and unlike the grantable capabilities — this is
//! host-side observability wired for every invocation, so it is **not** deny-by-default: a guest
//! that imports `wasi:logging` when no sink is wired simply has its messages dropped.
//!
//! The interface is vendored unversioned (`wasi:logging/logging`, matching the proposal's
//! canonical WIT and the version-agnostic import allowlist). A guest built against a *versioned*
//! `wasi:logging` package would not resolve this import; the portable stdout path still captures
//! its `println!` output regardless.

use crate::logging::{LogStream, LoggingBinding};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/wasi-logging-host",
    });
}

use generated::wasi::logging::logging as logging_iface;
use logging_iface::Level;

/// The per-invocation host view of the `wasi:logging` capability. `None` when no log sink is
/// wired for this invocation (messages are then dropped — capture is host-side, not a grant).
pub struct WasiLoggingHost<'a> {
    binding: Option<&'a LoggingBinding>,
}

impl<'a> WasiLoggingHost<'a> {
    pub fn new(binding: Option<&'a LoggingBinding>) -> Self {
        Self { binding }
    }
}

/// The stable tag for a level (mirrors the enum names).
fn level_str(level: Level) -> &'static str {
    match level {
        Level::Trace => "trace",
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
        Level::Critical => "critical",
    }
}

/// Diagnostic levels (`warn`/`error`/`critical`) route to `stderr`; the rest to `stdout` —
/// so an operator's existing stream filter keeps working across stdio and structured logs.
fn level_stream(level: Level) -> LogStream {
    match level {
        Level::Warn | Level::Error | Level::Critical => LogStream::Stderr,
        _ => LogStream::Stdout,
    }
}

/// Render one structured log message into a captured line, preserving the level (and the
/// context tag, when non-empty) as a text prefix.
fn render(level: Level, context: &str, message: &str) -> String {
    if context.is_empty() {
        format!("[{}] {message}", level_str(level))
    } else {
        format!("[{}] {context}: {message}", level_str(level))
    }
}

impl logging_iface::Host for WasiLoggingHost<'_> {
    fn log(&mut self, level: Level, context: String, message: String) {
        let Some(binding) = self.binding else {
            return; // no sink wired → drop (capture is host-side observability, not a grant)
        };
        binding.sink.append_tagged(
            &binding.scope,
            binding.request_id.as_deref(),
            level_stream(level),
            &render(level, &context, &message),
        );
    }
}

/// Add the `wasi:logging` interface to `linker`, resolving the per-invocation host via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> WasiLoggingHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    logging_iface::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::logging_iface::{Host, Level};
    use super::*;
    use crate::logging::LogSink;
    use std::sync::{Arc, Mutex};

    /// One recorded append: `(scope, request_id, stream, line)`.
    type Recorded = (String, Option<String>, LogStream, String);

    /// Records every appended line.
    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<Recorded>>);

    impl LogSink for RecordingSink {
        fn append(&self, scope: &str, stream: LogStream, line: &str) {
            self.append_tagged(scope, None, stream, line);
        }
        fn append_tagged(
            &self,
            scope: &str,
            request_id: Option<&str>,
            stream: LogStream,
            line: &str,
        ) {
            self.0.lock().unwrap().push((
                scope.to_string(),
                request_id.map(str::to_string),
                stream,
                line.to_string(),
            ));
        }
    }

    fn binding(sink: Arc<dyn LogSink>, request_id: Option<&str>) -> LoggingBinding {
        LoggingBinding {
            sink,
            scope: "blog".to_string(),
            request_id: request_id.map(str::to_string),
        }
    }

    #[test]
    fn a_granted_log_is_captured_with_its_level_stream_and_request_id() {
        let sink = Arc::new(RecordingSink::default());
        let b = binding(sink.clone(), Some("r-7"));
        let mut host = WasiLoggingHost::new(Some(&b));
        host.log(Level::Info, "auth".into(), "signed in".into());
        host.log(Level::Error, String::new(), "boom".into());
        let calls = sink.0.lock().unwrap();
        // info → stdout, context folded into the line as a prefix, tagged with the request id.
        assert_eq!(calls[0].0, "blog");
        assert_eq!(calls[0].1.as_deref(), Some("r-7"));
        assert_eq!(calls[0].2, LogStream::Stdout);
        assert_eq!(calls[0].3, "[info] auth: signed in");
        // error → stderr; empty context omits the tag.
        assert_eq!(calls[1].2, LogStream::Stderr);
        assert_eq!(calls[1].3, "[error] boom");
    }

    #[test]
    fn an_ungranted_log_is_dropped() {
        let mut host = WasiLoggingHost::new(None);
        host.log(Level::Warn, "x".into(), "nothing to capture".into()); // no panic, no sink
    }
}
