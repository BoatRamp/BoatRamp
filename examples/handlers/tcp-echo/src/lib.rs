// A boatramp *inbound-TCP connection* guest (PLAN-handler-tcp-inbound): the host binds + listens +
// accepts on an operator-declared `[serve.listeners.<name>]` and re-enters `handle` ONCE per
// already-accepted connection, handing it the peer address plus the connection's `wasi:io` byte
// streams. This guest holds NO `wasi:sockets` authority — the host owns the socket. It echoes every
// inbound byte straight back to the peer until EOF / peer-drop, then returns `Ok` — exercising the
// real accept→dispatch→read→write→teardown path for the inbound-TCP live gate.
wit_bindgen::generate!({
    world: "boatramp:caps-example/tcp-echo",
    path: "wit",
    generate_all,
});

use exports::boatramp::handlers::tcp_connection_handler::{ConnectionError, Guest};
use wasi::io::streams::{InputStream, OutputStream, StreamError};

struct Component;

// `output-stream.blocking-write-and-flush` accepts at most 4096 bytes per call, so read + echo in
// chunks bounded by that.
const CHUNK: u64 = 4096;

impl Guest for Component {
    fn handle(
        _peer: String,
        input: InputStream,
        output: OutputStream,
    ) -> Result<(), ConnectionError> {
        loop {
            match input.blocking_read(CHUNK) {
                Ok(bytes) => {
                    // `blocking-read` returns at least one byte unless the stream is closed; an empty
                    // slice (possible on a spurious ready) just loops to read again.
                    if bytes.is_empty() {
                        continue;
                    }
                    output.blocking_write_and_flush(&bytes).map_err(|e| {
                        ConnectionError {
                            message: match e {
                                StreamError::Closed => "peer closed while writing".to_string(),
                                StreamError::LastOperationFailed(_) => {
                                    "write failed".to_string()
                                }
                            },
                        }
                    })?;
                }
                // The peer closed its write half (EOF) — the normal end of the echo.
                Err(StreamError::Closed) => return Ok(()),
                Err(StreamError::LastOperationFailed(_)) => {
                    return Err(ConnectionError {
                        message: "read failed".to_string(),
                    });
                }
            }
        }
    }
}

export!(Component);
