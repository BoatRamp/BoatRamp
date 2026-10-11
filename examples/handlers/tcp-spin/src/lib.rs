// A boatramp *inbound-TCP connection* guest (PLAN-handler-tcp-inbound) — the COMPUTE-BOUND fixture
// for the HIGH-fix proof. On dispatch it IGNORES the connection and busy-loops forever with NO
// suspending host call, modeling a CPU-bound guest (a parser loop / ReDoS / decompression bomb on
// untrusted peer bytes). The ONLY thing that can end this connection is the conn-lane epoch-YIELD
// (`epoch_deadline_async_yield_and_update`) forcing the fiber to return `Poll::Pending` periodically
// so the host wall-clock watchdog can drop the call at `max_conn_duration`. Without that fix the guest
// would pin a tokio worker AND starve the watchdog — so the live gate's max-duration-teardown scenario
// for this guest is a genuine regression test for the HIGH finding.
wit_bindgen::generate!({
    world: "boatramp:caps-example/tcp-spin",
    path: "wit",
    generate_all,
});

use exports::boatramp::handlers::tcp_connection_handler::{ConnectionError, Guest};
use wasi::io::streams::{InputStream, OutputStream};

struct Component;

impl Guest for Component {
    fn handle(
        _peer: String,
        _input: InputStream,
        _output: OutputStream,
    ) -> Result<(), ConnectionError> {
        // Busy-loop forever with no host call — the host conn-lane epoch-yield + watchdog is what
        // preempts this (never returns on its own).
        loop {
            core::hint::spin_loop();
        }
    }
}

export!(Component);
