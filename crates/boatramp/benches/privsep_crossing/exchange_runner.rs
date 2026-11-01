//! The measurement loop shared by every substrate that carries the PAYLOAD itself across the
//! crossing (byte-relay, container, vsock-loopback, vsock-firecracker) — only HOW a connection
//! to a fresh backend is obtained differs between them (a `connect` closure each substrate
//! module supplies). Substrate 1 (fd-pass) does NOT reuse this: it hands off an fd + head and
//! never waits for a payload response, so its own loop lives in `fdpass.rs`.
//!
//! Protocol contract with the backend (see `worker.rs`): the FIRST frame read on any freshly
//! connected fd is always a `READY` marker, sent only once the backend can actually serve — so
//! "time from `connect()` to that frame" is exactly the substrate's spawn/setup cost.

use std::io;
use std::os::fd::RawFd;
use std::process::Child;
use std::time::Instant;

use crate::stats::{self, Percentiles};
use crate::wire;

pub struct ExchangeOutcome {
    pub warm: Percentiles,
    pub warm_rps: f64,
    pub warm_iterations: usize,
    pub cold_spawn: Percentiles,
    pub cold_iterations: usize,
}

/// Runs the cold (spawn cost, N fresh backends) then warm (one persistent backend, many
/// round trips) measurement for one (substrate, payload) cell. `connect` spawns a fresh backend
/// and returns `(child, frontend-side connected fd)`; ownership of both passes to this function.
pub fn measure<F>(
    mut connect: F,
    head: &[u8],
    response_len: usize,
    warm_iterations: usize,
    cold_iterations: usize,
) -> io::Result<ExchangeOutcome>
where
    F: FnMut() -> io::Result<(Child, RawFd)>,
{
    let mut cold_us = Vec::with_capacity(cold_iterations.max(1));
    for _ in 0..cold_iterations {
        let t0 = Instant::now();
        let (mut child, fd) = connect()?;
        let _ready = wire::read_frame(fd)?;
        cold_us.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
        // SAFETY: `fd` is exclusively owned by this scope (the connector hands over ownership).
        unsafe {
            libc::close(fd);
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    let (mut warm_child, warm_fd) = connect()?;
    let _ready = wire::read_frame(warm_fd)?; // untimed setup — excluded from the warm sample set
    let mut resp_buf = Vec::new();
    let mut warm_us = Vec::with_capacity(warm_iterations);
    for _ in 0..warm_iterations {
        let d = wire::client_exchange(warm_fd, head, response_len, &mut resp_buf)?;
        warm_us.push(d.as_secs_f64() * 1_000_000.0);
    }
    // SAFETY: `warm_fd` is exclusively owned here.
    unsafe {
        libc::close(warm_fd);
    }
    let _ = warm_child.kill();
    let _ = warm_child.wait();

    Ok(ExchangeOutcome {
        warm: stats::summarize(&warm_us),
        warm_rps: stats::throughput_rps(&warm_us),
        warm_iterations,
        cold_spawn: stats::summarize(&cold_us),
        cold_iterations,
    })
}
