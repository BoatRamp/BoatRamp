//! Substrate 1: **OS-process, socketpair fd-pass (`SCM_RIGHTS`).** The BUILT Phase-1 `local`
//! transport, unmodified — drives the real `boatramp_server::privsep_link::LinkEndpoint`.
//!
//! Unlike every other byte-carrying substrate, the fd-pass crossing itself carries NO payload:
//! the frontend hands the backend an accepted client fd + a parsed head, then the response flows
//! directly backend-fd <-> client afterward, bypassing the link entirely (that's the whole point
//! — zero per-byte cost on the link). So there is nothing to wait for except an explicit 1-byte
//! ack frame this benchmark adds SOLELY so the frontend has something to time; a real deployed
//! frontend never waits for one. The reported latency here is "one `send_client_conn` + a 1-byte
//! ack round trip" — NOT a payload round trip — and the task spec's 4 payload-size columns are
//! still run independently (fresh samples each) to let the table show, empirically, that this
//! substrate's crossing cost does not vary with response size.

use std::io;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::process::Child;
use std::time::Instant;

use boatramp_server::privsep_link::LinkEndpoint;

use crate::exchange_runner::ExchangeOutcome;
use crate::spawn;
use crate::stats;

fn connect(current_exe: &Path, core_backend: Option<usize>) -> io::Result<(Child, LinkEndpoint)> {
    let (front, back) = LinkEndpoint::socketpair()?;
    let back_raw = back.into_raw_fd();
    let child = spawn::spawn_with_inherited_fd(
        current_exe,
        &["_worker", "fd-pass-backend", "--fd", "3"],
        back_raw,
        core_backend,
    )?;
    Ok((child, front))
}

pub fn run(
    current_exe: &Path,
    head: &[u8],
    warm_iterations: usize,
    cold_iterations: usize,
    core_backend: Option<usize>,
) -> io::Result<ExchangeOutcome> {
    // ---- cold: spawn + ready cost, N fresh backends ----
    let mut cold_us = Vec::with_capacity(cold_iterations.max(1));
    for _ in 0..cold_iterations {
        let t0 = Instant::now();
        let (mut child, front) = connect(current_exe, core_backend)?;
        let _ready = front.recv_frame()?;
        cold_us.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
        drop(front);
        let _ = child.kill();
        let _ = child.wait();
    }

    // ---- warm: one persistent backend, many fd handoffs ----
    let (mut warm_child, front) = connect(current_exe, core_backend)?;
    let _ready = front.recv_frame()?;
    let mut warm_us = Vec::with_capacity(warm_iterations);
    for _ in 0..warm_iterations {
        // A fresh anonymous socketpair stands in for a freshly-accepted client connection —
        // created BEFORE the timer starts, so its own cost isn't attributed to the crossing.
        let (client_near, client_far) = LinkEndpoint::socketpair()?;
        // SAFETY: `client_far` outlives this borrow (it's dropped only after the call returns).
        let borrowed = unsafe { BorrowedFd::borrow_raw(client_far.as_raw_fd()) };
        let t0 = Instant::now();
        front.send_client_conn(borrowed, head)?;
        let ack = front.recv_frame()?;
        warm_us.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
        debug_assert_eq!(ack, b"OK".to_vec());
        drop(client_near);
        drop(client_far);
    }
    drop(front);
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
