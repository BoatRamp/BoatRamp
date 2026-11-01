//! Substrate 2: **OS-process, socketpair byte-relay.** A plain `socketpair(2)` between two
//! separate OS processes; the request head and the response payload both cross it as ordinary
//! bytes (one extra copy each way) — the Phase-1 shape where the frontend stays a POLICY POINT
//! (it can inspect/transform bytes) rather than splicing a raw fd.

use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::process::Child;

use crate::exchange_runner::{self, ExchangeOutcome};
use crate::spawn;

pub fn run(
    current_exe: &Path,
    head: &[u8],
    response_len: usize,
    warm_iterations: usize,
    cold_iterations: usize,
    core_backend: Option<usize>,
) -> io::Result<ExchangeOutcome> {
    let connect = || -> io::Result<(Child, RawFd)> {
        let (front, back) = spawn::raw_socketpair()?;
        let child = spawn::spawn_with_inherited_fd(
            current_exe,
            &["_worker", "relay-fd", "--fd", "3"],
            back,
            core_backend,
        )?;
        Ok((child, front))
    };
    exchange_runner::measure(
        connect,
        head,
        response_len,
        warm_iterations,
        cold_iterations,
    )
}
