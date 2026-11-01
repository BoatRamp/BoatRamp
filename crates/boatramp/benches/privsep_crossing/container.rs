//! Substrate 3: **container (namespace-isolated backend).** The SAME socketpair byte-relay
//! crossing as `byterelay.rs` — the only difference is that the backend process is spawned
//! inside fresh net/pid/mount/uts/ipc namespaces via `unshare --fork` (the task spec's "netns
//! /pidns via unshare" option), isolating it like a container's backend WITHOUT pulling in a
//! full container runtime/image layer — those add one-time setup cost, not per-request crossing
//! cost, so separating them out keeps this measurement honest about what a NAMESPACE boundary
//! alone costs vs. substrate 2's plain same-namespace socketpair.
//!
//! The pre-existing socketpair fd handed to the namespaced child is an ANONYMOUS `AF_UNIX`
//! socket (no filesystem path) — unaffected by the net/mount namespace change, so this isolates
//! exactly the namespace-boundary overhead, not a different IPC mechanism.
//!
//! Needs `CAP_SYS_ADMIN` (new net/mount namespaces) — run the WHOLE harness under `sudo` for
//! this substrate (documented in `main.rs`'s `--help` and the methodology note); `unshare(1)`
//! must be on `$PATH` (checked at lighthouse: `/run/current-system/sw/bin/unshare`).

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
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "container substrate needs unshare(2) net/pid/mount namespaces — Linux-only",
        ));
    }
    let exe_str = current_exe.to_string_lossy().into_owned();
    let connect = || -> io::Result<(Child, RawFd)> {
        let (front, back) = spawn::raw_socketpair()?;
        let args: Vec<&str> = vec![
            "--mount",
            "--uts",
            "--ipc",
            "--net",
            "--pid",
            "--mount-proc",
            "--fork",
            "--",
            &exe_str,
            "_worker",
            "relay-fd",
            "--fd",
            "3",
        ];
        let child =
            spawn::spawn_with_inherited_fd(Path::new("unshare"), &args, back, core_backend)?;
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
