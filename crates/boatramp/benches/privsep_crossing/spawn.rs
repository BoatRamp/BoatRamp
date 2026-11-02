//! Shared "spawn a backend worker" plumbing: a plain `socketpair(2)` + the `pre_exec` `dup2`
//! trick that hands one end to a freshly-exec'd child at a FIXED fd number (3) — the same
//! pattern `boatramp_server::privsep_link`'s own root uses to wire a real privsep instance
//! (comment in `crates/boatramp/Cargo.toml`), reused here so substrates 2/3's backend spawn is
//! faithful to how the real root hands a link end to a child.

use std::io;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

/// A plain `AF_UNIX`/`SOCK_STREAM` socketpair, both ends `CLOEXEC` (mirrors
/// `privsep_link::LinkEndpoint::socketpair`'s own safety posture — neither end leaks to an
/// unrelated fork+exec by accident; the one end actually handed to a child is un-CLOEXEC'd by
/// the `dup2` in `pre_exec` below, which is the ONLY place either end becomes inheritable).
pub fn raw_socketpair() -> io::Result<(RawFd, RawFd)> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `fds` is a valid 2-element array the kernel fills in.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    for &fd in &fds {
        // SAFETY: `fd` was just created by the socketpair call above.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            // SAFETY: tightening this fd's own flags.
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
    Ok((fds[0], fds[1]))
}

/// The fixed fd number a spawned backend finds its inherited end at — matches the `--fd 3` the
/// orchestration modules pass to `_worker relay-fd`/`_worker fd-pass-backend`.
pub const CHILD_FD_SLOT: RawFd = 3;

/// Spawns `program` (+ `args`), handing `child_end` to it at [`CHILD_FD_SLOT`] via a `pre_exec`
/// `dup2` (clearing `CLOEXEC` on the NEW fd 3, which is `dup2`'s standard behavior — the
/// original `child_end` fd keeps its own `CLOEXEC` flag and is simply closed in the parent after
/// spawn, exactly like the real root closes both original socketpair ends once it has handed out
/// copies). If `pin_core` is set, the child self-pins via `PRIVSEP_BENCH_PIN_CORE` (read by
/// `worker.rs`'s `maybe_pin_from_env`) rather than affinity-setting the child from the parent
/// side — simpler, and correct even when `program` is `unshare` wrapping the real target.
pub fn spawn_with_inherited_fd(
    program: &Path,
    args: &[&str],
    child_end: RawFd,
    pin_core: Option<usize>,
) -> io::Result<Child> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(core) = pin_core {
        cmd.env("PRIVSEP_BENCH_PIN_CORE", core.to_string());
    }
    // SAFETY: the closure only calls `dup2` (async-signal-safe) before `execve`, per
    // `pre_exec`'s contract; `child_end` is a valid fd owned by this process until the `close`
    // below runs in the PARENT (the child's dup2'd copy at fd 3 is independent of it).
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(child_end, CHILD_FD_SLOT) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    // SAFETY: the parent's own copy of `child_end` is no longer needed — the child's dup2'd
    // fd 3 is a separate, independent reference to the same underlying socket.
    unsafe {
        libc::close(child_end);
    }
    Ok(child)
}
