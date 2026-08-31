//! `docker exec`-style re-entry into a **running** container, Linux-only.
//!
//! Runs a one-shot command inside an already-jailed container by joining its
//! namespaces (the same namespaces the [`worker`](crate::worker) unshared at
//! launch) and `execvp`-ing the command there, capturing its stdout/stderr and
//! exit status. No external `nsenter` (the shipped musl image has no util-linux)
//! and no CRIU — this is the live-container analogue of the launch path's
//! `setns` netns config, generalized to every namespace.
//!
//! ## Why the double fork
//!
//! The container is a **rootless user-namespace** container (its ids are mapped
//! onto an unprivileged host range — see [`worker::USERNS_HOST_BASE`]), so we must
//! join its user namespace, and to create an inode / signal a process inside it we
//! adopt the mapped namespace-root identity (uid/gid `0`, which the map points at
//! the host base) exactly as the worker's forked init does. The ordering the
//! kernel requires:
//!
//! 1. `setns(CLONE_NEWUSER)` **first** — every other namespace is owned by that
//!    user namespace, so joining them is only permitted once we hold it;
//! 2. then `setns` the mount / pid / net / uts / ipc namespaces;
//! 3. `setns(CLONE_NEWPID)` only affects **children** created afterward (a process
//!    can't change its own pid namespace), so we `fork` once more — the grandchild
//!    is then a first-class member of the container's pid namespace (it can see the
//!    container's `/proc`, is reaped by the container init, etc.).
//!
//! We do all of this in a forked **child** so the calling server's own namespaces
//! are never touched (`setns` is per-thread/process and irreversible for the pid
//! ns). The intermediate child joins the namespaces + forks the grandchild, waits
//! for it, and exits carrying the grandchild's status; the grandchild dups the
//! pipes onto its stdio, `chdir("/")`, and `execvp`s the command.
//!
//! [`worker`]: crate::worker
//! [`worker::USERNS_HOST_BASE`]: crate::worker::USERNS_HOST_BASE

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::path::Path;

use boatramp_core::compute::{BackendError, ExecOutput};
use nix::sched::{setns, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    chdir, close, dup2, execvp, fork, pipe, setresgid, setresuid, ForkResult, Gid, Pid, Uid,
};

/// The namespaces we join (in this order — user first) to re-enter a running
/// container. Each maps a `/proc/<pid1>/ns/<file>` to the `setns` flag; the pid
/// namespace is joined last because it only affects the post-`fork` grandchild.
const NS_JOIN: &[(&str, CloneFlags)] = &[
    ("user", CloneFlags::CLONE_NEWUSER),
    ("mnt", CloneFlags::CLONE_NEWNS),
    ("uts", CloneFlags::CLONE_NEWUTS),
    ("ipc", CloneFlags::CLONE_NEWIPC),
    ("net", CloneFlags::CLONE_NEWNET),
    ("pid", CloneFlags::CLONE_NEWPID),
];

/// The container id's cgroup.procs path (`/sys/fs/cgroup/boatramp/<id>/cgroup.procs`),
/// the set of host pids in the container — the input to [`crate::criu::find_pid1`].
fn cgroup_procs_path(id: &str) -> String {
    format!("/sys/fs/cgroup/boatramp/{id}/cgroup.procs")
}

/// Run `argv` inside the container identified by `container_id` (the launch-time
/// `<workload>-<replica>` stem), feeding `stdin` to it and buffering its
/// stdout/stderr + exit code. See the module docs for the namespace-join recipe.
///
/// Blocking (it `fork`s + does synchronous pipe IO), so the async `ComputeBackend`
/// impl runs it on a blocking thread.
pub fn exec_in_container(
    container_id: &str,
    argv: &[String],
    stdin: Option<&[u8]>,
) -> Result<ExecOutput, BackendError> {
    if argv.is_empty() {
        return Err(BackendError::Other("exec: empty argv".into()));
    }

    // Resolve the container's pid1 (the pidns init) from its cgroup. Absent ⇒ the
    // container isn't running (or was never launched) — a clear operator error.
    let procs = cgroup_procs_path(container_id);
    let pid1 = crate::criu::find_pid1(Path::new(&procs)).ok_or_else(|| {
        BackendError::Other(format!(
            "exec: container {container_id} is not running (no pid1 in {procs})"
        ))
    })?;

    // Open an fd for each namespace of pid1 up front (in the parent, before the
    // fork): the child inherits them, and opening them here surfaces a vanished
    // container as a plain error rather than a child-process failure.
    let ns_fds = open_ns_fds(pid1)?;

    // Pipes: (read, write). The child writes stdout/stderr; the parent reads them.
    // stdin is optional — when present the parent writes it and the child reads fd 0.
    let (out_r, out_w) =
        pipe().map_err(|e| BackendError::Other(format!("exec: pipe stdout: {e}")))?;
    let (err_r, err_w) =
        pipe().map_err(|e| BackendError::Other(format!("exec: pipe stderr: {e}")))?;
    let stdin_pipe = match stdin {
        Some(_) => Some(pipe().map_err(|e| BackendError::Other(format!("exec: pipe stdin: {e}")))?),
        None => None,
    };

    // SAFETY: fork in a process that is single-threaded *for the purpose of the
    // child's syscall sequence* — the child only calls async-signal-safe operations
    // (setns/fork/dup2/close/chdir/setresuid/execvp) before `execvp`, so it never
    // touches a lock a sibling thread might hold. This mirrors the worker's fork.
    match unsafe { fork() }.map_err(|e| BackendError::Other(format!("exec: fork: {e}")))? {
        ForkResult::Child => {
            // The command must inherit ONLY the fds it needs (its stdout/stderr write
            // ends + its stdin read end). Every other inherited fd is explicitly closed
            // here: the parent's read ends (`out_r`/`err_r`) — else the command holding
            // a read end would keep the pipe from ever signalling EOF to itself — and
            // the stdin WRITE end, whose survival in this process would stop the
            // command's `cat` from ever seeing EOF on stdin (the classic pipe leak).
            drop(out_r);
            drop(err_r);
            // Detach the fds we keep via `into_raw_fd` so their `OwnedFd`s don't
            // double-close on scope exit; the grandchild `close`s them after `dup2`.
            let out_w = out_w.into_raw_fd();
            let err_w = err_w.into_raw_fd();
            let stdin_r = stdin_pipe.map(|(r, w)| {
                drop(w); // command never writes its own stdin
                r.into_raw_fd()
            });
            child_enter_and_exec(&ns_fds, argv, out_w, err_w, stdin_r);
            // child_enter_and_exec never returns on success (execvp) and exits on error.
            unreachable!("exec child returned");
        }
        ForkResult::Parent { child } => {
            // Close the child-side fds in the parent so our reads see EOF when the
            // child (grandchild) exits, and drop the ns fds we no longer need.
            drop(out_w);
            drop(err_w);
            drop(ns_fds);
            let stdin_w = stdin_pipe.map(|(r, w)| {
                drop(r); // parent never reads stdin
                w
            });
            parent_pump_and_reap(child, out_r, err_r, stdin_w, stdin)
        }
    }
}

/// Open the `/proc/<pid1>/ns/<name>` file for each namespace we join, returned in
/// the same order as [`NS_JOIN`] so the child `setns`es them in order (user first).
fn open_ns_fds(pid1: u32) -> Result<Vec<(OwnedFd, CloneFlags)>, BackendError> {
    NS_JOIN
        .iter()
        .map(|(name, flag)| {
            let path = format!("/proc/{pid1}/ns/{name}");
            let file = std::fs::File::open(&path)
                .map_err(|e| BackendError::Other(format!("exec: open {path}: {e}")))?;
            Ok((OwnedFd::from(file), *flag))
        })
        .collect()
}

/// In the forked child: join the container's namespaces (user first), adopt the
/// mapped namespace-root identity, `fork` so the grandchild is in the container's
/// pid namespace, wire the grandchild's stdio to the pipes, `chdir("/")`, and
/// `execvp` `argv`. Never returns on success; on any error it prints to the real
/// stderr and exits non-zero (the parent then sees a non-zero exit).
fn child_enter_and_exec(
    ns_fds: &[(OwnedFd, CloneFlags)],
    argv: &[String],
    out_w: i32,
    err_w: i32,
    stdin_r: Option<i32>,
) {
    // Join every namespace in order — user first (it owns the others), pid last (it
    // only takes effect for the grandchild forked below).
    for (fd, flag) in ns_fds {
        if let Err(e) = setns(fd, *flag) {
            fail(format!("setns {flag:?}: {e}"));
        }
    }
    // Adopt the container's mapped namespace-root (uid/gid 0 → host base). Our host
    // identity is unmapped in the joined user namespace (the map starts at the host
    // base), so without this our fsuid is the overflow id and any inode / process
    // access inside fails. Same adoption the worker's init does. gid before uid.
    if let Err(e) = setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0)) {
        fail(format!("setresgid ns-root: {e}"));
    }
    if let Err(e) = setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)) {
        fail(format!("setresuid ns-root: {e}"));
    }

    // A PID namespace only takes effect for children created after `setns`, so fork:
    // the grandchild is a member of the container's pid namespace; this intermediate
    // child stays in the host pidns and reaps it, propagating its status.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Intermediate: close the fds meant for the grandchild, wait for it, and
            // exit carrying its status so the top-level parent can decode it.
            let _ = close(out_w);
            let _ = close(err_w);
            if let Some(fd) = stdin_r {
                let _ = close(fd);
            }
            match waitpid(child, None) {
                Ok(status) => std::process::exit(encode_status(status)),
                Err(e) => fail(format!("waitpid grandchild: {e}")),
            }
        }
        Ok(ForkResult::Child) => {
            // Grandchild: this is the command's process. Wire stdio to the pipes.
            grandchild_exec(argv, out_w, err_w, stdin_r);
            unreachable!("grandchild returned");
        }
        Err(e) => fail(format!("fork grandchild: {e}")),
    }
}

/// The grandchild (in the container's pid namespace): `dup2` the pipe ends onto
/// stdin/stdout/stderr, `chdir("/")`, and `execvp` the command. Never returns on
/// success.
fn grandchild_exec(argv: &[String], out_w: i32, err_w: i32, stdin_r: Option<i32>) {
    // stdout(1) + stderr(2) from the write ends. If no stdin was supplied, redirect
    // fd 0 from /dev/null so the command reads EOF immediately (not the parent's tty).
    if let Err(e) = dup2(out_w, 1) {
        fail(format!("dup2 stdout: {e}"));
    }
    if let Err(e) = dup2(err_w, 2) {
        fail(format!("dup2 stderr: {e}"));
    }
    match stdin_r {
        Some(fd) => {
            if let Err(e) = dup2(fd, 0) {
                fail(format!("dup2 stdin: {e}"));
            }
        }
        None => match std::fs::File::open("/dev/null") {
            Ok(f) => {
                if let Err(e) = dup2(f.as_raw_fd(), 0) {
                    fail(format!("dup2 /dev/null: {e}"));
                }
            }
            Err(e) => fail(format!("open /dev/null: {e}")),
        },
    }
    // Close the original pipe fds now they're duped onto 0/1/2 (best-effort). Guard on
    // `> 2` so we never close a stdio fd we just set up (the pipe fds are allocated in
    // the server parent, which holds 0/1/2, so they're always high — the guard is
    // belt-and-suspenders).
    if out_w > 2 {
        let _ = close(out_w);
    }
    if err_w > 2 {
        let _ = close(err_w);
    }
    if let Some(fd) = stdin_r {
        if fd > 2 {
            let _ = close(fd);
        }
    }

    // Run from the container root (the joined mount namespace's `/`), so a relative
    // command / cwd behaves like a fresh container process.
    if let Err(e) = chdir("/") {
        fail(format!("chdir /: {e}"));
    }

    let cargv: Vec<CString> = match argv
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => fail("argv has an interior NUL".to_string()),
    };
    match execvp(&cargv[0], &cargv) {
        Ok(_) => unreachable!("execvp returned Ok"),
        // 127 = "command not found", the shell convention for a failed exec.
        Err(e) => {
            eprintln!("boatramp exec: execvp {:?}: {e}", argv[0]);
            std::process::exit(127);
        }
    }
}

/// In the top-level parent: write `stdin` to the child (if any) and drain
/// stdout/stderr to EOF concurrently (separate threads, so a full pipe on one
/// stream can't deadlock the other or the stdin write), then reap the intermediate
/// child and decode the command's status.
fn parent_pump_and_reap(
    child: Pid,
    out_r: OwnedFd,
    err_r: OwnedFd,
    stdin_w: Option<OwnedFd>,
    stdin: Option<&[u8]>,
) -> Result<ExecOutput, BackendError> {
    // Read each pipe on its own thread. `File::from` takes ownership of the fd, so
    // it's closed when the reader thread finishes.
    let out_handle = std::thread::spawn(move || read_to_end(out_r));
    let err_handle = std::thread::spawn(move || read_to_end(err_r));

    // Feed stdin, then drop the write end so the command sees EOF. A write error
    // (e.g. the command exited without reading) is not fatal — treat a broken pipe
    // as "the command didn't consume all input" and continue to collect its output.
    if let (Some(w), Some(data)) = (stdin_w, stdin) {
        let mut f = std::fs::File::from(w);
        let _ = f.write_all(data);
        drop(f); // EOF for the command's fd 0
    }

    let stdout = out_handle
        .join()
        .map_err(|_| BackendError::Other("exec: stdout reader panicked".into()))?
        .map_err(|e| BackendError::Other(format!("exec: read stdout: {e}")))?;
    let stderr = err_handle
        .join()
        .map_err(|_| BackendError::Other("exec: stderr reader panicked".into()))?
        .map_err(|e| BackendError::Other(format!("exec: read stderr: {e}")))?;

    // Reap the intermediate child; it exited with the encoded command status.
    let exit_code = match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
        Ok(other) => {
            return Err(BackendError::Other(format!(
                "exec: unexpected wait status {other:?}"
            )))
        }
        Err(e) => return Err(BackendError::Other(format!("exec: waitpid: {e}"))),
    };

    Ok(ExecOutput {
        exit_code,
        stdout,
        stderr,
    })
}

/// Read an owned fd to EOF, taking ownership so it's closed on return.
fn read_to_end(fd: OwnedFd) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::from(fd);
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Encode a reaped [`WaitStatus`] into the exit code the intermediate child exits
/// with, so the top-level parent recovers the command's real status: a normal exit
/// passes its code through; a signal maps to `128 + signal` (shell convention).
/// The child can only pass a `u8` out via its own exit code, and both branches fit
/// (`0..=255` / `128 + <=64`).
fn encode_status(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    }
}

/// Print a child-side failure to the real stderr and exit non-zero. Runs only in a
/// forked child (never the server process), so exiting is correct — `126` marks a
/// pre-exec setup failure (distinct from the command's own `127`/status).
fn fail(msg: String) -> ! {
    eprintln!("boatramp exec: {msg}");
    std::process::exit(126);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_procs_path_matches_the_launch_layout() {
        assert_eq!(
            cgroup_procs_path("web-0"),
            "/sys/fs/cgroup/boatramp/web-0/cgroup.procs"
        );
    }

    #[test]
    fn ns_join_order_puts_user_first_and_pid_last() {
        // The kernel requires the user namespace joined first (it owns the others)
        // and the pid namespace last (it only affects the post-fork grandchild).
        assert_eq!(NS_JOIN.first().map(|(n, _)| *n), Some("user"));
        assert_eq!(NS_JOIN.last().map(|(n, _)| *n), Some("pid"));
        assert_eq!(NS_JOIN.len(), 6, "user+mnt+uts+ipc+net+pid");
    }

    #[test]
    fn encode_status_passes_exit_and_maps_signal() {
        assert_eq!(encode_status(WaitStatus::Exited(Pid::from_raw(1), 0)), 0);
        assert_eq!(encode_status(WaitStatus::Exited(Pid::from_raw(1), 42)), 42);
        assert_eq!(
            encode_status(WaitStatus::Signaled(
                Pid::from_raw(1),
                nix::sys::signal::Signal::SIGKILL,
                false
            )),
            128 + 9
        );
    }

    #[test]
    fn empty_argv_is_rejected() {
        let err = exec_in_container("nope-0", &[], None).unwrap_err();
        assert!(matches!(err, BackendError::Other(m) if m.contains("empty argv")));
    }
}
