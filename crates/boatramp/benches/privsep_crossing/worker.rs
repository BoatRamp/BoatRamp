//! Backend-role bodies, run in a RE-EXEC'd child process (`<exe> _worker <role> ...` — see
//! `main.rs`'s hidden dispatch). Keeping the backend as a real separate OS process (not a thread)
//! is what makes substrates 1-3 faithfully "OS-process" crossings, and lets each role be spawned
//! under `unshare` (substrate 3) or pinned to its own core (`PRIVSEP_BENCH_PIN_CORE` env var,
//! set by the frontend before `spawn()`) exactly like a real deployed instance would be.

use std::io;
use std::os::fd::RawFd;
use std::process::ExitCode;

use boatramp_server::privsep_link::LinkEndpoint;

use crate::affinity;
use crate::vsock_raw;
use crate::wire;

/// The byte every served response body is filled with — content is irrelevant, only volume is.
const FILL: u8 = 0xAB;
/// The fixed marker frame every backend sends exactly once, right after it is ready to serve —
/// the frontend's "time since connect()" to this frame IS the cold/spawn-cost measurement.
const READY: &[u8] = b"READY";

fn maybe_pin_from_env() {
    if let Ok(v) = std::env::var("PRIVSEP_BENCH_PIN_CORE") {
        if let Ok(core) = v.parse::<usize>() {
            let _ = affinity::pin_current_thread(core);
        }
    }
}

fn is_eof(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
    )
}

/// Substrate 1 (fd-pass) backend: the REAL Phase-1 `local` transport. Loops `recv_client_conn`,
/// drops the received fd (per design F5 it is opaque — this benchmark doesn't need to serve it
/// further to measure the crossing), and sends a 1-byte-frame ack so the frontend has something
/// to wait on (fd-pass carries no payload across the link itself, so there is nothing else to
/// time — see `fdpass.rs` for the full rationale).
pub fn run_fd_pass_backend(fd: RawFd) -> io::Result<()> {
    maybe_pin_from_env();
    // SAFETY: `fd` was handed to this process by the frontend's `pre_exec` dup2 and is owned
    // exclusively by this process from here on.
    let link = unsafe { LinkEndpoint::from_inherited_fd(fd) };
    link.send_frame(READY)?;
    loop {
        match link.recv_client_conn() {
            Ok((client_fd, _head)) => {
                drop(client_fd);
                link.send_frame(b"OK")?;
            }
            Err(e) if is_eof(&e) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

/// Substrates 2/3 (byte-relay / container) backend: an inherited, already-connected stream fd
/// (a plain socketpair for byte-relay; the SAME socketpair handed into a namespace-isolated
/// process for `container` — see `container.rs`). Runs the generic head+payload exchange loop.
pub fn run_relay_fd_backend(fd: RawFd) -> io::Result<()> {
    maybe_pin_from_env();
    wire::write_frame(fd, READY)?;
    wire::server_loop(fd, FILL)
}

/// Substrate 4a (vsock loopback) backend: creates its OWN `AF_VSOCK` listener bound to
/// `VMADDR_CID_LOCAL` (no fd is passed in — vsock endpoints aren't fd-passed in this design),
/// accepts exactly one connection (one benchmark run), then runs the same exchange loop.
pub fn run_vsock_loopback_backend(port: u32) -> io::Result<()> {
    maybe_pin_from_env();
    let listener = vsock_raw::socket_vsock()?;
    vsock_raw::bind_vsock(listener, vsock_raw::VMADDR_CID_LOCAL, port)?;
    vsock_raw::listen_vsock(listener, 4)?;
    let conn = vsock_raw::accept_vsock(listener)?;
    wire::write_frame(conn, READY)?;
    let result = wire::server_loop(conn, FILL);
    vsock_raw::close_fd(conn);
    vsock_raw::close_fd(listener);
    result
}

/// Hidden re-exec entry point: `<exe> _worker <role> [--fd N | --port N]` — `main.rs` forwards
/// everything after `_worker` here before any `clap` parsing runs, so a worker role never pays
/// for (or needs) the frontend's CLI surface. A plain manual scan of `--fd`/`--port` is enough —
/// every caller (`fdpass.rs`/`byterelay.rs`/`container.rs`/`vsock.rs`) only ever passes one.
pub fn dispatch(args: &[String]) -> ExitCode {
    let Some(role) = args.first() else {
        eprintln!("_worker: missing role (fd-pass-backend | relay-fd | vsock-loopback-backend)");
        return ExitCode::FAILURE;
    };
    let find_u32 = |flag: &str| -> Option<u32> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse::<u32>().ok())
    };
    let result = match role.as_str() {
        "fd-pass-backend" => match find_u32("--fd") {
            Some(fd) => run_fd_pass_backend(fd as RawFd),
            None => {
                eprintln!("_worker fd-pass-backend: missing --fd");
                return ExitCode::FAILURE;
            }
        },
        "relay-fd" => match find_u32("--fd") {
            Some(fd) => run_relay_fd_backend(fd as RawFd),
            None => {
                eprintln!("_worker relay-fd: missing --fd");
                return ExitCode::FAILURE;
            }
        },
        "vsock-loopback-backend" => match find_u32("--port") {
            Some(port) => run_vsock_loopback_backend(port),
            None => {
                eprintln!("_worker vsock-loopback-backend: missing --port");
                return ExitCode::FAILURE;
            }
        },
        other => {
            eprintln!("_worker: unknown role '{other}'");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("_worker {role}: {e}");
            ExitCode::FAILURE
        }
    }
}
