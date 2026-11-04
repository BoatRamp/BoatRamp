//! `privsep-vsock-guest`: the minimal firecracker-guest half of the vsock crossing substrate.
//! Chain-exec'd as the microVM's PID 1 via the kernel boot arg `rdinit=/init` (no shell, no
//! libc init system, no busybox) — it binds `AF_VSOCK`, accepts connections from the host, and
//! runs the SAME request/response exchange (`wire::server_loop`) every other byte-carrying
//! substrate's backend runs, so the only variable between substrates is the crossing itself.
//!
//! As PID 1, this process must NEVER return/exit — the kernel panics ("Attempted to kill
//! init!") if it does — so every fallible step logs to the serial console (stdout/stderr, wired
//! to `ttyS0` by the boot arg `console=ttyS0`) and the outer loop just retries.
//!
//! Built standalone for `x86_64-unknown-linux-musl` (statically linked): depends on nothing but
//! `libc` + `std`, via the two `#[path]`-included files shared with the host-side bench binary.

// This bin is the Linux-only firecracker-guest init (it binds `AF_VSOCK` and uses Linux libc).
// Everything but a stub `main` is gated to `target_os = "linux"`, so non-Linux targets (the
// Windows Tunnel CI lane; macOS) build a stub that compiles + exits rather than failing on the
// Linux-only socket/libc APIs. It is only ever actually BOOTED on the linux-musl guest.
#[cfg(target_os = "linux")]
#[path = "vsock_raw.rs"]
mod vsock_raw;
#[cfg(target_os = "linux")]
#[path = "wire.rs"]
mod wire;

/// Fixed vsock port the guest listens on — the host-side `vsock-firecracker` substrate driver
/// dials this same port.
#[cfg(target_os = "linux")]
const GUEST_PORT: u32 = 5201;
/// The byte the guest fills every served response with (content is irrelevant to the benchmark —
/// only the volume crossing is measured).
#[cfg(target_os = "linux")]
const FILL: u8 = 0xAB;
/// The one-shot marker frame the guest sends the instant it has accepted a connection, BEFORE
/// serving — the host's `exchange_runner::measure` reads exactly one frame after connect and
/// treats the time-to-that-frame as the substrate's spawn/setup cost. Every other backend
/// (`worker::run_*`) sends this; the firecracker guest must match the SAME contract or the host
/// blocks forever waiting for a frame that never comes. Content is irrelevant (the host discards
/// it); it just has to be one framed message.
#[cfg(target_os = "linux")]
const READY: &[u8] = b"READY";

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("privsep-vsock-guest is a Linux-only firecracker-guest init (AF_VSOCK); not supported on this target");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    println!("privsep-vsock-guest: booting (pid 1)");
    loop {
        if let Err(e) = run() {
            eprintln!("privsep-vsock-guest: {e} — retrying");
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> std::io::Result<()> {
    let listener = vsock_raw::socket_vsock()?;
    vsock_raw::bind_vsock(listener, vsock_raw::VMADDR_CID_ANY, GUEST_PORT)?;
    vsock_raw::listen_vsock(listener, 16)?;
    println!("privsep-vsock-guest: listening on vsock port {GUEST_PORT}");
    loop {
        match vsock_raw::accept_vsock(listener) {
            Ok(conn) => {
                // Send the READY marker FIRST (the host's measure() reads one frame after
                // connect as the spawn-cost signal), then serve the steady-state loop — matching
                // every `worker::run_*` backend's contract.
                let served =
                    wire::write_frame(conn, READY).and_then(|()| wire::server_loop(conn, FILL));
                if let Err(e) = served {
                    eprintln!("privsep-vsock-guest: connection error: {e}");
                }
                vsock_raw::close_fd(conn);
            }
            Err(e) => {
                eprintln!("privsep-vsock-guest: accept error: {e}");
            }
        }
    }
}
