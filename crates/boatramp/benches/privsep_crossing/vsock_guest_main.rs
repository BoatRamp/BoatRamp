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

#[path = "vsock_raw.rs"]
mod vsock_raw;
#[path = "wire.rs"]
mod wire;

/// Fixed vsock port the guest listens on — the host-side `vsock-firecracker` substrate driver
/// dials this same port.
const GUEST_PORT: u32 = 5201;
/// The byte the guest fills every served response with (content is irrelevant to the benchmark —
/// only the volume crossing is measured).
const FILL: u8 = 0xAB;

fn main() {
    println!("privsep-vsock-guest: booting (pid 1)");
    loop {
        if let Err(e) = run() {
            eprintln!("privsep-vsock-guest: {e} — retrying");
        }
    }
}

fn run() -> std::io::Result<()> {
    let listener = vsock_raw::socket_vsock()?;
    vsock_raw::bind_vsock(listener, vsock_raw::VMADDR_CID_ANY, GUEST_PORT)?;
    vsock_raw::listen_vsock(listener, 16)?;
    println!("privsep-vsock-guest: listening on vsock port {GUEST_PORT}");
    loop {
        match vsock_raw::accept_vsock(listener) {
            Ok(conn) => {
                if let Err(e) = wire::server_loop(conn, FILL) {
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
