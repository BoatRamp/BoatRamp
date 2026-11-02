//! `privsep_crossing` — the privsep Phase-3 substrate-decision benchmark
//! (`PLAN-privsep-fabric-composition.md` decision 1).
//!
//! Measures the frontend→backend `local`-shape CROSSING cost — the primitive each isolation
//! substrate actually makes a served request pay to hand off from the exposed byte-parser
//! (frontend) to the backend holding authority — across the substrate spectrum, so the owner can
//! pick the Phase-3 frontend substrate from REAL numbers rather than estimates. This binary does
//! NOT recommend a substrate; it only measures.
//!
//! # Substrates
//! - `fdpass` — **OS-process, socketpair fd-pass (`SCM_RIGHTS`).** The BUILT Phase-1 `local`
//!   transport, unmodified: drives the real `boatramp_server::privsep_link::LinkEndpoint`
//!   (`send_client_conn`/`recv_client_conn`). The accepted-client fd + response payload never
//!   cross the link after handoff, so this substrate's cost is (by design) independent of
//!   response size — see `fdpass.rs`.
//! - `byterelay` — **OS-process, socketpair byte-relay.** A plain `socketpair(2)` between two
//!   processes; request head + response body both cross it as ordinary bytes (the frontend stays
//!   a policy point, at the cost of one extra copy each way) — see `byterelay.rs`.
//! - `container` — the SAME byte-relay crossing, but the backend process is spawned inside fresh
//!   net/pid/mount/uts/ipc namespaces via `unshare --fork` — isolates the namespace-boundary tax
//!   alone, without a full container image/runtime layer muddying the per-request number — see
//!   `container.rs`. Needs `CAP_SYS_ADMIN` (run under `sudo`).
//! - `vsock-loopback` — a real `AF_VSOCK` round trip via the kernel's host-local loopback
//!   transport (`VMADDR_CID_LOCAL`, Linux ≥5.6) — no hypervisor. Sanctioned LOWER BOUND for the VM
//!   substrate when a real guest can't be stood up: real `AF_VSOCK` syscalls, zero hypervisor-exit
//!   cost — see `vsock.rs`.
//! - `vsock-firecracker` — a real firecracker microVM (kernel + initramfs only, no root block
//!   device), the guest's own PID 1 (`vsock_guest_main.rs`, built by
//!   `guest/build-initrd.sh`) listening on `AF_VSOCK`, dialed from the host through firecracker's
//!   own Unix-socket vsock bridge (`CONNECT <port>\n` handshake). Needs `--fc-bin`/`--fc-kernel`/
//!   `--fc-initramfs`; omitted (or if the guest fails to come up) reports N/A with the reason
//!   rather than guessing — see `vsock.rs`.
//! - `wasm` — `wasmtime` classic-module copy-in/copy-out across the guest's linear-memory
//!   boundary (no splice): the request is `Memory::write`-ed in, a trivial exported function is
//!   called (so the call isn't optimized away), the response is `Memory::read` back out — see
//!   `wasmcross.rs`. Deliberately bypasses `boatramp-handlers`' full wasi-http component path; the
//!   decision-relevant number is the copy, not guest compute.
//!
//! # Payload shapes
//! One representative parsed `RequestHead` (`payloads::representative_head`, ~300 bytes, the same
//! shape `privsep_link::send_client_conn`'s `head` argument carries in production) crosses with
//! EVERY request. The response body is measured at the task spec's four REAL serving-shape sizes
//! (`payloads::PAYLOAD_SIZES`): 1 KiB (API JSON), 64 KiB (typical page), 512 KiB and 2 MiB
//! (image-serve). No substrate is measured with a trivial 1-byte stand-in.
//!
//! # Warm / cold, and spawn cost
//! Per (substrate, payload) cell: `cold_iterations` FRESH backends are spawned one at a time —
//! "time from deciding to connect to the first byte of a ready signal" is the substrate's
//! spawn/setup cost (`exchange_runner::measure`'s cold loop; `fdpass.rs`/`wasmcross.rs` mirror the
//! same shape for their own connection/instantiation primitive). Then ONE persistent backend
//! serves `warm_iterations` back-to-back request/response round trips, serially (one frontend,
//! one backend, no concurrency) — the steady-state p50/p99 + implied throughput. Cold and warm are
//! reported as SEPARATE numbers (never blended) because spawn cost matters independently for
//! Phase-4 per-tenant instances.
//!
//! # Faithfulness / caveats (read before trusting a number)
//! - Every substrate is driven on the SAME box, pinned with `sched_setaffinity` (not external
//!   `taskset`, so it applies correctly to forked/re-exec'd/namespaced children too) — frontend to
//!   `--frontend-cpu`, backend to `--backend-cpu` (both optional; unset = no pinning, the OS
//!   scheduler picks, which is itself a valid "no isolation" baseline but noisier).
//! - `fdpass`'s reported "crossing cost" is the `SCM_RIGHTS` handoff + a 1-byte ack — NOT a
//!   payload round trip (there is no payload on the link for this substrate by design). It is run
//!   at all four payload-size columns anyway so the table shows, empirically, that the number
//!   doesn't move with size — that flatness IS the finding, not a gap in methodology.
//! - `container` needs `CAP_SYS_ADMIN`; run the whole binary under `sudo` for that substrate or it
//!   reports N/A with the `unshare` error.
//! - `vsock-firecracker` needs a real kernel + initramfs (see `guest/build-initrd.sh`) and the
//!   `firecracker` binary; omit any of `--fc-bin`/`--fc-kernel`/`--fc-initramfs` to skip it
//!   (reports N/A). A full VM boot is the per-sample cost for its COLD loop, so
//!   `--vm-cold-iterations` defaults much lower than the other substrates' `--cold-iterations`.
//! - `wasm`'s "cold" is per-`Instance` instantiation (Engine + compiled Module are shared, as a
//!   real deployment would reuse one precompiled artifact across many per-request instances) —
//!   not a process spawn; it is reported in the same table column because it is the Phase-4
//!   analogue (per-tenant instance setup), not because the two costs are the same KIND of thing.
//! - This binary measures the CROSSING on synthetic fixtures (a throwaway socketpair/vsock
//!   connection standing in for an accepted client connection), not boatramp's full serving
//!   stack — by design (task spec: hold the served work constant, measure the crossing delta).
//!
//! Lighthouse-only for any REAL measurement (`cargo bench --bench privsep_crossing --
//! --substrates ...`); it still BUILDS everywhere `boatramp` builds (musl/CI included) because
//! every substrate that needs a live kernel feature self-checks at run time and reports N/A with
//! the reason instead of failing to compile or panicking the whole run.

mod affinity;
mod byterelay;
mod container;
mod exchange_runner;
mod fdpass;
mod payloads;
mod spawn;
mod stats;
mod vsock;
#[path = "vsock_raw.rs"]
mod vsock_raw;
mod wasmcross;
#[path = "wire.rs"]
mod wire;
mod worker;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use stats::Cell;

#[derive(Parser, Debug)]
#[command(
    name = "privsep_crossing",
    about = "privsep Phase-3 frontend<->backend crossing-cost benchmark (measures only; does not recommend)"
)]
struct Cli {
    /// Comma-separated substrate list.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "fdpass,byterelay,container,vsock-loopback,vsock-firecracker,wasm"
    )]
    substrates: Vec<String>,

    /// Comma-separated payload-size labels (see `payloads::PAYLOAD_SIZES`).
    #[arg(long, value_delimiter = ',', default_value = "1KiB,64KiB,512KiB,2MiB")]
    sizes: Vec<String>,

    /// Steady-state round trips per (substrate, payload) cell.
    #[arg(long, default_value_t = 2000)]
    warm_iterations: usize,

    /// Fresh-backend spawns per (substrate, payload) cell, for process/namespace/vsock-loopback
    /// substrates.
    #[arg(long, default_value_t = 20)]
    cold_iterations: usize,

    /// Fresh-VM boots per (substrate, payload) cell for `vsock-firecracker` ONLY — a full microVM
    /// boot is the cold sample, so this defaults far lower than `--cold-iterations`.
    #[arg(long, default_value_t = 5)]
    vm_cold_iterations: usize,

    /// `Store`+`Instance` instantiations per payload size for `wasm`'s cold measurement.
    #[arg(long, default_value_t = 50)]
    wasm_instantiate_iterations: usize,

    /// Pin the frontend (this process) to this CPU core.
    #[arg(long)]
    frontend_cpu: Option<usize>,

    /// Pin every spawned backend (process/namespace) to this CPU core.
    #[arg(long)]
    backend_cpu: Option<usize>,

    /// Path to a real `firecracker` binary — all three `--fc-*` paths are required together to
    /// run `vsock-firecracker`; any missing reports it N/A.
    #[arg(long)]
    fc_bin: Option<PathBuf>,
    /// Guest kernel image (`vmlinux`), e.g. `nix build .#vmlinux`.
    #[arg(long)]
    fc_kernel: Option<PathBuf>,
    /// Guest initramfs built by `guest/build-initrd.sh`.
    #[arg(long)]
    fc_initramfs: Option<PathBuf>,
    #[arg(long, default_value_t = 3)]
    fc_guest_cid: u32,
    #[arg(long, default_value_t = 5201)]
    fc_guest_port: u32,
    #[arg(long, default_value_t = 1)]
    fc_vcpus: u8,
    #[arg(long, default_value_t = 128)]
    fc_mem_mib: u32,
    /// Scratch dir for per-VM sockets/config (removed after the `vsock-firecracker` run).
    #[arg(long, default_value = "/tmp/privsep-crossing-fc")]
    fc_work_dir: PathBuf,

    /// First `AF_VSOCK` port used by `vsock-loopback` (each cold iteration takes the next one, so
    /// a torn-down backend's port isn't immediately reused).
    #[arg(long, default_value_t = 6200)]
    vsock_port_base: u32,

    /// Also print a machine-parseable CSV dump after the table.
    #[arg(long)]
    csv: bool,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() > 1 && argv[1] == "_worker" {
        return worker::dispatch(&argv[2..]);
    }

    let cli = Cli::parse();
    if let Some(core) = cli.frontend_cpu
        && let Err(e) = affinity::pin_current_thread(core)
    {
        eprintln!("warning: failed to pin frontend to core {core}: {e}");
    }

    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: could not resolve current_exe: {e}");
            return ExitCode::FAILURE;
        }
    };

    let head = payloads::representative_head();
    let sizes: Vec<payloads::PayloadSize> = cli
        .sizes
        .iter()
        .filter_map(|label| match payloads::find_payload(label) {
            Some(p) => Some(p),
            None => {
                eprintln!("warning: unknown payload size '{label}', skipping");
                None
            }
        })
        .collect();

    let mut cells: Vec<Cell> = Vec::new();
    let mut vsock_port = cli.vsock_port_base;

    for substrate in &cli.substrates {
        for size in &sizes {
            let cell = match substrate.as_str() {
                "fdpass" => run_cell("fdpass", size.label, || {
                    fdpass::run(
                        &current_exe,
                        &head,
                        cli.warm_iterations,
                        cli.cold_iterations,
                        cli.backend_cpu,
                    )
                }),
                "byterelay" => run_cell("byterelay", size.label, || {
                    byterelay::run(
                        &current_exe,
                        &head,
                        size.bytes,
                        cli.warm_iterations,
                        cli.cold_iterations,
                        cli.backend_cpu,
                    )
                }),
                "container" => run_cell("container", size.label, || {
                    container::run(
                        &current_exe,
                        &head,
                        size.bytes,
                        cli.warm_iterations,
                        cli.cold_iterations,
                        cli.backend_cpu,
                    )
                }),
                "vsock-loopback" => {
                    let base = vsock_port;
                    vsock_port += (cli.cold_iterations as u32) + 2;
                    run_cell("vsock-loopback", size.label, || {
                        vsock::run_loopback(
                            &current_exe,
                            &head,
                            size.bytes,
                            cli.warm_iterations,
                            cli.cold_iterations,
                            cli.backend_cpu,
                            base,
                        )
                    })
                }
                "vsock-firecracker" => match (&cli.fc_bin, &cli.fc_kernel, &cli.fc_initramfs) {
                    (Some(bin), Some(kernel), Some(initramfs)) => {
                        let cfg = vsock::FirecrackerConfig {
                            firecracker_bin: bin.clone(),
                            kernel: kernel.clone(),
                            initramfs: initramfs.clone(),
                            guest_cid: cli.fc_guest_cid,
                            guest_port: cli.fc_guest_port,
                            vcpus: cli.fc_vcpus,
                            mem_mib: cli.fc_mem_mib,
                            work_dir: cli.fc_work_dir.join(size.label),
                        };
                        run_cell("vsock-firecracker", size.label, || {
                            vsock::run_firecracker(
                                &cfg,
                                &head,
                                size.bytes,
                                cli.warm_iterations,
                                cli.vm_cold_iterations,
                            )
                        })
                    }
                    _ => Cell::na(
                        "vsock-firecracker",
                        size.label,
                        "missing --fc-bin/--fc-kernel/--fc-initramfs (skipped, not guessed)",
                    ),
                },
                "wasm" => run_wasm_cell(
                    size.label,
                    size.bytes,
                    cli.warm_iterations,
                    cli.wasm_instantiate_iterations,
                ),
                other => Cell::na(other, size.label, "unknown substrate name"),
            };
            cells.push(cell);
        }
    }

    stats::print_table(&cells);
    if cli.csv {
        println!();
        stats::print_csv(&cells);
    }
    ExitCode::SUCCESS
}

fn run_cell(
    substrate: &str,
    payload_label: &str,
    f: impl FnOnce() -> std::io::Result<exchange_runner::ExchangeOutcome>,
) -> Cell {
    match f() {
        Ok(o) => Cell {
            substrate: substrate.to_string(),
            payload_label: payload_label.to_string(),
            warm: Some(o.warm),
            warm_rps: Some(o.warm_rps),
            warm_iterations: o.warm_iterations,
            cold_spawn_us: Some(o.cold_spawn),
            cold_iterations: o.cold_iterations,
            note: String::new(),
        },
        Err(e) => Cell::na(substrate, payload_label, &e.to_string()),
    }
}

fn run_wasm_cell(
    payload_label: &str,
    payload_bytes: usize,
    warm_iterations: usize,
    instantiate_iterations: usize,
) -> Cell {
    match wasmcross::run(payload_bytes, warm_iterations, instantiate_iterations) {
        Ok(o) => Cell {
            substrate: "wasm".to_string(),
            payload_label: payload_label.to_string(),
            warm: Some(o.copy_warm),
            warm_rps: Some(o.copy_warm_rps),
            warm_iterations: o.copy_warm_iterations,
            cold_spawn_us: Some(o.instantiate_cold),
            cold_iterations: o.instantiate_iterations,
            note: "cold = Store+Instance instantiation, not a process spawn".to_string(),
        },
        Err(e) => Cell::na("wasm", payload_label, &e.to_string()),
    }
}
