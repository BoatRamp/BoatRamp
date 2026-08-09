//! Standalone `__vz-run` worker for the crate's own `vz_live` integration test.
//!
//! Production re-execs the `boatramp` binary's `__vz-run` subcommand; this
//! self-contained bin lets `boatramp-vz`'s integration test spawn a worker
//! without the whole binary (mirrors firecracker's `vmm-worker`). It parses a
//! [`WorkerConfig`] JSON argv element and boots one VM.
//!
//! On macOS it boots via Virtualization.framework; off macOS it reports that the
//! backend is unsupported and exits non-zero (the backend never spawns it there —
//! `build_compute` `cfg`-gates registration to macOS).

use boatramp_vz::WorkerConfig;

fn main() -> std::process::ExitCode {
    // Accept the same argv shape the production `boatramp` binary re-execs
    // (`__vz-run <json>`): skip an optional leading subcommand token so this
    // standalone worker is a drop-in `self_exe` for `VzBackend` in the live test.
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some(boatramp_vz::VZ_RUN_SUBCOMMAND) {
        args.next();
    }
    let arg = match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("vz-worker: missing WorkerConfig JSON argument");
            return std::process::ExitCode::FAILURE;
        }
    };
    // `--gen-machine-id`: print a fresh, stable VM machine identity (hex) and exit.
    // The live save/restore test needs one shared across the boot + restore
    // processes (VZ requires the restore identifier to match the saved VM's).
    if arg == "--gen-machine-id" {
        return gen_machine_id();
    }
    let json = arg;
    let cfg: WorkerConfig = match serde_json::from_str(&json) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("vz-worker: invalid WorkerConfig: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match run(cfg) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vz-worker: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "macos")]
fn run(cfg: WorkerConfig) -> Result<(), String> {
    boatramp_vz::vm::run_worker(cfg)
}

#[cfg(not(target_os = "macos"))]
fn run(_cfg: WorkerConfig) -> Result<(), String> {
    Err("the macOS VMM backend requires macOS (Virtualization.framework)".into())
}

#[cfg(target_os = "macos")]
fn gen_machine_id() -> std::process::ExitCode {
    println!("{}", boatramp_vz::vm::new_machine_id_hex());
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn gen_machine_id() -> std::process::ExitCode {
    eprintln!("vz-worker: --gen-machine-id requires macOS (Virtualization.framework)");
    std::process::ExitCode::FAILURE
}
