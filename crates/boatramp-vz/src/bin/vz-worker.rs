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
    let json = match std::env::args().nth(1) {
        Some(json) => json,
        None => {
            eprintln!("vz-worker: missing WorkerConfig JSON argument");
            return std::process::ExitCode::FAILURE;
        }
    };
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
