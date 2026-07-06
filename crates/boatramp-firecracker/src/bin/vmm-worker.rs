//! Thin re-exec target for the embedded VMM backend: `vmm-worker __vmm-run
//! <json-WorkerConfig>` builds + runs one jailed microVM in this process
//! (separate address space + dropped caps + seccomp). Production re-execs the
//! `boatramp` binary's `__vmm-run` subcommand (same [`run_jailed_worker`]); this
//! standalone bin lets the crate's own integration test be self-contained (the
//! test points the backend's `self_exe` at it via `CARGO_BIN_EXE_vmm-worker`).

#[cfg(all(target_os = "linux", feature = "embedded", feature = "backend"))]
fn main() {
    use boatramp_firecracker::embedded_backend::{
        run_jailed_worker, WorkerConfig, VMM_RUN_SUBCOMMAND,
    };

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some(VMM_RUN_SUBCOMMAND) {
        eprintln!("usage: vmm-worker {VMM_RUN_SUBCOMMAND} <json-config>");
        std::process::exit(2);
    }
    let cfg: WorkerConfig = match args.get(2).map(|j| serde_json::from_str(j)) {
        Some(Ok(cfg)) => cfg,
        _ => {
            eprintln!("vmm-worker: missing/invalid <json-config>");
            std::process::exit(2);
        }
    };
    if let Err(e) = run_jailed_worker(cfg) {
        eprintln!("vmm-worker: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "linux", feature = "embedded", feature = "backend")))]
fn main() {
    eprintln!("vmm-worker: only supported on Linux with the `embedded` + `backend` features");
    std::process::exit(2);
}
