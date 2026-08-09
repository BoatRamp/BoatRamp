//! Live boot of the macOS VMM backend — **ignored by default** (Apple silicon +
//! macOS 15+ only, and needs a real arm64 `vmlinux` + ext4 rootfs). Mirrors the
//! firecracker crate's `fc_live` / `embedded_backend_live` seam: the orchestration
//! (staging, IPAM, spawn, endpoint) is unit-tested on every host; the actual VM
//! boot is exercised only here, on a capable machine, with fixtures provided via
//! env vars.
//!
//! Run with:
//! ```sh
//! BOATRAMP_VZ_KERNEL=/path/to/vmlinux \
//! BOATRAMP_VZ_ROOTFS=/path/to/rootfs.ext4 \
//!   cargo test -p boatramp-vz --features backend -- --ignored vz_live
//! ```
//! The binary must be code-signed with the `com.apple.security.virtualization`
//! entitlement (`codesign --entitlements vz.entitlements -s - <test-bin>`), else
//! `VZVirtualMachine` init/start fails — that is expected on an unsigned binary
//! and is the reason this is `#[ignore]`.

#![cfg(all(target_os = "macos", feature = "backend"))]

use std::time::Duration;

use boatramp_vz::config::WorkerConfig;

/// Build a `VZVirtualMachineConfiguration` from real fixtures and validate it —
/// exercises the whole `vm::build_configuration` path (boot loader, virtio-blk,
/// virtio-net NAT, serial) without a full boot. Skips (passes) when fixtures are
/// absent so CI on a capable-but-unprovisioned mac stays green.
#[test]
#[ignore = "needs Apple-silicon macOS + a signed test binary + kernel/rootfs fixtures"]
fn vz_live_build_configuration_validates() {
    let (Some(kernel), Some(rootfs)) = (
        std::env::var_os("BOATRAMP_VZ_KERNEL"),
        std::env::var_os("BOATRAMP_VZ_ROOTFS"),
    ) else {
        eprintln!("vz_live: set BOATRAMP_VZ_KERNEL + BOATRAMP_VZ_ROOTFS to run");
        return;
    };
    let cfg = WorkerConfig {
        rootfs_path: rootfs.to_string_lossy().into_owned(),
        kernel_path: kernel.to_string_lossy().into_owned(),
        cmdline_override: None,
        env_cmdline: String::new(),
        guest_ip: "192.168.64.5".into(),
        gateway: "192.168.64.1".into(),
        writable_root: false,
        mem_mib: 512,
        vcpus: 1,
        volumes: vec![],
        restore_path: None,
    };
    boatramp_vz::vm::build_configuration(&cfg)
        .expect("a well-formed config with real kernel+rootfs must validate");
}

/// Boot a VM and stop it after a short delay — the full lifecycle. Requires a
/// signed binary + real fixtures; skips (passes) without them.
#[test]
#[ignore = "needs Apple-silicon macOS + a signed test binary + kernel/rootfs fixtures"]
fn vz_live_boot_and_stop() {
    let (Some(kernel), Some(rootfs)) = (
        std::env::var_os("BOATRAMP_VZ_KERNEL"),
        std::env::var_os("BOATRAMP_VZ_ROOTFS"),
    ) else {
        eprintln!("vz_live: set BOATRAMP_VZ_KERNEL + BOATRAMP_VZ_ROOTFS to run");
        return;
    };
    let cfg = WorkerConfig {
        rootfs_path: rootfs.to_string_lossy().into_owned(),
        kernel_path: kernel.to_string_lossy().into_owned(),
        cmdline_override: None,
        env_cmdline: String::new(),
        guest_ip: "192.168.64.5".into(),
        gateway: "192.168.64.1".into(),
        writable_root: false,
        mem_mib: 512,
        vcpus: 1,
        volumes: vec![],
        restore_path: None,
    };
    // Run the worker in a thread; close its "stdin" analog by dropping after a
    // delay is not directly possible here (run_worker reads the process stdin), so
    // this test primarily verifies build+start don't error before the run loop.
    let handle = std::thread::spawn(move || boatramp_vz::vm::run_worker(cfg));
    std::thread::sleep(Duration::from_secs(2));
    // If the worker returned an error already (bad config / unsigned binary), fail.
    if handle.is_finished() {
        handle
            .join()
            .expect("worker thread panicked")
            .expect("worker start failed");
    }
    // Otherwise the VM is up in the run loop; the test process exiting tears it down.
}
