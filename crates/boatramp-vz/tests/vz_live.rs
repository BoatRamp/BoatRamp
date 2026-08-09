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
        machine_id: None,
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
        machine_id: None,
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

/// The **scale-to-zero round-trip**: cold boot → snapshot (pause + save + stop) →
/// restore (recreate the VM with the SAME machine identity + `restoreMachineState`
/// + resume) → assert the guest resumed *from saved RAM* rather than cold-booting.
///
/// Proof channel is the serial console (networking-independent): the fixture rootfs
/// generates a per-cold-boot nonce (the kernel `boot_id`, held in RAM) and heartbeats
/// it as `VZFIX-NONCE=<id>` every 2s. A true restore keeps printing the SAME nonce to
/// the restore process's serial with no fresh kernel boot banner; a cold reboot would
/// show a new nonce (and `Run /sbin/init` / `IP-Config`). This is the exact
/// `run_worker` snapshot/restore path `VzBackend::snapshot`/`restore` drive.
///
/// Drives the **signed** standalone `vz-worker` as a child (so stdin is the control
/// channel and stderr is the serial), pointed at by env vars:
/// ```sh
/// # build, then sign a COPY *outside* target/ (a later `cargo test` re-links the
/// # bin in place and would strip the signature — VZ then rejects the unsigned worker):
/// cargo build -p boatramp-vz --features backend --bin vz-worker
/// cp target/debug/vz-worker /tmp/vzw && codesign --entitlements vz.entitlements -s - -f /tmp/vzw
/// BOATRAMP_VZ_WORKER=/tmp/vzw \
/// BOATRAMP_VZ_KERNEL=/path/to/vmlinux \
/// BOATRAMP_VZ_ROOTFS=/path/to/rootfs.ext4 \
///   cargo test -p boatramp-vz --features backend -- --ignored vz_live_snapshot_restore
/// ```
/// The rootfs must heartbeat `VZFIX-NONCE=<id>` on the console (the crate's throwaway
/// `boatramp-firecracker` `vzfix` example builds exactly such an image). Skips
/// (passes) when any fixture env var is absent.
#[test]
#[ignore = "needs Apple-silicon macOS + a signed vz-worker + kernel/rootfs fixtures"]
fn vz_live_snapshot_restore_roundtrip() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

    let (Some(worker), Some(kernel), Some(rootfs)) = (
        std::env::var_os("BOATRAMP_VZ_WORKER"),
        std::env::var_os("BOATRAMP_VZ_KERNEL"),
        std::env::var_os("BOATRAMP_VZ_ROOTFS"),
    ) else {
        eprintln!(
            "vz_live: set BOATRAMP_VZ_WORKER + BOATRAMP_VZ_KERNEL + BOATRAMP_VZ_ROOTFS to run"
        );
        return;
    };
    let worker = std::path::PathBuf::from(worker);
    let kernel = kernel.to_string_lossy().into_owned();
    let rootfs = rootfs.to_string_lossy().into_owned();

    // A stable machine identity shared across the boot + restore processes (VZ
    // requires the restore identifier to match the saved VM's).
    let machine_id = {
        let out = Command::new(&worker)
            .arg("--gen-machine-id")
            .output()
            .expect("run vz-worker --gen-machine-id");
        assert!(out.status.success(), "gen machine-id failed");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };

    let state_path = std::env::temp_dir()
        .join("vz-live-rt.vzstate")
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&state_path);

    // Cold boot vs restore differ only in restore_path.
    let base = WorkerConfig {
        rootfs_path: rootfs,
        kernel_path: kernel,
        cmdline_override: None,
        env_cmdline: String::new(),
        guest_ip: "192.168.64.45".into(),
        gateway: "192.168.64.1".into(),
        writable_root: false,
        mem_mib: 512,
        vcpus: 1,
        volumes: vec![],
        restore_path: None,
        machine_id: Some(machine_id),
    };

    // Spawn the worker, returning the child + a shared buffer its serial lines land in.
    fn spawn(
        worker: &std::path::Path,
        cfg: &WorkerConfig,
    ) -> (std::process::Child, Arc<Mutex<Vec<String>>>) {
        let json = serde_json::to_string(cfg).unwrap();
        let mut child = Command::new(worker)
            .arg(json)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vz-worker");
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = lines.clone();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        (child, lines)
    }

    // Wait up to `secs` for a serial line matching `pred`; returns the line or None.
    fn wait_for(
        lines: &Arc<Mutex<Vec<String>>>,
        secs: u64,
        pred: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            if let Some(l) = lines.lock().unwrap().iter().find(|l| pred(l)) {
                return Some(l.clone());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }
    let nonce_of = |line: &str| {
        line.split("VZFIX-NONCE=")
            .nth(1)
            .map(|s| s.trim().to_string())
    };

    // --- Phase 1: cold boot, capture the RAM nonce off the heartbeat. ---
    let (mut p1, l1) = spawn(&worker, &base);
    let hb1 = wait_for(&l1, 40, |l| l.contains("VZFIX-NONCE="))
        .expect("phase 1: guest should heartbeat VZFIX-NONCE on the serial");
    let nonce1 = nonce_of(&hb1).expect("nonce1");
    assert!(!nonce1.is_empty(), "nonce1 non-empty");

    // --- Snapshot over the control channel; the worker pauses + saves + stops. ---
    writeln!(p1.stdin.as_mut().unwrap(), "snapshot {state_path}").unwrap();
    p1.stdin.as_mut().unwrap().flush().unwrap();
    let st = p1.wait().expect("wait phase 1 worker");
    assert!(
        st.success(),
        "snapshot worker should exit cleanly, got {st}"
    );
    assert!(
        std::fs::metadata(&state_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "snapshot must produce a non-empty state file"
    );

    // --- Phase 2: restore from the saved state; the guest must resume, not reboot. ---
    let mut restore_cfg = base.clone();
    restore_cfg.restore_path = Some(state_path.clone());
    let (mut p2, l2) = spawn(&worker, &restore_cfg);
    let hb2 = wait_for(&l2, 30, |l| l.contains("VZFIX-NONCE="))
        .expect("phase 2: restored guest should heartbeat VZFIX-NONCE on the serial");
    let nonce2 = nonce_of(&hb2).expect("nonce2");

    // A restored VM resumes from RAM: the nonce is identical and there is NO fresh
    // kernel boot banner on the restore serial.
    let cold_banner = l2.lock().unwrap().iter().any(|l| {
        l.contains("Run /sbin/init")
            || l.contains("IP-Config: Complete")
            || l.contains("Booting Linux")
    });
    let _ = p2.kill();
    let _ = p2.wait();
    let _ = std::fs::remove_file(&state_path);

    assert_eq!(
        nonce1, nonce2,
        "restore must preserve RAM (same boot_id nonce), not cold-boot"
    );
    assert!(
        !cold_banner,
        "restore must resume from saved state, not re-run the kernel boot"
    );
    eprintln!("vz scale-to-zero round-trip OK: nonce {nonce1} preserved across park/wake");
}
