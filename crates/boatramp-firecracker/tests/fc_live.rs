//! Live microVM boot test on a KVM host.
//!
//! `#[ignore]`d: it boots a *real* Firecracker VM, so it needs a Linux host with
//! `/dev/kvm`, the `firecracker` binary, and (for the tap/NAT) root + `ip`/`nft`.
//! It does nothing in CI / on macOS. Run it on a KVM VM:
//!
//! ```sh
//! # one-time: a bridge for the taps (or pass BOATRAMP_FC_SETUP_NODE=1 below)
//! sudo ip link add br-boatramp type bridge && sudo ip addr add 10.0.0.1/24 dev br-boatramp
//! sudo ip link set br-boatramp up
//!
//! sudo BOATRAMP_FC_KERNEL=/path/vmlinux BOATRAMP_FC_ROOTFS=/path/rootfs.ext4 \
//!   cargo test -p boatramp-firecracker --test fc_live -- --ignored --nocapture
//! ```
//!
//! Optional env: `BOATRAMP_FC_FIRECRACKER` (binary, default `firecracker`),
//! `BOATRAMP_FC_BRIDGE` (default `br-boatramp`), `BOATRAMP_FC_SUBNET`
//! (default `10.0.0.0/24`), `BOATRAMP_FC_SCRATCH` (a pre-made ext4; otherwise a
//! 64 MiB scratch is created with `mke2fs`), `BOATRAMP_FC_MAKE_BRIDGE=1`
//! (create the bridge instead of requiring it to pre-exist — handy in CI),
//! `BOATRAMP_FC_CMDLINE` (override the guest kernel cmdline, e.g. for a squashfs
//! rootfs), `BOATRAMP_FC_SETUP_NODE=1` (also bring up the bridge and NAT, needs
//! `BOATRAMP_FC_UPLINK`).
#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use boatramp_core::ipam::IpPool;
use boatramp_firecracker::config::{FcMachine, MachineResources};
use boatramp_firecracker::executor::{Executor, ExecutorConfig, SystemHost};
use boatramp_firecracker::net::{NodeNetwork, TapNetwork};
use boatramp_types::compute::{ComputeSpec, RestartPolicy};

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn spec() -> ComputeSpec {
    ComputeSpec {
        version: 1,
        rootfs: "0".repeat(64),
        kernel: "0".repeat(64),
        kernel_cmdline: None,
        vcpus: 1,
        mem_mib: 256,
        entrypoint: vec!["/sbin/init".into()],
        env: std::collections::BTreeMap::new(),
        port: 8080,
        restart: RestartPolicy::Never,
        scale_to_zero: false,
        volumes: vec![],
        isolation: boatramp_types::compute::IsolationRequirement::Trusted,
        prefer_backend: None,
    }
}

/// Create a sparse 64 MiB ext4 scratch image with `mke2fs`, returning its path.
fn make_scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!("br-fc-scratch-{}.ext4", std::process::id()));
    let status = std::process::Command::new("mke2fs")
        .args(["-F", "-q", "-t", "ext4"])
        .arg(&path)
        .arg("65536") // blocks (×1KiB ≈ 64 MiB)
        .status()
        .expect("run mke2fs (install e2fsprogs)");
    assert!(status.success(), "mke2fs failed");
    path
}

#[test]
#[ignore = "boots a real Firecracker VM; needs /dev/kvm + firecracker + root"]
fn boots_and_stops_a_real_microvm() {
    let (Some(kernel), Some(rootfs)) = (env("BOATRAMP_FC_KERNEL"), env("BOATRAMP_FC_ROOTFS"))
    else {
        eprintln!("skipping: set BOATRAMP_FC_KERNEL and BOATRAMP_FC_ROOTFS to boot a live VM");
        return;
    };

    let firecracker_bin = env("BOATRAMP_FC_FIRECRACKER").unwrap_or_else(|| "firecracker".into());
    let bridge = env("BOATRAMP_FC_BRIDGE").unwrap_or_else(|| "br-boatramp".into());
    let subnet = env("BOATRAMP_FC_SUBNET").unwrap_or_else(|| "10.0.0.0/24".into());
    let scratch = env("BOATRAMP_FC_SCRATCH")
        .map(PathBuf::from)
        .unwrap_or_else(make_scratch);

    // Optionally create the tap's bridge (CI convenience; ignores "exists").
    if env("BOATRAMP_FC_MAKE_BRIDGE").as_deref() == Some("1") {
        let _ = std::process::Command::new("ip")
            .args(["link", "add", &bridge, "type", "bridge"])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["link", "set", &bridge, "up"])
            .status();
    }

    let runtime_dir = PathBuf::from("/run/boatramp");
    std::fs::create_dir_all(&runtime_dir).expect("create runtime dir (run as root)");

    // Allocate a guest IP + derive its MAC.
    let mut pool = IpPool::new(&subnet).expect("valid subnet");
    let ip = pool.allocate().expect("a free guest IP");
    let mac = IpPool::mac_for(ip);

    let tap = TapNetwork::for_vm("live0", &bridge);
    let resources = MachineResources {
        kernel_path: kernel,
        rootfs_path: rootfs,
        scratch_path: scratch.display().to_string(),
        tap_name: tap.tap_name.clone(),
        guest_mac: mac,
        guest_ip: ip.to_string(),
    };
    let mut spec = spec();
    spec.kernel_cmdline = env("BOATRAMP_FC_CMDLINE");
    let machine = FcMachine::from_spec(&spec, &resources);

    let executor = Executor::new(
        SystemHost,
        ExecutorConfig {
            firecracker_bin,
            jailer: None,
            runtime_dir,
            api_timeout: Duration::from_secs(10),
        },
    );

    if env("BOATRAMP_FC_SETUP_NODE").as_deref() == Some("1") {
        let uplink = env("BOATRAMP_FC_UPLINK").expect("BOATRAMP_FC_UPLINK for node setup");
        let gw = format!(
            "{}/24",
            subnet
                .rsplit_once('.')
                .map(|(n, _)| format!("{n}.1"))
                .unwrap()
        );
        executor.setup_node(&NodeNetwork::new(&gw, &uplink));
    }

    let vm = executor
        .launch("live0", &machine, &tap)
        .expect("launch the microVM");
    eprintln!("booted live0 → pid {} (guest {ip})", vm.pid.0);

    // Let it run briefly, then stop + tear down.
    std::thread::sleep(Duration::from_secs(2));
    executor.stop(&vm).expect("stop the microVM");
    eprintln!("stopped + tore down live0");
}
