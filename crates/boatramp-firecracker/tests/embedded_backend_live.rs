//! Live end-to-end test for the [`EmbeddedVmmBackend`]: drive the full
//! `ComputeBackend` lifecycle — `launch` an in-process
//! microVM replica, prove it is reachable on its allocated IP (ping over the
//! backend-managed tap), then `stop` it and confirm the tap + IP are reclaimed.
//!
//! Self-skips unless `/dev/kvm` + `BOATRAMP_TEST_KERNEL` (vmlinux) +
//! `BOATRAMP_TEST_ROOTFS` (an ext4/squashfs rootfs) are present **and** the
//! process can set up a bridge/tap (`CAP_NET_ADMIN` — run under `sudo`).
//! Dispatch-only (`compute-live`); needs the `backend` + `embedded` features.
#![cfg(all(target_os = "linux", feature = "embedded", feature = "backend"))]

use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{Artifact, ComputeBackend, ComputeSpec, LaunchRequest};
use boatramp_core::{GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_firecracker::embedded_backend::EmbeddedVmmBackend;

/// A blob backend that's never used — `launch` is fed a `VmImages` artifact made
/// from local file paths, so `materialize`/`Storage::get` are bypassed.
struct NullStorage;

#[async_trait]
impl Storage for NullStorage {
    async fn get(&self, _: &str) -> Result<GetObject, StorageError> {
        Err(StorageError::NotFound(String::new()))
    }
    async fn get_range(&self, _: &str, _: u64, _: Option<u64>) -> Result<GetObject, StorageError> {
        Err(StorageError::NotFound(String::new()))
    }
    async fn put(
        &self,
        _: &str,
        _: boatramp_core::ByteStream,
        _: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::unsupported("null"))
    }
    async fn head(&self, _: &str) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::NotFound(String::new()))
    }
    async fn delete(&self, _: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        Ok(Vec::new())
    }
}

const BRIDGE: &str = "br-embtest";
const GATEWAY: &str = "172.30.9.1";
const SUBNET: &str = "172.30.9.0/24";
// The first IP the pool hands out (`.1` is the reserved gateway).
const GUEST_IP: &str = "172.30.9.2";

fn ip(args: &[&str]) -> bool {
    std::process::Command::new("ip")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sample_spec() -> ComputeSpec {
    use boatramp_types::compute::{IsolationRequirement, RestartPolicy};
    ComputeSpec {
        version: 1,
        rootfs: "r".repeat(64),
        kernel: "k".repeat(64),
        // Deterministic cmdline: the guest gets `.2` (first pool IP) + a `/bin/sh`
        // init so the read-only squashfs stays alive for the probe. The backend
        // appends the virtio-MMIO `device=` fragments.
        kernel_cmdline: Some(format!(
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/bin/sh \
             ip={GUEST_IP}::{GATEWAY}:255.255.255.0::eth0:off"
        )),
        vcpus: 1,
        mem_mib: 512,
        entrypoint: vec![],
        env: std::collections::BTreeMap::new(),
        port: 8080,
        restart: RestartPolicy::Always,
        scale_to_zero: false,
        volumes: vec![],
        isolation: IsolationRequirement::Trusted,
        prefer_backend: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "boots a microVM via the backend + pings it; needs /dev/kvm + CAP_NET_ADMIN + BOATRAMP_TEST_KERNEL + BOATRAMP_TEST_ROOTFS"]
async fn launches_pings_and_stops_a_microvm() {
    let (Ok(kernel), Ok(rootfs)) = (
        std::env::var("BOATRAMP_TEST_KERNEL"),
        std::env::var("BOATRAMP_TEST_ROOTFS"),
    ) else {
        eprintln!("SKIP: set BOATRAMP_TEST_KERNEL + BOATRAMP_TEST_ROOTFS");
        return;
    };
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm unavailable");
        return;
    }

    // Watchdog: the VM thread is a daemon; bound the process if stop wedges.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(60));
        eprintln!("FATAL: embedded backend test exceeded 60s — aborting");
        std::process::exit(124);
    });

    // Host bridge the tap enslaves to. Needs CAP_NET_ADMIN; skip cleanly if not.
    let _ = ip(&["link", "del", BRIDGE]); // clean any stale bridge
    if !ip(&["link", "add", BRIDGE, "type", "bridge"]) {
        eprintln!("SKIP: cannot create bridge (need CAP_NET_ADMIN / sudo)");
        return;
    }
    assert!(ip(&[
        "addr",
        "add",
        &format!("{GATEWAY}/24"),
        "dev",
        BRIDGE
    ]));
    assert!(ip(&["link", "set", BRIDGE, "up"]));

    let backend = EmbeddedVmmBackend::new(
        Arc::new(NullStorage),
        // The re-exec'd jailed worker target (this crate's `vmm-worker` bin).
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_vmm-worker")),
        std::env::temp_dir().join("br-embtest-data"),
        BRIDGE.to_string(),
        GATEWAY.to_string(),
        SUBNET,
    )
    .expect("build backend");

    let req = LaunchRequest {
        workload: "web".to_string(),
        replica: 0,
        spec: sample_spec(),
        artifact: Artifact::VmImages {
            rootfs_path: rootfs,
            kernel_path: kernel,
        },
    };

    let instance = backend.launch(&req).await.expect("launch replica");
    assert_eq!(
        instance.endpoint.host, GUEST_IP,
        "endpoint is the pool's .2"
    );

    // Wait for the guest to boot + bring eth0 up, then ping it over the tap.
    let mut reachable = false;
    for _ in 0..40 {
        let ok = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "1", &instance.endpoint.host])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            reachable = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Stop the replica: signals the vCPU out of KVM_RUN, joins the thread, tears
    // the tap down, releases the IP.
    backend.stop(&instance.handle).await.expect("stop replica");

    // The per-VM tap is gone after stop.
    let tap_gone = !ip(&["link", "show", "tap-web-0"]);

    // Best-effort bridge teardown before asserting.
    let _ = ip(&["link", "del", BRIDGE]);

    assert!(
        reachable,
        "backend-launched guest was not reachable over its tap (datapath/launch broken)"
    );
    assert!(tap_gone, "stop did not tear the VM's tap down");
}

/// The full **VMM-OCI** path end to end: build an ext4 rootfs from a real OCI
/// image (`busybox`, entrypoint overridden to `httpd`) with the baked `/sbin/init`,
/// launch it via the backend, and confirm the **workload actually serves** —
/// `health()` returns `Healthy` (a TCP connect to the app port succeeds). Then
/// stop + reclaim. Proves materialize→boot→init→exec-entrypoint→serve.
///
/// Needs `/dev/kvm` + `CAP_NET_ADMIN` + network (pull busybox) + `mke2fs` +
/// `BOATRAMP_TEST_KERNEL`. The `build` feature (OCI pull + ext4) must be on.
#[cfg(feature = "build")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "builds a rootfs from busybox + serves it; needs /dev/kvm + CAP_NET_ADMIN + network + mke2fs + BOATRAMP_TEST_KERNEL"]
async fn serves_an_oci_workload_end_to_end() {
    use boatramp_core::compute::Health;

    const BRIDGE2: &str = "br-embtest2";
    const GATEWAY2: &str = "172.30.10.1";
    const SUBNET2: &str = "172.30.10.0/24";
    const GUEST2: &str = "172.30.10.2";
    const APP_PORT: u16 = 8081;

    let Ok(kernel) = std::env::var("BOATRAMP_TEST_KERNEL") else {
        eprintln!("SKIP: set BOATRAMP_TEST_KERNEL");
        return;
    };
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm unavailable");
        return;
    }

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(120));
        eprintln!("FATAL: OCI e2e test exceeded 120s — aborting");
        std::process::exit(124);
    });

    // Build the rootfs from busybox, overriding the entrypoint to a foreground
    // httpd on APP_PORT. The baked /sbin/init mounts pseudo-fs + execs it.
    let rootfs_path = std::env::temp_dir().join("br-oci-e2e.ext4");
    let _ = std::fs::remove_file(&rootfs_path);
    let entrypoint = vec![
        "httpd".to_string(),
        "-f".to_string(),
        "-p".to_string(),
        APP_PORT.to_string(),
    ];
    if let Err(e) = boatramp_firecracker::oci::build_rootfs(
        "busybox:latest",
        &entrypoint,
        &[],
        &rootfs_path,
        128,
        &[],
    )
    .await
    {
        eprintln!("SKIP: rootfs build failed (network / mke2fs?): {e}");
        return;
    }

    // Host bridge (distinct from the other test's).
    let _ = ip(&["link", "del", BRIDGE2]);
    if !ip(&["link", "add", BRIDGE2, "type", "bridge"]) {
        eprintln!("SKIP: cannot create bridge (need CAP_NET_ADMIN / sudo)");
        return;
    }
    assert!(ip(&[
        "addr",
        "add",
        &format!("{GATEWAY2}/24"),
        "dev",
        BRIDGE2
    ]));
    assert!(ip(&["link", "set", BRIDGE2, "up"]));

    let backend = EmbeddedVmmBackend::new(
        Arc::new(NullStorage),
        // The re-exec'd jailed worker target (this crate's `vmm-worker` bin).
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_vmm-worker")),
        std::env::temp_dir().join("br-embtest2-data"),
        BRIDGE2.to_string(),
        GATEWAY2.to_string(),
        SUBNET2,
    )
    .expect("build backend");

    // No kernel_cmdline override → the backend's default cmdline runs /sbin/init
    // (the baked init), which execs httpd.
    let mut spec = sample_spec();
    spec.kernel_cmdline = None;
    spec.port = APP_PORT;
    let req = LaunchRequest {
        workload: "srv".to_string(),
        replica: 0,
        spec,
        artifact: Artifact::VmImages {
            rootfs_path: rootfs_path.display().to_string(),
            kernel_path: kernel,
        },
    };

    let instance = backend.launch(&req).await.expect("launch replica");
    assert_eq!(instance.endpoint.host, GUEST2);
    assert_eq!(instance.endpoint.port, APP_PORT);

    // Poll health until the workload serves (boot + init + httpd bind takes a bit).
    let mut healthy = false;
    for _ in 0..50 {
        if matches!(backend.health(&instance.handle).await, Ok(Health::Healthy)) {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    backend.stop(&instance.handle).await.expect("stop replica");
    let _ = ip(&["link", "del", BRIDGE2]);
    let _ = std::fs::remove_file(&rootfs_path);

    assert!(
        healthy,
        "OCI workload did not serve on its port (build→boot→init→exec→serve broken)"
    );
}

/// Prove the **freestanding guest init** boots a **shell-less** image: build a
/// rootfs from `hashicorp/http-echo` (a `FROM scratch` static Go binary — no
/// `/bin/sh`, no `mount`), launch it, and confirm it serves (`health = Healthy`).
/// Only the baked static `/sbin/init` (mount pseudo-fs + execve, no libc/shell)
/// can boot this — proving universal image support. Same prerequisites as the
/// busybox e2e.
#[cfg(feature = "build")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "builds a scratch image rootfs + serves it; needs /dev/kvm + CAP_NET_ADMIN + network + mke2fs + BOATRAMP_TEST_KERNEL"]
async fn serves_a_shell_less_scratch_image() {
    use boatramp_core::compute::Health;

    const BRIDGE3: &str = "br-embtest3";
    const GATEWAY3: &str = "172.30.11.1";
    const SUBNET3: &str = "172.30.11.0/24";
    const GUEST3: &str = "172.30.11.2";
    const APP_PORT: u16 = 8082;

    let Ok(kernel) = std::env::var("BOATRAMP_TEST_KERNEL") else {
        eprintln!("SKIP: set BOATRAMP_TEST_KERNEL");
        return;
    };
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm unavailable");
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(120));
        eprintln!("FATAL: scratch e2e test exceeded 120s — aborting");
        std::process::exit(124);
    });

    // hashicorp/http-echo: `FROM scratch` + a static binary at `/http-echo`.
    let rootfs_path = std::env::temp_dir().join("br-scratch-e2e.ext4");
    let _ = std::fs::remove_file(&rootfs_path);
    let entrypoint = vec![
        "/http-echo".to_string(),
        format!("-listen=:{APP_PORT}"),
        "-text=boatramp".to_string(),
    ];
    if let Err(e) = boatramp_firecracker::oci::build_rootfs(
        "hashicorp/http-echo",
        &entrypoint,
        &[],
        &rootfs_path,
        64,
        &[],
    )
    .await
    {
        eprintln!("SKIP: rootfs build failed (network / mke2fs?): {e}");
        return;
    }

    let _ = ip(&["link", "del", BRIDGE3]);
    if !ip(&["link", "add", BRIDGE3, "type", "bridge"]) {
        eprintln!("SKIP: cannot create bridge (need CAP_NET_ADMIN / sudo)");
        return;
    }
    assert!(ip(&[
        "addr",
        "add",
        &format!("{GATEWAY3}/24"),
        "dev",
        BRIDGE3
    ]));
    assert!(ip(&["link", "set", BRIDGE3, "up"]));

    let backend = EmbeddedVmmBackend::new(
        Arc::new(NullStorage),
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_vmm-worker")),
        std::env::temp_dir().join("br-embtest3-data"),
        BRIDGE3.to_string(),
        GATEWAY3.to_string(),
        SUBNET3,
    )
    .expect("build backend");

    let mut spec = sample_spec();
    spec.kernel_cmdline = None;
    spec.port = APP_PORT;
    let req = LaunchRequest {
        workload: "echo".to_string(),
        replica: 0,
        spec,
        artifact: Artifact::VmImages {
            rootfs_path: rootfs_path.display().to_string(),
            kernel_path: kernel,
        },
    };

    let instance = backend.launch(&req).await.expect("launch replica");
    assert_eq!(instance.endpoint.host, GUEST3);

    let mut healthy = false;
    for _ in 0..50 {
        if matches!(backend.health(&instance.handle).await, Ok(Health::Healthy)) {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    backend.stop(&instance.handle).await.expect("stop replica");
    let _ = ip(&["link", "del", BRIDGE3]);
    let _ = std::fs::remove_file(&rootfs_path);

    assert!(
        healthy,
        "shell-less scratch workload did not serve (static guest init broken)"
    );
}

/// **Scale-to-zero** end to end: launch a serving busybox-httpd microVM,
/// confirm it serves, **snapshot** it (the jailed worker pauses + streams its
/// vCPU + chip + device-model state + RAM out; the VM is torn down), then
/// **restore** it into a fresh jailed worker and confirm it **serves again**.
/// Serving after restore is the strong proof: the resumed guest's virtio-net only
/// works if the host-side device model (queue cursors included) round-tripped —
/// a fresh restore with reset cursors would desync the rings and the httpd would
/// be unreachable. Same prerequisites as the busybox e2e.
#[cfg(feature = "build")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "snapshots + restores a serving microVM; needs /dev/kvm + CAP_NET_ADMIN + network + mke2fs + BOATRAMP_TEST_KERNEL"]
async fn snapshots_and_restores_a_serving_workload() {
    use boatramp_core::compute::Health;

    const BRIDGE4: &str = "br-embtest4";
    const GATEWAY4: &str = "172.30.12.1";
    const SUBNET4: &str = "172.30.12.0/24";
    const GUEST4: &str = "172.30.12.2";
    const APP_PORT: u16 = 8083;

    let Ok(kernel) = std::env::var("BOATRAMP_TEST_KERNEL") else {
        eprintln!("SKIP: set BOATRAMP_TEST_KERNEL");
        return;
    };
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm unavailable");
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(180));
        eprintln!("FATAL: snapshot/restore e2e test exceeded 180s — aborting");
        std::process::exit(124);
    });

    let rootfs_path = std::env::temp_dir().join("br-snap-e2e.ext4");
    let _ = std::fs::remove_file(&rootfs_path);
    let entrypoint = vec![
        "httpd".to_string(),
        "-f".to_string(),
        "-p".to_string(),
        APP_PORT.to_string(),
    ];
    if let Err(e) = boatramp_firecracker::oci::build_rootfs(
        "busybox:latest",
        &entrypoint,
        &[],
        &rootfs_path,
        128,
        &[],
    )
    .await
    {
        eprintln!("SKIP: rootfs build failed (network / mke2fs?): {e}");
        return;
    }

    let _ = ip(&["link", "del", BRIDGE4]);
    if !ip(&["link", "add", BRIDGE4, "type", "bridge"]) {
        eprintln!("SKIP: cannot create bridge (need CAP_NET_ADMIN / sudo)");
        return;
    }
    assert!(ip(&[
        "addr",
        "add",
        &format!("{GATEWAY4}/24"),
        "dev",
        BRIDGE4
    ]));
    assert!(ip(&["link", "set", BRIDGE4, "up"]));

    let backend = EmbeddedVmmBackend::new(
        Arc::new(NullStorage),
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_vmm-worker")),
        std::env::temp_dir().join("br-embtest4-data"),
        BRIDGE4.to_string(),
        GATEWAY4.to_string(),
        SUBNET4,
    )
    .expect("build backend");

    // Smaller RAM keeps the snapshot stream modest; busybox needs little.
    let mut spec = sample_spec();
    spec.kernel_cmdline = None;
    spec.port = APP_PORT;
    spec.mem_mib = 256;
    let req = LaunchRequest {
        workload: "snap".to_string(),
        replica: 0,
        spec,
        artifact: Artifact::VmImages {
            rootfs_path: rootfs_path.display().to_string(),
            kernel_path: kernel,
        },
    };

    let cleanup = || {
        let _ = ip(&["link", "del", BRIDGE4]);
        let _ = std::fs::remove_file(std::env::temp_dir().join("br-snap-e2e.ext4"));
        // The snapshot stream is ~the guest RAM size; don't leave it in /tmp.
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("br-embtest4-data"));
    };

    let instance = backend.launch(&req).await.expect("launch replica");
    assert_eq!(instance.endpoint.host, GUEST4);
    let mut served_before = false;
    for _ in 0..50 {
        if matches!(backend.health(&instance.handle).await, Ok(Health::Healthy)) {
            served_before = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    if !served_before {
        cleanup();
        panic!("workload did not serve before snapshot (boot/serve broken)");
    }

    // Snapshot: the worker pauses + streams its state out, the VM is torn down.
    let snapshot = match backend.snapshot(&instance.handle).await {
        Ok(Some(snap)) => snap,
        other => {
            cleanup();
            panic!("snapshot did not produce a Snapshot: {other:?}");
        }
    };

    // Restore into a fresh worker; it must resume + serve again.
    let restored = match backend.restore(&snapshot).await {
        Ok(inst) => inst,
        Err(e) => {
            cleanup();
            panic!("restore failed: {e}");
        }
    };
    assert_eq!(restored.endpoint.host, GUEST4, "same IP after restore");
    let mut served_after = false;
    for _ in 0..50 {
        if matches!(backend.health(&restored.handle).await, Ok(Health::Healthy)) {
            served_after = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    backend.stop(&restored.handle).await.expect("stop replica");
    cleanup();

    assert!(
        served_after,
        "restored workload did not serve — device-model state (queue cursors) lost on restore"
    );
}

/// **Persistent volumes** end to end: a busybox workload mounts a
/// writable volume at `/data` (baked mount dir → `/dev/vdb` mounted by the guest
/// init), increments a counter file on each boot, and serves it. Launch → read
/// `1`, **stop**, relaunch → read `2`: the increment proves the volume image was
/// created, mounted, written, and **persisted across the VM's teardown** (a
/// fresh/unmounted volume would read `1` again). Same prerequisites as the OCI
/// e2e (needs network + `mke2fs` + `/dev/kvm` + `CAP_NET_ADMIN` + kernel).
#[cfg(feature = "build")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "writes to a persistent volume across a restart; needs /dev/kvm + CAP_NET_ADMIN + network + mke2fs + BOATRAMP_TEST_KERNEL"]
async fn persistent_volume_survives_a_restart() {
    use boatramp_core::compute::VolumeRef;

    const BRIDGE5: &str = "br-embtest5";
    const GATEWAY5: &str = "172.30.13.1";
    const SUBNET5: &str = "172.30.13.0/24";
    const GUEST5: &str = "172.30.13.2";
    const APP_PORT: u16 = 8084;

    let Ok(kernel) = std::env::var("BOATRAMP_TEST_KERNEL") else {
        eprintln!("SKIP: set BOATRAMP_TEST_KERNEL");
        return;
    };
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm unavailable");
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(300));
        eprintln!("FATAL: volume e2e test exceeded 300s — aborting");
        std::process::exit(124);
    });

    // A busybox workload that increments /data/n on each boot then serves /data.
    let rootfs_path = std::env::temp_dir().join("br-vol-e2e.ext4");
    let _ = std::fs::remove_file(&rootfs_path);
    // `sync` after the write: the stop path SIGKILLs the VM, so the guest must
    // flush the ext4 page cache through the virtio-blk FLUSH path to the host
    // image for the increment to survive the (hard) restart.
    let script = format!(
        "if [ -f /data/n ]; then n=$(cat /data/n); else n=0; fi; \
         n=$((n+1)); echo $n > /data/n; sync; exec httpd -f -p {APP_PORT} -h /data"
    );
    let entrypoint = vec!["sh".to_string(), "-c".to_string(), script];
    if let Err(e) = boatramp_firecracker::oci::build_rootfs(
        "busybox:latest",
        &entrypoint,
        &[],
        &rootfs_path,
        128,
        &["/data".to_string()], // bake the volume mount-point dir + map
    )
    .await
    {
        eprintln!("SKIP: rootfs build failed (network / mke2fs?): {e}");
        return;
    }

    let _ = ip(&["link", "del", BRIDGE5]);
    if !ip(&["link", "add", BRIDGE5, "type", "bridge"]) {
        eprintln!("SKIP: cannot create bridge (need CAP_NET_ADMIN / sudo)");
        return;
    }
    assert!(ip(&[
        "addr",
        "add",
        &format!("{GATEWAY5}/24"),
        "dev",
        BRIDGE5
    ]));
    assert!(ip(&["link", "set", BRIDGE5, "up"]));

    // Fresh volume state: this test asserts the *increment*, so start clean.
    let data_dir = std::env::temp_dir().join("br-embtest5-data");
    let _ = std::fs::remove_dir_all(&data_dir);

    let backend = EmbeddedVmmBackend::new(
        Arc::new(NullStorage),
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_vmm-worker")),
        data_dir.clone(),
        BRIDGE5.to_string(),
        GATEWAY5.to_string(),
        SUBNET5,
    )
    .expect("build backend");

    let mut spec = sample_spec();
    spec.kernel_cmdline = None;
    spec.port = APP_PORT;
    spec.mem_mib = 256;
    spec.volumes = vec![VolumeRef {
        mount: "/data".to_string(),
        name: "persist".to_string(),
        size_mib: 16,
    }];
    let req = LaunchRequest {
        workload: "vol".to_string(),
        replica: 0,
        spec,
        artifact: Artifact::VmImages {
            rootfs_path: rootfs_path.display().to_string(),
            kernel_path: kernel,
        },
    };

    let cleanup = || {
        let _ = ip(&["link", "del", BRIDGE5]);
        let _ = std::fs::remove_file(std::env::temp_dir().join("br-vol-e2e.ext4"));
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("br-embtest5-data"));
    };

    // GET /n, returning the trimmed body (the counter), or None if not serving.
    async fn counter(host: &str, port: u16) -> Option<u32> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect((host, port)),
        )
        .await
        .ok()?
        .ok()?;
        s.write_all(format!("GET /n HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .ok()?;
        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_end(&mut buf))
            .await
            .ok()?
            .ok()?;
        let text = String::from_utf8_lossy(&buf);
        text.split_once("\r\n\r\n")
            .and_then(|(_, body)| body.trim().parse::<u32>().ok())
    }

    // Poll for the counter (boot + script + httpd bind takes a moment; allow a
    // generous window so a slow/loaded host doesn't flake the durability check).
    async fn read_counter(host: &str, port: u16) -> Option<u32> {
        for _ in 0..160 {
            if let Some(n) = counter(host, port).await {
                return Some(n);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        None
    }

    // First boot: the volume is created + mounted; the counter reads 1.
    let inst1 = backend.launch(&req).await.expect("launch 1");
    assert_eq!(inst1.endpoint.host, GUEST5);
    let first = read_counter(GUEST5, APP_PORT).await;
    backend.stop(&inst1.handle).await.expect("stop 1");

    // Second boot: same persistent volume → the counter increments to 2.
    let inst2 = backend.launch(&req).await.expect("launch 2");
    let second = read_counter(GUEST5, APP_PORT).await;
    backend.stop(&inst2.handle).await.expect("stop 2");
    cleanup();

    let (first, second) = match (first, second) {
        (Some(a), Some(b)) => (a, b),
        other => panic!("volume workload did not serve the counter both boots: {other:?}"),
    };
    assert_eq!(first, 1, "first boot starts the counter at 1");
    assert_eq!(
        second,
        first + 1,
        "counter persisted + incremented across the restart (volume is durable)"
    );
}
