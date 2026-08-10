//! Live launch of the native container backend — **ignored by default**, Linux +
//! privileged only (namespaces, cgroup v2, veth into a bridge). Mirrors the VZ /
//! firecracker live seams: the orchestration is unit-tested on every host; the
//! actual jail + boot + (later) CRIU checkpoint/restore run only here.
//!
//! Prereqs on the host (see the spike runbook): a bridge with the gateway IP, e.g.
//! ```sh
//! sudo ip link add br-boatramp type bridge 2>/dev/null || true
//! sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
//! sudo ip link set br-boatramp up
//! ```
//! Run (as root, since the backend does veth/cgroup/unshare):
//! ```sh
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   BOATRAMP_CONTAINER_ROOTFS=/tmp/bb-rootfs.tar.gz \
//!   cargo test -p boatramp-container --test container_live -- --ignored --nocapture
//! ```
//! Skips (passes) when the fixtures env vars are absent.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_container::ContainerBackend;
use boatramp_core::compute::{
    Artifact, ComputeBackend, ComputeSpec, IsolationRequirement, LaunchRequest, RestartPolicy,
    RootSource,
};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::StreamExt;

/// A `Storage` that serves one on-disk blob (the rootfs `.tar.gz`) for every key.
struct FileBlob(Vec<u8>);

#[async_trait]
impl Storage for FileBlob {
    async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
        let bytes = Bytes::from(self.0.clone());
        let size = self.0.len() as u64;
        let body: ByteStream = futures::stream::once(async move { Ok(bytes) }).boxed();
        Ok(GetObject {
            meta: ObjectMeta {
                key: String::new(),
                size: Some(size),
                content_type: None,
                etag: None,
            },
            body,
        })
    }
    async fn get_range(&self, _: &str, _: u64, _: Option<u64>) -> Result<GetObject, StorageError> {
        Err(StorageError::unsupported("range"))
    }
    async fn put(&self, _: &str, _: ByteStream, _: PutMeta) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::unsupported("put"))
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

/// The container entrypoint: generate a **per-process random nonce once**, stash it
/// in a tmpfs file, and serve it over httpd. CRIU dumps + restores the tmpfs, so a
/// restore that preserves memory keeps serving the SAME nonce; a cold restart
/// generates a new one. (Unlike a VM, containers share the host kernel, so the
/// kernel `boot_id` can't tell restore from cold-start here — a per-process value
/// can.) stdout stays quiet (httpd daemonizes) so the launcher's log pipes never
/// EPIPE while the test holds the container.
fn nonce_entrypoint() -> Vec<String> {
    vec![
        "/bin/busybox".into(),
        "sh".into(),
        "-c".into(),
        // Absolute `/bin/busybox <applet>` throughout: the spec sets no PATH, so a
        // bare applet wouldn't resolve inside the jail. `$RANDOM` (ash builtin) is
        // evaluated once, at start, into the tmpfs nonce file.
        "echo ${RANDOM}${RANDOM}${RANDOM} > /tmp/nonce; \
         /bin/busybox httpd -p 8080 -h /tmp; \
         while :; do /bin/busybox sleep 3600; done"
            .into(),
    ]
}

fn spec_for(rootfs_hash: &str) -> ComputeSpec {
    ComputeSpec {
        version: 1,
        root: RootSource::Tar(rootfs_hash.into()),
        kernel: String::new(),
        kernel_cmdline: None,
        vcpus: 1,
        mem_mib: 128,
        entrypoint: nonce_entrypoint(),
        env: std::collections::BTreeMap::new(),
        port: 8080,
        restart: RestartPolicy::Always,
        scale_to_zero: false,
        volumes: vec![],
        writable_root: false,
        cap_add: Vec::new(),
        user: None,
        isolation: IsolationRequirement::Trusted,
        prefer_backend: None,
        bindings: vec![],
    }
}

/// Launch a real container serving the boot_id nonce, print everything needed to
/// drive CRIU by hand (container id, IP:port, cgroup path + pids), probe the nonce
/// over HTTP, then hold for `BOATRAMP_CONTAINER_HOLD_SECS` (default 0) so a manual
/// `criu dump`/`restore` can run against the live tree. The spike vehicle for
/// finding the working CRIU args; the scale-to-zero round-trip lands on top later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Linux + root + a bridge + a rootfs tar (privileged live seam)"]
async fn container_live_launch_and_hold() {
    let (Some(bin), Some(rootfs_path)) = (
        std::env::var_os("BOATRAMP_BIN"),
        std::env::var_os("BOATRAMP_CONTAINER_ROOTFS"),
    ) else {
        eprintln!("container_live: set BOATRAMP_BIN + BOATRAMP_CONTAINER_ROOTFS to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let hold: u64 = std::env::var("BOATRAMP_CONTAINER_HOLD_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let rootfs = std::fs::read(&rootfs_path).expect("read rootfs tar");
    let data_dir = std::env::temp_dir().join(format!("boatramp-clive-{}", std::process::id()));
    let backend = ContainerBackend::new(
        Arc::new(FileBlob(rootfs)),
        data_dir.clone(),
        bridge,
        &subnet,
        PathBuf::from(bin),
    )
    .expect("backend");

    let hash = "d".repeat(64);
    let spec = spec_for(&hash);
    let artifact = backend
        .materialize(&spec)
        .await
        .expect("materialize rootfs");
    assert!(matches!(artifact, Artifact::Rootfs { .. }));

    let req = LaunchRequest {
        workload: "clive".into(),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend.launch(&req).await.expect("launch container");
    let id = format!("{}-{}", inst.handle.workload, inst.handle.replica);
    let cgroup = format!("/sys/fs/cgroup/boatramp/{id}");
    let procs = std::fs::read_to_string(format!("{cgroup}/cgroup.procs")).unwrap_or_default();
    eprintln!("== container launched ==");
    eprintln!(
        "id={id}  endpoint={}:{}",
        inst.endpoint.host, inst.endpoint.port
    );
    eprintln!("backend_ref={}", inst.handle.backend_ref);
    eprintln!("cgroup={cgroup}");
    eprintln!(
        "cgroup.procs=[{}]",
        procs.split_whitespace().collect::<Vec<_>>().join(",")
    );

    // Probe the nonce over HTTP (the container's IP is on the bridge subnet).
    let url = format!("http://{}:{}/nonce", inst.endpoint.host, inst.endpoint.port);
    let mut nonce = String::new();
    for _ in 0..40 {
        if let Ok(out) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "2", &url])
            .output()
        {
            if out.status.success() && !out.stdout.is_empty() {
                nonce = String::from_utf8_lossy(&out.stdout).trim().to_string();
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!("nonce={nonce:?}");
    assert!(
        !nonce.is_empty(),
        "container should serve the boot_id nonce over HTTP"
    );

    if hold > 0 {
        eprintln!("holding {hold}s for manual CRIU (dump the cgroup pids, then restore)...");
        std::thread::sleep(Duration::from_secs(hold));
    }

    // Clean up (idempotent) unless we intentionally leaked for an external CRIU dump.
    if std::env::var_os("BOATRAMP_CONTAINER_NO_STOP").is_none() {
        let _ = backend.stop(&inst.handle).await;
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

/// Poll the container's `/nonce` endpoint over HTTP, returning the body or empty.
fn probe_nonce(host: &str, port: u16) -> String {
    let url = format!("http://{host}:{port}/nonce");
    for _ in 0..40 {
        if let Ok(out) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "2", &url])
            .output()
        {
            if out.status.success() && !out.stdout.is_empty() {
                return String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    String::new()
}

/// The **scale-to-zero round-trip through the backend**: launch a container serving a
/// per-process nonce, `snapshot()` it (CRIU dump → the container is parked + gone),
/// `restore()` it (CRIU restore + the `__criu-net-setup` action-script re-attaches
/// the veth), and assert the restored container serves the SAME nonce over HTTP —
/// i.e. its in-RAM state AND its networking came back. The container analog of the
/// VZ / KVM scale-to-zero round-trips.
///
/// Needs Linux + root + a bridge + a rootfs tar (as the launch test) **and** a
/// working `criu` (on PATH or `$BOATRAMP_CRIU`); skips (passes) if any is absent or
/// the backend reports no scale-to-zero (CRIU not usable here).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge + a rootfs tar + criu (privileged live seam)"]
async fn container_criu_roundtrip() {
    let (Some(bin), Some(rootfs_path)) = (
        std::env::var_os("BOATRAMP_BIN"),
        std::env::var_os("BOATRAMP_CONTAINER_ROOTFS"),
    ) else {
        eprintln!("container_criu: set BOATRAMP_BIN + BOATRAMP_CONTAINER_ROOTFS to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());

    let rootfs = std::fs::read(&rootfs_path).expect("read rootfs tar");
    let data_dir = std::env::temp_dir().join(format!("boatramp-ccriu-{}", std::process::id()));
    let backend = ContainerBackend::new(
        Arc::new(FileBlob(rootfs)),
        data_dir.clone(),
        bridge,
        &subnet,
        PathBuf::from(bin),
    )
    .expect("backend");

    if !backend.capabilities().scale_to_zero {
        eprintln!("container_criu: backend reports no scale-to-zero (criu unusable); skipping");
        return;
    }

    let hash = "d".repeat(64);
    let spec = spec_for(&hash);
    let artifact = backend.materialize(&spec).await.expect("materialize");
    let req = LaunchRequest {
        workload: "ccriu".into(),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend.launch(&req).await.expect("launch");
    let nonce1 = probe_nonce(&inst.endpoint.host, inst.endpoint.port);
    assert!(
        !nonce1.is_empty(),
        "container should serve a nonce before park"
    );

    // Park: CRIU dump. `Some(snapshot)` and the container is gone.
    let snap = backend
        .snapshot(&inst.handle)
        .await
        .expect("snapshot ok")
        .expect("snapshot produced (container was running)");
    // The parked container's port should no longer answer.
    assert!(
        probe_nonce(&inst.endpoint.host, inst.endpoint.port).is_empty(),
        "parked container should not serve"
    );

    // Wake: CRIU restore + veth re-attach. The restored container serves again.
    let inst2 = backend.restore(&snap).await.expect("restore ok");
    let nonce2 = probe_nonce(&inst2.endpoint.host, inst2.endpoint.port);

    let _ = backend.stop(&inst2.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    assert_eq!(
        nonce1, nonce2,
        "restored container must serve the SAME nonce (in-RAM state + networking preserved)"
    );
    eprintln!("container scale-to-zero round-trip OK: nonce {nonce1} preserved across park/wake");
}
