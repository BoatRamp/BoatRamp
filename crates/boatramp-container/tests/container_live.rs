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
        startup_grace_secs: 30,
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

/// End-to-end **co-located Postgres from an OCI image**: pull `pgvector/pgvector:pg16`
/// over the registry HTTP API (no Docker daemon — `RootSource::Image`), launch it
/// rootless with a persistent volume, and assert it `initdb`s and answers a real query
/// over TCP — proving the two container-backend gaps at runtime: the image pull
/// (`materialize` → `stage_image`) and the sticky `/run` tmpfs Postgres needs to create
/// `/run/postgresql` for its socket during init.
///
/// The container backend overlays only the image's *filesystem* layers, not its OCI
/// *config*, so the spec supplies the entrypoint + env explicitly (the managed-compute
/// layer would; applying the image's own config is a separate follow-up). Run as root
/// with the bridge up (see the module header); shells out to `psql` for the query, so it
/// needs a Postgres client on PATH. Ignored by default (pulls ~150 MB + is privileged).
async fn run_pg_e2e(host_root: bool) {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("container_live_postgres: set BOATRAMP_BIN to run");
        return;
    };
    let tag = if host_root { "hr" } else { "rl" };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-cpg-{tag}-{}", std::process::id()));
    let backend = ContainerBackend::new(
        // Storage is unused for the Image path (the pull is over HTTP, not from Storage).
        Arc::new(FileBlob(Vec::new())),
        data_dir.clone(),
        bridge,
        &subnet,
        PathBuf::from(bin),
    )
    .expect("backend")
    // Rootless (default) shifts the rootfs into the mapped host range; host-root maps
    // `0 → host 0` (single-tenant opt-in). Both must reach a serving Postgres.
    .with_host_root(host_root);

    let pw = "s3cr3t-pw";
    // Build the spec through the SHARED synthesizer the node's auto-register path uses,
    // so this gate proves exactly the managed-DB workload that ships (never a divergent,
    // hand-rolled copy). Then apply the two things the reconcile does at launch:
    //  - the rootless privilege directive (sets user 999:999 against the pre-owned
    //    volume — the entrypoint then inits as that user and can write the chowned data
    //    dir, instead of gosu-dropping to a 999 that can't write a root-owned volume);
    //  - the managed server-init credential env (`POSTGRES_*`), which reconcile injects
    //    from the sealed credential (a password so the TCP query authenticates).
    let mut spec = boatramp_core::compute::managed_db_spec(
        boatramp_core::compute::ManagedDbEngine::Postgres,
        Some("pgvector/pgvector:pg16"),
        512,
    );
    boatramp_core::compute::PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    spec.env
        .insert("POSTGRES_USER".to_string(), "app".to_string());
    spec.env
        .insert("POSTGRES_PASSWORD".to_string(), pw.to_string());
    spec.env
        .insert("POSTGRES_DB".to_string(), "app".to_string());

    let artifact = backend
        .materialize(&spec)
        .await
        .expect("materialize (pull) pgvector image");
    assert!(matches!(artifact, Artifact::Rootfs { .. }));

    let req = LaunchRequest {
        workload: format!("cpg{tag}"),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend
        .launch(&req)
        .await
        .expect("launch pgvector container");
    let host = inst.endpoint.host.clone();
    let port = inst.endpoint.port;
    eprintln!("== pgvector launched == endpoint={host}:{port}");

    // Poll a real query over TCP: success proves initdb ran (so `/run` was writable —
    // Gap B) and the pulled image booted (Gap A). ~30 s budget for first-boot initdb.
    let conn = format!("postgresql://app:{pw}@{host}:{port}/app");
    let mut ok = false;
    let mut last = String::new();
    for _ in 0..60 {
        if let Ok(out) = std::process::Command::new("psql")
            .args([&conn, "-tAc", "select 1"])
            .output()
        {
            last = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success() && last.trim() == "1" {
                ok = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // Also confirm the pgvector extension is installable (the whole point of the image).
    let mut ext = false;
    if ok {
        if let Ok(out) = std::process::Command::new("psql")
            .args([
                &conn,
                "-tAc",
                "create extension if not exists vector; select extversion from pg_extension where extname='vector'",
            ])
            .output()
        {
            ext = out.status.success() && !out.stdout.is_empty();
            eprintln!(
                "pgvector extension: {}",
                String::from_utf8_lossy(&out.stdout).trim()
            );
        }
    }

    let _ = backend.stop(&inst.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    assert!(
        ok,
        "postgres should answer `select 1` over TCP (last: {last:?})"
    );
    assert!(
        ext,
        "pgvector `vector` extension should create + report a version"
    );
    eprintln!(
        "co-located pgvector from an OCI image ({}): initdb + query + extension OK",
        if host_root { "host-root" } else { "rootless" }
    );
}

/// The **rootless** (default) path: in-container root maps to an unprivileged host uid, so
/// the rootfs is ownership-shifted into the mapped range. Way 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn container_live_postgres_from_oci_image() {
    run_pg_e2e(false).await;
}

/// The **host-root** opt-in: `0 → host 0`, so in-container root is real host root (a
/// single-tenant / trusted posture, like a stock Docker container). Way 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn container_live_postgres_host_root() {
    run_pg_e2e(true).await;
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

/// **Exec into a running container** (docker-exec style): launch a container, then
/// re-enter its namespaces via `ComputeBackend::exec` and run a one-shot command,
/// asserting (a) a plain command returns exit 0 with its stdout captured, and (b)
/// a stdin pipe round-trips (`busybox cat` echoes the bytes we feed it). Proves the
/// `setns`-into-a-running-container seam (user-ns first, `fork` for the pid ns, pipe
/// capture) — the analog of the launch path's netns config, generalized to exec.
///
/// Needs Linux + root + a bridge + a rootfs tar with `/bin/busybox` (as the launch
/// test); skips (passes) when the fixture env vars are absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Linux + root + a bridge + a rootfs tar with busybox (privileged live seam)"]
async fn container_exec_runs_command_and_round_trips_stdin() {
    let (Some(bin), Some(rootfs_path)) = (
        std::env::var_os("BOATRAMP_BIN"),
        std::env::var_os("BOATRAMP_CONTAINER_ROOTFS"),
    ) else {
        eprintln!("container_exec: set BOATRAMP_BIN + BOATRAMP_CONTAINER_ROOTFS to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());

    let rootfs = std::fs::read(&rootfs_path).expect("read rootfs tar");
    let data_dir = std::env::temp_dir().join(format!("boatramp-cexec-{}", std::process::id()));
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
    let artifact = backend.materialize(&spec).await.expect("materialize");
    let req = LaunchRequest {
        workload: "cexec".into(),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend.launch(&req).await.expect("launch container");

    // The container serves the nonce over HTTP — wait for it so we know the jail is
    // fully up (pid1 in the cgroup) before exec joins its namespaces.
    let nonce = probe_nonce(&inst.endpoint.host, inst.endpoint.port);
    assert!(!nonce.is_empty(), "container should be serving before exec");

    // (a) A plain command: `busybox echo hi` → exit 0, stdout contains "hi".
    let echo = backend
        .exec(
            &inst.handle,
            &[
                "/bin/busybox".to_string(),
                "echo".to_string(),
                "hi".to_string(),
            ],
            None,
        )
        .await
        .expect("exec echo");
    eprintln!(
        "exec echo: code={} stdout={:?} stderr={:?}",
        echo.exit_code,
        String::from_utf8_lossy(&echo.stdout),
        String::from_utf8_lossy(&echo.stderr)
    );
    assert_eq!(echo.exit_code, 0, "echo exits 0");
    assert!(
        String::from_utf8_lossy(&echo.stdout).contains("hi"),
        "echo stdout should contain 'hi'"
    );

    // (b) A stdin round-trip: `busybox cat` with stdin b"xyz" → stdout "xyz".
    let cat = backend
        .exec(
            &inst.handle,
            &["/bin/busybox".to_string(), "cat".to_string()],
            Some(b"xyz"),
        )
        .await
        .expect("exec cat");
    assert_eq!(cat.exit_code, 0, "cat exits 0");
    assert_eq!(
        cat.stdout, b"xyz",
        "cat should echo the stdin bytes back on stdout"
    );

    let _ = backend.stop(&inst.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!("container exec OK: echo captured + stdin round-tripped");
}
