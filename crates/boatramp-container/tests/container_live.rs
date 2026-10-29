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
        pull_secret: None,
        bindings: vec![],
        post_launch: vec![],
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
        .materialize("default", "clive", &spec, None)
        .await
        .expect("materialize rootfs");
    assert!(matches!(artifact, Artifact::Rootfs { .. }));

    let req = LaunchRequest {
        project: "default".into(),
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
            && out.status.success()
            && !out.stdout.is_empty()
        {
            nonce = String::from_utf8_lossy(&out.stdout).trim().to_string();
            break;
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
        false,
    );
    boatramp_core::compute::PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    spec.env
        .insert("POSTGRES_USER".to_string(), "app".to_string());
    spec.env
        .insert("POSTGRES_PASSWORD".to_string(), pw.to_string());
    spec.env
        .insert("POSTGRES_DB".to_string(), "app".to_string());

    let artifact = backend
        .materialize("default", &format!("cpg{tag}"), &spec, None)
        .await
        .expect("materialize (pull) pgvector image");
    assert!(matches!(artifact, Artifact::Rootfs { .. }));

    let req = LaunchRequest {
        project: "default".into(),
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
    if ok
        && let Ok(out) = std::process::Command::new("psql")
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

/// Build the managed-Postgres spec exactly as [`run_pg_e2e`] does (the SHARED synthesizer the
/// node's auto-register path uses), with the rootless `999:999` privilege directive + the
/// managed init-credential env — so this gate proves the workload that actually ships.
/// The managed-Postgres spec, driving the REAL stock pgvector entrypoint. Uses the `Rootless`
/// privilege model (the stock node default): the entrypoint runs AS the `postgres` uid 999, so
/// `gosu` isn't needed — which is what lighthouse can run (its kernel/userns returns "operation
/// not supported" when the worker tries to grant a `Caps`-model container CAP_SETUID/CAP_CHOWN,
/// so the Provisor's entrypoint-as-root posture can't be driven here). The CORE failure the fix
/// addresses — the DB (running as its runtime uid) cannot read a reused data dir owned OUTSIDE
/// the container's userns map — is identical in both models and is exercised here; the
/// runtime-uid-vs-entrypoint-uid distinction the `Caps` model adds is covered by the unit tests.
fn managed_pg_spec(pw: &str) -> ComputeSpec {
    let mut spec = boatramp_core::compute::managed_db_spec(
        boatramp_core::compute::ManagedDbEngine::Postgres,
        Some("pgvector/pgvector:pg16"),
        512,
        false,
    );
    boatramp_core::compute::PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    spec.env
        .insert("POSTGRES_USER".to_string(), "app".to_string());
    spec.env
        .insert("POSTGRES_PASSWORD".to_string(), pw.to_string());
    spec.env
        .insert("POSTGRES_DB".to_string(), "app".to_string());
    spec
}

/// Materialize + launch the managed-pg `spec` on `backend` as workload `wl`.
async fn launch_managed_pg(
    backend: &ContainerBackend,
    spec: &ComputeSpec,
    wl: &str,
) -> boatramp_core::compute::Instance {
    let artifact = backend
        .materialize("default", wl, spec, None)
        .await
        .expect("materialize (pull) pgvector image");
    let req = LaunchRequest {
        project: "default".into(),
        workload: wl.into(),
        replica: 0,
        spec: spec.clone(),
        artifact,
    };
    backend
        .launch(&req)
        .await
        .expect("launch pgvector container")
}

/// Poll `select 1` over TCP; `true` once Postgres answers. ~40 s budget (first boot initdb).
fn pg_answers(host: &str, port: u16, pw: &str) -> bool {
    let conn = format!("postgresql://app:{pw}@{host}:{port}/app");
    for _ in 0..80 {
        if let Ok(out) = std::process::Command::new("psql")
            .args([&conn, "-tAc", "select 1"])
            .output()
            && out.status.success()
            && String::from_utf8_lossy(&out.stdout).trim() == "1"
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// The `(uid, gid)` owning a host path (not following symlinks).
fn owner_of(path: &std::path::Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).expect("stat volume file");
    (m.uid(), m.gid())
}

/// **Reused-volume data preservation (the v0.45.0 managed-DB regression fix).** The CORE of the
/// Provisor failure: a managed Postgres data dir carried across a `fly machine update` /
/// `userns_base` change is owned, on the host, at a PRIOR base — OUTSIDE the current container's
/// userns map range, so it is `nobody` inside and the DB (running as its runtime uid) cannot
/// read its own cluster files (`global/pg_filenode.map: Permission denied`). v0.45.0's
/// worker-side recursive `chown_tree_to` either doesn't reach it or destructively rewrites the
/// user's whole data dir. (On the Provisor the entrypoint runs as userns-root and its root-path
/// `chown -R` EPERMs first; that `Caps` posture can't be driven on this box — the kernel/userns
/// refuses to grant the container CAP_CHOWN/CAP_SETUID — so this gate drives the REAL entrypoint
/// in the `Rootless` model, where it runs AS postgres 999 and the SAME out-of-map read failure
/// occurs; the runtime-vs-entrypoint-uid distinction is unit-tested.)
///
/// The fix makes **derive-base the primary, always-on strategy for a reused volume**: it picks
/// the userns base `D` so the data's existing host owner maps onto the DB's RUNTIME uid detected
/// from the image's `/etc/passwd` (NOT the spec/entrypoint uid), reading the data AS-IS — NO
/// chown, NO reinit. This gate, with a REAL pgvector cluster + a SENTINEL row:
///   1. Seed a real cluster (real `docker-entrypoint.sh`) and write a SENTINEL row.
///   2. Rewrite the data dir to `200999:200999` — a volume from a prior subuid base 200000
///      (`200999 = 200000 + the image postgres uid 999`), OUTSIDE the current map range
///      [100000,165535] → `nobody` inside.
///   3. Relaunch (WITH the fix): the launcher detects the runtime uid 999 and derives base
///      200000, so Postgres reads the cluster AS-IS — HEALTHY, the SENTINEL row SURVIVES, and
///      the data dir is left byte-for-byte at 200999 (ownership NOT mutated, no reinit).
///   4. Relaunch once more: the derived volume stays healthy (no regression).
///
/// Mutation-sensitive: (a) neuter the derive so the base stays 100000 — the data is `nobody`
/// inside and Postgres FATALs (`up` is false); (b) the shipped recursive chown (or deriving with
/// the entrypoint/guest uid instead of the runtime uid) rewrites the owner away from 200999 —
/// the "owner unchanged" assertion fails. Needs Linux + root + a bridge + psql; pulls pgvector.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn container_live_postgres_reused_volume_preserves_data_on_euid_root() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("container_live_postgres_reuse: set BOATRAMP_BIN to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-cpgreuse-{}", std::process::id()));
    let pw = "s3cr3t-pw";
    let spec = managed_pg_spec(pw);

    // The DEFAULT container backend — host root on this test box, the live Fly posture (euid-root
    // worker, rootless user-namespace, base 100000). No chown override: the fix must engage on
    // the default managed-pg path.
    let mk = || {
        ContainerBackend::new(
            // Storage is unused for the OCI Image path (the pull is over HTTP).
            Arc::new(FileBlob(Vec::new())),
            data_dir.clone(),
            bridge.clone(),
            &subnet,
            PathBuf::from(&bin),
        )
        .expect("backend")
    };

    // 1) Seed a real healthy cluster (real entrypoint → initdb) + a SENTINEL row.
    let seed = mk();
    let inst = launch_managed_pg(&seed, &spec, "cpgreuse").await;
    let (host, port) = (inst.endpoint.host.clone(), inst.endpoint.port);
    assert!(
        pg_answers(&host, port, pw),
        "seed: a fresh cluster must answer select 1"
    );
    let (wrote, out) = psql_exec(
        &host,
        port,
        pw,
        "create table sentinel(v text); insert into sentinel values('SENTINEL-OK')",
    );
    assert!(wrote, "seed: write the sentinel row (out: {out})");
    let _ = seed.stop(&inst.handle).await;

    // The backing dir is now keyed by the per-(project, workload) scope: default project +
    // workload "cpgreuse" ⇒ `<volumes>/cpgreuse/data`.
    let vol = data_dir
        .join("compute")
        .join("volumes")
        .join("@cpgreuse")
        .join("data");
    let sample = vol.join("PG_VERSION");
    assert!(sample.exists(), "seed produced a real cluster data dir");

    // 2) Simulate a volume carried across a userns_base change: rewrite the whole data dir to
    //    200999 (prior subuid base 200000 + the image postgres uid 999), OUTSIDE the current
    //    map range [100000,165535] → `nobody` inside the base-100000 container.
    let st = std::process::Command::new("chown")
        .args(["-R", "200999:200999", &vol.display().to_string()])
        .status()
        .expect("spawn chown fixture");
    assert!(st.success(), "fixture chown -R 200999:200999 must succeed");
    assert_eq!(
        owner_of(&sample),
        (200999, 200999),
        "fixture: the reused data dir is now owned under the prior subuid base"
    );

    // 3) Relaunch (WITH the fix): detect the runtime uid 999 + derive base 200000, so the real
    //    entrypoint + Postgres read the reused data in-map, as-is.
    let fixed = mk();
    let inst = launch_managed_pg(&fixed, &spec, "cpgreuse").await;
    let (host, port) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let up = pg_answers(&host, port, pw);
    let sentinel = if up {
        let (ok, o) = psql_exec(&host, port, pw, "select v from sentinel");
        eprintln!("sentinel read: ok={ok} out={}", o.trim());
        ok && o.trim() == "SENTINEL-OK"
    } else {
        false
    };
    if !up {
        let log = data_dir.join("compute").join("logs").join("cpgreuse-0.log");
        eprintln!(
            "reuse FAIL — guest log:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
    }
    let _ = fixed.stop(&inst.handle).await;
    let owner_after = owner_of(&sample);

    assert!(
        up,
        "fix: a reused volume at a prior mapping must come up HEALTHY (derive-base reads it \
         as-is); without the derive it is `nobody` inside and Postgres FATALs on \
         global/pg_filenode.map"
    );
    assert!(
        sentinel,
        "fix: the SENTINEL row must SURVIVE — the data is read in place, never reinitialized"
    );
    assert_eq!(
        owner_after,
        (200999, 200999),
        "fix: the data is read AS-IS — ownership is NOT mutated (the shipped recursive chown, or \
         deriving with the entrypoint uid, would rewrite it)"
    );

    // 4) No-regress: relaunching the derived volume stays healthy with the sentinel intact.
    let inst = launch_managed_pg(&fixed, &spec, "cpgreuse").await;
    let (host, port) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let up2 = pg_answers(&host, port, pw);
    let sentinel2 = up2 && {
        let (ok, o) = psql_exec(&host, port, pw, "select v from sentinel");
        ok && o.trim() == "SENTINEL-OK"
    };
    let _ = fixed.stop(&inst.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);
    assert!(
        sentinel2,
        "relaunch of the derived volume must stay healthy with the sentinel intact (no regress)"
    );
    eprintln!(
        "reused-volume data preservation OK: detected runtime uid 999, derived base 200000, \
         Postgres read its cluster as-is, sentinel survived, ownership left at 200999, \
         no-regress relaunch"
    );
}

/// **Cross-tenant volume-collision fix (the CRITICAL defect).** TWO co-located managed
/// Postgres workloads — modeling the Provisor's `default` DB and its `control` DB — are
/// each handed the bare volume name `"data"` (the managed-DB synthesizer's default). Before
/// the fix the container backend keyed a volume's backing dir by that bare name alone, so
/// BOTH mounted the SAME host directory `<data_dir>/compute/volumes/data`: the second
/// Postgres either crash-loops on the first's cluster (fail-closed DoS, the observed shape)
/// or, worse, serves the neighbor's data (fail-open cross-tenant disclosure / two postmasters
/// on one PGDATA → corruption). The fix keys the backing dir by the collision-free
/// `(project, workload)` scope, so each DB gets its OWN cluster.
///
/// This is a TRUE multi-tenant fixture (two DISTINCT clusters, each with its own sentinel
/// row) proving ZERO cross-read. **Mutation-sensitive**: neuter the scope (make
/// `compute_volume_scope`/`scoped_volume_dir` ignore the workload) and both DBs collapse onto
/// `<volumes>/data` again — the second either fails to come up (the `_up` assert fires) or
/// reads the first's `sentinel` row (the cross-read assert fires). Needs Linux + root + a
/// bridge + psql; pulls pgvector.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn container_colocated_managed_dbs_get_isolated_volumes() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("container_colocated_managed_dbs: set BOATRAMP_BIN to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-colo-{}", std::process::id()));
    let pw = "s3cr3t-pw";
    let spec = managed_pg_spec(pw); // the bare `"data"` volume, exactly as shipped

    // ONE node-global backend (data_dir shared across workloads), exactly like the node builds
    // it. Both managed DBs run under the reserved `default` project (the Provisor's posture).
    let backend = ContainerBackend::new(
        Arc::new(FileBlob(Vec::new())),
        data_dir.clone(),
        bridge.clone(),
        &subnet,
        PathBuf::from(&bin),
    )
    .expect("backend");

    // Launch BOTH co-located managed DBs, each requesting the bare `"data"` volume.
    let pg = launch_managed_pg(&backend, &spec, "pg").await;
    let control = launch_managed_pg(&backend, &spec, "control").await;
    let (pg_host, pg_port) = (pg.endpoint.host.clone(), pg.endpoint.port);
    let (ct_host, ct_port) = (control.endpoint.host.clone(), control.endpoint.port);

    // Both come up healthy, side by side (pre-fix the second collided on the first's cluster
    // and either crash-looped or served the neighbor's data). `pg_answers` polls until each
    // has finished `initdb` and is answering, so the on-disk cluster assertions below are not
    // racing a still-initializing container.
    let pg_up = pg_answers(&pg_host, pg_port, pw);
    let ct_up = pg_answers(&ct_host, ct_port, pw);
    assert!(pg_up, "pg must be healthy");
    assert!(
        ct_up,
        "control must be healthy co-located with pg (no collision)"
    );

    // Each landed on its OWN per-(project, workload) scoped backing dir; the legacy flat
    // shared dir was never created.
    let pg_dir = data_dir.join("compute/volumes/@pg/data");
    let ct_dir = data_dir.join("compute/volumes/@control/data");
    let legacy = data_dir.join("compute/volumes/data");
    assert!(
        pg_dir.join("PG_VERSION").exists(),
        "pg got its own cluster dir"
    );
    assert!(
        ct_dir.join("PG_VERSION").exists(),
        "control got its own cluster dir"
    );
    assert!(
        !legacy.exists(),
        "the collision-prone flat <volumes>/data must NOT be used anymore"
    );
    assert_ne!(pg_dir, ct_dir, "distinct backing dirs");

    // Seed a DISTINCT sentinel in each, then prove ZERO cross-read: each DB sees ONLY its own.
    let (w1, o1) = psql_exec(
        &pg_host,
        pg_port,
        pw,
        "create table sentinel(v text); insert into sentinel values('PG-SENTINEL')",
    );
    assert!(w1, "seed pg sentinel (out: {o1})");
    let (w2, o2) = psql_exec(
        &ct_host,
        ct_port,
        pw,
        "create table sentinel(v text); insert into sentinel values('CONTROL-SENTINEL')",
    );
    assert!(w2, "seed control sentinel (out: {o2})");

    let (_, pg_read) = psql_exec(
        &pg_host,
        pg_port,
        pw,
        "select string_agg(v, ',') from sentinel",
    );
    let (_, ct_read) = psql_exec(
        &ct_host,
        ct_port,
        pw,
        "select string_agg(v, ',') from sentinel",
    );
    let _ = backend.stop(&pg.handle).await;
    let _ = backend.stop(&control.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    assert_eq!(
        pg_read.trim(),
        "PG-SENTINEL",
        "pg must see ONLY its own row — never control's (cross-tenant read)"
    );
    assert_eq!(
        ct_read.trim(),
        "CONTROL-SENTINEL",
        "control must see ONLY its own row — never pg's (cross-tenant read)"
    );
    eprintln!(
        "colocated isolation OK: pg→{pg_dir:?} control→{ct_dir:?}, both healthy, zero cross-read"
    );
}

/// **Legacy single-claimant adoption + fail-closed refuse.** On upgrade, an existing
/// deployment holds a managed cluster at the pre-fix bare `<volumes>/data`. EXACTLY ONE
/// workload — the proven owner — adopts it (data preserved, read AS-IS via the derive-base
/// repair); every other co-located DB gets a FRESH dir and NEVER touches the shared one; and
/// when the owner is NOT proven, the launch fails closed rather than fresh-initializing over a
/// neighbor's cluster. Drives real pgvector clusters. Needs Linux + root + a bridge + psql.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn container_legacy_data_volume_adopted_only_by_the_claimant() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("container_legacy_data_adoption: set BOATRAMP_BIN to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-legacy-{}", std::process::id()));
    let pw = "s3cr3t-pw";
    let spec = managed_pg_spec(pw);
    let mk = || {
        ContainerBackend::new(
            Arc::new(FileBlob(Vec::new())),
            data_dir.clone(),
            bridge.clone(),
            &subnet,
            PathBuf::from(&bin),
        )
        .expect("backend")
    };
    let legacy = data_dir.join("compute/volumes/data");

    // 1) Seed a real cluster as "pg", write a SENTINEL row, then MOVE it to the pre-fix flat
    //    `<volumes>/data` to model an upgraded deployment (an atomic rename preserves ownership).
    {
        let b = mk();
        let inst = launch_managed_pg(&b, &spec, "pg").await;
        let (h, p) = (inst.endpoint.host.clone(), inst.endpoint.port);
        assert!(pg_answers(&h, p, pw), "seed cluster must answer");
        let (w, o) = psql_exec(
            &h,
            p,
            pw,
            "create table sentinel(v text); insert into sentinel values('LEGACY-OWNER')",
        );
        assert!(w, "seed the legacy sentinel (out: {o})");
        let _ = b.stop(&inst.handle).await;
    }
    let scoped_pg = data_dir.join("compute/volumes/@pg/data");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::rename(&scoped_pg, &legacy).expect("stage the legacy flat <volumes>/data");
    // pg's scope dir is now empty; remove it so the adoption path (scoped dir absent) engages.
    let _ = std::fs::remove_dir_all(data_dir.join("compute/volumes/@pg"));
    assert!(
        legacy.join("PG_VERSION").exists(),
        "legacy flat cluster staged"
    );

    // 2) The PROVEN claimant ("default"/"pg") adopts the legacy dir (atomic rename, read as-is).
    let claimant = mk().with_legacy_data_claimant(Some(("default".into(), "pg".into())));
    let inst = launch_managed_pg(&claimant, &spec, "pg").await;
    let (h, p) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let pg_up = pg_answers(&h, p, pw);
    let (_, read) = psql_exec(&h, p, pw, "select string_agg(v, ',') from sentinel");
    let _ = claimant.stop(&inst.handle).await;
    assert!(pg_up, "the claimant must come up on the adopted cluster");
    assert_eq!(
        read.trim(),
        "LEGACY-OWNER",
        "the claimant adopted the legacy cluster AS-IS — the owner's data is preserved"
    );
    assert!(
        !legacy.exists(),
        "the legacy flat dir was migrated away (atomic rename, not a copy)"
    );
    assert!(
        scoped_pg.join("PG_VERSION").exists(),
        "the data now lives under the claimant's scoped dir"
    );

    // 3) A co-located NON-claimant ("control") gets a FRESH cluster and never sees the owner's
    //    data (the legacy dir is already adopted/gone, so it simply fresh-inits in its own scope).
    let inst = launch_managed_pg(&claimant, &spec, "control").await;
    let (h, p) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let ct_up = pg_answers(&h, p, pw);
    let (cross_ok, cross) = psql_exec(&h, p, pw, "select v from sentinel");
    let _ = claimant.stop(&inst.handle).await;
    assert!(ct_up, "the non-claimant must come up on a FRESH cluster");
    assert!(
        !(cross_ok && cross.trim() == "LEGACY-OWNER"),
        "the non-claimant must NOT see the owner's data (fresh cluster has no `sentinel` table)"
    );
    assert!(
        data_dir
            .join("compute/volumes/@control/data/PG_VERSION")
            .exists(),
        "the non-claimant got its own scoped dir"
    );

    // 4) REFUSE-ON-UNPROVEN: re-stage a legacy flat dir and launch a NOT-YET-MIGRATED managed
    //    DB ("analytics") with NO proven owner (claimant = None) → the launch FAILS CLOSED, the
    //    legacy data untouched. (A fresh workload name whose scoped dir does not yet exist, so
    //    the adoption path actually engages rather than skipping an already-migrated dir.)
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("PG_VERSION"), "16").unwrap();
    std::fs::write(legacy.join("marker"), "OWNER-DATA").unwrap();
    let ambiguous = mk(); // claimant: None
    let refused = ambiguous
        .materialize("default", "analytics", &spec, None)
        .await;
    assert!(
        refused.is_err(),
        "with no proven owner, a managed DB must refuse to launch over an unclaimed legacy dir"
    );
    assert_eq!(
        std::fs::read_to_string(legacy.join("marker")).unwrap(),
        "OWNER-DATA",
        "the refusal left the legacy data byte-for-byte in place"
    );
    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!("legacy single-claimant adoption + refuse-on-unproven OK");
}

/// **F4 node-side bulk migration — the ENV-configured turnkey recovery topology.** The mainline
/// deployment runs a NODE-DEFAULT managed pg (workload `pg`, DEFAULT project) that owns the
/// historical bare `<volumes>/data` cluster, with a co-located applied `control` DB (no data) that
/// also collided on it — and NO node-static `[databases]` config / NO `adopt_legacy_data_volume`
/// flag. The node recognizes the node-default pg as the trusted claimant and F4 proactively
/// migrates its cluster into `<volumes>/@pg/data` BEFORE launch, so the working pg comes up with
/// its data preserved and the declared `control` gets a FRESH scoped dir — both healthy, zero
/// cross-read. This drives F4's backend migration (`migrate_legacy_volumes`) on real pgvector
/// clusters with the exact (project, workload, volume) triple the node computes. Mutation-
/// sensitive: skip the migration and pg fails closed on the unadopted `<volumes>/data`. Needs
/// Linux + root + a bridge + psql.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn container_f4_node_default_pg_adopts_data_colocated_control_fresh() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("container_f4_node_default_pg: set BOATRAMP_BIN to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-f4-{}", std::process::id()));
    let pw = "s3cr3t-pw";
    let spec = managed_pg_spec(pw);
    let mk = || {
        ContainerBackend::new(
            Arc::new(FileBlob(Vec::new())),
            data_dir.clone(),
            bridge.clone(),
            &subnet,
            PathBuf::from(&bin),
        )
        .expect("backend")
    };
    let legacy = data_dir.join("compute/volumes/data");

    // 1) Seed the node-default pg's cluster + a SENTINEL, then stage it at the pre-fix flat
    //    `<volumes>/data` (model the historical turnkey on-disk state).
    {
        let b = mk();
        let inst = launch_managed_pg(&b, &spec, "pg").await;
        let (h, p) = (inst.endpoint.host.clone(), inst.endpoint.port);
        assert!(pg_answers(&h, p, pw), "seed cluster answers");
        let (w, o) = psql_exec(
            &h,
            p,
            pw,
            "create table sentinel(v text); insert into sentinel values('PROVISOR')",
        );
        assert!(w, "seed the node-default pg sentinel (out: {o})");
        let _ = b.stop(&inst.handle).await;
    }
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::rename(data_dir.join("compute/volumes/@pg/data"), &legacy)
        .expect("stage the legacy flat <volumes>/data");
    let _ = std::fs::remove_dir_all(data_dir.join("compute/volumes/@pg"));
    assert!(
        legacy.join("PG_VERSION").exists(),
        "legacy flat cluster staged"
    );

    // 2) F4: the node computes the node-trusted authorized set (node-default pg owns `data`) and
    //    the backend migrates it into the scoped layout BEFORE launch — no config flag involved.
    let backend = mk();
    let authorized = vec![("default".to_string(), "pg".to_string(), "data".to_string())];
    assert_eq!(
        backend.migrate_legacy_volumes(&authorized).await,
        1,
        "F4 migrated the node-default pg's legacy `data` cluster"
    );
    assert!(!legacy.exists(), "legacy flat dir migrated away");
    assert!(
        data_dir
            .join("compute/volumes/@pg/data/PG_VERSION")
            .exists()
    );

    // 3) The node-default pg launches on the ADOPTED cluster (data preserved, read as-is).
    let inst = launch_managed_pg(&backend, &spec, "pg").await;
    let (pg_h, pg_p) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let pg_up = pg_answers(&pg_h, pg_p, pw);
    let (_, pg_read) = psql_exec(&pg_h, pg_p, pw, "select string_agg(v, ',') from sentinel");

    // 4) The co-located declared `control` gets a FRESH scoped dir (the legacy `data` is gone) —
    //    healthy, and it CANNOT see the node-default pg's data.
    let ctrl = launch_managed_pg(&backend, &spec, "control").await;
    let (ct_h, ct_p) = (ctrl.endpoint.host.clone(), ctrl.endpoint.port);
    let ct_up = pg_answers(&ct_h, ct_p, pw);
    let (cross_ok, cross) = psql_exec(&ct_h, ct_p, pw, "select v from sentinel");
    let _ = backend.stop(&inst.handle).await;
    let _ = backend.stop(&ctrl.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    assert!(pg_up, "the node-default pg came up on its adopted cluster");
    assert_eq!(
        pg_read.trim(),
        "PROVISOR",
        "the node-default pg's data is preserved, read as-is"
    );
    assert!(
        ct_up,
        "the co-located declared `control` came up on a FRESH scoped dir"
    );
    assert!(
        !(cross_ok && cross.trim() == "PROVISOR"),
        "the declared `control` must NOT see the node-default pg's data (zero cross-read)"
    );
    eprintln!(
        "F4 turnkey OK: node-default pg adopted <volumes>/data, control fresh, zero cross-read"
    );
}

/// Run one SQL statement via `psql`, returning `(success, combined stdout+stderr)`.
fn psql_exec(host: &str, port: u16, pw: &str, sql: &str) -> (bool, String) {
    let conn = format!("postgresql://app:{pw}@{host}:{port}/app");
    match std::process::Command::new("psql")
        .args([&conn, "-tAc", sql])
        .output()
    {
        Ok(out) => (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        ),
        Err(e) => (false, e.to_string()),
    }
}

/// `ls -lan` a host path (numeric owners), for ownership evidence in the diagnostic.
fn ls_lan(path: &std::path::Path) -> String {
    std::process::Command::new("ls")
        .args(["-lan", &path.display().to_string()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Read the running container's `/proc/<pid>/uid_map` by finding a pid in its cgroup.
fn container_uid_map(id: &str) -> String {
    let procs = std::fs::read_to_string(format!("/sys/fs/cgroup/boatramp/{id}/cgroup.procs"))
        .unwrap_or_default();
    let Some(pid) = procs.split_whitespace().next() else {
        return "(no pid in cgroup)".into();
    };
    std::fs::read_to_string(format!("/proc/{pid}/uid_map"))
        .unwrap_or_else(|e| format!("(err: {e})"))
}

/// **DIAGNOSTIC (full host visibility).** Reproduce the Provisor shape and MEASURE it:
/// euid-root worker + DEFAULT rootless-userns backend (recursive worker chown ON — the
/// shipped v0.45.0 behaviour) + managed-pg `Rootless(999)` + a reused data volume whose host
/// owner is a subuid mapping under a DIFFERENT base than the current launch. Prints host-side
/// `ls -lan`, the container `uid_map`, the guest log, and whether a SENTINEL row survives.
///
/// Env knobs (so scenarios can be probed without recompiling):
///   DIAG_FOREIGN_UID / DIAG_FOREIGN_GID  the owner to rewrite the reused volume to (default 70999)
///   DIAG_USER                            the launch `user` ("999:999" default; "" leaves it unset → guest 0)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "diagnostic: needs Linux + root + bridge + psql; pulls pgvector"]
async fn container_diag_reused_volume_mapping() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("diag: set BOATRAMP_BIN");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let foreign_uid: u32 = std::env::var("DIAG_FOREIGN_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(70999);
    let foreign_gid: u32 = std::env::var("DIAG_FOREIGN_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(70999);
    let user = std::env::var("DIAG_USER").unwrap_or_else(|_| "999:999".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-diag-{}", std::process::id()));
    let pw = "s3cr3t-pw";

    let mut spec = boatramp_core::compute::managed_db_spec(
        boatramp_core::compute::ManagedDbEngine::Postgres,
        Some("pgvector/pgvector:pg16"),
        512,
        false,
    );
    if !user.is_empty() {
        let (u, g) = user
            .split_once(':')
            .unwrap_or((user.as_str(), user.as_str()));
        boatramp_core::compute::PrivilegeDirective::Rootless {
            uid: u.parse().unwrap(),
            gid: g.parse().unwrap(),
        }
        .apply(&mut spec);
    }
    spec.env.insert("POSTGRES_USER".into(), "app".into());
    spec.env.insert("POSTGRES_PASSWORD".into(), pw.into());
    spec.env.insert("POSTGRES_DB".into(), "app".into());
    eprintln!(
        "DIAG spec.user = {:?}  foreign={foreign_uid}:{foreign_gid}",
        spec.user
    );

    let mk = || {
        ContainerBackend::new(
            Arc::new(FileBlob(Vec::new())),
            data_dir.clone(),
            bridge.clone(),
            &subnet,
            PathBuf::from(&bin),
        )
        .expect("backend")
    };

    // Backing dir keyed by the per-(project, workload) scope: default project + workload
    // "diag" ⇒ `<volumes>/diag/data`.
    let vol = data_dir
        .join("compute")
        .join("volumes")
        .join("@diag")
        .join("data");

    // Phase A: fresh init under the current mapping; insert a sentinel.
    let b = mk();
    let inst = launch_managed_pg(&b, &spec, "diag").await;
    let (host, port) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let up = pg_answers(&host, port, pw);
    eprintln!("[A] fresh launch: pg answers = {up}");
    eprintln!("[A] uid_map: {}", container_uid_map("diag-0").trim());
    if up {
        let (ok, o) = psql_exec(
            &host,
            port,
            pw,
            "create table sentinel(v text); insert into sentinel values('ALIVE-42'); select v from sentinel",
        );
        eprintln!("[A] sentinel write: ok={ok} out={}", o.trim());
    }
    eprintln!("[A] host ls -lan (volume root):\n{}", ls_lan(&vol));
    eprintln!(
        "[A] host ls -lan (global/):\n{}",
        ls_lan(&vol.join("global"))
    );
    let _ = b.stop(&inst.handle).await;

    // Phase B: rewrite the reused volume to a foreign (prior-base) owner.
    let st = std::process::Command::new("chown")
        .args([
            "-R",
            &format!("{foreign_uid}:{foreign_gid}"),
            &vol.display().to_string(),
        ])
        .status()
        .expect("chown fixture");
    eprintln!(
        "[B] chown -R {foreign_uid}:{foreign_gid} success={}",
        st.success()
    );
    eprintln!("[B] host ls -lan (volume root):\n{}", ls_lan(&vol));

    // Phase C: relaunch under current (recursive-chown) code; measure.
    let b = mk();
    let inst = launch_managed_pg(&b, &spec, "diag").await;
    let (host, port) = (inst.endpoint.host.clone(), inst.endpoint.port);
    let up = pg_answers(&host, port, pw);
    eprintln!("[C] relaunch: pg answers = {up}");
    eprintln!("[C] uid_map: {}", container_uid_map("diag-0").trim());
    eprintln!(
        "[C] host ls -lan AFTER worker chown (volume root):\n{}",
        ls_lan(&vol)
    );
    eprintln!(
        "[C] host ls -lan (global/):\n{}",
        ls_lan(&vol.join("global"))
    );
    let sentinel = if up {
        let (ok, o) = psql_exec(&host, port, pw, "select v from sentinel");
        eprintln!("[C] sentinel read: ok={ok} out={}", o.trim());
        o.trim() == "ALIVE-42"
    } else {
        false
    };
    let log = data_dir.join("compute").join("logs").join("diag-0.log");
    eprintln!(
        "[C] guest log:\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    let _ = b.stop(&inst.handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!("[SUMMARY] relaunch-healthy={up} sentinel-survived={sentinel}");
}

/// Poll the container's `/nonce` endpoint over HTTP, returning the body or empty.
fn probe_nonce(host: &str, port: u16) -> String {
    let url = format!("http://{host}:{port}/nonce");
    for _ in 0..40 {
        if let Ok(out) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "2", &url])
            .output()
            && out.status.success()
            && !out.stdout.is_empty()
        {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
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
    let artifact = backend
        .materialize("default", "ccriu", &spec, None)
        .await
        .expect("materialize");
    let req = LaunchRequest {
        project: "default".into(),
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
    let artifact = backend
        .materialize("default", "cexec", &spec, None)
        .await
        .expect("materialize");
    let req = LaunchRequest {
        project: "default".into(),
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

/// **One-shot `run_ephemeral`** (the native project-export/import engine): with NO
/// persisted workload, pull a small OCI image daemonless (the DEFAULT on-demand path —
/// `stage_image`), launch a hardened one-shot jail on it with veth egress, and prove the
/// three load-bearing properties of the ephemeral contract:
///   (A) **stdout streams out** + the exit code is captured — `sh -c 'echo hi'` → the
///       sink receives `hi` and the code is 0;
///   (B) **stdin streams in** over the dedicated pipe — `cat` echoes a payload we feed it
///       back on stdout (the restore direction, decoupled from the handshake fd);
///   (C) a **non-zero exit is a legitimate code**, returned as `Ok(code)` not an error —
///       `sh -c 'exit 7'` → `Ok(7)`.
///
/// Mirrors the co-located-Postgres seam: needs Linux + root + a bridge (for the veth
/// netns wiring, exercised even though `echo`/`cat` need no DB), and network to pull the
/// image. Ignored by default; skips (passes) when `BOATRAMP_BIN` is absent. Uses a small
/// busybox image by default (override with `CONTAINER_EPHEMERAL_IMAGE`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Linux + root + a bridge (privileged live seam); pulls a small OCI image"]
async fn container_live_run_ephemeral() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("container_live_run_ephemeral: set BOATRAMP_BIN to run");
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());
    let image =
        std::env::var("CONTAINER_EPHEMERAL_IMAGE").unwrap_or_else(|_| "busybox:latest".into());
    let data_dir = std::env::temp_dir().join(format!("boatramp-cephm-{}", std::process::id()));
    let backend = ContainerBackend::new(
        // Storage is unused for the DEFAULT image path (the pull is over HTTP).
        Arc::new(FileBlob(Vec::new())),
        data_dir.clone(),
        bridge,
        &subnet,
        PathBuf::from(bin),
    )
    .expect("backend");

    // (A) Streamed stdout + exit code: `sh -c 'echo hi'`.
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    let code = backend
        .run_ephemeral(
            &image,
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string(),
            ],
            &[],
            None,
            &mut sink,
        )
        .await
        .expect("run_ephemeral echo");
    let out = String::from_utf8_lossy(sink.get_ref()).trim().to_string();
    eprintln!("run_ephemeral echo: code={code} stdout={out:?}");
    assert_eq!(code, 0, "echo exits 0");
    assert_eq!(
        out, "hi",
        "the client's stdout must stream back to the sink"
    );

    // (B) Streamed stdin (the restore direction): `cat` echoes the fed payload.
    let payload = b"boatramp-ephemeral-stdin-roundtrip".to_vec();
    let mut reader = futures::io::Cursor::new(payload.clone());
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    let code = backend
        .run_ephemeral(
            &image,
            &["/bin/cat".to_string()],
            &[],
            Some(&mut reader),
            &mut sink,
        )
        .await
        .expect("run_ephemeral cat");
    assert_eq!(code, 0, "cat exits 0");
    assert_eq!(
        sink.get_ref(),
        &payload,
        "cat must echo the STREAMED stdin back on stdout (restore path)"
    );

    // (C) A non-zero exit is a legitimate code (returned as Ok), not an error.
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    let code = backend
        .run_ephemeral(
            &image,
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 7".to_string(),
            ],
            &[],
            None,
            &mut sink,
        )
        .await
        .expect("run_ephemeral exit-7 returns Ok(code), not Err");
    assert_eq!(code, 7, "a non-zero client exit is returned as Ok(7)");

    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!("native run_ephemeral OK: streamed stdout + stdin round-trip + non-zero exit code");
}
