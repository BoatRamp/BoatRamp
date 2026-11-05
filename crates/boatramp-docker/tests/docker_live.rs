//! Live integration coverage for the remote-Docker backend, against a real
//! Docker daemon. Env-gated: it skips cleanly when `BOATRAMP_TEST_DOCKER` is
//! unset (and when no daemon is reachable), so `cargo test` stays green without
//! infrastructure — the same pattern as the S3/MinIO test.
//!
//! Run it:
//! ```sh
//! BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live -- --nocapture
//! ```
//! It pulls a tiny image, launches a replica, asserts it's healthy (running),
//! runs a command inside it via `exec` (stdout, stderr, stdin, exit code), then
//! stops + removes it — exercising materialize → launch → health → exec → stop.

use std::collections::BTreeMap;

use boatramp_core::compute::{ComputeBackend, Health, LaunchRequest};
use boatramp_docker::DockerBackend;
use boatramp_types::compute::{ComputeSpec, IsolationRequirement, RestartPolicy, RootSource};

/// A small, widely-cached image with a long-lived entrypoint (no port needed —
/// health is daemon-`inspect` based).
const TEST_IMAGE: &str = "alpine:3.20";

fn spec() -> ComputeSpec {
    ComputeSpec {
        version: 1,
        root: RootSource::Image(TEST_IMAGE.to_string()),
        kernel: String::new(),
        kernel_cmdline: None,
        vcpus: 1,
        mem_mib: 64,
        entrypoint: vec!["sleep".into(), "30".into()],
        env: BTreeMap::new(),
        port: 0,
        restart: RestartPolicy::Never,
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

#[tokio::test]
async fn docker_round_trip() {
    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping docker test: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }
    let backend = DockerBackend::connect().expect("connect to docker");
    let spec = spec();

    let artifact = backend
        .materialize("default", "ittest", &spec, None)
        .await
        .expect("materialize (pull)");
    let req = LaunchRequest {
        project: "default".into(),
        workload: "ittest".into(),
        replica: 0,
        spec: spec.clone(),
        artifact,
    };
    let instance = backend.launch(&req).await.expect("launch");
    assert_eq!(
        backend.health(&instance.handle).await.expect("health"),
        Health::Healthy,
        "the launched container should be running"
    );

    // exec: stdout capture + zero exit.
    let out = backend
        .exec(&instance.handle, &["echo".into(), "hello".into()], None)
        .await
        .expect("exec echo");
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.stdout, b"hello\n");
    assert!(out.stderr.is_empty());

    // exec: non-zero exit code is surfaced.
    let out = backend
        .exec(&instance.handle, &["false".into()], None)
        .await
        .expect("exec false");
    assert_ne!(out.exit_code, 0, "`false` exits non-zero");

    // exec: stdin is fed to the command (cat echoes it back on stdout).
    let out = backend
        .exec(&instance.handle, &["cat".into()], Some(b"piped-in"))
        .await
        .expect("exec cat <stdin>");
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.stdout, b"piped-in");

    backend.stop(&instance.handle).await.expect("stop");
    // After stop, the container is gone → unhealthy.
    assert_eq!(
        backend.health(&instance.handle).await.expect("health"),
        Health::Unhealthy,
    );
}

/// A busybox-`nc` persistent TCP server that writes a fixed `body` to every connection on `:8080`.
/// `nc -lk ... -e` keeps listening (one response per connect); it needs nothing writable and no
/// extra applet (alpine busybox ships `nc`, but not `httpd`). A sibling reaches it by the
/// workload's network alias.
fn server_spec(body: &str) -> ComputeSpec {
    let mut s = spec();
    s.entrypoint = vec![
        "nc".into(),
        "-lk".into(),
        "-p".into(),
        "8080".into(),
        "-e".into(),
        "sh".into(),
        "-c".into(),
        format!("printf '{body}'"),
    ];
    s.port = 8080;
    s
}

/// A long-lived client spec we `exec` probes into.
fn client_spec() -> ComputeSpec {
    let mut s = spec();
    s.entrypoint = vec!["sleep".into(), "600".into()];
    s.port = 0;
    s
}

/// The **cross-project network isolation** live gate (the v0.54.1 managed-DB-DNS fix). Proves,
/// against a REAL Docker daemon, that:
///
/// 1. Two workloads in ONE project resolve + connect to each other by NAME over the per-project
///    user-defined network (the bug: the default bridge has no embedded DNS, so the name never
///    resolved and a managed-DB-bound sibling crash-looped).
/// 2. The SAME workload name in a SECOND project resolves to a DIFFERENT container (no cross-
///    project DNS leak), and
/// 3. a container in one project CANNOT reach another project's container even by raw IP
///    (docker's inter-network isolation — the tenancy boundary). A single-project fixture is blind
///    to a leak, so BOTH projects are seeded and the foreign reach is asserted to FAIL.
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final success marker,
/// which is printed ONLY after every assertion holds — it cannot be earned without the real pass.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   per_project_network -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_per_project_network_dns_and_cross_project_isolation() {
    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }
    let backend = DockerBackend::connect().expect("connect to docker");

    // Launch (materialize + launch) one replica of `workload` in `project`.
    async fn launch(
        backend: &DockerBackend,
        project: &str,
        workload: &str,
        spec: &ComputeSpec,
    ) -> boatramp_core::compute::Instance {
        let artifact = backend
            .materialize(project, workload, spec, None)
            .await
            .expect("materialize");
        let req = LaunchRequest {
            project: project.into(),
            workload: workload.into(),
            replica: 0,
            spec: spec.clone(),
            artifact,
        };
        backend.launch(&req).await.expect("launch")
    }

    // Project "proja": server workload "db" (serves HELLO) + client "app".
    // Project "projb": server workload "db" (serves WORLD) + client "app" — the SAME workload
    // name on purpose, to prove names don't leak across projects.
    let a_db = launch(&backend, "proja", "db", &server_spec("HELLO")).await;
    let a_app = launch(&backend, "proja", "app", &client_spec()).await;
    let b_db = launch(&backend, "projb", "db", &server_spec("WORLD")).await;
    let b_app = launch(&backend, "projb", "app", &client_spec()).await;

    // (1)+(2): each project's "app" resolves "db" by NAME over its own network (Docker's embedded
    // DNS answers the workload alias) and connects, reading back ITS OWN project's server body —
    // never the other project's. `nc <name> 8080` exercises resolution + TCP connect in one. Retry
    // to absorb the listener's startup.
    let fetch_by_name = |h: &boatramp_core::compute::InstanceHandle| {
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "for i in $(seq 1 30); do R=$(nc -w3 db 8080 </dev/null 2>/dev/null); \
             if [ -n \"$R\" ]; then printf '%s' \"$R\"; exit 0; fi; sleep 1; done; exit 1"
                .to_string(),
        ];
        let h = h.clone();
        let backend = &backend;
        async move {
            backend
                .exec(&h, &argv, None)
                .await
                .expect("exec nc by name")
        }
    };
    let out_a = fetch_by_name(&a_app.handle).await;
    assert_eq!(
        out_a.exit_code, 0,
        "proja/app must resolve+reach proja/db by name"
    );
    assert_eq!(
        String::from_utf8_lossy(&out_a.stdout).trim(),
        "HELLO",
        "proja/app must see proja/db (HELLO), never projb/db"
    );
    let out_b = fetch_by_name(&b_app.handle).await;
    assert_eq!(
        out_b.exit_code, 0,
        "projb/app must resolve+reach projb/db by name"
    );
    assert_eq!(
        String::from_utf8_lossy(&out_b.stdout).trim(),
        "WORLD",
        "projb/app must see projb/db (WORLD) — the name 'db' must NOT leak proja/db across projects"
    );

    // (3): CROSS-PROJECT reach by raw IP must FAIL. Grab projb/db's container IP (its project-net
    // address) and try to connect from proja/app — docker's inter-network isolation must drop it.
    // `nc -z -w5` is a zero-I/O connect scan: exit 0 on connect, non-zero on a blocked/refused one.
    let b_db_ip = backend
        .replica_direct_host(&b_db.handle)
        .await
        .expect("projb/db bridge IP");
    let argv_ip = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("nc -z -w5 {b_db_ip} 8080"),
    ];
    let cross = backend
        .exec(&a_app.handle, &argv_ip, None)
        .await
        .expect("exec cross-project nc by ip");
    assert_ne!(
        cross.exit_code, 0,
        "proja/app must NOT reach projb/db by IP {b_db_ip} — cross-project L3 isolation breached"
    );

    // Also prove the NAME does not resolve across projects: the foreign workload name has no alias
    // on proja's network, so the connect cannot even resolve a host. (proja has no workload named
    // 'otherdb', so this is a pure negative resolution — symmetry with the raw-IP block above.)
    let argv_badname = vec![
        "sh".to_string(),
        "-c".to_string(),
        "nc -z -w5 otherdb 8080".to_string(),
    ];
    let badname = backend
        .exec(&a_app.handle, &argv_badname, None)
        .await
        .expect("exec unknown-name nc");
    assert_ne!(
        badname.exit_code, 0,
        "an unknown workload name must NOT resolve on a project network"
    );

    // Cleanup (best-effort): stopping the last workload of each project GCs its network.
    for h in [&a_app.handle, &a_db.handle, &b_app.handle, &b_db.handle] {
        let _ = backend.stop(h).await;
    }

    // The single success marker the capability gate greps for — printed ONLY after every
    // assertion above held (name resolution within a project, no cross-project name leak, and no
    // cross-project IP reach). It cannot be reached without the real, end-to-end pass.
    println!(
        "DOCKER PROJECT-NET DNS + CROSS-PROJECT ISOLATION OK: proja/app->proja/db by name (HELLO); \
         projb/app->projb/db by name (WORLD); proja/app denied projb/db by ip {b_db_ip} and by name"
    );
}
