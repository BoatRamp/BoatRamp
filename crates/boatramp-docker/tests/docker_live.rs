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
        bindings: vec![],
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
        .materialize(&spec)
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
