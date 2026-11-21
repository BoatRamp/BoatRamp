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

use boatramp_core::compute::{ComputeBackend, Health, LaunchRequest, compute_instance_id};
use boatramp_docker::DockerBackend;
use boatramp_types::compute::{ComputeSpec, RestartPolicy, RootSource};

/// A small, widely-cached image with a long-lived entrypoint (no port needed —
/// health is daemon-`inspect` based).
const TEST_IMAGE: &str = "alpine:3.20";

fn spec() -> ComputeSpec {
    ComputeSpec::builder(RootSource::Image(TEST_IMAGE.to_string()), 1, 64, 0)
        .entrypoint(vec!["sleep".into(), "30".into()])
        .restart(RestartPolicy::Never)
        .build()
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
        redaction: Default::default(),
        priority_class: None,
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
            redaction: Default::default(),
            priority_class: None,
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

/// The **long managed-DB workload SD** live gate (Bug D — Docker 29 RFC 1035 63-octet label cap).
///
/// The cross-project gate above launches a SHORT server workload (`db`), which registers an
/// embedded-DNS service-discovery record on EVERY docker version — so it could never reproduce
/// simertec's failure. A `Single`-isolation managed-DB workload is `bramp-db-<25>-<ident>_<25>`
/// (≈ 69 octets); Docker 29.9.1's libnetwork refuses to publish an SD record for a label over 63
/// octets (Docker 28 tolerated it, which is why the gate was green), so a sibling resolving the
/// DB by that over-long name got NXDOMAIN and a managed-DB-bound workload crash-looped.
///
/// This launches a server under a RAW managed-DB-shaped name EXCEEDING 63 octets — exercising the
/// real `launch()` path — and asserts a sibling resolves + connects to it by the SHORT
/// [`managed_db_alias`](boatramp_core::compute::managed_db_alias) the fix publishes (the SAME short
/// label a consumer's DSN host resolves). Version behavior: on Docker 28 it passes before and after
/// the fix; on Docker 29.9.1 it FAILS before the fix (the > 63-octet alias never registers) and
/// PASSES after (the short alias registers). It deliberately does NOT assert the raw long name
/// fails to resolve — that is true only on 29.x, and the gate must stay green on the 28.x box too.
///
/// `#[ignore]` + env-gated; the capability gate greps the final marker, printed only after the
/// assertion holds.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   long_managed_db -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_resolves_long_managed_db_workload_by_short_alias() {
    use boatramp_core::compute::{DNS_LABEL_MAX_LEN, is_valid_dns_label, managed_db_alias};
    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }
    let backend = DockerBackend::connect().expect("connect to docker");

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
            redaction: Default::default(),
            priority_class: None,
        };
        backend.launch(&req).await.expect("launch")
    }

    // A RAW managed-DB-shaped server workload name OVER 63 octets (two 25-char digests), the exact
    // shape that failed to register on Docker 29.9.1.
    let h = "abcdefghijklmnopqrstuvwxy"; // 25 base-36 chars
    let db_workload = format!("bramp-db-{h}-mailroom_{h}");
    assert!(
        db_workload.len() > DNS_LABEL_MAX_LEN,
        "fixture must exceed the 63-octet DNS label cap (the bug): {} octets",
        db_workload.len()
    );
    let alias = managed_db_alias(&db_workload);
    assert!(
        is_valid_dns_label(&alias) && alias.len() <= DNS_LABEL_MAX_LEN,
        "the published alias must be a valid DNS label: {alias}"
    );

    // Launch the server under its RAW (> 63-octet) workload name + a short sibling client.
    let db = launch(&backend, "longsd", &db_workload, &server_spec("LONGOK")).await;
    let app = launch(&backend, "longsd", "app", &client_spec()).await;

    // The sibling resolves + reads the server BY ITS SHORT ALIAS (what the fix publishes AND what a
    // consumer's DSN host resolves) — NOT the > 63-octet workload name Docker 29 never registers.
    // `nc <alias> 8080` exercises resolution + TCP connect; retry to absorb the listener's startup.
    let argv = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "for i in $(seq 1 30); do R=$(nc -w3 {alias} 8080 </dev/null 2>/dev/null); \
             if [ -n \"$R\" ]; then printf '%s' \"$R\"; exit 0; fi; sleep 1; done; exit 1"
        ),
    ];
    let out = backend
        .exec(&app.handle, &argv, None)
        .await
        .expect("exec nc by short alias");
    assert_eq!(
        out.exit_code, 0,
        "app must resolve + reach the managed-DB server by its SHORT alias {alias} \
         (the > 63-octet raw name {db_workload} is what Docker 29 refuses to register)"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "LONGOK",
        "the sibling must read the server's body over the short alias"
    );

    for handle in [&app.handle, &db.handle] {
        let _ = backend.stop(handle).await;
    }
    println!(
        "DOCKER LONG MANAGED-DB SD OK: a {}-octet managed-DB workload resolved by its short alias \
         {alias} (LONGOK) over the per-project network — the > 63-octet raw name is never used for \
         resolution",
        db_workload.len()
    );
}

/// The **recreate-on-redeploy** live gate (Bug A). A redeploy that CHANGES a workload's
/// spec must REPLACE the running container (stop + remove + relaunch), NOT restart the old
/// one in place — otherwise `launch` (and, with it, the per-project-network attach) never
/// re-runs on the normal redeploy path. The reconcile DECISION (stale spec → recreate) is
/// unit-tested in `boatramp-core` (`reconcile_recreates_on_spec_hash_change`); this gate
/// proves the docker EXECUTION end-to-end against a real daemon:
///
/// 1. A server workload `svc` serving `AAA` is launched; a sibling `app` resolves it by
///    NAME over the project network and reads `AAA` (baseline — the launch attached the
///    per-project net).
/// 2. `svc` is RELAUNCHED for the SAME `(project, workload, replica)` serving `BBB` — the
///    redeploy's recreate (the reconcile emits Stop then Launch; `launch` itself also
///    force-removes the stale same-name container).
/// 3. The sibling resolves `svc` by name again and now reads `BBB`. That it reads the NEW
///    body — reachable BY NAME — proves the old container was REPLACED (a restart-in-place
///    would still serve `AAA`) AND that the relaunch re-attached the per-project network
///    (name resolution only works there). A restart-in-place fails BOTH.
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final marker,
/// printed ONLY after the assertion holds.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   recreate_on_spec_change -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_recreate_on_spec_change_replaces_container_and_reattaches_project_net() {
    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }
    let backend = DockerBackend::connect().expect("connect to docker");

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
            redaction: Default::default(),
            priority_class: None,
        };
        backend.launch(&req).await.expect("launch")
    }

    // Resolve the `svc` workload BY NAME over the project net and read back its body.
    let fetch_svc = |h: &boatramp_core::compute::InstanceHandle| {
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "for i in $(seq 1 30); do R=$(nc -w3 svc 8080 </dev/null 2>/dev/null); \
             if [ -n \"$R\" ]; then printf '%s' \"$R\"; exit 0; fi; sleep 1; done; exit 1"
                .to_string(),
        ];
        let h = h.clone();
        let backend = &backend;
        async move { backend.exec(&h, &argv, None).await.expect("exec nc svc") }
    };

    // (1) Deploy svc=AAA + a client; the client reads AAA by name.
    let svc_a = launch(&backend, "redeploy", "svc", &server_spec("AAA")).await;
    let app = launch(&backend, "redeploy", "app", &client_spec()).await;
    let out = fetch_svc(&app.handle).await;
    assert_eq!(out.exit_code, 0, "app must reach svc by name");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "AAA",
        "baseline: svc serves AAA"
    );

    // (2) REDEPLOY: relaunch svc with a changed spec (serves BBB) for the SAME identity.
    let svc_b = launch(&backend, "redeploy", "svc", &server_spec("BBB")).await;

    // (3) The client now reads BBB by name — proving the container was REPLACED (a
    //     restart-in-place would still serve AAA) and the relaunch re-attached the net.
    let out = fetch_svc(&app.handle).await;
    assert_eq!(out.exit_code, 0, "app must reach the recreated svc by name");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "BBB",
        "after a spec-change redeploy, svc must serve the NEW body BBB (the container was \
         recreated + re-attached to the project net), never the stale AAA"
    );

    // (4) RESOLUTION gate (reproduces simertec's exact failure): the recreated svc must be
    //     resolvable by BOTH its network ALIAS (the workload name `svc`, what the managed-DB
    //     DSN uses) AND its full container NAME (`boatramp-redeploy-svc-0`). A zero-I/O `nc`
    //     connect scan succeeds only when the name RESOLVES (embedded DNS) and the port is
    //     reachable — exactly what a bridge-primary (secondary-net) container could NOT do.
    //     This assertion, not endpoint metadata, is the success marker.
    let connect_by = |name: &str| {
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "for i in $(seq 1 30); do if nc -z -w3 {name} 8080; then exit 0; fi; sleep 1; done; exit 1"
            ),
        ];
        let h = app.handle.clone();
        let backend = &backend;
        async move {
            backend
                .exec(&h, &argv, None)
                .await
                .expect("exec nc resolve")
        }
    };
    let by_alias = connect_by("svc").await;
    assert_eq!(
        by_alias.exit_code, 0,
        "svc must resolve + connect by its ALIAS (workload name)"
    );
    // Default-less project "redeploy" → container name `boatramp-<project>-<workload>-<replica>`.
    let by_name = connect_by("boatramp-redeploy-svc-0").await;
    assert_eq!(
        by_name.exit_code, 0,
        "svc must resolve + connect by its FULL container name boatramp-redeploy-svc-0"
    );

    // (5) AUTO-HEAL IDEMPOTENCY (Security MEDIUM-1): a correctly new-model container — primary-
    //     attached to the project net — must NOT be flagged for redeploy. `needs_redeploy` keys on
    //     an exact `HostConfig.NetworkMode` string compare against the live daemon; if that ever
    //     mismatched for a correctly-deployed container, EVERY reconcile tick would stop+relaunch
    //     EVERY container (a self-inflicted outage/churn loop with repeated managed-DB restarts).
    //     This proves idempotency against the real daemon, not just a string unit test.
    assert!(
        !backend
            .needs_redeploy(&svc_b.handle, &server_spec("BBB"))
            .await,
        "idempotency: a freshly relaunched container on the project net must report \
         needs_redeploy=false, else reconcile would churn every tick"
    );

    for h in [&app.handle, &svc_b.handle, &svc_a.handle] {
        let _ = backend.stop(h).await;
    }
    println!(
        "DOCKER RECREATE-ON-REDEPLOY + RESOLUTION OK: svc redeployed AAA->BBB; app read the NEW \
         body and resolved svc by BOTH alias 'svc' and full name 'boatramp-redeploy-svc-0' over \
         the per-project network (container replaced + primary-attached, not restarted in place)"
    );
}

/// The **run_ephemeral default-bridge reachability** regression gate (v0.56.1).
///
/// v0.56.0 made the per-project network the PRIMARY attach for BOTH `launch()` (correct — DNS fix)
/// AND `run_ephemeral()` (WRONG). For the one-shot export/import dump/restore client that is a
/// regression: making the per-project net its `NetworkMode` DROPS the daemon default bridge, so the
/// client can no longer reach a database that lives on the DEFAULT bridge — the real CI/live
/// topology, where the export/import target is an external/BYO `postgres://` at `172.17.0.x`. That
/// shape broke all 7 project-export/import live tests (connect timeout) and is why v0.56.0 was
/// reverted.
///
/// This proves the corrected dual-attach: `run_ephemeral` keeps the DEFAULT bridge as the one-shot's
/// PRIMARY network and attaches the hinted per-project net only as a SECONDARY endpoint. We stand up
/// a TCP "database" on the DEFAULT bridge via the raw Engine API (the backend's own `launch()` always
/// binds a workload to a per-project net, so it cannot produce a default-bridge target), then run the
/// one-shot client WITH a per-project-net hint (`EPHEMERAL_NETWORK_ENV`) so it IS dual-attached —
/// reproducing the exact regression condition — and assert the client still reaches the
/// default-bridge DB (`nc -z` connect scan → exit 0). Under the reverted v0.56.0 shape the client
/// would be confined to the per-project net and the scan would TIME OUT (non-zero).
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final marker, printed
/// ONLY after the assertion holds.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   ephemeral_reaches_default_bridge -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_ephemeral_reaches_default_bridge_db_when_dual_attached() {
    use boatramp_docker::{EPHEMERAL_NETWORK_ENV, project_network_name};
    use bollard::Docker;
    use bollard::container::{
        Config as BollardConfig, CreateContainerOptions, RemoveContainerOptions,
    };
    use bollard::image::CreateImageOptions;
    use bollard::models::HostConfig;
    use futures::StreamExt;

    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }

    let docker = Docker::connect_with_local_defaults().expect("raw docker client");

    // Pull the image for the default-bridge "database" (idempotent; the backend caches it too).
    let mut pull = docker.create_image(
        Some(CreateImageOptions {
            from_image: "alpine".to_string(),
            tag: "3.20".to_string(),
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(step) = pull.next().await {
        step.expect("pull alpine:3.20 for the default-bridge DB");
    }

    // A TCP "database" on the DEFAULT bridge (NO networking_config ⇒ daemon default network).
    // `nc -lk` keeps accepting connections so the client's connect scan always finds a listener.
    let db_name = format!("boatramp-ephv2-dbridge-db-{}", std::process::id());
    let _ = docker
        .remove_container(
            &db_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    docker
        .create_container(
            Some(CreateContainerOptions {
                name: db_name.clone(),
                platform: None,
            }),
            BollardConfig {
                image: Some("alpine:3.20".to_string()),
                cmd: Some(vec![
                    "nc".into(),
                    "-lk".into(),
                    "-p".into(),
                    "5432".into(),
                    "-e".into(),
                    "sh".into(),
                    "-c".into(),
                    "printf PONG".into(),
                ]),
                host_config: Some(HostConfig {
                    auto_remove: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .expect("create default-bridge DB container");
    docker
        .start_container::<String>(&db_name, None)
        .await
        .expect("start default-bridge DB container");

    // Its DEFAULT-bridge IP — the host the export/import client must reach (mirrors the BYO
    // `postgres://172.17.0.x` CI topology).
    let info = docker
        .inspect_container(&db_name, None)
        .await
        .expect("inspect default-bridge DB");
    let db_ip = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.networks.as_ref())
        .and_then(|nets| nets.get("bridge"))
        .and_then(|ep| ep.ip_address.clone())
        .filter(|ip| !ip.is_empty())
        .expect("default-bridge IP of the DB container");

    // The one-shot export/import client, DUAL-ATTACHED: a per-project-net hint forces the secondary
    // attach (the exact regression condition), while the default bridge must stay PRIMARY so the
    // client can still reach the default-bridge DB. The per-project net does NOT contain the DB, so
    // the ONLY route to it is the default bridge — a reverted-v0.56.0 client (per-project net as
    // NetworkMode, default bridge dropped) would time out here.
    let net = project_network_name("ephv2dbridge");
    let backend = DockerBackend::connect().expect("connect to docker");
    let mut stdout = futures::io::sink();
    let exit = backend
        .run_ephemeral(
            "alpine:3.20",
            &[
                "nc".into(),
                "-z".into(),
                "-w5".into(),
                db_ip.clone(),
                "5432".into(),
            ],
            &[(EPHEMERAL_NETWORK_ENV.to_string(), net.clone())],
            None,
            &mut stdout,
        )
        .await
        .expect("run_ephemeral connect-scan");

    // Cleanup (best-effort) BEFORE the assertion so a failure still tears down the fixture.
    let _ = docker
        .remove_container(
            &db_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker.remove_network(&net).await;

    assert_eq!(
        exit, 0,
        "dual-attached run_ephemeral must still reach the DEFAULT-bridge DB at {db_ip}:5432 — a \
         non-zero (timeout) exit is the reverted-v0.56.0 regression (per-project net made PRIMARY, \
         default bridge dropped)"
    );

    // The single success marker the capability gate greps for — printed ONLY after the one-shot
    // reached the default-bridge DB while dual-attached to a per-project net.
    println!(
        "DOCKER EPHEMERAL DEFAULT-BRIDGE OK: dual-attached run_ephemeral reached the default-bridge \
         DB at {db_ip}:5432 with per-project net {net} as a SECONDARY attach (default bridge stayed \
         primary)"
    );
}

/// The **managed-DB alias UPGRADE auto-heal** live gate (Bug D, upgrade path — the fix on this
/// branch). v0.57.0's [`managed_db_alias`] publishes a short (≤ 63-octet) network alias for a long
/// managed-DB workload name, which is correct for FRESH deployments. But a managed DB created
/// BEFORE that fix kept its OLD raw (~69-octet) `--network-alias`; the v0.57.0 reconcile recreated
/// the CONSUMER (its DSN host changed → spec change) but NOT the PRODUCER PG (its spec is
/// unchanged), so the producer kept answering only its old long name while the consumer dialed the
/// new short one → NXDOMAIN. simertec hit this live on Docker 29.9.1 (recreating both by hand fixed
/// it).
///
/// The fix adds a SECOND auto-heal to [`ComputeBackend::needs_redeploy`]: a container that is
/// primary on the per-project net but whose live DNS alias
/// (`NetworkSettings.Networks.<net>.Aliases`) does NOT contain the current
/// `managed_db_alias(workload)` is reported as needing a recreate, so the producer re-launches with
/// the current short alias on upgrade with NO manual recreate.
///
/// This gate reproduces the pre-fix → post-fix UPGRADE end-to-end against a real daemon:
///
/// 1. A "pre-fix" managed-DB producer is created DIRECTLY via the Engine API, mirroring `launch`'s
///    create (primary on the per-project net, a busybox-`nc` listener) but with its endpoint
///    `--network-alias` set to the RAW LONG workload name (> 63 octets) instead of the short
///    `managed_db_alias` the current `launch` would publish — the exact pre-fix on-wire state.
/// 2. `needs_redeploy` MUST report `true` for it: it is primary on the net (so the net-mismatch heal
///    does not fire) but advertises a STALE long alias, not the current short one. BEFORE the fix
///    this returned `false` (the producer's spec is unchanged → never recreated → stays on the long
///    alias → the consumer's short-alias lookup NXDOMAINs); that `false`→`true` flip is simertec's
///    live failure, caught.
/// 3. The reconcile heal is driven (stop + `launch`), then three things are asserted: (a) the
///    recreated container's LIVE alias on the project net now CONTAINS `managed_db_alias(workload)`
///    (the short one), (b) a sibling resolves + reaches it by that short alias (`nc <short> 8080`),
///    and (c) `needs_redeploy` now returns `false` — idempotent, so the reconcile does not churn.
///
/// Version independence: the recreate TRIGGER (stale-alias detection via `inspect`) is
/// Docker-version-agnostic, so Docker 28 validates it too; the gate deliberately does NOT assert
/// the long name fails to resolve (that > 63-octet DNS-registration symptom is Docker-29-specific).
/// It asserts the TRIGGER + the re-aliasing + idempotency — the parts the fix owns.
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final marker, printed
/// ONLY after every assertion holds.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   alias_upgrade_heal -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_reconcile_heals_a_producer_carrying_a_stale_managed_db_alias_on_upgrade() {
    use std::collections::HashMap;

    use boatramp_core::compute::{
        DNS_LABEL_MAX_LEN, Instance, InstanceHandle, compute_instance_id, is_valid_dns_label,
        managed_db_alias,
    };
    use boatramp_docker::project_network_name;
    use bollard::Docker;
    use bollard::container::{
        Config as BollardConfig, CreateContainerOptions, NetworkingConfig, RemoveContainerOptions,
    };
    use bollard::image::CreateImageOptions;
    use bollard::models::{EndpointSettings, HostConfig};
    use futures::StreamExt;

    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }
    let backend = DockerBackend::connect().expect("connect to docker");
    let docker = Docker::connect_with_local_defaults().expect("raw docker client");

    async fn launch(
        backend: &DockerBackend,
        project: &str,
        workload: &str,
        spec: &ComputeSpec,
    ) -> Instance {
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
            redaction: Default::default(),
            priority_class: None,
        };
        backend.launch(&req).await.expect("launch")
    }

    let project = "aliasheal";
    let project_net = project_network_name(project);

    // A RAW managed-DB-shaped PRODUCER workload name OVER 63 octets (two 25-char digests), so its
    // current alias is the SHORT hash — distinct from the raw name. This is the shape that kept a
    // long `--network-alias` across the pre-fix era.
    let h = "abcdefghijklmnopqrstuvwxy"; // 25 base-36 chars
    let db_workload = format!("bramp-db-{h}-aliasheal_{h}");
    assert!(
        db_workload.len() > DNS_LABEL_MAX_LEN,
        "fixture must exceed the 63-octet DNS label cap: {} octets",
        db_workload.len()
    );
    let short_alias = managed_db_alias(&db_workload); // what the CURRENT launch publishes
    assert!(
        is_valid_dns_label(&short_alias) && short_alias.len() <= DNS_LABEL_MAX_LEN,
        "the current alias must be a valid DNS label: {short_alias}"
    );
    assert_ne!(
        short_alias, db_workload,
        "the short alias must differ from the raw long name (else there is nothing to heal)"
    );

    // Launch the sibling CONSUMER first — this create-if-absents the per-project network and pulls
    // the image, so the pre-fix producer we create by hand can attach to an existing network.
    let app = launch(&backend, project, "app", &client_spec()).await;

    // Belt-and-braces image pull for the raw-created producer (idempotent; `app`'s materialize
    // already pulled it).
    let mut pull = docker.create_image(
        Some(CreateImageOptions {
            from_image: "alpine".to_string(),
            tag: "3.20".to_string(),
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(step) = pull.next().await {
        step.expect("pull alpine:3.20 for the pre-fix producer");
    }

    // (1) Create the PRE-FIX producer DIRECTLY, mirroring `launch`'s create (primary on the
    //     per-project net, a busybox-`nc` listener serving HEAL on :8080) BUT with the endpoint
    //     `--network-alias` set to the RAW LONG workload name — the exact pre-fix on-wire state a
    //     v0.57.0 upgrade would leave the producer in. The container name is the SAME one `launch`
    //     derives, so the reconcile's stop + relaunch targets this very container.
    let db_name = format!("boatramp-{}", compute_instance_id(project, &db_workload, 0));
    let _ = docker
        .remove_container(
            &db_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let stale_endpoint = EndpointSettings {
        // THE PRE-FIX STATE: the long raw workload name, not the short managed_db_alias.
        aliases: Some(vec![db_workload.clone()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(CreateContainerOptions {
                name: db_name.clone(),
                platform: None,
            }),
            BollardConfig {
                image: Some("alpine:3.20".to_string()),
                cmd: Some(vec![
                    "nc".into(),
                    "-lk".into(),
                    "-p".into(),
                    "8080".into(),
                    "-e".into(),
                    "sh".into(),
                    "-c".into(),
                    "printf HEAL".into(),
                ]),
                host_config: Some(HostConfig {
                    // Primary on the per-project net, exactly like `launch`.
                    network_mode: Some(project_net.clone()),
                    ..Default::default()
                }),
                networking_config: Some(NetworkingConfig {
                    endpoints_config: HashMap::from([(project_net.clone(), stale_endpoint)]),
                }),
                ..Default::default()
            },
        )
        .await
        .expect("create pre-fix producer with a STALE long alias");
    docker
        .start_container::<String>(&db_name, None)
        .await
        .expect("start pre-fix producer");

    // The handle the deploy store would hold for this producer (backend_ref decodes to the
    // container name; the ip:port is unused by `needs_redeploy`).
    let db_handle = InstanceHandle {
        project: project.into(),
        workload: db_workload.clone(),
        replica: 0,
        backend_ref: format!("{db_name}@127.0.0.1:0"),
    };

    // (2) THE TRIGGER. The producer is primary on the per-project net (so the net-mismatch heal does
    //     NOT fire) but advertises the STALE long alias, not the current short one → recreate.
    //     MUTATION SENSE: BEFORE the fix, `needs_redeploy` had ONLY the net-mismatch check, so this
    //     was `false` (the producer's spec is unchanged → never recreated → keeps the long alias →
    //     the consumer's short-alias DSN lookup NXDOMAINs). That is simertec's live failure.
    assert!(
        backend
            .needs_redeploy(&db_handle, &server_spec("HEAL"))
            .await,
        "a producer primary on the project net but carrying a STALE long alias ({db_workload}) \
         instead of the current short alias ({short_alias}) MUST be flagged for recreate — \
         before the fix this was false and the upgrade left the producer unresolvable"
    );

    // (3) Drive the reconcile heal the same way the reconcile emits it: Stop then Launch. `launch`
    //     re-creates the producer with the CURRENT short alias.
    let _ = backend.stop(&db_handle).await;
    let db_healed = launch(&backend, project, &db_workload, &server_spec("HEAL")).await;

    // (3a) The recreated producer's LIVE alias on the project net now CONTAINS the short alias
    //      (Docker also lists the short container id among the aliases, so assert containment).
    let info = docker
        .inspect_container(&db_name, None)
        .await
        .expect("inspect healed producer");
    let live_aliases: Vec<String> = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.networks.as_ref())
        .and_then(|nets| nets.get(&project_net))
        .and_then(|ep| ep.aliases.clone())
        .unwrap_or_default();
    assert!(
        live_aliases.iter().any(|a| a == &short_alias),
        "the healed producer must advertise the CURRENT short alias {short_alias} on {project_net}; \
         live aliases were {live_aliases:?}"
    );
    assert!(
        !live_aliases.iter().any(|a| a == &db_workload),
        "the healed producer must no longer advertise the stale long alias {db_workload}; \
         live aliases were {live_aliases:?}"
    );

    // (3b) The sibling resolves + reaches the healed producer BY ITS SHORT ALIAS (the same label a
    //      consumer's DSN host resolves). `nc <short> 8080` exercises resolution + TCP connect;
    //      retry to absorb the listener's startup.
    let argv = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "for i in $(seq 1 30); do R=$(nc -w3 {short_alias} 8080 </dev/null 2>/dev/null); \
             if [ -n \"$R\" ]; then printf '%s' \"$R\"; exit 0; fi; sleep 1; done; exit 1"
        ),
    ];
    let out = backend
        .exec(&app.handle, &argv, None)
        .await
        .expect("exec nc by short alias");
    assert_eq!(
        out.exit_code, 0,
        "app must resolve + reach the healed producer by its short alias {short_alias}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "HEAL",
        "the sibling must read the producer's body (HEAL) over the short alias"
    );

    // (3c) IDEMPOTENCY: the healed producer is now current (primary on the net AND advertising the
    //      current short alias), so `needs_redeploy` must report `false` — no churn loop.
    assert!(
        !backend
            .needs_redeploy(&db_healed.handle, &server_spec("HEAL"))
            .await,
        "a healed producer carrying the current short alias must report needs_redeploy=false, \
         else the reconcile would recreate it every tick"
    );

    for handle in [&app.handle, &db_healed.handle] {
        let _ = backend.stop(handle).await;
    }
    // Best-effort GC of the per-project net in case a prior assertion left a workload attached.
    let _ = docker.remove_network(&project_net).await;

    // The single success marker the capability gate greps for — printed ONLY after the stale-alias
    // producer was flagged, recreated with the current short alias, reached by a sibling over it,
    // and reported idempotent.
    println!(
        "DOCKER MANAGED-DB ALIAS UPGRADE HEAL OK: a {}-octet producer carrying the stale long \
         alias was flagged for recreate, relaunched with the short alias {short_alias}, reached by \
         a sibling (HEAL) over that alias, and then reported needs_redeploy=false (idempotent)",
        db_workload.len()
    );
}

/// The **legacy-unscoped-bridge UPGRADE** live gate (the reap-race defect fixed on this branch —
/// tokenfield's blocked prod managed-Postgres adopter).
///
/// A per-project docker network created BEFORE the scoped-bridge driver-opt existed carries docker's
/// unscoped `br-<hash>` bridge. The NixOS compute-firewall admits only the scoped `boatramp-` bridge,
/// so that network's shim traffic is dropped forever: the bridge name is fixed for a network's life,
/// `create_bridge_network` treats the already-existing network as success (409) without changing it,
/// and the best-effort `remove_network` in `stop()` raced the reconcile relaunch and could never
/// win — so `compute restart` never migrated it. The fix makes `ensure_project_network` detect a
/// stale bridge at launch and, when the network is EMPTY (the instant a plain `compute restart`
/// produces between the old container's removal and the new one's attach), remove + recreate it on
/// the scoped bridge, while NEVER tearing down a network that still has a live attached container.
///
/// This reproduces BOTH halves against a REAL daemon:
///
///   A. UPGRADE. A per-project network is pre-created DIRECTLY with NO bridge-name opt (docker's
///      unscoped `br-<hash>`, the exact pre-fix on-wire state). A workload is then launched into
///      that project; the FIRST launch finds the network empty, so `ensure_project_network` removes
///      + recreates it on the scoped `project_bridge_name` bridge and attaches. We assert the
///      network now reports the scoped bridge opt, still carries the per-project isolation labels
///      (`boatramp.managed` + `boatramp.project` — the SAME isolated network, only the bridge name
///      changed), the launched workload is attached, and a sibling reaches it over the upgraded net
///      (the data plane works) — the migration a plain `compute restart` now performs automatically.
///
///   B. LIVE GUARD. A second per-project network is pre-created unscoped AND a live `nc` server is
///      attached to it directly. A workload is then launched into that project; because the network
///      has a live endpoint, `ensure_project_network` leaves it UNTOUCHED. We assert the network is
///      STILL on the unscoped bridge (never rebuilt), the pre-existing live server is STILL running
///      (its endpoint never severed), and the newly launched sibling still reaches it by name — a
///      live per-project network is never torn down. (The emptiness guard is the first gate; docker
///      refusing to remove a network with active endpoints is the backstop — both hold here.)
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final marker, printed
/// ONLY after every assertion holds — it cannot be earned without the real end-to-end pass. The
/// firewall-admission half (the scoped bridge is what the NixOS rule admits) is covered live by
/// `scripts/compute-net-turnkey-gate.sh` on a real NixOS host.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   stale_unscoped_bridge -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_stale_unscoped_bridge_is_upgraded_on_relaunch_and_a_live_network_is_never_torn_down()
 {
    use std::collections::HashMap;

    use boatramp_docker::{project_bridge_name, project_network_name};
    use bollard::Docker;
    use bollard::container::{
        Config as BollardConfig, CreateContainerOptions, NetworkingConfig, RemoveContainerOptions,
    };
    use bollard::image::CreateImageOptions;
    use bollard::models::{EndpointSettings, HostConfig};
    use bollard::network::{CreateNetworkOptions, InspectNetworkOptions};
    use futures::StreamExt;

    // The docker driver-opt key that pins (and reports) a user-defined bridge's interface name.
    // Absent in a network's `Options` ⇒ docker auto-generated an unscoped `br-<hash>`.
    const BRIDGE_NAME_OPT: &str = "com.docker.network.bridge.name";

    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }
    let backend = DockerBackend::connect().expect("connect to docker");
    let docker = Docker::connect_with_local_defaults().expect("raw docker client");

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
            redaction: Default::default(),
            priority_class: None,
        };
        backend.launch(&req).await.expect("launch")
    }

    // The bridge the daemon actually reports for a network (the pinned opt), or None for a legacy
    // auto-generated `br-<hash>`.
    async fn bridge_opt(docker: &Docker, net: &str) -> Option<String> {
        docker
            .inspect_network(net, None::<InspectNetworkOptions<String>>)
            .await
            .expect("inspect network")
            .options
            .and_then(|o| o.get(BRIDGE_NAME_OPT).cloned())
    }

    // Pre-create a per-project network DIRECTLY on docker's UNSCOPED bridge (NO bridge-name opt) with
    // the per-project isolation labels — the exact shape a pre-fix boatramp left behind.
    async fn precreate_unscoped(docker: &Docker, project: &str) -> String {
        let net = project_network_name(project);
        let _ = docker.remove_network(&net).await;
        docker
            .create_network(CreateNetworkOptions {
                name: net.clone(),
                driver: "bridge".to_string(),
                labels: HashMap::from([
                    ("boatramp.managed".to_string(), "true".to_string()),
                    ("boatramp.project".to_string(), project.to_string()),
                ]),
                // NO `options` ⇒ docker assigns an unscoped `br-<hash>` — the pre-fix state.
                ..Default::default()
            })
            .await
            .expect("pre-create unscoped per-project network");
        net
    }

    // Pull the test-double once (the backend caches it too; belt-and-braces for the raw-created
    // live server in part B).
    let mut pull = docker.create_image(
        Some(CreateImageOptions {
            from_image: "alpine".to_string(),
            tag: "3.20".to_string(),
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(step) = pull.next().await {
        step.expect("pull alpine:3.20");
    }

    // ===================================================================================
    // PART A — the UPGRADE: an EMPTY legacy-unscoped network is migrated to the scoped bridge.
    // ===================================================================================
    let proj_a = "stalebridge";
    let net_a = precreate_unscoped(&docker, proj_a).await;

    // Precondition: the pre-created network is on docker's UNSCOPED bridge (no pinned opt) — i.e.
    // the reap-race defect's exact starting state. If this were already scoped there would be
    // nothing to upgrade and the gate would be vacuous.
    let expected_a = project_bridge_name(&net_a);
    assert_ne!(
        bridge_opt(&docker, &net_a).await,
        Some(expected_a.clone()),
        "fixture precondition: {net_a} must start on an UNSCOPED bridge (not the scoped {expected_a})"
    );

    // Launch the FIRST workload into the project. The network is empty at this instant, so
    // `ensure_project_network` removes + recreates it on the scoped bridge, then attaches.
    let a_db = launch(&backend, proj_a, "db", &server_spec("UP")).await;

    // (A1) The network is now on the SCOPED bridge — the migration happened automatically.
    assert_eq!(
        bridge_opt(&docker, &net_a).await,
        Some(expected_a.clone()),
        "after a relaunch the empty legacy network must be recreated on the scoped bridge {expected_a}"
    );

    // (A2) The per-project isolation labels survived the recreate — the SAME isolated network, only
    // the bridge name changed (a different-tenancy or unlabeled network would be a leak).
    let net_a_info = docker
        .inspect_network(&net_a, None::<InspectNetworkOptions<String>>)
        .await
        .expect("inspect upgraded net");
    let labels_a = net_a_info.labels.unwrap_or_default();
    assert_eq!(
        labels_a.get("boatramp.managed").map(String::as_str),
        Some("true"),
        "the upgraded network must keep boatramp.managed=true"
    );
    assert_eq!(
        labels_a.get("boatramp.project").map(String::as_str),
        Some(proj_a),
        "the upgraded network must keep its owning-project label"
    );

    // (A3) The launched workload is attached to the upgraded (scoped) network.
    let a_db_name = decode_name(&a_db.handle);
    let attached = docker
        .inspect_container(&a_db_name, None)
        .await
        .expect("inspect launched db")
        .network_settings
        .and_then(|ns| ns.networks)
        .map(|nets| nets.contains_key(&net_a))
        .unwrap_or(false);
    assert!(
        attached,
        "the launched workload must be attached to the upgraded network {net_a}"
    );

    // (A4) The upgraded network carries data-plane traffic: a sibling launched into the project
    // resolves + reaches the server by name over the scoped bridge (proves the migration did not
    // break reachability — the whole point of the firewall-admitted scoped bridge).
    let a_app = launch(&backend, proj_a, "app", &client_spec()).await;
    let reach = vec![
        "sh".to_string(),
        "-c".to_string(),
        "for i in $(seq 1 30); do R=$(nc -w3 db 8080 </dev/null 2>/dev/null); \
         if [ -n \"$R\" ]; then printf '%s' \"$R\"; exit 0; fi; sleep 1; done; exit 1"
            .to_string(),
    ];
    let out = backend
        .exec(&a_app.handle, &reach, None)
        .await
        .expect("exec reach db by name");
    assert_eq!(
        out.exit_code, 0,
        "app must resolve + reach db over the upgraded scoped network {net_a}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "UP",
        "the sibling must read the server's body over the upgraded network"
    );

    // ===================================================================================
    // PART B — the LIVE GUARD: a legacy-unscoped network with a LIVE attached container is never
    // torn down; it is left on its unscoped bridge until a workload cycle empties it.
    // ===================================================================================
    let proj_b = "stalebridgelive";
    let net_b = precreate_unscoped(&docker, proj_b).await;
    let expected_b = project_bridge_name(&net_b);

    // A LIVE `nc` server attached DIRECTLY to the unscoped network (primary, alias `liveserver`),
    // serving ALIVE — the pre-existing live endpoint the guard must protect.
    let live_name = format!("boatramp-stalebridge-liveserver-{}", std::process::id());
    let _ = docker
        .remove_container(
            &live_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    docker
        .create_container(
            Some(CreateContainerOptions {
                name: live_name.clone(),
                platform: None,
            }),
            BollardConfig {
                image: Some("alpine:3.20".to_string()),
                cmd: Some(vec![
                    "nc".into(),
                    "-lk".into(),
                    "-p".into(),
                    "8080".into(),
                    "-e".into(),
                    "sh".into(),
                    "-c".into(),
                    "printf ALIVE".into(),
                ]),
                host_config: Some(HostConfig {
                    network_mode: Some(net_b.clone()),
                    ..Default::default()
                }),
                networking_config: Some(NetworkingConfig {
                    endpoints_config: HashMap::from([(
                        net_b.clone(),
                        EndpointSettings {
                            aliases: Some(vec!["liveserver".to_string()]),
                            ..Default::default()
                        },
                    )]),
                }),
                ..Default::default()
            },
        )
        .await
        .expect("create the live server on the unscoped network");
    docker
        .start_container::<String>(&live_name, None)
        .await
        .expect("start the live server");

    // Launch a workload into this project. The network has a live endpoint, so the upgrade must be
    // SKIPPED and the network left intact.
    let b_probe = launch(&backend, proj_b, "probe", &client_spec()).await;

    // (B1) The network is STILL on the UNSCOPED bridge — it was NOT recreated (a live network must
    // never be torn down). This is the guard: an occupied legacy network is left as-is.
    assert_ne!(
        bridge_opt(&docker, &net_b).await,
        Some(expected_b.clone()),
        "a legacy network with a LIVE attached container must be left on its unscoped bridge, \
         never recreated on the scoped {expected_b} (that would sever the live endpoint)"
    );

    // (B2) The pre-existing live server is STILL running — its endpoint was never severed.
    let live_running = docker
        .inspect_container(&live_name, None)
        .await
        .expect("inspect live server")
        .state
        .and_then(|s| s.running)
        .unwrap_or(false);
    assert!(
        live_running,
        "the pre-existing live server must still be running — the guard must not have torn down \
         its network"
    );

    // (B3) The newly launched sibling still reaches the live server by name over the intact
    // (unscoped) network — it kept serving throughout.
    let reach_live = vec![
        "sh".to_string(),
        "-c".to_string(),
        "for i in $(seq 1 30); do R=$(nc -w3 liveserver 8080 </dev/null 2>/dev/null); \
         if [ -n \"$R\" ]; then printf '%s' \"$R\"; exit 0; fi; sleep 1; done; exit 1"
            .to_string(),
    ];
    let out_live = backend
        .exec(&b_probe.handle, &reach_live, None)
        .await
        .expect("exec reach live server by name");
    assert_eq!(
        out_live.exit_code, 0,
        "the launched probe must reach the pre-existing live server over the intact network"
    );
    assert_eq!(
        String::from_utf8_lossy(&out_live.stdout).trim(),
        "ALIVE",
        "the live server must keep serving its body through the untouched network"
    );

    // Cleanup (best-effort): stop the launched workloads (which GCs each empty project net on the
    // last stop), force-remove the raw live server, and drop any residual networks.
    for h in [&a_app.handle, &a_db.handle, &b_probe.handle] {
        let _ = backend.stop(h).await;
    }
    let _ = docker
        .remove_container(
            &live_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker.remove_network(&net_a).await;
    let _ = docker.remove_network(&net_b).await;

    // The single success marker the capability gate greps for — printed ONLY after BOTH the upgrade
    // (an empty legacy network migrated to the scoped bridge, labels preserved, workload attached +
    // reachable) AND the live guard (an occupied legacy network left untouched, its live endpoint
    // intact and still serving) held end-to-end.
    println!(
        "DOCKER STALE-BRIDGE UPGRADE OK: empty legacy net {net_a} migrated to scoped bridge \
         {expected_a} (labels kept, db reachable as UP); occupied legacy net {net_b} left on its \
         unscoped bridge with its live server still serving ALIVE (never torn down)"
    );
}

/// Decode an `InstanceHandle`'s backend-ref to the docker container name (`<name>@<ip>:<port>`), for
/// the raw-API inspects the stale-bridge gate makes against the backend-launched containers.
fn decode_name(handle: &boatramp_core::compute::InstanceHandle) -> String {
    handle
        .backend_ref
        .split_once('@')
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| handle.backend_ref.clone())
}

/// A `MakeWriter` over a shared buffer so the forwarder's `tracing` output can be
/// asserted in the live gate (the forwarder runs on background runtime threads, so a
/// GLOBAL subscriber is needed to capture across threads).
#[derive(Clone)]
struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CaptureWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Install ONCE a process-global fmt subscriber over a SHARED buffer and return it, so
/// several tracing-capturing live gates (guest-log forwarding + secret redaction) coexist
/// in one shared `--ignored` run: `set_global_default` can only win once, so the two tests
/// must share the subscriber rather than each racing to install its own (the loser would
/// capture nothing and its tracing assertion would spuriously fail). Each test asserts on
/// its OWN unique markers / secret, so the shared buffer stays unambiguous. (Mirrors the
/// `OnceLock` capture the boatramp-guestlog unit tests use.)
static TRACING_CAPTURE: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<u8>>>> =
    std::sync::OnceLock::new();
fn install_tracing_capture() -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
    TRACING_CAPTURE
        .get_or_init(|| {
            let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let w = buf.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(move || CaptureWriter(w.clone()))
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            buf
        })
        .clone()
}

/// The **guest-log forwarding** live gate (v0.64.0 observability parity). Proves,
/// against a REAL Docker daemon, that a long-running container launched on the docker
/// backend has its stdout AND stderr forwarded into boatramp observability through the
/// SAME shared sink the native container backend uses:
///
/// 1. the lines appear in the per-container log file
///    `<data_dir>/compute/logs/<instance-id>.log`, each framed `<stream>: <line>` so
///    stdout and stderr are distinguishable; AND
/// 2. the same lines are mirrored to structured `tracing` on the `boatramp::guest`
///    target, tagged with the container id + stream.
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final
/// success marker, printed ONLY after both the file AND the tracing assertions hold —
/// it cannot be earned by a silent skip or a one-sided forward.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   docker_log_forwarding -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_log_forwarding_to_the_shared_sink() {
    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping docker test: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }

    // Capture `boatramp::guest` tracing into a SHARED in-memory buffer via the one
    // process-global subscriber (the forwarder emits from background threads). Shared so
    // this gate and the redaction gate coexist in the broad `--ignored` run; assertions
    // use UNIQUE markers below.
    let buf = install_tracing_capture();

    let data_dir = tempfile::tempdir().expect("temp data_dir");
    let backend = DockerBackend::connect()
        .expect("connect to docker")
        .with_data_dir(data_dir.path());

    let marker_out = "BRAMP_STDOUT_9f3c1";
    let marker_err = "BRAMP_STDERR_7a2d8";
    let mut spec = spec();
    // Emit a known line to stdout AND stderr, then stay alive so the forwarder follows
    // a long-running workload (not a one-shot).
    spec.entrypoint = vec![
        "sh".into(),
        "-c".into(),
        format!("echo {marker_out}; echo {marker_err} 1>&2; sleep 30"),
    ];

    let artifact = backend
        .materialize("default", "logfwd", &spec, None)
        .await
        .expect("materialize (pull)");
    let req = LaunchRequest {
        project: "default".into(),
        workload: "logfwd".into(),
        replica: 0,
        spec: spec.clone(),
        artifact,
        redaction: Default::default(),
        priority_class: None,
    };
    let instance = backend.launch(&req).await.expect("launch");

    // The forwarder is a detached background task; give it a moment to attach, replay
    // the container's startup output, and flush it to the file.
    let id = compute_instance_id("default", "logfwd", 0);
    let path = data_dir
        .path()
        .join("compute")
        .join("logs")
        .join(format!("{id}.log"));
    let mut file_contents = String::new();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Ok(s) = std::fs::read_to_string(&path)
            && s.contains(marker_out)
            && s.contains(marker_err)
        {
            file_contents = s;
            break;
        }
    }

    backend.stop(&instance.handle).await.expect("stop");

    // (1) Both streams reached the per-container log file, each framed by its stream.
    assert!(
        file_contents.contains(&format!("stdout: {marker_out}")),
        "stdout line not forwarded to {}: {:?}",
        path.display(),
        file_contents
    );
    assert!(
        file_contents.contains(&format!("stderr: {marker_err}")),
        "stderr line not forwarded to {}: {:?}",
        path.display(),
        file_contents
    );

    // (2) The same lines were mirrored to structured tracing on `boatramp::guest`,
    // tagged with the container id + stream.
    let logged = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(
        logged.contains(marker_out) && logged.contains(marker_err),
        "lines not mirrored to tracing: {logged}"
    );
    assert!(
        logged.contains("boatramp::guest"),
        "guest target missing: {logged}"
    );
    assert!(logged.contains(&id), "container id tag missing: {logged}");
    assert!(
        logged.contains("stdout") && logged.contains("stderr"),
        "stream tags missing: {logged}"
    );

    // The single success marker the capability gate greps for — printed ONLY after
    // both the file AND the tracing assertions held.
    println!(
        "DOCKER GUEST-LOG FORWARDING OK: a long-running docker-backend container's stdout \
         ({marker_out}) + stderr ({marker_err}) were forwarded into {} AND mirrored to the \
         boatramp::guest tracing target tagged container={id}",
        path.display()
    );
}

/// The **guest-log secret redaction** live gate (PLAN-guest-log-secret-redaction). Proves,
/// against a REAL Docker daemon, that when a workload's launch carries a secret-sourced
/// redaction set, a container that prints that value has it REDACTED out of BOTH shared
/// sinks — the per-container file `<data_dir>/compute/logs/<id>.log` AND the
/// `boatramp::guest` tracing target — while a hardcoded LITERAL value (not in the set)
/// passes through untouched (provenance scoping, end-to-end). Reproduce-first +
/// mutation-sensitive: with the redactor removed (or the admin opt-out), the secret would
/// appear in both and the `!contains(secret)` assertions go RED.
///
/// `#[ignore]` + env-gated (needs a daemon); the capability gate greps the final success
/// marker, printed ONLY after the file AND tracing redaction assertions AND the
/// literal-survives assertion all hold — a silent skip or a one-sided redact cannot earn
/// it.
///
/// Run it:
/// ```sh
/// BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-docker --test docker_live \
///   docker_log_redaction -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a reachable Docker daemon; set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_log_redaction_to_the_shared_sink() {
    if std::env::var("BOATRAMP_TEST_DOCKER").is_err() {
        eprintln!("skipping docker test: set BOATRAMP_TEST_DOCKER=1 (needs a reachable daemon)");
        return;
    }

    // Shared global tracing capture (unique secret/markers keep this gate's assertions
    // unambiguous even when it shares the buffer with the forwarding gate).
    let buf = install_tracing_capture();

    let data_dir = tempfile::tempdir().expect("temp data_dir");
    // Redaction ON by default (no `.with_guest_log_redaction(false)`).
    let backend = DockerBackend::connect()
        .expect("connect to docker")
        .with_data_dir(data_dir.path());

    // A secret-shaped value (what a `{{sql.*}}` DSN looks like) carried in the launch's
    // redaction set, plus a hardcoded literal that is NOT in the set. The container prints
    // BOTH to stdout (as an `echo $DATABASE_URL`-style leak would), then stays alive.
    let secret = "postgres://app:S3cr3tP%40ss_LIVE_7b2e9@bramp-db-live.flycast:5432/appdb";
    let literal = "LOG_LEVEL_IS_debug_a_literal_value";
    let mut spec = spec();
    spec.entrypoint = vec![
        "sh".into(),
        "-c".into(),
        format!("echo SECRET={secret}; echo LITERAL={literal}; sleep 30"),
    ];

    let artifact = backend
        .materialize("default", "logredact", &spec, None)
        .await
        .expect("materialize (pull)");
    // Populate the per-launch redaction set with the secret-sourced value (the reconcile's
    // `launch_one` does this from the resolved binding/managed-DB env in production).
    let mut redaction = boatramp_core::compute::RedactionSet::new();
    redaction.push(secret.to_string());
    let req = LaunchRequest {
        project: "default".into(),
        workload: "logredact".into(),
        replica: 0,
        spec: spec.clone(),
        artifact,
        redaction,
        priority_class: None,
    };
    let instance = backend.launch(&req).await.expect("launch");

    let id = compute_instance_id("default", "logredact", 0);
    let path = data_dir
        .path()
        .join("compute")
        .join("logs")
        .join(format!("{id}.log"));
    // Wait until BOTH lines have been forwarded (the literal is the later line, so seeing
    // it means the secret line was already processed too).
    let mut file_contents = String::new();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Ok(s) = std::fs::read_to_string(&path)
            && s.contains(literal)
        {
            file_contents = s;
            break;
        }
    }

    backend.stop(&instance.handle).await.expect("stop");

    // (1) FILE: the secret is gone + replaced by the placeholder; the literal survives.
    assert!(
        !file_contents.contains(secret),
        "secret leaked into the log file {}: {file_contents:?}",
        path.display()
    );
    assert!(
        file_contents.contains(boatramp_guestlog::REDACTED_PLACEHOLDER),
        "placeholder missing from the log file: {file_contents:?}"
    );
    assert!(
        file_contents.contains(literal),
        "a hardcoded literal (not secret-sourced) must NOT be redacted: {file_contents:?}"
    );

    // (2) TRACING: the same redaction holds in the `boatramp::guest` stream.
    let logged = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(
        !logged.contains(secret),
        "secret leaked into the tracing stream: {logged}"
    );
    assert!(
        logged.contains(boatramp_guestlog::REDACTED_PLACEHOLDER),
        "placeholder missing from the tracing stream: {logged}"
    );

    // The single success marker the capability gate greps for — printed ONLY after the
    // file + tracing redaction AND the literal-survives assertions all held.
    println!(
        "DOCKER GUEST-LOG REDACTION OK: a container's printed secret-sourced value was \
         redacted to the placeholder in {} AND in the boatramp::guest tracing target \
         (container={id}), while the hardcoded literal survived (provenance scoping)",
        path.display()
    );
}
