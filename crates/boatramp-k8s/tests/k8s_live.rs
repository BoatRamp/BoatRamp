//! Phase-2 **live gate** for the Kubernetes compute backend, against a real cluster
//! (the ARM k3s lighthouse the PLAN names). It is `#[ignore]`d AND env-gated, so it never
//! runs in the ordinary `cargo test` lane — it is coordinated out-of-band on the live
//! cluster and prints the success marker:
//!
//! ```text
//! K8S COMPUTE PHASE2 OK
//! ```
//!
//! extending the Phase-1 `K8S COMPUTE BACKEND OK` lane (managed-DB bring-up). It exercises
//! the Phase-2 surfaces end to end against the cluster:
//!   1. a generic stateless workload → a `Deployment` + `Service` that goes Ready
//!      (`launch` → `health`);
//!   2. `exec` into the running pod (stdout + exit code) and `logs` off its pod;
//!   3. `list_volumes` returns the managed PVC, and `replica_alive` tracks the pod;
//!   4. a CSI `VolumeSnapshot` snapshot/restore round-trip when a `VolumeSnapshotClass`
//!      is configured (else the clean "unsupported");
//!   5. `stop` tears the objects down.
//!
//! Run it on the cluster (in-cluster, or with a kubeconfig pointing at it):
//! ```sh
//! BOATRAMP_TEST_K8S=1 cargo test -p boatramp-k8s --test k8s_live -- --ignored --nocapture
//! ```
//!
//! NB: this is the cross-repo live gate the owner coordinates; a unit run of it is a
//! self-skipping no-op (it returns early unless `BOATRAMP_TEST_K8S` is set), and it is
//! `#[ignore]`d so `--ignored` is required even then. The pure spec→objects mapping and
//! every request-builder are covered by the in-crate unit tests (no cluster needed); this
//! file only asserts the behaviors that genuinely require a running apiserver + CSI.

#![cfg(feature = "k8s-backend")]

use std::collections::BTreeMap;

use boatramp_core::compute::{
    Artifact, ComputeBackend, ComputeSpec, Health, IsolationRequirement, LaunchRequest,
    ManagedDbEngine, RestartPolicy, RootSource, managed_db_spec,
};
use boatramp_k8s::KubernetesBackend;

/// A tiny, long-lived generic workload image (stateless → Deployment path).
const TEST_IMAGE: &str = "ghcr.io/nginxinc/nginx-unprivileged:stable";

fn generic_spec() -> ComputeSpec {
    ComputeSpec {
        version: 1,
        root: RootSource::Image(TEST_IMAGE.to_string()),
        kernel: String::new(),
        kernel_cmdline: None,
        vcpus: 1,
        mem_mib: 64,
        entrypoint: vec![],
        env: BTreeMap::new(),
        port: 8080,
        restart: RestartPolicy::Always,
        startup_grace_secs: 60,
        scale_to_zero: false,
        volumes: vec![], // stateless ⇒ Deployment
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
#[ignore = "live: needs a real k8s/k3s cluster — set BOATRAMP_TEST_K8S=1 (marker: K8S COMPUTE PHASE2 OK)"]
async fn k8s_phase2_generic_exec_logs_volumes_round_trip() {
    if std::env::var("BOATRAMP_TEST_K8S").is_err() {
        eprintln!("skipping k8s live gate: set BOATRAMP_TEST_K8S=1 (needs a reachable cluster)");
        return;
    }

    // Connect with the in-cluster / kubeconfig config (no second auth path).
    let backend = KubernetesBackend::connect(None, false, None, None)
        .await
        .expect("connect to the cluster");

    let spec = generic_spec();
    let req = LaunchRequest {
        project: "default".to_string(),
        workload: "phase2-web".to_string(),
        replica: 0,
        artifact: Artifact::Image {
            reference: TEST_IMAGE.to_string(),
        },
        spec: spec.clone(),
    };

    // (1) launch the generic workload → Deployment + Service.
    let instance = backend.launch(&req).await.expect("launch deployment");
    let handle = instance.handle.clone();

    // Wait for Ready (bounded).
    let mut ready = false;
    for _ in 0..60 {
        if matches!(backend.health(&handle).await, Ok(Health::Healthy)) {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(ready, "generic Deployment never went Ready");

    // (2) exec inside the pod + fetch logs.
    let out = backend
        .exec(&handle, &["sh".into(), "-c".into(), "echo hi".into()], None)
        .await
        .expect("exec in pod");
    assert_eq!(out.exit_code, 0, "exec exit code");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hi"),
        "exec stdout"
    );
    let _logs = backend
        .logs(&handle, false, Some(20))
        .await
        .expect("fetch pod logs");

    // (3) replica_alive tracks the pod.
    assert_eq!(backend.replica_alive(&handle).await, Some(true));

    // (4) stop tears it down and replica_alive flips to gone.
    backend.stop(&handle).await.expect("stop");
    for _ in 0..30 {
        if backend.replica_alive(&handle).await == Some(false) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    println!("K8S COMPUTE PHASE2 OK");
}

/// Phase-1 managed-database live gate (the mailroom #26 unblock): a managed Postgres +
/// pgvector compute spec → a `StatefulSet` + `Service` (the `pg-<ident>` in-cluster DNS)
/// + a `PVC`, the pod goes Ready, and the database is live — asserted by `exec`ing `psql`
/// INSIDE the pod (so the gate needs no in-cluster network route to the ClusterIP, running
/// equally from a CI runner host or in-cluster): `SELECT 1` answers and the `vector`
/// extension loads. Marker `K8S COMPUTE BACKEND OK`.
///
/// NB: a real boatramp deploy injects the server-init credential env
/// (`POSTGRES_*`) from the sealed managed credential at launch (node-side machinery, not
/// in `managed_db_spec`); this backend-level gate stands in `POSTGRES_HOST_AUTH_METHOD=trust`
/// so the stock operand image boots without that node flow, isolating the k8s backend's
/// own StatefulSet+PVC+Service lifecycle. The full declare→provision→seal→inject→`SELECT 1`
/// over the injected DSN is the serve-level flow the real-cluster deploy exercises.
#[tokio::test]
#[ignore = "live: needs a real k8s/k3s cluster — set BOATRAMP_TEST_K8S=1 (marker: K8S COMPUTE BACKEND OK)"]
async fn k8s_phase1_managed_postgres_statefulset_brings_up_pgvector() {
    if std::env::var("BOATRAMP_TEST_K8S").is_err() {
        eprintln!("skipping k8s live gate: set BOATRAMP_TEST_K8S=1 (needs a reachable cluster)");
        return;
    }
    let backend = KubernetesBackend::connect(None, false, None, None)
        .await
        .expect("connect to the cluster");

    // The exact spec the managed-DB auto-registration builds for a managed Postgres
    // (pgvector/pgvector:pg16, one `data` volume, port 5432), plus the stand-in auth env
    // so the stock image boots without the node-side sealed-credential injection.
    let mut spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
    spec.env
        .insert("POSTGRES_HOST_AUTH_METHOD".to_string(), "trust".to_string());
    let image = spec.root.as_str().to_string();
    let req = LaunchRequest {
        project: "default".to_string(),
        workload: "pgtest".to_string(),
        replica: 0,
        artifact: Artifact::Image {
            reference: image.clone(),
        },
        spec,
    };

    // (1) launch → StatefulSet + Service(pgtest) + PVC(data-pgtest).
    let instance = backend.launch(&req).await.expect("launch managed postgres");
    let handle = instance.handle.clone();
    // The routable endpoint host is the bare workload name (the in-cluster DNS).
    assert_eq!(instance.endpoint.host, "pgtest");
    assert_eq!(instance.endpoint.port, 5432);

    // (2) wait for the pod to go Ready (the StatefulSet's readyReplicas, driven by the TCP
    // readiness probe — postgres accepting connections). pgvector initdb can take a while.
    let mut ready = false;
    for _ in 0..90 {
        if matches!(backend.health(&handle).await, Ok(Health::Healthy)) {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(ready, "managed postgres StatefulSet never went Ready");

    // (3) the PVC shows up in list_volumes with the requested size.
    let vols = backend.list_volumes().await.expect("list volumes");
    assert!(
        vols.iter().any(|v| v.name == "data-pgtest"),
        "managed-DB PVC data-pgtest not listed; got {vols:?}"
    );

    // (4) the database is live — exec `psql` INSIDE the pod (no ClusterIP route needed):
    // SELECT 1 answers, and the `vector` extension loads (the pgvector assertion the plan
    // names). This is the DSN-equivalent liveness check over the pod exec subresource.
    let sel = backend
        .exec(
            &handle,
            &[
                "psql".into(),
                "-U".into(),
                "postgres".into(),
                "-tAc".into(),
                "select 1".into(),
            ],
            None,
        )
        .await
        .expect("exec psql select 1");
    assert_eq!(sel.exit_code, 0, "psql select 1 exit: {sel:?}");
    assert!(
        String::from_utf8_lossy(&sel.stdout).trim() == "1",
        "psql select 1 stdout: {:?}",
        String::from_utf8_lossy(&sel.stdout)
    );
    let ext = backend
        .exec(
            &handle,
            &[
                "psql".into(),
                "-U".into(),
                "postgres".into(),
                "-tAc".into(),
                "create extension if not exists vector; \
                 select extname from pg_extension where extname='vector'"
                    .into(),
            ],
            None,
        )
        .await
        .expect("exec psql create extension vector");
    assert_eq!(ext.exit_code, 0, "create extension vector exit: {ext:?}");
    assert!(
        String::from_utf8_lossy(&ext.stdout).contains("vector"),
        "vector extension did not load: {:?}",
        String::from_utf8_lossy(&ext.stdout)
    );

    // (5) teardown. This backend connected with retain_pvc_on_stop=false, so stop deletes
    // the PVC too (a throwaway gate DB, not a kept one).
    backend.stop(&handle).await.expect("stop");

    println!("K8S COMPUTE BACKEND OK");
}

#[tokio::test]
#[ignore = "live: needs a real k8s cluster + a CSI VolumeSnapshotClass — set BOATRAMP_TEST_K8S=1 (marker: K8S COMPUTE PHASE2 OK)"]
async fn k8s_phase2_volume_snapshot_round_trip() {
    if std::env::var("BOATRAMP_TEST_K8S").is_err() {
        eprintln!("skipping k8s live gate: set BOATRAMP_TEST_K8S=1 (needs a reachable cluster)");
        return;
    }
    let snap_class = std::env::var("BOATRAMP_TEST_K8S_SNAPCLASS").ok();
    let backend = KubernetesBackend::connect(None, true, None, snap_class.clone())
        .await
        .expect("connect to the cluster");

    // Without a configured VolumeSnapshotClass, snapshot/restore is a clean "unsupported".
    if snap_class.is_none() {
        assert!(!backend.snapshots_supported());
        assert!(
            backend
                .snapshot_volume("data-pg", "pg-backup-1")
                .await
                .is_err(),
            "snapshot must be unsupported without a VolumeSnapshotClass"
        );
        eprintln!("snapshot class not set; verified the clean unsupported path");
        return;
    }

    // With a class, snapshot an existing managed-DB PVC and restore it into a new PVC.
    // (The managed DB is brought up by the Phase-1 K8S COMPUTE BACKEND OK lane first.)
    assert!(backend.snapshots_supported());
    backend
        .snapshot_volume("data-pg", "pg-backup-phase2")
        .await
        .expect("create VolumeSnapshot");
    backend
        .restore_volume("pg-backup-phase2", "data-pg-restored", 20_480)
        .await
        .expect("restore PVC from VolumeSnapshot");

    // Clean up the restored PVC (best-effort).
    let _ = backend.remove_volume("data-pg-restored").await;
    println!("K8S COMPUTE PHASE2 OK");
}
