//! Live capability gate for the PROJECT-SCOPED `compute status` endpoint
//! (`GET /api/projects/<p>/compute/status`) — the multi-tenant CLI gap this change
//! closes. Before it, `boatramp compute status` only ever hit the node-global
//! `/api/compute/status` (`System·Admin`), so a tenant could not poll its OWN compute
//! workload's readiness without a node-global `admin` token — blocking the
//! `project_admin` token-tightening.
//!
//! It stands up ONE in-process node — the REAL full `router()` over a `DeployStore`
//! with a REAL token [`Auth`] (so the authz layer actually runs) — and drives the
//! endpoint end to end over the real axum stack (`tower::oneshot`), the same idiom the
//! `conformance` / kv-stratum gates use. The fixture seeds TWO tenants (`acme` and
//! `globex`), each with one healthy + running replica, so the cross-tenant isolation is
//! observable.
//!
//! What it asserts (each a release precondition — the point of the fix, proven):
//!   1. **Own-project read.** A `project_admin:acme` token reads
//!      `GET /api/projects/acme/compute/status` → 200, and the `healthy + running`
//!      readiness signal is present for acme's OWN replica.
//!   2. **No cross-tenant leak.** That same 200 response contains ZERO of `globex`'s
//!      replicas — the project-scoped read is store-scoped to the one tenant's keyspace.
//!   3. **Cross-tenant refusal.** The `project_admin:acme` token on another tenant's
//!      `GET /api/projects/globex/compute/status` is **403** (authz, the per-project
//!      right, before any existence check).
//!   4. **Node-global refusal.** The `project_admin:acme` token on the node-global
//!      `GET /api/compute/status` is **403** — the fix does NOT weaken that surface.
//!   5. **Node-global positive control.** A node `admin` token on the node-global
//!      `GET /api/compute/status` is 200 and DOES see both tenants (the endpoint still
//!      works for the operator).
//!
//! `#[ignore]`d + wired into `.github/workflows/ci.yml` as a HARD gate that asserts the
//! success marker, so a silent skip or an authz regression fails the merge (the
//! ignore-gated-tests-not-evidence discipline). Run locally with:
//!   `cargo test -p boatramp-server --test compute_status_project_scope_live -- --ignored --nocapture`

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use boatramp_core::authz::GrantedRole;
use boatramp_core::compute::{
    Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
};
use boatramp_core::cose::{self, Claims, LocalSigner, Signer, TokenAlg};
use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::{Project, ProjectRef};
use boatramp_server::{Auth, HandlerRuntime, router};
use boatramp_storage::FsStorage;
use tower::ServiceExt;

/// A seeded project record (pre-seeded directly — the create API needs a system-admin
/// token, and the existence guard only reads the pointer).
fn project(name: &str) -> Project {
    Project {
        version: boatramp_core::SCHEMA_VERSION,
        name: name.to_string(),
        created_at: 0,
        meta: Default::default(),
        config: Default::default(),
        secrets_ref: None,
    }
}

/// A healthy + running observed replica for `(project, workload)`.
fn healthy_running(project: &str, workload: &str, ip: &str) -> ObservedInstance {
    ObservedInstance {
        handle: InstanceHandle {
            project: project.to_string(),
            workload: workload.to_string(),
            replica: 0,
            backend_ref: "pid-0".to_string(),
        },
        node: 1,
        backend: "container".to_string(),
        endpoint: Endpoint {
            scheme: Scheme::Http,
            host: ip.to_string(),
            port: 8080,
        },
        region: None,
        healthy: true,
        started_at: Some(boatramp_core::time::now_unix()),
        phase: ReplicaPhase::Running,
        readiness: Readiness::Provisioned,
        data_dir: None,
        snapshot: None,
        active_spec: None,
    }
}

/// A token [`Auth`] over a fresh keypair plus a token minted from it carrying `roles`
/// (the default RBAC policy applies; no TTL).
async fn token_auth(roles: &[GrantedRole]) -> (Auth, String) {
    let signer = LocalSigner::generate(TokenAlg::Es256);
    let claims = Claims {
        roles: roles.to_vec(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: None,
        now_unix: 0,
    };
    let token = cose::mint(&claims, &signer).await.expect("mint token");
    let auth = Auth::with_key(signer.public_key(), Arc::new(MemoryKv::new()));
    (auth, token)
}

/// `GET <path>` with a bearer token through the REAL router (auth layer runs).
/// Returns `(status, json)`.
async fn get_as(
    deploy: &DeployStore,
    auth: Auth,
    path: &str,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = router(deploy.clone(), auth, HandlerRuntime::disabled())
        .oneshot(req)
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Whether a `compute status` JSON array carries a healthy + running replica for
/// `project`.
fn has_healthy_running(body: &serde_json::Value, project: &str) -> bool {
    body.as_array().is_some_and(|arr| {
        arr.iter().any(|r| {
            r["project"] == project
                && r["healthy"] == serde_json::Value::Bool(true)
                && r["phase"] == "running"
        })
    })
}

/// Whether a `compute status` JSON array mentions `project` at all.
fn mentions(body: &serde_json::Value, project: &str) -> bool {
    body.as_array()
        .is_some_and(|arr| arr.iter().any(|r| r["project"] == project))
}

#[tokio::test]
#[ignore = "live gate: drives the real router()+auth; run in CI via the dedicated job"]
async fn compute_status_project_scope_gate() {
    let dir = std::env::temp_dir().join(format!("br-compute-status-{}", std::process::id()));
    let deploy = DeployStore::new(Arc::new(FsStorage::new(dir)), Arc::new(MemoryKv::new()));

    // Two tenants, each with a healthy+running replica.
    deploy.put_project(&project("acme")).await.unwrap();
    deploy.put_project(&project("globex")).await.unwrap();
    deploy
        .set_replica_state(
            ProjectRef::new("acme"),
            &healthy_running("acme", "web", "10.0.0.2"),
        )
        .await
        .unwrap();
    deploy
        .set_replica_state(
            ProjectRef::new("globex"),
            &healthy_running("globex", "web", "10.0.0.3"),
        )
        .await
        .unwrap();

    // 1 + 2. A project_admin:acme token reads its OWN project's compute status (200,
    // healthy+running present) and sees ZERO of globex's replicas.
    let (acme_auth, acme_tok) = token_auth(&[GrantedRole::scoped("project_admin", "acme")]).await;
    let (status, body) = get_as(
        &deploy,
        acme_auth.clone(),
        "/api/projects/acme/compute/status",
        &acme_tok,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "project_admin:acme must read its OWN project's compute status"
    );
    assert!(
        has_healthy_running(&body, "acme"),
        "acme's own healthy+running readiness signal must be present: {body}"
    );
    assert!(
        !mentions(&body, "globex"),
        "a project-scoped status must NOT leak another tenant's replica: {body}"
    );

    // 3. The SAME token on another tenant's project-scoped status is 403 (cross-tenant).
    let (status, _) = get_as(
        &deploy,
        acme_auth.clone(),
        "/api/projects/globex/compute/status",
        &acme_tok,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "project_admin:acme must be refused on globex's compute status"
    );

    // 4. The SAME token on the node-global status is 403 (the fix does not weaken it).
    let (status, _) = get_as(&deploy, acme_auth, "/api/compute/status", &acme_tok).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "project_admin:acme must be refused on the node-global /api/compute/status"
    );

    // 5. Positive control: a node admin still reads the node-global status across tenants.
    let (admin_auth, admin_tok) = token_auth(&[GrantedRole::global("admin")]).await;
    let (status, body) = get_as(&deploy, admin_auth, "/api/compute/status", &admin_tok).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a node admin must still read the node-global compute status"
    );
    assert!(
        mentions(&body, "acme") && mentions(&body, "globex"),
        "the node-global status still spans every tenant for an operator: {body}"
    );

    println!("COMPUTE STATUS PROJECT-SCOPE GATE OK");
}
