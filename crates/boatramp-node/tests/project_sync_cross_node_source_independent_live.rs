//! **Cross-node `project sync` SOURCE-VERSION-INDEPENDENCE gate** (Tier-2 / live — needs a Docker
//! daemon AND a reachable Postgres / MySQL; self-skips otherwise, exactly like
//! `project_export_roundtrip.rs`).
//!
//! This is the gate for the v0.59.2 fix: a managed-DB `project sync` into an ABSENT/fresh dest must
//! land the data CROSS-NODE against **any** source version — including a pre-v0.59.1 source that does
//! not understand the `managed_restore` query param and silently degrades a `data_only=true` request
//! to a schema-less Overlay the target then (correctly) refuses. That is exactly construens's
//! repeated production failure (a clone FROM an older prod into a new env).
//!
//! WHY THIS GATE IS FAITHFUL (and the earlier `project_sync_managed_pg_shadow_land_live` is not):
//! that gate round-trips `export_clone`/`import` IN-PROCESS with HAND-BUILT `ExportOptions` /
//! `ImportOptions`, so the WIRE layer where the signal actually drops
//! (`CloneSourceQuery::export_opts`, the query-param→`ExportOptions` translation) is never exercised.
//! This gate instead stands up the REAL `boatramp-server` router over a real managed-pg/mysql
//! `NodeProjectExport` capability on BOTH a SOURCE node and a TARGET node, and drives:
//!   - the SOURCE `POST /api/projects/<p>/clone/stream` HANDLER over the real axum stack
//!     (`tower::oneshot`) — the managed-restore mode travels ONLY as a wire query param (and the
//!     pre-v0.59.1 source is simulated faithfully by OMITTING the param, which a v0.59.1 source maps
//!     to the IDENTICAL legacy Overlay head an old `CloneSourceQuery` would), and
//!   - the TARGET `POST /api/project-import` HANDLER over the real axum stack — which reconstructs
//!     the bundle head from the STREAM and drives the real `NodeProjectExport::import`.
//!
//! The gate constructs NO `ExportOptions`/`ImportOptions`/`BundleHead` by hand: the source handler
//! builds the export opts from the wire query, and the target handler builds the import opts from its
//! own query params — the mode is never hand-set anywhere.
//!
//! (A true 2-PROCESS gate — two real `boatramp serve` processes + the `clone/from` orchestrator over
//! a real socket — is NOT achievable in-repo: the orchestrator's SSRF guard refuses a loopback
//! `source_url`. That is the lighthouse two-node LIVE run. Here the TARGET half is driven via the
//! real `project-import` handler, which exercises the SAME `NodeProjectExport::import` the clone
//! orchestrator calls — so the managed-restore signal still travels only over the wire, and the
//! exact import arm that refuses/lands is exercised for real.)
//!
//! ARMS:
//!   - **GREEN (the fix):** the sync's OWN decision for an absent managed dest
//!     (`project_sync::data_clone_request(/*dest_absent=*/true)` — `data_only=false` +
//!     `skip_control_plane_kv=true`) drives the SOURCE clone/stream over the wire (simulating an OLD
//!     source that ignores `managed_restore`), then the TARGET imports it and the seeded rows LAND on
//!     the provisioned dest. On the UNFIXED base `data_clone_request` returns `data_only=true` ⇒ the
//!     old source emits an Overlay ⇒ the import REFUSES ⇒ the "rows land" assertion FAILS (RED).
//!   - **ZERO SOURCE-DOMAIN CARRY (construens bar D):** the source's control-plane DOMAIN layer
//!     (`domainverify`/`alias`/a settings key) is seeded, so the FULL bundle carries it. After the
//!     clamped absent-dest import the fresh target holds NONE of it (the data-plane-only clamp skips
//!     the control-plane KV slice; `carry_kv_stratum` carries the control plane selectively instead).
//!     A CONTROL arm imports the SAME full bundle WITHOUT the clamp and asserts the domain layer DOES
//!     land — so the zero-carry is the clamp's doing, not a source that carried nothing (F1 can never
//!     silently regress).
//!   - **VERSION-SKEW (permanent RED-refusing):** the EXISTING-dest shape (`data_only=true`, no
//!     `managed_restore`, simulating an old source) is REFUSED on import — proving the real wire
//!     signal-drop reaches the managed-overlay guard. After the error-hardening the refusal names the
//!     version skew explicitly (distinct from the generic data-only RCE refusal).
//!
//! Emits `PROJECT SYNC CROSS-NODE PG SOURCE-INDEPENDENT OK` / `… MYSQL …` only after BOTH arms pass,
//! so a silent skip or a regression fails the CI gate (the ignore-gated-tests-not-evidence
//! discipline). Run locally with a reachable pg/mysql + docker:
//!   `BOATRAMP_TEST_PG_URL=… BOATRAMP_TEST_MYSQL_URL=… cargo test -p boatramp-node \
//!      --features project-export --test project_sync_cross_node_source_independent_live \
//!      -- --test-threads=1 --nocapture`
#![cfg(feature = "project-export")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use boatramp_core::compute::{
    ComputeBackend, Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::project_export::ProjectExport;
use boatramp_core::project_sync::data_clone_request;
use boatramp_docker::DockerBackend;
use boatramp_node::config::ExternalDatabaseConfig;
use boatramp_node::managed_sql::NodeOperatorSql;
use boatramp_node::pg_client::{MysqlConnection, PgConnection};
use boatramp_node::project_export::NodeProjectExport;
use boatramp_server::{Auth, HandlerRuntime, ServerOptions, router_with};
use boatramp_storage::fs::FsStorage;
use tower::ServiceExt;

// ---------------------------------------------------------------------------------------------
// test-URL parsing + ephemeral-container SQL helpers (local copies of the project_export_roundtrip
// harness — these tests live in their own crate target).
// ---------------------------------------------------------------------------------------------

fn parse_pg_url(url: &str) -> Option<(String, String, String, u16, String)> {
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))?;
    let (userinfo, hostpart) = rest.rsplit_once('@')?;
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    let (hostport, db) = hostpart.split_once('/')?;
    let db = db.split(['?', '&']).next().unwrap_or(db).to_string();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 5432),
    };
    Some((user, password, host, port, db))
}

fn parse_mysql_url(url: &str) -> Option<(String, String, String, u16, String)> {
    let rest = url.strip_prefix("mysql://")?;
    let (userinfo, hostpart) = rest.rsplit_once('@')?;
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    let (hostport, db) = hostpart.split_once('/')?;
    let db = db.split(['?', '&']).next().unwrap_or(db).to_string();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 3306),
    };
    Some((user, password, host, port, db))
}

fn pg_conn(user: &str, password: &str, host: &str, port: u16, db: &str) -> PgConnection {
    PgConnection {
        host: host.to_string(),
        port,
        user: user.to_string(),
        password: password.to_string(),
        database: db.to_string(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    }
}

async fn psql(
    backend: &dyn ComputeBackend,
    image: &str,
    c: &PgConnection,
    sql: &str,
) -> (i32, String) {
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
    let td = tempfile::tempdir().unwrap();
    let sql_path = td.path().join("in.sql");
    tokio::fs::write(&sql_path, sql).await.unwrap();
    let out_path = td.path().join("out");
    let argv = vec![
        "sh".to_string(),
        "-c".to_string(),
        "exec psql -v ON_ERROR_STOP=1 -tA -f - 2>&1".to_string(),
    ];
    let mut env = c.env();
    env.push((
        "PGOPTIONS".to_string(),
        "-c client_min_messages=warning".to_string(),
    ));
    let infile = tokio::fs::File::open(&sql_path).await.unwrap();
    let mut rdr = infile.compat();
    let code = {
        let f = tokio::fs::File::create(&out_path).await.unwrap();
        let mut sink = f.compat_write();
        backend
            .run_ephemeral(image, &argv, &env, Some(&mut rdr), &mut sink)
            .await
            .expect("psql run_ephemeral")
    };
    let out = tokio::fs::read_to_string(&out_path)
        .await
        .unwrap_or_default();
    (code, out.trim().to_string())
}

async fn mysql_run(
    backend: &dyn ComputeBackend,
    image: &str,
    c: &MysqlConnection,
    db: Option<&str>,
    sql: &str,
) -> (i32, String) {
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
    let td = tempfile::tempdir().unwrap();
    let sql_path = td.path().join("in.sql");
    tokio::fs::write(&sql_path, sql).await.unwrap();
    let out_path = td.path().join("out");
    let target = db.map(|d| format!(" {d}")).unwrap_or_default();
    let conn = c.conn_args().join(" ");
    let argv = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("mysql {conn} --connect-timeout=10 -N --batch{target} 2>&1"),
    ];
    let env = c.env();
    let infile = tokio::fs::File::open(&sql_path).await.unwrap();
    let mut rdr = infile.compat();
    let f = tokio::fs::File::create(&out_path).await.unwrap();
    let mut sink = f.compat_write();
    let code = backend
        .run_ephemeral(image, &argv, &env, Some(&mut rdr), &mut sink)
        .await
        .expect("mysql run_ephemeral");
    let out = tokio::fs::read_to_string(&out_path)
        .await
        .unwrap_or_default();
    (code, out.trim().to_string())
}

fn now_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// ---------------------------------------------------------------------------------------------
// one node = a real `router_with` over a managed-DB `NodeProjectExport` cap + the clone/import wire.
// ---------------------------------------------------------------------------------------------

/// Build a NODE: the REAL `boatramp-server` router over `cap` (the managed-DB project-export
/// capability) — the same router the shipped `serve` path builds. Auth is disabled (the token
/// layer), but the clone/import handlers' OWN static `Project·Admin` re-check still runs.
fn node_app(cap: Arc<dyn ProjectExport>, deploy: DeployStore) -> axum::Router {
    let options = ServerOptions {
        project_export: Some(cap),
        ..Default::default()
    };
    router_with(
        deploy,
        Auth::disabled(),
        HandlerRuntime::disabled(),
        options,
    )
}

fn connect_info() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000)))
}

/// Drive the SOURCE `clone/stream` HANDLER over the real axum stack and collect the streamed bundle.
/// `managed_restore` is the WIRE query param — pass `None` to simulate a pre-v0.59.1 source that
/// ignores it (the degradation that reproduces the production failure).
async fn clone_stream_bundle(
    app: &axum::Router,
    project: &str,
    data_only: bool,
    managed_restore: Option<&str>,
) -> Vec<u8> {
    let mut uri = format!("/api/projects/{project}/clone/stream?data_only={data_only}");
    if let Some(mr) = managed_restore {
        uri.push_str("&managed_restore=");
        uri.push_str(mr);
    }
    let mut r = Request::builder()
        .method("POST")
        .uri(&uri)
        .body(Body::empty())
        .unwrap();
    r.extensions_mut().insert(connect_info());
    let resp = app.clone().oneshot(r).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "clone/stream must stream a bundle (routing/auth OK)"
    );
    to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

/// Drive the TARGET `project-import` HANDLER over the real axum stack. Returns `(status, body)` —
/// the body is the JSON report on success or the plain-text refusal otherwise. `query_extra` carries
/// additional wire query params (e.g. `&force=true`, `&managed_restore=shadow-swap`,
/// `&allow_schema_skew=true`).
async fn project_import(
    app: &axum::Router,
    project: &str,
    bundle: Vec<u8>,
    query_extra: &str,
) -> (StatusCode, String) {
    let uri =
        format!("/api/project-import?project={project}&apply=true&overwrite=true{query_extra}");
    let mut r = Request::builder()
        .method("POST")
        .uri(&uri)
        .body(Body::from(bundle))
        .unwrap();
    r.extensions_mut().insert(connect_info());
    let resp = app.clone().oneshot(r).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Seal the managed-DB credential + seed a healthy, already-Provisioned replica of `workload` for
/// project `default` pointing at the test DB server — the control-plane state the resolver reads.
async fn wire_managed(
    kv: &Arc<dyn KvStore>,
    deploy: &DeployStore,
    envelope: &Arc<dyn KeyEnvelope>,
    workload: &str,
    password: &str,
    host: &str,
    port: u16,
) {
    use boatramp_core::compute::Readiness;
    let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
    kv.put(&format!("managed-sql-cred/default/{workload}"), sealed)
        .await
        .unwrap();
    deploy
        .set_replica_state(
            ProjectRef::new("default"),
            &ObservedInstance {
                handle: InstanceHandle {
                    project: "default".to_string(),
                    workload: workload.to_string(),
                    replica: 0,
                    backend_ref: String::new(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.to_string(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .unwrap();
}

/// A managed-DB NODE under test: the real router app + the node's control-plane KV store (held so a
/// test can SEED the source's domain layer and ASSERT zero source-domain carry on the target) + the
/// tempdirs kept alive for the driver's lifetime.
struct ManagedNode {
    app: axum::Router,
    kv: Arc<dyn KvStore>,
    _tempdirs: Vec<tempfile::TempDir>,
}

/// Seed the SOURCE node's control-plane KV with a DOMAIN layer: a `domainverify` proof, an `alias`,
/// and a non-domain settings key. A FULL bundle stages all of these in its control-plane KV member.
/// The data-plane-only clamp must land the managed DATA but carry NONE of these to a fresh target
/// (construens bar D: zero source-domain carry under `--identity fresh`).
async fn seed_domain_layer(kv: &Arc<dyn KvStore>) {
    kv.put(
        "project/default/domainverify/example.com",
        br#"{"token":"src-proof"}"#.to_vec(),
    )
    .await
    .unwrap();
    kv.put(
        "project/default/alias/www.example.com",
        b"example.com".to_vec(),
    )
    .await
    .unwrap();
    kv.put(
        "project/default/config/settings",
        br#"{"k":"src"}"#.to_vec(),
    )
    .await
    .unwrap();
}

/// The three source-owned control-plane keys `seed_domain_layer` writes — the data-plane-only clamp
/// must leave ALL of them ABSENT on the target.
const DOMAIN_LAYER_KEYS: [&str; 3] = [
    "project/default/domainverify/example.com",
    "project/default/alias/www.example.com",
    "project/default/config/settings",
];

// ---------------------------------------------------------------------------------------------
// PG gate
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn project_sync_cross_node_pg_source_independent_live() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (cross-node pg source-independent gate)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (cross-node pg source-independent gate)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let table = format!("brxn_t_{s}");
    let source_db = format!("brxn_src_{s}");
    let live_db = format!("brxn_live_{s}");
    let maint = pg_conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image =
        boatramp_core::compute::pg_client_image_for_server_version(&ver).expect("client image");

    // --- SOURCE + dest physical DBs; seed the source with known rows ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("CREATE DATABASE {source_db}"),
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let expect = "1:alpha\n2:beta\n3:gamma";
    let src_conn = pg_conn(&user, &password, &host, port, &source_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &src_conn,
        &format!(
            "CREATE TABLE {table}(id int primary key, v text); \
             INSERT INTO {table} VALUES (1,'alpha'),(2,'beta'),(3,'gamma');"
        ),
    )
    .await;
    assert_eq!(c, 0, "seed source rows: {o}");

    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));

    // Build a managed-pg NODE (its own kv/deploy/driver) binding `app` → `db_name`, exposed via the
    // REAL router. `trusted_extensions([])` so a dedicated managed shadow-swap restore runs clean.
    let build_node = {
        let backend = backend.clone();
        let envelope = envelope.clone();
        let user = user.clone();
        let password = password.clone();
        let host = host.clone();
        move |db_name: String| {
            let backend = backend.clone();
            let envelope = envelope.clone();
            let user = user.clone();
            let password = password.clone();
            let host = host.clone();
            async move {
                let databases = BTreeMap::from([(
                    "app".to_string(),
                    ExternalDatabaseConfig {
                        kind: "postgres".to_string(),
                        compute: Some("pg".to_string()),
                        database: Some(db_name),
                        user: Some(user.clone()),
                        ..Default::default() // Single / Project = dedicated
                    },
                )]);
                let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
                let td = tempfile::tempdir().unwrap();
                let blobs: Arc<dyn boatramp_core::Storage> =
                    Arc::new(FsStorage::new(td.path().join("blobs")));
                let deploy = DeployStore::new(blobs.clone(), kv.clone());
                let work = td.path().join("work");
                std::fs::create_dir_all(&work).unwrap();
                wire_managed(&kv, &deploy, &envelope, "pg", &password, &host, port).await;
                let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
                    databases.clone(),
                    kv.clone(),
                    Some(envelope.clone()),
                    DeployStore::new(blobs.clone(), kv.clone()),
                ));
                let driver = NodeProjectExport::new(
                    databases,
                    deploy.clone(),
                    kv.clone(),
                    blobs.clone(),
                    work,
                )
                .with_managed_pg(backend.clone(), envelope.clone(), op, false)
                .with_trusted_extensions(vec![]);
                let app = node_app(Arc::new(driver), deploy);
                ManagedNode {
                    app,
                    kv,
                    _tempdirs: vec![td],
                }
            }
        }
    };

    let src_node = build_node(source_db.clone()).await;
    let dst_node = build_node(live_db.clone()).await;
    // Seed the SOURCE's control-plane DOMAIN layer, so the FULL bundle carries it (and we can prove
    // the data-plane-only clamp does NOT carry it to the fresh target — construens bar D).
    seed_domain_layer(&src_node.kv).await;

    // ============================ VERSION-SKEW arm (permanent RED-refusing) ============================
    // The EXISTING-dest shape against an OLD source: `data_only=true`, NO `managed_restore` on the
    // wire (an old `CloneSourceQuery` drops it). The source emits a LEGACY DataPlane+Overlay head;
    // the target REFUSES the managed overlay. We additionally pass the EXPECTED mode
    // (`managed_restore=shadow-swap`) so the refusal names the version skew (post-hardening).
    let overlay_bundle = clone_stream_bundle(&src_node.app, "default", true, None).await;
    let (skew_status, skew_body) = project_import(
        &dst_node.app,
        "default",
        overlay_bundle,
        "&force=true&allow_schema_skew=true&managed_restore=shadow-swap",
    )
    .await;
    assert_ne!(
        skew_status,
        StatusCode::OK,
        "a managed-pg Overlay from an old source MUST be refused on import, got OK: {skew_body}"
    );
    assert!(
        skew_body.contains("MANAGED pg") || skew_body.contains("managed"),
        "the refusal must be the managed-overlay guard, got: {skew_body}"
    );
    // (The error-hardening tightens this to assert the DISTINCT version-skew phrasing — see the
    // `managed-DB restore refused: the source node did not emit a shadow-swap bundle head` message.)
    assert!(
        skew_body.contains("shadow-swap bundle head") && skew_body.contains("upgrade the source"),
        "version-skew refusal must name the cause (old source could not emit a shadow-swap head), \
         got: {skew_body}"
    );

    // ============================ GREEN arm (the fix) ============================
    // The sync's OWN decision for an absent managed dest, driven over the real wire. Simulate an OLD
    // source by OMITTING `managed_restore` (the source maps it to the legacy coupling). On the
    // UNFIXED base `req.data_only == true` ⇒ Overlay ⇒ the import refuses ⇒ this arm FAILS (RED).
    let req = data_clone_request(/*dest_absent=*/ true);
    let full_bundle = clone_stream_bundle(&src_node.app, "default", req.data_only, None).await;
    // Build the import query from the sync's OWN decision (force + the data-plane-only clamp) — so the
    // gate exercises the real `data_clone_request` choice over the real wire, not a hand-set flag.
    let mut green_q = String::new();
    if req.force {
        green_q.push_str("&force=true");
    }
    if req.skip_control_plane_kv {
        green_q.push_str("&skip_control_plane_kv=true");
    }
    let (land_status, land_body) =
        project_import(&dst_node.app, "default", full_bundle.clone(), &green_q).await;
    assert_eq!(
        land_status,
        StatusCode::OK,
        "the absent-dest sync must LAND the managed-pg data cross-node against an old source \
         (the fix); got {land_status}: {land_body}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&land_body).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        report
            .get("pg_databases")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "exactly one managed pg db restored: {land_body}"
    );

    // --- F1 (construens bar D): ZERO source-domain carry. The clamped FULL-bundle import landed the
    //     managed DATA but must have carried NONE of the source's control-plane domain layer. ---
    for key in DOMAIN_LAYER_KEYS {
        let got = dst_node.kv.get(key).await.unwrap();
        assert!(
            got.is_none(),
            "data-plane-only clamp LEAKED a source control-plane key onto the fresh target: {key} \
             (= {got:?}); the domain layer must be carried only by sync's selective carry_kv_stratum"
        );
    }

    // --- CONTROL: the SAME full bundle imported WITHOUT the clamp DOES carry the domain layer — so
    //     the zero-carry above is the CLAMP's doing, not a source that carried nothing. A fresh third
    //     node + db so the control's managed restore has somewhere to land. ---
    let ctrl_db = format!("brxn_ctrl_{s}");
    for sql in [
        format!("DROP DATABASE IF EXISTS {ctrl_db}"),
        format!("CREATE DATABASE {ctrl_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "ctrl setup `{sql}`: {o}");
    }
    let ctrl_node = build_node(ctrl_db.clone()).await;
    let (ctrl_status, ctrl_body) =
        project_import(&ctrl_node.app, "default", full_bundle, "&force=true").await;
    assert_eq!(
        ctrl_status,
        StatusCode::OK,
        "control (unclamped) full-bundle import must succeed: {ctrl_body}"
    );
    let carried = ctrl_node
        .kv
        .get("project/default/domainverify/example.com")
        .await
        .unwrap();
    assert!(
        carried.is_some(),
        "control: an UNCLAMPED full-bundle import MUST carry the source domain layer (proving the \
         clamp is load-bearing); got absent"
    );

    // --- rows LAND + are queryable on the provisioned dest db ---
    let live_conn = pg_conn(&user, &password, &host, port, &live_db);
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &live_conn,
        &format!("SELECT id || ':' || v FROM {table} ORDER BY id"),
    )
    .await;
    assert_eq!(
        got, expect,
        "rows landed on the dest via the full-bundle shadow+swap"
    );

    // --- no orphan shadow db / ephemeral apply role remains ---
    let (_c, shadows) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{live_db}__shadow_%'"),
    )
    .await;
    assert!(
        shadows.trim().is_empty(),
        "no orphan shadow database: {shadows:?}"
    );

    // --- cleanup (best-effort) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("DROP DATABASE IF EXISTS {ctrl_db}"),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT SYNC CROSS-NODE PG SOURCE-INDEPENDENT OK");
}

// ---------------------------------------------------------------------------------------------
// MySQL analogue (dedicated/Single managed mysql → chunked shadow-swap), same real transport.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn project_sync_cross_node_mysql_source_independent_live() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (cross-node mysql source-independent gate)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!(
                "SKIP: no reachable Docker daemon (cross-node mysql source-independent gate)"
            );
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    let s = now_suffix();
    let table = format!("brxn_t_{s}");
    let source_db = format!("brxn_src_{s}");
    let live_db = format!("brxn_live_{s}");
    let mkconn = |db: &str| MysqlConnection {
        host: host.clone(),
        port,
        user: user.clone(),
        password: password.clone(),
        database: db.to_string(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };
    let maint = MysqlConnection {
        database: String::new(),
        ..mkconn("")
    };

    for sql in [
        format!("DROP DATABASE IF EXISTS `{source_db}`;"),
        format!("CREATE DATABASE `{source_db}`;"),
        format!("DROP DATABASE IF EXISTS `{live_db}`;"),
        format!("CREATE DATABASE `{live_db}`;"),
    ] {
        let (c, o) = mysql_run(backend.as_ref(), image, &maint, None, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let expect = "1:alpha\n2:beta";
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &maint,
        Some(&source_db),
        &format!(
            "CREATE TABLE {table}(id INT PRIMARY KEY, v TEXT); \
             INSERT INTO {table} VALUES (1,'alpha'),(2,'beta');"
        ),
    )
    .await;
    assert_eq!(c, 0, "seed source rows: {o}");

    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([7u8; 32]));

    let build_node = {
        let backend = backend.clone();
        let envelope = envelope.clone();
        let user = user.clone();
        let password = password.clone();
        let host = host.clone();
        move |db_name: String| {
            let backend = backend.clone();
            let envelope = envelope.clone();
            let user = user.clone();
            let password = password.clone();
            let host = host.clone();
            async move {
                let databases = BTreeMap::from([(
                    "app".to_string(),
                    ExternalDatabaseConfig {
                        kind: "mysql".to_string(),
                        compute: Some("my".to_string()),
                        database: Some(db_name),
                        user: Some(user.clone()),
                        ..Default::default() // Single / Project = dedicated
                    },
                )]);
                let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
                let td = tempfile::tempdir().unwrap();
                let blobs: Arc<dyn boatramp_core::Storage> =
                    Arc::new(FsStorage::new(td.path().join("blobs")));
                let deploy = DeployStore::new(blobs.clone(), kv.clone());
                let work = td.path().join("work");
                std::fs::create_dir_all(&work).unwrap();
                wire_managed(&kv, &deploy, &envelope, "my", &password, &host, port).await;
                let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
                    databases.clone(),
                    kv.clone(),
                    Some(envelope.clone()),
                    DeployStore::new(blobs.clone(), kv.clone()),
                ));
                let driver = NodeProjectExport::new(
                    databases,
                    deploy.clone(),
                    kv.clone(),
                    blobs.clone(),
                    work,
                )
                .with_managed_pg(backend.clone(), envelope.clone(), op, false)
                .with_trusted_extensions(vec![]);
                let app = node_app(Arc::new(driver), deploy);
                ManagedNode {
                    app,
                    kv,
                    _tempdirs: vec![td],
                }
            }
        }
    };

    let src_node = build_node(source_db.clone()).await;
    let dst_node = build_node(live_db.clone()).await;
    // Seed the SOURCE domain layer so we can prove the clamp carries NONE of it to the fresh target.
    seed_domain_layer(&src_node.kv).await;

    // VERSION-SKEW arm: old-source Overlay → refused (with the version-skew phrasing post-hardening).
    let overlay_bundle = clone_stream_bundle(&src_node.app, "default", true, None).await;
    let (skew_status, skew_body) = project_import(
        &dst_node.app,
        "default",
        overlay_bundle,
        "&force=true&allow_schema_skew=true&managed_restore=shadow-swap",
    )
    .await;
    assert_ne!(
        skew_status,
        StatusCode::OK,
        "a managed-mysql Overlay from an old source MUST be refused on import: {skew_body}"
    );
    assert!(
        skew_body.contains("MANAGED mysql") || skew_body.contains("managed"),
        "the refusal must be the managed-overlay guard, got: {skew_body}"
    );
    assert!(
        skew_body.contains("shadow-swap bundle head") && skew_body.contains("upgrade the source"),
        "version-skew refusal must name the cause, got: {skew_body}"
    );

    // GREEN arm: the fix's absent-dest decision over the real wire → rows land + ZERO domain carry.
    let req = data_clone_request(/*dest_absent=*/ true);
    let full_bundle = clone_stream_bundle(&src_node.app, "default", req.data_only, None).await;
    let mut green_q = String::new();
    if req.force {
        green_q.push_str("&force=true");
    }
    if req.skip_control_plane_kv {
        green_q.push_str("&skip_control_plane_kv=true");
    }
    let (land_status, land_body) =
        project_import(&dst_node.app, "default", full_bundle, &green_q).await;
    assert_eq!(
        land_status,
        StatusCode::OK,
        "the absent-dest sync must LAND the managed-mysql data cross-node against an old source \
         (the fix); got {land_status}: {land_body}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&land_body).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        report
            .get("pg_databases")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "exactly one managed mysql db restored: {land_body}"
    );

    // F1 (construens bar D): ZERO source-domain carry — the clamped import landed the managed DATA
    // but must have carried none of the source's control-plane domain layer onto the fresh target.
    for key in DOMAIN_LAYER_KEYS {
        let got = dst_node.kv.get(key).await.unwrap();
        assert!(
            got.is_none(),
            "data-plane-only clamp LEAKED a source control-plane key onto the fresh target: {key}"
        );
    }

    let (_c, got) = mysql_run(
        backend.as_ref(),
        image,
        &maint,
        Some(&live_db),
        &format!("SELECT CONCAT(id, ':', v) FROM {table} ORDER BY id;"),
    )
    .await;
    assert_eq!(
        got, expect,
        "rows landed on the dest via the full-bundle shadow+swap"
    );

    for sql in [
        format!("DROP DATABASE IF EXISTS `{live_db}`;"),
        format!("DROP DATABASE IF EXISTS `{source_db}`;"),
    ] {
        let _ = mysql_run(backend.as_ref(), image, &maint, None, &sql).await;
    }

    println!("PROJECT SYNC CROSS-NODE MYSQL SOURCE-INDEPENDENT OK");
}
