//! **Live end-to-end gates for the construens atomic-swap self-heal fix (v0.59.8).**
//!
//! Drives the REAL managed-pg restore path (export_clone → import → non-superuser shadow + atomic
//! swap) against a real Postgres + Docker, for the construens shape: a prior-FAILED existing-dest
//! Shared-Postgres tenant (populated live db + a stray `__old_` swap-aside owned by the derived owner
//! role, so the FULL `fresh_dest=false` self-heal fires). Two gates:
//!
//! * GATE 2 — `construens_existing_dest_heal_lands_live`: a successful restore LANDS the source data
//!   ONE-SHOT into the dest's live db, and the dest's PRIOR data is preserved, recoverable, in a
//!   `__deleted_` grace tombstone — no stranding, no manual step.
//! * GATE 3 (NEGATIVE) — `construens_restore_failure_leaves_live_serving`: the SAME setup but the
//!   shadow restore is made to FAIL (a non-trusted extension the non-superuser apply role cannot
//!   create — a cause-agnostic stand-in for "a restore failure, for ANY reason"). The import surfaces
//!   an error AND the ORIGINAL live db is STILL SERVING its prior data, untouched — the atomicity
//!   invariant. Reverting the fix (the self-heal empties live up front) turns this RED (live emptied).
//!
//! Needs `BOATRAMP_TEST_PG_URL` (a superuser Postgres URL) + a reachable Docker daemon; self-skips
//! otherwise. Prints `CONSTRUENS EXISTING-DEST HEAL LANDS OK` / `CONSTRUENS RESTORE-FAIL LIVE INTACT OK`.

#![cfg(feature = "project-export")]

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::compute::{
    ComputeBackend, Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
    pg_client_image_for_server_version,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::project_export::{
    BundleScope, CloneSkip, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
};
use boatramp_docker::DockerBackend;
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::NodeOperatorSql;
use boatramp_node::pg_client::PgConnection;
use boatramp_node::project_export::NodeProjectExport;
use boatramp_node::tenant_sql::provision_tenant;
use boatramp_storage::fs::FsStorage;
use boatramp_storage::tenant_provision::{
    bounded_aside_db_name, sanitize_ident, tenant_db_name, tenant_owner_role_name,
};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

fn parse_pg_url(url: &str) -> Option<(String, String, String, u16)> {
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))?;
    let (userinfo, hostpart) = rest.rsplit_once('@')?;
    let (user, password) = userinfo.split_once(':')?;
    let (hostport, _db) = hostpart.split_once('/').unwrap_or((hostpart, ""));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 5432),
    };
    Some((user.to_string(), password.to_string(), host, port))
}

fn now_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn conn(user: &str, password: &str, host: &str, port: u16, db: &str) -> PgConnection {
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

/// Run psql in an ephemeral container, feeding `sql` on stdin; returns `(exit_code, trimmed_stdout)`.
async fn psql(
    backend: &dyn ComputeBackend,
    image: &str,
    c: &PgConnection,
    sql: &str,
) -> (i32, String) {
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

fn shared_binding(superuser: &str) -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some("pg".into()),
        database: Some("appdb".into()),
        user: Some(superuser.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

async fn wire(
    kv: &Arc<dyn KvStore>,
    deploy: &DeployStore,
    envelope: &Arc<dyn KeyEnvelope>,
    password: &str,
    host: &str,
    port: u16,
) {
    let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
    kv.put("managed-sql-cred/default/pg", sealed).await.unwrap();
    deploy
        .set_replica_state(
            ProjectRef::new("default"),
            &ObservedInstance {
                handle: InstanceHandle {
                    project: "default".to_string(),
                    workload: "pg".to_string(),
                    replica: 0,
                    backend_ref: String::new(),
                },
                node: 0,
                backend: "docker".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.to_string(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .unwrap();
}

/// A managed-pg Shared driver + its own kv/deploy/blobs/work (held alive by the caller).
struct Node {
    drv: NodeProjectExport,
    kv: Arc<dyn KvStore>,
    deploy: DeployStore,
    envelope: Arc<dyn KeyEnvelope>,
    _td: tempfile::TempDir,
}

async fn build_node(
    backend: &Arc<dyn ComputeBackend>,
    envelope: &Arc<dyn KeyEnvelope>,
    superuser: &str,
    password: &str,
    host: &str,
    port: u16,
) -> Node {
    let databases = BTreeMap::from([("app".to_string(), shared_binding(superuser))]);
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    let work = td.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    wire(&kv, &deploy, envelope, password, host, port).await;
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        DeployStore::new(blobs.clone(), kv.clone()),
    ));
    let drv = NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs.clone(), work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false)
        .with_trusted_extensions(vec![]);
    Node {
        drv,
        kv,
        deploy,
        envelope: envelope.clone(),
        _td: td,
    }
}

/// Drop the derived live db + any asides/tombstones + the derived roles of a Shared tenant (re-runnable).
async fn cleanup_tenant(
    backend: &dyn ComputeBackend,
    image: &str,
    maint: &PgConnection,
    project: &str,
) {
    let ident = sanitize_ident(project);
    let live = tenant_db_name("appdb", &ident);
    let prefix = &live[..live.len().min(30)];
    let (_c, dbs) = psql(
        backend,
        image,
        maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{prefix}%'"),
    )
    .await;
    for d in dbs.lines().filter(|l| !l.trim().is_empty()) {
        let _ = psql(
            backend,
            image,
            maint,
            &format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", d.trim()),
        )
        .await;
    }
    for role in [
        tenant_owner_role_name("pg", &ident),
        boatramp_storage::tenant_provision::tenant_role_name("pg", &ident),
    ] {
        let _ = psql(
            backend,
            image,
            maint,
            &format!("DROP ROLE IF EXISTS \"{role}\""),
        )
        .await;
    }
}

/// Provision a Shared tenant, seed its live db with `seed_sql`, and fabricate the prior-failed TANGLE
/// (a stray empty `__old_` aside owned by the derived owner role ⇒ the FULL existing-dest self-heal).
async fn setup_prior_failed_dest(
    node: &Node,
    backend: &dyn ComputeBackend,
    image: &str,
    maint: &PgConnection,
    su: &str,
    pw: &str,
    host: &str,
    port: u16,
    project: &str,
    seed_sql: &str,
) -> String {
    provision_tenant(
        &node.deploy,
        &node.kv,
        &node.envelope,
        &shared_binding(su),
        project,
        "",
    )
    .await
    .expect("provision dest tenant");
    let ident = sanitize_ident(project);
    let live = tenant_db_name("appdb", &ident);
    let live_conn = conn(su, pw, host, port, &live);
    let (c, o) = psql(backend, image, &live_conn, seed_sql).await;
    assert_eq!(c, 0, "seed dest live db: {o}");
    let owner_role = tenant_owner_role_name("pg", &ident);
    let stray = bounded_aside_db_name(&live, "__old_", "1");
    let (c, o) = psql(
        backend,
        image,
        maint,
        &format!("CREATE DATABASE \"{stray}\" OWNER \"{owner_role}\""),
    )
    .await;
    assert_eq!(c, 0, "create stray __old_ aside (tangle): {o}");
    live
}

async fn export_shared_bundle(src: &Node, project: &str) -> Vec<u8> {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join(format!("bundle-{}.brproj", now_suffix()));
    let f = tokio::fs::File::create(&path).await.unwrap();
    let mut sink = f.compat_write();
    src.drv
        .export_clone(
            project,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                ..Default::default()
            },
            &CloneSkip::default(),
            &mut sink,
        )
        .await
        .expect("export_clone source Shared tenant");
    std::fs::read(&path).unwrap()
}

async fn env_setup() -> Option<(Arc<dyn ComputeBackend>, String, String, String, u16, String)> {
    let url = std::env::var("BOATRAMP_TEST_PG_URL").ok()?;
    let (user, password, host, port) = parse_pg_url(&url)?;
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon");
            return None;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");
    Some((backend, user, password, host, port, image))
}

#[tokio::test]
async fn construens_existing_dest_heal_lands_live() {
    let Some((backend, user, password, host, port, image)) = env_setup().await else {
        eprintln!("SKIP: construens existing-dest heal gate (env unset)");
        return;
    };
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    let maint = conn(&user, &password, &host, port, "postgres");
    let s = now_suffix();
    let src_proj = format!("csrc{s}");
    let dst_proj = format!("cdst{s}");

    cleanup_tenant(backend.as_ref(), &image, &maint, &src_proj).await;
    cleanup_tenant(backend.as_ref(), &image, &maint, &dst_proj).await;

    // SOURCE: a Shared tenant seeded with NEW data to land.
    let src = build_node(&backend, &envelope, &user, &password, &host, port).await;
    provision_tenant(
        &src.deploy,
        &src.kv,
        &src.envelope,
        &shared_binding(&user),
        &src_proj,
        "",
    )
    .await
    .expect("provision source tenant");
    let src_live = tenant_db_name("appdb", &sanitize_ident(&src_proj));
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, &src_live),
        "CREATE TABLE widget(id int primary key, v text); \
         INSERT INTO widget VALUES (1,'NEW-alpha'),(2,'NEW-beta');",
    )
    .await;
    assert_eq!(c, 0, "seed source rows: {o}");
    let bundle = export_shared_bundle(&src, &src_proj).await;

    // DEST: a PRIOR-FAILED existing dest — populated with OLD data + a tangle.
    let dst = build_node(&backend, &envelope, &user, &password, &host, port).await;
    let dst_live = setup_prior_failed_dest(
        &dst,
        backend.as_ref(),
        &image,
        &maint,
        &user,
        &password,
        &host,
        port,
        &dst_proj,
        "CREATE TABLE old_marker(v text); INSERT INTO old_marker VALUES ('OLD-cdst');",
    )
    .await;

    // IMPORT into the existing dest (apply + ShadowSwap bundle; skip_control_plane_kv=false ⇒ the FULL
    // existing-dest self-heal). It must land the SOURCE data ONE-SHOT.
    let mut body = futures::io::Cursor::new(bundle);
    let report = dst
        .drv
        .import(
            &dst_proj,
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                ..Default::default()
            },
        )
        .await
        .expect("existing-dest heal import must SUCCEED one-shot");
    assert_eq!(report.pg_databases, 1, "one managed pg db restored");

    // The dest live db now serves the SOURCE (NEW) data — landed one-shot through the self-heal + swap.
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, &dst_live),
        "SELECT v FROM widget ORDER BY id",
    )
    .await;
    assert_eq!(
        got, "NEW-alpha\nNEW-beta",
        "source rows landed on the dest live db"
    );
    // The dest's OLD data is NOT in the new live db...
    let (_c, old_in_live) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, &dst_live),
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname='public' AND c.relname='old_marker'",
    )
    .await;
    assert_eq!(
        old_in_live.trim(),
        "0",
        "the OLD table must not remain in the new live db"
    );
    // ...it is PRESERVED, recoverable, in a `__deleted_` grace tombstone.
    let prefix = &dst_live[..dst_live.len().min(30)];
    let (_c, tombs) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{prefix}%__deleted\\_%' ESCAPE '\\'"),
    )
    .await;
    let tomb = tombs
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .expect("a `__deleted_` grace tombstone of the old live db must exist after the swap");
    let (_c, old_data) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, tomb),
        "SELECT v FROM old_marker LIMIT 1",
    )
    .await;
    assert_eq!(
        old_data.trim(),
        "OLD-cdst",
        "the OLD data must be recoverable in the tombstone"
    );

    // No orphan shadow db remains.
    let (_c, shadows) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{prefix}%__shadow_%'"),
    )
    .await;
    assert!(
        shadows.trim().is_empty(),
        "no orphan shadow db: {shadows:?}"
    );

    cleanup_tenant(backend.as_ref(), &image, &maint, &src_proj).await;
    cleanup_tenant(backend.as_ref(), &image, &maint, &dst_proj).await;
    println!("CONSTRUENS EXISTING-DEST HEAL LANDS OK");
}

#[tokio::test]
async fn construens_restore_failure_leaves_live_serving() {
    let Some((backend, user, password, host, port, image)) = env_setup().await else {
        eprintln!("SKIP: construens restore-failure gate (env unset)");
        return;
    };
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    let maint = conn(&user, &password, &host, port, "postgres");
    let s = now_suffix();
    let src_proj = format!("fsrc{s}");
    let dst_proj = format!("fdst{s}");

    cleanup_tenant(backend.as_ref(), &image, &maint, &src_proj).await;
    cleanup_tenant(backend.as_ref(), &image, &maint, &dst_proj).await;

    // SOURCE seeded with a NON-TRUSTED extension (`bloom`) the dest's non-superuser apply role cannot
    // create — a deterministic, cause-AGNOSTIC stand-in for "a restore failure, for any reason".
    let src = build_node(&backend, &envelope, &user, &password, &host, port).await;
    provision_tenant(
        &src.deploy,
        &src.kv,
        &src.envelope,
        &shared_binding(&user),
        &src_proj,
        "",
    )
    .await
    .expect("provision source tenant");
    let src_live = tenant_db_name("appdb", &sanitize_ident(&src_proj));
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, &src_live),
        "CREATE EXTENSION IF NOT EXISTS bloom; \
         CREATE TABLE widget(id int primary key, v text); INSERT INTO widget VALUES (1,'NEW');",
    )
    .await;
    if c != 0 {
        eprintln!(
            "SKIP: could not install the `bloom` contrib extension on the source ({o}) — cannot inject a deterministic restore failure"
        );
        cleanup_tenant(backend.as_ref(), &image, &maint, &src_proj).await;
        return;
    }
    let bundle = export_shared_bundle(&src, &src_proj).await;

    // DEST: a PRIOR-FAILED existing dest — populated with OLD data + a tangle.
    let dst = build_node(&backend, &envelope, &user, &password, &host, port).await;
    let dst_live = setup_prior_failed_dest(
        &dst,
        backend.as_ref(),
        &image,
        &maint,
        &user,
        &password,
        &host,
        port,
        &dst_proj,
        "CREATE TABLE old_marker(v text); INSERT INTO old_marker VALUES ('OLD-fdst');",
    )
    .await;

    // IMPORT — the shadow restore FAILS (bloom cannot be created by the non-superuser apply role, and
    // the dest pre-creates no extensions). The import must error, and the ORIGINAL live db must STILL
    // be serving its prior data, untouched (the atomicity invariant).
    let mut body = futures::io::Cursor::new(bundle);
    let res = dst
        .drv
        .import(
            &dst_proj,
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                ..Default::default()
            },
        )
        .await;
    let err = res.expect_err("the import MUST fail when the shadow restore fails");
    let msg = err.to_string();
    eprintln!("restore-failure import error (expected): {msg}");

    // THE ATOMICITY INVARIANT: the original live db is STILL serving its prior data.
    let (c, got) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, &dst_live),
        "SELECT v FROM old_marker LIMIT 1",
    )
    .await;
    assert_eq!(
        c, 0,
        "the original live db must still be connectable after the failed restore"
    );
    assert_eq!(
        got.trim(),
        "OLD-fdst",
        "LIVE-SERVING-AFTER-FAILED-RESTORE (the invariant): a failed restore must leave the ORIGINAL \
         live db serving its prior data — never an emptied mirror. Reverting the fix turns this RED."
    );
    // The source (NEW) data must NOT have landed.
    let (_c, newcnt) = psql(
        backend.as_ref(),
        &image,
        &conn(&user, &password, &host, port, &dst_live),
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname='public' AND c.relname='widget'",
    )
    .await;
    assert_eq!(
        newcnt.trim(),
        "0",
        "a failed restore must not have landed the source data"
    );
    // No orphan shadow db remains (drop-on-abort ran).
    let prefix = &dst_live[..dst_live.len().min(30)];
    let (_c, shadows) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{prefix}%__shadow_%'"),
    )
    .await;
    assert!(
        shadows.trim().is_empty(),
        "no orphan shadow db after abort: {shadows:?}"
    );

    cleanup_tenant(backend.as_ref(), &image, &maint, &src_proj).await;
    cleanup_tenant(backend.as_ref(), &image, &maint, &dst_proj).await;
    println!("CONSTRUENS RESTORE-FAIL LIVE INTACT OK");
}
