//! **Live gate: the owner-gated migration FUNCTION-STEP path, end to end.**
//!
//! Drives the REAL server-side orchestrator ([`boatramp_server::run_migration`]) over the REAL node
//! substrate ([`NodeMigrationRunner`]), a REAL wasm engine, a REAL compiled guest
//! (`tests/fixtures/migrate-fn.wasm`, built from `examples/handlers/migrate-fn`), and a REAL Postgres
//! (bring-your-own-URL, so no compute stack). It proves the function-step base the whole feature
//! rests on:
//!
//! - **`MIGRATE FUNCTION-STEP DDL OK`** — a `function` step's `migrate::exec` runs owner-role DDL and
//!   the step is recorded with `kind = function` (the table it created exists);
//! - **`MIGRATE-DDL RLS-INVARIANT OK` (S1 binding-split)** — the same function's `sql-open` sees NO
//!   tenant `sql` binding (the guest returns `sql:absent` → the step applies; a leak would 500);
//! - **`MIGRATE-DDL LEDGER-GUARD OK` (S3)** — a function `migrate::exec` referencing
//!   `boatramp_migrations` is refused (`ledger-protected`) → the step fails;
//! - **`MIGRATE FUNCTION-STEP IDEMPOTENT OK` (S7)** — a function step that fails after partial work
//!   is NOT recorded and is re-attempted on the next apply;
//! - **`MIGRATE-DDL CONTEXT-GATED OK` (S2)** — the SAME component invoked as a normal request gets
//!   `not-a-migration` from `migrate::exec` (no owner-DDL outside a migration run), and its DDL never
//!   runs;
//! - **`MIGRATE BASELINE OK` (#480)** — a baseline records a prefix without running it (no schema
//!   change, `origin = baseline`), and a later apply runs only the suffix.
//!
//! Requires `BOATRAMP_TEST_PG_URL` (skips when unset). Prints `MIGRATE FUNCTION-STEP OK [postgres]`.

#![cfg(all(feature = "sql-postgres", feature = "migrate"))]

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{MigrationAction, MigrationStep, MigrationSubstrate, SqlValue};
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::{NodeMigrationRunner, NodeOperatorSql};
use boatramp_server::{run_migration, Auth, HandlerRuntime, MigrateMode, ServerOptions};
use boatramp_storage::FsStorage;
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::BodyExt;
use tower::ServiceExt;

const DB: &str = "app";
const URL_ENV: &str = "BOATRAMP_MIGRATE_FN_TEST_URL";
const FN_NAME: &str = "migrate-fn";

fn fn_step(id: &str, args: &str) -> MigrationStep {
    MigrationStep {
        id: id.to_string(),
        action: MigrationAction::Function {
            name: FN_NAME.to_string(),
            version: None,
            args: Some(args.to_string()),
        },
    }
}
fn sql_step(id: &str, script: &str) -> MigrationStep {
    MigrationStep {
        id: id.to_string(),
        action: MigrationAction::Sql {
            script: script.to_string(),
            no_transaction: false,
        },
    }
}

/// Build the shared DeployStore over a temp FsStorage + MemoryKv.
fn deploy_store() -> DeployStore {
    let dir = std::env::temp_dir().join(format!("boatramp-migrate-fn-{}", std::process::id()));
    DeployStore::new(Arc::new(FsStorage::new(dir)), Arc::new(MemoryKv::new()))
}

/// A managed bring-your-own-URL Postgres binding pointing at the test PG.
fn databases() -> BTreeMap<String, ExternalDatabaseConfig> {
    let mut databases = BTreeMap::new();
    databases.insert(
        DB.to_string(),
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            url_env: URL_ENV.to_string(),
            compute: None,
            database: None,
            user: None,
            pool_max: Some(4),
            read_only: false,
            connect_timeout_secs: Some(10),
            tenant: TenantIsolation::Shared,
            tenant_scope: TenantScope::Project,
            ..Default::default()
        },
    );
    databases
}

/// Deploy the compiled migrate-fn fixture as a top-level project function importing `migrate-ddl`
/// (+ `sql`, so the binding-split has something to be split away).
async fn deploy_fixture(deploy: &DeployStore) {
    use boatramp_core::deploy::sha256_hex;
    use boatramp_core::function::{Function, FunctionConfig, Lifecycle, Owner};
    let wasm = include_bytes!("fixtures/migrate-fn.wasm").to_vec();
    let hash = sha256_hex(&wasm);
    let stream = futures::stream::once(async move { Ok(Bytes::from(wasm)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();
    let config = FunctionConfig {
        imports: vec!["migrate-ddl".to_string(), "sql".to_string()],
        ..Default::default()
    };
    let f = Function::new(
        FN_NAME,
        Owner::Project("default".into()),
        &hash,
        config,
        Lifecycle::Independent,
        0,
    );
    deploy.put_function(ProjectRef::DEFAULT, &f).await.unwrap();
}

/// A direct (non-ledgered) connection to the test PG for setup + verification.
async fn direct() -> Arc<dyn boatramp_core::sql::SqlBackend> {
    use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
    let url = std::env::var("BOATRAMP_TEST_PG_URL").unwrap();
    connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap()
}

async fn table_exists(c: &Arc<dyn boatramp_core::sql::SqlBackend>, table: &str) -> bool {
    let rows = c
        .run_query(&format!(
            "SELECT to_regclass('public.{table}') IS NOT NULL AS e"
        ))
        .await
        .unwrap();
    matches!(
        rows.rows.first().and_then(|r| r.first()),
        Some(SqlValue::Boolean(true))
    )
}

#[tokio::test]
async fn migrate_function_step_end_to_end_on_a_real_engine() {
    let Some(url) = std::env::var("BOATRAMP_TEST_PG_URL").ok() else {
        eprintln!("skip migrate_function: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    std::env::set_var(URL_ENV, &url);

    // Clean slate.
    let c = direct().await;
    for stmt in [
        "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE",
        "DROP TABLE IF EXISTS fnmade",
        "DROP TABLE IF EXISTS zz",
        "DROP TABLE IF EXISTS ctx",
        "DROP TABLE IF EXISTS base_a",
        "DROP TABLE IF EXISTS base_b",
        "DROP TABLE IF EXISTS suffix_c",
    ] {
        let _ = c.run_script(stmt).await;
    }

    let deploy = deploy_store();
    deploy_fixture(&deploy).await;

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(
        engine,
        Arc::new(MemoryKv::new()),
        Arc::new(FsStorage::new(std::env::temp_dir().join(format!(
            "boatramp-migrate-fn-blob-{}",
            std::process::id()
        )))),
        None,
        None,
    );
    // Lenient tenancy posture so a NORMAL request to the sql-importing fixture reaches the guest
    // (the S2 probe) instead of being refused for an undeclared tenancy before the guest runs. This
    // does not affect migration invocations (they early-return before tenancy resolution). Keeping
    // the fixture's `sql` grant makes the S1 binding-split a strong "granted-but-dropped" proof.
    runtime.set_tenancy_posture(false, false);

    let op = Arc::new(NodeOperatorSql::new(
        databases(),
        Arc::new(MemoryKv::new()),
        None,
        deploy.clone(),
    ));
    let substrate: Arc<dyn MigrationSubstrate> = Arc::new(NodeMigrationRunner::new(
        op,
        std::collections::BTreeSet::new(),
    ));

    // --- S2 context-gate: the SAME component invoked as a NORMAL request gets not-a-migration ---
    {
        let options = ServerOptions {
            migration_substrate: Some(substrate.clone()),
            ..Default::default()
        };
        let app = boatramp_server::router_with(
            deploy.clone(),
            Auth::disabled(),
            runtime.clone(),
            options,
        );
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/projects/default/functions/{FN_NAME}/invoke"))
            .header("content-type", "text/plain")
            .body(axum::body::Body::from("exec CREATE TABLE ctx (id int)"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(
            status.is_server_error() && body.contains("not-a-migration"),
            "a normal request must get not-a-migration from migrate::exec (S2), got {status}: {body}"
        );
        assert!(
            !table_exists(&c, "ctx").await,
            "a normal request's migrate::exec DDL must NOT run (no owner-DDL outside a migration)"
        );
    }

    // --- #1 function-step DDL as owner + recorded (kind=function) ---
    let s1 = fn_step(
        "0001_fn_ddl",
        "exec CREATE TABLE fnmade (id int primary key)",
    );
    let rep = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        std::slice::from_ref(&s1),
        MigrateMode::Apply,
    )
    .await
    .unwrap();
    assert_eq!(
        rep.newly_applied,
        vec!["0001_fn_ddl"],
        "the function step applied: {rep:?}"
    );
    assert!(rep.failed.is_none());
    assert_eq!(
        rep.kinds.get("0001_fn_ddl").map(String::as_str),
        Some("function")
    );
    assert!(
        table_exists(&c, "fnmade").await,
        "the function created the table as owner"
    );
    let applied = substrate.preflight("default", DB).await.unwrap();
    assert_eq!(
        applied.iter().map(|a| a.kind.as_str()).collect::<Vec<_>>(),
        vec!["function"]
    );

    // --- S1 binding-split: the function's sql-open sees NO tenant binding (sql:absent → applies) ---
    let s2 = fn_step("0002_sqlsplit", "sql-open");
    let rep = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        &[s1.clone(), s2.clone()],
        MigrateMode::Apply,
    )
    .await
    .unwrap();
    assert_eq!(
        rep.newly_applied, vec!["0002_sqlsplit"],
        "sql-open applied ⇒ the guest saw sql:absent (binding-split holds); a leak would 500: {rep:?}"
    );

    // --- S3 ledger-guard via a function: migrate::exec touching the ledger schema is refused ---
    let s3 = fn_step(
        "0003_guard",
        "exec DROP TABLE boatramp_migrations.schema_migrations",
    );
    let rep = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        &[s1.clone(), s2.clone(), s3.clone()],
        MigrateMode::Apply,
    )
    .await
    .unwrap();
    let failed = rep.failed.as_ref().expect("the ledger-guarded step failed");
    assert_eq!(failed.id, "0003_guard");
    assert!(
        failed.error.contains("ledger-protected"),
        "the failure distinguishes a ledger-guard refusal: {}",
        failed.error
    );
    // 0003 is NOT recorded.
    let applied = substrate.preflight("default", DB).await.unwrap();
    assert!(!applied.iter().any(|a| a.id == "0003_guard"));

    // --- S7 idempotent: a function step that fails after partial work is NOT recorded + re-attempted ---
    let s3b = fn_step(
        "0003_fail",
        "fail-after CREATE TABLE IF NOT EXISTS zz (i int)",
    );
    let set = [s1.clone(), s2.clone(), s3b.clone()];
    let rep = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        &set,
        MigrateMode::Apply,
    )
    .await
    .unwrap();
    assert_eq!(
        rep.failed.as_ref().map(|f| f.id.as_str()),
        Some("0003_fail")
    );
    let applied = substrate.preflight("default", DB).await.unwrap();
    assert!(
        !applied.iter().any(|a| a.id == "0003_fail"),
        "a failed function step is NOT recorded (at-least-once)"
    );
    // Re-apply the SAME set → 0003 is re-attempted (pending again), not skipped.
    let rep2 = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        &set,
        MigrateMode::Apply,
    )
    .await
    .unwrap();
    assert_eq!(
        rep2.failed.as_ref().map(|f| f.id.as_str()),
        Some("0003_fail"),
        "the unrecorded step is re-attempted on the next apply"
    );

    // --- #480 baseline: record a prefix WITHOUT running it, then apply only the suffix ---
    // Fresh ledger for a clean baseline narrative (drop what the function steps recorded).
    for stmt in [
        "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE",
        "DROP TABLE IF EXISTS fnmade",
        "DROP TABLE IF EXISTS zz",
    ] {
        let _ = c.run_script(stmt).await;
    }
    let base = [
        sql_step("b0001", "CREATE TABLE base_a (id int)"),
        sql_step("b0002", "CREATE TABLE base_b (id int)"),
    ];
    let rep = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        &base,
        MigrateMode::Baseline {
            up_to: Some("b0002".to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        rep.newly_applied,
        vec!["b0001", "b0002"],
        "baseline records the prefix"
    );
    // No schema change happened, and the rows are marked origin=baseline.
    assert!(!table_exists(&c, "base_a").await, "baseline runs NO DDL");
    let applied = substrate.preflight("default", DB).await.unwrap();
    assert!(
        applied
            .iter()
            .filter(|a| a.id.starts_with('b'))
            .all(|a| a.origin == "baseline"),
        "baselined rows carry origin=baseline"
    );
    // A later apply of the full set runs ONLY the held suffix.
    let full = [
        base[0].clone(),
        base[1].clone(),
        sql_step("b0003", "CREATE TABLE suffix_c (id int)"),
    ];
    let rep = run_migration(
        &runtime,
        &deploy,
        &substrate,
        "default",
        DB,
        &full,
        MigrateMode::Apply,
    )
    .await
    .unwrap();
    assert_eq!(
        rep.newly_applied,
        vec!["b0003"],
        "apply runs only the suffix after a baseline"
    );
    assert!(table_exists(&c, "suffix_c").await);

    // Cleanup.
    for stmt in [
        "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE",
        "DROP TABLE IF EXISTS base_a",
        "DROP TABLE IF EXISTS base_b",
        "DROP TABLE IF EXISTS suffix_c",
        "DROP TABLE IF EXISTS zz",
    ] {
        let _ = c.run_script(stmt).await;
    }

    println!("MIGRATE FUNCTION-STEP OK [postgres]");
}
