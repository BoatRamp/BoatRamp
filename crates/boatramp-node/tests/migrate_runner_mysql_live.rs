//! **Live gate: the schema-migration SUBSTRATE on a real MySQL (backend parity).**
//!
//! The MySQL analog of `migrate_runner_sqlx_live` (Postgres). Drives the node-side
//! [`MigrationSubstrate`] (`NodeMigrationRunner`) end to end against a real MySQL via a
//! bring-your-own-URL managed binding, and proves the MySQL parity contract — which is
//! **backend-honest**, i.e. weaker-than-Postgres where the engine can't keep the guarantee:
//!
//! - **DDL identity is a DISTINCT login** (`migration_url_env`), never the runtime user — the
//!   owner-role analog. Absent it (or if it equals the runtime identity) migrate refuses fail-closed
//!   (asserted in the crate's unit tests; here we supply a distinct admin login).
//! - **preflight** creates the `boatramp_migrations` InnoDB ledger DATABASE + table and returns the
//!   applied rows in order.
//! - **apply / status** — a `sql` step applies + records its ledger row with the supplied effective
//!   hash + `apply` origin; a second preflight reads the ledger back in order.
//! - **NON-ATOMIC per step (the honest caveat)** — MySQL implicitly commits each DDL, so a
//!   multi-DDL step whose 2nd statement errors leaves the 1st statement's DDL **applied** (not
//!   rolled back) while the step is reported failed + carries the `PARTIALLY APPLIED` marker. This
//!   is the opposite of the Postgres gate (which asserts a clean rollback) — the parity is honest,
//!   not identical.
//! - **content-hash immutability signal** — the ledger records the effective hash the caller
//!   supplied (the orchestrator compares it on re-apply; here we assert it is what was recorded).
//! - **extension step refused** — MySQL has no `CREATE EXTENSION`, so an `extension` step is a
//!   per-step failure; a raw `sql` step that `CREATE EXTENSION`s is likewise refused.
//! - **owner-DDL seam guards (S3/S4)** — the `migrate-ddl` seam refuses a ledger-DATABASE reference
//!   and guest transaction control (tokenized under the MySQL dialect: a `#`-comment can't hide it),
//!   and runs plain owner DDL + a verification query.
//! - **baseline origin (U6)** — a `record(…, Baseline)` row reads back with `origin = "baseline"`
//!   and the step is NOT run.
//!
//! Requires `BOATRAMP_TEST_MYSQL_URL` (the runtime user) and derives a distinct DDL login from it
//! (the `root` account, credentials from the CI service container). Skips when unset. Prints
//! `MIGRATE MYSQL PARITY OK` (the CI grep marker).

#![cfg(all(feature = "sql-mysql", feature = "migrate"))]

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::MemoryKv;
use boatramp_core::sql::{
    LedgerOrigin, MigrateDdlError, MigrationAction, MigrationStep, MigrationSubstrate,
    SubstrateStepOutcome,
};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::{NodeMigrationRunner, NodeOperatorSql};
use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
use boatramp_storage::FsStorage;

const DB: &str = "app";
const RUNTIME_URL_ENV: &str = "BOATRAMP_MIGRATE_MYSQL_RUNTIME_URL";
const DDL_URL_ENV: &str = "BOATRAMP_MIGRATE_MYSQL_DDL_URL";

fn sql_step(id: &str, script: &str) -> MigrationStep {
    MigrationStep {
        id: id.to_string(),
        action: MigrationAction::Sql {
            script: script.to_string(),
            no_transaction: false,
        },
    }
}
fn ext_step(id: &str, name: &str) -> MigrationStep {
    MigrationStep {
        id: id.to_string(),
        action: MigrationAction::Extension {
            name: name.to_string(),
        },
    }
}

/// Derive a DISTINCT DDL/admin connection URL from the runtime `BOATRAMP_TEST_MYSQL_URL`.
///
/// The runtime URL is `mysql://boatramp:boatramp@host:port/db`. The DDL identity must be a different
/// login with schema-change + `CREATE DATABASE` rights — the service container's `root` account
/// (root password == the container's `MYSQL_ROOT_PASSWORD`, `boatramp` in CI). We keep the same
/// host/port/db and swap the userinfo to `root:<root_pw>`. If the URL can't be parsed we return
/// `None` (skip), never silently reuse the runtime identity (that would defeat the whole point).
fn ddl_url_from_runtime(runtime: &str) -> Option<String> {
    // Split scheme://userinfo@hostpart. We only rewrite the userinfo segment.
    let (scheme, rest) = runtime.split_once("://")?;
    let hostpart = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
    // The CI service container's root credentials (see .github/workflows/ci.yml). Overridable so a
    // local run against a different MySQL can point the DDL login elsewhere.
    let root_user =
        std::env::var("BOATRAMP_TEST_MYSQL_ROOT_USER").unwrap_or_else(|_| "root".into());
    let root_pw =
        std::env::var("BOATRAMP_TEST_MYSQL_ROOT_PASSWORD").unwrap_or_else(|_| "boatramp".into());
    Some(format!("{scheme}://{root_user}:{root_pw}@{hostpart}"))
}

/// Build the substrate over a BYO-URL MySQL binding: runtime `url_env` + a distinct DDL
/// `migration_url_env`. Returns `None` (skip) when `BOATRAMP_TEST_MYSQL_URL` is unset.
fn runner_for() -> Option<NodeMigrationRunner> {
    let runtime = std::env::var("BOATRAMP_TEST_MYSQL_URL").ok()?;
    let ddl = ddl_url_from_runtime(&runtime)?;
    assert_ne!(
        runtime, ddl,
        "the DDL identity must be DISTINCT from the runtime user"
    );
    std::env::set_var(RUNTIME_URL_ENV, &runtime);
    std::env::set_var(DDL_URL_ENV, &ddl);

    let mut databases = BTreeMap::new();
    databases.insert(
        DB.to_string(),
        ExternalDatabaseConfig {
            kind: "mysql".to_string(),
            url_env: RUNTIME_URL_ENV.to_string(),
            migration_url_env: Some(DDL_URL_ENV.to_string()),
            pool_max: Some(4),
            read_only: false,
            connect_timeout_secs: Some(10),
            tenant: TenantIsolation::Shared,
            tenant_scope: TenantScope::Project,
            ..Default::default()
        },
    );
    let op = Arc::new(NodeOperatorSql::new(
        databases,
        Arc::new(MemoryKv::new()),
        None,
        DeployStore::new(
            Arc::new(FsStorage::new(
                std::env::temp_dir().join("boatramp-migrate-mysql-test"),
            )),
            Arc::new(MemoryKv::new()),
        ),
    ));
    // No trusted extensions — MySQL refuses the extension step kind outright regardless.
    Some(NodeMigrationRunner::new(
        op,
        std::collections::BTreeSet::new(),
    ))
}

/// Apply a `sql`/`extension` step at `ordinal`, recording the intrinsic content hash (the effective
/// hash for these kinds) with the `apply` origin — the exact call the orchestrator makes.
async fn apply(
    sub: &NodeMigrationRunner,
    step: &MigrationStep,
    ordinal: usize,
) -> SubstrateStepOutcome {
    let eff = step.content_hash();
    sub.apply_substrate_step("default", DB, step, ordinal, &eff)
        .await
        .expect("substrate step (infra)")
}

fn applied_ids(applied: &[boatramp_core::sql::AppliedMigration]) -> Vec<String> {
    applied.iter().map(|a| a.id.clone()).collect()
}

/// A direct DDL-login connection for out-of-band setup / assertions (not ledgered).
async fn ddl_conn() -> Arc<dyn boatramp_core::sql::SqlBackend> {
    let ddl = std::env::var(DDL_URL_ENV).unwrap();
    connect(ExternalSqlKind::Mysql, &ExternalSqlOptions::new(ddl)).unwrap()
}

#[tokio::test]
async fn migrate_substrate_mysql_parity_on_a_real_engine() {
    let Some(sub) = runner_for() else {
        eprintln!("skip migrate_substrate_mysql: BOATRAMP_TEST_MYSQL_URL unset");
        return;
    };

    // Clean slate (re-runnable): drop the ledger DATABASE + any test tables via the DDL login. The
    // runtime user owns database `boatramp` (from the service container) — we create/drop tables in
    // it as the DDL login (root), which can reach every schema.
    {
        let c = ddl_conn().await;
        for stmt in [
            "DROP DATABASE IF EXISTS boatramp_migrations",
            "DROP TABLE IF EXISTS boatramp.widget",
            "DROP TABLE IF EXISTS boatramp.gadget",
            "DROP TABLE IF EXISTS boatramp.baselined",
            "DROP TABLE IF EXISTS boatramp.owner_made",
            "DROP TABLE IF EXISTS boatramp.z",
        ] {
            let _ = c.run_script(stmt).await;
        }
    }

    // --- preflight on an empty ledger creates the InnoDB ledger + returns nothing ---
    let applied = sub.preflight("default", DB).await.unwrap();
    assert!(applied.is_empty(), "empty ledger");
    // The ledger DATABASE exists now (created by preflight as the DDL login).
    {
        let c = ddl_conn().await;
        let rows = c
            .run_query(
                "SELECT COUNT(*) FROM information_schema.schemata \
                 WHERE schema_name = 'boatramp_migrations'",
            )
            .await
            .unwrap();
        let n = match rows.rows.first().and_then(|r| r.first()) {
            Some(boatramp_core::sql::SqlValue::Integer(n)) => *n,
            other => panic!("unexpected schemata count: {other:?}"),
        };
        assert_eq!(n, 1, "preflight created the boatramp_migrations database");
    }

    // --- apply two sql steps in order; the ledger records them with origin=apply ---
    let s1 = sql_step(
        "0001_widget",
        "CREATE TABLE boatramp.widget (id int primary key, name varchar(64))",
    );
    let s2 = sql_step(
        "0002_seed",
        "INSERT INTO boatramp.widget (id, name) VALUES (1, 'a')",
    );
    assert!(matches!(
        apply(&sub, &s1, 0).await,
        SubstrateStepOutcome::Applied
    ));
    assert!(matches!(
        apply(&sub, &s2, 1).await,
        SubstrateStepOutcome::Applied
    ));
    let applied = sub.preflight("default", DB).await.unwrap();
    assert_eq!(applied_ids(&applied), vec!["0001_widget", "0002_seed"]);
    assert!(
        applied.iter().all(|a| a.origin == "apply"),
        "applied rows carry origin=apply"
    );
    assert_eq!(
        applied[0].content_hash,
        s1.content_hash(),
        "the recorded hash is the effective hash the orchestrator supplied (immutability signal)"
    );

    // --- NON-ATOMIC per step (the honest MySQL caveat): a multi-DDL step whose 2nd statement
    //     errors leaves the 1st statement's DDL APPLIED (MySQL auto-commits each DDL), and the step
    //     is reported failed WITH the `PARTIALLY APPLIED` marker + no ledger row. This is the
    //     opposite of the Postgres gate (which asserts a clean rollback). ---
    let partial = sql_step(
        "0003_partial",
        "CREATE TABLE boatramp.gadget (id int primary key); \
         CREATE TABLE boatramp.gadget (id int primary key)", // 2nd fails: table already exists
    );
    let outcome = apply(&sub, &partial, 2).await;
    match outcome {
        SubstrateStepOutcome::Failed(msg) => {
            assert!(
                msg.contains("PARTIALLY APPLIED"),
                "a mid-DDL failure on MySQL is reported as partially applied: {msg}"
            );
        }
        other => panic!("expected a failed partial step, got {other:?}"),
    }
    // Not recorded in the ledger…
    let after = sub.preflight("default", DB).await.unwrap();
    assert!(
        !after.iter().any(|a| a.id == "0003_partial"),
        "a failed step is never recorded"
    );
    // …but the 1st statement's DDL DID apply (the partial): `gadget` exists (the very reason the
    // 2nd statement's re-create failed). Proves the non-atomic behavior honestly.
    {
        let c = ddl_conn().await;
        let rows = c
            .run_query(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = 'boatramp' AND table_name = 'gadget'",
            )
            .await
            .unwrap();
        let n = match rows.rows.first().and_then(|r| r.first()) {
            Some(boatramp_core::sql::SqlValue::Integer(n)) => *n,
            other => panic!("unexpected tables count: {other:?}"),
        };
        assert_eq!(
            n, 1,
            "the 1st DDL of a partially-applied step is NOT rolled back on MySQL"
        );
    }

    // --- extension step is refused outright on MySQL (no CREATE EXTENSION) ---
    match apply(&sub, &ext_step("0004_citext", "citext"), 3).await {
        SubstrateStepOutcome::Failed(msg) => assert!(
            msg.contains("MySQL"),
            "an extension step is refused on MySQL: {msg}"
        ),
        other => panic!("expected extension step refused on MySQL, got {other:?}"),
    }
    // A raw sql step that CREATE EXTENSIONs is likewise refused.
    assert!(matches!(
        apply(
            &sub,
            &sql_step("0004_rawext", "CREATE EXTENSION IF NOT EXISTS whatever"),
            3
        )
        .await,
        SubstrateStepOutcome::Failed(_)
    ));

    // --- a sql step carrying its own BEGIN/COMMIT is refused (DDL implicitly commits on MySQL) ---
    match apply(
        &sub,
        &sql_step(
            "0004_txn",
            "BEGIN; CREATE TABLE boatramp.sneaky (x int); COMMIT",
        ),
        3,
    )
    .await
    {
        SubstrateStepOutcome::Failed(msg) => assert!(
            msg.contains("BEGIN") || msg.contains("implicitly commits"),
            "a MySQL sql step may not carry its own transaction control: {msg}"
        ),
        other => panic!("expected txn-control refusal, got {other:?}"),
    }

    // --- a genuinely bad single-statement DDL is a clean per-step failure (no partial marker) ---
    match apply(
        &sub,
        &sql_step("0004_bad", "CREATE TABLE boatramp.bad (id nonsense_type)"),
        3,
    )
    .await
    {
        SubstrateStepOutcome::Failed(_) => {}
        other => panic!("expected a failed step for bad DDL, got {other:?}"),
    }

    // --- a good single-DDL step at ordinal 3 applies + records (proves apply resumes after the
    //     failed attempts at the same ordinal) ---
    assert!(matches!(
        apply(
            &sub,
            &sql_step(
                "0003_partial",
                "CREATE TABLE IF NOT EXISTS boatramp.gadget2 (id int)"
            ),
            2
        )
        .await,
        SubstrateStepOutcome::Applied
    ));

    // --- owner-DDL seam (the migrate-ddl backing): guards + a real DDL + a verification query ---
    let ddl = sub.owner_ddl("default", DB).await.unwrap();
    // S3: a ledger-DATABASE reference is refused (backtick-quoted, MySQL dialect).
    assert!(matches!(
        ddl.exec("SELECT * FROM `boatramp_migrations`.`schema_migrations`")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // S4: guest transaction control is refused.
    assert!(matches!(
        ddl.exec("BEGIN; CREATE TABLE boatramp.x(i int); COMMIT")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S4 (MySQL `#`-comment evasion): a COMMIT before a `#` line comment is real control; the MySQL
    // dialect tokenizer catches it where a generic scan might not.
    assert!(matches!(
        ddl.exec("DROP TABLE IF EXISTS boatramp.y; COMMIT # trailing")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S3 (comment evasion): a ledger reference hidden behind a block comment is still refused.
    assert!(matches!(
        ddl.exec("DROP TABLE /*x*/ `boatramp_migrations`.`schema_migrations`")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // S4 (MySQL executable-comment evasion, Security review CRITICAL-1): MySQL EXECUTES a
    // `/*! … */` comment body while the block-comment lexer would drop it, so a `/*! COMMIT */`
    // could smuggle transaction control past the S4 guard. It is refused (txn-control) — proving the
    // fix holds against a REAL MySQL that would actually run the comment.
    assert!(matches!(
        ddl.exec("CREATE TABLE z(a int); /*! COMMIT */")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S3 (MySQL executable-comment evasion, CRITICAL-1): a ledger write hidden in an executable
    // comment is refused (ledger-protected) — the sole barrier for the DDL identity on MySQL.
    assert!(matches!(
        ddl.exec("/*! DELETE FROM boatramp_migrations.schema_migrations */")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // Verify the executable-comment guard did NOT actually run `CREATE TABLE z` (the `/*! COMMIT */`
    // above was refused BEFORE the owner connection — no statement should have reached the wire).
    {
        let c = ddl_conn().await;
        let rows = c
            .run_query(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = 'boatramp' AND table_name = 'z'",
            )
            .await
            .unwrap();
        let n = match rows.rows.first().and_then(|r| r.first()) {
            Some(boatramp_core::sql::SqlValue::Integer(n)) => *n,
            other => panic!("unexpected tables count: {other:?}"),
        };
        assert_eq!(
            n, 0,
            "a refused executable-comment step must never touch the owner connection"
        );
    }
    // A plain owner DDL runs (auto-commit), and a verification query reads it back.
    ddl.exec("CREATE TABLE IF NOT EXISTS boatramp.owner_made (n int)")
        .await
        .unwrap();
    ddl.exec("INSERT INTO boatramp.owner_made (n) VALUES (7)")
        .await
        .unwrap();
    let rows = ddl
        .query("SELECT n FROM boatramp.owner_made ORDER BY n")
        .await
        .unwrap();
    assert_eq!(
        rows.rows.len(),
        1,
        "the DDL login sees the row it just wrote"
    );
    let _ = ddl.exec("DROP TABLE boatramp.owner_made").await;

    // --- baseline origin (U6): record without running reads back origin=baseline + no table ---
    let baselined = sql_step("0007_baselined", "CREATE TABLE boatramp.baselined (id int)");
    sub.record(
        "default",
        DB,
        &baselined,
        3,
        &baselined.content_hash(),
        LedgerOrigin::Baseline,
    )
    .await
    .unwrap();
    let after = sub.preflight("default", DB).await.unwrap();
    let row = after
        .iter()
        .find(|a| a.id == "0007_baselined")
        .expect("baselined row present");
    assert_eq!(row.origin, "baseline", "a baselined row is marked as such");
    {
        let c = ddl_conn().await;
        let rows = c
            .run_query(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = 'boatramp' AND table_name = 'baselined'",
            )
            .await
            .unwrap();
        let n = match rows.rows.first().and_then(|r| r.first()) {
            Some(boatramp_core::sql::SqlValue::Integer(n)) => *n,
            other => panic!("unexpected tables count: {other:?}"),
        };
        assert_eq!(n, 0, "baseline records without running the step");
    }

    // Final cleanup (direct DDL connection so it isn't ledgered).
    {
        let c = ddl_conn().await;
        for stmt in [
            "DROP DATABASE IF EXISTS boatramp_migrations",
            "DROP TABLE IF EXISTS boatramp.widget",
            "DROP TABLE IF EXISTS boatramp.gadget",
            "DROP TABLE IF EXISTS boatramp.gadget2",
            "DROP TABLE IF EXISTS boatramp.baselined",
            "DROP TABLE IF EXISTS boatramp.owner_made",
            "DROP TABLE IF EXISTS boatramp.z",
        ] {
            let _ = c.run_script(stmt).await;
        }
    }

    println!("MIGRATE MYSQL PARITY OK");
}
