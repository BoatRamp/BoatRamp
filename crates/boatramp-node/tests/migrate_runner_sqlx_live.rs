//! **Live gate: the schema-migration SUBSTRATE on a real Postgres.**
//!
//! Drives the node-side [`MigrationSubstrate`] (the `NodeMigrationRunner`) end to end against a real
//! Postgres (via a bring-your-own-URL managed binding, so no compute/resolver stack is needed) and
//! proves the substrate contract the server-side orchestrator relies on:
//!
//! - **preflight** ensures the ledger and returns the applied rows in order;
//! - **apply_substrate_step** applies a `sql`/`extension` step + records its ledger row (with the
//!   supplied effective hash + `apply` origin), atomically for a transactional step;
//! - **atomic per step** — a step whose (multi-statement) script errors mid-way leaves NO schema
//!   change AND NO ledger row (the whole `BEGIN … COMMIT` rolled back);
//! - **extension allowlist** — an allowlisted `Extension` step applies; a non-allowlisted one and a
//!   raw `sql` step that `CREATE EXTENSION`s are per-step failures;
//! - **transaction-control refusal** — a transactional `sql` step carrying its own BEGIN/COMMIT is
//!   refused (it would desync the atomic wrapper);
//! - **owner-DDL guards (S3/S4)** — the `migrate-ddl` seam refuses a ledger-schema reference and
//!   guest transaction control, and runs plain owner DDL + a verification query;
//! - **baseline origin (U6)** — a `record(…, Baseline)` row reads back with `origin = "baseline"`.
//!
//! The server-side orchestrator adds the prefix-consistency / content-hash / function-step /
//! context-gate / RLS-invariant / bundle gates on top (see the server live gates). Requires
//! `BOATRAMP_TEST_PG_URL` (skips when unset). Prints `MIGRATE RUNNER LEDGER OK [postgres]`.

#![cfg(all(feature = "sql-postgres", feature = "migrate"))]

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
use boatramp_storage::FsStorage;

const DB: &str = "app";
const URL_ENV: &str = "BOATRAMP_MIGRATE_RUNNER_TEST_URL";

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

fn runner_for() -> Option<NodeMigrationRunner> {
    let url = std::env::var("BOATRAMP_TEST_PG_URL").ok()?;
    // The runner reads the connection URL from `url_env`; inject it via a MapEnv (never mutate
    // the process environment) pointed at the same PG.
    let env = boatramp_core::env::MapEnv::new().with(URL_ENV, url);
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
    let op = Arc::new(
        NodeOperatorSql::new(
            databases,
            Arc::new(MemoryKv::new()),
            None,
            DeployStore::new(
                Arc::new(FsStorage::new(
                    std::env::temp_dir().join("boatramp-migrate-test"),
                )),
                Arc::new(MemoryKv::new()),
            ),
        )
        .with_env_source(Arc::new(env)),
    );
    let mut allow = std::collections::BTreeSet::new();
    allow.insert("citext".to_string());
    Some(NodeMigrationRunner::new(op, allow))
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

#[tokio::test]
async fn migrate_substrate_ledger_atomicity_and_owner_ddl_on_a_real_engine() {
    let Some(sub) = runner_for() else {
        eprintln!("skip migrate_substrate: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    // Clean slate (re-runnable): drop the ledger schema + test tables via a DIRECT connection.
    {
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
        let url = std::env::var("BOATRAMP_TEST_PG_URL").unwrap();
        let c = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
        for stmt in [
            "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE",
            "DROP TABLE IF EXISTS widget",
            "DROP TABLE IF EXISTS gadget",
            "DROP TABLE IF EXISTS baselined",
        ] {
            let _ = c.run_script(stmt).await;
        }
    }

    // --- preflight on an empty ledger returns nothing ---
    let applied = sub.preflight("default", DB).await.unwrap();
    assert!(applied.is_empty(), "empty ledger");

    // --- apply two sql steps in order; the ledger records them with origin=apply ---
    let s1 = sql_step(
        "0001_widget",
        "CREATE TABLE widget (id int primary key, name text)",
    );
    let s2 = sql_step("0002_seed", "INSERT INTO widget (id, name) VALUES (1, 'a')");
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
        "the recorded hash is the effective hash the orchestrator supplied"
    );

    // --- atomic per-step: a step whose 2nd statement errors leaves NO table + NO ledger row ---
    let bad = sql_step(
        "0003_atomic",
        "CREATE TABLE gadget (id int primary key); INSERT INTO gadget (id) VALUES ('not-an-int')",
    );
    assert!(
        matches!(apply(&sub, &bad, 2).await, SubstrateStepOutcome::Failed(_)),
        "a mid-script error is a per-step failure"
    );
    let after = sub.preflight("default", DB).await.unwrap();
    assert!(
        !after.iter().any(|a| a.id == "0003_atomic"),
        "a rolled-back step must not be recorded"
    );
    // gadget must be gone → a clean recreate succeeds (would fail if it lingered).
    let fix = sql_step("0003_atomic", "CREATE TABLE gadget (id int primary key)");
    assert!(
        matches!(apply(&sub, &fix, 2).await, SubstrateStepOutcome::Applied),
        "retry after rollback applies cleanly"
    );

    // --- extension allowlist: allowlisted applies; non-allowlisted refused ---
    assert!(matches!(
        apply(&sub, &ext_step("0004_citext", "citext"), 3).await,
        SubstrateStepOutcome::Applied
    ));
    assert!(
        matches!(
            apply(&sub, &ext_step("0005_dblink", "dblink"), 4).await,
            SubstrateStepOutcome::Failed(_)
        ),
        "a non-allowlisted extension is a per-step failure"
    );

    // --- raw CREATE EXTENSION in a sql step is refused ---
    assert!(matches!(
        apply(
            &sub,
            &sql_step("0005_raw", "CREATE EXTENSION IF NOT EXISTS pgcrypto"),
            4
        )
        .await,
        SubstrateStepOutcome::Failed(_)
    ));

    // --- a transactional sql step carrying its own BEGIN/COMMIT is refused ---
    assert!(matches!(
        apply(
            &sub,
            &sql_step("0006_txn", "BEGIN; CREATE TABLE sneaky (x int); COMMIT;"),
            4
        )
        .await,
        SubstrateStepOutcome::Failed(_)
    ));

    // --- owner-DDL seam (the migrate-ddl backing): guards + a real DDL + a verification query ---
    let ddl = sub.owner_ddl("default", DB).await.unwrap();
    // S3: a ledger-schema reference is refused.
    assert!(matches!(
        ddl.exec("SELECT * FROM boatramp_migrations.schema_migrations")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // S4: guest transaction control is refused.
    assert!(matches!(
        ddl.exec("BEGIN; CREATE TABLE x(i int); COMMIT")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S4 (comment-evasion, Security review HIGH-1): a trailing-comment COMMIT that a byte scan
    // missed but Postgres executes is refused by the tokenizer guard on the REAL seam.
    assert!(matches!(
        ddl.exec("CREATE TABLE y(i int); COMMIT-- sneak")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S3 (comment-evasion): a ledger reference hidden behind a block comment is still refused.
    assert!(matches!(
        ddl.exec("DROP TABLE /*x*/ boatramp_migrations.schema_migrations")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // A plain owner DDL runs (auto-commit), and a verification query reads it back as owner.
    ddl.exec("CREATE TABLE IF NOT EXISTS owner_made (n int)")
        .await
        .unwrap();
    ddl.exec("INSERT INTO owner_made (n) VALUES (7)")
        .await
        .unwrap();
    let rows = ddl
        .query("SELECT n FROM owner_made ORDER BY n")
        .await
        .unwrap();
    assert_eq!(rows.rows.len(), 1, "the owner sees the row it just wrote");
    let _ = ddl.exec("DROP TABLE owner_made").await;

    // --- baseline origin (U6): record without running reads back origin=baseline ---
    let baselined = sql_step("0007_baselined", "CREATE TABLE baselined (id int)");
    sub.record(
        "default",
        DB,
        &baselined,
        4,
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
    // ...and the table was NOT created (record runs nothing).
    {
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
        let url = std::env::var("BOATRAMP_TEST_PG_URL").unwrap();
        let c = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
        let exists = c
            .run_query("SELECT to_regclass('public.baselined') IS NOT NULL AS e")
            .await
            .unwrap();
        // to_regclass returns NULL (→ false) when the table was never created.
        assert!(
            matches!(
                exists.rows.first().and_then(|r| r.first()),
                Some(boatramp_core::sql::SqlValue::Boolean(false))
                    | Some(boatramp_core::sql::SqlValue::Null)
            ),
            "baseline records without running the step"
        );
    }

    // Final cleanup (direct connection so it isn't ledgered).
    {
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
        let url = std::env::var("BOATRAMP_TEST_PG_URL").unwrap();
        let c = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
        for stmt in [
            "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE",
            "DROP TABLE IF EXISTS widget",
            "DROP TABLE IF EXISTS gadget",
            "DROP TABLE IF EXISTS baselined",
        ] {
            let _ = c.run_script(stmt).await;
        }
    }

    println!("MIGRATE RUNNER LEDGER OK [postgres]");
}
