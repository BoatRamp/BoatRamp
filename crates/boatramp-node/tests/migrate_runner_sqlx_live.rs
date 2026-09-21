//! **Live gate: the schema-migration runner on a real Postgres.**
//!
//! Drives [`NodeMigrationRunner`] end to end against a real Postgres (via a bring-your-own-URL
//! managed binding, so no compute/resolver stack is needed) and proves the ledger contract:
//!
//! - **dry-run** reports the pending ids without applying;
//! - **apply** applies the pending suffix in order and records the ledger; a **re-apply** is an
//!   idempotent no-op (already-applied);
//! - **atomic per step** — a step whose (multi-statement) script errors mid-way leaves NO schema
//!   change AND NO ledger row (the whole `BEGIN … COMMIT` rolled back); a re-apply then retries;
//! - **content-hash immutability** — re-submitting an applied id with a changed body is refused;
//! - **prefix-divergence** — a reordered set is refused fail-closed;
//! - **extension allowlist** — an allowlisted `Extension` step applies; a non-allowlisted one and a
//!   raw `sql` step that `CREATE EXTENSION`s are refused (per-step failures).
//!
//! Requires `BOATRAMP_TEST_PG_URL` (skips when unset). Prints `MIGRATE RUNNER LEDGER OK [postgres]`.

#![cfg(feature = "sql-postgres")]

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::MemoryKv;
use boatramp_core::sql::{MigrationAction, MigrationRunner, MigrationStep};
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
    // The runner reads the connection URL from `url_env`; point it at the same PG.
    std::env::set_var(URL_ENV, &url);
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
    let op = Arc::new(NodeOperatorSql::new(
        databases,
        Arc::new(MemoryKv::new()),
        None,
        DeployStore::new(
            Arc::new(FsStorage::new(
                std::env::temp_dir().join("boatramp-migrate-test"),
            )),
            Arc::new(MemoryKv::new()),
        ),
    ));
    let mut allow = std::collections::BTreeSet::new();
    allow.insert("citext".to_string());
    Some(NodeMigrationRunner::new(op, allow))
}

#[tokio::test]
async fn migrate_runner_ledger_and_atomicity_on_a_real_engine() {
    let Some(runner) = runner_for() else {
        eprintln!("skip migrate_runner: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    // Clean slate (re-runnable): drop the ledger schema + test tables via a DIRECT connection, so
    // the runner starts against a truly empty ledger (cleaning up through the runner would record
    // the cleanup steps and pollute it).
    {
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
        let url = std::env::var("BOATRAMP_TEST_PG_URL").unwrap();
        let c = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
        for stmt in [
            "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE",
            "DROP TABLE IF EXISTS widget",
            "DROP TABLE IF EXISTS gadget",
        ] {
            let _ = c.run_script(stmt).await;
        }
    }

    // --- dry-run: reports pending, applies nothing ---
    let set = vec![
        sql_step(
            "0001_widget",
            "CREATE TABLE widget (id int primary key, name text)",
        ),
        sql_step("0002_seed", "INSERT INTO widget (id, name) VALUES (1, 'a')"),
    ];
    let plan = runner.apply("default", DB, &set, true).await.unwrap();
    assert_eq!(plan.pending, vec!["0001_widget", "0002_seed"]);
    assert!(plan.newly_applied.is_empty(), "dry-run applies nothing");

    // --- apply: both applied, in order ---
    let rep = runner.apply("default", DB, &set, false).await.unwrap();
    assert_eq!(rep.newly_applied, vec!["0001_widget", "0002_seed"]);
    assert!(rep.failed.is_none());

    // --- re-apply: idempotent no-op ---
    let rep2 = runner.apply("default", DB, &set, false).await.unwrap();
    assert!(
        rep2.newly_applied.is_empty(),
        "re-apply applies nothing new"
    );
    assert_eq!(rep2.already_applied, vec!["0001_widget", "0002_seed"]);

    // --- status reflects the ledger ---
    let st = runner.status("default", DB).await.unwrap();
    assert_eq!(
        st.applied.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
        vec!["0001_widget", "0002_seed"]
    );

    // --- content-hash immutability: same id, changed body → refused (checked while exactly the
    //     2-step prefix is applied, so this is a content mismatch, not a length divergence) ---
    let tampered = [
        set[0].clone(),
        sql_step(
            "0002_seed",
            "INSERT INTO widget (id, name) VALUES (2, 'CHANGED')",
        ),
    ];
    let err = runner
        .apply("default", DB, &tampered, false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, boatramp_core::sql::MigrationError::ContentChanged(_)),
        "a changed applied migration body is refused, got {err:?}"
    );

    // --- prefix-divergence: reordered applied prefix → refused ---
    let reordered = [set[1].clone(), set[0].clone()];
    let err2 = runner
        .apply("default", DB, &reordered, false)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err2,
            boatramp_core::sql::MigrationError::PrefixDivergence(_)
        ),
        "a reordered set is refused, got {err2:?}"
    );

    // --- atomic per-step: a step whose 2nd statement errors leaves NO table + NO ledger row ---
    let bad = [
        set[0].clone(),
        set[1].clone(),
        sql_step(
            "0003_atomic",
            "CREATE TABLE gadget (id int primary key); INSERT INTO gadget (id) VALUES ('not-an-int')",
        ),
    ];
    let rep3 = runner.apply("default", DB, &bad, false).await.unwrap();
    assert_eq!(
        rep3.failed.as_ref().map(|f| f.id.as_str()),
        Some("0003_atomic"),
        "the failing step is reported"
    );
    // The gadget table must NOT exist (the CREATE rolled back with the failing INSERT), and 0003 is
    // NOT in the ledger — proven by a dry-run showing it still pending + a status without it.
    let after = runner.status("default", DB).await.unwrap();
    assert!(
        !after.applied.iter().any(|a| a.id == "0003_atomic"),
        "a rolled-back step must not be recorded"
    );
    // gadget must be gone → recreating it in a fresh step must succeed (would fail if it lingered).
    let fix = [
        set[0].clone(),
        set[1].clone(),
        sql_step("0003_atomic", "CREATE TABLE gadget (id int primary key)"),
    ];
    let rep_fix = runner.apply("default", DB, &fix, false).await.unwrap();
    assert_eq!(
        rep_fix.newly_applied,
        vec!["0003_atomic"],
        "retry after rollback applies cleanly"
    );

    // --- extension allowlist: allowlisted applies; non-allowlisted + raw CREATE EXTENSION refused ---
    let with_ext = [
        set[0].clone(),
        set[1].clone(),
        sql_step("0003_atomic", "CREATE TABLE gadget (id int primary key)"),
        ext_step("0004_citext", "citext"),
    ];
    let rep_ext = runner.apply("default", DB, &with_ext, false).await.unwrap();
    assert_eq!(
        rep_ext.newly_applied,
        vec!["0004_citext"],
        "allowlisted extension applies"
    );

    let bad_ext = [
        set[0].clone(),
        set[1].clone(),
        sql_step("0003_atomic", "CREATE TABLE gadget (id int primary key)"),
        ext_step("0004_citext", "citext"),
        ext_step("0005_dblink", "dblink"),
    ];
    let rep_bad = runner.apply("default", DB, &bad_ext, false).await.unwrap();
    assert_eq!(
        rep_bad.failed.as_ref().map(|f| f.id.as_str()),
        Some("0005_dblink"),
        "a non-allowlisted extension is refused (per-step failure)"
    );

    let raw_ext = [
        set[0].clone(),
        set[1].clone(),
        sql_step("0003_atomic", "CREATE TABLE gadget (id int primary key)"),
        ext_step("0004_citext", "citext"),
        sql_step("0005_raw", "CREATE EXTENSION IF NOT EXISTS pgcrypto"),
    ];
    let rep_raw = runner.apply("default", DB, &raw_ext, false).await.unwrap();
    assert_eq!(
        rep_raw.failed.as_ref().map(|f| f.id.as_str()),
        Some("0005_raw"),
        "a raw sql step that CREATE EXTENSIONs is refused (per-step failure)"
    );

    // --- a transactional sql step carrying its own BEGIN/COMMIT is refused (would desync the
    //     atomic wrapper) — a per-step failure, not applied. ---
    let txn_ctrl = [
        set[0].clone(),
        set[1].clone(),
        sql_step("0003_atomic", "CREATE TABLE gadget (id int primary key)"),
        ext_step("0004_citext", "citext"),
        sql_step("0006_txn", "BEGIN; CREATE TABLE sneaky (x int); COMMIT;"),
    ];
    let rep_txn = runner.apply("default", DB, &txn_ctrl, false).await.unwrap();
    assert_eq!(
        rep_txn.failed.as_ref().map(|f| f.id.as_str()),
        Some("0006_txn"),
        "a transactional step with its own BEGIN/COMMIT is refused"
    );

    // Final cleanup.
    let _ = runner
        .apply(
            "default",
            DB,
            &[sql_step("z", "DROP SCHEMA IF EXISTS boatramp_migrations CASCADE; DROP TABLE IF EXISTS widget; DROP TABLE IF EXISTS gadget;")],
            false,
        )
        .await;

    println!("MIGRATE RUNNER LEDGER OK [postgres]");
}
