//! **Live gate: the schema-migration SUBSTRATE on a real embedded libsql/SQLite file (backend
//! parity).**
//!
//! The embedded-libsql analog of `migrate_runner_sqlx_live` (Postgres) and `migrate_runner_mysql_live`
//! (MySQL). Drives the node-side [`MigrationSubstrate`] (`LibsqlMigrationRunner`, dispatched through
//! `DispatchMigrationRunner`) end to end against a **real embedded libsql file** and proves the libsql
//! parity contract — which is **backend-honest**: libsql's strength is transactional DDL, so unlike
//! MySQL a failed step rolls back CLEANLY.
//!
//! - **No owner/runtime split (N/A owner-role safety).** SQLite is a single-connection file — no
//!   roles, no RLS. The FILE is the trust boundary; there is no owner role to run DDL as and no
//!   `migration_url_env` analog. Stated plainly (not pretended). The guest still NEVER holds a DB
//!   credential/handle — every statement is host-mediated (asserted below via the owner-DDL seam).
//! - **preflight** creates the reserved-prefixed `boatramp_migrations_schema_migrations` ledger table
//!   in the site's own database and returns the applied rows in order.
//! - **apply / status** — a `sql` step applies + records its ledger row (supplied effective hash +
//!   `apply` origin); a second preflight reads the ledger back in order.
//! - **TRANSACTIONAL ROLLBACK (the libsql strength, INVERSE of MySQL)** — a multi-statement `sql` step
//!   whose 2nd statement errors leaves the 1st statement's effect **rolled back** and no ledger row.
//!   This is the opposite of the MySQL gate (which asserts a mid-DDL statement stays applied). We
//!   assert the 1st table is GONE (a clean recreate succeeds).
//! - **content-hash immutability signal** — the ledger records the effective hash the caller supplied.
//! - **`extension` step refused** — SQLite has no guest-loadable extension surface, so an `extension`
//!   step is a per-step failure; a raw `sql` step that `CREATE EXTENSION`s is likewise refused.
//! - **txn-control refusal under the SQLite dialect** — a transactional `sql` step carrying its own
//!   BEGIN/COMMIT is refused (it would desync the atomic wrapper); tokenized under sqlparser's
//!   `SQLiteDialect` (a `--`-comment can't hide a COMMIT).
//! - **owner-DDL seam guards (S3/S4)** — the `migrate-ddl` seam (the `function`-step backing) refuses
//!   a ledger-table reference and guest transaction control, and runs plain host-mediated DDL + a
//!   verification query. A compiled-guest `function` step needs a real orchestrator + wasm engine
//!   (covered by the server-side function-step gate on Postgres); here we drive the seam directly plus
//!   a `sql` step, per the task's "compiled guest if feasible, else a sql step".
//! - **baseline origin (U6)** — a `record(…, Baseline)` row reads back with `origin = "baseline"` and
//!   the step is NOT run.
//!
//! Needs no service container — an embedded libsql file under a temp dir. Runs on the **host**
//! toolchain (a static-musl test binary segfaults in libsql's bundled SQLite; see the orm-tenancy
//! gate), so it is wired into the host-glibc `test-orm-tenancy` CI job. Prints `MIGRATE LIBSQL PARITY
//! OK` (the CI grep marker).

#![cfg(feature = "migrate")]

use std::collections::BTreeMap;

use boatramp_core::sql::{
    LedgerOrigin, MigrateDdlError, MigrationAction, MigrationStep, MigrationSubstrate,
    SubstrateStepOutcome,
};
use boatramp_node::config::ExternalDatabaseConfig;
use boatramp_node::managed_sql::LibsqlMigrationRunner;

const DB: &str = "app";

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

/// Build the libsql substrate over a throwaway embedded file under a per-process temp dir.
fn runner_for() -> (LibsqlMigrationRunner, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "boatramp-migrate-libsql-live-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("app.db");
    let mut databases = BTreeMap::new();
    databases.insert(
        DB.to_string(),
        ExternalDatabaseConfig {
            kind: "libsql".to_string(),
            path: Some(path.clone()),
            ..Default::default()
        },
    );
    (LibsqlMigrationRunner::new(databases), path)
}

/// Apply a `sql`/`extension` step at `ordinal`, recording the intrinsic content hash (the effective
/// hash for these kinds) with the `apply` origin — the exact call the orchestrator makes.
async fn apply(
    sub: &LibsqlMigrationRunner,
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

/// A direct read against the same embedded file (out-of-band, not ledgered) — proves a table's
/// existence independent of the substrate.
async fn table_exists(path: &std::path::Path, table: &str) -> bool {
    use boatramp_core::sql::SqlBackend;
    let db = boatramp_storage::LibsqlSql::open_local(path).await.unwrap();
    let rows = db
        .run_query(&format!(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
        ))
        .await
        .unwrap();
    matches!(
        rows.rows.first().and_then(|r| r.first()),
        Some(boatramp_core::sql::SqlValue::Integer(n)) if *n == 1
    )
}

#[tokio::test]
async fn migrate_substrate_libsql_parity_on_a_real_embedded_file() {
    let (sub, path) = runner_for();

    // --- preflight on an empty ledger creates the ledger table + returns nothing ---
    let applied = sub.preflight("default", DB).await.unwrap();
    assert!(applied.is_empty(), "empty ledger");
    assert!(
        table_exists(&path, "boatramp_migrations_schema_migrations").await,
        "preflight created the reserved libsql ledger table"
    );

    // --- apply two sql steps in order; the ledger records them with origin=apply ---
    let s1 = sql_step(
        "0001_widget",
        "CREATE TABLE widget (id integer primary key, name text)",
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
        "the recorded hash is the effective hash the orchestrator supplied (immutability signal)"
    );

    // --- TRANSACTIONAL ROLLBACK (the libsql strength, INVERSE of the MySQL gate): a multi-statement
    //     step whose 2nd statement errors leaves the 1st statement's effect ROLLED BACK and no ledger
    //     row. On MySQL the 1st DDL would stay applied (PARTIALLY APPLIED); on SQLite it is undone. ---
    let atomic = sql_step(
        "0003_atomic",
        "CREATE TABLE gadget (id integer primary key); \
         CREATE TABLE gadget (id integer primary key)", // 2nd fails: table already exists
    );
    match apply(&sub, &atomic, 2).await {
        SubstrateStepOutcome::Failed(_) => {}
        other => panic!("expected a failed step for the mid-script error, got {other:?}"),
    }
    // Not recorded in the ledger…
    let after = sub.preflight("default", DB).await.unwrap();
    assert!(
        !after.iter().any(|a| a.id == "0003_atomic"),
        "a rolled-back step must not be recorded"
    );
    // …and the 1st statement's table was ROLLED BACK — it does NOT exist (the SQLite guarantee, the
    // opposite of MySQL's partial-apply where `gadget` would linger). A clean recreate proves it.
    assert!(
        !table_exists(&path, "gadget").await,
        "the 1st DDL of a failed multi-statement step is ROLLED BACK on libsql (transactional DDL)"
    );
    let fix = sql_step(
        "0003_atomic",
        "CREATE TABLE gadget (id integer primary key)",
    );
    assert!(
        matches!(apply(&sub, &fix, 2).await, SubstrateStepOutcome::Applied),
        "retry after a clean rollback applies (would fail if the 1st CREATE had leaked)"
    );

    // --- extension step is refused outright on libsql (no guest-loadable extension surface) ---
    match apply(&sub, &ext_step("0004_ext", "spellfix"), 3).await {
        SubstrateStepOutcome::Failed(msg) => assert!(
            msg.contains("libsql") || msg.contains("SQLite"),
            "an extension step is refused on libsql: {msg}"
        ),
        other => panic!("expected extension step refused on libsql, got {other:?}"),
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

    // --- a transactional sql step carrying its own BEGIN/COMMIT is refused under the SQLite dialect ---
    match apply(
        &sub,
        &sql_step("0004_txn", "BEGIN; CREATE TABLE sneaky (x integer); COMMIT"),
        3,
    )
    .await
    {
        SubstrateStepOutcome::Failed(msg) => assert!(
            msg.contains("BEGIN") || msg.contains("transaction"),
            "a transactional sql step may not carry its own BEGIN/COMMIT: {msg}"
        ),
        other => panic!("expected txn-control refusal, got {other:?}"),
    }
    // The txn-control refusal did NOT create `sneaky` (the whole step is refused before running).
    assert!(!table_exists(&path, "sneaky").await);

    // --- a sql step referencing the host-owned ledger table is refused ---
    assert!(matches!(
        apply(
            &sub,
            &sql_step(
                "0004_ledger",
                "INSERT INTO boatramp_migrations_schema_migrations (id) VALUES ('x')"
            ),
            3
        )
        .await,
        SubstrateStepOutcome::Failed(_)
    ));

    // --- comment-nesting evasion is REFUSED (task #490 re-review — it is NOT "fail-safe") ---
    // sqlparser's `SQLiteDialect` NESTS `/* … */`, but real SQLite does NOT (first `*/` closes), so
    // `/* a /* b */ <kw> -- */` is a VALID statement the engine EXECUTES (the trailing `-- */` is a
    // line comment, NOT a dangling `*/`) — verified live that a `CREATE TABLE` after such a comment
    // runs. So it is the SAME critical evasion as MySQL. The guard now strips comments NON-nesting, so
    // the hidden `COMMIT` is flagged and the whole step is refused BEFORE anything runs — `victim`
    // never gets created. (Mutation: revert the SQLite non-nesting strip and this leaks `victim`.)
    let hidden_commit = sql_step(
        "0004_nestcomment",
        "CREATE TABLE victim (x integer); /* a /* b */ COMMIT -- */",
    );
    match apply(&sub, &hidden_commit, 3).await {
        SubstrateStepOutcome::Failed(_) => {}
        other => {
            panic!("a nested-comment-hidden COMMIT must be REFUSED (txn control), got {other:?}")
        }
    }
    assert!(
        !table_exists(&path, "victim").await,
        "a refused nested-comment step must never run its CREATE (the hidden COMMIT is flagged)"
    );

    // --- owner-DDL seam (the migrate-ddl backing a function step): the guest NEVER holds a DB
    //     credential/handle — it calls exec/query and the HOST runs each statement (auto-commit) on
    //     the connection it owns. Guards fire host-side under the SQLite dialect. ---
    let ddl = sub.owner_ddl("default", DB).await.unwrap();
    // S3: a ledger-table reference is refused (bare + backtick-quoted, SQLite dialect).
    assert!(matches!(
        ddl.exec("SELECT * FROM boatramp_migrations_schema_migrations")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    assert!(matches!(
        ddl.exec("DROP TABLE `boatramp_migrations_schema_migrations`")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // S4: guest transaction control is refused.
    assert!(matches!(
        ddl.exec("BEGIN; CREATE TABLE x(i integer); COMMIT")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S4 (comment-evasion): a COMMIT before a `--` line comment is real control the tokenizer catches.
    assert!(matches!(
        ddl.exec("DROP TABLE IF EXISTS y; COMMIT -- sneak")
            .await
            .unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    // S4/S3 (task #490 re-review): SQLite is NON-nesting, so `/* a /* b */ <kw> -- */` EXECUTES on the
    // real engine — the guard (now a non-nesting comment strip) must refuse it, same as MySQL.
    assert!(matches!(
        ddl.exec("/* a /* b */ COMMIT -- */").await.unwrap_err(),
        MigrateDdlError::TxnControl
    ));
    assert!(matches!(
        ddl.exec("/* a /* b */ DROP TABLE boatramp_migrations_schema_migrations -- */")
            .await
            .unwrap_err(),
        MigrateDdlError::LedgerProtected
    ));
    // A plain host-mediated DDL runs (auto-commit), and a verification query reads it back.
    ddl.exec("CREATE TABLE IF NOT EXISTS owner_made (n integer)")
        .await
        .unwrap();
    ddl.exec("INSERT INTO owner_made (n) VALUES (7)")
        .await
        .unwrap();
    let rows = ddl
        .query("SELECT n FROM owner_made ORDER BY n")
        .await
        .unwrap();
    assert_eq!(
        rows.rows.len(),
        1,
        "the host-mediated seam sees the row it just wrote"
    );

    // --- baseline origin (U6): record without running reads back origin=baseline + no table ---
    let baselined = sql_step("0007_baselined", "CREATE TABLE baselined (id integer)");
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
    assert!(
        !table_exists(&path, "baselined").await,
        "baseline records without running the step"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(path.parent().unwrap());

    println!("MIGRATE LIBSQL PARITY OK");
}
