//! **Live gate: ownership-safe per-replica DYNAMIC credentials — the MySQL analogue.**
//!
//! MySQL has NO object ownership, so the Postgres orphaning hazard does not exist: a
//! dynamic user is grant-based ([`mint_dynamic_role_ddl`] grants `ALL PRIVILEGES ON
//! <db>.*`, DDL included) and drops cleanly with `DROP USER` ([`drop_dynamic_role_ddl`]),
//! nothing to orphan. This gate proves on a REAL MySQL:
//!
//! 1. a minted dynamic user does DDL + DML in its tenant database;
//! 2. it is CONFINED to that database (a second database it was not granted is unreachable);
//! 3. it drops cleanly and the DATA SURVIVES the user drop (owned by no one);
//! 4. a FRESH dynamic user minted afterwards has identical access to that data.
//!
//! Requires `BOATRAMP_TEST_MYSQL_URL` = a **root** MySQL URL (skips cleanly when unset).
//! Marked `#[ignore]`. Prints `DYNAMIC CRED OWNERSHIP OK [mysql]` on success.

#![cfg(feature = "sql-mysql")]

use std::sync::Arc;

use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{drop_dynamic_role_ddl, mint_dynamic_role_ddl};

const DB: &str = "dyn_myappdb";
const OTHER_DB: &str = "dyn_other"; // a database the dynamic user is NOT granted
const DYN1: &str = "dyn_myappdb_d0";
const DYN1_PW: &str = "d1pw";
const DYN2: &str = "dyn_myappdb_d0_b";
const DYN2_PW: &str = "d2pw";
const OWNER: &str = "inert_owner"; // inert on MySQL (no object ownership)

fn as_role(root_url: &str, user: &str, pw: &str, db: &str) -> String {
    let (scheme, rest) = root_url.split_once("://").expect("url has scheme");
    let after_at = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
    let (hostport, _tail) = after_at.split_once('/').unwrap_or((after_at, ""));
    format!("{scheme}://{user}:{pw}@{hostport}/{db}")
}

async fn probe(be: &Arc<dyn SqlBackend>, sql: &str) -> String {
    let rows = be
        .run_query(sql)
        .await
        .unwrap_or_else(|e| panic!("probe `{sql}`: {e}"));
    match rows.rows.into_iter().flatten().next() {
        Some(SqlValue::Text(s)) => s,
        Some(SqlValue::Boolean(b)) => b.to_string(),
        Some(SqlValue::Integer(n)) => n.to_string(),
        other => panic!("probe `{sql}` returned unexpected cell {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a live root MySQL via BOATRAMP_TEST_MYSQL_URL (run on lighthouse / the live CI lane)"]
async fn dynamic_cred_lifecycle_is_clean_on_a_real_mysql() {
    let Ok(root_url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("skip dynamic_cred mysql: BOATRAMP_TEST_MYSQL_URL unset");
        return;
    };
    let k = ExternalSqlKind::Mysql;
    let root = connect(k, &ExternalSqlOptions::new(root_url.clone())).unwrap();

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP USER IF EXISTS '{DYN1}'@'%'"),
        format!("DROP USER IF EXISTS '{DYN2}'@'%'"),
        format!("DROP DATABASE IF EXISTS `{DB}`"),
        format!("DROP DATABASE IF EXISTS `{OTHER_DB}`"),
    ] {
        let _ = root.run_script(&stmt).await;
    }
    root.run_script(&format!("CREATE DATABASE `{DB}`"))
        .await
        .unwrap();
    root.run_script(&format!("CREATE DATABASE `{OTHER_DB}`"))
        .await
        .unwrap();

    // === 1. mint DYN1, do DDL + DML in the tenant db ===
    for stmt in mint_dynamic_role_ddl(k, DB, OWNER, DYN1, DYN1_PW) {
        root.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("mint dyn1 `{stmt}`: {e}"));
    }
    let dyn1 = connect(
        k,
        &ExternalSqlOptions::new(as_role(&root_url, DYN1, DYN1_PW, DB)),
    )
    .unwrap();
    for stmt in [
        "CREATE TABLE t1 (id int PRIMARY KEY AUTO_INCREMENT, v varchar(32))",
        "INSERT INTO t1 (v) VALUES ('from-dyn1')",
    ] {
        dyn1.run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("dyn1 DDL/DML `{stmt}`: {e}"));
    }

    // === 2. CONFINEMENT: dyn1 must NOT reach the database it was not granted ===
    assert!(
        dyn1.run_script(&format!("CREATE TABLE `{OTHER_DB}`.leak (id int)"))
            .await
            .is_err(),
        "the dynamic user must be confined to its tenant db (db.* grant is the boundary)"
    );

    // === 3. drop DYN1 cleanly; the DATA survives (owned by no one) ===
    for stmt in drop_dynamic_role_ddl(k, DYN1, OWNER) {
        root.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("drop dyn1 `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(
            &root,
            &format!("SELECT (NOT EXISTS (SELECT 1 FROM mysql.user WHERE user='{DYN1}'))")
        )
        .await,
        "1",
        "dyn1 must be fully dropped"
    );
    assert_eq!(
        probe(&root, &format!("SELECT COUNT(*) FROM `{DB}`.t1")).await,
        "1",
        "the tenant data must survive the user drop"
    );

    // === 4. a FRESH dynamic user has identical access to the surviving data ===
    for stmt in mint_dynamic_role_ddl(k, DB, OWNER, DYN2, DYN2_PW) {
        root.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("mint dyn2 `{stmt}`: {e}"));
    }
    let dyn2 = connect(
        k,
        &ExternalSqlOptions::new(as_role(&root_url, DYN2, DYN2_PW, DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&dyn2, "SELECT COUNT(*) FROM t1").await,
        "1",
        "the fresh dynamic user must read the prior user's data"
    );
    for stmt in [
        "ALTER TABLE t1 ADD COLUMN w int",
        "INSERT INTO t1 (v, w) VALUES ('from-dyn2', 7)",
        "CREATE TABLE t2 (id int)",
        "DROP TABLE t2",
    ] {
        dyn2.run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("dyn2 identical-access `{stmt}`: {e}"));
    }
    for stmt in drop_dynamic_role_ddl(k, DYN2, OWNER) {
        let _ = root.run_script(&stmt).await;
    }

    // Teardown (best-effort).
    for stmt in [
        format!("DROP DATABASE IF EXISTS `{DB}`"),
        format!("DROP DATABASE IF EXISTS `{OTHER_DB}`"),
    ] {
        let _ = root.run_script(&stmt).await;
    }

    println!("DYNAMIC CRED OWNERSHIP OK [mysql]");
}
