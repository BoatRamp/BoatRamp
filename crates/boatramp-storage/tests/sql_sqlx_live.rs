//! Live round-trip coverage for the external Postgres/MySQL [`SqlBackend`]s
//! (the bring-your-own-database path). **Env-gated**: each test skips cleanly
//! when its `BOATRAMP_TEST_*_URL` is unset, so `cargo test` is green without a
//! database. The pure value classifiers are covered unconditionally by the unit
//! tests in `src/sql_sqlx.rs`; this exercises real connect → transaction →
//! marshalling → read-only enforcement against a live engine.
//!
//! Bring a database up with the dev recipes (`just pg` / `just mysql` print the
//! URL) and run:
//! ```sh
//! just pg
//! BOATRAMP_TEST_PG_URL=postgres://boatramp:boatramp@localhost:5432/boatramp \
//!   cargo test -p boatramp-storage --features sql-postgres --test sql_sqlx_live -- --nocapture
//!
//! just mysql
//! BOATRAMP_TEST_MYSQL_URL=mysql://boatramp:boatramp@localhost:3306/boatramp \
//!   cargo test -p boatramp-storage --features sql-mysql --test sql_sqlx_live -- --nocapture
//! ```
#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

#[allow(unused_imports)]
use boatramp_core::sql::{SqlError, SqlValue};
#[allow(unused_imports)]
use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};

/// The external Postgres backend: create a table, round-trip every value class,
/// classify a syntax error, and prove a `read_only` backend rejects writes.
#[cfg(feature = "sql-postgres")]
#[tokio::test]
async fn postgres_round_trip() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip postgres_round_trip: BOATRAMP_TEST_PG_URL unset");
        return;
    };

    let backend = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(url.clone()),
    )
    .unwrap();

    let mut tx = backend.begin().await.unwrap();
    tx.execute("DROP TABLE IF EXISTS bramp_ext_test", &[])
        .await
        .unwrap();
    tx.execute(
        "CREATE TABLE bramp_ext_test \
         (id INT, name TEXT, flag BOOL, ratio FLOAT8, payload BYTEA, note TEXT)",
        &[],
    )
    .await
    .unwrap();
    let affected = tx
        .execute(
            "INSERT INTO bramp_ext_test VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                SqlValue::Integer(1),
                SqlValue::Text("alpha".into()),
                SqlValue::Boolean(true),
                SqlValue::Real(1.5),
                SqlValue::Blob(vec![1, 2, 3]),
                SqlValue::Null,
            ],
        )
        .await
        .unwrap();
    assert_eq!(affected, 1);
    tx.commit().await.unwrap();

    let mut tx = backend.begin().await.unwrap();
    let rows = tx
        .query(
            "SELECT id, name, flag, ratio, payload, note FROM bramp_ext_test ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        rows.columns,
        ["id", "name", "flag", "ratio", "payload", "note"]
    );
    assert_eq!(
        rows.rows[0],
        vec![
            SqlValue::Integer(1),
            SqlValue::Text("alpha".into()),
            SqlValue::Boolean(true),
            SqlValue::Real(1.5),
            SqlValue::Blob(vec![1, 2, 3]),
            SqlValue::Null,
        ]
    );

    // Rich types stringify into `text`.
    let mut tx = backend.begin().await.unwrap();
    let rows = tx
        .query(
            "SELECT '2026-07-15 12:00:00'::timestamp AS ts, '{\"a\":1}'::jsonb AS doc, 3.14::numeric AS n",
            &[],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(&rows.rows[0][0], SqlValue::Text(s) if s.contains("2026-07-15")));
    assert!(matches!(&rows.rows[0][1], SqlValue::Text(s) if s.contains("\"a\"")));
    assert_eq!(rows.rows[0][2], SqlValue::Text("3.14".into()));

    // A syntax error classifies as Syntax (SQLSTATE 42xxx).
    let mut tx = backend.begin().await.unwrap();
    let err = tx.query("SELECT * FROM", &[]).await.unwrap_err();
    assert!(matches!(err, SqlError::Syntax(_)), "got {err:?}");
    tx.rollback().await.unwrap();

    // A read-only backend rejects writes at the engine.
    let ro = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(url).read_only(true),
    )
    .unwrap();
    let mut tx = ro.begin().await.unwrap();
    let err = tx
        .execute(
            "INSERT INTO bramp_ext_test VALUES (2, 'x', false, 0, '', NULL)",
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SqlError::Other(_)), "got {err:?}");
    tx.rollback().await.unwrap();
}

/// The external MySQL backend: same round-trip. MySQL has no native `BOOL`
/// (`TINYINT(1)`), so a boolean reads back as the integer `1`.
#[cfg(feature = "sql-mysql")]
#[tokio::test]
async fn mysql_round_trip() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("skip mysql_round_trip: BOATRAMP_TEST_MYSQL_URL unset");
        return;
    };

    let backend = connect(
        ExternalSqlKind::Mysql,
        &ExternalSqlOptions::new(url.clone()),
    )
    .unwrap();

    let mut tx = backend.begin().await.unwrap();
    tx.execute("DROP TABLE IF EXISTS bramp_ext_test", &[])
        .await
        .unwrap();
    tx.execute(
        "CREATE TABLE bramp_ext_test \
         (id INT, name VARCHAR(64), flag TINYINT, ratio DOUBLE, payload BLOB, note VARCHAR(64))",
        &[],
    )
    .await
    .unwrap();
    let affected = tx
        .execute(
            "INSERT INTO bramp_ext_test VALUES (?, ?, ?, ?, ?, ?)",
            &[
                SqlValue::Integer(1),
                SqlValue::Text("alpha".into()),
                SqlValue::Boolean(true),
                SqlValue::Real(1.5),
                SqlValue::Blob(vec![1, 2, 3]),
                SqlValue::Null,
            ],
        )
        .await
        .unwrap();
    assert_eq!(affected, 1);
    tx.commit().await.unwrap();

    let mut tx = backend.begin().await.unwrap();
    let rows = tx
        .query(
            "SELECT id, name, flag, ratio, payload, note FROM bramp_ext_test ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        rows.columns,
        ["id", "name", "flag", "ratio", "payload", "note"]
    );
    assert_eq!(
        rows.rows[0],
        vec![
            SqlValue::Integer(1),
            SqlValue::Text("alpha".into()),
            // MySQL bool is TINYINT — an integer 0/1 in the value vocabulary.
            SqlValue::Integer(1),
            SqlValue::Real(1.5),
            SqlValue::Blob(vec![1, 2, 3]),
            SqlValue::Null,
        ]
    );

    // JSON stringifies into `text`.
    let mut tx = backend.begin().await.unwrap();
    let rows = tx
        .query("SELECT CAST('{\"a\":1}' AS JSON) AS doc", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(&rows.rows[0][0], SqlValue::Text(s) if s.contains("\"a\"")));

    // A read-only backend rejects writes at the engine.
    let ro = connect(
        ExternalSqlKind::Mysql,
        &ExternalSqlOptions::new(url).read_only(true),
    )
    .unwrap();
    let mut tx = ro.begin().await.unwrap();
    let err = tx
        .execute(
            "INSERT INTO bramp_ext_test VALUES (2, 'x', 0, 0, '', NULL)",
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SqlError::Other(_)), "got {err:?}");
    tx.rollback().await.unwrap();
}
