//! Integration coverage for the libsql [`SqlBackend`] against a real **remote
//! sqld** server (the cluster path). Env-gated: it skips cleanly when
//! `BOATRAMP_TEST_LIBSQL_URL` isn't set, so `cargo test` is green without
//! infrastructure. (Local-file mode is covered unconditionally by the unit test
//! in `src/sql_libsql.rs`.)
//!
//! Run against a local sqld (the dev shell provides one — `just sqld` prints the
//! URLs). The per-site factory test additionally needs the admin API URL
//! (`just sqld` enables namespaces + the admin port):
//! ```sh
//! just sqld
//! # Use the `localhost` hostname, not 127.0.0.1: with namespaces enabled sqld
//! # routes by the Host subdomain, so the per-site factory needs `<ns>.localhost`
//! # to resolve (you can't subdomain a bare IP), and a plain `localhost` falls
//! # back to the default namespace for the round-trip test.
//! BOATRAMP_TEST_LIBSQL_URL=http://localhost:8080 \
//! BOATRAMP_TEST_LIBSQL_ADMIN_URL=http://localhost:9090 \
//!   cargo test -p boatramp-storage --features sql --test sql_libsql -- --nocapture
//! ```
#![cfg(feature = "sql")]

use boatramp_core::sql::{SqlBackend, SqlBackends, SqlValue};
use boatramp_storage::{LibsqlSql, LibsqlSqlBackends};

/// The single-node factory path (no server): each site gets its own embedded
/// database **file**, so the same table name in two sites holds different data,
/// and a site's named database is separate from its default. Runs unconditionally.
#[tokio::test]
async fn factory_local_gives_each_site_its_own_file() {
    let dir = std::env::temp_dir().join(format!("boatramp-libsql-factory-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let backends = LibsqlSqlBackends::local(&dir);

    async fn write_secret(db: &dyn SqlBackend, value: &str) {
        let mut tx = db.begin().await.unwrap();
        tx.execute("CREATE TABLE IF NOT EXISTS secrets (v TEXT)", &[])
            .await
            .unwrap();
        tx.execute("DELETE FROM secrets", &[]).await.unwrap();
        tx.execute(
            "INSERT INTO secrets VALUES (?1)",
            &[SqlValue::Text(value.into())],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    async fn read_secret(db: &dyn SqlBackend) -> Vec<SqlValue> {
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query("SELECT v FROM secrets", &[]).await.unwrap();
        tx.commit().await.unwrap();
        rows.rows.into_iter().flatten().collect()
    }

    let alpha = backends.database("alpha", "").await.unwrap();
    let beta = backends.database("beta", "").await.unwrap();
    write_secret(alpha.as_ref(), "alpha-secret").await;
    write_secret(beta.as_ref(), "beta-secret").await;
    assert_eq!(
        read_secret(alpha.as_ref()).await,
        vec![SqlValue::Text("alpha-secret".into())]
    );
    assert_eq!(
        read_secret(beta.as_ref()).await,
        vec![SqlValue::Text("beta-secret".into())]
    );

    // A site's named database is a separate file from its default.
    let alpha_logs = backends.database("alpha", "logs").await.unwrap();
    write_secret(alpha_logs.as_ref(), "alpha-logs-secret").await;
    assert_eq!(
        read_secret(alpha_logs.as_ref()).await,
        vec![SqlValue::Text("alpha-logs-secret".into())]
    );
    assert_eq!(
        read_secret(alpha.as_ref()).await,
        vec![SqlValue::Text("alpha-secret".into())]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn libsql_remote_round_trip_commit_and_rollback() {
    let Some(url) = std::env::var("BOATRAMP_TEST_LIBSQL_URL").ok() else {
        eprintln!("skipping libsql test: set BOATRAMP_TEST_LIBSQL_URL (a sqld URL) to run it");
        return;
    };
    let token = std::env::var("BOATRAMP_TEST_LIBSQL_TOKEN").unwrap_or_default();
    let backend = LibsqlSql::connect_remote(&url, &token)
        .await
        .expect("connect to sqld");
    let table = format!("bramp_libsql_test_{}", std::process::id());

    {
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&format!("DROP TABLE IF EXISTS {table}"), &[])
            .await
            .unwrap();
        tx.execute(
            &format!("CREATE TABLE {table} (id INTEGER, name TEXT)"),
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    {
        let mut tx = backend.begin().await.unwrap();
        let n = tx
            .execute(
                &format!("INSERT INTO {table} VALUES (?1, ?2), (?3, ?4)"),
                &[
                    SqlValue::Integer(1),
                    SqlValue::Text("a".into()),
                    SqlValue::Integer(2),
                    SqlValue::Text("b".into()),
                ],
            )
            .await
            .unwrap();
        assert_eq!(n, 2);
        tx.commit().await.unwrap();
    }

    {
        let mut tx = backend.begin().await.unwrap();
        let rows = tx
            .query(
                &format!("SELECT id, name FROM {table} WHERE id >= ?1 ORDER BY id"),
                &[SqlValue::Integer(1)],
            )
            .await
            .unwrap();
        assert_eq!(rows.columns, vec!["id", "name"]);
        assert_eq!(rows.rows.len(), 2);
        assert_eq!(rows.rows[0][0], SqlValue::Integer(1));
        assert_eq!(rows.rows[1][1], SqlValue::Text("b".into()));
        tx.commit().await.unwrap();
    }

    {
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&format!("INSERT INTO {table} VALUES (99, 'z')"), &[])
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }
    {
        let mut tx = backend.begin().await.unwrap();
        let rows = tx
            .query(&format!("SELECT id FROM {table} WHERE id = 99"), &[])
            .await
            .unwrap();
        assert!(rows.rows.is_empty(), "rolled-back row should be gone");
        tx.commit().await.unwrap();
    }

    let mut tx = backend.begin().await.unwrap();
    tx.execute(&format!("DROP TABLE {table}"), &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// The factory must give each site its own sqld **namespace** (a separate
/// database) — the same table name in two sites holds different data, and a
/// site's named database is separate from its default. Needs sqld with
/// `--enable-namespaces` + the admin API (`just sqld` provides both); skips
/// unless `BOATRAMP_TEST_LIBSQL_ADMIN_URL` is also set.
#[tokio::test]
async fn factory_gives_each_site_its_own_namespace() {
    let (Some(url), Some(admin_url)) = (
        std::env::var("BOATRAMP_TEST_LIBSQL_URL").ok(),
        std::env::var("BOATRAMP_TEST_LIBSQL_ADMIN_URL").ok(),
    ) else {
        eprintln!(
            "skipping libsql factory test: set BOATRAMP_TEST_LIBSQL_URL and \
             BOATRAMP_TEST_LIBSQL_ADMIN_URL (e.g. via `just sqld`) to run it"
        );
        return;
    };
    let token = std::env::var("BOATRAMP_TEST_LIBSQL_TOKEN").unwrap_or_default();
    let backends = LibsqlSqlBackends::remote(url, admin_url, token, None);

    async fn write_secret(db: &dyn SqlBackend, value: &str) {
        let mut tx = db.begin().await.unwrap();
        tx.execute("DROP TABLE IF EXISTS secrets", &[])
            .await
            .unwrap();
        tx.execute("CREATE TABLE secrets (v TEXT)", &[])
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO secrets VALUES (?1)",
            &[SqlValue::Text(value.into())],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    async fn read_secret(db: &dyn SqlBackend) -> Vec<SqlValue> {
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query("SELECT v FROM secrets", &[]).await.unwrap();
        tx.commit().await.unwrap();
        rows.rows.into_iter().flatten().collect()
    }

    let alpha = backends
        .database("alpha", "")
        .await
        .expect("alpha namespace");
    let beta = backends.database("beta", "").await.expect("beta namespace");
    write_secret(alpha.as_ref(), "alpha-secret").await;
    write_secret(beta.as_ref(), "beta-secret").await;

    // Each site sees only its own row — proof the namespaces are separate.
    assert_eq!(
        read_secret(alpha.as_ref()).await,
        vec![SqlValue::Text("alpha-secret".into())]
    );
    assert_eq!(
        read_secret(beta.as_ref()).await,
        vec![SqlValue::Text("beta-secret".into())]
    );

    // A site's named database is a different namespace from its default.
    let alpha_logs = backends
        .database("alpha", "logs")
        .await
        .expect("alpha logs namespace");
    write_secret(alpha_logs.as_ref(), "alpha-logs-secret").await;
    assert_eq!(
        read_secret(alpha_logs.as_ref()).await,
        vec![SqlValue::Text("alpha-logs-secret".into())]
    );
    assert_eq!(
        read_secret(alpha.as_ref()).await,
        vec![SqlValue::Text("alpha-secret".into())]
    );
}
