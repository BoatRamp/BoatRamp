//! **Live project export/import round-trip gate** (Tier-2 / nightly — NOT the merge
//! gate: it needs a Docker daemon AND a Postgres server).
//!
//! Self-skipping: it runs only when `BOATRAMP_TEST_PG_URL` is set (a reachable Postgres,
//! e.g. `postgres://user:pw@host:5432/db`) AND a Docker daemon is reachable; otherwise it
//! prints why and returns (a clean skip), exactly like `migrate_runner_sqlx_live.rs`.
//!
//! What it proves end-to-end against the REAL tools (`pg_dump`/`pg_restore` in an
//! ephemeral container via `run_ephemeral`, the `BRPROJ` bundle format, the version→image
//! map): seed a source table, EXPORT it through `run_ephemeral(pg_dump)` streaming into a
//! bundle member, bundle it (SHA-256 verified), EXTRACT + verify, create a fresh target
//! database, IMPORT it through `run_ephemeral(pg_restore)` streaming the member in via
//! stdin, then assert ROW + SCHEMA equality. On success it prints the marker
//! `PROJECT EXPORT ROUNDTRIP OK` (the gate's success token).
//!
//! Anti-hollow note: the version-match (mutation a) and the data-only divergence
//! (mutation b) are proven at the unit level in the merge gate; this live test exercises
//! the real streaming path (so a `run_ephemeral` buffer-then-truncate — mutation d —
//! would surface here as a corrupt/short dump that fails the restore + the row check).
#![cfg(feature = "project-export")]

use std::sync::Arc;

use boatramp_core::compute::{ComputeBackend, pg_client_image_for_server_version};
use boatramp_docker::DockerBackend;
use boatramp_node::pg_client::{
    MysqlConnection, PgConnection, mysql_restore_invocation, mysqldump_invocation,
    pg_dump_invocation, pg_restore_invocation,
};
use boatramp_node::project_bundle::{self, MemberKind, PgMemberInfo, SourceInfo, StagedMember};

/// Parse `postgres://user:pass@host:port/db` into the parts (best-effort, for the test
/// URL — not a general URL parser).
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
    // Drop any ?query on the db.
    let db = db.split(['?', '&']).next().unwrap_or(db).to_string();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 5432),
    };
    Some((user, password, host, port, db))
}

/// Parse `mysql://user:pass@host:port/db` into the parts (best-effort, for the test URL).
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

fn conn(user: &str, password: &str, host: &str, port: u16, db: &str) -> PgConnection {
    PgConnection {
        host: host.to_string(),
        port,
        user: user.to_string(),
        password: password.to_string(),
        database: db.to_string(),
        connect_timeout_secs: 10,
    }
}

/// Run `psql -v ON_ERROR_STOP=1 -tAc <sql>` in an ephemeral container, returning
/// `(exit_code, stdout_trimmed)`.
async fn psql(
    backend: &dyn ComputeBackend,
    image: &str,
    c: &PgConnection,
    sql: &str,
) -> (i32, String) {
    use tokio_util::compat::TokioAsyncWriteCompatExt;
    let td = tempfile::tempdir().unwrap();
    let out_path = td.path().join("out");
    let argv = vec![
        "psql".to_string(),
        "-v".to_string(),
        "ON_ERROR_STOP=1".to_string(),
        "-tAc".to_string(),
        sql.to_string(),
    ];
    let env = c.env();
    let code = {
        let f = tokio::fs::File::create(&out_path).await.unwrap();
        let mut sink = f.compat_write();
        backend
            .run_ephemeral(image, &argv, &env, None, &mut sink)
            .await
            .expect("psql run_ephemeral")
    };
    let out = tokio::fs::read_to_string(&out_path)
        .await
        .unwrap_or_default();
    (code, out.trim().to_string())
}

/// Run a `mysql` client script in an ephemeral container, returning `(exit_code,
/// stdout_trimmed)`. The SQL is fed on stdin (so no shell-quoting of statements), under
/// `sh -c '… 2>&1'` so a failed statement's stderr merges into the sink (run_ephemeral
/// drops container stderr on a non-zero exit). `-N --batch` gives clean, header-less,
/// tab-separated output. `db` names an optional default database (`None` for a
/// maintenance connection, e.g. CREATE/DROP DATABASE).
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
    // `db` here is always a test-controlled identifier (never user input), safe to inline.
    let target = db.map(|d| format!(" {d}")).unwrap_or_default();
    // Host/port/user are explicit (conn_args): env() now carries only MYSQL_PWD, and the
    // `mysql` client would otherwise fall back to the local socket. The flag values are an
    // IP/port/slug (no shell metacharacters), safe to inline into the sh -c string.
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

#[tokio::test]
async fn project_export_roundtrip_live() {
    // --- self-skip gates ---
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg round-trip not run)");
        return;
    };
    let Some((user, password, host, port, db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pg round-trip not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let src = conn(&user, &password, &host, port, &db);

    // --- version-detect -> client image (exercises the live version map) ---
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &src,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(
        code, 0,
        "SHOW server_version_num failed; is the DSN reachable?"
    );
    let image = pg_client_image_for_server_version(&ver)
        .expect("detected server version maps to a client image");
    eprintln!("detected server_version_num={ver} -> client image {image}");

    // --- seed the source ---
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let table = format!("brexport_rt_{suffix}");
    let (code, _) = psql(
        backend.as_ref(),
        &image,
        &src,
        &format!(
            "DROP TABLE IF EXISTS {table}; CREATE TABLE {table}(id int primary key, v text); \
             INSERT INTO {table} VALUES (1,'alpha'),(2,'beta'),(3,'gamma');"
        ),
    )
    .await;
    assert_eq!(code, 0, "seed source table");
    let expect = "1:alpha\n2:beta\n3:gamma";
    let (_, got_src) = psql(
        backend.as_ref(),
        &image,
        &src,
        &format!("SELECT id || ':' || v FROM {table} ORDER BY id"),
    )
    .await;
    assert_eq!(got_src, expect, "source rows");

    // --- EXPORT: pg_dump -> bundle member (FULL: schema + data) ---
    let td = tempfile::tempdir().unwrap();
    let dump = td.path().join("dump.pgc");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = pg_dump_invocation(&src, /* data_only = */ false);
        let f = tokio::fs::File::create(&dump).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("pg_dump run_ephemeral");
        assert_eq!(code, 0, "pg_dump exit code");
    }
    assert!(
        std::fs::metadata(&dump)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "pg_dump produced a non-empty custom-format dump"
    );

    // --- bundle it (SHA-256) + extract + verify ---
    let bundle = td.path().join("rt.brproj");
    let staged = vec![StagedMember {
        path: "sql/app.pgc".to_string(),
        kind: MemberKind::PgDump,
        source: dump.clone(),
        pg: Some(PgMemberInfo {
            server_version_num: ver.clone(),
            client_image: image.clone(),
            schema_fingerprint: None,
        }),
    }];
    project_bundle::write_bundle(
        &bundle,
        suffix,
        false,
        SourceInfo {
            project: "default".to_string(),
            site: None,
        },
        &staged,
    )
    .expect("write bundle");
    let extract = td.path().join("extract");
    let manifest = project_bundle::extract_and_verify(&bundle, &extract).expect("extract + verify");
    let member = extract.join(&manifest.pg_members().next().unwrap().path);
    assert!(member.exists(), "extracted pg member present");

    // --- create a fresh target database ---
    let target_db = format!("brexport_rt_{suffix}_tgt");
    // CREATE DATABASE must run outside a transaction, against a maintenance db.
    // psql sends a single `-c` multi-statement string as ONE implicit transaction,
    // and the server rejects "CREATE DATABASE cannot run inside a transaction block";
    // so DROP and CREATE go as two separate single-statement invocations (each a
    // standalone implicit transaction, which CREATE DATABASE is allowed to be).
    let maint = conn(&user, &password, &host, port, "postgres");
    let (dcode, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP DATABASE IF EXISTS {target_db}"),
    )
    .await;
    assert_eq!(dcode, 0, "drop pre-existing target database");
    let (ccode, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE {target_db}"),
    )
    .await;
    assert_eq!(ccode, 0, "create target database");
    let tgt = conn(&user, &password, &host, port, &target_db);

    // --- IMPORT: pg_restore streaming the member in via stdin (FULL restore) ---
    {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let inv = pg_restore_invocation(&tgt, /* data_only = */ false);
        // `run_ephemeral` drops captured container stderr on a non-zero exit, so a failed
        // restore would surface only a bare code. Run the SAME argv under `sh -c … 2>&1`
        // so pg_restore's diagnostics merge into the sink and land in the failure message.
        // The shell only redirects fds; stdin (the piped member) and the argv are the
        // product driver's exactly.
        let restore_argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("{} 2>&1", inv.argv.join(" ")),
        ];
        let infile = tokio::fs::File::open(&member).await.unwrap();
        let mut rdr = infile.compat();
        let out_path = td.path().join("restore.out");
        let out = tokio::fs::File::create(&out_path).await.unwrap();
        let mut sink = out.compat_write();
        let code = backend
            .run_ephemeral(&image, &restore_argv, &inv.env, Some(&mut rdr), &mut sink)
            .await
            .expect("pg_restore run_ephemeral");
        let restore_out = tokio::fs::read_to_string(&out_path)
            .await
            .unwrap_or_default();
        assert_eq!(
            code, 0,
            "pg_restore exit code; pg_restore output:\n{restore_out}"
        );
    }

    // --- assert ROW + SCHEMA equality on the target ---
    let (_, got_tgt) = psql(
        backend.as_ref(),
        &image,
        &tgt,
        &format!("SELECT id || ':' || v FROM {table} ORDER BY id"),
    )
    .await;
    assert_eq!(got_tgt, expect, "restored target rows match the source");

    // --- cleanup (best-effort) ---
    let _ = psql(
        backend.as_ref(),
        &image,
        &src,
        &format!("DROP TABLE IF EXISTS {table}"),
    )
    .await;
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP DATABASE IF EXISTS {target_db}"),
    )
    .await;

    println!("PROJECT EXPORT ROUNDTRIP OK");
}

/// **In-process libsql snapshot → bundle → restore round-trip** (no Docker, no external
/// server — embedded libsql). Seeds a local libsql database through the public
/// `SqlBackends::database` accessor at the project-qualified identity the driver snapshots
/// (`default`-style `project/site`), `snapshot_into`s a staged member (`VACUUM INTO` +
/// `PRAGMA integrity_check`), bundles it (SHA-256), extracts + verifies, then
/// `restore_snapshot`s the extracted member into a FRESH store (no-clobber + integrity
/// check) and asserts ROW equality against the source. Finally proves the no-clobber guard
/// refuses a second restore over the now-populated target. Emits the gate's libsql marker.
///
/// Unlike the pg/mysql round-trips this needs no server/daemon, so it also runs in the
/// merge gate when the `project-export` feature is built — but the capability gate greps
/// its marker so a silent skip (e.g. the libsql backend feature-gated away) is caught.
#[tokio::test]
async fn project_export_roundtrip_libsql() {
    use boatramp_core::project::ProjectRef;
    use boatramp_core::sql::{SqlBackend, SqlBackends, SqlValue};
    use boatramp_storage::sql_libsql::LibsqlSqlBackends;

    let project = "acme";
    let site = "blog";
    let expect: Vec<(i64, String)> = vec![
        (1, "alpha".to_string()),
        (2, "beta".to_string()),
        (3, "gamma".to_string()),
    ];

    // --- seed the source libsql db at the project-qualified default-db identity ---
    let src_dir = tempfile::tempdir().expect("src dir");
    let backends = LibsqlSqlBackends::local(src_dir.path());
    {
        let db: Arc<dyn SqlBackend> = backends
            .database(project, site, "")
            .await
            .expect("open source db");
        let mut tx = db.begin().await.expect("begin");
        tx.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", &[])
            .await
            .expect("create");
        let n = tx
            .execute(
                "INSERT INTO t VALUES (?1,?2),(?3,?4),(?5,?6)",
                &[
                    SqlValue::Integer(1),
                    SqlValue::Text("alpha".into()),
                    SqlValue::Integer(2),
                    SqlValue::Text("beta".into()),
                    SqlValue::Integer(3),
                    SqlValue::Text("gamma".into()),
                ],
            )
            .await
            .expect("insert");
        assert_eq!(n, 3, "seeded three rows");
        tx.commit().await.expect("commit");
    }

    // The identity the driver snapshots: `ProjectRef::qualified` (two-segment post-v0.31.0).
    let qsite = ProjectRef::new(project).qualified(site);

    // --- EXPORT: snapshot_into a staged member (VACUUM INTO + integrity_check) ---
    let stage_dir = tempfile::tempdir().expect("stage dir");
    let snap = stage_dir.path().join("default.sqlite");
    let integrity = backends
        .snapshot_into(&qsite, "", &snap)
        .await
        .expect("snapshot_into");
    assert_eq!(integrity, "ok", "snapshot integrity_check");
    assert!(
        std::fs::metadata(&snap)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "snapshot file present + non-empty"
    );

    // --- bundle it (SHA-256) + extract + verify ---
    let member_path = format!("libsql/{project}/{site}/default.sqlite");
    let staged = vec![StagedMember {
        path: member_path.clone(),
        kind: MemberKind::Libsql,
        source: snap.clone(),
        pg: None,
    }];
    let td = tempfile::tempdir().expect("bundle dir");
    let bundle = td.path().join("libsql-rt.brproj");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    project_bundle::write_bundle(
        &bundle,
        now,
        false,
        SourceInfo {
            project: project.to_string(),
            site: Some(site.to_string()),
        },
        &staged,
    )
    .expect("write bundle");
    let extract = td.path().join("extract");
    let manifest = project_bundle::extract_and_verify(&bundle, &extract).expect("extract + verify");
    assert!(
        manifest
            .members
            .iter()
            .any(|m| m.kind == MemberKind::Libsql && m.path == member_path),
        "libsql member present in the verified manifest"
    );
    let member_file = extract.join(&member_path);
    assert!(member_file.exists(), "extracted libsql member present");

    // --- IMPORT: restore_snapshot into a FRESH store (no-clobber + integrity_check) ---
    let tgt_dir = tempfile::tempdir().expect("tgt dir");
    let tgt = LibsqlSqlBackends::local(tgt_dir.path());
    tgt.restore_snapshot(&qsite, "", &member_file)
        .await
        .expect("restore_snapshot");

    // --- reopen + assert ROW equality against the source ---
    let rdb: Arc<dyn SqlBackend> = tgt
        .database(project, site, "")
        .await
        .expect("open restored db");
    let mut tx = rdb.begin().await.expect("begin restored");
    let rows = tx
        .query("SELECT id, v FROM t ORDER BY id", &[])
        .await
        .expect("query restored");
    tx.commit().await.expect("commit restored");
    let got: Vec<(i64, String)> = rows
        .rows
        .iter()
        .map(|r| {
            let id = match &r[0] {
                SqlValue::Integer(i) => *i,
                other => panic!("id not integer: {other:?}"),
            };
            let v = match &r[1] {
                SqlValue::Text(s) => s.clone(),
                other => panic!("v not text: {other:?}"),
            };
            (id, v)
        })
        .collect();
    assert_eq!(got, expect, "restored rows match the source");

    // --- no-clobber: a second restore over the now-populated target must refuse ---
    assert!(
        tgt.restore_snapshot(&qsite, "", &member_file)
            .await
            .is_err(),
        "restore_snapshot must refuse to overwrite a non-empty destination"
    );

    println!("PROJECT EXPORT LIBSQL ROUNDTRIP OK");
}

/// **Live MySQL export/import round-trip** (Tier-2 / nightly — needs a Docker daemon AND a
/// MySQL server). Self-skipping on `BOATRAMP_TEST_MYSQL_URL` + a reachable Docker daemon.
///
/// Mirrors the pg gate against the REAL tools (`mysqldump`/`mysql` in an ephemeral
/// container via `run_ephemeral`, the `BRPROJ` bundle): create + seed a source database,
/// EXPORT it with a FULL `mysqldump --databases` (schema + data, carrying `CREATE
/// DATABASE`/`USE`), bundle it (SHA-256 verified), EXTRACT + verify, DROP the source db,
/// then IMPORT the dump via `mysql` streaming from stdin (the FULL dump recreates the db),
/// and assert ROW equality. Emits `PROJECT EXPORT MYSQL ROUNDTRIP OK`.
#[tokio::test]
async fn project_export_roundtrip_mysql() {
    // --- self-skip gates ---
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (live mysql round-trip not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live mysql round-trip not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    // Pin 8.0: `mysql:8` may float to 8.4 where `--default-authentication-plugin` is gone;
    // the capability container pairs this with native-password auth over the plaintext
    // bridge. The client image ships both `mysqldump` and `mysql`.
    let image = "mysql:8.0";

    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let src_db = format!("brexport_mysql_rt_{suffix}");
    let mkconn = |db: &str| MysqlConnection {
        host: host.clone(),
        port,
        user: user.clone(),
        password: password.clone(),
        database: db.to_string(),
        connect_timeout_secs: 10,
    };
    // A maintenance connection (no default db) for CREATE/DROP DATABASE.
    let admin = mkconn("");
    let expect = "1:alpha\n2:beta\n3:gamma";

    // --- create + seed the source database ---
    let (code, out) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!("DROP DATABASE IF EXISTS {src_db}; CREATE DATABASE {src_db};"),
    )
    .await;
    assert_eq!(code, 0, "create source database; mysql output:\n{out}");
    let (code, out) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&src_db),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         INSERT INTO t VALUES (1,'alpha'),(2,'beta'),(3,'gamma');",
    )
    .await;
    assert_eq!(code, 0, "seed source table; mysql output:\n{out}");
    let (_code, got_src) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&src_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(got_src, expect, "source rows");

    // --- EXPORT: mysqldump FULL -> bundle member (stdout is the dump; keep it clean) ---
    let td = tempfile::tempdir().unwrap();
    let dump = td.path().join("dump.sql");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = mysqldump_invocation(&mkconn(&src_db), /* data_only = */ false);
        let f = tokio::fs::File::create(&dump).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("mysqldump run_ephemeral");
        if code != 0 {
            // mysqldump's stdout is the dump, so we can't fold stderr into it on the
            // happy path; on failure, re-run routing stderr->sink (dump discarded) to
            // surface the reason (run_ephemeral drops container stderr on non-zero exit).
            let diag_argv = vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("{} 2>&1 1>/dev/null", inv.argv.join(" ")),
            ];
            let errf = td.path().join("dump.err");
            let ef = tokio::fs::File::create(&errf).await.unwrap();
            let mut esink = ef.compat_write();
            let _ = backend
                .run_ephemeral(image, &diag_argv, &inv.env, None, &mut esink)
                .await;
            let err = tokio::fs::read_to_string(&errf).await.unwrap_or_default();
            panic!("mysqldump exit code = {code}; mysqldump stderr:\n{err}");
        }
    }
    assert!(
        std::fs::metadata(&dump)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "mysqldump produced a non-empty dump"
    );

    // --- bundle it (SHA-256) + extract + verify ---
    let bundle = td.path().join("mysql-rt.brproj");
    let member_path = format!("sql/{src_db}.sql");
    let staged = vec![StagedMember {
        path: member_path.clone(),
        kind: MemberKind::MysqlDump,
        source: dump.clone(),
        pg: None,
    }];
    project_bundle::write_bundle(
        &bundle,
        suffix,
        false,
        SourceInfo {
            project: "default".to_string(),
            site: None,
        },
        &staged,
    )
    .expect("write bundle");
    let extract = td.path().join("extract");
    let manifest = project_bundle::extract_and_verify(&bundle, &extract).expect("extract + verify");
    let member = extract.join(
        &manifest
            .members
            .iter()
            .find(|m| m.kind == MemberKind::MysqlDump)
            .expect("mysql member in manifest")
            .path,
    );
    assert!(member.exists(), "extracted mysql member present");

    // --- DROP the source db, then IMPORT the FULL dump (recreates it via CREATE DATABASE/USE) ---
    let (code, out) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!("DROP DATABASE IF EXISTS {src_db};"),
    )
    .await;
    assert_eq!(
        code, 0,
        "drop source database before restore; mysql output:\n{out}"
    );
    {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let inv = mysql_restore_invocation(&mkconn(&src_db), /* data_only = */ false);
        // `mysql` restore reads the dump from stdin; run it under `sh -c … 2>&1` so a
        // failed statement surfaces (run_ephemeral drops stderr on a non-zero exit).
        let restore_argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("{} 2>&1", inv.argv.join(" ")),
        ];
        let infile = tokio::fs::File::open(&member).await.unwrap();
        let mut rdr = infile.compat();
        let out_path = td.path().join("restore.out");
        let out = tokio::fs::File::create(&out_path).await.unwrap();
        let mut sink = out.compat_write();
        let code = backend
            .run_ephemeral(image, &restore_argv, &inv.env, Some(&mut rdr), &mut sink)
            .await
            .expect("mysql restore run_ephemeral");
        let restore_out = tokio::fs::read_to_string(&out_path)
            .await
            .unwrap_or_default();
        assert_eq!(
            code, 0,
            "mysql restore exit code; mysql output:\n{restore_out}"
        );
    }

    // --- assert ROW equality on the restored db ---
    let (_code, got_tgt) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&src_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(got_tgt, expect, "restored rows match the source");

    // --- cleanup (best-effort) ---
    let _ = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!("DROP DATABASE IF EXISTS {src_db};"),
    )
    .await;

    println!("PROJECT EXPORT MYSQL ROUNDTRIP OK");
}

/// **Live full-DRIVER round-trip** — drives the real `NodeProjectExport::export()` /
/// `import()` (not the reconstructed primitives the pg/mysql/libsql tests use), closing the
/// "driver has no end-to-end live coverage" gap for the pg path: it exercises the driver's
/// `resolve_pg` (version-detect + endpoint) + `run_sql_client` streaming (pg_dump stdout →
/// bundle stage; pg_restore ← the staged member). External `url_env` binding (so no
/// compute/deploy resolution), single driver, same-db drop-and-restore. The KV/blob/identity
/// orchestration is already gated in-process; this adds the live pg glue. Self-skips exactly
/// like the pg round-trip. Emits `PROJECT EXPORT DRIVER ROUNDTRIP OK`.
#[tokio::test]
async fn project_export_roundtrip_driver_live() {
    use boatramp_core::Storage;
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::env::MapEnv;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_export::{
        ExportOptions, IdentityChoice, ImportOptions, ProjectExport,
    };
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live driver round-trip not run)");
        return;
    };
    let Some((user, password, host, port, db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live driver round-trip not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    // Build the full driver over an EXTERNAL url_env pg binding pointing at the test DSN.
    let databases = BTreeMap::from([(
        "app".to_string(),
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            url_env: "BR_DRV_DSN".to_string(),
            ..Default::default()
        },
    )]);
    let env: Arc<dyn boatramp_core::env::EnvSource> =
        Arc::new(MapEnv::new().with("BR_DRV_DSN", &url));
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    // A real OWNED control-plane key so the scoped KV slice is non-trivial (a synthetic
    // non-owned key would be excluded by the C1 project-scoping, leaving the slice empty).
    kv.put("project/default/config/tenancy", b"{}".to_vec())
        .await
        .unwrap();
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    // The managed path requires an envelope even for an external binding (it unseals a
    // MANAGED credential — unused here, external reads the DSN from env). A local KEK fits.
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([0u8; 32]));
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(
        NodeOperatorSql::new(
            databases.clone(),
            kv.clone(),
            Some(envelope.clone()),
            DeployStore::new(blobs.clone(), kv.clone()),
        )
        .with_env_source(env.clone()),
    );
    let work = td.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let driver = NodeProjectExport::new(
        databases,
        DeployStore::new(blobs.clone(), kv.clone()),
        kv.clone(),
        blobs.clone(),
        work,
    )
    .with_env_source(env.clone())
    .with_managed_pg(backend.clone(), envelope, op, false);

    // Detect the client image (the first psql uses a fixed image just to read the version).
    let src = conn(&user, &password, &host, port, &db);
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &src,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "SHOW server_version_num; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("version maps to a client image");

    // Seed a table in the source db.
    let (code, _) = psql(
        backend.as_ref(),
        &image,
        &src,
        "DROP TABLE IF EXISTS brdrv_rt; CREATE TABLE brdrv_rt(id int primary key, v text); \
         INSERT INTO brdrv_rt VALUES (1,'alpha'),(2,'beta');",
    )
    .await;
    assert_eq!(code, 0, "seed source table");
    let expect = "1:alpha\n2:beta";

    // EXPORT through the driver (full) — exercises resolve_pg + run_sql_client(pg_dump),
    // STREAMED into an in-memory buffer (models the HTTP response the handler wires the sink
    // to; no bundle temp file).
    let bundle = {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(
                "default",
                &ExportOptions {
                    data_only: false,
                    include_identity: false,
                    transport_key: None,
                },
                &mut sink,
            )
            .await
            .expect("driver export");
        sink.into_inner()
    };
    // Read the streamed v2 bundle back to confirm the expected members are present.
    let mut kinds: Vec<MemberKind> = Vec::new();
    project_bundle::read_bundle_streaming(bundle.as_slice(), |spec, _sz, body| {
        let mut v = Vec::new();
        std::io::Read::read_to_end(body, &mut v).map_err(project_bundle::BundleError::Io)?;
        kinds.push(spec.kind);
        Ok(())
    })
    .expect("read back the streamed bundle");
    assert!(
        kinds.contains(&MemberKind::PgDump),
        "driver export staged a pg dump member"
    );
    assert!(
        kinds.contains(&MemberKind::Kv),
        "driver export staged the control-plane KV slice"
    );

    // Drop the table, then IMPORT through the driver — exercises run_sql_client(pg_restore).
    // `force` overlays the (non-empty, same-process) KV; identity Fresh (no identity member).
    let (code, _) = psql(backend.as_ref(), &image, &src, "DROP TABLE brdrv_rt").await;
    assert_eq!(code, 0, "drop before restore");
    let report = {
        let mut source = futures::io::Cursor::new(bundle);
        driver
            .import(
                "default",
                &mut source,
                ImportOptions {
                    apply: true,
                    force: true,
                    // Same-process re-import into the project's own populated store — opt in to
                    // replacing an existing target (env-clone uses a fresh target and needs no
                    // overwrite).
                    overwrite: true,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("driver import")
    };
    assert!(
        report.pg_databases >= 1,
        "driver import restored at least one pg database"
    );

    // ROW equality after the full driver round-trip.
    let (_, got) = psql(
        backend.as_ref(),
        &image,
        &src,
        "SELECT id || ':' || v FROM brdrv_rt ORDER BY id",
    )
    .await;
    assert_eq!(got, expect, "driver round-trip restored the rows");

    let _ = psql(
        backend.as_ref(),
        &image,
        &src,
        "DROP TABLE IF EXISTS brdrv_rt",
    )
    .await;
    println!("PROJECT EXPORT DRIVER ROUNDTRIP OK");
}

#[test]
fn parse_pg_url_handles_the_common_shapes() {
    // A pure unit guard so the URL parser is covered in the MERGE gate (no network).
    assert_eq!(
        parse_pg_url("postgres://u:p@h:5432/db"),
        Some(("u".into(), "p".into(), "h".into(), 5432, "db".into()))
    );
    assert_eq!(
        parse_pg_url("postgresql://svc:pw@10.0.0.5:6000/app?sslmode=require"),
        Some((
            "svc".into(),
            "pw".into(),
            "10.0.0.5".into(),
            6000,
            "app".into()
        ))
    );
    // Password may contain a ':' (split on the FIRST only).
    assert_eq!(
        parse_pg_url("postgres://u:a:b@h:5432/db"),
        Some(("u".into(), "a:b".into(), "h".into(), 5432, "db".into()))
    );
    assert_eq!(parse_pg_url("not-a-url"), None);
}

/// **≥2-TENANT cross-tenant LEAK gate** (merge gate — no Docker, no DB server: in-memory KV
/// + filesystem blobs; the pg/mysql/libsql members self-skip because the fixture declares no
/// SQL bindings). Drives the REAL streaming `NodeProjectExport::export` / `import`.
///
/// A single-tenant fixture is structurally blind to a leak, so this seeds TWO projects
/// (`acme`, `globex`) each with their own KV + blobs, PLUS global "crown-jewel" keyspaces
/// (`cert/`, `domain/`, `daemonconfig/`, `_cp/`) that belong to neither — all in ONE shared
/// store. It then exports `acme` and asserts that ZERO bytes belonging to `globex` or the
/// global crown jewels appear in the bundle or in an imported target, checked BOTH by key
/// membership AND by a raw byte-scan for a globex-only sentinel; and a project-RENAME import
/// proves every re-keyed blob lands ONLY in the target scope, with no source-scope (`acme`)
/// key surviving.
///
/// Mutations that turn this RED: exporting the whole KV store instead of
/// `scope_entries_to_project` (globex/cert bytes appear in the bundle — byte-scan + key
/// membership fail); listing blobs under `hblob/` instead of `hblob/acme/` (globex blob
/// bytes appear); or dropping the per-blob `target_blob_key` re-key / fail-closed check (a
/// renamed import keeps a source-scope `hblob/acme/` key).
#[tokio::test]
async fn project_export_cross_tenant_leak_gate() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_export::{
        ExportOptions, IdentityChoice, ImportOptions, ProjectExport,
    };
    use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use bytes::Bytes;
    use futures::StreamExt;
    use sha2::{Digest, Sha256};

    // A `siteconfig/<hash>` body is content-addressed (hash == sha256(body)); the import-side
    // fail-closed check verifies that, so the legit clone must seed a REAL content address.
    fn siteconfig_key(body: &[u8]) -> String {
        format!("siteconfig/{}", hex::encode(Sha256::digest(body)))
    }

    async fn put_blob(store: &dyn Storage, key: &str, data: &[u8]) {
        let data = data.to_vec();
        let stream: ByteStream =
            futures::stream::once(async move { Ok::<Bytes, StorageError>(Bytes::from(data)) })
                .boxed();
        store
            .put(key, stream, PutMeta { content_type: None })
            .await
            .expect("seed blob");
    }
    async fn read_blob(store: &dyn Storage, key: &str) -> Vec<u8> {
        let mut body = store.get(key).await.expect("get blob").body;
        let mut out = Vec::new();
        while let Some(chunk) = body.next().await {
            out.extend_from_slice(chunk.expect("blob chunk").as_ref());
        }
        out
    }
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Hand-craft a v2 bundle carrying ONLY a KV slice with the given entries (bypassing the
    /// export-side scope filter) — models a crafted/tampered bundle crossing the trust boundary,
    /// for the import-direction (HIGH-1) checks. `source` is the bundle's declared source project
    /// (set it == the import target so the re-key is a no-op and the crafted keys reach the
    /// import-side filter verbatim).
    fn craft_kv_bundle(source: &str, entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        use boatramp_core::kv::KvDumpEntry;
        use boatramp_node::project_bundle::{self, MemberKind, MemberSpec, SourceInfo};
        let kv_entries: Vec<KvDumpEntry> = entries
            .iter()
            .map(|(k, v)| KvDumpEntry {
                key: k.clone(),
                value: v.clone(),
                version: 1,
            })
            .collect();
        let kv_bytes = boatramp_core::kv_dump::encode_dump(&kv_entries, 0);
        let td = tempfile::tempdir().unwrap();
        let tmp = td.path().join("kv");
        std::fs::write(&tmp, &kv_bytes).unwrap();
        let specs = vec![MemberSpec {
            path: project_bundle::KV_MEMBER_PATH.to_string(),
            kind: MemberKind::Kv,
            pg: None,
        }];
        let mut out: Vec<u8> = Vec::new();
        project_bundle::write_bundle_streaming(
            &mut out,
            0,
            false,
            SourceInfo {
                project: source.to_string(),
                site: None,
            },
            specs,
            |_spec| Ok(tmp.clone()),
        )
        .unwrap();
        out
    }

    // A value that exists ONLY in globex's data / the global crown jewels — if any of it ever
    // appears in acme's export or an imported target, a tenant boundary leaked.
    const GLOBEX_SENTINEL: &[u8] = b"GLOBEX_ONLY_CROWN_JEWEL_SENTINEL_9e3af17c";
    const GLOBAL_SENTINEL: &[u8] = b"GLOBAL_TLS_PRIVATE_KEY_SENTINEL_7c1d44b0";

    let src_tmp = tempfile::tempdir().unwrap();
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());

    // --- acme's OWNED control-plane keyspace (travels) ---
    kv.put("project/acme/config/tenancy", b"{\"acme\":true}".to_vec())
        .await
        .unwrap();
    kv.put(
        "project/acme/secret/api-key",
        b"acme-sealed-secret".to_vec(),
    )
    .await
    .unwrap();
    // A real content-addressed site config: the pointer stores the body's sha256, the body
    // lives at `siteconfig/<that-hash>`. Both must survive a legit clone (and the body must
    // pass the import-side content-address check).
    let acme_site_body = b"{\"acme\":\"site config body\"}".to_vec();
    let acme_site_key = siteconfig_key(&acme_site_body);
    let acme_site_hash = acme_site_key
        .strip_prefix("siteconfig/")
        .unwrap()
        .to_string();
    kv.put("project/acme/site/web", acme_site_hash.clone().into_bytes())
        .await
        .unwrap();
    kv.put(&acme_site_key, acme_site_body.clone())
        .await
        .unwrap();

    // --- globex's OWNED keyspace (must NEVER travel in acme's export) ---
    kv.put("project/globex/config/tenancy", GLOBEX_SENTINEL.to_vec())
        .await
        .unwrap();
    kv.put(
        "project/globex/secret/api-key",
        [GLOBEX_SENTINEL, b"-sealed"].concat(),
    )
    .await
    .unwrap();
    kv.put("project/globex/site/web", b"HASHGLOBEX".to_vec())
        .await
        .unwrap();
    kv.put("siteconfig/HASHGLOBEX", GLOBEX_SENTINEL.to_vec())
        .await
        .unwrap();
    // sibling-prefix over-capture guard: `acmecorp` is NOT `acme`.
    kv.put("project/acmecorp/secret/s", GLOBEX_SENTINEL.to_vec())
        .await
        .unwrap();

    // --- GLOBAL crown jewels / node state (belong to NO project; must NEVER travel) ---
    kv.put("cert/acme.example.com", GLOBAL_SENTINEL.to_vec())
        .await
        .unwrap();
    kv.put("cert/globex.example.com", GLOBAL_SENTINEL.to_vec())
        .await
        .unwrap();
    kv.put("domain/acme.example.com", br#"{"project":"acme"}"#.to_vec())
        .await
        .unwrap();
    kv.put("daemonconfig/deadbeef", b"node-config".to_vec())
        .await
        .unwrap();
    kv.put("_cp/leader", b"node-1".to_vec()).await.unwrap();

    // --- blobs for BOTH tenants (globex's body carries the sentinel) ---
    let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(src_tmp.path().join("blobs")));
    put_blob(
        blobs.as_ref(),
        "hblob/acme/web/c/logo.png",
        b"ACME-LOGO-PNG-BYTES",
    )
    .await;
    put_blob(
        blobs.as_ref(),
        "hblob/acme/web/c/page.html",
        b"<h1>acme</h1>",
    )
    .await;
    put_blob(
        blobs.as_ref(),
        "hblob/globex/web/c/secret.bin",
        GLOBEX_SENTINEL,
    )
    .await;
    // sibling-prefix blob guard.
    put_blob(
        blobs.as_ref(),
        "hblob/acmecorp/web/c/x.bin",
        GLOBEX_SENTINEL,
    )
    .await;

    let work = src_tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let drv = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(blobs.clone(), kv.clone()),
        kv.clone(),
        blobs.clone(),
        work,
    );

    // === EXPORT acme (FULL) into a buffer ===
    let bundle = {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        drv.export(
            "acme",
            &ExportOptions {
                data_only: false,
                ..Default::default()
            },
            &mut sink,
        )
        .await
        .expect("export acme");
        sink.into_inner()
    };

    // RAW BYTE-SCAN: neither the globex-only sentinel nor the global crown-jewel sentinel may
    // appear ANYWHERE in acme's bundle bytes (KV slice, blob bodies, manifest — all of it).
    assert!(
        !contains(&bundle, GLOBEX_SENTINEL),
        "globex-only sentinel bytes LEAKED into acme's export bundle"
    );
    assert!(
        !contains(&bundle, GLOBAL_SENTINEL),
        "global crown-jewel sentinel bytes LEAKED into acme's export bundle"
    );

    // === IMPORT into a fresh SAME-NAME target store ===
    let tgt_tmp = tempfile::tempdir().unwrap();
    let tgt_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let tgt_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tgt_tmp.path().join("blobs")));
    let tgt_work = tgt_tmp.path().join("work");
    std::fs::create_dir_all(&tgt_work).unwrap();
    let tgt = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(tgt_blobs.clone(), tgt_kv.clone()),
        tgt_kv.clone(),
        tgt_blobs.clone(),
        tgt_work,
    );
    {
        let mut source = futures::io::Cursor::new(bundle.clone());
        tgt.import(
            "acme",
            &mut source,
            ImportOptions {
                apply: true,
                force: true,
                identity: IdentityChoice::Fresh,
                ..Default::default()
            },
        )
        .await
        .expect("import acme");
    }

    // KEY MEMBERSHIP on the target KV: acme's keyspace present; ZERO globex / global keys.
    let tgt_keys = tgt_kv.list_prefix("").await.unwrap();
    assert!(
        tgt_keys.iter().any(|k| k == "project/acme/config/tenancy"),
        "acme's owned keyspace restored"
    );
    assert!(
        tgt_keys.contains(&acme_site_key),
        "acme's referenced (content-addressed) site-config body carried + restored"
    );
    assert!(
        !tgt_keys.iter().any(|k| k.contains("globex")),
        "NO globex key may appear in the imported target"
    );
    assert!(
        !tgt_keys.iter().any(|k| k == "siteconfig/HASHGLOBEX"),
        "globex's site-config body must NOT travel"
    );
    assert!(
        !tgt_keys.iter().any(|k| k == "project/acmecorp/secret/s"),
        "a sibling-prefix project is not over-captured"
    );
    assert!(
        !tgt_keys.iter().any(|k| k.starts_with("cert/")
            || k.starts_with("domain/")
            || k.starts_with("wildcard/")
            || k.starts_with("daemonconfig/")
            || k.starts_with("_cp/")),
        "NO global crown-jewel / routing / node key may appear in the imported target"
    );

    // BLOB MEMBERSHIP + raw byte-scan on the TARGET store: only acme's blobs, under hblob/acme/.
    let tgt_blob_keys: Vec<String> = tgt_blobs
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.key)
        .collect();
    assert!(
        tgt_blob_keys
            .iter()
            .any(|k| k == "hblob/acme/web/c/logo.png"),
        "acme's blob restored under its own scope"
    );
    assert!(
        !tgt_blob_keys.iter().any(|k| k.contains("globex")),
        "NO globex blob in the target"
    );
    assert!(
        !tgt_blob_keys
            .iter()
            .any(|k| k.starts_with("hblob/acmecorp/")),
        "a sibling-prefix blob scope is not over-captured"
    );
    for k in &tgt_blob_keys {
        let body = read_blob(tgt_blobs.as_ref(), k).await;
        assert!(
            !contains(&body, GLOBEX_SENTINEL),
            "globex sentinel bytes found inside target blob {k:?}"
        );
    }

    // === MEDIUM-1(a): a second import into the now-POPULATED target is REFUSED without
    //     `overwrite`, and proceeds WITH it. (A fresh target needs no overwrite — proven by
    //     the import above, which ran against the then-empty `tgt`.) ===
    {
        let mut src = futures::io::Cursor::new(bundle.clone());
        let refused = tgt
            .import(
                "acme",
                &mut src,
                ImportOptions {
                    apply: true,
                    force: true,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await;
        assert!(
            refused.is_err(),
            "re-import into a populated target must be refused without overwrite"
        );
    }
    {
        let mut src = futures::io::Cursor::new(bundle.clone());
        tgt.import(
            "acme",
            &mut src,
            ImportOptions {
                apply: true,
                force: true,
                overwrite: true,
                identity: IdentityChoice::Fresh,
                ..Default::default()
            },
        )
        .await
        .expect("re-import into a populated target succeeds WITH overwrite");
    }

    // === IMPORT-trust direction (HIGH-1): a crafted bundle whose KV slice carries a foreign
    //     tenant / global / poisoned key is REFUSED fail-closed, and the target is left
    //     untouched. source == target ("acme") ⇒ the re-key is a no-op, so the crafted keys
    //     reach the import-side scope filter verbatim. ===
    // (label, KV entries to plant) — one crafted bundle per case.
    type CraftedCase = (&'static str, Vec<(String, Vec<u8>)>);
    let malicious_sets: Vec<CraftedCase> = vec![
        (
            "another tenant's project key",
            vec![
                ("project/acme/config/tenancy".into(), b"{}".to_vec()),
                ("project/globex/secret/x".into(), GLOBEX_SENTINEL.to_vec()),
            ],
        ),
        (
            "a global TLS cert",
            vec![("cert/evil.example.com".into(), GLOBAL_SENTINEL.to_vec())],
        ),
        (
            "a global routing record",
            vec![(
                "domain/evil.example.com".into(),
                br#"{"project":"acme"}"#.to_vec(),
            )],
        ),
        (
            "a node daemon config",
            vec![("daemonconfig/evil".into(), b"x".to_vec())],
        ),
        (
            "an unreferenced siteconfig",
            vec![("siteconfig/deadbeef".into(), b"orphan".to_vec())],
        ),
        (
            "a POISONED siteconfig (body != content-address)",
            vec![
                ("project/acme/site/web".into(), b"deadbeef".to_vec()),
                (
                    "siteconfig/deadbeef".into(),
                    b"not-the-preimage-of-deadbeef".to_vec(),
                ),
            ],
        ),
    ];
    for (what, entries) in &malicious_sets {
        let crafted = craft_kv_bundle("acme", entries);
        let mt_tmp = tempfile::tempdir().unwrap();
        let mt_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mt_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(mt_tmp.path().join("blobs")));
        let mt_work = mt_tmp.path().join("work");
        std::fs::create_dir_all(&mt_work).unwrap();
        let mt = NodeProjectExport::new(
            BTreeMap::new(),
            DeployStore::new(mt_blobs.clone(), mt_kv.clone()),
            mt_kv.clone(),
            mt_blobs.clone(),
            mt_work,
        );
        let mut src = futures::io::Cursor::new(crafted);
        let res = mt
            .import(
                "acme",
                &mut src,
                ImportOptions {
                    apply: true,
                    force: true,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await;
        assert!(
            res.is_err(),
            "import of a bundle carrying {what} MUST be refused (fail-closed)"
        );
        // Fail-closed BEFORE writing: the target KV holds NONE of the crafted foreign/global keys.
        let after = mt_kv.list_prefix("").await.unwrap();
        assert!(
            !after.iter().any(|k| k.contains("globex")
                || k.starts_with("cert/")
                || k.starts_with("domain/")
                || k.starts_with("daemonconfig/")
                || k.starts_with("siteconfig/")),
            "a refused import ({what}) must not have written any foreign/global/siteconfig key"
        );
    }

    // === RENAME variant: import acme's bundle AS `acmeclone` ===
    let rn_tmp = tempfile::tempdir().unwrap();
    let rn_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let rn_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(rn_tmp.path().join("blobs")));
    let rn_work = rn_tmp.path().join("work");
    std::fs::create_dir_all(&rn_work).unwrap();
    let rn = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(rn_blobs.clone(), rn_kv.clone()),
        rn_kv.clone(),
        rn_blobs.clone(),
        rn_work,
    );
    {
        let mut source = futures::io::Cursor::new(bundle.clone());
        rn.import(
            "acmeclone",
            &mut source,
            ImportOptions {
                apply: true,
                force: true,
                identity: IdentityChoice::Fresh,
                ..Default::default()
            },
        )
        .await
        .expect("rename import");
    }

    // Every re-keyed blob lands ONLY under the TARGET scope; no source-scope (`acme`) key.
    let rn_blob_keys: Vec<String> = rn_blobs
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.key)
        .collect();
    assert!(
        !rn_blob_keys.is_empty(),
        "the rename import restored acme's blob under the new project name"
    );
    for k in &rn_blob_keys {
        assert!(
            k.starts_with("hblob/acmeclone/"),
            "re-keyed blob {k:?} must land under the TARGET scope hblob/acmeclone/"
        );
        assert!(
            !k.starts_with("hblob/acme/"),
            "NO source-scope (acme) blob key may survive a rename import"
        );
    }
    let rn_keys = rn_kv.list_prefix("").await.unwrap();
    assert!(
        rn_keys.iter().any(|k| k.starts_with("project/acmeclone/")),
        "KV re-keyed to the TARGET project on rename"
    );
    assert!(
        !rn_keys.iter().any(|k| k.starts_with("project/acme/")),
        "NO source-scope (acme) KV key may survive a rename import"
    );
    assert!(
        !rn_keys.iter().any(|k| k.contains("globex")),
        "NO globex key in the renamed target"
    );

    println!("PROJECT EXPORT CROSS-TENANT LEAK GATE OK");
}
