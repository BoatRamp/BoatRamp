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
    MysqlConnection, PgConnection, mysql_restore_invocation, mysql_shadow_invocation,
    mysqldump_invocation, mysqldump_tables_only_invocation, pg_dump_invocation,
    pg_restore_invocation, pg_restore_shadow_invocation,
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

/// Run `psql -v ON_ERROR_STOP=1 -tA -f -` (SQL fed on stdin) in an ephemeral container,
/// returning `(exit_code, output_trimmed)`. Wrapped in `sh -c '… 2>&1'` so a failed
/// statement's stderr merges into the sink — like `mysql_run`, because `run_ephemeral`
/// keeps only the container's stdout and DROPS its stderr on a non-zero exit, which would
/// otherwise hide WHY a setup/probe failed (e.g. a refused DDL). SQL on stdin (not a `-c`
/// argv string) avoids shell-quoting crafted SQL. `PGOPTIONS` raises `client_min_messages`
/// to `warning` so routine NOTICEs never pollute the captured output of an output-parsed
/// probe (`SELECT …`); real errors still surface.
async fn psql(
    backend: &dyn ComputeBackend,
    image: &str,
    c: &PgConnection,
    sql: &str,
) -> (i32, String) {
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
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
        // Direct dump+restore (no shadow pre-create) → empty exclude list keeps `--no-comments`.
        let inv = pg_dump_invocation(&src, /* data_only = */ false, "160000", &[], false);
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

/// Monotonic-ish per-test suffix (seconds since epoch) for unique test db/role names.
fn now_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// **Live pg ATOMIC shadow-restore round-trip** (inc2 Stage C; Tier-2 / nightly — needs a Docker
/// daemon AND a Postgres server whose DSN user can `CREATE ROLE`/`CREATE DATABASE`). Self-skips.
///
/// Proves the SECURITY-CRITICAL split + the swap end-to-end against REAL pg: seed a SOURCE db,
/// `pg_dump -Fc` it (FULL), create a SHADOW db owned by a freshly-created NON-SUPERUSER role, apply
/// the dump with `pg_restore_shadow_invocation` CONNECTING AS THAT NON-SUPERUSER ROLE (so a crafted
/// dump's superuser-only escapes would fail — see the crafted-escape gate), then the TRUSTED
/// superuser/maintenance connection terminates + `ALTER DATABASE … RENAME`-swaps the shadow in for
/// an (empty) live db, and we assert ROW equality on the swapped-in live db. Emits
/// `PROJECT EXPORT PG CHUNKED SHADOW OK`.
#[tokio::test]
async fn project_export_pg_chunked_shadow_live() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg shadow round-trip not run)");
        return;
    };
    let Some((user, password, host, port, db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pg shadow round-trip not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let su = conn(&user, &password, &host, port, &db); // the DSN superuser
    let maint = conn(&user, &password, &host, port, "postgres"); // superuser @ maintenance db
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &su,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let s = now_suffix();
    let table = format!("brexp_shadow_t_{s}");
    let source_db = format!("brexp_shadow_src_{s}");
    let live_db = format!("brexp_shadow_live_{s}");
    let shadow_db = format!("{live_db}__shadow_{s}");
    let role = format!("brexp_shadow_role_{s}");
    let rolepw = format!("rpw_{s}");
    let expect = "1:alpha\n2:beta\n3:gamma";

    // --- TRUSTED DDL (superuser): a NON-SUPERUSER apply role + a source db owned by it ---
    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "CREATE ROLE \"{role}\" LOGIN PASSWORD '{rolepw}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
        ),
    )
    .await;
    assert_eq!(c, 0, "create the non-superuser apply role");
    for sql in [
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("CREATE DATABASE {source_db} OWNER \"{role}\""),
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db} OWNER \"{role}\""),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup DDL `{sql}`: {o}");
    }

    // --- seed the SOURCE db as the role (so the dump's objects are role-ownable) ---
    let src_conn = conn(&user, &password, &host, port, &source_db);
    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &src_conn,
        &format!(
            "CREATE TABLE {table}(id int primary key, v text); \
             INSERT INTO {table} VALUES (1,'alpha'),(2,'beta'),(3,'gamma');"
        ),
    )
    .await;
    assert_eq!(c, 0, "seed source table");

    // --- EXPORT: pg_dump -Fc FULL of the source db (the driver streams this O(chunk); here a temp
    //     archive is sufficient to exercise the shadow apply + swap) ---
    let td = tempfile::tempdir().unwrap();
    let dump = td.path().join("dump.pgc");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = pg_dump_invocation(&src_conn, false, "160000", &[], false);
        let f = tokio::fs::File::create(&dump).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("pg_dump run_ephemeral");
        assert_eq!(code, 0, "pg_dump");
    }

    // --- TRUSTED DDL (superuser): create the shadow db owned by the non-superuser role ---
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE {shadow_db} OWNER \"{role}\""),
    )
    .await;
    assert_eq!(c, 0, "create shadow db: {o}");

    // --- IMPORT: pg_restore into the SHADOW, CONNECTING AS THE NON-SUPERUSER ROLE ---
    let role_conn = conn(&role, &rolepw, &host, port, &shadow_db);
    {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let inv = pg_restore_shadow_invocation(&role_conn, &shadow_db);
        let restore_argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("{} 2>&1", inv.argv.join(" ")),
        ];
        let infile = tokio::fs::File::open(&dump).await.unwrap();
        let mut rdr = infile.compat();
        let out_path = td.path().join("restore.out");
        let out = tokio::fs::File::create(&out_path).await.unwrap();
        let mut sink = out.compat_write();
        let code = backend
            .run_ephemeral(&image, &restore_argv, &inv.env, Some(&mut rdr), &mut sink)
            .await
            .expect("pg_restore run_ephemeral");
        let out = tokio::fs::read_to_string(&out_path)
            .await
            .unwrap_or_default();
        assert_eq!(
            code, 0,
            "pg_restore into shadow (as non-superuser); output:\n{out}"
        );
    }

    // --- TRUSTED DDL (superuser): atomic rename-swap shadow in for live ---
    for sql in [
        format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = '{live_db}' AND pid <> pg_backend_pid()"
        ),
        format!("ALTER DATABASE {live_db} RENAME TO {live_db}__old_{s}"),
        format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = '{shadow_db}' AND pid <> pg_backend_pid()"
        ),
        format!("ALTER DATABASE {shadow_db} RENAME TO {live_db}"),
        format!("DROP DATABASE IF EXISTS {live_db}__old_{s}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "swap DDL `{sql}`: {o}");
    }

    // --- row equality on the swapped-in live db ---
    let live_conn = conn(&user, &password, &host, port, &live_db);
    let (_, got) = psql(
        backend.as_ref(),
        &image,
        &live_conn,
        &format!("SELECT id || ':' || v FROM {table} ORDER BY id"),
    )
    .await;
    assert_eq!(got, expect, "rows after shadow swap match the source");

    // --- cleanup (best-effort) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("DROP DATABASE IF EXISTS {shadow_db}"),
        format!("DROP ROLE IF EXISTS \"{role}\""),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT EXPORT PG CHUNKED SHADOW OK");
}

/// **Live pg corruption → all-or-nothing abort** (inc2 Stage C; Tier-2 / nightly). Self-skips.
///
/// A TRUNCATED dump fed to `pg_restore --single-transaction` into the shadow ABORTS (non-zero), the
/// driver's drop-on-abort `DROP DATABASE <shadow>` is reproduced, and we assert NO leftover
/// `*__shadow_*` database remains AND the live db is byte-for-byte unchanged (its sentinel row
/// survives — nothing partial ever reached live). Emits `PROJECT EXPORT PG CORRUPTION ABORT OK`.
#[tokio::test]
async fn project_export_pg_corruption_aborts_live() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg corruption-abort not run)");
        return;
    };
    let Some((user, password, host, port, db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres:// URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pg corruption-abort not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let su = conn(&user, &password, &host, port, &db);
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &su,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let s = now_suffix();
    let source_db = format!("brexp_abort_src_{s}");
    let live_db = format!("brexp_abort_live_{s}");
    let shadow_db = format!("{live_db}__shadow_{s}");
    let role = format!("brexp_abort_role_{s}");
    let rolepw = format!("rpw_{s}");

    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE ROLE \"{role}\" LOGIN PASSWORD '{rolepw}' NOSUPERUSER NOCREATEDB"),
    )
    .await;
    assert_eq!(c, 0, "create role");
    for sql in [
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("CREATE DATABASE {source_db} OWNER \"{role}\""),
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db} OWNER \"{role}\""),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }

    // --- seed source + a SENTINEL row in the live db (must survive the aborted import) ---
    let src_conn = conn(&user, &password, &host, port, &source_db);
    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &src_conn,
        "CREATE TABLE t(id int primary key, v text); INSERT INTO t VALUES (7,'source');",
    )
    .await;
    assert_eq!(c, 0, "seed source");
    let live_conn = conn(&user, &password, &host, port, &live_db);
    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &live_conn,
        "CREATE TABLE sentinel(id int primary key, v text); INSERT INTO sentinel VALUES (1,'keep');",
    )
    .await;
    assert_eq!(c, 0, "seed live sentinel");

    // --- dump the source, then TRUNCATE it to simulate a corrupt/short member ---
    let td = tempfile::tempdir().unwrap();
    let dump = td.path().join("dump.pgc");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = pg_dump_invocation(&src_conn, false, "160000", &[], false);
        let f = tokio::fs::File::create(&dump).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("pg_dump");
        assert_eq!(code, 0, "pg_dump");
    }
    let bytes = std::fs::read(&dump).unwrap();
    let truncated = td.path().join("dump.trunc.pgc");
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap(); // keep the header, drop the rest

    // --- create the shadow, then feed the TRUNCATED archive as the non-superuser role ---
    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE {shadow_db} OWNER \"{role}\""),
    )
    .await;
    assert_eq!(c, 0, "create shadow");
    let role_conn = conn(&role, &rolepw, &host, port, &shadow_db);
    let restore_code = {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let inv = pg_restore_shadow_invocation(&role_conn, &shadow_db);
        let infile = tokio::fs::File::open(&truncated).await.unwrap();
        let mut rdr = infile.compat();
        let out = tokio::fs::File::create(td.path().join("r.out"))
            .await
            .unwrap();
        let mut sink = out.compat_write();
        backend
            .run_ephemeral(&image, &inv.argv, &inv.env, Some(&mut rdr), &mut sink)
            .await
            .expect("pg_restore run_ephemeral")
    };
    assert_ne!(
        restore_code, 0,
        "a truncated --single-transaction restore MUST abort non-zero (nothing committed)"
    );

    // --- driver drop-on-abort: DROP the shadow ---
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = '{shadow_db}' AND pid <> pg_backend_pid()"
        ),
    )
    .await;
    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP DATABASE IF EXISTS {shadow_db}"),
    )
    .await;
    assert_eq!(c, 0, "drop shadow on abort");

    // --- assert NO leftover *__shadow_* db + the live sentinel is intact (live never touched) ---
    let (_, shadows) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{live_db}__shadow_%'"),
    )
    .await;
    assert!(
        shadows.trim().is_empty(),
        "no orphan shadow database must remain after abort; found: {shadows:?}"
    );
    let (_, got) = psql(
        backend.as_ref(),
        &image,
        &live_conn,
        "SELECT id || ':' || v FROM sentinel ORDER BY id",
    )
    .await;
    assert_eq!(
        got, "1:keep",
        "the live db is UNCHANGED after the aborted import"
    );

    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("DROP DATABASE IF EXISTS {shadow_db}"),
        format!("DROP ROLE IF EXISTS \"{role}\""),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT EXPORT PG CORRUPTION ABORT OK");
}

/// **Live pg crafted-superuser-escape REFUSED** (inc2 Stage C — the pg analogue of Build 1's libsql
/// ATTACH-authorizer gate; Tier-2 / nightly). Self-skips.
///
/// A pg dump in a bundle is attacker-crafted, and a SUPERUSER restore of a crafted dump can `COPY …
/// TO PROGRAM` (arbitrary command) / `CREATE FUNCTION … LANGUAGE c` (arbitrary native code) = box
/// takeover. This gate proves that when those exact escape statements are applied AS THE TARGET'S
/// NON-SUPERUSER ROLE (how the driver applies every bundle dump), Postgres REFUSES each one — so the
/// out-of-target program never runs (Postgres checks the privilege BEFORE executing the program, so
/// a refusal means nothing outside the target was touched). `pg_restore` runs an archive's COPY/
/// CREATE statements as the connected role, so the identical confinement applies to a real crafted
/// `-Fc` bundle. Emits `PROJECT EXPORT PG CRAFTED ESCAPE REFUSED OK`.
#[tokio::test]
async fn project_export_pg_crafted_superuser_escape_refused_live() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg crafted-escape gate not run)");
        return;
    };
    let Some((user, password, host, port, db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres:// URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pg crafted-escape gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let su = conn(&user, &password, &host, port, &db);
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &su,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let s = now_suffix();
    let scratch = format!("brexp_escape_{s}");
    let role = format!("brexp_escape_role_{s}");
    let rolepw = format!("rpw_{s}");
    // An out-of-target path a superuser COPY TO PROGRAM would create (on the server); the refusal
    // means the program never runs.
    let victim = format!("/tmp/brexp_pwned_{s}");

    let (c, _) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "CREATE ROLE \"{role}\" LOGIN PASSWORD '{rolepw}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
        ),
    )
    .await;
    assert_eq!(c, 0, "create the non-superuser role");
    for sql in [
        format!("DROP DATABASE IF EXISTS {scratch}"),
        format!("CREATE DATABASE {scratch} OWNER \"{role}\""),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }

    // Each escape is run AS THE NON-SUPERUSER ROLE (the identity the driver's pg_restore uses).
    let role_conn = conn(&role, &rolepw, &host, port, &scratch);

    // (1) COPY … TO PROGRAM — needs superuser / pg_execute_server_program; MUST be refused.
    let (copy_code, copy_out) = psql(
        backend.as_ref(),
        &image,
        &role_conn,
        &format!("COPY (SELECT 1) TO PROGRAM 'touch {victim}'"),
    )
    .await;
    assert_ne!(
        copy_code, 0,
        "COPY ... TO PROGRAM must be REFUSED to a non-superuser role; output:\n{copy_out}"
    );

    // (2) CREATE FUNCTION … LANGUAGE c — only a superuser may create a C-language function.
    let (fn_code, fn_out) = psql(
        backend.as_ref(),
        &image,
        &role_conn,
        "CREATE FUNCTION brexp_evil() RETURNS integer AS '/bin/false', 'x' LANGUAGE c",
    )
    .await;
    assert_ne!(
        fn_code, 0,
        "CREATE FUNCTION ... LANGUAGE c must be REFUSED to a non-superuser role; output:\n{fn_out}"
    );

    // (3) CREATE EXTENSION of an untrusted extension — likewise superuser-only.
    let (ext_code, _ext_out) = psql(
        backend.as_ref(),
        &image,
        &role_conn,
        "CREATE EXTENSION IF NOT EXISTS plpython3u",
    )
    .await;
    assert_ne!(
        ext_code, 0,
        "CREATE EXTENSION of an untrusted language must be REFUSED to a non-superuser role"
    );

    for sql in [
        format!("DROP DATABASE IF EXISTS {scratch}"),
        format!("DROP ROLE IF EXISTS \"{role}\""),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT EXPORT PG CRAFTED ESCAPE REFUSED OK");
}

/// Hand-build a v3 bundle carrying ONLY a CHUNKED `PgDump` member `sql/<db>.pgc` whose body is a
/// real `-Fc` archive (produced by `pg_dump`) — models a crafted pg member crossing the trust
/// boundary. Drives the driver-SURFACE crafted-escape gate below.
fn craft_chunked_pg_bundle(source: &str, db: &str, dump: &[u8]) -> Vec<u8> {
    use boatramp_node::project_bundle::{self, MemberKind, MemberSpec, SourceInfo};
    let member_path = format!("sql/{db}.pgc");
    let specs = vec![MemberSpec::chunked(member_path, MemberKind::PgDump, None)];
    let dump = dump.to_vec();
    let mut out: Vec<u8> = Vec::new();
    project_bundle::write_bundle_streaming_v3(
        &mut out,
        0,
        false,
        SourceInfo {
            project: source.to_string(),
            site: None,
        },
        specs,
        1 << 16,
        |_spec| unreachable!("the crafted bundle has no sidecar member"),
        |_spec| Ok(Box::new(std::io::Cursor::new(dump.clone())) as Box<dyn std::io::Read>),
    )
    .expect("craft chunked pg bundle");
    out
}

/// **Live pg crafted-escape REFUSED THROUGH THE REAL DRIVER** (inc2 HIGH-1 gate — the pg analogue of
/// the libsql `shadow_apply_refuses_writefile_and_load_extension` gate, driven end-to-end through
/// `NodeProjectExport::import`, NOT a hand-provisioned role; Tier-2 / nightly). Self-skips.
///
/// This proves the SURFACE: a crafted bundle whose chunked pg member defines a `CREATE EVENT
/// TRIGGER` — a DEFINITIVELY superuser-only op, and itself an import-time code-execution vector (an
/// event trigger runs its function on DDL) — is REFUSED when imported through the real driver on a
/// MANAGED, Single/dedicated config, because the driver applies the untrusted dump as a
/// freshly-minted EPHEMERAL NON-SUPERUSER role (the HIGH-1 fix) — NOT the bootstrap superuser. An
/// event trigger is chosen over the alternatives because it needs no external file (unlike a
/// `LANGUAGE c` function, whose library Postgres accesses at CREATE even with
/// `check_function_bodies=off`, so a nonexistent-lib payload cannot be created in the SOURCE),
/// `pg_dump` emits it into a `-Fc` archive (unlike `COPY … TO PROGRAM`), and a db-owner cannot
/// install it (unlike `CREATE EXTENSION` of a trusted-marked extension like recent pgvector, which
/// would false-RED the gate). The import FAILS and the superuser-only side-effect never lands (the
/// event trigger is absent from the live target, no `*__shadow_*` db remains, no `brexp_apply_*`
/// role leaks). The companion `..._crafted_superuser_escape_refused_live` mechanism test covers the
/// `COPY … TO PROGRAM` filesystem-marker escape against the same kind of non-superuser role. Emits
/// `PROJECT EXPORT PG CRAFTED ESCAPE DRIVER OK`.
#[tokio::test]
async fn project_export_pg_crafted_escape_refused_via_driver_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_export::{ImportOptions, ProjectExport};
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg crafted-escape DRIVER gate not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (crafted-escape DRIVER gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let source_db = format!("brexp_ce_src_{s}");
    let live_db = format!("brexp_ce_live_{s}");
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // --- build a crafted SOURCE db that defines a superuser-only `CREATE EVENT TRIGGER` + dump it.
    //     The event trigger (its no-op plpgsql function is creatable by anyone) needs no external
    //     file, is emitted by `pg_dump -Fc`, and a restore hits the superuser-only privilege check
    //     ("permission denied to create event trigger"). The trigger is created LAST so its (empty)
    //     body never fires on the source's own DDL. ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("CREATE DATABASE {source_db}"),
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let src = conn(&user, &password, &host, port, &source_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &src,
        "CREATE TABLE t(id int primary key); \
         CREATE FUNCTION brexp_evil_et_fn() RETURNS event_trigger \
           LANGUAGE plpgsql AS $$ BEGIN END $$; \
         CREATE EVENT TRIGGER brexp_evil_et ON ddl_command_start \
           EXECUTE FUNCTION brexp_evil_et_fn();",
    )
    .await;
    assert_eq!(
        c, 0,
        "define the superuser-only event trigger in the source: {o}"
    );
    let td = tempfile::tempdir().unwrap();
    let dumpf = td.path().join("src.pgc");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = pg_dump_invocation(&src, false, "160000", &[], false);
        let f = tokio::fs::File::create(&dumpf).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("pg_dump");
        assert_eq!(code, 0, "pg_dump source (with the event trigger)");
    }
    let dump_bytes = std::fs::read(&dumpf).unwrap();
    let bundle = craft_chunked_pg_bundle("default", "app", &dump_bytes);

    // --- build a MANAGED, Single/default driver pointing at the test DSN (seeded replica) ---
    let databases = BTreeMap::from([(
        "app".to_string(),
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            compute: Some("pg".to_string()),
            database: Some(live_db.clone()),
            user: Some(user.clone()),
            ..Default::default() // tenant=Single, tenant_scope=Project (the dedicated case)
        },
    )]);
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([7u8; 32]));
    // Seal the DSN (superuser) password under the EXACT key operator_target derives for
    // Single/default: managed-sql-cred/default/pg.
    {
        let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
        kv.put("managed-sql-cred/default/pg", sealed).await.unwrap();
    }
    let td2 = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td2.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    // Seed a healthy running replica for (default, "pg") whose endpoint is the test DSN.
    deploy
        .set_replica_state(
            boatramp_core::project::ProjectRef::new("default"),
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
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
            },
        )
        .await
        .unwrap();
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        DeployStore::new(blobs.clone(), kv.clone()),
    ));
    let work = td2.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let drv = NodeProjectExport::new(databases, deploy, kv.clone(), blobs.clone(), work)
        // published_endpoint=false ⇒ the seeded replica endpoint host is used verbatim.
        .with_managed_pg(backend.clone(), envelope, op, false)
        // The refused op is a superuser-only event trigger (superuser-only regardless of any
        // extension allowlist), so the allowlist is irrelevant here — empty.
        .with_trusted_extensions(vec![]);

    // --- import the crafted bundle THROUGH THE REAL DRIVER: must FAIL (escape refused) ---
    let mut src_body = futures::io::Cursor::new(bundle);
    let res = drv
        .import(
            "default",
            &mut src_body,
            ImportOptions {
                apply: true,
                overwrite: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        res.is_err(),
        "import of a crafted bundle defining an event trigger MUST fail (the non-superuser \
         apply cannot CREATE an event trigger); got: {res:?}"
    );

    // --- side-effect never landed: the event trigger is absent from live, no shadow/role leaked ---
    let live = conn(&user, &password, &host, port, &live_db);
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT 1 FROM pg_event_trigger WHERE evtname = 'brexp_evil_et'",
    )
    .await;
    assert!(
        got.trim().is_empty(),
        "the crafted superuser-only event trigger must NOT exist in the live target after a refused import"
    );
    let (_c, shadows) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{live_db}__shadow_%'"),
    )
    .await;
    assert!(
        shadows.trim().is_empty(),
        "no orphan shadow database must remain: {shadows:?}"
    );
    let (_c, roles) = psql(
        backend.as_ref(),
        &image,
        &maint,
        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'brexp_apply_%'",
    )
    .await;
    assert!(
        roles.trim().is_empty(),
        "no orphan ephemeral apply role must remain: {roles:?}"
    );

    // --- cleanup (best-effort) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {source_db}"),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT EXPORT PG CRAFTED ESCAPE DRIVER OK");
}

/// **Live POSITIVE pgvector round-trip THROUGH THE REAL DRIVER** (inc2 HIGH-1 L3 — the load-bearing
/// correctness proof for the env-clone pipeline; Tier-2 / nightly, needs a live pgvector pg +
/// `BOATRAMP_TEST_PG_URL`). Self-skips.
///
/// Proves that a legit FULL dedicated bundle of a source DB that USES pgvector (a `vector(3)` column
/// with rows) round-trips SUCCESSFULLY under the ephemeral NON-SUPERUSER apply when `vector` is on
/// the extension allowlist: the superuser pre-creates `vector` in the shadow, so the dump's
/// `CREATE EXTENSION IF NOT EXISTS vector` NO-OPS (the existence check precedes the superuser
/// privilege check, so no superuser is needed to re-run it) and the `vector(3)` table + rows restore
/// as the ephemeral role. The dump is taken `--no-comments`, so the OWNER-only `COMMENT ON EXTENSION
/// vector` that pg_dump would otherwise emit — which the non-superuser apply could not run on the
/// superuser-owned extension — is absent (the extension's comment is re-set by CREATE EXTENSION
/// regardless). Drives the REAL `pg_dump` (the driver's export primitive) →
/// the REAL `NodeProjectExport::import`, then asserts: the import SUCCEEDS, the swapped-in live DB
/// has the `vector` extension + the table rows intact, the ephemeral `brexp_apply_%` role is DROPPED,
/// the `*__shadow_*` db is GONE, and the live DB is owned by the configured owner. This is the
/// end-to-end proof that the non-superuser confinement does NOT break a pgvector restore. Emits
/// `PROJECT EXPORT PG PGVECTOR ROUNDTRIP OK`.
#[tokio::test]
async fn project_export_pg_pgvector_roundtrip_via_driver_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_export::{ImportOptions, ProjectExport};
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pgvector round-trip not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pgvector round-trip not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let source_db = format!("brexp_pv_src_{s}");
    let live_db = format!("brexp_pv_live_{s}");
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // --- a source DB that USES pgvector (vector(3) column + rows) + dump it ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("CREATE DATABASE {source_db}"),
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let src = conn(&user, &password, &host, port, &source_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &src,
        "CREATE EXTENSION IF NOT EXISTS vector; \
         CREATE TABLE items(id int primary key, embedding vector(3)); \
         INSERT INTO items VALUES (1, '[1,2,3]'), (2, '[4,5,6]');",
    )
    .await;
    assert_eq!(
        c, 0,
        "seed pgvector source (needs the pgvector image, e.g. pgvector/pgvector:pg16): {o}"
    );
    let td = tempfile::tempdir().unwrap();
    let dumpf = td.path().join("src.pgc");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = pg_dump_invocation(&src, false, "160000", &[], false);
        let f = tokio::fs::File::create(&dumpf).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("pg_dump");
        assert_eq!(code, 0, "pg_dump pgvector source");
    }
    let bundle = craft_chunked_pg_bundle("default", "app", &std::fs::read(&dumpf).unwrap());

    // --- MANAGED Single/default driver pointing at the test DSN (seeded replica), vector ALLOWLISTED ---
    let databases = BTreeMap::from([(
        "app".to_string(),
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            compute: Some("pg".to_string()),
            database: Some(live_db.clone()),
            user: Some(user.clone()),
            ..Default::default()
        },
    )]);
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    {
        let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
        kv.put("managed-sql-cred/default/pg", sealed).await.unwrap();
    }
    let td2 = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td2.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    deploy
        .set_replica_state(
            boatramp_core::project::ProjectRef::new("default"),
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
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
            },
        )
        .await
        .unwrap();
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        DeployStore::new(blobs.clone(), kv.clone()),
    ));
    let work = td2.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let drv = NodeProjectExport::new(databases, deploy, kv.clone(), blobs.clone(), work)
        .with_managed_pg(backend.clone(), envelope, op, false)
        // vector ON the allowlist ⇒ the superuser pre-creates it in the shadow ⇒ the dump's
        // `CREATE EXTENSION IF NOT EXISTS vector` no-ops under the ephemeral non-superuser apply.
        .with_trusted_extensions(vec!["vector".to_string()]);

    // --- import THROUGH THE REAL DRIVER: must SUCCEED under the non-superuser apply ---
    let mut src_body = futures::io::Cursor::new(bundle);
    let res = drv
        .import(
            "default",
            &mut src_body,
            ImportOptions {
                apply: true,
                overwrite: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        res.is_ok(),
        "a legit pgvector bundle MUST round-trip under the ephemeral non-superuser apply when \
         `vector` is allowlisted; got: {res:?}"
    );

    // --- the swapped-in live DB has vector + the rows intact ---
    let live = conn(&user, &password, &host, port, &live_db);
    let (_c, has_vec) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT 1 FROM pg_extension WHERE extname = 'vector'",
    )
    .await;
    assert_eq!(
        has_vec.trim(),
        "1",
        "the live DB must have the vector extension after restore"
    );
    let (_c, rows) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT id || ':' || embedding FROM items ORDER BY id",
    )
    .await;
    assert_eq!(
        rows, "1:[1,2,3]\n2:[4,5,6]",
        "the vector(3) table's rows must round-trip intact"
    );
    // --- the ephemeral role is dropped, the shadow is gone, live is owned by the configured owner ---
    let (_c, roles) = psql(
        backend.as_ref(),
        &image,
        &maint,
        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'brexp_apply_%'",
    )
    .await;
    assert!(
        roles.trim().is_empty(),
        "no ephemeral apply role must remain: {roles:?}"
    );
    let (_c, shadows) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{live_db}__shadow_%'"),
    )
    .await;
    assert!(
        shadows.trim().is_empty(),
        "no shadow db must remain: {shadows:?}"
    );
    let (_c, owner) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{live_db}'"
        ),
    )
    .await;
    assert_eq!(
        owner.trim(),
        user,
        "the swapped-in live DB must be owned by the configured owner, not the ephemeral role"
    );

    // --- cleanup (best-effort) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {source_db}"),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT EXPORT PG PGVECTOR ROUNDTRIP OK");
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
    tgt.restore_snapshot(&qsite, "", &member_file, false)
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

    // --- no-clobber: a second restore over the now-populated target must refuse without
    //     overwrite (the shadow restore's overwrite gate, replacing the v1 no-clobber) ---
    assert!(
        tgt.restore_snapshot(&qsite, "", &member_file, false)
            .await
            .is_err(),
        "restore_snapshot must refuse to overwrite a non-empty destination"
    );

    println!("PROJECT EXPORT LIBSQL ROUNDTRIP OK");
}

/// **§4b — the no-Docker ATOMICITY gate (chunked `.dump` libsql through the real driver).** Drives
/// `NodeProjectExport::export` → `import` for a libsql-only project: the export streams the site's
/// database as a ChunkedTrailer `.dump` member (v3), and the import applies it into an ATOMIC
/// shadow DB that is `std::fs::rename`d over live only when the trailing SHA verified. Proves BOTH:
///  (1) a clean round-trip restores the rows and leaves NO `*.shadow_*` residue (commit); and
///  (2) corruption → ALL-OR-NOTHING: a bundle whose libsql member is tampered (so its streamed
///      bytes no longer match the trailer) imported with `overwrite=true` ABORTS, the target's
///      pre-existing SENTINEL rows SURVIVE (live is never renamed-over), and no shadow is left.
///
/// RED mutations: dropping the trailer-verify (commit-always) promotes the corrupt shadow → the
/// sentinel assertion fails; a non-atomic restore (apply straight onto live) → the sentinel is gone.
#[tokio::test]
async fn project_export_roundtrip_libsql_chunked_atomic() {
    use boatramp_core::Storage;
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_export::{
        ExportOptions, IdentityChoice, ImportOptions, ProjectExport,
    };
    use boatramp_core::sql::{SqlBackend, SqlBackends, SqlValue};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use boatramp_storage::sql_libsql::LibsqlSqlBackends;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn byte_find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }
    fn shadow_residue(dir: &std::path::Path) -> usize {
        let mut n = 0;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p
                        .file_name()
                        .and_then(|x| x.to_str())
                        .is_some_and(|x| x.contains(".shadow_"))
                    {
                        n += 1;
                    }
                }
            }
        }
        n
    }

    let project = "acme";
    let site = "blog";
    const MARKER: &str = "SRCMARKER_UNIQUE_9z7q";

    // --- SOURCE: a libsql-only project with one site DB (+ a KV site pointer so list_sites finds
    //     it). A small chunk size makes the `.dump` span several `.part` entries. ---
    let src_tmp = tempfile::tempdir().unwrap();
    let src_libsql_dir = src_tmp.path().join("handlers-sql");
    let src_backends = Arc::new(LibsqlSqlBackends::local(&src_libsql_dir));
    {
        let db: Arc<dyn SqlBackend> = src_backends.database(project, site, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", &[])
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO t VALUES (?1,?2),(?3,?4)",
            &[
                SqlValue::Integer(1),
                SqlValue::Text(MARKER.into()),
                SqlValue::Integer(2),
                SqlValue::Text("beta".into()),
            ],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let src_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    // A `current/<site>` pointer so `DeployStore::list_sites` enumerates the site.
    src_kv
        .put("project/acme/current/blog", b"dep1".to_vec())
        .await
        .unwrap();
    let src_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(src_tmp.path().join("blobs")));
    let src_work = src_tmp.path().join("work");
    std::fs::create_dir_all(&src_work).unwrap();
    let drv = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(src_blobs.clone(), src_kv.clone()),
        src_kv.clone(),
        src_blobs.clone(),
        src_work,
    )
    .with_libsql(src_backends.clone())
    .with_chunk_size(4096);

    // EXPORT (FULL) → a v3 bundle with a ChunkedTrailer libsql member.
    let bundle = {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        drv.export(project, &ExportOptions::default(), &mut sink)
            .await
            .expect("export");
        sink.into_inner()
    };
    assert!(
        byte_find(&bundle, b"\"format_version\": 3").is_some(),
        "the bundle is v3 (a chunked libsql member is present)"
    );
    assert!(
        byte_find(&bundle, b"libsql/acme/blog/default.sqlite.part00000").is_some(),
        "the libsql member is framed as chunked `.part` entries"
    );
    assert!(
        byte_find(&bundle, b"libsql/acme/blog/default.sqlite.brtrailer").is_some(),
        "the chunked libsql member carries a trailing `.brtrailer`"
    );

    // --- IMPORT (1): clean round-trip into a FRESH target via the atomic shadow. ---
    let tgt_tmp = tempfile::tempdir().unwrap();
    let tgt_libsql_dir = tgt_tmp.path().join("handlers-sql");
    let tgt_backends = Arc::new(LibsqlSqlBackends::local(&tgt_libsql_dir));
    let tgt_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let tgt_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tgt_tmp.path().join("blobs")));
    let tgt_work = tgt_tmp.path().join("work");
    std::fs::create_dir_all(&tgt_work).unwrap();
    let tgt_drv = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(tgt_blobs.clone(), tgt_kv.clone()),
        tgt_kv.clone(),
        tgt_blobs.clone(),
        tgt_work,
    )
    .with_libsql(tgt_backends.clone());
    {
        let mut src = futures::io::Cursor::new(bundle.clone());
        let report = tgt_drv
            .import(
                project,
                &mut src,
                ImportOptions {
                    apply: true,
                    force: true,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("clean import");
        assert!(report.libsql_databases >= 1, "a libsql db was restored");
    }
    // Rows restored + NO shadow residue (the commit cleaned up).
    {
        let db: Arc<dyn SqlBackend> = tgt_backends.database(project, site, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let rows = tx
            .query("SELECT id, v FROM t ORDER BY id", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(rows.rows.len(), 2);
        assert_eq!(rows.rows[0][1], SqlValue::Text(MARKER.into()));
    }
    assert_eq!(
        shadow_residue(&tgt_libsql_dir),
        0,
        "no *.shadow_* residue after a committed chunked import"
    );

    // --- IMPORT (2): corruption → ALL-OR-NOTHING. Pre-seed the target with a SENTINEL, tamper the
    //     bundle's libsql `.dump` so its bytes no longer hash to the trailer, import overwrite=true
    //     → abort; sentinel survives; no shadow residue. ---
    let cor_tmp = tempfile::tempdir().unwrap();
    let cor_libsql_dir = cor_tmp.path().join("handlers-sql");
    let cor_backends = Arc::new(LibsqlSqlBackends::local(&cor_libsql_dir));
    {
        let db: Arc<dyn SqlBackend> = cor_backends.database(project, site, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute("CREATE TABLE sentinel(v TEXT)", &[])
            .await
            .unwrap();
        tx.execute("INSERT INTO sentinel VALUES ('SURVIVOR')", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    // Flip one byte of the source marker inside the chunked `.dump` (a `.part` body). The member's
    // streamed bytes now differ from the (unchanged) trailer SHA → the atomic reader aborts.
    let mut corrupt = bundle.clone();
    let at = byte_find(&corrupt, MARKER.as_bytes()).expect("marker present in the dump stream");
    corrupt[at + MARKER.len() - 1] ^= 0x01; // 'z' → '{' : still valid SQL text, wrong bytes
    let cor_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let cor_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(cor_tmp.path().join("blobs")));
    let cor_work = cor_tmp.path().join("work");
    std::fs::create_dir_all(&cor_work).unwrap();
    let cor_drv = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(cor_blobs.clone(), cor_kv.clone()),
        cor_kv.clone(),
        cor_blobs.clone(),
        cor_work,
    )
    .with_libsql(cor_backends.clone());
    {
        let mut src = futures::io::Cursor::new(corrupt);
        let res = cor_drv
            .import(
                project,
                &mut src,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: true, // the target libsql db exists (sentinel)
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await;
        assert!(
            res.is_err(),
            "a tampered chunked libsql member must ABORT the import"
        );
    }
    // The SENTINEL survives (live was never renamed-over), and no shadow residue remains.
    {
        let db: Arc<dyn SqlBackend> = cor_backends.database(project, site, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query("SELECT v FROM sentinel", &[]).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            rows.rows,
            vec![vec![SqlValue::Text("SURVIVOR".into())]],
            "the aborted corrupt import left the live target untouched (atomic)"
        );
        // The tampered import's table `t` never reached live.
        let mut tx = db.begin().await.unwrap();
        assert!(
            tx.query("SELECT 1 FROM t", &[]).await.is_err(),
            "the corrupt import's table must NOT exist on the live target"
        );
        tx.rollback().await.unwrap();
    }
    assert_eq!(
        shadow_residue(&cor_libsql_dir),
        0,
        "the aborted corrupt import left no *.shadow_* residue"
    );

    println!("PROJECT EXPORT LIBSQL CHUNKED ATOMIC OK");
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

/// **Live MySQL ATOMIC shadow-restore round-trip** (inc2 Stage D; Tier-2 / nightly — needs a Docker
/// daemon AND a MySQL server whose DSN user can `CREATE USER`/`GRANT`/`CREATE DATABASE`). Self-skips.
///
/// Proves the non-superuser-apply split + the `RENAME TABLE` swap: seed a SOURCE db, dump it
/// TABLES-ONLY (`mysqldump_tables_only_invocation` — no `CREATE DATABASE`/`USE`), create a SHADOW db
/// + a NON-SUPERUSER user granted only on the shadow, apply the dump with `mysql_shadow_invocation`
/// AS THAT NON-SUPERUSER USER, then atomically `RENAME TABLE shadow.t → live.t` (after moving any
/// live table aside) and assert ROW equality on the swapped-in live db. Emits
/// `PROJECT EXPORT MYSQL SHADOW OK`.
#[tokio::test]
async fn project_export_mysql_chunked_shadow_live() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (live mysql shadow round-trip not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live mysql shadow round-trip not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    let s = now_suffix();
    let source_db = format!("brexp_mysh_src_{s}");
    let live_db = format!("brexp_mysh_live_{s}");
    let shadow_db = format!("{live_db}__shadow_{s}");
    let role = format!("brexp_mysh_role_{s}");
    let rolepw = format!("rpw_{s}");
    let expect = "1:alpha\n2:beta\n3:gamma";

    let mkconn = |db: &str, u: &str, pw: &str| MysqlConnection {
        host: host.clone(),
        port,
        user: u.to_string(),
        password: pw.to_string(),
        database: db.to_string(),
        connect_timeout_secs: 10,
    };
    let admin = mkconn("", &user, &password); // superuser, no default db

    // --- TRUSTED DDL (superuser): dbs + a NON-SUPERUSER user granted ONLY on the shadow + live ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!(
            "DROP DATABASE IF EXISTS {source_db}; CREATE DATABASE {source_db}; \
             DROP DATABASE IF EXISTS {live_db}; CREATE DATABASE {live_db}; \
             DROP DATABASE IF EXISTS {shadow_db}; CREATE DATABASE {shadow_db}; \
             CREATE USER '{role}'@'%' IDENTIFIED BY '{rolepw}'; \
             GRANT ALL PRIVILEGES ON `{shadow_db}`.* TO '{role}'@'%';"
        ),
    )
    .await;
    assert_eq!(c, 0, "setup DDL; mysql output:\n{o}");

    // --- seed the SOURCE db ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&source_db),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         INSERT INTO t VALUES (1,'alpha'),(2,'beta'),(3,'gamma');",
    )
    .await;
    assert_eq!(c, 0, "seed source; mysql output:\n{o}");

    // --- EXPORT: tables-only mysqldump of the source db (no CREATE DATABASE/USE) → temp ---
    let td = tempfile::tempdir().unwrap();
    let dump = td.path().join("dump.sql");
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let inv = mysqldump_tables_only_invocation(&mkconn(&source_db, &user, &password));
        let f = tokio::fs::File::create(&dump).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(image, &inv.argv, &inv.env, None, &mut sink)
            .await
            .expect("mysqldump run_ephemeral");
        assert_eq!(code, 0, "mysqldump tables-only");
    }
    assert!(
        std::fs::metadata(&dump)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "tables-only dump is non-empty"
    );

    // --- IMPORT: apply into the SHADOW as the NON-SUPERUSER user (stdin = the dump) ---
    {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let role_conn = mkconn(&shadow_db, &role, &rolepw);
        let inv = mysql_shadow_invocation(&role_conn, &shadow_db);
        // Fold stderr into the sink so a failed apply surfaces its reason.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("{} 2>&1", inv.argv.join(" ")),
        ];
        let infile = tokio::fs::File::open(&dump).await.unwrap();
        let mut rdr = infile.compat();
        let out_path = td.path().join("apply.out");
        let out = tokio::fs::File::create(&out_path).await.unwrap();
        let mut sink = out.compat_write();
        let code = backend
            .run_ephemeral(image, &argv, &inv.env, Some(&mut rdr), &mut sink)
            .await
            .expect("mysql apply run_ephemeral");
        let out = tokio::fs::read_to_string(&out_path)
            .await
            .unwrap_or_default();
        assert_eq!(
            code, 0,
            "mysql apply into shadow (as non-superuser); output:\n{out}"
        );
    }

    // --- TRUSTED DDL (superuser): atomic RENAME TABLE swap (live has no tables yet) + drop shadow ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!(
            "RENAME TABLE `{shadow_db}`.`t` TO `{live_db}`.`t`; \
             DROP DATABASE IF EXISTS {shadow_db};"
        ),
    )
    .await;
    assert_eq!(c, 0, "RENAME TABLE swap; mysql output:\n{o}");

    // --- row equality on the swapped-in live db ---
    let (_c, got) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        got, expect,
        "rows after the mysql shadow swap match the source"
    );

    // --- cleanup ---
    let _ = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!(
            "DROP DATABASE IF EXISTS {live_db}; DROP DATABASE IF EXISTS {source_db}; \
             DROP DATABASE IF EXISTS {shadow_db}; DROP USER IF EXISTS '{role}'@'%';"
        ),
    )
    .await;

    println!("PROJECT EXPORT MYSQL SHADOW OK");
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
                    delta: None,
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
    use boatramp_core::project::ProjectRef;
    use boatramp_core::project_export::{
        ExportOptions, IdentityChoice, ImportOptions, ProjectExport,
    };
    use boatramp_core::sql::{SqlBackend, SqlBackends, SqlValue};
    use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use boatramp_storage::sql_libsql::LibsqlSqlBackends;
    use bytes::Bytes;
    use futures::StreamExt;
    use sha2::{Digest, Sha256};

    fn byte_find(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

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
        let specs = vec![MemberSpec::sidecar(
            project_bundle::KV_MEMBER_PATH.to_string(),
            MemberKind::Kv,
            None,
        )];
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

    /// Hand-build a v3 bundle carrying ONLY a KV slice framed as a CHUNKED member (`.part*` +
    /// `.brtrailer`, bypassing the export-side scope filter), to prove framing is NOT a tenancy
    /// bypass: the import must run `enforce_target_scoped_kv` on a chunked KV member exactly as on a
    /// sidecar one. A deliberately small `chunk_size` splits the slice into several parts; the
    /// trailer is self-consistent (a crafted-but-valid bundle), so the ONLY thing that can refuse it
    /// is the scope enforce — which it must.
    fn craft_chunked_bundle(source: &str, entries: &[(String, Vec<u8>)]) -> Vec<u8> {
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
        let specs = vec![MemberSpec::chunked(
            project_bundle::KV_MEMBER_PATH.to_string(),
            MemberKind::Kv,
            None,
        )];
        let mut out: Vec<u8> = Vec::new();
        project_bundle::write_bundle_streaming_v3(
            &mut out,
            0,
            false,
            SourceInfo {
                project: source.to_string(),
                site: None,
            },
            specs,
            8, // tiny chunk size ⇒ the crafted KV slice spans multiple `.part` entries
            |_spec| unreachable!("the crafted bundle has no sidecar member"),
            |_spec| Ok(Box::new(std::io::Cursor::new(kv_bytes.clone())) as Box<dyn std::io::Read>),
        )
        .unwrap();
        out
    }

    /// Hand-build a v3 bundle carrying ONLY a CHUNKED libsql member whose `.dump` is arbitrary
    /// attacker-supplied SQL text — models a crafted libsql member crossing the trust boundary
    /// (HIGH-1). The member path `libsql/<source>/<site>/default.sqlite` makes the import resolve
    /// the target site; the import must confine the apply so the `.dump` can touch nothing outside
    /// the shadow.
    fn craft_chunked_libsql_bundle(source: &str, site: &str, dump_text: &str) -> Vec<u8> {
        use boatramp_node::project_bundle::{self, MemberKind, MemberSpec, SourceInfo};
        let member_path = format!("libsql/{source}/{site}/default.sqlite");
        let specs = vec![MemberSpec::chunked(member_path, MemberKind::Libsql, None)];
        let dump = dump_text.as_bytes().to_vec();
        let mut out: Vec<u8> = Vec::new();
        project_bundle::write_bundle_streaming_v3(
            &mut out,
            0,
            false,
            SourceInfo {
                project: source.to_string(),
                site: Some(site.to_string()),
            },
            specs,
            64,
            |_spec| unreachable!("the crafted bundle has no sidecar member"),
            |_spec| Ok(Box::new(std::io::Cursor::new(dump.clone())) as Box<dyn std::io::Read>),
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
    // A LARGE acme blob (> the test chunk size) → export frames it ChunkedTrailer; its re-key on
    // import must behave EXACTLY as a sidecar blob's. Its body carries only an acme-only marker
    // (never a cross-tenant sentinel), so the byte-scan over the bundle stays meaningful.
    const ACME_BIG_MARKER: &[u8] = b"ACME_BIG_BLOB_MARKER_4a9f_";
    let big_blob: Vec<u8> = ACME_BIG_MARKER.iter().cycle().take(4096).copied().collect();
    put_blob(blobs.as_ref(), "hblob/acme/web/c/big.bin", &big_blob).await;

    // A libsql binding: a source site DB (+ a `current/<site>` pointer so the export enumerates it)
    // so the bundle carries a CHUNKED libsql `.dump` member whose target-SITE re-key must hold on a
    // rename import.
    let src_libsql_dir = src_tmp.path().join("handlers-sql");
    let src_libsql = Arc::new(LibsqlSqlBackends::local(&src_libsql_dir));
    {
        let db: Arc<dyn SqlBackend> = src_libsql.database("acme", "blog", "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", &[])
            .await
            .unwrap();
        tx.execute("INSERT INTO t VALUES (1,'acme-libsql-row')", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    kv.put("project/acme/current/blog", b"dep1".to_vec())
        .await
        .unwrap();

    let work = src_tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    // A small chunk size so the 4 KiB blob + the libsql `.dump` are framed as several `.part`
    // entries (inc2 default #6 chunk size is 64 MiB; `with_chunk_size` is the test override).
    let drv = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(blobs.clone(), kv.clone()),
        kv.clone(),
        blobs.clone(),
        work,
    )
    .with_libsql(src_libsql.clone())
    .with_chunk_size(1024);

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

    // The bundle is v3 and BOTH the large blob and the libsql `.dump` are framed as chunked
    // `.part` members (so the chunked re-key + atomic restore paths are actually exercised).
    assert!(
        byte_find(&bundle, b"\"format_version\": 3"),
        "a chunked member makes the bundle v3"
    );
    assert!(
        byte_find(&bundle, b"blobs/hblob/acme/web/c/big.bin.part00000"),
        "the large acme blob is framed ChunkedTrailer"
    );
    assert!(
        byte_find(&bundle, b"libsql/acme/blog/default.sqlite.part00000"),
        "the libsql member is framed ChunkedTrailer (streamed `.dump`)"
    );

    // === IMPORT into a fresh SAME-NAME target store ===
    let tgt_tmp = tempfile::tempdir().unwrap();
    let tgt_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let tgt_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tgt_tmp.path().join("blobs")));
    let tgt_libsql = Arc::new(LibsqlSqlBackends::local(
        tgt_tmp.path().join("handlers-sql"),
    ));
    let tgt_work = tgt_tmp.path().join("work");
    std::fs::create_dir_all(&tgt_work).unwrap();
    let tgt = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(tgt_blobs.clone(), tgt_kv.clone()),
        tgt_kv.clone(),
        tgt_blobs.clone(),
        tgt_work,
    )
    .with_libsql(tgt_libsql.clone());
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
    // The CHUNKED (large) blob restored under acme's scope with its bytes intact — the chunked
    // re-key lands it in the target scope exactly as a sidecar blob.
    assert!(
        tgt_blob_keys
            .iter()
            .any(|k| k == "hblob/acme/web/c/big.bin"),
        "the chunked large blob restored under hblob/acme/"
    );
    assert_eq!(
        read_blob(tgt_blobs.as_ref(), "hblob/acme/web/c/big.bin").await,
        big_blob,
        "the chunked blob round-trips byte-for-byte"
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

    // The CHUNKED libsql member restored into the target under acme's qualified site identity (the
    // atomic shadow swapped in), with its row intact.
    {
        let db: Arc<dyn SqlBackend> = tgt_libsql.database("acme", "blog", "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query("SELECT v FROM t", &[]).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            rows.rows,
            vec![vec![SqlValue::Text("acme-libsql-row".into())]],
            "the chunked libsql `.dump` member restored under acme's scope"
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
    // Each crafted case is run with BOTH a Sidecar KV member AND a CHUNKED KV member — framing must
    // NOT be a tenancy-barrier bypass: `enforce_target_scoped_kv` runs regardless of framing, so a
    // chunked crafted member aborts fail-closed exactly as a sidecar one (writing nothing foreign).
    for (what, entries) in &malicious_sets {
        for (framing, crafted) in [
            ("sidecar", craft_kv_bundle("acme", entries)),
            ("chunked", craft_chunked_bundle("acme", entries)),
        ] {
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
                "import of a {framing} bundle carrying {what} MUST be refused (fail-closed)"
            );
            // Fail-closed: the target KV holds NONE of the crafted foreign/global keys.
            let after = mt_kv.list_prefix("").await.unwrap();
            assert!(
                !after.iter().any(|k| k.contains("globex")
                    || k.starts_with("cert/")
                    || k.starts_with("domain/")
                    || k.starts_with("daemonconfig/")
                    || k.starts_with("siteconfig/")),
                "a refused {framing} import ({what}) must not have written any foreign/global key"
            );
        }
    }

    // === HIGH-1 (inc2 Security): a crafted CHUNKED LIBSQL member whose `.dump` carries an
    //     `ATTACH DATABASE '<out-of-target abs path>'` escape is REFUSED, and the out-of-target
    //     victim file is byte-for-byte UNTOUCHED — proven through the REAL NodeProjectExport::import
    //     (the shadow-apply authorizer denies ATTACH at PREPARE, before the file is opened). ===
    {
        let atk_tmp = tempfile::tempdir().unwrap();
        // A victim PATH OUTSIDE the target's libsql dir that does NOT yet exist — a real ATTACH
        // would CREATE it, so "never created" is an unambiguous proof the escape wrote nothing.
        let victim = atk_tmp.path().join("victim.db");
        assert!(!victim.exists());
        let evil_dump = format!(
            "CREATE TABLE t(v TEXT);\nATTACH DATABASE '{}' AS v;\n\
             CREATE TABLE v.pwned(x);\nINSERT INTO v.pwned VALUES (1);\n",
            victim.display()
        );
        let crafted = craft_chunked_libsql_bundle("acme", "blog", &evil_dump);

        let atk_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let atk_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(atk_tmp.path().join("blobs")));
        let atk_libsql = Arc::new(LibsqlSqlBackends::local(
            atk_tmp.path().join("handlers-sql"),
        ));
        let atk_work = atk_tmp.path().join("work");
        std::fs::create_dir_all(&atk_work).unwrap();
        let atk = NodeProjectExport::new(
            BTreeMap::new(),
            DeployStore::new(atk_blobs.clone(), atk_kv.clone()),
            atk_kv.clone(),
            atk_blobs.clone(),
            atk_work,
        )
        .with_libsql(atk_libsql.clone());

        let mut src = futures::io::Cursor::new(crafted);
        let res = atk
            .import(
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
            .await;
        assert!(
            res.is_err(),
            "a crafted libsql `.dump` carrying ATTACH DATABASE MUST be refused (fail-closed)"
        );
        assert!(
            !victim.exists(),
            "the ATTACH escape must NOT have created/written the out-of-target victim file"
        );
        // MUTATION (RED): remove the shadow-apply authorizer → the ATTACH creates the victim db +
        // INSERT writes it (a cross-tenant/file escape the shadow-drop does NOT undo) → the
        // victim-not-created assertion goes RED.
    }

    // === RENAME variant: import acme's bundle AS `acmeclone` ===
    let rn_tmp = tempfile::tempdir().unwrap();
    let rn_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let rn_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(rn_tmp.path().join("blobs")));
    let rn_libsql = Arc::new(LibsqlSqlBackends::local(rn_tmp.path().join("handlers-sql")));
    let rn_work = rn_tmp.path().join("work");
    std::fs::create_dir_all(&rn_work).unwrap();
    let rn = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(rn_blobs.clone(), rn_kv.clone()),
        rn_kv.clone(),
        rn_blobs.clone(),
        rn_work,
    )
    .with_libsql(rn_libsql.clone());
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

    // The CHUNKED libsql member's target-SITE re-key holds on a rename: the db lands under the
    // TARGET project's qualified identity (`acmeclone/blog`), and NO source-scope (`acme/blog`)
    // libsql file survives — framing (chunked `.dump`) is not a re-key bypass.
    assert!(
        rn_libsql.local_database_exists(&ProjectRef::new("acmeclone").qualified("blog"), ""),
        "the chunked libsql member restored under the TARGET (acmeclone) qualified site"
    );
    assert!(
        !rn_libsql.local_database_exists(&ProjectRef::new("acme").qualified("blog"), ""),
        "NO source-scope (acme) libsql db may survive a rename import"
    );
    {
        let db: Arc<dyn SqlBackend> = rn_libsql.database("acmeclone", "blog", "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query("SELECT v FROM t", &[]).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            rows.rows,
            vec![vec![SqlValue::Text("acme-libsql-row".into())]],
            "the renamed libsql db carries the source row under the target scope"
        );
    }

    println!("PROJECT EXPORT CROSS-TENANT LEAK GATE OK");
}

// ===========================================================================================
// pg WAL true-delta (PLAN-sql-true-delta Stage 2)
// ===========================================================================================

/// A raw `pgoutput` (proto v1) message body is big-endian: these build the bytes the capture
/// drain would frame, so the tests exercise the real `frame → decode_framed → render_changes`
/// replay pipeline.
fn po_be32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}
fn po_tcol(s: &str) -> Vec<u8> {
    let mut v = vec![b't'];
    v.extend_from_slice(&po_be32(s.len() as u32));
    v.extend_from_slice(s.as_bytes());
    v
}
fn po_msg(tag: char, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag as u8];
    v.extend_from_slice(body);
    v
}

/// A framed `pgoutput` stream whose Relation namespace + table + the INSERT value all carry
/// SQL-injection payloads — a CRAFTED true-delta member. `render_changes` must quote every piece
/// INERT (identifiers via `quote_ident`, the value via `quote_literal`); executed against a
/// restored base it targets a NONEXISTENT (quoted) table and fails fail-closed — the embedded
/// `DROP TABLE victim` never runs.
fn crafted_injection_pgwal() -> Vec<u8> {
    use boatramp_core::pgoutput::frame_message;
    let evil_ns = r#"public"; DROP TABLE victim; --"#;
    let evil_tbl = r#"t"; DROP TABLE victim; --"#;
    let evil_val = r#"99'); DROP TABLE victim; --"#;
    let mut rel = Vec::new();
    rel.extend_from_slice(&po_be32(1)); // rel_id
    rel.extend_from_slice(evil_ns.as_bytes());
    rel.push(0);
    rel.extend_from_slice(evil_tbl.as_bytes());
    rel.push(0);
    rel.push(b'd'); // REPLICA IDENTITY default
    rel.extend_from_slice(&1u16.to_be_bytes()); // 1 column
    rel.push(1); // key
    rel.extend_from_slice(b"id\0");
    rel.extend_from_slice(&po_be32(23)); // int4 oid
    rel.extend_from_slice(&po_be32(0xFFFF_FFFF)); // typmod -1
    let mut ins = Vec::new();
    ins.extend_from_slice(&po_be32(1));
    ins.push(b'N');
    ins.extend_from_slice(&1u16.to_be_bytes());
    ins.extend_from_slice(&po_tcol(evil_val));
    [
        frame_message(&po_msg('R', &rel)),
        frame_message(&po_msg('I', &ins)),
    ]
    .concat()
}

/// MERGE-GATE (no Docker / no Postgres): the untrusted pg-WAL delta trust boundary the node crosses
/// on replay. A crafted framed delta whose change carries SQL-injection payloads in every
/// identifier + value must `decode_framed` + `render_changes` to INERT, fully-quoted SQL; and a
/// change on a `REPLICA IDENTITY NOTHING` table is REFUSED (so the engine falls back to a full
/// dump rather than replay a row it cannot match). This is the pg-WAL analogue of the ≥2-tenant
/// leak gate's "a crafted change cannot escape its scope", proven at the render boundary.
#[test]
fn pg_wal_delta_crafted_change_renders_inert() {
    use boatramp_core::pgoutput::{ReplayError, decode_framed, frame_message, render_changes};

    let changes =
        decode_framed(&crafted_injection_pgwal()).expect("decode the crafted framed delta");
    let stmts = render_changes(&changes).expect("render the crafted change");
    assert_eq!(stmts.len(), 1);
    // Deterministic, mutation-sensitive: every `"`/`'` is doubled, so the `; DROP TABLE victim; --`
    // lives ONLY inside a quoted identifier or a quoted string literal — never a bare statement.
    assert_eq!(
        stmts[0],
        r#"INSERT INTO "public""; DROP TABLE victim; --"."t""; DROP TABLE victim; --" ("id") VALUES ('99''); DROP TABLE victim; --')"#,
        "a crafted delta must render to inert, fully-quoted SQL (no injection)"
    );

    // A REPLICA IDENTITY NOTHING delete cannot be faithfully matched → render REFUSES it (the engine
    // then falls back to a full dump; never a partial/guessed replay).
    let mut rel = Vec::new();
    rel.extend_from_slice(&po_be32(2));
    rel.extend_from_slice(b"public\0noident\0");
    rel.push(b'n'); // REPLICA IDENTITY NOTHING
    rel.extend_from_slice(&1u16.to_be_bytes());
    rel.push(0);
    rel.extend_from_slice(b"a\0");
    rel.extend_from_slice(&po_be32(25));
    rel.extend_from_slice(&po_be32(0xFFFF_FFFF));
    let mut del = Vec::new();
    del.extend_from_slice(&po_be32(2));
    del.push(b'O');
    del.extend_from_slice(&1u16.to_be_bytes());
    del.extend_from_slice(&po_tcol("x"));
    let stream = [
        frame_message(&po_msg('R', &rel)),
        frame_message(&po_msg('D', &del)),
    ]
    .concat();
    let ch = decode_framed(&stream).expect("decode");
    assert!(
        matches!(render_changes(&ch), Err(ReplayError::NoReplicaIdentity(_))),
        "a REPLICA IDENTITY NOTHING delta must be refused → full-dump fallback"
    );
}

/// LIVE gate (Docker + a `wal_level=logical` Postgres): the pg logical-WAL true-delta round-trip.
/// Seeds a base, creates a BASE resumable export (which creates the pgoutput capture slot), mutates
/// rows (insert/update/delete), takes an INCREMENTAL delta export (which drains the slot into a
/// `PgWalDelta` member), then imports the chain and asserts the restored db EXACTLY equals the
/// MUTATED source — a result ONLY base-dump + WAL-replay can produce (the base dump alone is the
/// pre-mutation state). Also proves: the delta is a TRUE WAL delta (not a full-dump fallback), the
/// drain drops the slot (bounded retention §4), a CRAFTED delta is refused fail-closed with the
/// victim table + a SECOND tenant's db left untouched. Marker: `PROJECT EXPORT PG TRUE-DELTA OK`.
#[tokio::test]
async fn project_export_pg_true_delta_roundtrip_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest, SqlDeltaKind};
    use boatramp_core::project_export::{ExportOptions, ImportOptions, ProjectExport};
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg true-delta round-trip not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pg true-delta not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let live_db = format!("brexp_td_live_{s}");
    let tenant_b_db = format!("brexp_td_tenantb_{s}");
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // PRECONDITION: logical decoding must be enabled (managed_db_spec sets `wal_level=logical` at
    // launch; a bring-your-own test pg must be started with it + replication slots too).
    let (_c, wal_level) = psql(backend.as_ref(), &image, &maint, "SHOW wal_level").await;
    assert_eq!(
        wal_level.trim(),
        "logical",
        "the test Postgres must run with wal_level=logical for the WAL true-delta gate (launch \
         pgvector with `-c wal_level=logical -c max_replication_slots=10 -c max_wal_senders=10`)"
    );

    // --- a source live DB (base rows + a victim table) + a SECOND tenant's DB (sentinel) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db}"),
        format!("DROP DATABASE IF EXISTS {tenant_b_db}"),
        format!("CREATE DATABASE {tenant_b_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let live = conn(&user, &password, &host, port, &live_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "CREATE TABLE t(id int primary key, v text); \
         CREATE TABLE victim(id int primary key); INSERT INTO victim VALUES (1); \
         INSERT INTO t VALUES (1,'alpha'),(2,'beta'),(3,'gamma');",
    )
    .await;
    assert_eq!(c, 0, "seed base rows: {o}");
    let tenant_b = conn(&user, &password, &host, port, &tenant_b_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &tenant_b,
        "CREATE TABLE b(id int primary key, v text); \
         INSERT INTO b VALUES (7,'TENANT_B_SENTINEL');",
    )
    .await;
    assert_eq!(c, 0, "seed tenant B: {o}");

    // --- the driver: a MANAGED Single/default pg binding with delta_capture, at the test DSN ---
    let databases = BTreeMap::from([(
        "app".to_string(),
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            compute: Some("pg".to_string()),
            database: Some(live_db.clone()),
            user: Some(user.clone()),
            delta_capture: true,
            ..Default::default()
        },
    )]);
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    {
        let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
        kv.put("managed-sql-cred/default/pg", sealed).await.unwrap();
    }
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    deploy
        .set_replica_state(
            boatramp_core::project::ProjectRef::new("default"),
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
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
            },
        )
        .await
        .unwrap();
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        DeployStore::new(blobs.clone(), kv.clone()),
    ));
    let work = td.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let resumable = td.path().join("resumable");
    let drv = NodeProjectExport::new(databases, deploy, kv.clone(), blobs.clone(), work)
        .with_managed_pg(backend.clone(), envelope, op, false)
        .with_resumable_base(Some(resumable.clone()));

    // --- BASE export: creates the pgoutput capture slot + the full dump ---
    let full = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    drv.export_resumable("default", &full, "base")
        .await
        .expect("base resumable export");
    // Count slots on THIS test's db only (`current_database()`), so any orphan slot a prior run
    // left on another db does not perturb the assertion.
    let (_c, slots) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT count(*) FROM pg_replication_slots WHERE database = current_database() \
         AND slot_name LIKE 'brexp_slot_%'",
    )
    .await;
    assert_eq!(
        slots.trim(),
        "1",
        "the base export must create exactly one pgoutput capture slot on this db"
    );

    // --- mutate the source: an INSERT, an UPDATE, and a DELETE ---
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "INSERT INTO t VALUES (4,'delta'); UPDATE t SET v='beta2' WHERE id=2; DELETE FROM t WHERE id=3;",
    )
    .await;
    assert_eq!(c, 0, "mutate source: {o}");

    // --- INCREMENTAL delta export: drains the slot into a PgWalDelta member ---
    let delta_opts = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: "base".to_string(),
        }),
    };
    drv.export_resumable("default", &delta_opts, "d1")
        .await
        .expect("incremental delta export");

    // PROVE it is a TRUE WAL delta, not a full-dump fallback: the d1 manifest declares PgWalReplay
    // and carries a `sql/app.pgwal` member instead of the full `sql/app.pgc` dump.
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::PgWalReplay,
        "the delta must have WAL-captured the pg db (not fallen back to a full dump)"
    );
    let pgwal_idx = d1_manifest
        .members
        .iter()
        .position(|m| m.path == "sql/app.pgwal" && m.kind == MemberKind::PgWalDelta)
        .expect("the delta must carry a sql/app.pgwal true-delta member");
    assert!(
        !d1_manifest.members.iter().any(|m| m.path == "sql/app.pgc"),
        "the full pg dump must be SUPERSEDED by the WAL delta member"
    );
    // The drain DROPPED the slot (bounded retention, §4 disk-fill guard).
    let (_c, slots_after) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT count(*) FROM pg_replication_slots WHERE database = current_database() \
         AND slot_name LIKE 'brexp_slot_%'",
    )
    .await;
    assert_eq!(
        slots_after.trim(),
        "0",
        "the delta drain must drop the capture slot (bounded retention)"
    );

    // --- CRAFTED-ESCAPE: a copy of d1 whose PgWalDelta member is a malicious injection stream must
    // be REFUSED fail-closed; the victim table (+ tenant B) must be UNTOUCHED (shadow dropped, no
    // swap). This is the ≥2-tenant leak gate's crafted case at the LIVE pg-WAL boundary. ---
    let d1_dir = resumable.join("d1");
    let evil_dir = resumable.join("evil");
    std::fs::create_dir_all(&evil_dir).unwrap();
    for ent in std::fs::read_dir(&d1_dir).unwrap() {
        let ent = ent.unwrap();
        if ent.file_type().unwrap().is_file() {
            std::fs::copy(ent.path(), evil_dir.join(ent.file_name())).unwrap();
        }
    }
    // Overwrite the pgwal member object + its `{size,sha256}` meta so it PASSES the integrity check
    // and reaches the replay (where the quoting + non-superuser confinement must neutralize it).
    let crafted = crafted_injection_pgwal();
    let obj = evil_dir.join(format!("m{pgwal_idx:05}"));
    std::fs::write(&obj, &crafted).unwrap();
    {
        use sha2::{Digest, Sha256};
        let meta = project_bundle::MemberMeta {
            size: crafted.len() as u64,
            sha256: hex::encode(Sha256::digest(&crafted)),
        };
        std::fs::write(
            evil_dir.join(format!("m{pgwal_idx:05}.meta")),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
    }
    let evil_res = drv
        .import_resumable(
            "default",
            "evil",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        evil_res.is_err(),
        "a crafted injection WAL delta MUST be refused fail-closed; got: {evil_res:?}"
    );
    let (_c, victim) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT count(*) FROM victim",
    )
    .await;
    assert_eq!(
        victim.trim(),
        "1",
        "the crafted delta's injected `DROP TABLE victim` must NOT have run (quoted inert; shadow dropped)"
    );

    // --- set a sentinel so the happy-path assertion PROVES the restore actually ran (a no-op import
    // would leave the sentinel; only a real base-dump + WAL-replay + swap yields the mutated set) ---
    let (c, _o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "DELETE FROM t; INSERT INTO t VALUES (99,'SENTINEL_PRE_IMPORT');",
    )
    .await;
    assert_eq!(c, 0, "plant the pre-import sentinel");

    // --- IMPORT the real delta chain: base dump → replay WAL → atomic swap ---
    let report = drv
        .import_resumable(
            "default",
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("delta chain import (base dump restore + WAL replay + swap)");
    assert!(report.pg_databases >= 1, "the pg db must be restored");

    // --- ASSERT source == target. The base dump alone is {1:alpha,2:beta,3:gamma}; ONLY replaying
    // the WAL delta (INSERT 4, UPDATE 2→beta2, DELETE 3) onto it yields exactly this set. ---
    let (_c, rows) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT id || ':' || v FROM t ORDER BY id",
    )
    .await;
    assert_eq!(
        rows, "1:alpha\n2:beta2\n4:delta",
        "the restored db must equal the MUTATED source (base dump + WAL replay) — not the base \
         state, not the pre-import sentinel"
    );

    // --- the SECOND tenant's db must be UNTOUCHED by the restore (≥2-tenant isolation) ---
    let (_c, b_rows) = psql(
        backend.as_ref(),
        &image,
        &tenant_b,
        "SELECT id || ':' || v FROM b ORDER BY id",
    )
    .await;
    assert_eq!(
        b_rows, "7:TENANT_B_SENTINEL",
        "the second tenant's db must be UNTOUCHED by the restore"
    );

    // --- cleanup (best-effort) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {tenant_b_db}"),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT EXPORT PG TRUE-DELTA OK");
}

/// LIVE gate (Docker + a `wal_level=logical` Postgres): the pg true-delta OVERLAP-WINDOW proof
/// (PLAN-sql-true-delta Stage-2 MEDIUM). A continuous stream of single-row INSERT statements commits
/// THROUGHOUT the BASE export — so writes land in the slot-create→dump window that the old,
/// un-pinned base dump left open. With the snapshot-pin (`CREATE_REPLICATION_SLOT … (SNAPSHOT
/// 'export')` held across `pg_dump --snapshot`), the base dump and the slot share ONE consistent
/// point, so each concurrent row lands in the dump XOR the WAL — never both — and the delta chain
/// imports CLEANLY with source == target. Under the OLD code a window row lands in BOTH, so the
/// WAL-replay INSERT is a duplicate-key `ON_ERROR_STOP` abort (import fails) or a row mismatch — so
/// this test FAILS on a regression and PASSES only when the window is closed. Marker:
/// `PROJECT EXPORT PG OVERLAP-WINDOW OK`.
#[tokio::test]
async fn project_export_pg_true_delta_overlap_window_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest, SqlDeltaKind};
    use boatramp_core::project_export::{ExportOptions, ImportOptions, ProjectExport};
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (pg overlap-window proof not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (pg overlap-window proof not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let live_db = format!("brexp_ow_live_{s}");
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // Self-skip (not assert) when logical decoding is off: the HARD marker gate is in
    // preflight-matrix (which launches pgvector with `-c wal_level=logical`), so a looser job on a
    // stock `replica` pgvector skips cleanly rather than failing — the marker simply never prints.
    let (_c, wal_level) = psql(backend.as_ref(), &image, &maint, "SHOW wal_level").await;
    if wal_level.trim() != "logical" {
        eprintln!(
            "SKIP: test Postgres is wal_level={} (overlap-window proof needs wal_level=logical)",
            wal_level.trim()
        );
        return;
    }

    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let live = conn(&user, &password, &host, port, &live_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "CREATE TABLE t(id int primary key, v text); \
         INSERT INTO t VALUES (1,'alpha'),(2,'beta'),(3,'gamma');",
    )
    .await;
    assert_eq!(c, 0, "seed base rows: {o}");

    // --- driver: a MANAGED Single/default pg binding with delta_capture at the test DSN ---
    let databases = BTreeMap::from([(
        "app".to_string(),
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            compute: Some("pg".to_string()),
            database: Some(live_db.clone()),
            user: Some(user.clone()),
            delta_capture: true,
            ..Default::default()
        },
    )]);
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    {
        let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
        kv.put("managed-sql-cred/default/pg", sealed).await.unwrap();
    }
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    deploy
        .set_replica_state(
            boatramp_core::project::ProjectRef::new("default"),
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
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
            },
        )
        .await
        .unwrap();
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        DeployStore::new(blobs.clone(), kv.clone()),
    ));
    let work = td.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let resumable = td.path().join("resumable");
    let drv = NodeProjectExport::new(databases, deploy, kv.clone(), blobs.clone(), work)
        .with_managed_pg(backend.clone(), envelope, op, false)
        .with_resumable_base(Some(resumable.clone()));

    // --- a CONCURRENT writer: single-row INSERT statements, each its own autocommit txn, spread by
    // pg_sleep so a stream of commits spans the WHOLE base export (and so the slot-create→dump
    // window). Feeds ONE psql a multi-statement script (container launch per INSERT would be far
    // too coarse to overlap the window). Ids 1000.. so they never collide with the base rows. ---
    const WRITER_ROWS: usize = 150;
    let writer_script = {
        let mut s = String::new();
        for k in 0..WRITER_ROWS {
            let id = 1000 + k;
            s.push_str(&format!(
                "INSERT INTO t VALUES ({id},'w{k}'); SELECT pg_sleep(0.025);\n"
            ));
        }
        s
    };
    let wbackend = backend.clone();
    let wimage = image.clone();
    let wlive = live.clone();
    let writer = tokio::spawn(async move {
        // ON_ERROR_STOP would abort on any failure (e.g. a dup key), so a non-zero exit here is a
        // real problem; assert it succeeded after the join.
        psql(wbackend.as_ref(), &wimage, &wlive, &writer_script).await
    });
    // Let the writer begin committing before the base export's capture orchestration runs.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // --- BASE export: SNAPSHOT-PINNED capture slot + base dump, while the writer commits ---
    let full = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    drv.export_resumable("default", &full, "base")
        .await
        .expect("base resumable export (snapshot-pinned, under concurrent writes)");

    // The base export created exactly one pgoutput slot on this db (the snapshot-pin path).
    let (_c, slots) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT count(*) FROM pg_replication_slots WHERE database = current_database() \
         AND slot_name LIKE 'brexp_slot_%'",
    )
    .await;
    assert_eq!(
        slots.trim(),
        "1",
        "the base export must create exactly one snapshot-pinned capture slot"
    );

    // Drain the writer fully, so every concurrent row is committed before we snapshot the
    // source + take the delta. A clean writer exit (ON_ERROR_STOP) means no INSERT failed.
    let (wcode, wout) = writer.await.expect("writer task join");
    assert_eq!(wcode, 0, "the concurrent writer must succeed: {wout}");

    // The source's authoritative post-write state — a compact, order-independent checksum.
    let checksum_sql = "SELECT count(*)||'|'||coalesce(sum(id),0)||'|'||\
                        coalesce(md5(string_agg(id||':'||v, ',' ORDER BY id)),'') FROM t";
    let (_c, source_sum) = psql(backend.as_ref(), &image, &live, checksum_sql).await;
    // Sanity: the base rows + every writer row are present in the source.
    assert!(
        source_sum
            .trim()
            .starts_with(&format!("{}|", 3 + WRITER_ROWS)),
        "source must hold the 3 base rows + {WRITER_ROWS} writer rows: {source_sum}"
    );

    // --- INCREMENTAL delta export: drains the WAL (every post-snapshot write) into a PgWalDelta ---
    let delta_opts = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: "base".to_string(),
        }),
    };
    drv.export_resumable("default", &delta_opts, "d1")
        .await
        .expect("incremental delta export");
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::PgWalReplay,
        "the delta must be a TRUE WAL delta (snapshot-pin must not have forced a full-dump fallback)"
    );

    // --- plant a pre-import sentinel so a no-op import can't masquerade as success ---
    let (c, _o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "DELETE FROM t; INSERT INTO t VALUES (-1,'SENTINEL_PRE_IMPORT');",
    )
    .await;
    assert_eq!(c, 0, "plant the pre-import sentinel");

    // --- IMPORT the chain: base dump restore + WAL replay + atomic swap ---
    let report = drv
        .import_resumable(
            "default",
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("delta chain import under concurrent-write overlap (window must be closed)");
    assert!(report.pg_databases >= 1, "the pg db must be restored");

    // --- THE PROOF: restored == source. Had any concurrent row landed in BOTH the base dump and
    // the WAL (the un-pinned overlap bug), the WAL-replay INSERT would have been a duplicate-key
    // abort (import error, caught above) or left a row mismatch here. Equality ⇒ window closed. ---
    let (_c, target_sum) = psql(backend.as_ref(), &image, &live, checksum_sql).await;
    assert_eq!(
        target_sum.trim(),
        source_sum.trim(),
        "the restored db must EXACTLY equal the concurrently-written source (base dump ⊎ WAL replay, \
         each row exactly once) — the overlap window is closed"
    );

    for sql in [format!("DROP DATABASE IF EXISTS {live_db}")] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }
    println!("PROJECT EXPORT PG OVERLAP-WINDOW OK");
}

/// LIVE gate (Docker + a `gtid_mode=ON --log-bin --binlog-format=ROW` MySQL): the mysql binlog
/// true-delta round-trip. Seeds a base, creates a BASE resumable export (which records the snapshot
/// GTID + start binlog in `mysql_capture.json`), mutates rows (insert/update/delete), takes an
/// INCREMENTAL delta export (which streams the binlog since the base into a `MysqlBinlogDelta`
/// member), then imports the chain into the live db and asserts it EXACTLY equals the MUTATED source
/// — a result ONLY base-dump + binlog-replay can produce (the base dump alone is the pre-mutation
/// state). Also proves: the delta is a TRUE binlog delta (not a full-dump fallback), a CRAFTED delta
/// is refused fail-closed with the victim table + a SECOND tenant's db left untouched (shadow
/// dropped, no swap). Marker: `PROJECT EXPORT MYSQL TRUE-DELTA OK`.
#[tokio::test]
async fn project_export_mysql_true_delta_roundtrip_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest, SqlDeltaKind};
    use boatramp_core::project_export::{ExportOptions, ImportOptions, ProjectExport};
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (live mysql true-delta round-trip not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live mysql true-delta not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    let s = now_suffix();
    let live_db = format!("brexp_mytd_live_{s}");
    let tenant_b_db = format!("brexp_mytd_tenantb_{s}");
    let mkconn = |db: &str| MysqlConnection {
        host: host.clone(),
        port,
        user: user.clone(),
        password: password.clone(),
        database: db.to_string(),
        connect_timeout_secs: 10,
    };
    let admin = mkconn("");

    // PRECONDITION: the server must run with GTID + row binlog (what `managed_db_spec` bakes into a
    // managed DB's launch argv under `delta_capture`). SELF-SKIP when it does not — so a mysql server
    // launched without the binlog argv (e.g. the env-clone capability gate) runs the OTHER tests
    // cleanly; the binlog true-delta GATE (preflight-matrix.yml + flake.nix) launches mysql WITH the
    // argv and gates on the `PROJECT EXPORT MYSQL TRUE-DELTA OK` marker, so a skip there FAILS the job
    // (the marker is never printed).
    let (_c, gtid_mode) =
        mysql_run(backend.as_ref(), image, &admin, None, "SELECT @@gtid_mode;").await;
    if gtid_mode.trim() != "ON" {
        eprintln!(
            "SKIP: the test MySQL is not gtid_mode=ON (binlog true-delta gate needs \
             `--log-bin --binlog-format=ROW --gtid-mode=ON --enforce-gtid-consistency=ON`)"
        );
        return;
    }

    // --- a source live DB (base rows + a victim table) + a SECOND tenant's DB (sentinel) ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!(
            "DROP DATABASE IF EXISTS {live_db}; CREATE DATABASE {live_db}; \
             DROP DATABASE IF EXISTS {tenant_b_db}; CREATE DATABASE {tenant_b_db};"
        ),
    )
    .await;
    assert_eq!(c, 0, "setup dbs: {o}");
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         CREATE TABLE victim(id INT PRIMARY KEY); INSERT INTO victim VALUES (1); \
         INSERT INTO t VALUES (1,'alpha'),(2,'beta'),(3,'gamma');",
    )
    .await;
    assert_eq!(c, 0, "seed base rows: {o}");
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&tenant_b_db),
        "CREATE TABLE b(id INT PRIMARY KEY, v TEXT); INSERT INTO b VALUES (7,'TENANT_B_SENTINEL');",
    )
    .await;
    assert_eq!(c, 0, "seed tenant B: {o}");

    // --- the driver: a MANAGED Single/default mysql binding with delta_capture, at the test DSN ---
    let databases = BTreeMap::from([(
        "app".to_string(),
        ExternalDatabaseConfig {
            kind: "mysql".to_string(),
            compute: Some("mysql".to_string()),
            database: Some(live_db.clone()),
            user: Some(user.clone()),
            delta_capture: true,
            ..Default::default()
        },
    )]);
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    {
        let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
        kv.put("managed-sql-cred/default/mysql", sealed)
            .await
            .unwrap();
    }
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    deploy
        .set_replica_state(
            boatramp_core::project::ProjectRef::new("default"),
            &ObservedInstance {
                handle: InstanceHandle {
                    project: "default".to_string(),
                    workload: "mysql".to_string(),
                    replica: 0,
                    backend_ref: String::new(),
                },
                node: 0,
                backend: "docker".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
            },
        )
        .await
        .unwrap();
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        DeployStore::new(blobs.clone(), kv.clone()),
    ));
    let work = td.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let resumable = td.path().join("resumable");
    let drv = NodeProjectExport::new(databases, deploy, kv.clone(), blobs.clone(), work)
        .with_managed_pg(backend.clone(), envelope, op, false)
        .with_resumable_base(Some(resumable.clone()));

    // --- BASE export: records the snapshot GTID + start binlog in mysql_capture.json ---
    let full = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    drv.export_resumable("default", &full, "base")
        .await
        .expect("base resumable export");
    let cap_sidecar = std::fs::read_to_string(resumable.join("base").join("mysql_capture.json"))
        .expect("the base export must write a mysql_capture.json sidecar");
    assert!(
        cap_sidecar.contains("base_gtid") && cap_sidecar.contains("start_log"),
        "the base sidecar must record the snapshot GTID + start binlog: {cap_sidecar}"
    );

    // --- mutate the source: an INSERT, an UPDATE, and a DELETE ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "INSERT INTO t VALUES (4,'delta'); UPDATE t SET v='beta2' WHERE id=2; DELETE FROM t WHERE id=3;",
    )
    .await;
    assert_eq!(c, 0, "mutate source: {o}");
    // Also land, WITHIN the delta's binlog range: (a) an account-DDL disclosure probe — a `CREATE
    // USER` carrying a password that the MEDIUM finding warns could leak into a tenant-downloadable
    // member; and (b) a foreign-tenant write. The db-scoped capture MUST drop BOTH from the member.
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        "CREATE USER 'mytd_leak_probe'@'%' IDENTIFIED BY 'LEAKHASH987';",
    )
    .await;
    assert_eq!(c, 0, "create in-range disclosure-probe account: {o}");
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&tenant_b_db),
        "INSERT INTO b VALUES (8,'B_INRANGE');",
    )
    .await;
    assert_eq!(c, 0, "foreign-tenant in-range write: {o}");

    // --- INCREMENTAL delta export: streams the binlog into a MysqlBinlogDelta member ---
    let delta_opts = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: "base".to_string(),
        }),
    };
    drv.export_resumable("default", &delta_opts, "d1")
        .await
        .expect("incremental delta export");

    // PROVE it is a TRUE binlog delta, not a full-dump fallback.
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::MysqlBinlogReplay,
        "the delta must have binlog-captured the mysql db (not fallen back to a full dump)"
    );
    let bin_idx = d1_manifest
        .members
        .iter()
        .position(|m| m.path == "sql/app.mysqlbinlog" && m.kind == MemberKind::MysqlBinlogDelta)
        .expect("the delta must carry a sql/app.mysqlbinlog true-delta member");
    assert!(
        !d1_manifest.members.iter().any(|m| m.path == "sql/app.sql"),
        "the full mysql dump must be SUPERSEDED by the binlog delta member"
    );

    // --- DISCLOSURE gate (MEDIUM): the exported member must be db-SCOPED — ZERO account DDL /
    // password hash / foreign-tenant events. The in-range `CREATE USER … IDENTIFIED BY 'LEAKHASH987'`
    // and the `tenant_b` write above are in the SERVER binlog, but the `--rewrite-db`/`--database`
    // db-scoping at capture must keep them OUT of the tenant-downloadable member. ---
    let member_bytes = std::fs::read(resumable.join("d1").join(format!("m{bin_idx:05}"))).unwrap();
    let member_text = String::from_utf8_lossy(&member_bytes);
    for needle in [
        "mytd_leak_probe",
        "LEAKHASH987",
        "CREATE USER",
        "ALTER USER",
        "SET PASSWORD",
        tenant_b_db.as_str(),
        "B_INRANGE",
    ] {
        assert!(
            !member_text.contains(needle),
            "DISCLOSURE: the exported binlog member leaked {needle:?} (db-scoping at capture failed)"
        );
    }
    // ...but it MUST carry the app db's events, rewritten to the delta shadow.
    assert!(
        member_text.contains("__shadow_brdelta"),
        "the member must carry the app db's row events rewritten to the delta shadow"
    );
    // Tidy the probe account.
    let _ = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        "DROP USER IF EXISTS 'mytd_leak_probe'@'%';",
    )
    .await;

    // --- plant a sentinel in `t` BEFORE the evil imports, so each refusal is PROVABLY a no-swap
    //     (`t` stays the sentinel), not a base-swap. ---
    let (c, _o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "DELETE FROM t; INSERT INTO t VALUES (99,'SENTINEL_PRE_IMPORT');",
    )
    .await;
    assert_eq!(c, 0, "plant the pre-import sentinel");

    // Build a fresh evil-copy of d1 whose binlog member is overwritten with `bytes` (+ fixed meta so
    // it passes the SHA integrity check and reaches the replay).
    let d1_dir = resumable.join("d1");
    let make_evil = |name: &str, bytes: &[u8]| {
        use sha2::{Digest, Sha256};
        let evil_dir = resumable.join(name);
        let _ = std::fs::remove_dir_all(&evil_dir);
        std::fs::create_dir_all(&evil_dir).unwrap();
        for ent in std::fs::read_dir(&d1_dir).unwrap() {
            let ent = ent.unwrap();
            if ent.file_type().unwrap().is_file() {
                std::fs::copy(ent.path(), evil_dir.join(ent.file_name())).unwrap();
            }
        }
        std::fs::write(evil_dir.join(format!("m{bin_idx:05}")), bytes).unwrap();
        let meta = project_bundle::MemberMeta {
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        std::fs::write(
            evil_dir.join(format!("m{bin_idx:05}.meta")),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
    };
    let evil_opts = || ImportOptions {
        apply: true,
        overwrite: true,
        force: true,
        ..Default::default()
    };

    // --- CRAFTED #1 (garbage): a member that is not valid SQL → the `mysql` apply errors → refused
    //     fail-closed (shadow dropped, nothing partial reaches live). ---
    make_evil(
        "evil_garbage",
        b"\x00\x01\x02 not valid binlog SQL at all; )(*&^ DROP TABLE victim; \xff\xfe",
    );
    let garbage_res = drv
        .import_resumable("default", "evil_garbage", evil_opts())
        .await;
    assert!(
        garbage_res.is_err(),
        "a crafted/garbage binlog member MUST be refused fail-closed; got: {garbage_res:?}"
    );

    // --- CRAFTED #2 (WELL-FORMED but malicious): a VALID SQL member whose statements target the
    //     VICTIM / foreign-tenant db. The apply user (ALL on the shadow ONLY) is DENIED → `mysql`
    //     errors → import refused. Proves the GRANT confinement (not just a decode failure): a
    //     well-formed member cannot reach any table outside the shadow. ---
    let evil_sql = format!(
        "INSERT INTO `{tenant_b_db}`.b VALUES (999,'ESCAPE_ATTEMPT');\n\
         DROP TABLE `{live_db}`.victim;\n"
    );
    make_evil("evil_wellformed", evil_sql.as_bytes());
    let wf_res = drv
        .import_resumable("default", "evil_wellformed", evil_opts())
        .await;
    assert!(
        wf_res.is_err(),
        "a well-formed member targeting another db MUST be DENIED by the shadow-scoped apply grants; \
         got: {wf_res:?}"
    );

    // After BOTH refused evil imports: `t` is still the sentinel (NO swap — distinguishes no-swap
    // from a base-swap), and the victim table + the second tenant's db are UNTOUCHED.
    let (_c, t_after_evil) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        t_after_evil, "99:SENTINEL_PRE_IMPORT",
        "`t` must be UNCHANGED (no swap) after the refused evil imports"
    );
    let (_c, victim) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "SELECT COUNT(*) FROM victim;",
    )
    .await;
    assert_eq!(
        victim.trim(),
        "1",
        "the victim table must be untouched after the refused evil imports"
    );
    let (_c, b_after_evil) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&tenant_b_db),
        "SELECT CONCAT(id, ':', v) FROM b ORDER BY id;",
    )
    .await;
    assert_eq!(
        b_after_evil, "7:TENANT_B_SENTINEL\n8:B_INRANGE",
        "the second tenant's db must be untouched after the refused evil imports"
    );

    // --- IMPORT the real delta chain: base dump → replay binlog → atomic swap ---
    let report = drv
        .import_resumable(
            "default",
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("delta chain import (base dump restore + binlog replay + swap)");
    assert!(report.pg_databases >= 1, "the mysql db must be restored");

    // --- ASSERT source == target. The base dump alone is {1:alpha,2:beta,3:gamma}; ONLY replaying
    // the binlog delta (INSERT 4, UPDATE 2→beta2, DELETE 3) onto it yields exactly this set. ---
    let (_c, rows) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        // One row per line (NOT GROUP_CONCAT — `mysql -N --batch` escapes an embedded newline as a
        // literal `\n`), so the batch output is the three rows joined by real newlines.
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        rows, "1:alpha\n2:beta2\n4:delta",
        "the restored db must equal the MUTATED source (base dump + binlog replay) — not the base \
         state, not the pre-import sentinel"
    );

    // --- the SECOND tenant's db must be UNTOUCHED by the restore (≥2-tenant isolation) ---
    let (_c, b_rows) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&tenant_b_db),
        "SELECT CONCAT(id, ':', v) FROM b ORDER BY id;",
    )
    .await;
    assert_eq!(
        b_rows, "7:TENANT_B_SENTINEL\n8:B_INRANGE",
        "the second tenant's db must be UNTOUCHED by the restore (its own rows, incl. the in-range \
         write, intact)"
    );

    // ===== RACE GUARD (the HIGH fix): the binlog-delta shadow name is DETERMINISTIC per db, so a
    // concurrent same-db import owns `<live>__shadow_brdelta` while it is populated + about to swap.
    // THIS import must refuse WITHOUT dropping that shadow — dropping another import's populated
    // shadow would leave ITS swap seeing an empty shadow and DESTROY live data. live is now the
    // mutated set; simulate "import A in flight" with a POPULATED shadow + marker. =====
    let delta_shadow = format!("{live_db}__shadow_brdelta");
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!(
            "CREATE DATABASE `{delta_shadow}`; \
             CREATE TABLE `{delta_shadow}`.marker(id INT PRIMARY KEY); \
             INSERT INTO `{delta_shadow}`.marker VALUES (1);"
        ),
    )
    .await;
    assert_eq!(c, 0, "pre-create a populated in-flight shadow: {o}");
    let collide = drv
        .import_resumable(
            "default",
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        collide.is_err(),
        "a same-db import whose deterministic shadow already exists MUST refuse (collision); got: {collide:?}"
    );
    // fix 1: the colliding import did NOT drop the in-flight shadow — the marker survives. (The
    // un-fixed code ran `mysql_drop_shadow` on the CREATE collision → this would be 0.)
    let (_c, marker) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&delta_shadow),
        "SELECT COUNT(*) FROM marker;",
    )
    .await;
    assert_eq!(
        marker.trim(),
        "1",
        "the colliding import MUST NOT drop the other import's populated shadow (data-loss race)"
    );
    // live is untouched (the colliding import refused before any swap).
    let (_c, t_after_collide) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        t_after_collide, "1:alpha\n2:beta2\n4:delta",
        "live must be untouched by the refused colliding import"
    );
    let _ = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!("DROP DATABASE IF EXISTS `{delta_shadow}`;"),
    )
    .await;

    // ===== SWAP-SAFETY (fix 2, data-preservation): drive the restore to a swap where the shadow is
    // EMPTY while live is non-empty — the swap MUST abort, leaving live INTACT. Reach that state via
    // an EMPTY-db base/delta chain imported over a sentinel-populated live. The UN-FIXED swap would
    // RENAME the live tables aside + DROP them (nothing to put back) → empty the tenant db. =====
    let (c, _o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "DROP TABLE IF EXISTS t; DROP TABLE IF EXISTS victim;",
    )
    .await;
    assert_eq!(c, 0, "empty the source db for the swap-safety base");
    drv.export_resumable("default", &full, "base2")
        .await
        .expect("empty base export");
    let delta2 = ExportOptions {
        data_only: false,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: "base2".to_string(),
        }),
    };
    drv.export_resumable("default", &delta2, "d2")
        .await
        .expect("empty delta export");
    // Now populate live with a sentinel, so the swap sees an EMPTY shadow vs a NON-EMPTY live.
    let (c, _o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); INSERT INTO t VALUES (42,'SWAP_SAFETY_SENTINEL');",
    )
    .await;
    assert_eq!(c, 0, "plant the swap-safety sentinel");
    let swap_res = drv
        .import_resumable(
            "default",
            "d2",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        swap_res.is_err(),
        "importing an empty-shadow chain over a non-empty live MUST abort the swap (data-loss \
         guard); got: {swap_res:?}"
    );
    let (_c, sentinel) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        sentinel, "42:SWAP_SAFETY_SENTINEL",
        "the swap-safety guard must leave LIVE INTACT; the un-fixed swap would EMPTY the live db"
    );

    // --- cleanup (best-effort) ---
    let _ = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!("DROP DATABASE IF EXISTS {live_db}; DROP DATABASE IF EXISTS {tenant_b_db};"),
    )
    .await;

    println!("PROJECT EXPORT MYSQL TRUE-DELTA OK");
}

// ===========================================================================================
// libsql CHANGESET true-delta (SQL true-delta program, Stage 4) — the IN-PROCESS ≥2-tenant gate.
// No Docker, no external server: embedded libsql, two SITES (separate DB FILES) in one project.
// Feature-gated on `sql-delta-libsql` (the engine); CI opts the feature in so this RUNS (not an
// ignore-gated stub). Marker: `PROJECT EXPORT LIBSQL TRUE-DELTA OK`.
// ===========================================================================================

/// **The libsql changeset true-delta gate.** Proves, entirely in-process:
///  (1) a REAL round-trip — base export → mutate (insert/update/delete) → DIFFERENTIAL delta export
///      (a `LibsqlChangeset` member, NOT a full dump) → import the chain → the restored site EXACTLY
///      equals the MUTATED source (a result ONLY base-snapshot + changeset-replay can produce — the
///      base snapshot alone is the pre-mutation state, and the pre-import sentinel proves the swap);
///  (2) a ≥2-tenant CRAFTED-ESCAPE — a changeset member tampered to carry a write to a table OUTSIDE
///      the restored base's schema is REFUSED, the target is left byte-unchanged (atomic — the
///      legit-looking change bundled with it is rolled back too), and the SECOND site is untouched.
///
/// Mutation-sensitive: without the apply confinement (the base-table filter's foreign-table refusal /
/// abort-on-conflict), the crafted member's legit-looking row change would leak into the target —
/// turning assertion (2) RED. And a full-dump fallback instead of a true changeset would make the
/// strategy/member assertions in (1) RED.
#[cfg(feature = "sql-delta-libsql")]
#[tokio::test]
async fn project_export_libsql_true_delta_and_crafted_escape_gate() {
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::ProjectRef;
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest, SqlDeltaKind};
    use boatramp_core::project_export::{ExportOptions, ImportOptions, ProjectExport};
    use boatramp_core::sql::{SqlBackend, SqlBackends, SqlValue};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use boatramp_storage::sql_libsql::LibsqlSqlBackends;
    use std::collections::BTreeMap;

    let project = "acme";
    let blog = "blog"; // tenant A — gets the true-delta
    let shop = "shop"; // tenant B — a SECOND site that must stay untouched

    let td = tempfile::tempdir().unwrap();
    let libsql_dir = td.path().join("handlers-sql");
    let backends = Arc::new(LibsqlSqlBackends::local(&libsql_dir));

    // Seed a site's `t` table from scratch.
    async fn seed(
        backends: &Arc<LibsqlSqlBackends>,
        project: &str,
        site: &str,
        rows: &[(i64, &str)],
    ) {
        let db: Arc<dyn SqlBackend> = backends.database(project, site, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let _ = tx.execute("DROP TABLE IF EXISTS t", &[]).await;
        tx.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", &[])
            .await
            .unwrap();
        for (id, v) in rows {
            tx.execute(
                "INSERT INTO t VALUES (?1,?2)",
                &[SqlValue::Integer(*id), SqlValue::Text((*v).into())],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }
    async fn read_t(backends: &Arc<LibsqlSqlBackends>, project: &str, site: &str) -> Vec<String> {
        let db: Arc<dyn SqlBackend> = backends.database(project, site, "").await.unwrap();
        let mut tx = db.begin_read_only().await.unwrap();
        let rows = tx
            .query("SELECT id || ':' || v FROM t ORDER BY id", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        rows.rows
            .into_iter()
            .map(|r| match &r[0] {
                SqlValue::Text(s) => s.clone(),
                other => format!("{other:?}"),
            })
            .collect()
    }

    seed(
        &backends,
        project,
        blog,
        &[(1, "orig"), (2, "beta"), (3, "gamma")],
    )
    .await;
    seed(&backends, project, shop, &[(1, "SHOPSENTINEL")]).await;

    // Deploy pointers so `DeployStore::list_sites` enumerates BOTH sites.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    kv.put("project/acme/current/blog", b"dep1".to_vec())
        .await
        .unwrap();
    kv.put("project/acme/current/shop", b"dep1".to_vec())
        .await
        .unwrap();
    // An OWNED control-plane key so the scoped KV slice is non-trivial.
    kv.put("project/acme/config/tenancy", b"{}".to_vec())
        .await
        .unwrap();

    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let work = td.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let resumable = td.path().join("resumable");
    let drv = NodeProjectExport::new(
        BTreeMap::new(),
        DeployStore::new(blobs.clone(), kv.clone()),
        kv.clone(),
        blobs.clone(),
        work,
    )
    .with_libsql(backends.clone())
    .with_resumable_base(Some(resumable.clone()));

    // --- BASE export (records a libsql_capture.json snapshot per site) ---
    let full = ExportOptions::default();
    drv.export_resumable(project, &full, "base")
        .await
        .expect("base export");
    assert!(
        resumable.join("base").join("libsql_capture.json").exists(),
        "the base export must record a libsql_capture.json sidecar"
    );

    // --- mutate blog: INSERT 4, UPDATE 2→beta2, DELETE 3 (shop untouched) ---
    {
        let db: Arc<dyn SqlBackend> = backends.database(project, blog, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute("INSERT INTO t VALUES (4,'delta')", &[])
            .await
            .unwrap();
        tx.execute("UPDATE t SET v='beta2' WHERE id=2", &[])
            .await
            .unwrap();
        tx.execute("DELETE FROM t WHERE id=3", &[]).await.unwrap();
        tx.commit().await.unwrap();
    }
    let mutated_expect = vec![
        "1:orig".to_string(),
        "2:beta2".to_string(),
        "4:delta".to_string(),
    ];

    // --- DIFFERENTIAL delta export against the fixed base ---
    let delta_opts = ExportOptions {
        delta: Some(DeltaRequest {
            mode: DeltaMode::Differential,
            base_reference: "base".to_string(),
        }),
        ..Default::default()
    };
    drv.export_resumable(project, &delta_opts, "d1")
        .await
        .expect("delta export");

    // PROVE it is a TRUE changeset delta, not a full-dump fallback.
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::LibsqlChangeset,
        "the delta must have changeset-captured libsql (not fallen back to a full dump)"
    );
    let blog_cs_path = format!("libsql/{project}/{blog}/default.changeset");
    let blog_cs_idx = d1_manifest
        .members
        .iter()
        .position(|m| m.kind == MemberKind::LibsqlChangeset && m.path == blog_cs_path)
        .expect("d1 must carry a blog libsql changeset member");
    assert!(
        !d1_manifest
            .members
            .iter()
            .any(|m| m.kind == MemberKind::Libsql && m.path.contains(&format!("/{blog}/"))),
        "the full blog libsql dump must be SUPERSEDED by the changeset member"
    );
    assert!(
        matches!(
            d1_manifest.members[blog_cs_idx].sql_cursor,
            Some(boatramp_core::project_delta::SqlMemberCursor::LibsqlChangesetBase { .. })
        ),
        "the changeset member must carry a LibsqlChangesetBase cursor"
    );

    // --- PART 1: REAL round-trip. Plant a PRE-IMPORT sentinel in blog, import the chain, assert
    //     blog == MUTATED source (base snapshot + changeset replay), shop == untouched sentinel. ---
    seed(&backends, project, blog, &[(99, "PRE_IMPORT")]).await;
    let report = drv
        .import_resumable(
            project,
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("delta chain import (base snapshot + changeset replay + atomic swap)");
    assert!(
        report.libsql_databases >= 1,
        "a libsql db was restored by the changeset pass"
    );
    assert_eq!(
        read_t(&backends, project, blog).await,
        mutated_expect,
        "the restored blog db must equal the MUTATED source — base snapshot + changeset replay \
         (not the base state, not the pre-import sentinel)"
    );
    assert_eq!(
        read_t(&backends, project, shop).await,
        vec!["1:SHOPSENTINEL".to_string()],
        "the SECOND site (shop) must be UNTOUCHED (its changeset is empty)"
    );

    // --- PART 2: CRAFTED-ESCAPE. Tamper d1's blog changeset member to carry a write to a FOREIGN
    //     table `evil` (plus a legit-looking t:1 update). Import → REFUSED, blog byte-unchanged
    //     (atomic), shop untouched. ---
    let evil = tempfile::tempdir().unwrap();
    let evil_backends = Arc::new(LibsqlSqlBackends::local(evil.path().join("db")));
    {
        let db: Arc<dyn SqlBackend> = evil_backends.database("x", "base", "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", &[])
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO t VALUES (1,'orig'),(2,'beta'),(3,'gamma')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "CREATE TABLE evil(id INTEGER PRIMARY KEY, secret TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let db2: Arc<dyn SqlBackend> = evil_backends.database("x", "cur", "").await.unwrap();
        let mut tx = db2.begin().await.unwrap();
        tx.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", &[])
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO t VALUES (1,'HACKED'),(2,'beta'),(3,'gamma')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "CREATE TABLE evil(id INTEGER PRIMARY KEY, secret TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO evil VALUES (1,'ESCAPED')", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let evil_base_snap = evil.path().join("eb.db");
    let evil_cur_snap = evil.path().join("ec.db");
    evil_backends
        .snapshot_into(&ProjectRef::new("x").qualified("base"), "", &evil_base_snap)
        .await
        .unwrap();
    evil_backends
        .snapshot_into(&ProjectRef::new("x").qualified("cur"), "", &evil_cur_snap)
        .await
        .unwrap();
    let crafted_raw = match tokio::task::spawn_blocking(move || {
        boatramp_storage::sql_libsql_changeset::capture_changeset(&evil_base_snap, &evil_cur_snap)
    })
    .await
    .unwrap()
    .expect("craft a changeset")
    {
        boatramp_storage::sql_libsql_changeset::ChangesetCapture::Changeset(c) => c,
        other => panic!("crafted capture unexpectedly fell back: {other:?}"),
    };
    let crafted_member = boatramp_core::project_delta::encode_libsql_changeset(&crafted_raw);

    // Overwrite d1's blog changeset member object `m{idx:05}` + regenerate its `{size,sha256}` meta.
    let obj = resumable.join("d1").join(format!("m{blog_cs_idx:05}"));
    std::fs::write(&obj, &crafted_member).unwrap();
    let sha = boatramp_core::deploy::sha256_hex(&crafted_member);
    std::fs::write(
        resumable.join("d1").join(format!("m{blog_cs_idx:05}.meta")),
        format!("{{\"size\":{},\"sha256\":\"{sha}\"}}", crafted_member.len()).as_bytes(),
    )
    .unwrap();

    // Reset blog live to the BASE content so the crafted t-change would apply cleanly — isolating
    // the FOREIGN-table refusal as the sole reason the import is rejected.
    seed(
        &backends,
        project,
        blog,
        &[(1, "orig"), (2, "beta"), (3, "gamma")],
    )
    .await;
    let res = drv
        .import_resumable(
            project,
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        res.is_err(),
        "a crafted changeset writing a table OUTSIDE the base schema MUST be refused"
    );
    assert_eq!(
        read_t(&backends, project, blog).await,
        vec![
            "1:orig".to_string(),
            "2:beta".to_string(),
            "3:gamma".to_string()
        ],
        "the refused crafted import left blog UNCHANGED (no partial/leaked write)"
    );
    assert_eq!(
        read_t(&backends, project, shop).await,
        vec!["1:SHOPSENTINEL".to_string()],
        "the second site must be UNTOUCHED by the refused crafted import"
    );

    println!("PROJECT EXPORT LIBSQL TRUE-DELTA OK");
}
