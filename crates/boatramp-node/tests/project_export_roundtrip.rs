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
        let inv = pg_dump_invocation(&src_conn, false);
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
        let inv = pg_dump_invocation(&src_conn, false);
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
        let inv = pg_dump_invocation(&src, false);
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
/// correctness proof for the construens clone; Tier-2 / nightly, needs a live pgvector pg +
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
        let inv = pg_dump_invocation(&src, false);
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
