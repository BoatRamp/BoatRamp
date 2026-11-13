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
        // Test fixtures reach a real external Postgres directly — no per-project network join.
        ephemeral_network: None,
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
                active_spec: None,
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

/// **Live `project sync` managed-pg SHADOW-LAND gate THROUGH THE REAL DRIVER** (the incident
/// regression proof — Tier-2 / nightly, needs a live pg + Docker + `BOATRAMP_TEST_PG_URL`).
/// Self-skips.
///
/// The incident: `project sync --include-pg` into a managed-pg destination requested a `DataPlane`
/// bundle, which the pre-split coupling forced to the schema-less `--data-only` OVERLAY — refused for
/// a managed binding. This gate proves the FIX end-to-end: a `DataPlane + ShadowSwap` bundle (exactly
/// what sync now requests) EXPORTS a FULL managed-pg dump through the driver and IMPORTS it into a
/// fresh managed dest via the atomic non-superuser shadow+swap, so the ROWS LAND and are queryable,
/// the dest DB is provisioned, no orphan `*__shadow_*` db / `brexp_apply_*` role remains, and the
/// control-plane KV slice is NOT carried (identity clean). The MUTATION half re-exports the SAME
/// data with `ManagedRestore::Overlay` and proves the import still REFUSES it with the
/// "data-only restore of MANAGED pg … not supported" error — so this gate catches the real bug
/// (a managed overlay), not merely "the refusal went away". Emits
/// `PROJECT SYNC MANAGED PG SHADOW LAND OK`.
#[tokio::test]
async fn project_sync_managed_pg_shadow_land_live() {
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project_export::{
        BundleScope, CloneSkip, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_storage::fs::FsStorage;
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (managed-pg sync shadow-land gate not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!(
                "SKIP: no reachable Docker daemon (managed-pg sync shadow-land gate not run)"
            );
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let table = format!("brsync_t_{s}");
    let source_db = format!("brsync_src_{s}");
    let live_db = format!("brsync_live_{s}");
    let maint = conn(&user, &password, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // --- SOURCE + (empty) dest DBs; seed the source with known rows ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {source_db}"),
        format!("CREATE DATABASE {source_db}"),
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("CREATE DATABASE {live_db}"),
    ] {
        let (c, o) = psql(backend.as_ref(), &image, &maint, &sql).await;
        assert_eq!(c, 0, "setup `{sql}`: {o}");
    }
    let expect = "1:alpha\n2:beta\n3:gamma";
    let src_conn = conn(&user, &password, &host, port, &source_db);
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &src_conn,
        &format!(
            "CREATE TABLE {table}(id int primary key, v text); \
             INSERT INTO {table} VALUES (1,'alpha'),(2,'beta'),(3,'gamma');"
        ),
    )
    .await;
    assert_eq!(c, 0, "seed source rows: {o}");

    // --- build a MANAGED Single/default driver pointing at a given physical db (seeded replica).
    //     Returned as a closure-free local since each driver holds its own kv/blobs/work tempdirs. ---
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    let build_driver = |db_name: String| {
        let databases = BTreeMap::from([(
            "app".to_string(),
            ExternalDatabaseConfig {
                kind: "postgres".to_string(),
                compute: Some("pg".to_string()),
                database: Some(db_name),
                user: Some(user.clone()),
                ..Default::default() // tenant=Single, tenant_scope=Project (dedicated)
            },
        )]);
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let td = tempfile::tempdir().unwrap();
        let blobs: Arc<dyn boatramp_core::Storage> =
            Arc::new(FsStorage::new(td.path().join("blobs")));
        let deploy = DeployStore::new(blobs.clone(), kv.clone());
        let work = td.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        (databases, kv, blobs, deploy, td, work)
    };

    // Seal + seed-replica helper applied to each driver's own kv/deploy.
    async fn wire(
        kv: &Arc<dyn boatramp_core::kv::KvStore>,
        deploy: &boatramp_core::deploy::DeployStore,
        envelope: &Arc<dyn boatramp_core::envelope::KeyEnvelope>,
        password: &str,
        host: &str,
        port: u16,
    ) {
        use boatramp_core::compute::{
            Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
        };
        let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
        kv.put("managed-sql-cred/default/pg", sealed).await.unwrap();
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
                        host: host.to_string(),
                        port,
                    },
                    region: None,
                    healthy: true,
                    started_at: None,
                    phase: ReplicaPhase::Running,
                    readiness: boatramp_core::compute::Readiness::Provisioned,
                    data_dir: None,
                    snapshot: None,
                    active_spec: None,
                },
            )
            .await
            .unwrap();
    }

    let op_for = |databases: BTreeMap<String, ExternalDatabaseConfig>,
                  kv: Arc<dyn KvStore>,
                  blobs: Arc<dyn boatramp_core::Storage>|
     -> Arc<dyn boatramp_core::sql::OperatorSql> {
        Arc::new(NodeOperatorSql::new(
            databases,
            kv.clone(),
            Some(envelope.clone()),
            DeployStore::new(blobs, kv),
        ))
    };

    // --- SOURCE driver: export a DataPlane + ShadowSwap bundle of the seeded source db ---
    let (sdbs, skv, sblobs, sdeploy, _std, swork) = build_driver(source_db.clone());
    wire(&skv, &sdeploy, &envelope, &password, &host, port).await;
    let sop = op_for(sdbs.clone(), skv.clone(), sblobs.clone());
    let drv_src = NodeProjectExport::new(sdbs, sdeploy, skv.clone(), sblobs.clone(), swork)
        .with_managed_pg(backend.clone(), envelope.clone(), sop, false);

    let td_bundle = tempfile::tempdir().unwrap();
    let export_bundle = |opts: ExportOptions| {
        let drv = &drv_src;
        let dir = td_bundle.path();
        async move {
            use tokio_util::compat::TokioAsyncWriteCompatExt;
            let path = dir.join(format!("bundle-{}.brproj", now_suffix()));
            let f = tokio::fs::File::create(&path).await.unwrap();
            let mut sink = f.compat_write();
            drv.export_clone("default", &opts, &CloneSkip::default(), &mut sink)
                .await
                .expect("export_clone");
            std::fs::read(&path).unwrap()
        }
    };

    let shadow_bundle = export_bundle(ExportOptions {
        scope: BundleScope::DataPlane,
        managed_restore: ManagedRestore::ShadowSwap,
        ..Default::default()
    })
    .await;

    // --- DEST driver: import the DataPlane+ShadowSwap bundle into the fresh dest → rows LAND ---
    let (ddbs, dkv, dblobs, ddeploy, _dtd, dwork) = build_driver(live_db.clone());
    wire(&dkv, &ddeploy, &envelope, &password, &host, port).await;
    let dop = op_for(ddbs.clone(), dkv.clone(), dblobs.clone());
    let drv_dst = NodeProjectExport::new(ddbs, ddeploy, dkv.clone(), dblobs.clone(), dwork)
        .with_managed_pg(backend.clone(), envelope.clone(), dop, false)
        .with_trusted_extensions(vec![]);

    let mut body = futures::io::Cursor::new(shadow_bundle.clone());
    let report = drv_dst
        .import(
            "default",
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                ..Default::default()
            },
        )
        .await
        .expect("DataPlane+ShadowSwap import must SUCCEED (the fix)");
    assert_eq!(report.pg_databases, 1, "one managed pg db restored");
    // Identity clean: a DataPlane bundle carries no control-plane KV slice.
    assert_eq!(
        report.kv_records, 0,
        "a DataPlane bundle carries no KV records"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("control-plane KV") && n.contains("NOT imported")),
        "the report must note the KV slice was not imported: {:?}",
        report.notes
    );

    // --- rows LAND + are queryable on the provisioned dest db ---
    let live_conn = conn(&user, &password, &host, port, &live_db);
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &live_conn,
        &format!("SELECT id || ':' || v FROM {table} ORDER BY id"),
    )
    .await;
    assert_eq!(got, expect, "rows landed on the dest via shadow+swap");

    // --- no orphan shadow db / ephemeral apply role remains ---
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

    // --- MUTATION: the SAME data as an Overlay bundle MUST still be refused on import (the real bug).
    //     allow_schema_skew lets the restore reach the managed-overlay refusal instead of short-
    //     circuiting on the fresh target's schema-ledger mismatch. ---
    let overlay_bundle = export_bundle(ExportOptions {
        scope: BundleScope::DataPlane,
        managed_restore: ManagedRestore::Overlay,
        ..Default::default()
    })
    .await;
    let mut obody = futures::io::Cursor::new(overlay_bundle);
    let refused = drv_dst
        .import(
            "default",
            &mut obody,
            ImportOptions {
                apply: true,
                overwrite: true,
                allow_schema_skew: true,
                ..Default::default()
            },
        )
        .await;
    let err = refused.expect_err("an Overlay managed-pg import MUST be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("data-only restore of MANAGED pg"),
        "the refusal must be the managed-overlay RCE guard, got: {msg}"
    );

    // --- cleanup (best-effort) ---
    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {source_db}"),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT SYNC MANAGED PG SHADOW LAND OK");
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
                active_spec: None,
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
        ephemeral_network: None,
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
        ephemeral_network: None,
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

/// **Live Shared-tenant managed-MySQL `project sync` shadow-land gate** (Tier-2 / nightly — needs a
/// Docker daemon AND a MySQL server whose DSN user can `CREATE USER`/`GRANT`/`CREATE DATABASE`).
/// Self-skips.
///
/// Proves the NEW Shared managed-MySQL sidecar shadow+swap END-TO-END THROUGH THE REAL DRIVER
/// (`NodeProjectExport::export`/`import` → `mysql_sidecar_shadow_restore`), mirroring the Shared
/// Postgres clone gate. ONE Shared MySQL server hosts ≥2 provisioned tenants (`src`, `other`) via the
/// shipped `provision_tenant` path (per the tenancy-gate rule — a single-tenant fixture is blind to a
/// leak). It EXPORTS `src`'s `DataPlane + ShadowSwap` bundle (framed SIDECAR/tables-only for a Shared
/// binding) and IMPORTS it into a BRAND-NEW `fresh` tenant whose per-tenant db was never provisioned,
/// then asserts: the rows LAND and are queryable AS THE FRESH TENANT'S OWN LOGIN ROLE; ZERO
/// cross-tenant bytes (the sibling `other`'s login role cannot reach `fresh`'s db, and `other` is
/// byte-for-byte unchanged); no orphan `*__shadow_*` db / `brexp_apply_%` user survives; a re-import
/// is idempotent; and the MUTATION — the SAME data re-exported as `Overlay` — is still REFUSED by the
/// RCE guard. Emits `PROJECT SYNC MANAGED MYSQL SHARED SHADOW LAND OK`.
#[tokio::test]
async fn project_sync_managed_mysql_shared_shadow_land_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, IdentityChoice, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::{ManagedSqlCredentials, NodeOperatorSql};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name, tenant_role_name};
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (managed-mysql Shared sync gate not run)");
        return;
    };
    let Some((superuser, su_password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (managed-mysql Shared sync gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    const COMPUTE: &str = "my";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "clonesp";
    let s = now_suffix();
    let src_project = format!("myclone-src-{s}");
    let fresh_project = format!("myclone-fresh-{s}");
    let other_project = format!("myclone-other-{s}");

    // Superuser maintenance connection (no default db) for CREATE/DROP DATABASE + catalog probes.
    let su = MysqlConnection {
        host: host.clone(),
        port,
        user: superuser.clone(),
        password: su_password.clone(),
        database: String::new(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };

    // --- control plane: MemoryKv + a throwaway FsStorage DeployStore + a reversible test envelope. ---
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-myclone-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([7u8; 32]));

    // Pre-seal the SUPERUSER credential under the key the resolver + provisioner read —
    // `(DEFAULT_PROJECT, COMPUTE)` — to the test URL's ACTUAL password.
    let sealed_su = envelope
        .wrap(su_password.as_bytes())
        .await
        .expect("seal superuser pw");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed_su,
    )
    .await
    .expect("pre-seal superuser credential");

    // Seed ONE healthy, already-Provisioned replica of the `my` workload pointing at the test MySQL.
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-mysql".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed healthy replica");

    let binding = ExternalDatabaseConfig {
        kind: "mysql".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(DB_BINDING.to_string(), binding.clone())]);

    let db_name = |project: &str| tenant_db_name(DATABASE, &sanitize_ident(project));
    let mkconn = |db: &str, u: &str, pw: &str| MysqlConnection {
        host: host.clone(),
        port,
        user: u.to_string(),
        password: pw.to_string(),
        database: db.to_string(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };

    // Teardown any prior run (re-runnable).
    for p in [&src_project, &fresh_project, &other_project] {
        let _ = mysql_run(
            backend.as_ref(),
            image,
            &su,
            None,
            &format!("DROP DATABASE IF EXISTS `{}`;", db_name(p)),
        )
        .await;
    }

    // === Provision the SOURCE + the pre-existing sibling tenant through the SHIPPED path. ===
    provision_tenant(&deploy, &kv, &envelope, &binding, &src_project, "")
        .await
        .expect("provision source tenant");
    provision_tenant(&deploy, &kv, &envelope, &binding, &other_project, "")
        .await
        .expect("provision the pre-existing sibling tenant");

    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&src_project)),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         INSERT INTO t VALUES (1,'alpha'),(2,'beta');",
    )
    .await;
    assert_eq!(c, 0, "seed source tenant table; mysql output:\n{o}");
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&other_project)),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         INSERT INTO t VALUES (99,'untouched');",
    )
    .await;
    assert_eq!(
        c, 0,
        "seed the pre-existing sibling tenant; mysql output:\n{o}"
    );
    let other_before = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&other_project)),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;

    // --- the driver, wired exactly like the normal serve path (managed mysql context). ---
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-myclone-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-myclone-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false);

    // === EXPORT the source tenant as DataPlane + ShadowSwap (framed SIDECAR/tables-only). ===
    let export_bundle = |restore: ManagedRestore| {
        let driver = &driver;
        let src_project = src_project.clone();
        async move {
            let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
            driver
                .export(
                    &src_project,
                    &ExportOptions {
                        scope: BundleScope::DataPlane,
                        managed_restore: restore,
                        include_identity: false,
                        transport_key: None,
                        delta: None,
                    },
                    &mut sink,
                )
                .await
                .expect("driver export of the source tenant");
            sink.into_inner()
        }
    };
    let bundle = export_bundle(ManagedRestore::ShadowSwap).await;

    // === IMPORT into the BRAND-NEW `fresh` tenant (its db was never provisioned → self-provision). ===
    let report = {
        let mut source = futures::io::Cursor::new(bundle.clone());
        driver
            .import(
                &fresh_project,
                &mut source,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: false, // a genuinely fresh target — no prior data to overlay.
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("Shared managed-mysql DataPlane+ShadowSwap import must SUCCEED")
    };
    assert!(
        report.pg_databases >= 1,
        "the clone restored at least one mysql database"
    );

    // --- rows LAND + are queryable AS THE FRESH TENANT'S OWN LOGIN ROLE (never the superuser). ---
    let fresh_db = db_name(&fresh_project);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let fresh_ident = sanitize_ident(&fresh_project);
    let fresh_role = tenant_role_name(COMPUTE, &fresh_ident);
    let fresh_pw = creds
        .password(&fresh_project, &format!("{COMPUTE}/{fresh_ident}"))
        .await
        .expect("fresh login credential (minted at self-provision)");
    let (c, got) = mysql_run(
        backend.as_ref(),
        image,
        &mkconn(&fresh_db, &fresh_role, &fresh_pw),
        Some(&fresh_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        c, 0,
        "fresh tenant's own login role must read its rows:\n{got}"
    );
    assert_eq!(got, "1:alpha\n2:beta", "rows landed on the fresh tenant db");

    // === ZERO cross-tenant bytes: the sibling `other`'s login role cannot reach `fresh`'s db. ===
    let other_ident = sanitize_ident(&other_project);
    let other_role = tenant_role_name(COMPUTE, &other_ident);
    let other_pw = creds
        .password(&other_project, &format!("{COMPUTE}/{other_ident}"))
        .await
        .expect("sibling login credential");
    let (code, out) = mysql_run(
        backend.as_ref(),
        image,
        &mkconn(&fresh_db, &other_role, &other_pw),
        Some(&fresh_db),
        "SELECT COUNT(*) FROM t;",
    )
    .await;
    assert_ne!(
        code, 0,
        "CROSS-TENANT LEAK: the sibling reached fresh's db + read its rows: {out}"
    );
    assert!(
        out.to_ascii_lowercase().contains("access denied"),
        "the sibling must be denied at fresh's db (got: {out})"
    );

    // --- no orphan shadow db / ephemeral apply user remains (read from the global catalogs). ---
    let (_c, shadows) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        &format!(
            "SELECT COUNT(*) FROM information_schema.schemata \
             WHERE schema_name LIKE '{fresh_db}%__shadow_%';"
        ),
    )
    .await;
    assert_eq!(
        shadows.trim(),
        "0",
        "no orphan shadow database must remain: {shadows:?}"
    );
    let (_c, users) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        "SELECT COUNT(*) FROM mysql.user WHERE user LIKE 'brexp_apply_%';",
    )
    .await;
    assert_eq!(
        users.trim(),
        "0",
        "no orphan ephemeral apply user must remain: {users:?}"
    );

    // --- TENANCY GATE: the pre-existing sibling tenant is byte-for-byte UNCHANGED. ---
    let other_after = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&other_project)),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;
    assert_eq!(
        other_after, other_before,
        "self-provisioning the fresh target must not touch the pre-existing sibling tenant"
    );

    // --- IDEMPOTENCY: re-importing into the now-provisioned `fresh` target is a clean success. ---
    let report2 = {
        let mut source = futures::io::Cursor::new(bundle);
        driver
            .import(
                &fresh_project,
                &mut source,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: true, // now has prior data from the first import.
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("re-importing into an already-provisioned target is idempotent")
    };
    assert!(
        report2.pg_databases >= 1,
        "the re-import still restored the db"
    );
    let got_again = mysql_run(
        backend.as_ref(),
        image,
        &mkconn(&fresh_db, &fresh_role, &fresh_pw),
        Some(&fresh_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;
    assert_eq!(
        got_again, "1:alpha\n2:beta",
        "idempotent re-import — rows unchanged, no clobber"
    );

    // === MUTATION: the SAME data as an Overlay bundle MUST still be refused on import (RCE guard). ===
    let overlay_bundle = export_bundle(ManagedRestore::Overlay).await;
    let mut obody = futures::io::Cursor::new(overlay_bundle);
    let refused = driver
        .import(
            &fresh_project,
            &mut obody,
            ImportOptions {
                apply: true,
                force: true,
                overwrite: true,
                allow_schema_skew: true,
                identity: IdentityChoice::Fresh,
                ..Default::default()
            },
        )
        .await;
    let err = refused.expect_err("an Overlay managed-mysql import MUST be refused");
    assert!(
        err.to_string()
            .contains("data-only restore of MANAGED mysql"),
        "the refusal must be the managed-overlay RCE guard, got: {err}"
    );

    // --- cleanup (best-effort) ---
    for p in [&src_project, &fresh_project, &other_project] {
        let _ = mysql_run(
            backend.as_ref(),
            image,
            &su,
            None,
            &format!("DROP DATABASE IF EXISTS `{}`;", db_name(p)),
        )
        .await;
    }

    println!("PROJECT SYNC MANAGED MYSQL SHARED SHADOW LAND OK");
}

/// **Live Shared `rls_session` force-RLS REPLICATE gate** (Tier-2 / nightly — needs a Docker daemon
/// AND a Postgres whose DSN user is the bootstrap superuser; self-skips). Proves, THROUGH the real
/// export/import driver on real pg, that the v0.59.4 `serve_as` serving posture ("Option C") drives
/// the superuser-only force-RLS machinery (`boatramp_force_rls_trg` event trigger +
/// `boatramp_force_rls()` function) EXACTLY as the posture requires on both ends of a clone/sync.
///
/// Two arms, one per posture (the posture is a property of the DECLARED binding — Option C recoupled
/// the FORCE-on-ENABLE trigger install from v0.59.3's `rls_session` to
/// `install_force_rls == rls_session && serve_as==Owner && Postgres`):
///
///   * **ARM A — `serve_as: non-owner` (the DEFAULT — construens's deliberate model).** A Shared
///     rls_session tenant that serves AS the per-tenant NON-OWNER runtime role. Plain `ENABLE` binds
///     the non-owner, so NO force trigger is installed and the restore REPLICATES the source's
///     per-table ENABLE/FORCE state FAITHFULLY (no blanket FORCE, no retroactive sweep). This is the
///     path construens runs — non-owner runtime confined by `ENABLE`, an owner/migrator that seeds
///     ACROSS tenants relying on NO-FORCE — so forcing or re-installing the fence on the dest would
///     break it. Asserts: (A1) the non-super shadow restore SUCCEEDS; (A2) REPLICATE — every dest
///     table's `relforcerowsecurity` == the source's (NO-FORCE stays NO-FORCE, FORCE stays FORCE,
///     nothing swept); (A3) NO force trigger + NO `boatramp_force_rls()` function on the dest (the
///     non-owner posture installs NONE — it would confine the owner-migrator and break seeding); (A4)
///     BEHAVIORAL isolation — a DISTINCT NON-OWNER non-super role with tenant GUC = A sees ONLY A's
///     rows on an A+B-seeded `ENABLE`+NO-FORCE table (zero foreign bytes), so isolation holds WITHOUT
///     FORCE.
///   * **ARM B — `serve_as: owner`.** A Shared rls_session tenant that serves AS the per-tenant OWNER
///     role (operate-as-owner): `ENABLE` does NOT bind the owner, so the posture installs the
///     superuser-only FORCE-on-ENABLE trigger. The source carries a DELIBERATELY `ENABLE`-only table
///     (the Security-FINDING-1 leak-#2 shape: a pre-existing/cross-posture ENABLE-only table landing
///     in an owner target). Asserts: (B1) the non-super shadow restore SUCCEEDS despite the dump
///     carrying the superuser-only trigger — the `pg_restore -L` TOC filter EXCLUDES exactly the two
///     reserved objects so it no longer hits construens's wall; (B2) FORCE-LIVE THROUGH THE RESTORE —
///     the owner-posture post-swap re-provision's retroactive FORCE-sweep upgrades the source's
///     ENABLE-only table to FORCE on the dest, so the dest is ALL-FORCE (owner-serving ⟺ FORCE live,
///     closing FINDING-1 leak #2 end-to-end through the driver); (B3) the trigger + function are
///     PRESENT (re-installed) on the dest; (B5) MUTATION — a PLAIN (unfiltered) non-super restore of
///     the same dump FAILS with construens's exact wall, `permission denied to create event trigger`.
///
/// Emits `PROJECT SYNC SHARED RLS FORCE REPLICATE OK`.
#[tokio::test]
async fn project_sync_shared_rls_force_replicate_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, IdentityChoice, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, ServeAs, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::{ManagedSqlCredentials, NodeOperatorSql};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{
        sanitize_ident, tenant_db_name, tenant_owner_role_name, tenant_role_name,
    };
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (Shared rls_session force-RLS replicate gate)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (force-RLS replicate gate)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "rlsforce";
    let s = now_suffix();

    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // --- control plane: MemoryKv + throwaway FsStorage DeployStore + a reversible test envelope. ---
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-rlsf-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([5u8; 32]));

    // Pre-seal the SUPERUSER credential the resolver + provisioner read — `(DEFAULT_PROJECT, COMPUTE)`.
    let sealed_su = envelope
        .wrap(su_pw.as_bytes())
        .await
        .expect("seal superuser pw");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed_su,
    )
    .await
    .expect("pre-seal superuser credential");
    // One healthy, already-Provisioned replica of the `pg` workload pointing at the test Postgres.
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-pg".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed healthy replica");

    let db_name = |p: &str| tenant_db_name(DATABASE, &sanitize_ident(p));
    // A SHARED, Project-grain, `rls_session = true` managed-pg binding for the given serving posture.
    let binding_for = |serve_as: ServeAs| ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        serve_as,
        tenant_guc: Some("app.tenant_id".into()),
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    // Build a managed-pg export/import driver for a single posture binding (its `databases` map drives
    // the post-swap re-provision, so the dest is re-provisioned at the SAME posture it was declared).
    let make_driver = |binding: ExternalDatabaseConfig, tag: &str| {
        let databases = BTreeMap::from([(DB_BINDING.to_string(), binding)]);
        let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
            databases.clone(),
            kv.clone(),
            Some(envelope.clone()),
            deploy.clone(),
        ));
        let work = std::env::temp_dir().join(format!("boatramp-rlsf-{tag}-work-{s}"));
        std::fs::create_dir_all(&work).unwrap();
        let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
            std::env::temp_dir().join(format!("boatramp-rlsf-{tag}-blobs-{s}")),
        ));
        NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
            .with_managed_pg(backend.clone(), envelope.clone(), op, false)
            .with_trusted_extensions(vec![])
    };

    // The per-table force-state probe (the replicate baseline + the dest assertion share it).
    const FORCE_Q: &str = "SELECT relname || ':' || relforcerowsecurity::text FROM pg_class \
         WHERE relname IN ('t_noforce','t_forced') ORDER BY relname";

    // =========================================================================================
    // ARM A — `serve_as: non-owner` (the DEFAULT): REPLICATE-faithful, NO force trigger, ENABLE
    // confines the non-owner runtime. This is construens's deliberate model.
    // =========================================================================================
    let a_src = format!("rlsf-a-src-{s}");
    let a_fresh = format!("rlsf-a-fresh-{s}");
    let a_binding = binding_for(ServeAs::NonOwner);
    for p in [&a_src, &a_fresh] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{}\"", db_name(p)),
        )
        .await;
    }
    provision_tenant(&deploy, &kv, &envelope, &a_binding, &a_src, "")
        .await
        .expect("provision ARM-A (non-owner) source tenant");

    // Seed the SOURCE: an owner-owned ENABLE table left DELIBERATELY NO-FORCE (construens's shape —
    // NO trigger exists under the non-owner posture, so NO FORCE is simply never applied) + a second
    // table explicitly set FORCE (so the per-table REPLICATE of BOTH directions is proven).
    let a_src_db = db_name(&a_src);
    let a_owner = tenant_owner_role_name(COMPUTE, &sanitize_ident(&a_src));
    let a_src_conn = conn(&superuser, &su_pw, &host, port, &a_src_db);
    let a_seed = format!(
        "CREATE TABLE t_noforce(id int primary key, tid text, v text); \
         ALTER TABLE t_noforce OWNER TO \"{a_owner}\"; \
         ALTER TABLE t_noforce ENABLE ROW LEVEL SECURITY; \
         CREATE POLICY p_noforce ON t_noforce USING (tid = current_setting('app.tenant_id', true)); \
         INSERT INTO t_noforce VALUES (1,'A','a1'),(2,'B','b1'),(3,'A','a2'); \
         CREATE TABLE t_forced(id int primary key, tid text); \
         ALTER TABLE t_forced OWNER TO \"{a_owner}\"; \
         ALTER TABLE t_forced ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE t_forced FORCE ROW LEVEL SECURITY; \
         INSERT INTO t_forced VALUES (1,'A'),(2,'B');"
    );
    let (c, o) = psql(backend.as_ref(), &image, &a_src_conn, &a_seed).await;
    assert_eq!(c, 0, "ARM A seed source RLS tables: {o}");
    // The non-owner posture installs NO fence trigger on the source either.
    let (_c, a_src_trg) = psql(
        backend.as_ref(),
        &image,
        &a_src_conn,
        "SELECT count(*) FROM pg_event_trigger WHERE evtname = 'boatramp_force_rls_trg'",
    )
    .await;
    assert_eq!(
        a_src_trg, "0",
        "ARM A (non-owner): provisioning must install NO force-RLS trigger on the source"
    );
    let a_src_force = psql(backend.as_ref(), &image, &a_src_conn, FORCE_Q).await.1;
    assert_eq!(
        a_src_force, "t_forced:true\nt_noforce:false",
        "ARM A source baseline: t_forced FORCE'd, t_noforce ENABLE-but-NO-FORCE (got {a_src_force:?})"
    );

    let a_driver = make_driver(a_binding, "a");
    let mut a_sink = futures::io::Cursor::new(Vec::<u8>::new());
    a_driver
        .export(
            &a_src,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut a_sink,
        )
        .await
        .expect("ARM A driver export of the non-owner source tenant");
    let a_bundle = a_sink.into_inner();

    // A1: the non-super shadow+swap restore into a BRAND-NEW tenant SUCCEEDS.
    let a_report = {
        let mut body = futures::io::Cursor::new(a_bundle.clone());
        a_driver
            .import(
                &a_fresh,
                &mut body,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: false,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("ARM A Shared rls_session DataPlane+ShadowSwap import MUST SUCCEED")
    };
    assert!(
        a_report.pg_databases >= 1,
        "ARM A: the clone restored the pg database"
    );
    let a_dest_db = db_name(&a_fresh);
    let a_dest_conn = conn(&superuser, &su_pw, &host, port, &a_dest_db);

    // A2 (REPLICATE — the key one): per-table force state round-trips EXACTLY. NO sweep.
    let a_dest_force = psql(backend.as_ref(), &image, &a_dest_conn, FORCE_Q)
        .await
        .1;
    assert_eq!(
        a_dest_force, a_src_force,
        "ARM A: force-RLS state must REPLICATE the source per table — NO-FORCE stays NO-FORCE (never \
         swept to FORCE), FORCE stays FORCE. source={a_src_force:?} dest={a_dest_force:?}"
    );

    // A3: the non-owner posture installs NEITHER the trigger NOR the function on the dest (it would
    // confine the owner-migrator and break construens's cross-tenant seeding).
    let (_c, a_trg) = psql(
        backend.as_ref(),
        &image,
        &a_dest_conn,
        "SELECT count(*) FROM pg_event_trigger WHERE evtname = 'boatramp_force_rls_trg'",
    )
    .await;
    assert_eq!(
        a_trg, "0",
        "ARM A (non-owner): the force-RLS event trigger must NOT be installed on the dest"
    );
    let (_c, a_func) = psql(
        backend.as_ref(),
        &image,
        &a_dest_conn,
        "SELECT count(*) FROM pg_proc WHERE proname = 'boatramp_force_rls'",
    )
    .await;
    assert_eq!(
        a_func, "0",
        "ARM A (non-owner): the boatramp_force_rls() function must NOT be present on the dest"
    );

    // A4 (behavioral): a DISTINCT NON-OWNER, non-super runtime role with tenant GUC = A sees ONLY A's
    // rows on the ENABLE+NO-FORCE table — isolation holds WITHOUT force.
    let a_fresh_ident = sanitize_ident(&a_fresh);
    let a_login = tenant_role_name(COMPUTE, &a_fresh_ident);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let a_login_pw = creds
        .password(&a_fresh, &format!("{COMPUTE}/{a_fresh_ident}"))
        .await
        .expect("ARM A fresh login credential (minted at self-provision)");
    let a_login_conn = conn(&a_login, &a_login_pw, &host, port, &a_dest_db);
    let probe = "SET app.tenant_id = 'A'; \
                 SELECT 'SEEN[' || coalesce(string_agg(v, ',' ORDER BY id), '') || '] B=' \
                 || count(*) FILTER (WHERE tid = 'B') FROM t_noforce";
    let (c, out) = psql(backend.as_ref(), &image, &a_login_conn, probe).await;
    assert_eq!(
        c, 0,
        "ARM A: the non-owner login role must read its own tenant's rows: {out}"
    );
    let seen = out
        .lines()
        .find(|l| l.starts_with("SEEN["))
        .unwrap_or("<no SEEN marker>");
    assert_eq!(
        seen, "SEEN[a1,a2] B=0",
        "ARM A: RLS must confine the NON-OWNER runtime to tenant A on an ENABLE+NO-FORCE table — it \
         must see EXACTLY A's rows (a1,a2) and ZERO B rows (B=0): isolation holds WITHOUT force. Full \
         psql output: {out:?}"
    );

    // =========================================================================================
    // ARM B — `serve_as: owner`: the posture that installs the superuser-only FORCE fence. Proves
    // the EXCLUDE path (construens's wall) AND that FORCE is made actually-live THROUGH a restore
    // (Security FINDING-1 leak #2: a source's pre-existing ENABLE-only table landing in an owner
    // target is retroactively FORCE-swept on the dest).
    // =========================================================================================
    let b_src = format!("rlsf-b-src-{s}");
    let b_fresh = format!("rlsf-b-fresh-{s}");
    let b_binding = binding_for(ServeAs::Owner);
    for p in [&b_src, &b_fresh] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{}\"", db_name(p)),
        )
        .await;
    }
    // Owner posture ⇒ provisioning installs the FORCE trigger (the retroactive sweep + zero-assert run
    // on the empty db — a no-op there).
    provision_tenant(&deploy, &kv, &envelope, &b_binding, &b_src, "")
        .await
        .expect("provision ARM-B (owner) source tenant");

    let b_src_db = db_name(&b_src);
    let b_owner = tenant_owner_role_name(COMPUTE, &sanitize_ident(&b_src));
    let b_src_conn = conn(&superuser, &su_pw, &host, port, &b_src_db);
    // Seed: `t_forced` (ENABLE ⇒ the trigger auto-FORCEs it) and `t_noforce`, a DELIBERATELY ENABLE-
    // only table (disable the trigger around it) — the FINDING-1 leak-#2 pre-existing shape that the
    // owner-posture restore's retroactive FORCE-sweep must close on the dest.
    let b_seed = format!(
        "CREATE TABLE t_forced(id int primary key, tid text); \
         ALTER TABLE t_forced OWNER TO \"{b_owner}\"; \
         ALTER TABLE t_forced ENABLE ROW LEVEL SECURITY; \
         INSERT INTO t_forced VALUES (1,'A'),(2,'B'); \
         ALTER EVENT TRIGGER boatramp_force_rls_trg DISABLE; \
         CREATE TABLE t_noforce(id int primary key, tid text, v text); \
         ALTER TABLE t_noforce OWNER TO \"{b_owner}\"; \
         ALTER TABLE t_noforce ENABLE ROW LEVEL SECURITY; \
         CREATE POLICY p_noforce ON t_noforce USING (tid = current_setting('app.tenant_id', true)); \
         ALTER TABLE t_noforce NO FORCE ROW LEVEL SECURITY; \
         ALTER EVENT TRIGGER boatramp_force_rls_trg ENABLE; \
         INSERT INTO t_noforce VALUES (1,'A','a1'),(2,'B','b1'),(3,'A','a2');"
    );
    let (c, o) = psql(backend.as_ref(), &image, &b_src_conn, &b_seed).await;
    assert_eq!(c, 0, "ARM B seed source RLS tables: {o}");
    let b_src_force = psql(backend.as_ref(), &image, &b_src_conn, FORCE_Q).await.1;
    assert_eq!(
        b_src_force, "t_forced:true\nt_noforce:false",
        "ARM B source baseline: t_forced trigger-FORCE'd, t_noforce DELIBERATELY ENABLE-only (the \
         leak-#2 pre-existing shape) (got {b_src_force:?})"
    );

    let b_driver = make_driver(b_binding, "b");
    let mut b_sink = futures::io::Cursor::new(Vec::<u8>::new());
    b_driver
        .export(
            &b_src,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut b_sink,
        )
        .await
        .expect("ARM B driver export of the owner source tenant");
    let b_bundle = b_sink.into_inner();

    // B1: the non-super shadow+swap restore SUCCEEDS despite the dump carrying the superuser-only
    // trigger — the EXCLUDE (TOC filter) drops exactly the two reserved objects. Without it the
    // restore would exit 1 on `permission denied to create event trigger` (construens's wall, proven
    // by the B5 mutation below).
    let b_report = {
        let mut body = futures::io::Cursor::new(b_bundle.clone());
        b_driver
            .import(
                &b_fresh,
                &mut body,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: false,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect(
                "ARM B Shared rls_session DataPlane+ShadowSwap import MUST SUCCEED (the EXCLUDE fix — \
                 a non-super restore of a dump carrying boatramp_force_rls_trg)",
            )
    };
    assert!(
        b_report.pg_databases >= 1,
        "ARM B: the clone restored the pg database"
    );
    let b_dest_db = db_name(&b_fresh);
    let b_dest_conn = conn(&superuser, &su_pw, &host, port, &b_dest_db);

    // B2 (FORCE-LIVE THROUGH THE RESTORE — the key owner-posture assertion): the source's pre-existing
    // ENABLE-only `t_noforce` is retroactively FORCE-SWEPT by the owner-posture post-swap re-provision,
    // so the dest is ALL-FORCE. This closes Security FINDING-1 leak #2 end-to-end through the driver:
    // owner-serving ⟺ FORCE actually live, even for ENABLE-only tables carried across a clone/sync.
    let b_dest_force = psql(backend.as_ref(), &image, &b_dest_conn, FORCE_Q)
        .await
        .1;
    assert_eq!(
        b_dest_force, "t_forced:true\nt_noforce:true",
        "ARM B (owner): the owner-posture restore must leave the dest ALL-FORCE — the retroactive \
         FORCE-sweep upgrades the source's ENABLE-only t_noforce (FINDING-1 leak #2 closed through \
         the driver). source={b_src_force:?} dest={b_dest_force:?}"
    );

    // B3: the trigger + function are PRESENT (re-installed) on the dest under the owner posture.
    let (_c, b_trg) = psql(
        backend.as_ref(),
        &image,
        &b_dest_conn,
        "SELECT count(*) FROM pg_event_trigger WHERE evtname = 'boatramp_force_rls_trg'",
    )
    .await;
    assert_eq!(
        b_trg, "1",
        "ARM B (owner): the force-RLS event trigger must be re-installed on the dest"
    );
    let (_c, b_func) = psql(
        backend.as_ref(),
        &image,
        &b_dest_conn,
        "SELECT count(*) FROM pg_proc WHERE proname = 'boatramp_force_rls'",
    )
    .await;
    assert_eq!(
        b_func, "1",
        "ARM B (owner): the boatramp_force_rls() function must be present on the dest"
    );

    // B5 (MUTATION — "drop the EXCLUDE"): a PLAIN non-super restore of the owner dump (which carries
    // the superuser-only event trigger) FAILS with construens's exact wall. Produce a full `-Fc` dump
    // of the owner source, create a fresh db owned by a fresh NON-super role, and restore WITHOUT the
    // TOC filter as that role → `permission denied to create event trigger`.
    //
    // The mut db/role names MUST be SHORT and independent of `b_src_db`: a real tenant db name is at
    // Postgres's 63-byte NAMEDATALEN limit, so a `{db}__mut` suffix would TRUNCATE back to the source
    // name — and `DROP DATABASE IF EXISTS {mut_db}` would then DROP THE SOURCE, leaving an empty dump.
    let mut_db = format!("brexp_mutdb_{s}");
    let mut_role = format!("brexp_mut_{s}");
    let (mc, mo) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "DROP DATABASE IF EXISTS \"{mut_db}\"; \
             DROP ROLE IF EXISTS \"{mut_role}\"; \
             CREATE ROLE \"{mut_role}\" LOGIN PASSWORD 'mutpw' NOSUPERUSER; \
             CREATE DATABASE \"{mut_db}\" OWNER \"{mut_role}\";"
        ),
    )
    .await;
    assert_eq!(mc, 0, "mutation setup (fresh non-super role + db): {mo}");
    let (_c, issuper) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT rolsuper FROM pg_roles WHERE rolname = '{mut_role}'"),
    )
    .await;
    assert_eq!(
        issuper, "f",
        "the mutation role {mut_role:?} MUST be NOSUPERUSER (rolsuper={issuper:?})"
    );
    let dumpfile = std::env::temp_dir().join(format!("rlsf-mut-dump-{s}.fc"));
    {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let argv = vec![
            "pg_dump".to_string(),
            "--no-owner".to_string(),
            "--no-privileges".to_string(),
            "--no-comments".to_string(),
            "-Fc".to_string(),
            "-d".to_string(),
            b_src_db.clone(),
        ];
        let f = tokio::fs::File::create(&dumpfile).await.unwrap();
        let mut out = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &argv, &b_src_conn.env(), None, &mut out)
            .await
            .expect("pg_dump for the mutation");
        assert_eq!(
            code, 0,
            "pg_dump of the owner source for the mutation must succeed"
        );
    }
    let mut_toc = {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let argv = vec!["pg_restore".to_string(), "-l".to_string()];
        let td = tempfile::tempdir().unwrap();
        let outp = td.path().join("toc.out");
        let inf = tokio::fs::File::open(&dumpfile).await.unwrap();
        let mut rdr = inf.compat();
        let f = tokio::fs::File::create(&outp).await.unwrap();
        let mut sink = f.compat_write();
        let _ = backend
            .run_ephemeral(&image, &argv, &[], Some(&mut rdr), &mut sink)
            .await
            .expect("pg_restore -l for the mutation TOC");
        tokio::fs::read_to_string(&outp).await.unwrap_or_default()
    };
    assert!(
        mut_toc.contains("boatramp_force_rls_trg"),
        "the mutation dump MUST carry the force-RLS EVENT TRIGGER (else the mutation is vacuous); \
         TOC was: {mut_toc}"
    );
    let mut_conn = conn(&mut_role, "mutpw", &host, port, &mut_db);
    let mut_out = {
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "exec pg_restore --no-owner --no-privileges --exit-on-error --single-transaction \
                 -U {mut_role} -d {mut_db} 2>&1"
            ),
        ];
        let td = tempfile::tempdir().unwrap();
        let outp = td.path().join("mut.out");
        let inf = tokio::fs::File::open(&dumpfile).await.unwrap();
        let mut rdr = inf.compat();
        let f = tokio::fs::File::create(&outp).await.unwrap();
        let mut sink = f.compat_write();
        let code = backend
            .run_ephemeral(&image, &argv, &mut_conn.env(), Some(&mut rdr), &mut sink)
            .await
            .expect("plain non-super restore (mutation)");
        let text = tokio::fs::read_to_string(&outp).await.unwrap_or_default();
        (code, text)
    };
    assert_ne!(
        mut_out.0, 0,
        "MUTATION: a PLAIN (unfiltered) non-super restore MUST FAIL (construens's wall): {}",
        mut_out.1
    );
    assert!(
        mut_out
            .1
            .to_ascii_lowercase()
            .contains("permission denied to create event trigger"),
        "the plain-restore failure must be construens's exact wall (permission denied to create \
         event trigger), got: {}",
        mut_out.1
    );

    // --- cleanup (best-effort) ---
    let _ = tokio::fs::remove_file(&dumpfile).await;
    for sql in [
        format!("DROP DATABASE IF EXISTS \"{mut_db}\""),
        format!("DROP ROLE IF EXISTS \"{mut_role}\""),
        format!("DROP DATABASE IF EXISTS \"{a_dest_db}\""),
        format!("DROP DATABASE IF EXISTS \"{a_src_db}\""),
        format!("DROP DATABASE IF EXISTS \"{b_dest_db}\""),
        format!("DROP DATABASE IF EXISTS \"{b_src_db}\""),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }

    println!("PROJECT SYNC SHARED RLS FORCE REPLICATE OK");
}

/// **Live construens-SHAPED idempotency + orphan-recovery gate** (Tier-2 / nightly; needs a live
/// Postgres `BOATRAMP_TEST_PG_URL` + Docker). Self-skips. Reproduces the construens cross-node
/// re-run incident and proves all four managed-DB fixes end-to-end on REAL pg, with ≥2 tenants in
/// the shared keyspace so cross-tenant isolation (ZERO foreign bytes) is asserted throughout.
///
/// The incident: a `project sync --apply` into a managed-pg dest FAILED at pg (`ERROR: database
/// "construens_…" already exists`); the best-effort deprovision then failed with a MISLABELED
/// `sql syntax error: database … already exists` (a broken soft-deprovision renaming INTO an
/// existing/collapsed name); `project rm` reported "owns nothing" yet LEFT the managed DB orphaned;
/// and no operator verb could drop the orphan. This gate proves the fixes:
///
/// 1. GAP 3 — a RE-RUN of the restore into a SAME-named dest whose managed DB ALREADY EXISTS (and
///    holds stale data) RECOVERS (idempotent replace / drop-and-recreate), twice, with the rows
///    landing and no orphan `__shadow_`/`__old_` db left.
/// 2. GAP 2 — the SOFT-deprovision of a tenant whose derived db name is AT Postgres's 63-byte cap
///    SUCCEEDS: the rename-aside is BOUNDED, so it never collapses back to the live name (the
///    construens `already exists`). MUTATION: the pre-fix unbounded `{db}__deleted_{ts}` overflows →
///    truncates to the live name → `ALTER DATABASE <db> RENAME TO <db>` → `database … already
///    exists`, so this `.expect(...)` fails without the fix.
/// 3. GAP 1 — `project rm`'s deprovisioner, given an EMPTY node-static map (the node that serves
///    managed DBs ONLY through the per-project declarative front door `project sync` uses), STILL
///    tears down a project's OWN DECLARED managed database. MUTATION: pre-fix it walked only the
///    static map, so the declared db was orphaned ("owns nothing").
/// 4. GAP 4 — the operator `db drop database` verb (`drop_database`) clears an orphaned managed
///    database, hard, scoped to the project's derived name.
///
/// Emits `PROJECT SYNC IDEMPOTENCY ORPHAN OK`.
#[tokio::test]
async fn project_sync_idempotency_orphan_recovery_live() {
    use boatramp_core::compute::{
        BackendRegistry, Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase,
        Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_core::sql::{ManagedDbDeclare, TenantDeprovisioner};
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_db_declare::{self, DeclareQuota, NodeManagedDbDeclare};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::{
        DEFAULT_DEPROVISION_GRACE_SECS, NodeTenantDeprovisioner, deprovision_tenant,
        provision_tenant,
    };
    use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name};
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (idempotency/orphan gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (idempotency/orphan gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "idem";
    let s = now_suffix();
    // A DELIBERATELY LONG dest project name so its derived tenant db name sits AT the 63-byte
    // NAMEDATALEN cap — the regime where the pre-fix `__deleted_<ts>` aside overflows + collapses.
    let dest = format!("idem-dest-{s}-{}", "z".repeat(28));
    let src = format!("idem-src-{s}");
    let sibling = format!("idem-sib-{s}");
    let decl = format!("idem-decl-{s}"); // gap 1 + gap 4: a PROJECT-DECLARED db (declarative front door)

    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    // --- control plane: MemoryKv + throwaway FsStorage DeployStore + a reversible test envelope. ---
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-idem-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([7u8; 32]));

    // Seal the SUPERUSER credential + seed ONE healthy replica of the shared `pg` workload.
    let seal_and_seed = |compute: String| {
        let (kv, deploy, envelope, su_pw, host) = (
            kv.clone(),
            deploy.clone(),
            envelope.clone(),
            su_pw.clone(),
            host.clone(),
        );
        async move {
            let sealed = envelope.wrap(su_pw.as_bytes()).await.expect("seal su pw");
            kv.put(
                &format!("managed-sql-cred/{DEFAULT_PROJECT}/{compute}"),
                sealed,
            )
            .await
            .expect("pre-seal superuser credential");
            deploy
                .set_replica_state(
                    ProjectRef::DEFAULT,
                    &ObservedInstance {
                        handle: InstanceHandle {
                            project: DEFAULT_PROJECT.to_string(),
                            workload: compute.clone(),
                            replica: 0,
                            backend_ref: "test-external-pg".to_string(),
                        },
                        node: 0,
                        backend: "external".to_string(),
                        endpoint: Endpoint {
                            scheme: Scheme::Http,
                            host: host.clone(),
                            port,
                        },
                        region: None,
                        healthy: true,
                        started_at: None,
                        phase: ReplicaPhase::Running,
                        readiness: Readiness::Provisioned,
                        data_dir: None,
                        snapshot: None,
                        active_spec: None,
                    },
                )
                .await
                .expect("seed healthy replica");
        }
    };
    seal_and_seed(COMPUTE.to_string()).await;

    // A SHARED, Project-grain, NON-rls managed-pg binding (per-tenant db on the shared `pg` server).
    let binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(DB_BINDING.to_string(), binding.clone())]);
    let db_name = |p: &str| tenant_db_name(DATABASE, &sanitize_ident(p));
    let dest_db = db_name(&dest);
    let src_db = db_name(&src);
    let sib_db = db_name(&sibling);

    // Precondition: the dest db name is AT the 63-byte cap (the overflow regime the fix targets).
    assert!(
        dest_db.len() >= 60,
        "the dest db name must be near the 63-byte cap to exercise the aside overflow, got {} bytes: {dest_db}",
        dest_db.len()
    );

    // Teardown any prior run (re-runnable).
    let decl_compute = managed_db_declare::derived_workload(&decl, "idemapp");
    let decl_db = tenant_db_name("idemapp", &sanitize_ident(&decl));
    for db in [&dest_db, &src_db, &sib_db, &decl_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    // Sweep any stale bounded asides from a prior run of THIS test's dest.
    let aside_like = format!("{}%", &dest_db[..dest_db.len().min(30)]);
    let (_c, stale) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{aside_like}' AND datname LIKE '%__deleted_%'"),
    )
    .await;
    for a in stale.lines().filter(|l| !l.trim().is_empty()) {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{}\"", a.trim()),
        )
        .await;
    }

    // === Provision the three static-binding tenants (shared keyspace: ≥2 tenants). ===
    for p in [&src, &dest, &sibling] {
        provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
            .await
            .unwrap_or_else(|e| panic!("provision {p}: {e}"));
    }

    // Seed: SOURCE rows, a DISTINCT sibling secret (the isolation witness), and STALE dest data
    // (to prove the re-run REPLACES it). Marker table seeded as the superuser (reaches every tenant db).
    let seed = |db: String, rows: &str| {
        let c = conn(&superuser, &su_pw, &host, port, &db);
        let sql =
            format!("CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES {rows};");
        let backend = backend.clone();
        let image = image.clone();
        async move {
            let (code, o) = psql(backend.as_ref(), &image, &c, &sql).await;
            assert_eq!(code, 0, "seed {db}: {o}");
        }
    };
    seed(src_db.clone(), "('A','src-a'),('B','src-b')").await;
    seed(sib_db.clone(), "('S','sibling-secret')").await;
    seed(dest_db.clone(), "('X','stale-dest')").await;

    // --- the driver (static binding, wired like the serve path). ---
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-idem-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-idem-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false)
        .with_trusted_extensions(vec![]);

    // === EXPORT the source tenant (DataPlane + ShadowSwap — a FULL `-Fc` dump). ===
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    driver
        .export(
            &src,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut sink,
        )
        .await
        .expect("export source tenant");
    let bundle = sink.into_inner();

    // === GAP 3: RE-RUN the restore into the SAME-named dest whose managed DB ALREADY EXISTS (with
    //     stale data) — TWICE. Each RECOVERS (idempotent replace / drop-and-recreate). ===
    for attempt in 1..=2 {
        let mut body = futures::io::Cursor::new(bundle.clone());
        driver
            .import(
                &dest,
                &mut body,
                ImportOptions {
                    apply: true,
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "RE-RUN #{attempt} into a same-named dest whose managed DB already exists MUST \
                     RECOVER (idempotent replace), got: {e}"
                )
            });
        let live = conn(&superuser, &su_pw, &host, port, &dest_db);
        let (_c, got) = psql(
            backend.as_ref(),
            &image,
            &live,
            "SELECT tid || ':' || v FROM marker ORDER BY tid",
        )
        .await;
        assert_eq!(
            got, "A:src-a\nB:src-b",
            "re-run #{attempt}: the source rows must land + the stale dest data must be gone"
        );
    }
    // No orphan shadow/old db left behind by the swap.
    let (_c, orphans) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "SELECT datname FROM pg_database WHERE datname LIKE '{aside_like}' AND (datname LIKE '%__shadow_%' OR datname LIKE '%__old_%')"
        ),
    )
    .await;
    assert!(
        orphans.trim().is_empty(),
        "no orphan __shadow_/__old_ db may remain after the swap: {orphans:?}"
    );

    // === ISOLATION (zero foreign bytes): the sibling tenant is a SEPARATE physical db, untouched by
    //     all the dest churn — it still holds ONLY its own secret, no src/dest bytes. ===
    let sib_conn = conn(&superuser, &su_pw, &host, port, &sib_db);
    let (_c, sib_rows) = psql(
        backend.as_ref(),
        &image,
        &sib_conn,
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        sib_rows, "S:sibling-secret",
        "cross-tenant isolation: the sibling db must hold ONLY its own row (zero foreign bytes)"
    );

    // === GAP 2: SOFT-deprovision the 63-byte-name dest tenant. The rename-aside must SUCCEED
    //     (bounded) — the pre-fix unbounded name collapses to the live name → `already exists`. ===
    deprovision_tenant(
        &deploy,
        &kv,
        &envelope,
        &binding,
        &dest,
        "",
        DEFAULT_DEPROVISION_GRACE_SECS,
    )
    .await
    .expect(
        "soft-deprovision of a 63-byte-name tenant MUST SUCCEED — the BOUNDED `__deleted_` aside \
         never collapses to the live name (the pre-fix unbounded name would fail `database … \
         already exists`, the construens soft-deprovision shape)",
    );
    // The live name is FREED (renamed aside) …
    let (_c, still_live) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{dest_db}'"),
    )
    .await;
    assert!(
        still_live.trim().is_empty(),
        "the soft-deprovision must FREE the live name (rename it aside): {dest_db}"
    );
    // … and the aside db exists, is ≤ 63 bytes, and is DISTINCT from the live name (never collapsed).
    let (_c, asides) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{aside_like}' AND datname LIKE '%__deleted_%'"),
    )
    .await;
    let aside_names: Vec<&str> = asides
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        aside_names.len(),
        1,
        "exactly one bounded aside must exist: {asides:?}"
    );
    assert!(
        aside_names[0].len() <= 63,
        "the aside must fit NAMEDATALEN (≤63 bytes), got {} bytes: {}",
        aside_names[0].len(),
        aside_names[0]
    );
    assert_ne!(
        aside_names[0], dest_db,
        "the aside must never collapse back to the live name"
    );
    // Clean up the aside (best-effort hard drop — grace recovery is not under test here).
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP DATABASE IF EXISTS \"{}\"", aside_names[0]),
    )
    .await;

    // === GAP 1: a PROJECT-DECLARED managed db (the declarative front door `project sync` uses) is
    //     torn down by the deprovisioner even with an EMPTY node-static map. ===
    // The declarative front door lowers a declaration to `user = database = <binding name>`, i.e.
    // its managed server is initialized with a superuser NAMED after the binding ("idemapp"). Our
    // one shared test container's superuser is "postgres", so stand up that superuser role (= su_pw)
    // here so the declared-path provision/deprovision/drop authenticates exactly as production does.
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='idemapp') THEN \
             CREATE ROLE idemapp SUPERUSER LOGIN PASSWORD '{su_pw}'; END IF; END $$;"
        ),
    )
    .await;
    assert_eq!(c, 0, "create the declared-binding superuser role: {o}");
    seal_and_seed(decl_compute.clone()).await; // the declared binding's DERIVED compute → same pg server
    let applydb: boatramp_core::compute::ApplyDatabase =
        serde_json::from_value(serde_json::json!({
            "name": "idemapp",
            "kind": "postgres",
            "tenant": "shared",
            "tenant_scope": "project",
        }))
        .expect("minimal ApplyDatabase");
    deploy
        .set_project_database(ProjectRef::new(&decl), &applydb)
        .await
        .expect("store the project declaration");
    let decl_binding = managed_db_declare::lower(&decl, &applydb);
    provision_tenant(&deploy, &kv, &envelope, &decl_binding, &decl, "")
        .await
        .expect("provision the declared tenant");
    let (_c, exists) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{decl_db}'"),
    )
    .await;
    assert_eq!(exists.trim(), "1", "precondition: the declared db exists");

    // EMPTY node-static map — the deprovisioner must still find the project's OWN declaration.
    // grace=0 → immediate hard drop, so the teardown is directly observable.
    let deprovisioner = NodeTenantDeprovisioner::new(
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        BTreeMap::new(),
        0,
    );
    deprovisioner.deprovision_project(&decl).await;
    let (_c, after_rm) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{decl_db}'"),
    )
    .await;
    assert!(
        after_rm.trim().is_empty(),
        "GAP 1: `project rm`'s deprovisioner (empty static map) MUST drop the PROJECT-DECLARED db — \
         pre-fix it walked only the static map and orphaned it"
    );

    // === GAP 4: the operator orphan-drop verb (`db drop database`) clears an orphan. ===
    provision_tenant(&deploy, &kv, &envelope, &decl_binding, &decl, "")
        .await
        .expect("re-provision the declared tenant for the orphan-drop");
    let (_c, reexists) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{decl_db}'"),
    )
    .await;
    assert_eq!(
        reexists.trim(),
        "1",
        "precondition: re-provisioned declared db exists"
    );
    let declare = NodeManagedDbDeclare::new(
        BTreeMap::new(), // EMPTY static map — resolves the project's own declaration
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::from_config(None, None),
        BackendRegistry::new(),
    );
    let outcome = declare
        .drop_database(&decl, "idemapp")
        .await
        .expect("GAP 4: `db drop database` must hard-drop the declared managed db");
    assert_eq!(
        outcome.database, decl_db,
        "the orphan-drop must target the DERIVED physical name (project-scoped, never raw)"
    );
    let (_c, after_drop) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{decl_db}'"),
    )
    .await;
    assert!(
        after_drop.trim().is_empty(),
        "GAP 4: `db drop database` must drop the managed db (the orphan is cleared)"
    );
    // The reserved `default` project is refused (the catastrophic-drop guard).
    let refused = declare.drop_database(DEFAULT_PROJECT, "idemapp").await;
    assert!(
        refused.is_err(),
        "the default project's install db must never be droppable"
    );

    // === FINAL ISOLATION RE-CHECK: the sibling survived every dest/decl operation intact. ===
    let (_c, sib_final) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &sib_db),
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        sib_final, "S:sibling-secret",
        "the sibling tenant must be untouched by all dest/decl churn (zero foreign bytes)"
    );

    // --- cleanup (best-effort) ---
    for db in [&src_db, &sib_db, &dest_db, &decl_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        "DROP ROLE IF EXISTS idemapp",
    )
    .await;

    println!("PROJECT SYNC IDEMPOTENCY ORPHAN OK");
}

/// **Live UNDECLARED-ORPHAN reconcile + absent-dest FULL-bundle shadow-swap LAND gate** (Tier-2 /
/// nightly — needs a Docker daemon AND real Postgres). The fifth-layer construens failure: a prior
/// `project rm` / failed sync leaves a managed DB **ORPHANED + UNDECLARED** (the physical per-tenant
/// db + roles exist in pg, but no declared binding), then a fresh `project sync --apply` runs an
/// ABSENT-dest FULL-bundle restore into the SAME project identity. v0.59.3's gap-3 idempotency
/// recovery lives in `pg_swap_shadow`'s shadow→live RENAME (the existing-dest swap path); the fresh
/// path's reconciliation of a POPULATED occupant was the gap. This gate reproduces that EXACT shape
/// on real pg and proves, with CONTENT checks (not just "no error"):
///
/// 1. **The FULL shadow-swap restore LANDS end-to-end**: create (reconciling the undeclared orphan at
///    the target name) → the real `pg_restore` into the shadow → the atomic swap into the live name →
///    the SOURCE rows are genuinely present + correct in the live dest DB afterward (exact rows).
/// 2. **FAIL-SAFE reconciliation (fix #1; DATA-LOSS-SENSITIVE, flagged for Security)**: a POPULATED
///    orphan occupying the target name is NOT silently clobbered — it is soft-deprovisioned to a
///    recoverable `__deleted_<ts>` tombstone (grace recovery), which still holds its REAL data.
///    MUTATION WITNESS: without the fix the orphan's data is destroyed with no recoverable aside — so
///    the "the preserved tombstone holds the real data" assertion fails on the unfixed code (the
///    construens silent-data-loss wall; the v0.59.2 restore mechanism itself had never completed
///    end-to-end against a real cross-node run, so this LANDS it on our rig).
/// 3. **Cross-tenant isolation**: ≥2 tenants, each a SEPARATE physical db (the Shared per-tenant-db
///    model) under `rls_session`. The sibling holds ONLY its own secret — zero foreign bytes —
///    through all the dest churn, and (this binding being the DEFAULT `serve_as: non-owner` posture)
///    the restored dest carries NO FORCE-on-ENABLE fence trigger: v0.59.4 "Option C" installs the
///    fence for the owner posture ONLY, since a non-owner runtime is already bound by plain `ENABLE`.
/// 4. **Raw UNDECLARED-ORPHAN drop (fix #2)**: `drop_orphan_database` clears an orphan whose binding
///    is GONE (the "no CLI path" case `drop_database` `NotDeclared`s), deriving the physical db +
///    `_owner`/login roles STRUCTURALLY from `(project, name)` (never a raw name), and REFUSES the
///    reserved `default` project (the catastrophic / out-of-namespace guard).
///
/// Emits `PROJECT SYNC UNDECLARED ORPHAN RECONCILE OK`.
#[tokio::test]
async fn project_sync_undeclared_orphan_reconcile_live() {
    use boatramp_core::compute::{
        BackendRegistry, Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase,
        Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_core::sql::ManagedDbDeclare;
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_db_declare::{self, DeclareQuota, NodeManagedDbDeclare};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name};
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (undeclared-orphan reconcile gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!(
                "SKIP: no reachable Docker daemon (undeclared-orphan reconcile gate not run)"
            );
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "uorph";
    let s = now_suffix();
    let dest = format!("uorph-dest-{s}");
    let src = format!("uorph-src-{s}");
    let sibling = format!("uorph-sib-{s}");

    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-uorph-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));

    // Seal the superuser credential + seed one healthy replica of a named shared `pg` workload.
    let seal_and_seed = |compute: String, su: String| {
        let (kv, deploy, envelope, su_pw, host) = (
            kv.clone(),
            deploy.clone(),
            envelope.clone(),
            su_pw.clone(),
            host.clone(),
        );
        async move {
            let sealed = envelope.wrap(su_pw.as_bytes()).await.expect("seal su pw");
            kv.put(
                &format!("managed-sql-cred/{DEFAULT_PROJECT}/{compute}"),
                sealed,
            )
            .await
            .expect("pre-seal superuser credential");
            deploy
                .set_replica_state(
                    ProjectRef::DEFAULT,
                    &ObservedInstance {
                        handle: InstanceHandle {
                            project: DEFAULT_PROJECT.to_string(),
                            workload: compute.clone(),
                            replica: 0,
                            backend_ref: "test-external-pg".to_string(),
                        },
                        node: 0,
                        backend: "external".to_string(),
                        endpoint: Endpoint {
                            scheme: Scheme::Http,
                            host: host.clone(),
                            port,
                        },
                        region: None,
                        healthy: true,
                        started_at: None,
                        phase: ReplicaPhase::Running,
                        readiness: Readiness::Provisioned,
                        data_dir: None,
                        snapshot: None,
                        active_spec: None,
                    },
                )
                .await
                .expect("seed healthy replica");
            let _ = su; // the shared `pg` server's superuser is the DSN's own ("postgres").
        }
    };
    seal_and_seed(COMPUTE.to_string(), superuser.clone()).await;

    // A SHARED, Project-grain, RLS-fenced managed-pg binding (per-tenant db on the shared `pg`
    // server) — construens's tenancy shape: `rls_session` with the DEFAULT `serve_as: non-owner`
    // posture, so the restore exercises the RLS-fenced path (any superuser-only force-RLS object in a
    // dump is excluded from the non-super restore) while the non-owner post-swap re-provision installs
    // NO fence trigger on the dest (owner-posture only — see assertion (3a)).
    let binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(DB_BINDING.to_string(), binding.clone())]);
    let db_name = |p: &str| tenant_db_name(DATABASE, &sanitize_ident(p));
    let dest_db = db_name(&dest);
    let src_db = db_name(&src);
    let sib_db = db_name(&sibling);

    // Teardown any prior run (re-runnable), including any bounded asides from a prior dest.
    for db in [&dest_db, &src_db, &sib_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let aside_like = format!("{}%", &dest_db[..dest_db.len().min(24)]);
    let (_c, stale) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{aside_like}' AND datname LIKE '%__deleted_%'"),
    )
    .await;
    for a in stale.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{a}\""),
        )
        .await;
    }

    // === Provision the three tenants (shared keyspace: ≥2 tenants, each a SEPARATE physical db). ===
    for p in [&src, &dest, &sibling] {
        provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
            .await
            .unwrap_or_else(|e| panic!("provision {p}: {e}"));
    }

    // Seed: SOURCE rows, a DISTINCT sibling secret (the isolation witness), and the POPULATED dest
    // orphan's REAL data (what a fresh sync must NOT silently clobber).
    let seed = |db: String, rows: &str| {
        let c = conn(&superuser, &su_pw, &host, port, &db);
        let sql =
            format!("CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES {rows};");
        let backend = backend.clone();
        let image = image.clone();
        async move {
            let (code, o) = psql(backend.as_ref(), &image, &c, &sql).await;
            assert_eq!(code, 0, "seed {db}: {o}");
        }
    };
    seed(src_db.clone(), "('A','src-a'),('B','src-b')").await;
    seed(sib_db.clone(), "('S','sibling-secret')").await;
    seed(dest_db.clone(), "('X','REAL-DEST-DATA'),('Y','more-real')").await;

    // --- the driver (static binding, wired like the serve path). ---
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-uorph-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-uorph-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases.clone(), deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false)
        .with_trusted_extensions(vec![]);

    // === EXPORT the source tenant as a FULL bundle (the absent-dest sync shape). ===
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    driver
        .export(
            &src,
            &ExportOptions {
                scope: BundleScope::Full,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut sink,
        )
        .await
        .expect("export source tenant");
    let bundle = sink.into_inner();

    // === THE FRESH SYNC: an ABSENT-dest FULL-bundle restore (`skip_control_plane_kv`, the sync's own
    //     absent-dest shape) into the same project identity whose managed DB is a POPULATED orphan. ===
    let mut body = futures::io::Cursor::new(bundle.clone());
    driver
        .import(
            &dest,
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                skip_control_plane_kv: true,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "absent-dest FULL-bundle shadow-swap restore into a POPULATED undeclared orphan MUST \
                 LAND (reconcile the orphan + restore the source), got: {e}"
            )
        });

    // (1) The FULL shadow-swap restore LANDED: the SOURCE rows are genuinely present + correct.
    let live = conn(&superuser, &su_pw, &host, port, &dest_db);
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        got, "A:src-a\nB:src-b",
        "the full shadow-swap restore must land the SOURCE rows in the live dest db (end-to-end on real pg)"
    );

    // (2) FAIL-SAFE: the POPULATED orphan was NOT clobbered — its REAL data survives in a recoverable
    //     `__deleted_` tombstone. MUTATION WITNESS: without the fix no tombstone exists and the data is gone.
    let (_c, asides) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT datname FROM pg_database WHERE datname LIKE '{aside_like}' AND datname LIKE '%__deleted_%'"),
    )
    .await;
    let tombstones: Vec<&str> = asides
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        tombstones.len(),
        1,
        "the populated orphan MUST be preserved as EXACTLY ONE recoverable `__deleted_` tombstone \
         (fail-safe reconcile) — WITHOUT the fix it is silently clobbered (no tombstone): {asides:?}"
    );
    assert!(
        tombstones[0].len() <= 63 && tombstones[0] != dest_db,
        "the tombstone must be bounded (≤63 bytes) and distinct from the live name: {}",
        tombstones[0]
    );
    let tconn = conn(&superuser, &su_pw, &host, port, tombstones[0]);
    let (_c, trows) = psql(
        backend.as_ref(),
        &image,
        &tconn,
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        trows, "X:REAL-DEST-DATA\nY:more-real",
        "the preserved tombstone MUST still hold the orphan's REAL data (fail-safe, never clobbered)"
    );

    // (3a) RLS posture through the restore: this binding is the DEFAULT `serve_as: non-owner`
    // (`rls_session` with no posture set), so the post-swap re-provision installs NO FORCE-on-ENABLE
    // fence trigger (v0.59.4 "Option C": the fence is owner-posture ONLY — `install_force_rls` —
    // because a non-owner runtime is already bound by plain `ENABLE`, and forcing would confine the
    // owner-migrator). Assert its ABSENCE so a regression that re-couples the fence to `rls_session`
    // (and would FORCE a non-owner dest's tables, breaking construens's seeding) fails here.
    let (_c, trg) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT count(*) FROM pg_event_trigger WHERE evtname = 'boatramp_force_rls_trg'",
    )
    .await;
    assert_eq!(
        trg.trim(),
        "0",
        "the restored dest db is a `serve_as: non-owner` tenant, so the post-swap re-provision must \
         install NO force-RLS fence trigger (owner-posture only); got {trg:?}"
    );

    // (3b) Cross-tenant isolation (zero foreign bytes): the sibling is a SEPARATE physical db, untouched.
    let sib_conn = conn(&superuser, &su_pw, &host, port, &sib_db);
    let (_c, sib_rows) = psql(
        backend.as_ref(),
        &image,
        &sib_conn,
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        sib_rows, "S:sibling-secret",
        "cross-tenant isolation: the sibling db must hold ONLY its own row (zero foreign bytes)"
    );

    // Clean up the tombstone (grace recovery is not under test here).
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP DATABASE IF EXISTS \"{}\"", tombstones[0]),
    )
    .await;

    // === (4) RAW UNDECLARED-ORPHAN DROP (fix #2). Provision a tenant via the DERIVED (declarative)
    //     binding, DON'T declare it (⇒ UNDECLARED), prove `drop_database` can't reach it, then
    //     `drop_orphan_database` clears it by reconstructed derivation. ===
    let orphanp = format!("uorph-orphan-{s}");
    let orphan_binding_name = "uorphapp";
    let orphan_compute = managed_db_declare::derived_workload(&orphanp, orphan_binding_name);
    let orphan_db = tenant_db_name(orphan_binding_name, &sanitize_ident(&orphanp));
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP DATABASE IF EXISTS \"{orphan_db}\""),
    )
    .await;
    // The declarative front door lowers `user = database = <binding name>`, so the managed server's
    // superuser is NAMED after the binding; our one shared container's superuser is "postgres", so
    // stand up that role (= su_pw) and seal/seed the DERIVED compute exactly as production would.
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{orphan_binding_name}') THEN \
             CREATE ROLE {orphan_binding_name} SUPERUSER LOGIN PASSWORD '{su_pw}'; END IF; END $$;"
        ),
    )
    .await;
    assert_eq!(c, 0, "create the derived-binding superuser role: {o}");
    seal_and_seed(orphan_compute.clone(), orphan_binding_name.to_string()).await;
    // The reconstructed managed Shared/Project/pg binding — EXACTLY what `drop_orphan_database`
    // rebuilds for an undeclared name, so provisioning here derives the SAME physical db + roles.
    let orphan_binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(orphan_compute.clone()),
        database: Some(orphan_binding_name.into()),
        user: Some(orphan_binding_name.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    provision_tenant(&deploy, &kv, &envelope, &orphan_binding, &orphanp, "")
        .await
        .expect("provision the (to-be-orphaned) tenant");
    let (_c, exists) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{orphan_db}'"),
    )
    .await;
    assert_eq!(exists.trim(), "1", "precondition: the orphan db exists");
    // The owner role exists too (what the immediate declared drop LEAKS, and the orphan drop clears).
    let owner_role = boatramp_storage::tenant_provision::tenant_owner_role_name(
        &orphan_compute,
        &sanitize_ident(&orphanp),
    );
    let (_c, owner_exists) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_roles WHERE rolname='{owner_role}'"),
    )
    .await;
    assert_eq!(
        owner_exists.trim(),
        "1",
        "precondition: the orphan's _owner role exists"
    );

    // NO declaration stored ⇒ UNDECLARED. An EMPTY static map NodeManagedDbDeclare models a node that
    // served this DB only through the declarative front door (construens).
    let declare = NodeManagedDbDeclare::new(
        BTreeMap::new(),
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::from_config(None, None),
        BackendRegistry::new(),
    );
    // The gap: the DECLARED drop can't reach an undeclared orphan ("no CLI path").
    assert!(
        matches!(
            declare.drop_database(&orphanp, orphan_binding_name).await,
            Err(boatramp_core::sql::DeclareError::NotDeclared(_))
        ),
        "the declared `db drop database` MUST `NotDeclared` an undeclared orphan (the gap the orphan verb fixes)"
    );
    // The fix: the ORPHAN drop clears it by reconstructed, project-scoped derivation.
    let outcome = declare
        .drop_orphan_database(&orphanp, orphan_binding_name)
        .await
        .expect("`db drop database --orphan` MUST clear an UNDECLARED orphan");
    assert_eq!(
        outcome.database, orphan_db,
        "the orphan drop must target the DERIVED physical name (project-scoped, never raw)"
    );
    let (_c, after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{orphan_db}'"),
    )
    .await;
    assert!(
        after.trim().is_empty(),
        "the orphan db must be gone after the orphan drop"
    );
    // The `_owner` role is also cleared (the leak the task requires fixed).
    let (_c, owner_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_roles WHERE rolname='{owner_role}'"),
    )
    .await;
    assert!(
        owner_after.trim().is_empty(),
        "the orphan's `_owner` role must be dropped too (not leaked)"
    );
    // Idempotent: a second orphan drop on the now-absent db is a clean no-op.
    declare
        .drop_orphan_database(&orphanp, orphan_binding_name)
        .await
        .expect("orphan drop must be idempotent on an already-absent db");
    // Out-of-namespace / catastrophic guard: the reserved `default` project is refused.
    assert!(
        declare
            .drop_orphan_database(DEFAULT_PROJECT, orphan_binding_name)
            .await
            .is_err(),
        "the reserved `default` project's install db must never be orphan-droppable"
    );

    // === FINAL isolation re-check: the sibling survived every dest/orphan operation intact. ===
    let (_c, sib_final) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &sib_db),
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        sib_final, "S:sibling-secret",
        "the sibling tenant must be untouched by all dest/orphan churn (zero foreign bytes)"
    );

    // --- cleanup (best-effort) ---
    for db in [&src_db, &sib_db, &dest_db, &orphan_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS {orphan_binding_name}"),
    )
    .await;

    println!("PROJECT SYNC UNDECLARED ORPHAN RECONCILE OK");
}

/// **Live ORPHAN-DROP clears OBJECT-OWNING derived roles + role-sharing SAFETY GUARD gate** (Tier-2 /
/// nightly — needs a Docker daemon AND real Postgres). The SIXTH-layer construens failure (v0.59.4
/// acceptance): `db drop database --orphan` dropped the physical DB but LEFT the tenant's per-tenant
/// derived roles (`_owner` + login) because they still OWN OBJECTS the single derived-name drop can
/// NOT reach — a `__deleted_` aside a prior failed sync left behind, owner-owned. A plain `DROP ROLE`
/// then errors ("role cannot be dropped because some objects depend on it — owner of database
/// <aside>") and is best-effort-skipped, so the roles + the orphaned aside LEAK. This gate reproduces
/// that EXACT tangled shape on real pg and proves, DATA-LOSS-SAFELY, with CONTENT checks:
///
/// A (EXCLUSIVE): a tenant whose `_owner`/login roles own ONLY its own derived DB + a `__deleted_`
///    aside. `db drop database --orphan` now FORCE-clears those exclusively-owned object-owning roles
///    (drop the orphan's own aside DBs + `DROP OWNED` + `DROP ROLE`). MUTATION WITNESS: WITHOUT the
///    fix both roles AND the aside survive the drop (the construens leak); with it they are gone. A
///    fresh re-sync into the SAME identity then LANDS end-to-end (source rows present, content-checked)
///    — the tenant recovers on a clean, un-tangled identity.
///
/// B (SHARED — the HARD GUARD): a tenant with TWO bindings on the SAME shared server sharing ONE
///    `_owner`/login role, one binding LIVE. Orphan-dropping the OTHER binding must LEAVE the shared
///    roles intact (their `DROP OWNED` would destroy the LIVE sibling's objects) and SURFACE them in
///    the drop outcome. MUTATION WITNESS: the live sibling's db + its secret row survive the orphan
///    drop UNCHANGED (a naive force-clear would clobber them — zero foreign bytes), and the outcome
///    reports the retained roles.
///
/// ≥2 tenants, each a SEPARATE physical db. Emits `PROJECT SYNC ORPHAN DROP OWNING-ROLES OK`.
#[tokio::test]
async fn project_sync_orphan_drop_clears_object_owning_roles_live() {
    use boatramp_core::compute::{
        BackendRegistry, Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase,
        Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_core::sql::ManagedDbDeclare;
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_db_declare::{DeclareQuota, NodeManagedDbDeclare};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{
        bounded_aside_db_name, sanitize_ident, tenant_db_name, tenant_owner_role_name,
        tenant_role_name,
    };
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (orphan owning-roles gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (orphan owning-roles gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    let s = now_suffix();
    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-oor-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));

    let seal_and_seed = |compute: String| {
        let (kv, deploy, envelope, su_pw, host) = (
            kv.clone(),
            deploy.clone(),
            envelope.clone(),
            su_pw.clone(),
            host.clone(),
        );
        async move {
            let sealed = envelope.wrap(su_pw.as_bytes()).await.expect("seal su pw");
            kv.put(
                &format!("managed-sql-cred/{DEFAULT_PROJECT}/{compute}"),
                sealed,
            )
            .await
            .expect("pre-seal superuser credential");
            deploy
                .set_replica_state(
                    ProjectRef::DEFAULT,
                    &ObservedInstance {
                        handle: InstanceHandle {
                            project: DEFAULT_PROJECT.to_string(),
                            workload: compute.clone(),
                            replica: 0,
                            backend_ref: "test-external-pg".to_string(),
                        },
                        node: 0,
                        backend: "external".to_string(),
                        endpoint: Endpoint {
                            scheme: Scheme::Http,
                            host: host.clone(),
                            port,
                        },
                        region: None,
                        healthy: true,
                        started_at: None,
                        phase: ReplicaPhase::Running,
                        readiness: Readiness::Provisioned,
                        data_dir: None,
                        snapshot: None,
                        active_spec: None,
                    },
                )
                .await
                .expect("seed healthy replica");
        }
    };
    seal_and_seed(COMPUTE.to_string()).await;

    // ===== SCENARIO A (EXCLUSIVE) =====
    const EXCL_BINDING: &str = "oorapp";
    const EXCL_DB: &str = "oorx";
    let src = format!("oor-src-{s}");
    let orphan = format!("oor-excl-{s}");

    let binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(EXCL_DB.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(EXCL_BINDING.to_string(), binding.clone())]);
    let db_name = |p: &str| tenant_db_name(EXCL_DB, &sanitize_ident(p));
    let src_db = db_name(&src);
    let orphan_db = db_name(&orphan);
    let owner_role = tenant_owner_role_name(COMPUTE, &sanitize_ident(&orphan));
    let login_role = tenant_role_name(COMPUTE, &sanitize_ident(&orphan));
    let aside_db = bounded_aside_db_name(&orphan_db, "__deleted_", &format!("{s}"));

    for db in [&src_db, &orphan_db, &aside_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }

    for p in [&src, &orphan] {
        provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
            .await
            .unwrap_or_else(|e| panic!("provision {p}: {e}"));
    }

    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &src_db),
        "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES ('A','src-a'),('B','src-b');",
    )
    .await;
    assert_eq!(c, 0, "seed src: {o}");

    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &orphan_db),
        &format!("SET ROLE \"{owner_role}\"; CREATE TABLE owned_in_live(i int); INSERT INTO owned_in_live VALUES (1); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed orphan live owner table: {o}");

    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE \"{aside_db}\" OWNER \"{owner_role}\""),
    )
    .await;
    assert_eq!(c, 0, "create owner-owned aside: {o}");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &aside_db),
        &format!("GRANT CONNECT ON DATABASE \"{aside_db}\" TO \"{login_role}\"; ALTER DEFAULT PRIVILEGES FOR ROLE \"{owner_role}\" IN SCHEMA public GRANT SELECT ON TABLES TO \"{login_role}\"; SET ROLE \"{owner_role}\"; CREATE TABLE owned_in_aside(i int); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed owner-owned aside objects: {o}");

    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-oor-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-oor-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases.clone(), deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false)
        .with_trusted_extensions(vec![]);
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    driver
        .export(
            &src,
            &ExportOptions {
                scope: BundleScope::Full,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut sink,
        )
        .await
        .expect("export source tenant");
    let bundle = sink.into_inner();

    // Precondition (proves the construens tangle EXISTS): the owner role owns the aside db — so a
    // plain `DROP ROLE` would error, and the un-fixed orphan drop leaks the roles + the aside.
    let (_c, owns) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{owner_role}' ORDER BY 1"),
    )
    .await;
    assert!(
        owns.lines().any(|l| l.trim() == aside_db),
        "precondition: the orphan's _owner role must OWN the `__deleted_` aside db (the construens \
         tangle the single-name drop can't reach), owned dbs were {owns:?}"
    );

    let declare = NodeManagedDbDeclare::new(
        databases.clone(),
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::from_config(None, None),
        BackendRegistry::new(),
    );
    let drop_res = declare
        .drop_orphan_database(&orphan, EXCL_BINDING)
        .await
        .expect("`db drop database --orphan` MUST clear the orphan (object-owning roles and all)");
    assert_eq!(
        drop_res.database, orphan_db,
        "orphan drop targets the DERIVED physical name"
    );
    assert!(
        drop_res.retained_roles.is_empty(),
        "an EXCLUSIVELY-owned orphan has NO role shared with a live binding, so NONE is retained: {:?}",
        drop_res.retained_roles
    );

    // (A) MUTATION WITNESS: the object-owning derived roles are now GONE (without the fix they
    // survive, un-droppable, because they own the aside — the construens leak).
    let (_c, roles_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT rolname FROM pg_roles WHERE rolname IN ('{owner_role}','{login_role}') ORDER BY 1"),
    )
    .await;
    assert!(
        roles_after.trim().is_empty(),
        "the orphan's object-owning `_owner` + login roles MUST be cleared by `--orphan` (WITHOUT \
         the fix they leak, un-droppable because they own the aside): still present [{roles_after}]"
    );
    // (A) MUTATION WITNESS: the owner-owned aside db is dropped too (its leak is what kept the role).
    let (_c, aside_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{aside_db}'"),
    )
    .await;
    assert!(
        aside_after.trim().is_empty(),
        "the orphan's own `__deleted_` aside db MUST be dropped (the exclusively-owned disposable \
         data that kept the roles un-droppable): still present"
    );
    // Idempotent: a second orphan drop on the now-cleared identity is a clean no-op.
    declare
        .drop_orphan_database(&orphan, EXCL_BINDING)
        .await
        .expect("orphan drop must be idempotent on an already-cleared identity");

    // (A) End-to-end RECOVERY: a fresh re-sync into the SAME identity LANDS the source rows (the
    // tenant recovers on a clean, un-tangled identity — no leftover role/aside collision).
    let mut body = futures::io::Cursor::new(bundle.clone());
    driver
        .import(
            &orphan,
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                skip_control_plane_kv: true,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| {
            panic!("fresh re-sync into the cleared orphan identity MUST LAND (no 'already exists'): {e}")
        });
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &orphan_db),
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        got, "A:src-a\nB:src-b",
        "the re-sync into the cleared identity must land the SOURCE rows end-to-end"
    );

    for db in [&src_db, &orphan_db, &aside_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS \"{owner_role}\""),
    )
    .await;
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS \"{login_role}\""),
    )
    .await;

    // ===================================================================================
    // SCENARIO B (SHARED — the HARD GUARD): two bindings on one server share ONE derived role; one
    // LIVE. Orphan-dropping the other must LEAVE the shared roles (their DROP OWNED would clobber the
    // live sibling) and preserve the live binding's data — zero foreign bytes.
    // ===================================================================================
    let shar = format!("oor-shar-{s}");
    const B1: &str = "shb1";
    const B2: &str = "shb2";
    const DB1: &str = "shd1";
    const DB2: &str = "shd2";
    let mk = |database: &str| ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(database.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let b1 = mk(DB1);
    let b2 = mk(DB2);
    let databases_b = BTreeMap::from([(B1.to_string(), b1.clone()), (B2.to_string(), b2.clone())]);
    let shar_ident = sanitize_ident(&shar);
    // The ONE owner + login role both bindings share (per `(tenant, server)`).
    let shared_owner = tenant_owner_role_name(COMPUTE, &shar_ident);
    let shared_login = tenant_role_name(COMPUTE, &shar_ident);
    let b1_db = tenant_db_name(DB1, &shar_ident);
    let b2_db = tenant_db_name(DB2, &shar_ident);

    for db in [&b1_db, &b2_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    provision_tenant(&deploy, &kv, &envelope, &b1, &shar, "")
        .await
        .unwrap_or_else(|e| panic!("provision B1: {e}"));
    provision_tenant(&deploy, &kv, &envelope, &b2, &shar, "")
        .await
        .unwrap_or_else(|e| panic!("provision B2: {e}"));

    // Both derived DBs are owned by the SAME shared owner role (precondition for the guard).
    let (_c, both_owned) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT count(*) FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{shared_owner}' AND d.datname IN ('{b1_db}','{b2_db}')"),
    )
    .await;
    assert_eq!(
        both_owned.trim(),
        "2",
        "precondition: both bindings' dbs are owned by the ONE shared owner role"
    );

    // Seed the LIVE sibling (B2) with its secret + an owner-owned object (what a naive force-clear of
    // the shared owner would DESTROY).
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &b2_db),
        &format!("SET ROLE \"{shared_owner}\"; CREATE TABLE live_secret(v text); INSERT INTO live_secret VALUES ('DO-NOT-CLOBBER'); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed B2 live secret: {o}");

    let declare_b = NodeManagedDbDeclare::new(
        databases_b.clone(),
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::from_config(None, None),
        BackendRegistry::new(),
    );
    // Orphan-drop B1 — the shared roles own B2's LIVE db, so the guard must LEAVE them.
    let drop_b = declare_b
        .drop_orphan_database(&shar, B1)
        .await
        .expect("orphan drop of B1 must succeed (dropping its db, LEAVING the shared roles)");
    assert_eq!(
        drop_b.database, b1_db,
        "B1 orphan drop targets B1's derived db"
    );

    // (B) B1's db is dropped (the orphan binding's own db — always correct).
    let (_c, b1_gone) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{b1_db}'"),
    )
    .await;
    assert!(b1_gone.trim().is_empty(), "B1's derived db must be dropped");

    // (B) HARD GUARD: the SHARED roles are LEFT intact + SURFACED in retained_roles.
    let (_c, shared_roles_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT rolname FROM pg_roles WHERE rolname IN ('{shared_owner}','{shared_login}') ORDER BY 1"),
    )
    .await;
    let mut present: Vec<&str> = shared_roles_after
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    present.sort_unstable();
    assert_eq!(
        present,
        {
            let mut e = vec![shared_login.as_str(), shared_owner.as_str()];
            e.sort_unstable();
            e
        },
        "the HARD GUARD must LEAVE both shared roles intact (a live sibling binding still uses them)"
    );
    let mut retained = drop_b.retained_roles.clone();
    retained.sort();
    let mut expect_retained = vec![shared_login.clone(), shared_owner.clone()];
    expect_retained.sort();
    assert_eq!(
        retained, expect_retained,
        "the drop outcome MUST SURFACE the retained shared roles: got {:?}",
        drop_b.retained_roles
    );

    // (B) MUTATION WITNESS (zero data loss): the LIVE sibling's db + its secret survive UNCHANGED (a
    // naive force-clear of the shared owner would have `DROP OWNED`-destroyed them).
    let (_c, live) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &b2_db),
        "SELECT v FROM live_secret",
    )
    .await;
    assert_eq!(
        live.trim(),
        "DO-NOT-CLOBBER",
        "the live sibling binding's data MUST be preserved (the shared-role guard never force-clears)"
    );

    // cleanup B (now B2 is disposable, its roles no longer shared → drops cleanly).
    let _ = declare_b.drop_orphan_database(&shar, B2).await;
    for db in [&b1_db, &b2_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS \"{shared_owner}\""),
    )
    .await;
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS \"{shared_login}\""),
    )
    .await;

    // ===================================================================================
    // SCENARIO C (SHARED — the PREFIX-COLLISION false positive the loose classifier missed): two
    // co-located bindings on one server share ONE derived role; the LIVE sibling's operator-chosen
    // logical db name is `<orphan-db-name>__old_x` — a PREFIX of the orphan's name plus an aside
    // marker substring. The orphan's derived primary (`shc1_<ident>`) and the sibling's
    // (`shc1__old_x_<ident>`) both sit at the 63-byte cap and share the `shc1` head, so the OLD loose
    // `base.starts_with(pre)` test (AND a bare `bounded_aside_db_name` reconstruction, which at the cap
    // collapses `base[..keep=4]` back onto `shc1`) classify the LIVE sibling as the orphan's own aside
    // → unconditional `DROP DATABASE` → silent clobber of live data + its shared roles. The fix
    // REJECTS it (the recovered suffix carries the sibling's tenant ident + digest — not an all-numeric
    // aside distinguisher), so the sibling SURVIVES and the shared roles are RETAINED. This is the case
    // Scenario B's non-prefix `shd1`/`shd2` pair cannot reach.
    // ===================================================================================
    let shar_c = format!("oor-sharc-{s}");
    const C1: &str = "shc1b"; // orphan binding
    const C2: &str = "shc2b"; // live sibling binding
    const C_DB1: &str = "shc1"; // orphan logical db
    const C_DB2: &str = "shc1__old_x"; // sibling logical db = <orphan db>__old_x (prefix + marker)
    let c1 = mk(C_DB1);
    let c2 = mk(C_DB2);
    let databases_c = BTreeMap::from([(C1.to_string(), c1.clone()), (C2.to_string(), c2.clone())]);
    let shar_c_ident = sanitize_ident(&shar_c);
    let shared_owner_c = tenant_owner_role_name(COMPUTE, &shar_c_ident);
    let shared_login_c = tenant_role_name(COMPUTE, &shar_c_ident);
    let c1_db = tenant_db_name(C_DB1, &shar_c_ident);
    let c2_db = tenant_db_name(C_DB2, &shar_c_ident);

    // Precondition: the derived names really collide the way the loose classifier keyed on — both at
    // the 63-byte cap, sharing the `shc1` head, with the sibling carrying `__old_` right after it.
    assert_eq!(
        c1_db.len(),
        63,
        "orphan derived db must sit AT the 63-byte cap"
    );
    assert_eq!(
        c2_db.len(),
        63,
        "sibling derived db must sit AT the 63-byte cap"
    );
    assert!(
        c1_db.starts_with("shc1") && c2_db.starts_with("shc1") && c2_db.contains("__old_"),
        "fixture precondition: the sibling carries the `__old_` marker over the orphan's shared prefix \
         (c1_db={c1_db}, c2_db={c2_db})"
    );

    for db in [&c1_db, &c2_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    provision_tenant(&deploy, &kv, &envelope, &c1, &shar_c, "")
        .await
        .unwrap_or_else(|e| panic!("provision C1 (orphan): {e}"));
    provision_tenant(&deploy, &kv, &envelope, &c2, &shar_c, "")
        .await
        .unwrap_or_else(|e| panic!("provision C2 (live sibling): {e}"));

    // Both derived DBs are owned by the SAME shared owner role (precondition for the guard, and the
    // reason the orphan drop even enumerates the sibling's db as a role dependency).
    let (_c, c_both_owned) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT count(*) FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{shared_owner_c}' AND d.datname IN ('{c1_db}','{c2_db}')"),
    )
    .await;
    assert_eq!(
        c_both_owned.trim(),
        "2",
        "precondition: both co-located bindings' dbs are owned by the ONE shared owner role"
    );

    // Seed the LIVE sibling (C2) with its secret — an owner-owned object a naive clobber would destroy.
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &c2_db),
        &format!("SET ROLE \"{shared_owner_c}\"; CREATE TABLE live_secret_c(v text); INSERT INTO live_secret_c VALUES ('DO-NOT-CLOBBER-C'); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed C2 live secret: {o}");

    let declare_c = NodeManagedDbDeclare::new(
        databases_c.clone(),
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::from_config(None, None),
        BackendRegistry::new(),
    );
    // Orphan-drop C1 — the shared roles own C2's LIVE db, whose derived name is a PREFIX + marker of
    // C1's. The fixed classifier must NOT mistake it for an aside; the guard must LEAVE the roles.
    let drop_c = declare_c.drop_orphan_database(&shar_c, C1).await.expect(
        "orphan drop of C1 must succeed (dropping ITS db, LEAVING the shared roles + sibling)",
    );
    assert_eq!(
        drop_c.database, c1_db,
        "C1 orphan drop targets C1's derived db"
    );

    // (C) C1's own db is dropped (always correct).
    let (_c, c1_gone) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{c1_db}'"),
    )
    .await;
    assert!(c1_gone.trim().is_empty(), "C1's derived db must be dropped");

    // (C) MUTATION WITNESS — the core of this arm: the LIVE sibling's db SURVIVES. With the OLD loose
    // `is_orphan_aside` (or a bare reconstruction), `is_orphan_aside(c1_db, c2_db)` is TRUE at the cap,
    // so C2's db is `DROP DATABASE`d here → this assertion FAILS (silent data loss caught).
    let (_c, c2_present) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{c2_db}'"),
    )
    .await;
    assert!(
        !c2_present.trim().is_empty(),
        "the LIVE sibling's db (name = orphan-db + `__old_x`) MUST SURVIVE the orphan drop — the \
         prefix-collision false positive this fix closes (without it, it is silently DROPped)"
    );

    // (C) The shared roles are LEFT intact + SURFACED in retained_roles (the HARD GUARD fired).
    let (_c, c_roles_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT rolname FROM pg_roles WHERE rolname IN ('{shared_owner_c}','{shared_login_c}') ORDER BY 1"),
    )
    .await;
    let mut c_present: Vec<&str> = c_roles_after
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    c_present.sort_unstable();
    assert_eq!(
        c_present,
        {
            let mut e = vec![shared_login_c.as_str(), shared_owner_c.as_str()];
            e.sort_unstable();
            e
        },
        "the guard must LEAVE both shared roles intact (the prefix-collision sibling still uses them)"
    );
    let mut c_retained = drop_c.retained_roles.clone();
    c_retained.sort();
    let mut c_expect_retained = vec![shared_login_c.clone(), shared_owner_c.clone()];
    c_expect_retained.sort();
    assert_eq!(
        c_retained, c_expect_retained,
        "the drop outcome MUST SURFACE the retained shared roles: got {:?}",
        drop_c.retained_roles
    );

    // (C) ZERO FOREIGN BYTES + FULLY FUNCTIONAL: the sibling's secret row is intact and the shared
    // owner role can still write + read it end-to-end (the db + its roles are untouched).
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &c2_db),
        &format!("SET ROLE \"{shared_owner_c}\"; INSERT INTO live_secret_c VALUES ('STILL-WORKS-C'); RESET ROLE;"),
    )
    .await;
    assert_eq!(
        c, 0,
        "the surviving sibling must remain fully functional (owner write): {o}"
    );
    let (_c, c_rows) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &c2_db),
        "SELECT v FROM live_secret_c ORDER BY v",
    )
    .await;
    assert_eq!(
        c_rows.trim(),
        "DO-NOT-CLOBBER-C\nSTILL-WORKS-C",
        "the sibling's secret row MUST be intact (zero foreign bytes) and the db fully functional"
    );

    // cleanup C (now the sibling is disposable, its roles no longer shared → drops cleanly).
    let _ = declare_c.drop_orphan_database(&shar_c, C2).await;
    for db in [&c1_db, &c2_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    for role in [&shared_owner_c, &shared_login_c] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP ROLE IF EXISTS \"{role}\""),
        )
        .await;
    }

    println!("PROJECT SYNC ORPHAN DROP OWNING-ROLES OK");
}

/// **Live COLLIDING-ORPHAN reconcile + role-untangle on the EXISTING-dest (fresh_dest=false) re-sync
/// gate** (Tier-2 / nightly — needs a Docker daemon AND real Postgres). The construens re-sync gap the
/// v0.59.4 fresh-dest reconcile did NOT cover: a prior FAILED/crashed sync swap leaves the managed DB
/// orphaned at the derived target name WITH a stray `__old_` aside db its derived roles still OWN; a
/// fresh `project sync` into the SAME identity is an EXISTING-dest incremental mirror
/// (`skip_control_plane_kv = false` ⇒ `fresh_dest = false`), on which the sidecar shadow-restore's
/// fresh-dest reconcile does NOT fire — so the swap lands the restore but LEAVES the orphan's stray
/// aside + its tangled roles (the leak), and a later clean lifecycle (`db drop database`, a tenancy
/// change) hits an un-droppable, object-owning role. This gate reproduces that EXACT shape on real pg
/// and proves, with CONTENT checks:
///
/// A (DISPOSABLE, same-identity re-sync): the orphan at the derived target name is OWNED BY the derived
///    owner role, holds an owner-owned table, AND the derived owner role ALSO owns a stray `__old_`
///    aside db (owner-owned object inside) — the construens tangle a plain `DROP ROLE` would refuse.
///    The existing-dest re-sync RECONCILES the colliding orphan: the restore LANDS (source rows
///    present), the derived roles are REUSED (same-identity re-provision), and the stray aside is
///    CLEARED so the roles own ONLY the restored live db — no leak. MUTATION WITNESS: WITHOUT the fix
///    the sync completes but the stray `__old_` aside + the role tangle SURVIVE (leaked).
///
/// B (SHARED — the HARD GUARD / fail-safe): the orphan's derived roles are SHARED with a LIVE sibling
///    binding on the same server (they own the sibling's live db too). The re-sync reconcile must LEAVE
///    the shared roles AND the orphan's own stray aside fully intact (force-clearing would risk the
///    live sibling's data) — the `shared_with_live` fail-safe. MUTATION WITNESS: the live sibling's db +
///    its secret row survive the re-sync UNCHANGED (zero foreign bytes).
///
/// ≥2 tenants, each a SEPARATE physical db. Emits `PROJECT SYNC COLLIDING ORPHAN RECONCILE ROLES OK`.
#[tokio::test]
async fn project_sync_colliding_orphan_reconcile_roles_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{
        bounded_aside_db_name, sanitize_ident, tenant_db_name, tenant_owner_role_name,
        tenant_role_name,
    };
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (colliding-orphan reconcile gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (colliding-orphan reconcile gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    let s = now_suffix();
    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-corph-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));

    let seal_and_seed = |compute: String| {
        let (kv, deploy, envelope, su_pw, host) = (
            kv.clone(),
            deploy.clone(),
            envelope.clone(),
            su_pw.clone(),
            host.clone(),
        );
        async move {
            let sealed = envelope.wrap(su_pw.as_bytes()).await.expect("seal su pw");
            kv.put(
                &format!("managed-sql-cred/{DEFAULT_PROJECT}/{compute}"),
                sealed,
            )
            .await
            .expect("pre-seal superuser credential");
            deploy
                .set_replica_state(
                    ProjectRef::DEFAULT,
                    &ObservedInstance {
                        handle: InstanceHandle {
                            project: DEFAULT_PROJECT.to_string(),
                            workload: compute.clone(),
                            replica: 0,
                            backend_ref: "test-external-pg".to_string(),
                        },
                        node: 0,
                        backend: "external".to_string(),
                        endpoint: Endpoint {
                            scheme: Scheme::Http,
                            host: host.clone(),
                            port,
                        },
                        region: None,
                        healthy: true,
                        started_at: None,
                        phase: ReplicaPhase::Running,
                        readiness: Readiness::Provisioned,
                        data_dir: None,
                        snapshot: None,
                        active_spec: None,
                    },
                )
                .await
                .expect("seed healthy replica");
        }
    };
    seal_and_seed(COMPUTE.to_string()).await;

    // ===== SCENARIO A (DISPOSABLE, same-identity existing-dest re-sync) =====
    const A_BINDING: &str = "corphapp";
    const A_DB: &str = "corph";
    let src = format!("corph-src-{s}");
    let dest = format!("corph-dest-{s}");

    let binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(A_DB.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(A_BINDING.to_string(), binding.clone())]);
    let db_name = |p: &str| tenant_db_name(A_DB, &sanitize_ident(p));
    let src_db = db_name(&src);
    let dest_db = db_name(&dest);
    let owner_role = tenant_owner_role_name(COMPUTE, &sanitize_ident(&dest));
    let login_role = tenant_role_name(COMPUTE, &sanitize_ident(&dest));
    // A genuine transient swap-aside of the dest's derived name (the junk a prior FAILED/crashed swap
    // leaves): `<dest-db>__old_<nanos>_<pid>` — classified as this orphan's OWN disposable aside.
    let stray_aside = bounded_aside_db_name(&dest_db, "__old_", &format!("{s}1_7"));

    for db in [&src_db, &dest_db, &stray_aside] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }

    for p in [&src, &dest] {
        provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
            .await
            .unwrap_or_else(|e| panic!("provision {p}: {e}"));
    }

    // Seed: SOURCE rows.
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &src_db),
        "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES ('A','src-a'),('B','src-b');",
    )
    .await;
    assert_eq!(c, 0, "seed src: {o}");

    // The orphan at the derived target name: a table OWNED BY the derived owner role (so DROP ROLE
    // would be refused until the objects are handled), + a stray `__old_` aside the SAME owner role
    // owns (an owner-owned object inside it) — the construens tangle a prior failed sync left behind.
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &dest_db),
        &format!("SET ROLE \"{owner_role}\"; CREATE TABLE owned_live(i int); INSERT INTO owned_live VALUES (1); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed orphan owner-owned live table: {o}");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE \"{stray_aside}\" OWNER \"{owner_role}\""),
    )
    .await;
    assert_eq!(c, 0, "create owner-owned stray aside: {o}");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &stray_aside),
        &format!("SET ROLE \"{owner_role}\"; CREATE TABLE owned_in_aside(i int); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed stray aside owner object: {o}");

    // Precondition (the tangle EXISTS): the owner role owns BOTH the live dest db AND the stray aside.
    let (_c, owns_pre) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT count(*) FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{owner_role}' AND d.datname IN ('{dest_db}','{stray_aside}')"),
    )
    .await;
    assert_eq!(
        owns_pre.trim(),
        "2",
        "precondition: the derived owner role must own BOTH the live orphan db AND the stray `__old_` aside (the construens tangle)"
    );

    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-corph-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-corph-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases.clone(), deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false)
        .with_trusted_extensions(vec![]);

    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    driver
        .export(
            &src,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut sink,
        )
        .await
        .expect("export source tenant");
    let bundle = sink.into_inner();

    // THE RE-SYNC: an EXISTING-dest incremental mirror (`skip_control_plane_kv = false` ⇒
    // fresh_dest = false) — the path construens's re-sync took (NOT the explicit `--orphan`).
    let mut body = futures::io::Cursor::new(bundle.clone());
    driver
        .import(
            &dest,
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                skip_control_plane_kv: false,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "existing-dest re-sync into a colliding orphan MUST LAND (reconcile + restore): {e}"
            )
        });

    // (A1) The restore LANDED: the SOURCE rows are present + correct on the live dest db.
    let live = conn(&superuser, &su_pw, &host, port, &dest_db);
    let (_c, got) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT tid || ':' || v FROM marker ORDER BY tid",
    )
    .await;
    assert_eq!(
        got, "A:src-a\nB:src-b",
        "the existing-dest re-sync must land the SOURCE rows in the live dest db (end-to-end on real pg)"
    );

    // (A2) MUTATION WITNESS: the stray `__old_` aside is CLEARED — WITHOUT the fix the fresh-dest
    // reconcile does not fire on this path, so the aside + the role tangle SURVIVE (leaked).
    let (_c, aside_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{stray_aside}'"),
    )
    .await;
    assert!(
        aside_after.trim().is_empty(),
        "the orphan's stray `__old_` aside db MUST be cleared by the re-sync reconcile (WITHOUT the \
         fix it LEAKS — the role-tangle construens hit): still present"
    );

    // (A3) The derived roles are REUSED (same-identity re-provision), and now own ONLY the restored
    // live db — the tangle is gone (no stray aside left for them to own).
    let (_c, owns_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{owner_role}' ORDER BY 1"),
    )
    .await;
    let owned: Vec<&str> = owns_after
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        owned,
        vec![dest_db.as_str()],
        "after the reconcile the derived owner role must own ONLY the restored live db (the stray \
         aside is gone, the tangle cleared): owns {owned:?}"
    );
    let (_c, roles_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT count(*) FROM pg_roles WHERE rolname IN ('{owner_role}','{login_role}')"),
    )
    .await;
    assert_eq!(
        roles_after.trim(),
        "2",
        "the derived owner + login roles are REUSED by the same-identity re-provision (still present)"
    );

    for db in [&src_db, &dest_db, &stray_aside] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }

    // ===== SCENARIO B (SHARED — the HARD GUARD / fail-safe) =====
    // Two bindings on the SAME server share ONE derived owner/login role (per `(tenant, server)`); one
    // binding LIVE. The re-sync reconcile of the OTHER must LEAVE the shared roles AND the orphan's own
    // stray aside intact (force-clearing would risk the live sibling) — zero foreign bytes.
    let shar = format!("corph-shar-{s}");
    let shar_src = format!("corph-sharsrc-{s}");
    const B1: &str = "cshb1";
    const B2: &str = "cshb2";
    const DB1: &str = "cshd1";
    const DB2: &str = "cshd2";
    let mk = |database: &str| ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(database.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let b1 = mk(DB1);
    let b2 = mk(DB2);
    let shar_ident = sanitize_ident(&shar);
    let shared_owner = tenant_owner_role_name(COMPUTE, &shar_ident);
    let shared_login = tenant_role_name(COMPUTE, &shar_ident);
    let b1_db = tenant_db_name(DB1, &shar_ident);
    let b2_db = tenant_db_name(DB2, &shar_ident);
    let b1_stray = bounded_aside_db_name(&b1_db, "__old_", &format!("{s}2_9"));
    // Source for re-syncing B1 (same binding name so the member resolves to B1 on import).
    let shar_src_ident = sanitize_ident(&shar_src);
    let b1_src_db = tenant_db_name(DB1, &shar_src_ident);

    for db in [&b1_db, &b2_db, &b1_stray, &b1_src_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    // Provision the two bindings on `shar` (shared roles own both dbs) + the source's B1.
    provision_tenant(&deploy, &kv, &envelope, &b1, &shar, "")
        .await
        .unwrap_or_else(|e| panic!("provision B1: {e}"));
    provision_tenant(&deploy, &kv, &envelope, &b2, &shar, "")
        .await
        .unwrap_or_else(|e| panic!("provision B2: {e}"));
    provision_tenant(&deploy, &kv, &envelope, &b1, &shar_src, "")
        .await
        .unwrap_or_else(|e| panic!("provision B1 source: {e}"));

    // Seed the LIVE sibling (B2) with its secret + an owner-owned object (what a naive force-clear of
    // the shared owner would destroy).
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &b2_db),
        &format!("SET ROLE \"{shared_owner}\"; CREATE TABLE live_secret(v text); INSERT INTO live_secret VALUES ('DO-NOT-CLOBBER'); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed B2 live secret: {o}");
    // Seed the source B1 rows + a stray `__old_` aside of B1 the SHARED owner owns (the tangle).
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &b1_src_db),
        "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES ('A','b1-a');",
    )
    .await;
    assert_eq!(c, 0, "seed B1 source: {o}");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE \"{b1_stray}\" OWNER \"{shared_owner}\""),
    )
    .await;
    assert_eq!(c, 0, "create B1 stray aside owned by the shared owner: {o}");

    // SOURCE export driver: ONLY binding B1 (so exporting `shar_src` dumps just B1, not an
    // unprovisioned B2).
    let databases_src = BTreeMap::from([(B1.to_string(), b1.clone())]);
    let op_src_b: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases_src.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work_src_b = std::env::temp_dir().join(format!("boatramp-corph-bsrc-work-{s}"));
    std::fs::create_dir_all(&work_src_b).unwrap();
    let blobs_src_b: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-corph-bsrc-blobs-{s}")),
    ));
    let src_driver_b = NodeProjectExport::new(
        databases_src.clone(),
        deploy.clone(),
        kv.clone(),
        blobs_src_b,
        work_src_b,
    )
    .with_managed_pg(backend.clone(), envelope.clone(), op_src_b, false)
    .with_trusted_extensions(vec![]);

    // The re-sync (import) driver for `shar` (binding map carries B1; B2 is live in pg).
    let databases_b = BTreeMap::from([(B1.to_string(), b1.clone()), (B2.to_string(), b2.clone())]);
    let op_b: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases_b.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work_b = std::env::temp_dir().join(format!("boatramp-corph-b-work-{s}"));
    std::fs::create_dir_all(&work_b).unwrap();
    let blobs_b: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-corph-b-blobs-{s}")),
    ));
    let driver_b = NodeProjectExport::new(
        databases_b.clone(),
        deploy.clone(),
        kv.clone(),
        blobs_b,
        work_b,
    )
    .with_managed_pg(backend.clone(), envelope.clone(), op_b, false)
    .with_trusted_extensions(vec![]);

    // Export B1 from the source project, import into `shar` (existing-dest re-sync of B1).
    let mut sink_b = futures::io::Cursor::new(Vec::<u8>::new());
    src_driver_b
        .export(
            &shar_src,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut sink_b,
        )
        .await
        .expect("export B1 source");
    let bundle_b = sink_b.into_inner();
    let mut body_b = futures::io::Cursor::new(bundle_b.clone());
    driver_b
        .import(
            &shar,
            &mut body_b,
            ImportOptions {
                apply: true,
                overwrite: true,
                skip_control_plane_kv: false,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("re-sync of B1 (shared-role tenant) MUST LAND: {e}"));

    // (B1) The LIVE sibling's db + its secret survive the re-sync UNCHANGED (zero foreign bytes).
    let (_c, live_secret) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &b2_db),
        "SELECT v FROM live_secret",
    )
    .await;
    assert_eq!(
        live_secret.trim(),
        "DO-NOT-CLOBBER",
        "the live sibling binding's data MUST be preserved across the re-sync (the shared-role \
         fail-safe never force-clears)"
    );
    // (B2) The shared roles survive intact (a live sibling still uses them).
    let (_c, shared_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!(
            "SELECT count(*) FROM pg_roles WHERE rolname IN ('{shared_owner}','{shared_login}')"
        ),
    )
    .await;
    assert_eq!(
        shared_after.trim(),
        "2",
        "the shared owner + login roles MUST be LEFT intact (shared with a live sibling)"
    );
    // (B3) The fail-safe LEFT the orphan's own stray aside too (the guard aborts the untangle when a
    // role is shared with a live sibling — it never force-touches anything).
    let (_c, b1_stray_after) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("SELECT 1 FROM pg_database WHERE datname='{b1_stray}'"),
    )
    .await;
    assert_eq!(
        b1_stray_after.trim(),
        "1",
        "the shared-with-live fail-safe must LEAVE even the orphan's own stray aside intact (never \
         force-clear a role entangled with a live sibling)"
    );

    // cleanup B
    for db in [&b1_db, &b2_db, &b1_stray, &b1_src_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    for r in [&shared_owner, &shared_login, &owner_role, &login_role] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP ROLE IF EXISTS \"{r}\""),
        )
        .await;
    }

    println!("PROJECT SYNC COLLIDING ORPHAN RECONCILE ROLES OK");
}

/// Build a Shared-Postgres managed binding for the self-heal tangle gate (a project-scoped tenant,
/// `rls_session`, per-tenant owner + login roles) — the construens cell the self-heal targets.
fn mk_shared_binding(
    superuser: &str,
    compute: &str,
    database: &str,
) -> boatramp_node::config::ExternalDatabaseConfig {
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(compute.into()),
        database: Some(database.into()),
        user: Some(superuser.to_string()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// **Live SELF-HEAL of a prior-failed managed-DB sync TANGLE** (v0.59.7 — Tier-2 / nightly; needs a
/// Docker daemon AND real Postgres). The construens requirement: `project sync --apply` must FULLY
/// SELF-HEAL from any prior-failed Shared-Postgres managed-DB sync state with ZERO operator
/// intervention — no `db drop --orphan`, no manual SQL. This gate reproduces construens's EXACT
/// live-queried tangle on real pg16 and proves the sidecar restore self-heals it end-to-end:
///
/// THE TANGLE (seeded exactly): a Shared non-default tenant whose prior sync failed, leaving
///   - the orphan DB at the derived target name, AT the 63-byte pg cap, OWNED BY the derived OWNER
///     role (with an owner-owned AND a login-owned table inside);
///   - a `__deleted_` grace TOMBSTONE whose name is the orphan name TRUNCATED to fit 63 bytes then
///     `__deleted_<ts>` appended (a `bounded_aside_db_name` cap-collapse output), OWNED BY the OWNER
///     role, carrying grace-recoverable data + an owner-owned AND a login-owned table;
///   - TWO derived roles: the OWNER owns BOTH databases (orphan + tombstone); the LOGIN owns NO
///     database (`datdba` null) but owns NON-DB objects (tables) inside both.
///
/// A (DEFAULT — preserve the tombstone): `project sync --apply` (no flag) self-heals with ZERO manual
///    steps — the restore LANDS (source rows present), BOTH derived roles are DROPPED + reprovisioned
///    FRESH (new OIDs), the orphan is reconciled, AND the `__deleted_` tombstone SURVIVES, REASSIGNED
///    to the stable superuser with its grace data intact. MUTATION WITNESS: on current main the sync
///    completes but the roles are REUSED (OIDs unchanged) and the tombstone stays OWNED BY the derived
///    owner (never reassigned) — the tangle survives.
///
/// B (EXPLICIT FLAG — destroy the tombstone): the SAME tangle + `--drop-soft-deleted`
///    (`drop_soft_deleted = true`) additionally DROPS the `__deleted_` tombstone; the rest self-heals
///    identically. The operator's deliberate opt-in to destroy soft-deleted data.
///
/// C (HEALTHY NO-OP — the heal is gated on broken state only): a CLEAN tenant re-sync (no stray
///    ownership) drops/rotates NOTHING — the derived roles are REUSED (OIDs UNCHANGED), no tombstone
///    is created, and the restore lands. MUTATION WITNESS: if the heal fired on a clean sync the role
///    OIDs would change (credential churn) — they must not.
///
/// D (FAIL-SAFE — never clobber a live sibling): the orphan's derived roles are SHARED with a LIVE
///    sibling binding on the same server. The heal LEAVES the shared roles (OIDs UNCHANGED), their
///    tombstone, and the live sibling's data fully intact (zero foreign bytes) — the `shared_with_live`
///    HARD GUARD. MUTATION WITNESS: a naive force-heal would DROP the shared roles / clobber the live
///    sibling's secret.
///
/// ≥2 tenants, each a SEPARATE physical db. Emits `PROJECT SYNC SELF-HEAL TANGLE OK`.
#[tokio::test]
async fn project_sync_self_heal_tangle_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::ExternalDatabaseConfig;
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{
        bounded_aside_db_name, sanitize_ident, tenant_db_name, tenant_owner_role_name,
        tenant_role_name,
    };
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (self-heal tangle gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (self-heal tangle gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const BASE: &str = "shd";
    let s = now_suffix();
    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-shself-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([11u8; 32]));

    // Seal the superuser credential + seed a healthy replica so the node's resolver reaches the DSN.
    let sealed = envelope.wrap(su_pw.as_bytes()).await.expect("seal su pw");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed,
    )
    .await
    .expect("pre-seal superuser credential");
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-pg".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed healthy replica");

    // A one-cell scalar probe on the maintenance connection (owned clones ⇒ reusable `Fn`).
    let scalar = {
        let (b, c, i) = (backend.clone(), maint.clone(), image.clone());
        move |sql: String| {
            let (b, c, i) = (b.clone(), c.clone(), i.clone());
            async move {
                let (_code, out) = psql(b.as_ref(), &i, &c, &sql).await;
                out.trim().to_string()
            }
        }
    };
    let role_oid = |role: &str| scalar(format!("SELECT oid FROM pg_roles WHERE rolname='{role}'"));
    let db_owner = |db: &str| {
        scalar(format!(
            "SELECT r.rolname FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname='{db}'"
        ))
    };
    let db_exists = |db: &str| scalar(format!("SELECT 1 FROM pg_database WHERE datname='{db}'"));

    // Seed the EXACT tangle into an ALREADY-PROVISIONED dest tenant (roles + live db exist): orphan
    // objects (owner-owned + login-owned table), a truncated-name `__deleted_` tombstone owned by the
    // owner, carrying grace data + an owner-owned + a login-owned table. Returns the derived names.
    let seed_tangle = {
        let (b, i, su, supw, host, maint) = (
            backend.clone(),
            image.clone(),
            superuser.clone(),
            su_pw.clone(),
            host.clone(),
            maint.clone(),
        );
        move |dest: String, ts: u64| {
            let (b, i, su, supw, host, maint) = (
                b.clone(),
                i.clone(),
                su.clone(),
                supw.clone(),
                host.clone(),
                maint.clone(),
            );
            async move {
                let ident = sanitize_ident(&dest);
                let dest_db = tenant_db_name(BASE, &ident);
                assert_eq!(
                    dest_db.len(),
                    63,
                    "the derived orphan db must sit AT the 63-byte pg cap to exercise the tombstone \
                     cap-collapse (gap #2) — got {} bytes: {dest_db}",
                    dest_db.len()
                );
                let owner_role = tenant_owner_role_name(COMPUTE, &ident);
                let login_role = tenant_role_name(COMPUTE, &ident);
                let tombstone = bounded_aside_db_name(&dest_db, "__deleted_", &ts.to_string());
                assert!(
                    tombstone.len() <= 63 && tombstone.ends_with(&format!("__deleted_{ts}")),
                    "tombstone must be a cap-bounded `__deleted_` aside: {tombstone}"
                );
                // Orphan D: owner-owned + login-owned table (login owns NON-DB objects inside D).
                let destc = conn(&su, &supw, &host, port, &dest_db);
                let (c, o) = psql(
                    b.as_ref(),
                    &i,
                    &destc,
                    &format!(
                        "SET ROLE \"{owner_role}\"; CREATE TABLE owned_live(i int); INSERT INTO owned_live VALUES(1); RESET ROLE; \
                         GRANT CREATE ON SCHEMA public TO \"{login_role}\"; \
                         SET ROLE \"{login_role}\"; CREATE TABLE login_live(i int); RESET ROLE;"
                    ),
                )
                .await;
                assert_eq!(c, 0, "seed orphan objects: {o}");
                // Tombstone T: owner-owned db with grace data + an owner-owned + a login-owned table.
                let _ = psql(
                    b.as_ref(),
                    &i,
                    &maint,
                    &format!("DROP DATABASE IF EXISTS \"{tombstone}\""),
                )
                .await;
                let (c, o) = psql(
                    b.as_ref(),
                    &i,
                    &maint,
                    &format!("CREATE DATABASE \"{tombstone}\" OWNER \"{owner_role}\""),
                )
                .await;
                assert_eq!(c, 0, "create tombstone db: {o}");
                let tombc = conn(&su, &supw, &host, port, &tombstone);
                let (c, o) = psql(
                    b.as_ref(),
                    &i,
                    &tombc,
                    &format!(
                        "GRANT CREATE ON SCHEMA public TO \"{owner_role}\", \"{login_role}\"; \
                         SET ROLE \"{owner_role}\"; \
                         CREATE TABLE grace(v text); INSERT INTO grace VALUES('GRACE-RECOVERABLE'); \
                         CREATE TABLE owned_in_tomb(i int); RESET ROLE; \
                         SET ROLE \"{login_role}\"; CREATE TABLE login_in_tomb(i int); RESET ROLE;"
                    ),
                )
                .await;
                assert_eq!(c, 0, "seed tombstone objects: {o}");
                (dest_db, tombstone, owner_role, login_role)
            }
        }
    };

    // Build a sync driver for a given databases map + tag (clones the shared node state per call).
    let make_driver = {
        let (kv, deploy, envelope, backend) = (
            kv.clone(),
            deploy.clone(),
            envelope.clone(),
            backend.clone(),
        );
        move |databases: BTreeMap<String, ExternalDatabaseConfig>, tag: &'static str| {
            let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
                databases.clone(),
                kv.clone(),
                Some(envelope.clone()),
                deploy.clone(),
            ));
            let work = std::env::temp_dir().join(format!("boatramp-shself-{tag}-work-{s}"));
            std::fs::create_dir_all(&work).unwrap();
            let blobs: Arc<dyn boatramp_core::Storage> =
                Arc::new(boatramp_storage::FsStorage::new(
                    std::env::temp_dir().join(format!("boatramp-shself-{tag}-blobs-{s}")),
                ));
            NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
                .with_managed_pg(backend.clone(), envelope.clone(), op, false)
                .with_trusted_extensions(vec![])
        }
    };

    let export_opts = || ExportOptions {
        scope: BundleScope::DataPlane,
        managed_restore: ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    let import_opts = |drop_soft_deleted: bool| ImportOptions {
        apply: true,
        overwrite: true,
        skip_control_plane_kv: false,
        expected_managed_restore: Some(ManagedRestore::ShadowSwap),
        drop_soft_deleted,
        ..Default::default()
    };

    // =====================================================================================
    // SCENARIO A (DEFAULT — the construens tangle, preserve the tombstone)
    // =====================================================================================
    {
        const BINDING: &str = "shselfa";
        let src = format!("shself-src-a-{s}");
        let dest = format!("shself-dest-a-aaaaaaaaaaaaaaaaaaaa-{s}");
        let binding = mk_shared_binding(&superuser, COMPUTE, BASE);
        let databases = BTreeMap::from([(BINDING.to_string(), binding.clone())]);
        let src_db = tenant_db_name(BASE, &sanitize_ident(&src));

        for p in [&src, &dest] {
            provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
                .await
                .unwrap_or_else(|e| panic!("provision {p}: {e}"));
        }
        let (dest_db, tombstone, owner_role, login_role) =
            seed_tangle(dest.clone(), 1_794_321_365 + (s % 1_000_000)).await;
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &src_db),
            "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES('A','src-a'),('B','src-b');",
        )
        .await;
        assert_eq!(c, 0, "seed src: {o}");

        // Precondition: the tangle EXISTS. Owner owns BOTH orphan + tombstone; login owns NO db but
        // owns non-DB objects inside the orphan.
        let owns_dbs = scalar(format!(
            "SELECT count(*) FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{owner_role}' AND d.datname IN ('{dest_db}','{tombstone}')"
        ))
        .await;
        assert_eq!(
            owns_dbs, "2",
            "precondition: owner must own BOTH orphan + tombstone"
        );
        let login_owns_db = scalar(format!(
            "SELECT count(*) FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='{login_role}')"
        ))
        .await;
        assert_eq!(login_owns_db, "0", "precondition: login owns NO database");
        let (_c, login_objs) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &dest_db),
            &format!("SELECT count(*) FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname='{login_role}') AND relkind='r'"),
        )
        .await;
        assert_ne!(
            login_objs.trim(),
            "0",
            "precondition: login owns non-DB objects inside the orphan"
        );

        let owner_oid_before = role_oid(&owner_role).await;
        let login_oid_before = role_oid(&login_role).await;
        assert!(!owner_oid_before.is_empty() && !login_oid_before.is_empty());

        // THE SELF-HEAL SYNC — existing-dest re-sync (skip_control_plane_kv=false ⇒ fresh_dest=false),
        // the path construens's re-sync took. NO flag (default preserve).
        let driver = make_driver(databases.clone(), "a");
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(&src, &export_opts(), &mut sink)
            .await
            .expect("export source");
        let bundle = sink.into_inner();
        let mut body = futures::io::Cursor::new(bundle.clone());
        driver
            .import(&dest, &mut body, import_opts(false))
            .await
            .unwrap_or_else(|e| panic!("self-heal sync into the construens tangle MUST LAND: {e}"));

        // (A1) restore LANDED: source rows present on the live dest.
        let (_c, got) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &dest_db),
            "SELECT tid||':'||v FROM marker ORDER BY tid",
        )
        .await;
        assert_eq!(
            got, "A:src-a\nB:src-b",
            "the self-heal restore must land the SOURCE rows"
        );

        // (A2) MUTATION WITNESS — the tombstone SURVIVES, REASSIGNED to the stable superuser.
        assert_eq!(
            db_exists(&tombstone).await,
            "1",
            "the `__deleted_` tombstone must SURVIVE (default preserve)"
        );
        assert_eq!(
            db_owner(&tombstone).await,
            superuser,
            "MUTATION WITNESS: the tombstone must be REASSIGNED to the stable superuser (on main it \
             stays owned by the derived owner — the tangle survives)"
        );
        // (A3) the tombstone's grace data is intact.
        let (_c, grace) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &tombstone),
            "SELECT v FROM grace",
        )
        .await;
        assert_eq!(
            grace.trim(),
            "GRACE-RECOVERABLE",
            "the tombstone's grace data must survive intact"
        );

        // (A4) MUTATION WITNESS — BOTH derived roles DROPPED + reprovisioned FRESH (new OIDs).
        let owner_oid_after = role_oid(&owner_role).await;
        let login_oid_after = role_oid(&login_role).await;
        assert!(
            !owner_oid_after.is_empty() && !login_oid_after.is_empty(),
            "roles must be reprovisioned (present)"
        );
        assert_ne!(
            owner_oid_after, owner_oid_before,
            "MUTATION WITNESS: the OWNER role must be DROPPED + reprovisioned FRESH (new OID); on main \
             it is reused (OID unchanged)"
        );
        assert_ne!(
            login_oid_after, login_oid_before,
            "MUTATION WITNESS: the LOGIN role must be DROPPED + reprovisioned FRESH (new OID); on main \
             it is reused (OID unchanged)"
        );

        // (A5) the fresh owner owns ONLY the restored live db (not the tombstone anymore).
        let owns_after = scalar(format!(
            "SELECT coalesce(string_agg(d.datname,',' ORDER BY d.datname),'') FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname='{owner_role}'"
        ))
        .await;
        assert_eq!(
            owns_after, dest_db,
            "after the heal the fresh owner must own ONLY the restored live db"
        );

        for db in [&src_db, &dest_db, &tombstone] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP DATABASE IF EXISTS \"{db}\""),
            )
            .await;
        }
        for r in [&owner_role, &login_role] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP ROLE IF EXISTS \"{r}\""),
            )
            .await;
        }
    }

    // =====================================================================================
    // SCENARIO B (EXPLICIT FLAG — same tangle + `--drop-soft-deleted`: destroy the tombstone)
    // =====================================================================================
    {
        const BINDING: &str = "shselfb";
        let src = format!("shself-src-b-{s}");
        let dest = format!("shself-dest-b-bbbbbbbbbbbbbbbbbbbb-{s}");
        let binding = mk_shared_binding(&superuser, COMPUTE, BASE);
        let databases = BTreeMap::from([(BINDING.to_string(), binding.clone())]);
        let src_db = tenant_db_name(BASE, &sanitize_ident(&src));

        for p in [&src, &dest] {
            provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
                .await
                .unwrap_or_else(|e| panic!("provision {p}: {e}"));
        }
        let (dest_db, tombstone, owner_role, login_role) =
            seed_tangle(dest.clone(), 1_794_000_001 + (s % 1_000_000)).await;
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &src_db),
            "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES('A','src-b-a');",
        )
        .await;
        assert_eq!(c, 0, "seed src b: {o}");
        let owner_oid_before = role_oid(&owner_role).await;

        let driver = make_driver(databases.clone(), "b");
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(&src, &export_opts(), &mut sink)
            .await
            .expect("export b");
        let bundle = sink.into_inner();
        let mut body = futures::io::Cursor::new(bundle.clone());
        driver
            .import(&dest, &mut body, import_opts(true)) // --drop-soft-deleted
            .await
            .unwrap_or_else(|e| panic!("self-heal sync (drop-soft-deleted) MUST LAND: {e}"));

        let (_c, got) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &dest_db),
            "SELECT tid||':'||v FROM marker ORDER BY tid",
        )
        .await;
        assert_eq!(
            got, "A:src-b-a",
            "the drop-soft-deleted heal must land the source rows"
        );
        // MUTATION WITNESS: with the flag the tombstone is DROPPED.
        assert_eq!(
            db_exists(&tombstone).await,
            "",
            "with `--drop-soft-deleted` the `__deleted_` tombstone must be DROPPED"
        );
        assert_ne!(
            role_oid(&owner_role).await,
            owner_oid_before,
            "flag path: owner role still reprovisioned fresh"
        );

        for db in [&src_db, &dest_db, &tombstone] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP DATABASE IF EXISTS \"{db}\""),
            )
            .await;
        }
        for r in [&owner_role, &login_role] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP ROLE IF EXISTS \"{r}\""),
            )
            .await;
        }
    }

    // =====================================================================================
    // SCENARIO C (HEALTHY NO-OP — a clean re-sync drops/rotates NOTHING)
    // =====================================================================================
    {
        const BINDING: &str = "shselfc";
        let src = format!("shself-src-c-{s}");
        let dest = format!("shself-dest-c-cccccccccccccccccccc-{s}");
        let binding = mk_shared_binding(&superuser, COMPUTE, BASE);
        let databases = BTreeMap::from([(BINDING.to_string(), binding.clone())]);
        let src_db = tenant_db_name(BASE, &sanitize_ident(&src));
        let ident = sanitize_ident(&dest);
        let dest_db = tenant_db_name(BASE, &ident);
        let owner_role = tenant_owner_role_name(COMPUTE, &ident);
        let login_role = tenant_role_name(COMPUTE, &ident);

        for p in [&src, &dest] {
            provision_tenant(&deploy, &kv, &envelope, &binding, p, "")
                .await
                .unwrap_or_else(|e| panic!("provision {p}: {e}"));
        }
        // dest carries live data, NO stray ownership (a healthy tenant).
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &dest_db),
            &format!("SET ROLE \"{owner_role}\"; CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES('X','old'); RESET ROLE;"),
        )
        .await;
        assert_eq!(c, 0, "seed clean dest: {o}");
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &src_db),
            "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES('X','new');",
        )
        .await;
        assert_eq!(c, 0, "seed clean src: {o}");

        let owner_oid_before = role_oid(&owner_role).await;
        let login_oid_before = role_oid(&login_role).await;

        let driver = make_driver(databases.clone(), "c");
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(&src, &export_opts(), &mut sink)
            .await
            .expect("export c");
        let bundle = sink.into_inner();
        let mut body = futures::io::Cursor::new(bundle.clone());
        driver
            .import(&dest, &mut body, import_opts(false))
            .await
            .unwrap_or_else(|e| panic!("clean re-sync MUST LAND: {e}"));

        let (_c, got) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &dest_db),
            "SELECT v FROM marker ORDER BY tid",
        )
        .await;
        assert_eq!(
            got.trim(),
            "new",
            "the clean re-sync must land the source rows"
        );
        // MUTATION WITNESS (gating): roles REUSED — OIDs UNCHANGED, no heal, no churn.
        assert_eq!(
            role_oid(&owner_role).await,
            owner_oid_before,
            "HEALTHY NO-OP: a clean re-sync must REUSE the owner role (OID unchanged — no drop/churn)"
        );
        assert_eq!(
            role_oid(&login_role).await,
            login_oid_before,
            "HEALTHY NO-OP: a clean re-sync must REUSE the login role (OID unchanged — no drop/churn)"
        );
        // No tombstone was conjured by a clean re-sync.
        let tomb_like = scalar(format!(
            "SELECT count(*) FROM pg_database WHERE datname LIKE '{prefix}%__deleted_%'",
            prefix = &dest_db[..dest_db.len().min(40)]
        ))
        .await;
        assert_eq!(
            tomb_like, "0",
            "a clean re-sync must not conjure a `__deleted_` tombstone"
        );

        for db in [&src_db, &dest_db] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP DATABASE IF EXISTS \"{db}\""),
            )
            .await;
        }
        for r in [&owner_role, &login_role] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP ROLE IF EXISTS \"{r}\""),
            )
            .await;
        }
    }

    // =====================================================================================
    // SCENARIO D (FAIL-SAFE — shared-with-live: never clobber a live sibling)
    // =====================================================================================
    {
        let shar = format!("shself-shar-d-dddddddddddddddddddd-{s}");
        let shar_src = format!("shself-sharsrc-d-{s}");
        const D1: &str = "shselfd1";
        const D2: &str = "shselfd2";
        const DB1: &str = "shdd1";
        const DB2: &str = "shdd2";
        let d1 = mk_shared_binding(&superuser, COMPUTE, DB1);
        let d2 = mk_shared_binding(&superuser, COMPUTE, DB2);
        let shar_ident = sanitize_ident(&shar);
        let shared_owner = tenant_owner_role_name(COMPUTE, &shar_ident);
        let shared_login = tenant_role_name(COMPUTE, &shar_ident);
        let d1_db = tenant_db_name(DB1, &shar_ident);
        let d2_db = tenant_db_name(DB2, &shar_ident);
        let d1_tomb = bounded_aside_db_name(
            &d1_db,
            "__deleted_",
            &format!("{}", 1_793_000_001 + (s % 1_000_000)),
        );
        let d1_src_db = tenant_db_name(DB1, &sanitize_ident(&shar_src));

        provision_tenant(&deploy, &kv, &envelope, &d1, &shar, "")
            .await
            .unwrap_or_else(|e| panic!("provision D1: {e}"));
        provision_tenant(&deploy, &kv, &envelope, &d2, &shar, "")
            .await
            .unwrap_or_else(|e| panic!("provision D2: {e}"));
        provision_tenant(&deploy, &kv, &envelope, &d1, &shar_src, "")
            .await
            .unwrap_or_else(|e| panic!("provision D1 src: {e}"));

        // Live sibling D2: a secret the shared owner owns (what a naive force-heal would destroy).
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &d2_db),
            &format!("SET ROLE \"{shared_owner}\"; CREATE TABLE live_secret(v text); INSERT INTO live_secret VALUES('DO-NOT-CLOBBER'); RESET ROLE;"),
        )
        .await;
        assert_eq!(c, 0, "seed D2 live secret: {o}");
        // Source D1 rows + a `__deleted_` tombstone of D1 the SHARED owner owns (the tangle).
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &d1_src_db),
            "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES('A','d1-a');",
        )
        .await;
        assert_eq!(c, 0, "seed D1 src: {o}");
        let (c, o) = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("CREATE DATABASE \"{d1_tomb}\" OWNER \"{shared_owner}\""),
        )
        .await;
        assert_eq!(c, 0, "create D1 tombstone owned by the shared owner: {o}");

        let shared_owner_oid_before = role_oid(&shared_owner).await;

        let src_driver = make_driver(BTreeMap::from([(D1.to_string(), d1.clone())]), "dsrc");
        let driver = make_driver(
            BTreeMap::from([(D1.to_string(), d1.clone()), (D2.to_string(), d2.clone())]),
            "d",
        );

        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        src_driver
            .export(&shar_src, &export_opts(), &mut sink)
            .await
            .expect("export D1 src");
        let bundle = sink.into_inner();
        let mut body = futures::io::Cursor::new(bundle.clone());
        driver
            .import(&shar, &mut body, import_opts(false))
            .await
            .unwrap_or_else(|e| panic!("re-sync of D1 (shared-role tenant) MUST LAND: {e}"));

        // (D1) the live sibling's data survives UNCHANGED (zero foreign bytes).
        let (_c, live_secret) = psql(
            backend.as_ref(),
            &image,
            &conn(&superuser, &su_pw, &host, port, &d2_db),
            "SELECT v FROM live_secret",
        )
        .await;
        assert_eq!(
            live_secret.trim(),
            "DO-NOT-CLOBBER",
            "the live sibling's data MUST be preserved (fail-safe)"
        );
        // (D2) the shared roles are LEFT intact — OIDs UNCHANGED (never force-dropped).
        assert_eq!(
            role_oid(&shared_owner).await,
            shared_owner_oid_before,
            "the shared owner role MUST be LEFT intact (OID unchanged) — a live sibling still uses it"
        );
        assert!(
            !role_oid(&shared_login).await.is_empty(),
            "the shared login role must remain present"
        );
        // (D3) the fail-safe LEFT the orphan's own tombstone too (never force-touched).
        assert_eq!(
            db_exists(&d1_tomb).await,
            "1",
            "the shared-with-live fail-safe must LEAVE the tombstone intact"
        );

        for db in [&d1_db, &d2_db, &d1_tomb, &d1_src_db] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP DATABASE IF EXISTS \"{db}\""),
            )
            .await;
        }
        for r in [&shared_owner, &shared_login] {
            let _ = psql(
                backend.as_ref(),
                &image,
                &maint,
                &format!("DROP ROLE IF EXISTS \"{r}\""),
            )
            .await;
        }
    }

    println!("PROJECT SYNC SELF-HEAL TANGLE OK");
}

/// **Live CROSS-NODE TENANCY-MISMATCH fail-closed gate (I2 — DATA-LOSS corner)** (Tier-2 / nightly —
/// needs a Docker daemon AND real Postgres). A cross-node `project sync` whose SOURCE framed the
/// managed member as Single/dedicated (the CHUNKED streamed-shadow path) while the TARGET binding
/// resolves the SAME binding name to a SHARED tenant cell. The chunked import path has NO fresh-dest
/// reconcile and resolves the TARGET's binding, so without a guard it would atomic-swap the chunked
/// dump into the Shared derived target name — CLOBBERING a POPULATED Shared occupant (its data gone,
/// no recoverable tombstone), bypassing the Shared occupant-reconcile entirely. This gate reproduces
/// the mismatch on real pg and proves the FAIL-CLOSED guard: the import is REFUSED and the populated
/// Shared occupant's data survives UNCHANGED. MUTATION WITNESS: WITHOUT the guard the chunked swap
/// lands and the occupant's secret row is CLOBBERED (zero → gone). Emits
/// `PROJECT SYNC TENANCY MISMATCH FAIL-CLOSED OK`.
#[tokio::test]
async fn project_sync_tenancy_mismatch_fail_closed_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{
        sanitize_ident, tenant_db_name, tenant_owner_role_name,
    };
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (tenancy-mismatch fail-closed gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!(
                "SKIP: no reachable Docker daemon (tenancy-mismatch fail-closed gate not run)"
            );
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const BINDING: &str = "tmmapp";
    let s = now_suffix();
    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-tmm-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));

    let sealed = envelope.wrap(su_pw.as_bytes()).await.expect("seal");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed,
    )
    .await
    .expect("seal su");
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-pg".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed replica");

    // SOURCE project = the reserved default (a Single/dedicated tenant there resolves the base shared
    // `pg` workload — already seeded — so the dedicated-export side needs no extra per-project replica;
    // the mismatch under test is purely the chunked FRAMING vs the Shared TARGET).
    let src = DEFAULT_PROJECT.to_string();
    let dest = format!("tmm-dest-{s}");

    // SOURCE: a Single/dedicated binding → the managed member is framed CHUNKED on export.
    let src_dd = format!("tmm_src_dd_{s}");
    let src_binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(src_dd.clone()),
        user: Some(superuser.clone()),
        // tenant = Single, tenant_scope = Project (dedicated) by default.
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    // TARGET: the SAME binding name resolves to a SHARED tenant cell (the mismatch).
    const TGT_DB: &str = "tmmshared";
    let tgt_binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(TGT_DB.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let tgt_db = tenant_db_name(TGT_DB, &sanitize_ident(&dest));
    let tgt_owner = tenant_owner_role_name(COMPUTE, &sanitize_ident(&dest));

    for db in [&src_dd, &tgt_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }

    // Provision the SOURCE dedicated db (create it + seed source rows).
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE \"{src_dd}\""),
    )
    .await;
    assert_eq!(c, 0, "create src dedicated db: {o}");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &src_dd),
        "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES ('A','src-a');",
    )
    .await;
    assert_eq!(c, 0, "seed src dedicated: {o}");

    // Provision the TARGET Shared tenant + seed a POPULATED occupant (the data a mismatch must NOT
    // clobber).
    provision_tenant(&deploy, &kv, &envelope, &tgt_binding, &dest, "")
        .await
        .expect("provision target Shared tenant");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &tgt_db),
        &format!("SET ROLE \"{tgt_owner}\"; CREATE TABLE occupant(v text); INSERT INTO occupant VALUES ('SHARED-OCCUPANT-SECRET'); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed populated Shared occupant: {o}");

    // SOURCE driver (Single binding) → export a DataPlane+ShadowSwap bundle (CHUNKED member).
    let src_dbs = BTreeMap::from([(BINDING.to_string(), src_binding.clone())]);
    let src_op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        src_dbs.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let src_work = std::env::temp_dir().join(format!("boatramp-tmm-src-work-{s}"));
    std::fs::create_dir_all(&src_work).unwrap();
    let src_blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-tmm-src-blobs-{s}")),
    ));
    let src_driver =
        NodeProjectExport::new(src_dbs, deploy.clone(), kv.clone(), src_blobs, src_work)
            .with_managed_pg(backend.clone(), envelope.clone(), src_op, false)
            .with_trusted_extensions(vec![]);
    let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
    src_driver
        .export(
            &src,
            &ExportOptions {
                scope: BundleScope::DataPlane,
                managed_restore: ManagedRestore::ShadowSwap,
                include_identity: false,
                transport_key: None,
                delta: None,
            },
            &mut sink,
        )
        .await
        .expect("export Single source (chunked member)");
    let bundle = sink.into_inner();

    // TARGET driver (SHARED binding, SAME binding name) imports the chunked member → the mismatch.
    let tgt_dbs = BTreeMap::from([(BINDING.to_string(), tgt_binding.clone())]);
    let tgt_op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        tgt_dbs.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let tgt_work = std::env::temp_dir().join(format!("boatramp-tmm-tgt-work-{s}"));
    std::fs::create_dir_all(&tgt_work).unwrap();
    let tgt_blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-tmm-tgt-blobs-{s}")),
    ));
    let tgt_driver =
        NodeProjectExport::new(tgt_dbs, deploy.clone(), kv.clone(), tgt_blobs, tgt_work)
            .with_managed_pg(backend.clone(), envelope.clone(), tgt_op, false)
            .with_trusted_extensions(vec![]);

    let mut body = futures::io::Cursor::new(bundle.clone());
    let import_result = tgt_driver
        .import(
            &dest,
            &mut body,
            ImportOptions {
                apply: true,
                overwrite: true,
                skip_control_plane_kv: false,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await;

    // MUTATION WITNESS (zero foreign bytes — the PRIMARY data-loss assertion): the populated Shared
    // occupant's secret survives UNCHANGED. WITHOUT the guard the chunked swap replaces the whole
    // derived db, so the `occupant` table is GONE (this query then errors ≠ the secret) — silent
    // cross-tenancy data loss. (`-v ON_ERROR_STOP=1` surfaces the missing table as a clear failure.)
    let (_c, occupant) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &tgt_db),
        "SELECT v FROM occupant",
    )
    .await;
    assert_eq!(
        occupant.trim(),
        "SHARED-OCCUPANT-SECRET",
        "the populated Shared occupant's data MUST survive the mismatch UNCHANGED (WITHOUT the guard \
         the chunked swap CLOBBERS it — silent cross-tenancy data loss): got [{occupant}]"
    );

    // FAIL-CLOSED: the tenancy mismatch is REFUSED (never clobbers the Shared occupant).
    assert!(
        import_result.is_err(),
        "a Single/dedicated-framed (chunked) managed member applied into a SHARED tenant cell is a \
         tenancy mismatch and MUST be REFUSED fail-closed (WITHOUT the guard the chunked swap clobbers \
         the Shared occupant): import unexpectedly succeeded"
    );

    // cleanup
    for db in [&src_dd, &tgt_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS \"{tgt_owner}\""),
    )
    .await;

    println!("PROJECT SYNC TENANCY MISMATCH FAIL-CLOSED OK");
}

/// **Live DELTA-PATH cross-node TENANCY-MISMATCH fail-closed gate (I2 on the pg WAL true-delta chain)**
/// (Tier-2 / nightly — needs a Docker daemon AND real Postgres with `wal_level=logical`). The SECOND
/// managed-pg shadow+swap seam, parallel to the streaming import arm: `restore_pg_true_delta_in_chain`
/// (reached via `import_resumable_dir` → `import_delta_chain` when the manifest declares a delta)
/// builds the SAME non-superuser shadow, restores a base dump, replays the WAL deltas, and atomically
/// swaps — but on the current branch it had NO I2 tenancy-mismatch guard (the only guard was on the
/// streaming arm). A cross-node `project sync` whose SOURCE framed the member Single/dedicated (pg
/// true-delta capture is Single-ONLY — `pg_capture_eligible` excludes Shared) while the TARGET resolves
/// the SAME binding name to a SHARED tenant cell would therefore atomic-swap the delta restore into the
/// Shared derived name, CLOBBERING a populated Shared occupant (silent cross-tenancy data loss),
/// bypassing the Shared occupant-reconcile. This gate reproduces the mismatch on real pg and proves the
/// FAIL-CLOSED guard on the delta path: the import is REFUSED and the populated Shared occupant's data
/// survives UNCHANGED. MUTATION WITNESS: WITHOUT the guard the delta swap lands and the occupant's row
/// is CLOBBERED (its table gone). Emits `PROJECT SYNC DELTA TENANCY MISMATCH FAIL-CLOSED OK`.
#[tokio::test]
async fn project_sync_delta_tenancy_mismatch_fail_closed_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::fs::FsStorage;
    use boatramp_storage::tenant_provision::{
        sanitize_ident, tenant_db_name, tenant_owner_role_name,
    };
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (delta tenancy-mismatch gate not run)");
        return;
    };
    let Some((superuser, su_pw, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (delta tenancy-mismatch gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const BINDING: &str = "dtmmapp";
    let s = now_suffix();
    let maint = conn(&superuser, &su_pw, &host, port, "postgres");
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "version detect; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("client image");
    let (_c, wal_level) = psql(backend.as_ref(), &image, &maint, "SHOW wal_level").await;
    if wal_level.trim() != "logical" {
        eprintln!("SKIP: test pg is not wal_level=logical (delta tenancy-mismatch gate not run)");
        return;
    }

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    let sealed = envelope.wrap(su_pw.as_bytes()).await.unwrap();
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed,
    )
    .await
    .unwrap();
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
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
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .unwrap();

    // SOURCE: a Single/dedicated binding with delta_capture → a real pg WAL delta chain on export.
    let src_dd = format!("dtmm_src_dd_{s}");
    let src_binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(src_dd.clone()),
        user: Some(superuser.clone()),
        delta_capture: true,
        // tenant = Single, tenant_scope = Project (dedicated) by default.
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    // TARGET: the SAME binding name resolves to a SHARED tenant cell (the mismatch).
    let dest = format!("dtmm-dest-{s}");
    const TGT_DB: &str = "dtmmshared";
    let tgt_binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(TGT_DB.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        rls_session: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let tgt_db = tenant_db_name(TGT_DB, &sanitize_ident(&dest));
    let tgt_owner = tenant_owner_role_name(COMPUTE, &sanitize_ident(&dest));

    for db in [&src_dd, &tgt_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    // Create + seed the SOURCE dedicated db.
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("CREATE DATABASE \"{src_dd}\""),
    )
    .await;
    assert_eq!(c, 0, "create src dedicated db: {o}");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &src_dd),
        "CREATE TABLE marker(tid text, v text); INSERT INTO marker VALUES ('A','src-a');",
    )
    .await;
    assert_eq!(c, 0, "seed src dedicated: {o}");

    // Provision the TARGET Shared tenant + seed a POPULATED occupant (what a mismatch must NOT clobber).
    provision_tenant(&deploy, &kv, &envelope, &tgt_binding, &dest, "")
        .await
        .expect("provision target Shared tenant");
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &tgt_db),
        &format!("SET ROLE \"{tgt_owner}\"; CREATE TABLE occupant(v text); INSERT INTO occupant VALUES ('SHARED-OCCUPANT-SECRET'); RESET ROLE;"),
    )
    .await;
    assert_eq!(c, 0, "seed populated Shared occupant: {o}");

    // SOURCE driver (Single binding, delta_capture) with a resumable base dir.
    let resumable = td.path().join("resumable");
    let src_dbs = BTreeMap::from([(BINDING.to_string(), src_binding.clone())]);
    let src_op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        src_dbs.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let src_work = td.path().join("src-work");
    std::fs::create_dir_all(&src_work).unwrap();
    let src_driver =
        NodeProjectExport::new(src_dbs, deploy.clone(), kv.clone(), blobs.clone(), src_work)
            .with_managed_pg(backend.clone(), envelope.clone(), src_op, false)
            .with_trusted_extensions(vec![])
            .with_resumable_base(Some(resumable.clone()));

    // BASE export (creates the capture slot + the full dump), then mutate, then an INCREMENTAL delta
    // export (drains the slot into a PgWalDelta member) → a real delta chain with manifest.delta=Some.
    let full = ExportOptions {
        scope: BundleScope::Full,
        managed_restore: ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    src_driver
        .export_resumable(DEFAULT_PROJECT, &full, "base")
        .await
        .expect("base resumable export");
    let (c, _o) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &src_dd),
        "INSERT INTO marker VALUES ('B','src-b');",
    )
    .await;
    assert_eq!(c, 0, "mutate src for the delta");
    let delta_opts = ExportOptions {
        scope: BundleScope::Full,
        managed_restore: ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: "base".to_string(),
        }),
    };
    src_driver
        .export_resumable(DEFAULT_PROJECT, &delta_opts, "d1")
        .await
        .expect("incremental delta export");
    // Confirm it really is a WAL delta chain (not a full-dump fallback) — so the import routes to
    // `restore_pg_true_delta_in_chain`, the seam under test.
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert!(
        d1_manifest.delta.is_some(),
        "the d1 manifest must declare a delta (so the import takes the delta-chain restore path)"
    );

    // TARGET driver (SHARED binding, SAME binding name), SAME resumable dir → import the delta chain.
    let tgt_dbs = BTreeMap::from([(BINDING.to_string(), tgt_binding.clone())]);
    let tgt_op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        tgt_dbs.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let tgt_work = td.path().join("tgt-work");
    std::fs::create_dir_all(&tgt_work).unwrap();
    let tgt_driver =
        NodeProjectExport::new(tgt_dbs, deploy.clone(), kv.clone(), blobs.clone(), tgt_work)
            .with_managed_pg(backend.clone(), envelope.clone(), tgt_op, false)
            .with_trusted_extensions(vec![])
            .with_resumable_base(Some(resumable.clone()));

    let import_result = tgt_driver
        .import_resumable(
            &dest,
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await;

    // MUTATION WITNESS (zero foreign bytes — PRIMARY data-loss assertion): the populated Shared
    // occupant's secret survives UNCHANGED. WITHOUT the delta-path guard the delta swap replaces the
    // whole derived db, so the `occupant` table is GONE (this query then errors ≠ the secret).
    let (_c, occupant) = psql(
        backend.as_ref(),
        &image,
        &conn(&superuser, &su_pw, &host, port, &tgt_db),
        "SELECT v FROM occupant",
    )
    .await;
    assert_eq!(
        occupant.trim(),
        "SHARED-OCCUPANT-SECRET",
        "the populated Shared occupant's data MUST survive the delta mismatch UNCHANGED (WITHOUT the \
         delta-path guard the WAL-delta swap CLOBBERS it — silent cross-tenancy data loss): got [{occupant}]"
    );
    // FAIL-CLOSED: the mismatch is REFUSED on the delta path too.
    assert!(
        import_result.is_err(),
        "a Single/dedicated-framed (delta-chain) managed member applied into a SHARED tenant cell is a \
         tenancy mismatch and MUST be REFUSED fail-closed on the DELTA path (WITHOUT the guard the \
         delta swap clobbers the Shared occupant): import unexpectedly succeeded"
    );

    // cleanup
    for db in [&src_dd, &tgt_db] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{db}\""),
        )
        .await;
    }
    let _ = psql(
        backend.as_ref(),
        &image,
        &maint,
        &format!("DROP ROLE IF EXISTS \"{tgt_owner}\""),
    )
    .await;

    println!("PROJECT SYNC DELTA TENANCY MISMATCH FAIL-CLOSED OK");
}

/// **Live mysql BINLOG-DELTA cross-node TENANCY-MISMATCH already-refused PROOF gate** (Tier-2 /
/// nightly — needs a Docker daemon AND a binlog-on + GTID MySQL). The mysql analogue of the pg
/// delta-path I2 corner. UNLIKE pg, the mysql binlog-delta restore (`restore_mysql_true_delta_in_chain`)
/// ALREADY passes `allow_shared = false` to `mysql_shadow_plan`, which REFUSES a Shared target before
/// any shadow is created (mysql binlog capture is Single/dedicated-only too). This gate PROVES that
/// existing protection is real and reachable — not an empty claim: a Single/dedicated-framed mysql
/// binlog-delta chain applied into a SHARED mysql tenant cell is REFUSED, and the populated Shared
/// occupant's data survives UNCHANGED (zero foreign bytes). So the mysql delta path needs NO new guard
/// (pg's new delta-path guard brings pg to parity). Emits
/// `PROJECT SYNC MYSQL DELTA TENANCY MISMATCH REFUSED OK`.
#[tokio::test]
async fn project_sync_mysql_delta_tenancy_mismatch_refused_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::fs::FsStorage;
    use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name};
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!(
            "SKIP: BOATRAMP_TEST_MYSQL_URL unset (mysql delta tenancy-mismatch gate not run)"
        );
        return;
    };
    let Some((user, password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!(
                "SKIP: no reachable Docker daemon (mysql delta tenancy-mismatch gate not run)"
            );
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "mysql";
    const BINDING: &str = "dmtmmapp";
    let s = now_suffix();
    let maint = MysqlConnection {
        host: host.clone(),
        port,
        user: user.clone(),
        password: password.clone(),
        database: String::new(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };
    let (code, _o) = mysql_run(backend.as_ref(), "mysql:8.0", &maint, None, "SELECT 1").await;
    assert_eq!(code, 0, "mysql reachable; is the DSN right?");
    // binlog must be on for a true binlog-delta (else the export falls back to a full dump and the
    // import takes the sidecar path, not the delta path under test).
    let (_c, logbin) = mysql_run(
        backend.as_ref(),
        "mysql:8.0",
        &maint,
        None,
        "SELECT @@log_bin",
    )
    .await;
    if logbin.trim() != "1" {
        eprintln!("SKIP: test mysql has log_bin off (mysql delta tenancy-mismatch gate not run)");
        return;
    }

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let td = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(FsStorage::new(td.path().join("blobs")));
    let deploy = DeployStore::new(blobs.clone(), kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([9u8; 32]));
    let sealed = envelope.wrap(password.as_bytes()).await.unwrap();
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed,
    )
    .await
    .unwrap();
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
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
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .unwrap();

    // SOURCE: a Single/dedicated mysql binding with delta_capture (binlog).
    let src_dd = format!("dmtmm_src_{s}");
    let src_binding = ExternalDatabaseConfig {
        kind: "mysql".into(),
        compute: Some(COMPUTE.into()),
        database: Some(src_dd.clone()),
        user: Some(user.clone()),
        delta_capture: true,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    // TARGET: the SAME binding name resolves to a SHARED mysql tenant cell (the mismatch).
    let dest = format!("dmtmm-dest-{s}");
    const TGT_DB: &str = "dmtmmshared";
    let tgt_binding = ExternalDatabaseConfig {
        kind: "mysql".into(),
        compute: Some(COMPUTE.into()),
        database: Some(TGT_DB.into()),
        user: Some(user.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let tgt_db = tenant_db_name(TGT_DB, &sanitize_ident(&dest));

    for db in [&src_dd, &tgt_db] {
        let _ = mysql_run(
            backend.as_ref(),
            "mysql:8.0",
            &maint,
            None,
            &format!("DROP DATABASE IF EXISTS `{db}`"),
        )
        .await;
    }
    // Create + seed the SOURCE dedicated db.
    let (c, o) = mysql_run(
        backend.as_ref(),
        "mysql:8.0",
        &maint,
        None,
        &format!("CREATE DATABASE `{src_dd}`"),
    )
    .await;
    assert_eq!(c, 0, "create src mysql db: {o}");
    let (c, o) = mysql_run(
        backend.as_ref(),
        "mysql:8.0",
        &maint,
        Some(&src_dd),
        "CREATE TABLE marker(tid varchar(8), v varchar(32)); INSERT INTO marker VALUES ('A','src-a');",
    )
    .await;
    assert_eq!(c, 0, "seed src mysql: {o}");

    // Provision the TARGET Shared mysql tenant + seed a POPULATED occupant.
    provision_tenant(&deploy, &kv, &envelope, &tgt_binding, &dest, "")
        .await
        .expect("provision target Shared mysql tenant");
    let (c, o) = mysql_run(
        backend.as_ref(),
        "mysql:8.0",
        &maint,
        Some(&tgt_db),
        "CREATE TABLE occupant(v varchar(64)); INSERT INTO occupant VALUES ('SHARED-OCCUPANT-SECRET');",
    )
    .await;
    assert_eq!(c, 0, "seed populated Shared mysql occupant: {o}");

    // SOURCE driver with a resumable base dir → base + incremental binlog delta.
    let resumable = td.path().join("resumable");
    let src_dbs = BTreeMap::from([(BINDING.to_string(), src_binding.clone())]);
    let src_op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        src_dbs.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let src_work = td.path().join("src-work");
    std::fs::create_dir_all(&src_work).unwrap();
    let src_driver =
        NodeProjectExport::new(src_dbs, deploy.clone(), kv.clone(), blobs.clone(), src_work)
            .with_managed_pg(backend.clone(), envelope.clone(), src_op, false)
            .with_resumable_base(Some(resumable.clone()));

    let full = ExportOptions {
        scope: BundleScope::Full,
        managed_restore: ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    src_driver
        .export_resumable(DEFAULT_PROJECT, &full, "base")
        .await
        .expect("base resumable export (mysql)");
    let (c, _o) = mysql_run(
        backend.as_ref(),
        "mysql:8.0",
        &maint,
        Some(&src_dd),
        "INSERT INTO marker VALUES ('B','src-b');",
    )
    .await;
    assert_eq!(c, 0, "mutate src mysql for the delta");
    let delta_opts = ExportOptions {
        scope: BundleScope::Full,
        managed_restore: ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: "base".to_string(),
        }),
    };
    src_driver
        .export_resumable(DEFAULT_PROJECT, &delta_opts, "d1")
        .await
        .expect("incremental binlog delta export");
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert!(
        d1_manifest.delta.is_some(),
        "the d1 manifest must declare a delta (so the import takes the mysql delta-chain restore path)"
    );

    // TARGET driver (SHARED binding), SAME resumable dir → import the binlog-delta chain.
    let tgt_dbs = BTreeMap::from([(BINDING.to_string(), tgt_binding.clone())]);
    let tgt_op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        tgt_dbs.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let tgt_work = td.path().join("tgt-work");
    std::fs::create_dir_all(&tgt_work).unwrap();
    let tgt_driver =
        NodeProjectExport::new(tgt_dbs, deploy.clone(), kv.clone(), blobs.clone(), tgt_work)
            .with_managed_pg(backend.clone(), envelope.clone(), tgt_op, false)
            .with_resumable_base(Some(resumable.clone()));

    let import_result = tgt_driver
        .import_resumable(
            &dest,
            "d1",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                expected_managed_restore: Some(ManagedRestore::ShadowSwap),
                ..Default::default()
            },
        )
        .await;

    // ALREADY REFUSED (allow_shared=false): the mismatch is rejected before any shadow is created.
    assert!(
        import_result.is_err(),
        "a Single/dedicated-framed (binlog-delta) mysql member applied into a SHARED tenant cell MUST \
         be REFUSED (mysql_shadow_plan allow_shared=false) — the EXISTING protection the pg guard mirrors"
    );
    // MUTATION WITNESS (zero foreign bytes): the populated Shared occupant's secret survives UNCHANGED.
    let (_c, occupant) = mysql_run(
        backend.as_ref(),
        "mysql:8.0",
        &maint,
        Some(&tgt_db),
        "SELECT v FROM occupant",
    )
    .await;
    assert_eq!(
        occupant.trim(),
        "SHARED-OCCUPANT-SECRET",
        "the populated Shared mysql occupant's data MUST survive the refused mismatch UNCHANGED: got [{occupant}]"
    );

    // cleanup
    for db in [&src_dd, &tgt_db] {
        let _ = mysql_run(
            backend.as_ref(),
            "mysql:8.0",
            &maint,
            None,
            &format!("DROP DATABASE IF EXISTS `{db}`"),
        )
        .await;
    }

    println!("PROJECT SYNC MYSQL DELTA TENANCY MISMATCH REFUSED OK");
}

/// **Live managed-MySQL triggers/routines/events carry + DEFINER re-point gate** (Tier-2 / nightly —
/// needs a Docker daemon AND a MySQL server whose DSN user can `CREATE USER`/`GRANT`/`CREATE
/// DATABASE`). Self-skips.
///
/// Proves Part 2 end-to-end THROUGH THE REAL DRIVER on a Shared tenant: a source schema with a
/// TRIGGER + a stored PROCEDURE + a stored FUNCTION + an EVENT + a VIEW (DEFINER = the superuser) is
/// EXPORTED and IMPORTED into a FRESH Shared tenant, and the carried objects: (1) LAND (they exist in
/// the fresh tenant db); (2) were restored as a NON-SUPER user (the restore connects only as the
/// ephemeral apply user — the whole import fails if a foreign DEFINER were required, and a non-SUPER
/// `CREATE TRIGGER`/`CREATE FUNCTION` on a binlog-on server needs `log_bin_trust_function_creators`,
/// which the managed-mysqld spec in `compute.rs` bakes on); (3) are RE-POINTED post-swap to the FRESH
/// TENANT'S OWN LOGIN ROLE — asserted by querying `information_schema.{triggers,routines,events,views}`
/// for each object's `DEFINER = <fresh_role>@%`; and (4) actually WORK — the carried trigger FIRES (an
/// INSERT appends to the audit table), the carried procedure RUNS (a `CALL` inserts a row), the
/// carried function RETURNS (`dbl(21)=42`), and the carried view is QUERYABLE over the live table.
/// Requires a FAITHFUL binlog-on + ROW + GTID server configured the way `compute.rs` produces (incl.
/// trust-function-creators), so the gate cannot false-green. Emits
/// `PROJECT EXPORT MYSQL ROUTINES+TRIGGERS OK`.
#[tokio::test]
async fn project_export_mysql_routines_triggers_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, IdentityChoice, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name, tenant_role_name};
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (mysql routines/triggers gate not run)");
        return;
    };
    let Some((superuser, su_password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (mysql routines/triggers gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    const COMPUTE: &str = "my";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "deftest";
    let s = now_suffix();
    let src_project = format!("mydef-src-{s}");
    let fresh_project = format!("mydef-fresh-{s}");

    let su = MysqlConnection {
        host: host.clone(),
        port,
        user: superuser.clone(),
        password: su_password.clone(),
        database: String::new(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-mydef-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([5u8; 32]));

    let sealed_su = envelope
        .wrap(su_password.as_bytes())
        .await
        .expect("seal superuser pw");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed_su,
    )
    .await
    .expect("pre-seal superuser credential");

    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-mysql".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed healthy replica");

    let binding = ExternalDatabaseConfig {
        kind: "mysql".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(DB_BINDING.to_string(), binding.clone())]);
    let db_name = |project: &str| tenant_db_name(DATABASE, &sanitize_ident(project));

    for p in [&src_project, &fresh_project] {
        let _ = mysql_run(
            backend.as_ref(),
            image,
            &su,
            None,
            &format!("DROP DATABASE IF EXISTS `{}`;", db_name(p)),
        )
        .await;
    }

    provision_tenant(&deploy, &kv, &envelope, &binding, &src_project, "")
        .await
        .expect("provision source tenant");

    // Seed the SOURCE tenant db with a schema that HAS a trigger + a stored procedure + an event
    // (all with DEFINER = the superuser, as any normal CREATE would). The trigger fires on INSERT.
    let src_db = db_name(&src_project);
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&src_db),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         CREATE TABLE audit(n INT); \
         CREATE TRIGGER trg AFTER INSERT ON t FOR EACH ROW INSERT INTO audit VALUES (NEW.id); \
         CREATE PROCEDURE addrow(IN i INT, IN sv TEXT) INSERT INTO t VALUES (i, sv); \
         CREATE FUNCTION dbl(x INT) RETURNS INT DETERMINISTIC RETURN x * 2; \
         CREATE EVENT ev ON SCHEDULE EVERY 1 HOUR DO DELETE FROM audit WHERE n < 0; \
         CREATE VIEW vw AS SELECT id, v FROM t; \
         INSERT INTO t VALUES (1,'alpha');",
    )
    .await;
    assert_eq!(c, 0, "seed source schema + objects; mysql output:\n{o}");
    // The source trigger fired on the seed INSERT → audit has {1}.
    let src_audit = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&src_db),
        "SELECT n FROM audit ORDER BY n;",
    )
    .await
    .1;
    assert_eq!(src_audit, "1", "source trigger fired on seed INSERT");

    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-mydef-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-mydef-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false);

    // EXPORT the source tenant (DataPlane + ShadowSwap → sidecar/tables-only + routines/events).
    let bundle = {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(
                &src_project,
                &ExportOptions {
                    scope: BundleScope::DataPlane,
                    managed_restore: ManagedRestore::ShadowSwap,
                    include_identity: false,
                    transport_key: None,
                    delta: None,
                },
                &mut sink,
            )
            .await
            .expect("driver export of the source tenant");
        sink.into_inner()
    };

    // IMPORT into the fresh tenant (self-provisions its db + role).
    let report = {
        let mut source = futures::io::Cursor::new(bundle);
        driver
            .import(
                &fresh_project,
                &mut source,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: false,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("import carrying triggers/routines/events must SUCCEED (restored non-SUPER)")
    };
    assert!(report.pg_databases >= 1, "the mysql db restored");

    let fresh_db = db_name(&fresh_project);
    let fresh_ident = sanitize_ident(&fresh_project);
    let fresh_role = tenant_role_name(COMPUTE, &fresh_ident);
    let expect_definer = format!("{fresh_role}@%");

    // (1)+(3) The carried objects LAND and are RE-POINTED to the fresh tenant's OWN login role
    // (information_schema.*.definer is `user@host`, not backtick-quoted).
    let trg_def = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        &format!(
            "SELECT definer FROM information_schema.triggers WHERE trigger_schema='{fresh_db}';"
        ),
    )
    .await
    .1;
    assert_eq!(
        trg_def, expect_definer,
        "the carried TRIGGER is re-pointed to the tenant role (got {trg_def:?})"
    );
    let proc_def = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        &format!(
            "SELECT definer FROM information_schema.routines WHERE routine_schema='{fresh_db}' \
             AND routine_name='addrow';"
        ),
    )
    .await
    .1;
    assert_eq!(
        proc_def, expect_definer,
        "the carried PROCEDURE is re-pointed to the tenant role (got {proc_def:?})"
    );
    let ev_def = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        &format!("SELECT definer FROM information_schema.events WHERE event_schema='{fresh_db}';"),
    )
    .await
    .1;
    assert_eq!(
        ev_def, expect_definer,
        "the carried EVENT is re-pointed to the tenant role (got {ev_def:?})"
    );
    // The stored FUNCTION (a plain-line `CREATE DEFINER=… FUNCTION` header — the case that hit the
    // ERROR 1227/1419 regression) is carried + re-pointed too.
    let fn_def = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        &format!(
            "SELECT definer FROM information_schema.routines WHERE routine_schema='{fresh_db}' \
             AND routine_name='dbl';"
        ),
    )
    .await
    .1;
    assert_eq!(
        fn_def, expect_definer,
        "the carried FUNCTION is re-pointed to the tenant role (got {fn_def:?})"
    );
    // The VIEW (schema-level, not swapped with the base tables) is carried + re-pointed too.
    let vw_def = mysql_run(
        backend.as_ref(),
        image,
        &su,
        None,
        &format!("SELECT definer FROM information_schema.views WHERE table_schema='{fresh_db}';"),
    )
    .await
    .1;
    assert_eq!(
        vw_def, expect_definer,
        "the carried VIEW is re-pointed to the tenant role (got {vw_def:?})"
    );
    // The carried VIEW is queryable (it resolves against the swapped-in base table).
    let vw_rows = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&fresh_db),
        "SELECT CONCAT(id, ':', v) FROM vw ORDER BY id;",
    )
    .await
    .1;
    assert_eq!(
        vw_rows, "1:alpha",
        "the carried view is queryable over the live table"
    );
    // The carried FUNCTION runs (deferred-resolution body + a DETERMINISTIC return).
    let fn_run = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&fresh_db),
        "SELECT dbl(21);",
    )
    .await
    .1;
    assert_eq!(
        fn_run, "42",
        "the carried function runs and returns its result"
    );

    // Row data landed too (the seed row + its trigger-written audit row rode the tables).
    let landed = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&fresh_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;
    assert_eq!(landed, "1:alpha", "table rows landed on the fresh tenant");

    // (4) The carried PROCEDURE actually RUNS, and the carried TRIGGER actually FIRES.
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&fresh_db),
        "CALL addrow(2, 'beta');",
    )
    .await;
    assert_eq!(c, 0, "the carried procedure runs; mysql output:\n{o}");
    let after = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&fresh_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;
    assert_eq!(
        after, "1:alpha\n2:beta",
        "the carried procedure inserted a row via CALL"
    );
    // The INSERT the procedure did must have fired the carried trigger → audit now has {1,2}.
    let audit = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&fresh_db),
        "SELECT n FROM audit ORDER BY n;",
    )
    .await
    .1;
    assert_eq!(
        audit, "1\n2",
        "the carried trigger fired on the procedure's INSERT (audit got the new id)"
    );

    // cleanup (best-effort).
    for p in [&src_project, &fresh_project] {
        let _ = mysql_run(
            backend.as_ref(),
            image,
            &su,
            None,
            &format!("DROP DATABASE IF EXISTS `{}`;", db_name(p)),
        )
        .await;
    }

    println!("PROJECT EXPORT MYSQL ROUTINES+TRIGGERS OK");
}

/// **Live managed-MySQL VIEW-NAME argument-injection refusal gate** (Tier-2 / nightly — Docker + a
/// MySQL server whose DSN user can `CREATE USER`/`GRANT`/`CREATE DATABASE`). Self-skips.
///
/// NEGATIVE control for the Security HIGH: the by-name view capture passes the shadow's (ATTACKER-
/// created) view names as positional `mysqldump` operands AS THE ADMIN, so a view named
/// `--all-databases` / `--host=…` could inject a mysqldump OPTION (dump every tenant / redirect the
/// superuser credential). A Shared source tenant is seeded with a view literally named
/// `` `--all-databases` ``; on import into a FRESH tenant the restore must be REFUSED fail-closed by
/// the view-name validator BEFORE the capture mysqldump runs — asserted by the error naming the
/// unsafe view, the fresh target staying EMPTY (the swap never happened — the validation precedes
/// it), and a pre-existing SIBLING tenant's data being byte-for-byte unchanged (no cross-tenant dump
/// occurred). Emits `PROJECT EXPORT MYSQL VIEW-NAME INJECTION REFUSED OK`.
#[tokio::test]
async fn project_export_mysql_view_name_injection_refused_live() {
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::KeyEnvelope;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        BundleScope, ExportOptions, IdentityChoice, ImportOptions, ManagedRestore, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::NodeOperatorSql;
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name};
    use std::collections::BTreeMap;

    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (mysql view-injection gate not run)");
        return;
    };
    let Some((superuser, su_password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (mysql view-injection gate not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    const COMPUTE: &str = "my";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "injtest";
    let s = now_suffix();
    let src_project = format!("myinj-src-{s}");
    let fresh_project = format!("myinj-fresh-{s}");
    let other_project = format!("myinj-other-{s}");

    let su = MysqlConnection {
        host: host.clone(),
        port,
        user: superuser.clone(),
        password: su_password.clone(),
        database: String::new(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-myinj-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> =
        Arc::new(boatramp_server::envelope::LocalKek::from_bytes([3u8; 32]));

    let sealed_su = envelope
        .wrap(su_password.as_bytes())
        .await
        .expect("seal superuser pw");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed_su,
    )
    .await
    .expect("pre-seal superuser credential");

    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-mysql".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed healthy replica");

    let binding = ExternalDatabaseConfig {
        kind: "mysql".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(DB_BINDING.to_string(), binding.clone())]);
    let db_name = |project: &str| tenant_db_name(DATABASE, &sanitize_ident(project));

    for p in [&src_project, &fresh_project, &other_project] {
        let _ = mysql_run(
            backend.as_ref(),
            image,
            &su,
            None,
            &format!("DROP DATABASE IF EXISTS `{}`;", db_name(p)),
        )
        .await;
    }

    provision_tenant(&deploy, &kv, &envelope, &binding, &src_project, "")
        .await
        .expect("provision source tenant");
    provision_tenant(&deploy, &kv, &envelope, &binding, &other_project, "")
        .await
        .expect("provision the pre-existing sibling tenant");

    // Seed the SOURCE with a table + a VIEW whose NAME is a mysqldump argument-injection payload.
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&src_project)),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); \
         INSERT INTO t VALUES (1,'alpha'); \
         CREATE VIEW `--all-databases` AS SELECT id FROM t;",
    )
    .await;
    assert_eq!(
        c, 0,
        "seed source + injection-named view; mysql output:\n{o}"
    );
    // The sibling tenant's known data (must stay byte-for-byte unchanged).
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&other_project)),
        "CREATE TABLE t(id INT PRIMARY KEY, v TEXT); INSERT INTO t VALUES (99,'untouched');",
    )
    .await;
    assert_eq!(c, 0, "seed sibling tenant; mysql output:\n{o}");
    let other_before = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&other_project)),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;

    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-myinj-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-myinj-blobs-{s}")),
    ));
    let driver = NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false);

    let bundle = {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(
                &src_project,
                &ExportOptions {
                    scope: BundleScope::DataPlane,
                    managed_restore: ManagedRestore::ShadowSwap,
                    include_identity: false,
                    transport_key: None,
                    delta: None,
                },
                &mut sink,
            )
            .await
            .expect("driver export of the source tenant");
        sink.into_inner()
    };

    // IMPORT must be REFUSED fail-closed by the view-name validator.
    let refused = {
        let mut source = futures::io::Cursor::new(bundle);
        driver
            .import(
                &fresh_project,
                &mut source,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: false,
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
    };
    let err = refused.expect_err("an injection-named view MUST refuse the import fail-closed");
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe name") && msg.contains("--all-databases"),
        "the refusal must be the view-name rejection, got: {msg}"
    );

    // Fail-closed: the swap never happened (the validation precedes it), so the fresh target's table
    // did NOT land (the carried table is absent / the query errors).
    let (code, _out) = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&fresh_project)),
        "SELECT COUNT(*) FROM t;",
    )
    .await;
    assert_ne!(
        code, 0,
        "the refused import must NOT have swapped the source table into the fresh tenant"
    );

    // No cross-tenant dump occurred: the sibling tenant is byte-for-byte unchanged.
    let other_after = mysql_run(
        backend.as_ref(),
        image,
        &su,
        Some(&db_name(&other_project)),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await
    .1;
    assert_eq!(
        other_after, other_before,
        "a refused injection import must not touch the sibling tenant"
    );

    for p in [&src_project, &fresh_project, &other_project] {
        let _ = mysql_run(
            backend.as_ref(),
            image,
            &su,
            None,
            &format!("DROP DATABASE IF EXISTS `{}`;", db_name(p)),
        )
        .await;
    }

    println!("PROJECT EXPORT MYSQL VIEW-NAME INJECTION REFUSED OK");
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
                    scope: boatramp_core::project_export::BundleScope::Full,
                    managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
                scope: boatramp_core::project_export::BundleScope::Full,
                managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
                active_spec: None,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
                active_spec: None,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
        ephemeral_network: None,
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
                active_spec: None,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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

// ===========================================================================================
// SQL true-delta MULTI-DELTA CHAIN gates (PLAN-sql-true-delta Stage 5). Each builds on the
// per-engine single-delta gate above by adding a THIRD link — a real base → d1 → d2 chain — and
// proving the chain RESTORES CORRECTLY to the final state after BOTH mutation rounds, honouring each
// engine's documented MODE limit, and carrying the crafted-escape assertion THROUGH the chain. Not a
// duplicate of the single-delta gates: those import a 2-link (base → d1) chain; these import the
// 3rd link and exercise the chain-walk + the full-dump-fallback-in-a-chain restore for the first
// time. Markers: `PROJECT EXPORT {PG,MYSQL,LIBSQL} TRUE-DELTA CHAIN OK`.
// ===========================================================================================

/// LIVE gate (Docker + a `wal_level=logical` Postgres): the pg logical-WAL true-delta MULTI-DELTA
/// CHAIN round-trip. Builds base → d1 → d2 and proves the chain restores to the final state after
/// BOTH mutation rounds, honouring pg's mode limit: a single advancing slot can true-delta only the
/// FIRST delta, so d1 is a genuine `PgWalReplay` member while d2 (incremental onto a delta parent,
/// whose dir records no slot) FULL-DUMPS as the fallback — and the chain restore (newest full dump
/// supersedes earlier WAL) yields d2's final state regardless of which links were true-delta vs
/// fallback. Also carries the crafted-escape assertion through the chain-import path: a tampered
/// WAL-delta member in a chain is refused fail-closed, the victim table + a SECOND tenant's db
/// untouched. Marker: `PROJECT EXPORT PG TRUE-DELTA CHAIN OK`.
#[tokio::test]
async fn project_export_pg_true_delta_chain_live() {
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
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live pg true-delta CHAIN not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live pg true-delta CHAIN not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    let s = now_suffix();
    let live_db = format!("brexp_tdc_live_{s}");
    let tenant_b_db = format!("brexp_tdc_tenantb_{s}");
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

    // PRECONDITION: logical decoding. SELF-SKIP (not assert) when a bring-your-own test pg lacks it,
    // so a pg launched without `-c wal_level=logical` (e.g. capability.yml's) runs the file's other
    // tests cleanly; the preflight-matrix CHAIN gate launches pg WITH it and gates on the marker, so
    // a skip there FAILS the job (the marker never prints).
    let (_c, wal_level) = psql(backend.as_ref(), &image, &maint, "SHOW wal_level").await;
    if wal_level.trim() != "logical" {
        eprintln!(
            "SKIP: the test Postgres is not wal_level=logical (pg WAL true-delta CHAIN gate needs \
             `-c wal_level=logical -c max_replication_slots=10 -c max_wal_senders=10`)"
        );
        return;
    }

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
        "CREATE TABLE b(id int primary key, v text); INSERT INTO b VALUES (7,'TENANT_B_SENTINEL');",
    )
    .await;
    assert_eq!(c, 0, "seed tenant B: {o}");

    // --- the driver: a MANAGED Single/default pg binding with delta_capture (identical to the
    //     single-delta gate's) ---
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
                active_spec: None,
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

    let full = ExportOptions {
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    let incr = |base: &str| ExportOptions {
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: base.to_string(),
        }),
    };

    // --- BASE export: creates the pgoutput capture slot + the full dump ---
    drv.export_resumable("default", &full, "cbase")
        .await
        .expect("base resumable export");

    // --- round-1 mutation → d1 (incremental vs cbase): the FIRST delta true-WAL-captures ---
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "INSERT INTO t VALUES (4,'delta'); UPDATE t SET v='beta2' WHERE id=2; DELETE FROM t WHERE id=3;",
    )
    .await;
    assert_eq!(c, 0, "round-1 mutate: {o}");
    drv.export_resumable("default", &incr("cbase"), "d1")
        .await
        .expect("delta d1 export");
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::PgWalReplay,
        "the FIRST chain delta must WAL-capture (true-delta), not full-dump"
    );
    let pgwal_idx = d1_manifest
        .members
        .iter()
        .position(|m| m.path == "sql/app.pgwal" && m.kind == MemberKind::PgWalDelta)
        .expect("d1 must carry a sql/app.pgwal true-delta member");
    assert!(
        !d1_manifest.members.iter().any(|m| m.path == "sql/app.pgc"),
        "d1's full pg dump must be SUPERSEDED by the WAL delta member"
    );

    // --- round-2 mutation → d2 (incremental vs d1): a LATER link, so pg FULL-DUMPS as the fallback
    //     (the documented mode limit — d1's dir records no slot; only a BASE export creates one). The
    //     chain still restores correctly below. ---
    let (c, o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "INSERT INTO t VALUES (5,'epsilon'); UPDATE t SET v='delta2' WHERE id=4; DELETE FROM t WHERE id=1;",
    )
    .await;
    assert_eq!(c, 0, "round-2 mutate: {o}");
    drv.export_resumable("default", &incr("d1"), "d2")
        .await
        .expect("delta d2 export");
    let d2_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d2").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d2_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::FullDumpFallback,
        "a LATER pg chain link must FULL-DUMP (a single advancing slot cannot re-emit the interval)"
    );
    assert!(
        d2_manifest
            .members
            .iter()
            .any(|m| m.path == "sql/app.pgc" && m.kind == MemberKind::PgDump),
        "d2 must carry a full pg dump member (the fallback)"
    );
    assert!(
        !d2_manifest
            .members
            .iter()
            .any(|m| m.kind == MemberKind::PgWalDelta),
        "d2 (a later link) must NOT carry a WAL delta member"
    );

    // --- CRAFTED-ESCAPE THROUGH THE CHAIN: tamper the d1 WAL-delta member (the replayed true-delta
    //     link) + fix its meta so it passes integrity and reaches the replay; import the base→evil
    //     chain. import_delta_chain → restore_pg_true_delta_in_chain must refuse it fail-closed (the
    //     injected statement hits a non-existent relation → ON_ERROR_STOP → shadow dropped → no
    //     swap), the victim table + tenant B untouched. ---
    let d1_dir = resumable.join("d1");
    let evil_dir = resumable.join("evil");
    std::fs::create_dir_all(&evil_dir).unwrap();
    for ent in std::fs::read_dir(&d1_dir).unwrap() {
        let ent = ent.unwrap();
        if ent.file_type().unwrap().is_file() {
            std::fs::copy(ent.path(), evil_dir.join(ent.file_name())).unwrap();
        }
    }
    let crafted = crafted_injection_pgwal();
    std::fs::write(evil_dir.join(format!("m{pgwal_idx:05}")), &crafted).unwrap();
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
        "a tampered WAL-delta member in the chain MUST be refused fail-closed; got: {evil_res:?}"
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
        "the crafted chain import must not touch the victim table (shadow dropped, no swap)"
    );

    // --- plant a pre-import sentinel so the clean chain import PROVES a real restore (not a no-op) ---
    let (c, _o) = psql(
        backend.as_ref(),
        &image,
        &live,
        "DELETE FROM t; INSERT INTO t VALUES (99,'SENTINEL_PRE_IMPORT');",
    )
    .await;
    assert_eq!(c, 0, "plant the pre-import sentinel");

    // --- IMPORT THE 3-LINK CHAIN (import d2 → resolves base → d1 → d2). The chain restore takes d2's
    //     newest full dump (superseding d1's WAL) → the FINAL state after BOTH mutation rounds. ---
    let report = drv
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
        .await
        .expect("3-link delta chain import (base → d1 → d2)");
    assert!(report.pg_databases >= 1, "the pg db must be restored");
    let (_c, rows) = psql(
        backend.as_ref(),
        &image,
        &live,
        "SELECT id || ':' || v FROM t ORDER BY id",
    )
    .await;
    assert_eq!(
        rows, "2:beta2\n4:delta2\n5:epsilon",
        "the restored db must equal the MUTATED source after the WHOLE chain (both rounds) — not the \
         base, not d1's state, not the pre-import sentinel"
    );
    let (_c, b_rows) = psql(
        backend.as_ref(),
        &image,
        &tenant_b,
        "SELECT id || ':' || v FROM b ORDER BY id",
    )
    .await;
    assert_eq!(
        b_rows, "7:TENANT_B_SENTINEL",
        "the second tenant's db must be UNTOUCHED by the chain restore"
    );

    for sql in [
        format!("DROP DATABASE IF EXISTS {live_db}"),
        format!("DROP DATABASE IF EXISTS {tenant_b_db}"),
    ] {
        let _ = psql(backend.as_ref(), &image, &maint, &sql).await;
    }
    println!("PROJECT EXPORT PG TRUE-DELTA CHAIN OK");
}

/// LIVE gate (Docker + a `gtid_mode=ON --log-bin --binlog-format=ROW` MySQL): the mysql binlog
/// true-delta MULTI-DELTA CHAIN round-trip. Builds base → d1 → d2 and proves the chain restores to
/// the final state after BOTH mutation rounds, honouring mysql's mode limit: a one-shot base GTID
/// coordinate lets only the FIRST delta true-binlog-capture, so d1 is a genuine `MysqlBinlogReplay`
/// member while d2 (incremental onto a delta parent, which records no coordinate) FULL-DUMPS as the
/// fallback — and the chain restore (newest full dump supersedes earlier binlog) yields d2's final
/// state. Also carries the crafted-escape assertion through the chain-import path: a well-formed but
/// malicious binlog-delta member in a chain is denied by the shadow-scoped apply grants and refused
/// fail-closed, the victim table + a SECOND tenant's db untouched. Marker:
/// `PROJECT EXPORT MYSQL TRUE-DELTA CHAIN OK`.
#[tokio::test]
async fn project_export_mysql_true_delta_chain_live() {
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
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL unset (live mysql true-delta CHAIN not run)");
        return;
    };
    let Some((user, password, host, port, _db)) = parse_mysql_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_MYSQL_URL is not a mysql URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live mysql true-delta CHAIN not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);
    let image = "mysql:8.0";

    let s = now_suffix();
    let live_db = format!("brexp_mytdc_live_{s}");
    let tenant_b_db = format!("brexp_mytdc_tenantb_{s}");
    let mkconn = |db: &str| MysqlConnection {
        host: host.clone(),
        port,
        user: user.clone(),
        password: password.clone(),
        database: db.to_string(),
        connect_timeout_secs: 10,
        ephemeral_network: None,
    };
    let admin = mkconn("");

    // PRECONDITION: GTID + row binlog. SELF-SKIP (like the single-delta mysql gate) when the server
    // lacks them — the preflight-matrix CHAIN gate launches mysql WITH the binlog argv and gates on
    // the marker, so a skip there FAILS the job (the marker never prints).
    let (_c, gtid_mode) =
        mysql_run(backend.as_ref(), image, &admin, None, "SELECT @@gtid_mode;").await;
    if gtid_mode.trim() != "ON" {
        eprintln!(
            "SKIP: the test MySQL is not gtid_mode=ON (binlog true-delta CHAIN gate needs \
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

    // --- the driver: a MANAGED Single/default mysql binding with delta_capture ---
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
                active_spec: None,
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

    let full = ExportOptions {
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: None,
    };
    let incr = |base: &str| ExportOptions {
        scope: boatramp_core::project_export::BundleScope::Full,
        managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
        include_identity: false,
        transport_key: None,
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: base.to_string(),
        }),
    };

    // --- BASE export: records the snapshot GTID + start binlog in mysql_capture.json ---
    drv.export_resumable("default", &full, "cbase")
        .await
        .expect("base resumable export");

    // --- round-1 mutation → d1 (incremental vs cbase): the FIRST delta true-binlog-captures ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "INSERT INTO t VALUES (4,'delta'); UPDATE t SET v='beta2' WHERE id=2; DELETE FROM t WHERE id=3;",
    )
    .await;
    assert_eq!(c, 0, "round-1 mutate: {o}");
    drv.export_resumable("default", &incr("cbase"), "d1")
        .await
        .expect("delta d1 export");
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::MysqlBinlogReplay,
        "the FIRST chain delta must binlog-capture (true-delta), not full-dump"
    );
    let bin_idx = d1_manifest
        .members
        .iter()
        .position(|m| m.path == "sql/app.mysqlbinlog" && m.kind == MemberKind::MysqlBinlogDelta)
        .expect("d1 must carry a sql/app.mysqlbinlog true-delta member");
    assert!(
        !d1_manifest.members.iter().any(|m| m.path == "sql/app.sql"),
        "d1's full mysql dump must be SUPERSEDED by the binlog delta member"
    );

    // --- round-2 mutation → d2 (incremental vs d1): a LATER link, so mysql FULL-DUMPS as the
    //     fallback (d1's dir records no GTID coordinate). The chain still restores correctly. ---
    let (c, o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "INSERT INTO t VALUES (5,'epsilon'); UPDATE t SET v='delta2' WHERE id=4; DELETE FROM t WHERE id=1;",
    )
    .await;
    assert_eq!(c, 0, "round-2 mutate: {o}");
    drv.export_resumable("default", &incr("d1"), "d2")
        .await
        .expect("delta d2 export");
    let d2_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d2").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d2_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::FullDumpFallback,
        "a LATER mysql chain link must FULL-DUMP (a one-shot base GTID cannot re-emit the interval)"
    );
    assert!(
        d2_manifest
            .members
            .iter()
            .any(|m| m.path == "sql/app.sql" && m.kind == MemberKind::MysqlDump),
        "d2 must carry a full mysql dump member (the fallback)"
    );
    assert!(
        !d2_manifest
            .members
            .iter()
            .any(|m| m.kind == MemberKind::MysqlBinlogDelta),
        "d2 (a later link) must NOT carry a binlog delta member"
    );

    // --- CRAFTED-ESCAPE THROUGH THE CHAIN: a well-formed-but-malicious binlog member (valid SQL
    //     targeting the VICTIM / foreign-tenant db) in place of d1's binlog member. The apply user
    //     (ALL on the shadow ONLY) is DENIED → `mysql` errors → the base→evil chain import is refused
    //     fail-closed, the victim + tenant B untouched (shadow dropped, no swap). ---
    let d1_dir = resumable.join("d1");
    let evil_dir = resumable.join("evil");
    std::fs::create_dir_all(&evil_dir).unwrap();
    for ent in std::fs::read_dir(&d1_dir).unwrap() {
        let ent = ent.unwrap();
        if ent.file_type().unwrap().is_file() {
            std::fs::copy(ent.path(), evil_dir.join(ent.file_name())).unwrap();
        }
    }
    let evil_sql = format!(
        "INSERT INTO `{tenant_b_db}`.b VALUES (999,'ESCAPE_ATTEMPT');\n\
         DROP TABLE `{live_db}`.victim;\n"
    );
    std::fs::write(evil_dir.join(format!("m{bin_idx:05}")), evil_sql.as_bytes()).unwrap();
    {
        use sha2::{Digest, Sha256};
        let meta = project_bundle::MemberMeta {
            size: evil_sql.len() as u64,
            sha256: hex::encode(Sha256::digest(evil_sql.as_bytes())),
        };
        std::fs::write(
            evil_dir.join(format!("m{bin_idx:05}.meta")),
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
        "a well-formed malicious binlog member in the chain MUST be refused by the shadow-scoped \
         apply grants; got: {evil_res:?}"
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
        "the crafted chain import must not touch the victim table (shadow dropped, no swap)"
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
        b_after_evil, "7:TENANT_B_SENTINEL",
        "tenant B must be untouched after the refused crafted chain import"
    );

    // --- plant a pre-import sentinel, then IMPORT THE 3-LINK CHAIN (import d2 → base → d1 → d2). The
    //     chain restore takes d2's newest full dump (superseding d1's binlog) → the FINAL state. ---
    let (c, _o) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "DELETE FROM t; INSERT INTO t VALUES (99,'SENTINEL_PRE_IMPORT');",
    )
    .await;
    assert_eq!(c, 0, "plant the pre-import sentinel");
    let report = drv
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
        .await
        .expect("3-link delta chain import (base → d1 → d2)");
    assert!(report.pg_databases >= 1, "the mysql db must be restored");
    let (_c, rows) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&live_db),
        "SELECT CONCAT(id, ':', v) FROM t ORDER BY id;",
    )
    .await;
    assert_eq!(
        rows, "2:beta2\n4:delta2\n5:epsilon",
        "the restored db must equal the MUTATED source after the WHOLE chain (both rounds) — not the \
         base, not d1's state, not the pre-import sentinel"
    );
    let (_c, b_rows) = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        Some(&tenant_b_db),
        "SELECT CONCAT(id, ':', v) FROM b ORDER BY id;",
    )
    .await;
    assert_eq!(
        b_rows, "7:TENANT_B_SENTINEL",
        "the second tenant's db must be UNTOUCHED by the chain restore"
    );

    let _ = mysql_run(
        backend.as_ref(),
        image,
        &admin,
        None,
        &format!("DROP DATABASE IF EXISTS {live_db}; DROP DATABASE IF EXISTS {tenant_b_db};"),
    )
    .await;
    println!("PROJECT EXPORT MYSQL TRUE-DELTA CHAIN OK");
}

/// The libsql changeset true-delta MULTI-DELTA CHAIN gate (in-process; feature `sql-delta-libsql`).
/// Unlike pg/mysql, libsql re-diffs a fixed base snapshot, so an INCREMENTAL chain is true-delta
/// across EVERY link: base → d1 (changeset vs base) → d2 (changeset vs d1). Proves (1) the 3-link
/// chain restores EXACTLY to the final state after BOTH mutation rounds (base snapshot + d1 changeset
/// + d2 changeset, applied in order), both links genuine `LibsqlChangeset` members; and (2) a
/// crafted changeset tampered into the MIDDLE link (d1) — carrying a write to a table OUTSIDE the
/// base schema — is REFUSED when the whole chain is imported, the target left byte-unchanged (no
/// swap) and a SECOND site untouched. Marker: `PROJECT EXPORT LIBSQL TRUE-DELTA CHAIN OK`.
#[cfg(feature = "sql-delta-libsql")]
#[tokio::test]
async fn project_export_libsql_true_delta_chain_and_crafted_escape_gate() {
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
    let blog = "blog"; // the true-delta site
    let shop = "shop"; // a SECOND site that must stay untouched

    let td = tempfile::tempdir().unwrap();
    let libsql_dir = td.path().join("handlers-sql");
    let backends = Arc::new(LibsqlSqlBackends::local(&libsql_dir));

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

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    kv.put("project/acme/current/blog", b"dep1".to_vec())
        .await
        .unwrap();
    kv.put("project/acme/current/shop", b"dep1".to_vec())
        .await
        .unwrap();
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

    // --- BASE export ---
    let full = ExportOptions::default();
    drv.export_resumable(project, &full, "cbase")
        .await
        .expect("base export");

    let incr = |base: &str| ExportOptions {
        delta: Some(DeltaRequest {
            mode: DeltaMode::Incremental,
            base_reference: base.to_string(),
        }),
        ..Default::default()
    };

    // --- round-1 mutation → d1 (incremental vs cbase): a changeset ---
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
    drv.export_resumable(project, &incr("cbase"), "d1")
        .await
        .expect("d1 export");
    let d1_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d1").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d1_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::LibsqlChangeset,
        "d1 must changeset-capture (not full-dump)"
    );
    let blog_cs_path = format!("libsql/{project}/{blog}/default.changeset");
    let d1_cs_idx = d1_manifest
        .members
        .iter()
        .position(|m| m.kind == MemberKind::LibsqlChangeset && m.path == blog_cs_path)
        .expect("d1 must carry a blog changeset member");

    // --- round-2 mutation → d2 (incremental vs d1): ANOTHER changeset (libsql true-deltas across
    //     links — the re-diffable fixed base snapshot each delta records). ---
    {
        let db: Arc<dyn SqlBackend> = backends.database(project, blog, "").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute("INSERT INTO t VALUES (5,'epsilon')", &[])
            .await
            .unwrap();
        tx.execute("UPDATE t SET v='delta2' WHERE id=4", &[])
            .await
            .unwrap();
        tx.execute("DELETE FROM t WHERE id=1", &[]).await.unwrap();
        tx.commit().await.unwrap();
    }
    drv.export_resumable(project, &incr("d1"), "d2")
        .await
        .expect("d2 export");
    let d2_manifest: project_bundle::StreamManifest =
        serde_json::from_slice(&std::fs::read(resumable.join("d2").join("MANIFEST")).unwrap())
            .unwrap();
    assert_eq!(
        d2_manifest.delta.as_ref().unwrap().sql_strategy,
        SqlDeltaKind::LibsqlChangeset,
        "d2 must ALSO changeset-capture (libsql true-deltas across chain links)"
    );
    assert!(
        d2_manifest
            .members
            .iter()
            .any(|m| m.kind == MemberKind::LibsqlChangeset && m.path == blog_cs_path),
        "d2 must carry a blog changeset member (not a full dump)"
    );

    let final_expect = vec![
        "2:beta2".to_string(),
        "4:delta2".to_string(),
        "5:epsilon".to_string(),
    ];

    // --- PART 1: clean 3-link round-trip. Plant a PRE-IMPORT sentinel in blog, import d2 (the chain
    //     base → d1 → d2), assert blog == the final state (base snapshot + d1 changeset + d2
    //     changeset, applied in order) and shop untouched. ---
    seed(&backends, project, blog, &[(99, "PRE_IMPORT")]).await;
    let report = drv
        .import_resumable(
            project,
            "d2",
            ImportOptions {
                apply: true,
                overwrite: true,
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("3-link delta chain import (base snapshot + 2 changesets)");
    assert!(
        report.libsql_databases >= 1,
        "a libsql db was restored by the changeset-chain pass"
    );
    assert_eq!(
        read_t(&backends, project, blog).await,
        final_expect,
        "blog must equal the final state after BOTH changeset links — not the base, not d1's state, \
         not the pre-import sentinel"
    );
    assert_eq!(
        read_t(&backends, project, shop).await,
        vec!["1:SHOPSENTINEL".to_string()],
        "the SECOND site (shop) must be UNTOUCHED"
    );

    // --- PART 2: CRAFTED MIDDLE-of-chain. Tamper d1's (the MIDDLE link's) changeset to carry a write
    //     to a FOREIGN table `evil`; import the whole chain (d2 → base → d1 → d2). The restore applies
    //     the base snapshot then d1's crafted changeset FIRST — whose foreign-table write is refused by
    //     the base-table confinement → the import aborts, blog byte-unchanged (no swap), shop
    //     untouched. The crafted changeset's t-portion applies cleanly against the base schema, so the
    //     FOREIGN-table write (a table absent from the base shadow) is what the confinement refuses. ---
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

    // Overwrite d1's blog changeset member + regenerate its {size,sha256} meta (so it passes the
    // integrity check and reaches the replay). d1's MANIFEST is untouched, so the chain coherence +
    // the d2→d1→base walk are intact — the ONLY tampered thing is the middle changeset's bytes.
    let obj = resumable.join("d1").join(format!("m{d1_cs_idx:05}"));
    std::fs::write(&obj, &crafted_member).unwrap();
    let sha = boatramp_core::deploy::sha256_hex(&crafted_member);
    std::fs::write(
        resumable.join("d1").join(format!("m{d1_cs_idx:05}.meta")),
        format!("{{\"size\":{},\"sha256\":\"{sha}\"}}", crafted_member.len()).as_bytes(),
    )
    .unwrap();

    // Plant a distinct sentinel so the refusal is PROVABLY a no-swap (blog stays the sentinel).
    seed(&backends, project, blog, &[(77, "CRAFTED_SENTINEL")]).await;
    let res = drv
        .import_resumable(
            project,
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
        res.is_err(),
        "a crafted MIDDLE-of-chain changeset writing a table OUTSIDE the base schema MUST be refused"
    );
    assert_eq!(
        read_t(&backends, project, blog).await,
        vec!["77:CRAFTED_SENTINEL".to_string()],
        "the refused crafted chain import left blog UNCHANGED (no partial/leaked write, no swap)"
    );
    assert_eq!(
        read_t(&backends, project, shop).await,
        vec!["1:SHOPSENTINEL".to_string()],
        "the second site must be UNTOUCHED by the refused crafted chain import"
    );

    println!("PROJECT EXPORT LIBSQL TRUE-DELTA CHAIN OK");
}

/// **Live clone self-provision on a Shared tenant** (PLAN-clone-self-provision-managed-db;
/// Tier-2 / nightly — needs a Docker daemon AND a Postgres server whose DSN user can `CREATE
/// ROLE`/`CREATE DATABASE`). Self-skips.
///
/// Reproduces construens's exact clone failure shape and proves the fix end-to-end through the
/// REAL `NodeProjectExport` driver (not a hand-rolled SQL reproduction, like the other
/// `_chunked_shadow_live` tests): ONE Shared Postgres server is ALREADY up and serving an
/// EXISTING tenant (`src`, provisioned + seeded through the shipped `provision_tenant` path,
/// exactly as a real project would be) when a clone targets a BRAND-NEW tenant project
/// (`fresh`) whose own database was NEVER provisioned on that already-healthy server —
/// construens's "database … does not exist" readiness-probe failure, reached via the SAME
/// sidecar `restore_member` arm a Shared binding's FULL dump always takes (`plan_export` frames
/// a Shared managed pg dump non-chunked). Before the fix, `driver.import(.., apply: true, ..)`
/// fails exactly that way; with the fix it self-provisions `fresh`'s own database first, so the
/// clone succeeds and the restored row matches the source.
///
/// Also proves, in the SAME run (the tenancy-gate + idempotency discipline) — and now every
/// cross-tenant assertion acts AS THE SIBLING tenant's LOGIN role (or fresh's own non-superuser
/// roles), NEVER the superuser, so a grant leak the superuser would be blind to is caught:
/// - **Restore-window negative control (the HIGH cross-tenant repro)**: while the clone runs and
///   the driver holds the shadow in existence, a concurrent loop as the sibling's login role
///   discovers the `<fresh_db>__shadow_%` names from `pg_database` and HAMMERS CONNECT attempts —
///   ZERO must succeed, the shadow's `datacl` never shows PUBLIC CONNECT, and no sibling session is
///   ever attached (the terminate-sweep ran). Non-vacuous: the prober must actually see the shadow.
/// - **Post-clone confidentiality**: the sibling cannot connect to `fresh`'s live db or read its
///   rows; `fresh`'s OWN owner + runtime roles can; `fresh`'s db has PUBLIC CONNECT revoked.
/// - **No surviving injected object**: `fresh`'s db holds no object owned by a role other than its
///   own owner/runtime roles.
/// - **Teardown**: no `<fresh_db>__shadow_%` db and no `brexp_apply_%` role remain after success.
/// - **Target-scoped only**: a THIRD, pre-existing tenant (`other`) is seeded and verified
///   UNCHANGED after the clone into `fresh` — self-provisioning `fresh` must never create,
///   touch, or affect `other`'s database.
/// - **Idempotent**: importing the SAME bundle into the now-provisioned `fresh` AGAIN
///   (`overwrite: true`) succeeds with no clobber/error — a retry-safe re-provision.
#[tokio::test]
async fn project_export_clone_self_provisions_a_fresh_shared_tenant_live() {
    use async_trait::async_trait;
    use boatramp_core::compute::{
        Endpoint, InstanceHandle, ObservedInstance, Readiness, ReplicaPhase, Scheme,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
    use boatramp_core::project_export::{
        ExportOptions, IdentityChoice, ImportOptions, ProjectExport,
    };
    use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
    use boatramp_node::managed_sql::{ManagedSqlCredentials, NodeOperatorSql};
    use boatramp_node::project_export::NodeProjectExport;
    use boatramp_node::tenant_sql::provision_tenant;
    use boatramp_storage::tenant_provision::{
        sanitize_ident, tenant_db_name, tenant_owner_role_name, tenant_role_name,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (live clone self-provision not run)");
        return;
    };
    let Some((superuser, su_password, host, port, maint_db)) = parse_pg_url(&url) else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL is not a postgres://user:pw@host:port/db URL");
        return;
    };
    let backend = match DockerBackend::connect() {
        Ok(b) if b.reachable().await => b,
        _ => {
            eprintln!("SKIP: no reachable Docker daemon (live clone self-provision not run)");
            return;
        }
    };
    let backend: Arc<dyn ComputeBackend> = Arc::new(backend);

    const COMPUTE: &str = "pg";
    const DB_BINDING: &str = "app";
    const DATABASE: &str = "clonesp";
    let s = now_suffix();
    let src_project = format!("clonesp-src-{s}");
    let fresh_project = format!("clonesp-fresh-{s}");
    let other_project = format!("clonesp-other-{s}");

    let maint = conn(&superuser, &su_password, &host, port, &maint_db);
    let (code, ver) = psql(
        backend.as_ref(),
        "postgres:16",
        &maint,
        "SHOW server_version_num",
    )
    .await;
    assert_eq!(code, 0, "SHOW server_version_num; is the DSN reachable?");
    let image = pg_client_image_for_server_version(&ver).expect("version maps to a client image");

    // --- control plane: MemoryKv + a throwaway FsStorage-backed DeployStore + a reversible
    // test envelope (mirrors `repair_reconcile_pg_live.rs`'s established live-gate fixture). ---
    struct RevEnvelope;
    #[async_trait]
    impl KeyEnvelope for RevEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().rev().copied().collect())
        }
        async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(w.iter().rev().copied().collect())
        }
    }
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-clone-selfprov-{s}")),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    // Pre-seal the SUPERUSER credential under the SAME key `provision_shared` + the server-init
    // env injector read — `(DEFAULT_PROJECT, COMPUTE)` — to the test URL's ACTUAL password (a
    // plain `.password()` would mint a random one the real server would reject).
    let sealed_su = envelope
        .wrap(su_password.as_bytes())
        .await
        .expect("seal superuser pw");
    kv.put(
        &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
        sealed_su,
    )
    .await
    .expect("pre-seal superuser credential");

    // Seed ONE healthy, ALREADY-Provisioned replica of the `pg` workload pointing at the test
    // Postgres — "the shared server is already up," exactly construens's shape. No container is
    // launched; the resolver just needs a healthy endpoint in the deploy store.
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-pg".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: host.clone(),
                    port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .expect("seed healthy replica");

    let binding = ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.clone()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };
    let databases = BTreeMap::from([(DB_BINDING.to_string(), binding.clone())]);

    let db_name = |project: &str| tenant_db_name(DATABASE, &sanitize_ident(project));
    let direct = |db: &str| conn(&superuser, &su_password, &host, port, db);

    // Teardown any prior run (re-runnable).
    for p in [&src_project, &fresh_project, &other_project] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", db_name(p)),
        )
        .await;
    }

    // === Provision + seed the SOURCE and the OTHER (pre-existing sibling) tenant through the
    // SHIPPED path — exactly as a normal first managed-sql access would. ===
    provision_tenant(&deploy, &kv, &envelope, &binding, &src_project, "")
        .await
        .expect("provision source tenant");
    provision_tenant(&deploy, &kv, &envelope, &binding, &other_project, "")
        .await
        .expect("provision the pre-existing sibling tenant");

    let (code, _) = psql(
        backend.as_ref(),
        &image,
        &direct(&db_name(&src_project)),
        "CREATE TABLE t(id int primary key, v text); INSERT INTO t VALUES (1,'alpha'),(2,'beta');",
    )
    .await;
    assert_eq!(code, 0, "seed source tenant table");
    let (code, _) = psql(
        backend.as_ref(),
        &image,
        &direct(&db_name(&other_project)),
        "CREATE TABLE t(id int primary key, v text); INSERT INTO t VALUES (99,'untouched');",
    )
    .await;
    assert_eq!(code, 0, "seed the pre-existing sibling tenant");
    let other_before = psql(
        backend.as_ref(),
        &image,
        &direct(&db_name(&other_project)),
        "SELECT id || ':' || v FROM t ORDER BY id",
    )
    .await
    .1;

    // --- the driver, wired exactly like the normal serve path (managed pg context). ---
    let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(NodeOperatorSql::new(
        databases.clone(),
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let work = std::env::temp_dir().join(format!("boatramp-clone-selfprov-work-{s}"));
    std::fs::create_dir_all(&work).unwrap();
    let blobs: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-clone-selfprov-blobs-{s}")),
    ));
    // Hold the SHARED shadow in existence (CREATED + LOCKED DOWN) for a few seconds so the
    // concurrent sibling prober below can observe it and prove a sibling can never CONNECT to it —
    // the direct repro of the HIGH restore-window finding. Test-only (inert in production).
    const SHADOW_WINDOW_DELAY_MS: u64 = 6_000;
    let driver = NodeProjectExport::new(databases, deploy.clone(), kv.clone(), blobs, work)
        .with_managed_pg(backend.clone(), envelope.clone(), op, false)
        .with_shadow_restore_test_delay_ms(SHADOW_WINDOW_DELAY_MS);

    // === The SIBLING tenant's real LOGIN role + password (never the superuser) — the identity the
    // cross-tenant assertions act as. `other` is a legitimate, already-provisioned sibling on the
    // SAME shared cluster; its login role can connect to its OWN database and read the world-readable
    // `pg_database`, but must be unable to reach `fresh`'s shadow or live db. ===
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let other_ident = sanitize_ident(&other_project);
    let other_role = tenant_role_name(COMPUTE, &other_ident);
    let other_pw = creds
        .password(&other_project, &format!("{COMPUTE}/{other_ident}"))
        .await
        .expect("sibling login credential");
    let other_login = conn(
        &other_role,
        &other_pw,
        &host,
        port,
        &db_name(&other_project),
    );
    let fresh_db = db_name(&fresh_project);
    // The driver bounds the shadow name to Postgres's 63-byte NAMEDATALEN by TRUNCATING the live-db
    // prefix while keeping the full `__shadow_<suffix>` distinguisher (see `bounded_derived_db_name`),
    // so a tenant-qualified `fresh_db` (already ~62 bytes) no longer appears verbatim in the shadow
    // name — a `'{fresh_db}__shadow_%'` LIKE would never match. Discover the shadow by a
    // guaranteed-retained prefix of `fresh_db` + the intact `__shadow_` marker. The helper always
    // keeps `>= 63 - len("__shadow_") - len(suffix)` (~27) bytes of the live prefix, so the first 20
    // bytes of `fresh_db` are always present; the `%` then spans the truncation point + the suffix.
    // This import is the only one on the cluster, so no sibling shadow can match this pattern.
    let fresh_prefix: String = fresh_db.chars().take(20).collect();
    let shadow_like = format!("{fresh_prefix}%__shadow_%");

    // === EXPORT the source tenant (FULL) through the driver — a Shared binding frames its pg
    // dump SIDECAR (non-chunked), the exact member shape `restore_member`'s PgDump arm handles. ===
    let bundle = {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        driver
            .export(
                &src_project,
                &ExportOptions {
                    scope: boatramp_core::project_export::BundleScope::Full,
                    managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
                    include_identity: false,
                    transport_key: None,
                    delta: None,
                },
                &mut sink,
            )
            .await
            .expect("driver export of the source tenant");
        sink.into_inner()
    };

    // === IMPORT into the BRAND-NEW `fresh` tenant — construens's exact shape: its own db was
    // NEVER provisioned on the already-healthy shared server. Before the fix this fails with the
    // readiness-probe "database … does not exist"; with the fix it self-provisions first.
    //
    // RESTORE-WINDOW NEGATIVE CONTROL (the direct repro of the HIGH cross-tenant finding): while the
    // clone runs — the driver HOLDS the shadow in existence for `SHADOW_WINDOW_DELAY_MS` after it is
    // created + locked down — a concurrent loop acts AS THE SIBLING tenant's login role, discovers
    // the `<fresh_db>__shadow_%` names from the world-readable `pg_database`, and HAMMERS CONNECT
    // attempts at them. The gate: ZERO successful sibling connects for the clone's whole duration
    // (every attempt must be `permission denied for database`), the shadow's `datacl` never shows
    // PUBLIC CONNECT, and the shadow never carries a sibling session (the terminate-sweep ran). On
    // the pre-fix shape (PUBLIC-CONNECT left on the shadow across a separate-container CREATE→REVOKE
    // gap, no terminate-sweep) a sibling connects during this window and the gate FAILS; with the fix
    // (gap-free CREATE+REVOKE+sweep, plus a pre-restore sweep) it holds. `shadow_sightings > 0` makes
    // the control non-vacuous: the prober MUST have actually seen the shadow while it existed. ===
    let done = Arc::new(AtomicBool::new(false));
    let import_fut = {
        let done = done.clone();
        let driver = &driver;
        let bundle = bundle.clone();
        let fresh_project = fresh_project.clone();
        async move {
            let mut source = futures::io::Cursor::new(bundle);
            let r = driver
                .import(
                    &fresh_project,
                    &mut source,
                    ImportOptions {
                        apply: true,
                        force: true,
                        overwrite: false, // a genuinely fresh target — no prior data to overlay.
                        identity: IdentityChoice::Fresh,
                        ..Default::default()
                    },
                )
                .await;
            done.store(true, Ordering::SeqCst);
            r
        }
    };
    let probe_fut = {
        let backend = backend.clone();
        let image = image.clone();
        let done = done.clone();
        let other_login = other_login.clone();
        let other_role = other_role.clone();
        let other_pw = other_pw.clone();
        let shadow_like = shadow_like.clone();
        let host = host.clone();
        async move {
            let mut sightings = 0u32;
            let mut connect_successes: Vec<String> = Vec::new();
            let mut public_connectable: Vec<String> = Vec::new();
            let mut sibling_sessions: Vec<String> = Vec::new();
            while !done.load(Ordering::SeqCst) {
                // Enumerate the live shadow(s) AS THE SIBLING (pg_database is world-readable).
                let (_c, listing) = psql(
                    backend.as_ref(),
                    &image,
                    &other_login,
                    &format!("SELECT datname FROM pg_database WHERE datname LIKE '{shadow_like}'"),
                )
                .await;
                for shadow in listing.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    sightings += 1;
                    // (a) a DIRECT connect attempt to the shadow as the sibling role — must be
                    // refused. `psql` exits non-zero on a refused connect (merged stderr carries
                    // "permission denied for database"); code == 0 means it got IN (a leak).
                    let sconn = conn(&other_role, &other_pw, &host, port, shadow);
                    let (code, out) = psql(backend.as_ref(), &image, &sconn, "SELECT 1").await;
                    if code == 0 {
                        connect_successes.push(format!("{shadow} => {out}"));
                    }
                    // (b) datacl + session witnesses, both read AS THE SIBLING from the global
                    // catalogs: PUBLIC must NOT hold CONNECT on the shadow, and no sibling session
                    // may be attached to it (proves REVOKE + the terminate-sweep held).
                    let (_c2, witness) = psql(
                        backend.as_ref(),
                        &image,
                        &other_login,
                        &format!(
                            "SELECT has_database_privilege('public', '{shadow}', 'CONNECT') || '|' \
                             || (SELECT count(*) FROM pg_stat_activity WHERE datname = '{shadow}' \
                             AND usename = '{other_role}')"
                        ),
                    )
                    .await;
                    if let Some((pub_conn, sib_sessions)) = witness.trim().split_once('|') {
                        if pub_conn.trim() == "t" {
                            public_connectable.push(shadow.to_string());
                        }
                        if sib_sessions.trim() != "0" {
                            sibling_sessions.push(format!(
                                "{shadow} has {} sibling session(s)",
                                sib_sessions.trim()
                            ));
                        }
                    }
                }
            }
            (
                sightings,
                connect_successes,
                public_connectable,
                sibling_sessions,
            )
        }
    };
    let (import_res, (sightings, connect_successes, public_connectable, sibling_sessions)) =
        tokio::join!(import_fut, probe_fut);
    let report = import_res.expect(
        "clone into a fresh, never-provisioned Shared tenant must now self-provision \
         and succeed (construens's failure shape, fixed)",
    );
    assert!(
        report.pg_databases >= 1,
        "the clone restored at least one pg database"
    );
    // The negative control is non-vacuous: the prober genuinely observed the shadow while it existed.
    assert!(
        sightings > 0,
        "the restore-window prober never saw a {shadow_like} database — the window was not \
         exercised (vacuous); raise SHADOW_WINDOW_DELAY_MS"
    );
    assert!(
        connect_successes.is_empty(),
        "CROSS-TENANT LEAK: the sibling tenant CONNECTED to the restoring shadow during the clone \
         window ({sightings} sighting(s)): {connect_successes:?}"
    );
    assert!(
        public_connectable.is_empty(),
        "the shadow had PUBLIC CONNECT during the window (datacl not locked down): {public_connectable:?}"
    );
    assert!(
        sibling_sessions.is_empty(),
        "a sibling session was attached to the shadow (terminate-sweep did not evict it): {sibling_sessions:?}"
    );

    // ROW equality on the newly self-provisioned target.
    let got = psql(
        backend.as_ref(),
        &image,
        &direct(&db_name(&fresh_project)),
        "SELECT id || ':' || v FROM t ORDER BY id",
    )
    .await
    .1;
    assert_eq!(
        got, "1:alpha\n2:beta",
        "fresh tenant restored the source's rows"
    );

    // === POST-CLONE CONFIDENTIALITY (as the SIBLING + as FRESH's OWN roles, never the superuser).
    // The cloned live db must be grant-isolated EXACTLY like a freshly-provisioned tenant db: the
    // sibling cannot connect to it or read its rows; fresh's own roles can; PUBLIC CONNECT is off. ===
    let fresh_ident = sanitize_ident(&fresh_project);
    let fresh_login_role = tenant_role_name(COMPUTE, &fresh_ident);
    let fresh_login_pw = creds
        .password(&fresh_project, &format!("{COMPUTE}/{fresh_ident}"))
        .await
        .expect("fresh login credential (minted at self-provision)");
    let fresh_owner_role = tenant_owner_role_name(COMPUTE, &fresh_ident);
    let fresh_owner_pw = creds
        .password(&fresh_project, &format!("{COMPUTE}/{fresh_ident}/owner"))
        .await
        .expect("fresh owner credential (minted at self-provision)");

    // The sibling tenant CANNOT connect to fresh's live db and so cannot read its rows.
    let (code, out) = psql(
        backend.as_ref(),
        &image,
        &conn(&other_role, &other_pw, &host, port, &fresh_db),
        "SELECT count(*) FROM t",
    )
    .await;
    assert_ne!(
        code, 0,
        "CROSS-TENANT LEAK: the sibling connected to fresh's live db + read its rows: {out}"
    );
    assert!(
        out.contains("permission denied for database"),
        "the sibling must be refused at CONNECT to fresh's live db (got: {out})"
    );
    // fresh's OWN runtime + owner roles CAN connect (the re-provision re-granted them).
    let (code, _) = psql(
        backend.as_ref(),
        &image,
        &conn(&fresh_login_role, &fresh_login_pw, &host, port, &fresh_db),
        "SELECT 1",
    )
    .await;
    assert_eq!(
        code, 0,
        "fresh's own runtime role must be able to connect to its db"
    );
    let (code, _) = psql(
        backend.as_ref(),
        &image,
        &conn(&fresh_owner_role, &fresh_owner_pw, &host, port, &fresh_db),
        "SELECT 1",
    )
    .await;
    assert_eq!(
        code, 0,
        "fresh's own owner role must be able to connect to its db"
    );
    // PUBLIC CONNECT is revoked on the live cloned db (read AS THE SIBLING from the global catalog).
    let (_c, pub_conn) = psql(
        backend.as_ref(),
        &image,
        &other_login,
        &format!("SELECT has_database_privilege('public', '{fresh_db}', 'CONNECT')"),
    )
    .await;
    assert_eq!(
        pub_conn.trim(),
        "f",
        "the cloned live db must have PUBLIC CONNECT revoked (datacl) like a provisioned tenant"
    );

    // === NO SURVIVING INJECTED OBJECT: every object in a non-system schema of the cloned db is
    // owned by fresh's OWN owner/runtime roles — never a sibling/intruder role (connected as fresh's
    // OWN owner role, the natural non-superuser identity that can read its own db's catalog). ===
    let (code, foreign_objs) = psql(
        backend.as_ref(),
        &image,
        &conn(&fresh_owner_role, &fresh_owner_pw, &host, port, &fresh_db),
        &format!(
            "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast') \
             AND c.relkind IN ('r','v','m','S','p') \
             AND r.rolname NOT IN ('{fresh_owner_role}','{fresh_login_role}')"
        ),
    )
    .await;
    assert_eq!(code, 0, "enumerate fresh's objects as its own owner role");
    assert_eq!(
        foreign_objs.trim(),
        "0",
        "an object owned by a role other than fresh's owner/runtime roles survived the clone \
         (a possible in-window injected object): {foreign_objs}"
    );

    // TENANCY GATE: the pre-existing sibling tenant is byte-for-byte UNCHANGED.
    let other_after = psql(
        backend.as_ref(),
        &image,
        &direct(&db_name(&other_project)),
        "SELECT id || ':' || v FROM t ORDER BY id",
    )
    .await
    .1;
    assert_eq!(
        other_after, other_before,
        "self-provisioning the fresh target must not touch the pre-existing sibling tenant"
    );

    // IDEMPOTENCY: re-importing the SAME bundle into the now-provisioned `fresh` target is a
    // clean, no-clobber success (retry-safe).
    let report2 = {
        let mut source = futures::io::Cursor::new(bundle);
        driver
            .import(
                &fresh_project,
                &mut source,
                ImportOptions {
                    apply: true,
                    force: true,
                    overwrite: true, // now has prior data from the first import.
                    identity: IdentityChoice::Fresh,
                    ..Default::default()
                },
            )
            .await
            .expect("re-importing into an already-provisioned target is idempotent")
    };
    assert!(
        report2.pg_databases >= 1,
        "the re-import still restored the pg database"
    );
    let got_again = psql(
        backend.as_ref(),
        &image,
        &direct(&db_name(&fresh_project)),
        "SELECT id || ':' || v FROM t ORDER BY id",
    )
    .await
    .1;
    assert_eq!(
        got_again, "1:alpha\n2:beta",
        "idempotent re-import — rows unchanged, no clobber"
    );

    // === TEARDOWN: after a successful clone, NEITHER a transient shadow database NOR the ephemeral
    // apply role survives (the swap renamed the shadow in + dropped the eph role; a failure path
    // would have dropped the shadow). Read AS THE SIBLING from the world-readable catalogs. ===
    let (_c, leftover_shadows) = psql(
        backend.as_ref(),
        &image,
        &other_login,
        &format!("SELECT count(*) FROM pg_database WHERE datname LIKE '{shadow_like}'"),
    )
    .await;
    assert_eq!(
        leftover_shadows.trim(),
        "0",
        "a {shadow_like} shadow database leaked past a successful clone: {leftover_shadows}"
    );
    let (_c, leftover_roles) = psql(
        backend.as_ref(),
        &image,
        &other_login,
        "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'brexp_apply_%'",
    )
    .await;
    assert_eq!(
        leftover_roles.trim(),
        "0",
        "an ephemeral brexp_apply_% apply role leaked past a successful clone: {leftover_roles}"
    );

    // --- cleanup (best-effort) ---
    for p in [&src_project, &fresh_project, &other_project] {
        let _ = psql(
            backend.as_ref(),
            &image,
            &maint,
            &format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", db_name(p)),
        )
        .await;
    }

    println!("PROJECT EXPORT CLONE SELF-PROVISION SHARED TENANT OK");
}
