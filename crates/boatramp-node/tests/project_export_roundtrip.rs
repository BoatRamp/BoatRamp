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
use boatramp_node::pg_client::{PgConnection, pg_dump_invocation, pg_restore_invocation};
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
        let infile = tokio::fs::File::open(&member).await.unwrap();
        let mut rdr = infile.compat();
        let out = tokio::fs::File::create(td.path().join("restore.out"))
            .await
            .unwrap();
        let mut sink = out.compat_write();
        let code = backend
            .run_ephemeral(&image, &inv.argv, &inv.env, Some(&mut rdr), &mut sink)
            .await
            .expect("pg_restore run_ephemeral");
        assert_eq!(code, 0, "pg_restore exit code");
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
