//! **Live gate: the schema-migration owner role is bounded to project-owner authority.**
//!
//! The owner-gated migration surface runs DDL as a dedicated per-project **owner role**, NOT the
//! cluster superuser — the constraint that makes it soundable on a Shared multi-tenant server. This
//! gate stands up the REAL three-identity model produced by [`provision_ddl`] + [`grant_app_role_ddl`]
//! on a real Postgres and proves, at the SQL/privilege level:
//!
//! 1. **Owner-role confinement** — as the owner role, a legitimate migration (CREATE TABLE + FORCE
//!    RLS + policy) succeeds, but every cluster-escape primitive is DENIED by privilege:
//!    `CREATE DATABASE`, `CREATE ROLE`, `ALTER ROLE … SUPERUSER`, `COPY … TO PROGRAM`,
//!    `CREATE EXTENSION dblink` (untrusted), `pg_read_file`. Pinning the DSN was never the boundary
//!    — the non-superuser role is.
//! 2. **Runtime role default-privileges + non-owner** — the runtime login role can DML the table the
//!    owner-role migration created (so `grant_app_role_ddl`'s owner-keyed `ALTER DEFAULT PRIVILEGES`
//!    fired), but CANNOT `DROP`/`ALTER` it (it is a non-owner) and is `NOBYPASSRLS`.
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset). Prints
//! `MIGRATE OWNER-ROLE CONFINEMENT OK [postgres]` on success (the CI grep marker).

#![cfg(feature = "sql-postgres")]

use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{grant_app_role_ddl, provision_ddl};

const DB: &str = "mig_appdb";
const ROLE: &str = "mig_role";
const ROLE_PW: &str = "rolepw";
const OWNER: &str = "mig_owner";
const OWNER_PW: &str = "0wnerpw";

/// Rewrite a superuser URL to connect as `user`/`pw` to database `db` (the harness pattern:
/// swap the leading `user:pass@` and the trailing `/db`).
fn as_role(su_url: &str, user: &str, pw: &str, db: &str) -> String {
    // Swap creds: everything before the first `@` after `//`.
    let (scheme, rest) = su_url.split_once("://").expect("url has scheme");
    let after_at = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
    // after_at = host[:port]/dbname[?params]; replace the /dbname path segment with /db.
    let (hostport, _tail) = after_at.split_once('/').unwrap_or((after_at, ""));
    format!("{scheme}://{user}:{pw}@{hostport}/{db}")
}

#[tokio::test]
async fn migrate_owner_role_is_confined_to_project_owner_authority() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip migrate_owner_role: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let su = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_url.clone()),
    )
    .unwrap();

    // --- teardown any prior run (re-runnable): drop the db, then the roles. ---
    for stmt in [
        &format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        &format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        &format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(stmt).await;
    }

    // --- setup: run the REAL provisioning DDL (three-identity) as superuser on the maintenance db,
    //     then the owner-keyed app grants inside the tenant db. ---
    for stmt in provision_ddl(
        ExternalSqlKind::Postgres,
        DB,
        ROLE,
        ROLE_PW,
        OWNER,
        OWNER_PW,
    ) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision `{stmt}`: {e}"));
    }
    // Reconnect to the tenant db AS THE SUPERUSER (same creds from su_url, switched database) to run
    // the owner-keyed app grants inside it.
    let su_tenant_url = {
        let (scheme, rest) = su_url.split_once("://").unwrap();
        let (creds, after) = rest.split_once('@').unwrap();
        let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
        format!("{scheme}://{creds}@{hostport}/{DB}")
    };
    let su_tenant = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_tenant_url),
    )
    .unwrap();
    for stmt in grant_app_role_ddl(ExternalSqlKind::Postgres, ROLE, OWNER) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("grant `{stmt}`: {e}"));
    }

    // --- (1) as the OWNER role: a legit migration works; every escape is DENIED by privilege. ---
    let owner = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(as_role(&su_url, OWNER, OWNER_PW, DB)),
    )
    .unwrap();

    // Legitimate owner-authority migration DDL succeeds.
    for stmt in [
        "CREATE TABLE note (tenant_id text NOT NULL, body text NOT NULL)",
        "ALTER TABLE note ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE note FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON note USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true))",
    ] {
        owner
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("owner legit DDL `{stmt}`: {e}"));
    }

    // Every cluster-escape / superuser-only primitive MUST be denied to the non-superuser owner.
    let escapes = [
        "CREATE DATABASE mig_escape",
        "CREATE ROLE mig_evil LOGIN",
        &format!("ALTER ROLE \"{OWNER}\" SUPERUSER"),
        "COPY (SELECT 1) TO PROGRAM 'id'",
        "CREATE EXTENSION dblink",
        "CREATE EXTENSION postgres_fdw",
        "SELECT pg_read_file('/etc/hostname')",
    ];
    for stmt in escapes {
        let r = owner.run_script(stmt).await;
        assert!(
            r.is_err(),
            "owner role must be DENIED `{stmt}` (it is not a superuser) — got Ok, a confinement breach"
        );
    }

    // --- (2) as the RUNTIME role: default-privileges fired (can DML the owner's table), but it is a
    //     non-owner (can't DROP/ALTER) and is RLS-subject. ---
    let app = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(as_role(&su_url, ROLE, ROLE_PW, DB)),
    )
    .unwrap();
    // DML works — the owner-keyed ALTER DEFAULT PRIVILEGES granted the runtime role SELECT/INSERT/…
    // on the owner-created table (the load-bearing R2 fix; without it this is `permission denied`).
    {
        let mut tx = app.begin().await.unwrap();
        tx.execute("SELECT set_config('app.tenant_id','A',true)", &[])
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO note (tenant_id, body) VALUES ('A','a-own')",
            &[],
        )
        .await
        .expect("runtime role may DML the owner-created table (default privileges fired)");
        tx.rollback().await.unwrap();
    }
    // The runtime role is a NON-OWNER: it cannot DROP or ALTER the owner's table.
    assert!(
        app.run_script("DROP TABLE note").await.is_err(),
        "runtime role must NOT be able to DROP the owner's table (non-owner)"
    );
    assert!(
        app.run_script("ALTER TABLE note ADD COLUMN sneaky text")
            .await
            .is_err(),
        "runtime role must NOT be able to ALTER the owner's table (non-owner)"
    );
    // And it cannot escalate either.
    assert!(
        app.run_script(&format!("ALTER ROLE \"{ROLE}\" SUPERUSER"))
            .await
            .is_err(),
        "runtime role must NOT be able to grant itself SUPERUSER"
    );

    // Teardown (best-effort).
    let _ = su
        .run_script(&format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"))
        .await;
    let _ = su
        .run_script(&format!("DROP ROLE IF EXISTS \"{ROLE}\""))
        .await;
    let _ = su
        .run_script(&format!("DROP ROLE IF EXISTS \"{OWNER}\""))
        .await;

    println!("MIGRATE OWNER-ROLE CONFINEMENT OK [postgres]");
}
