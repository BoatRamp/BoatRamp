//! Pure builders for the **SQL export/import client invocation** (Postgres + MySQL) that
//! the driver runs inside
//! [`run_ephemeral`](boatramp_core::compute::ComputeBackend::run_ephemeral): the `argv`
//! and the process environment.
//!
//! ## The credential non-leak rule lives here
//! The password rides in an **environment variable** (`PGPASSWORD` for Postgres,
//! `MYSQL_PWD` for MySQL), NEVER in argv. Both argv and the container environment are
//! visible to a privileged `docker inspect`, but argv leaks far more broadly — it shows
//! in every process listing (`ps`, `/proc/<pid>/cmdline`) inside and outside the
//! container, to any local observer, no daemon privilege required — whereas the
//! container environment is only reachable with daemon/inspect access. Env is therefore
//! the smaller exposure (not zero), and it is the right choice over argv. No DSN string
//! is assembled at all: the discrete `PG*` / `MYSQL*` connection variables connect the
//! client, so there is no connection string to accidentally `format!` into a log. The
//! only secret is the password env var.
//!
//! ## `--data-only` vs full
//! `--data-only` emits/restores ONLY the table data; the target keeps its OWN migrated
//! schema (Phase 1 is data-only: app data, no identity/RBAC/routing). A full export
//! carries schema + data. `--no-owner`/`--no-privileges` keep a restore from trying to
//! reassign ownership/ACLs across environments, and `pg_restore --exit-on-error` makes a
//! failed object abort loudly rather than leave a half-restored database.
//!
//! Kept pure so the data-only divergence and the cred-placement invariant are
//! unit-mutation-gated in the merge gate.

/// A resolved Postgres connection target for the client. Assembled by the driver from
/// the sealed-credential unseal + the resolved replica endpoint; consumed only to emit
/// the `PG*` environment.
#[derive(Debug, Clone)]
pub struct PgConnection {
    /// The reachable host (an external DSN host, or a colocated DB's container bridge IP).
    pub host: String,
    /// The server port.
    pub port: u16,
    /// The role to connect as.
    pub user: String,
    /// The password — the ONLY secret; it goes in `PGPASSWORD`, never argv.
    pub password: String,
    /// The physical database to dump/restore.
    pub database: String,
    /// A bounded connect timeout (seconds) so a dump/restore against an unreachable DSN
    /// fails fast instead of pinning the ephemeral container until the backstop.
    pub connect_timeout_secs: u32,
}

impl PgConnection {
    /// The discrete `PG*` connection environment. The password is here (in the
    /// environment), never in argv.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("PGHOST".to_string(), self.host.clone()),
            ("PGPORT".to_string(), self.port.to_string()),
            ("PGUSER".to_string(), self.user.clone()),
            ("PGPASSWORD".to_string(), self.password.clone()),
            ("PGDATABASE".to_string(), self.database.clone()),
            (
                "PGCONNECT_TIMEOUT".to_string(),
                self.connect_timeout_secs.to_string(),
            ),
        ]
    }
}

/// A fully-built client invocation: the `argv` (no credential) + the environment (the
/// credential), ready to hand to `run_ephemeral(image, argv, env, …)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlInvocation {
    /// The command + args — NEVER carries a credential.
    pub argv: Vec<String>,
    /// The process environment — carries `PGPASSWORD`.
    pub env: Vec<(String, String)>,
}

/// Build the `pg_dump` invocation for an EXPORT. Custom format (`-Fc`): compressed and
/// the natural input to `pg_restore`. `--data-only` emits only the data AND EXCLUDES the
/// host-owned migration ledger's rows (`boatramp_migrations.*`): the ledger is a schema
/// INSIDE the tenant database, so a plain `--data-only` dump would carry its rows and a
/// `pg_restore --data-only --exit-on-error` into the already-migrated target (the
/// matching-fingerprint case — the PRIMARY use) would hit a primary-key conflict on the
/// ledger and abort. Excluding it keeps the target's own `boatramp_migrations` ledger
/// intact (the stated property).
pub fn pg_dump_invocation(conn: &PgConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec![
        "pg_dump".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        "-Fc".to_string(),
    ];
    if data_only {
        argv.push("--data-only".to_string());
        // Exclude the host-owned migration ledger's DATA (schema-qualified pattern) so
        // the restore does not collide with the target's existing ledger rows.
        argv.push("--exclude-table-data=boatramp_migrations.*".to_string());
    }
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the `pg_restore` invocation for an IMPORT (reads the custom-format dump from
/// stdin). `--data-only` restores only the data into the target's existing migrated
/// schema; `--exit-on-error` aborts loudly on the first failed object.
pub fn pg_restore_invocation(conn: &PgConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec![
        "pg_restore".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        "--exit-on-error".to_string(),
    ];
    if data_only {
        argv.push("--data-only".to_string());
    }
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// A resolved MySQL connection target for the client. The password goes in `MYSQL_PWD`
/// (the env the mysql/mysqldump clients read), never argv.
#[derive(Debug, Clone)]
pub struct MysqlConnection {
    /// The reachable host.
    pub host: String,
    /// The server port.
    pub port: u16,
    /// The role to connect as.
    pub user: String,
    /// The password — the ONLY secret; it goes in `MYSQL_PWD`, never argv.
    pub password: String,
    /// The physical database to dump/restore.
    pub database: String,
    /// A bounded connect timeout (seconds).
    pub connect_timeout_secs: u32,
}

impl MysqlConnection {
    /// The discrete `MYSQL*` connection environment. `MYSQL_PWD` carries the password
    /// (never argv); the rest name the host/port/user so no DSN string is built.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("MYSQL_HOST".to_string(), self.host.clone()),
            ("MYSQL_TCP_PORT".to_string(), self.port.to_string()),
            ("MYSQL_USER".to_string(), self.user.clone()),
            ("MYSQL_PWD".to_string(), self.password.clone()),
        ]
    }

    /// The `--connect-timeout=<secs>` arg both clients accept (there is no env for it).
    fn connect_timeout_arg(&self) -> String {
        format!("--connect-timeout={}", self.connect_timeout_secs)
    }
}

/// Build the `mysqldump` invocation for an EXPORT. `--single-transaction` takes a
/// consistent snapshot without locking (InnoDB); `--no-tablespaces` avoids the `PROCESS`
/// privilege requirement. A FULL dump emits schema + data under `--databases <db>` (so
/// the stream carries `CREATE DATABASE`/`USE`); `--data-only` emits only the rows for
/// `<db>` (`--no-create-info`), restored into the target's existing schema.
pub fn mysqldump_invocation(conn: &MysqlConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec![
        "mysqldump".to_string(),
        "--single-transaction".to_string(),
        "--no-tablespaces".to_string(),
        conn.connect_timeout_arg(),
    ];
    if data_only {
        argv.push("--no-create-info".to_string());
        argv.push(conn.database.clone());
    } else {
        argv.push("--databases".to_string());
        argv.push(conn.database.clone());
    }
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the `mysql` invocation for an IMPORT (reads the SQL dump from stdin). A FULL
/// bundle's dump carries its own `USE <db>` (from `--databases`), so no positional db is
/// needed; a `--data-only` dump has none, so the target `<db>` is named on the command
/// line. The database name is NOT a credential, so passing it in argv is fine.
pub fn mysql_restore_invocation(conn: &MysqlConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec!["mysql".to_string(), conn.connect_timeout_arg()];
    if data_only {
        argv.push(conn.database.clone());
    }
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> PgConnection {
        PgConnection {
            host: "10.0.0.5".to_string(),
            port: 5432,
            user: "svc".to_string(),
            password: "sup3r-s3cret-pw".to_string(),
            database: "app".to_string(),
            connect_timeout_secs: 10,
        }
    }

    #[test]
    fn data_only_toggles_the_flag_on_both_sides() {
        // The data-only path MUST diverge from the full path (anti-hollow mutation (b):
        // drop the data_only honoring and this divergence vanishes).
        let dump_do = pg_dump_invocation(&conn(), true);
        let dump_full = pg_dump_invocation(&conn(), false);
        assert!(dump_do.argv.iter().any(|a| a == "--data-only"));
        assert!(!dump_full.argv.iter().any(|a| a == "--data-only"));
        // A --data-only dump EXCLUDES the migration ledger's rows so a restore into an
        // already-migrated target does not PK-conflict on it; a full dump does not.
        assert!(
            dump_do
                .argv
                .iter()
                .any(|a| a == "--exclude-table-data=boatramp_migrations.*")
        );
        assert!(
            !dump_full
                .argv
                .iter()
                .any(|a| a == "--exclude-table-data=boatramp_migrations.*")
        );

        let restore_do = pg_restore_invocation(&conn(), true);
        let restore_full = pg_restore_invocation(&conn(), false);
        assert!(restore_do.argv.iter().any(|a| a == "--data-only"));
        assert!(!restore_full.argv.iter().any(|a| a == "--data-only"));
    }

    #[test]
    fn credential_is_in_the_env_never_in_argv() {
        let c = conn();
        for inv in [
            pg_dump_invocation(&c, true),
            pg_restore_invocation(&c, false),
        ] {
            // The password is present in the environment...
            assert!(
                inv.env
                    .iter()
                    .any(|(k, v)| k == "PGPASSWORD" && v == &c.password),
                "PGPASSWORD must be set in the environment"
            );
            // ...and NEVER appears in argv (which shows in ps/inspect). This is the
            // non-leak invariant; a regression that put the password on the command
            // line fails here.
            for a in &inv.argv {
                assert!(
                    !a.contains(&c.password),
                    "credential leaked into argv: {a:?}"
                );
            }
            // No connection string is assembled at all — no `postgres://` in argv.
            for a in &inv.argv {
                assert!(
                    !a.contains("://"),
                    "a DSN must never be built into argv: {a:?}"
                );
            }
        }
    }

    #[test]
    fn env_carries_the_discrete_connection_and_a_bounded_timeout() {
        let e = conn().env();
        let get = |k: &str| e.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        assert_eq!(get("PGHOST").as_deref(), Some("10.0.0.5"));
        assert_eq!(get("PGPORT").as_deref(), Some("5432"));
        assert_eq!(get("PGUSER").as_deref(), Some("svc"));
        assert_eq!(get("PGDATABASE").as_deref(), Some("app"));
        // A bounded connect timeout so an unreachable DSN fails fast.
        assert_eq!(get("PGCONNECT_TIMEOUT").as_deref(), Some("10"));
    }

    fn myconn() -> MysqlConnection {
        MysqlConnection {
            host: "10.0.0.6".to_string(),
            port: 3306,
            user: "svc".to_string(),
            password: "sup3r-s3cret-pw".to_string(),
            database: "app".to_string(),
            connect_timeout_secs: 10,
        }
    }

    #[test]
    fn mysql_data_only_toggles_and_credential_stays_in_env() {
        // data-only diverges: dump uses --no-create-info (no --databases); full uses
        // --databases; restore names the db only for data-only.
        let dump_do = mysqldump_invocation(&myconn(), true);
        let dump_full = mysqldump_invocation(&myconn(), false);
        assert!(dump_do.argv.iter().any(|a| a == "--no-create-info"));
        assert!(!dump_full.argv.iter().any(|a| a == "--no-create-info"));
        assert!(dump_full.argv.iter().any(|a| a == "--databases"));
        assert!(!dump_do.argv.iter().any(|a| a == "--databases"));

        let restore_do = mysql_restore_invocation(&myconn(), true);
        let restore_full = mysql_restore_invocation(&myconn(), false);
        assert!(restore_do.argv.iter().any(|a| a == "app"));
        assert!(!restore_full.argv.iter().any(|a| a == "app"));

        // The password is in MYSQL_PWD (env), never argv; no DSN in argv.
        let c = myconn();
        for inv in [
            mysqldump_invocation(&c, true),
            mysql_restore_invocation(&c, false),
        ] {
            assert!(
                inv.env
                    .iter()
                    .any(|(k, v)| k == "MYSQL_PWD" && v == &c.password),
                "MYSQL_PWD must be set in the environment"
            );
            for a in &inv.argv {
                assert!(
                    !a.contains(&c.password),
                    "credential leaked into argv: {a:?}"
                );
                assert!(
                    !a.contains("://"),
                    "a DSN must never be built into argv: {a:?}"
                );
            }
        }
    }

    #[test]
    fn mysql_env_carries_the_discrete_connection() {
        let e = myconn().env();
        let get = |k: &str| e.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        assert_eq!(get("MYSQL_HOST").as_deref(), Some("10.0.0.6"));
        assert_eq!(get("MYSQL_TCP_PORT").as_deref(), Some("3306"));
        assert_eq!(get("MYSQL_USER").as_deref(), Some("svc"));
        // The password is here, never argv.
        assert_eq!(get("MYSQL_PWD").as_deref(), Some("sup3r-s3cret-pw"));
    }
}
