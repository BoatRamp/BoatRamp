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
/// schema; `--exit-on-error` aborts loudly on the first failed object. Unlike `psql`/
/// `pg_dump`, `pg_restore` does NOT infer the target from `PGDATABASE` — without `-d`
/// (restore into a database) or `-f` (emit a script) it refuses with "one of -d/--dbname
/// and -f/--file must be specified"; so the target database is named with `-d` (the host/
/// port/user/password still come from the env, and the db name is not a credential).
pub fn pg_restore_invocation(conn: &PgConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec![
        "pg_restore".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        "--exit-on-error".to_string(),
        "-d".to_string(),
        conn.database.clone(),
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
    /// The connection ENVIRONMENT: `MYSQL_PWD` (the password) ONLY. The password is the
    /// sole secret and goes in the env every MySQL client reads, never argv. Host/port/
    /// user are NOT placed here — unlike libpq's `PGHOST` (honored by all libpq tools),
    /// `MYSQL_HOST` is read by the `mysql` CLI ALONE; `mysqldump` ignores it and defaults
    /// to the local unix socket ("Can't connect to local MySQL server through socket"),
    /// so the host/port/user travel in argv via [`conn_args`](Self::conn_args).
    pub fn env(&self) -> Vec<(String, String)> {
        vec![("MYSQL_PWD".to_string(), self.password.clone())]
    }

    /// The non-secret connection args every MySQL client (both `mysql` and `mysqldump`)
    /// honors: `--host`, `--port`, `--user`. A real host IP (not "localhost") forces TCP
    /// rather than the local socket. None of these is a credential, so argv is correct;
    /// no DSN string is assembled.
    pub fn conn_args(&self) -> Vec<String> {
        vec![
            format!("--host={}", self.host),
            format!("--port={}", self.port),
            format!("--user={}", self.user),
        ]
    }

    /// The `--connect-timeout=<secs>` arg the `mysql` client accepts (there is no env for
    /// it). NOTE: `mysqldump` does NOT register this option — passing it there fails with
    /// "[ERROR] unknown variable 'connect-timeout=10'" — so only `mysql_restore_invocation`
    /// uses it, never `mysqldump_invocation`.
    fn connect_timeout_arg(&self) -> String {
        format!("--connect-timeout={}", self.connect_timeout_secs)
    }
}

/// Build the `mysqldump` invocation for an EXPORT. `--single-transaction` takes a
/// consistent snapshot without locking (InnoDB); `--no-tablespaces` avoids the `PROCESS`
/// privilege requirement. Host/port/user are explicit ([`conn_args`](MysqlConnection::conn_args))
/// because `mysqldump` ignores `MYSQL_HOST`. A FULL dump emits schema + data under
/// `--databases <db>` (so the stream carries `CREATE DATABASE`/`USE`); `--data-only` emits
/// only the rows for `<db>` (`--no-create-info`), restored into the target's existing
/// schema. No `--connect-timeout`: `mysqldump` does not register it (unknown variable);
/// the overall ephemeral-run timeout bounds a stuck dump instead.
pub fn mysqldump_invocation(conn: &MysqlConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec![
        "mysqldump".to_string(),
        "--single-transaction".to_string(),
        "--no-tablespaces".to_string(),
    ];
    argv.extend(conn.conn_args());
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

/// Build the `mysql` invocation for an IMPORT (reads the SQL dump from stdin). Host/port/
/// user are explicit ([`conn_args`](MysqlConnection::conn_args)) so the client connects
/// over TCP, not the local socket. A FULL bundle's dump carries its own `USE <db>` (from
/// `--databases`), so no positional db is needed; a `--data-only` dump has none, so the
/// target `<db>` is named on the command line. The database name is NOT a credential, so
/// passing it in argv is fine.
pub fn mysql_restore_invocation(conn: &MysqlConnection, data_only: bool) -> SqlInvocation {
    let mut argv = vec!["mysql".to_string()];
    argv.extend(conn.conn_args());
    argv.push(conn.connect_timeout_arg());
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
        // pg_restore needs an explicit `-d <db>` target (it does NOT read PGDATABASE);
        // without it the restore aborts "one of -d/--dbname and -f/--file must be
        // specified". The db name follows the `-d` flag as its own argv element.
        for inv in [&restore_do, &restore_full] {
            let pos = inv
                .argv
                .iter()
                .position(|a| a == "-d")
                .expect("pg_restore argv must carry -d");
            assert_eq!(
                inv.argv.get(pos + 1).map(String::as_str),
                Some(conn().database.as_str()),
                "the target database must follow -d"
            );
        }
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
        // mysqldump does NOT register --connect-timeout (it fails with "unknown variable");
        // it must never appear on a dump invocation, but the mysql restore client DOES
        // accept it.
        for d in [&dump_do, &dump_full] {
            assert!(
                !d.argv.iter().any(|a| a.starts_with("--connect-timeout")),
                "mysqldump must not carry --connect-timeout"
            );
        }

        let restore_do = mysql_restore_invocation(&myconn(), true);
        let restore_full = mysql_restore_invocation(&myconn(), false);
        assert!(
            restore_full
                .argv
                .iter()
                .any(|a| a.starts_with("--connect-timeout")),
            "the mysql restore client should carry --connect-timeout"
        );
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
            // Host must be explicit in argv: mysqldump ignores MYSQL_HOST and would hit
            // the local socket (error 2002) without it.
            assert!(
                inv.argv.iter().any(|a| a == &format!("--host={}", c.host)),
                "the connection host must be explicit in argv: {:?}",
                inv.argv
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
        let c = myconn();
        // The ENV carries ONLY the password (the sole secret) — mysqldump ignores
        // MYSQL_HOST, so host/port/user must NOT be relied on via env.
        let e = c.env();
        assert_eq!(e.len(), 1, "env carries only MYSQL_PWD");
        assert_eq!(e[0].0, "MYSQL_PWD");
        assert_eq!(e[0].1, "sup3r-s3cret-pw");
        // Host/port/user travel in argv (so both mysql and mysqldump connect over TCP),
        // and never the password.
        let a = c.conn_args();
        assert!(a.iter().any(|x| x == "--host=10.0.0.6"));
        assert!(a.iter().any(|x| x == "--port=3306"));
        assert!(a.iter().any(|x| x == "--user=svc"));
        assert!(
            !a.iter().any(|x| x.contains("sup3r-s3cret-pw")),
            "password never in conn_args"
        );
    }
}
