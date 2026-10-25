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

/// The first `pg_dump` major version that supports `--exclude-extension` (PG17). Below this,
/// the extension-comment problem (see [`pg_dump_invocation`]) can only be handled with the
/// blunt `--no-comments`.
const PG_EXCLUDE_EXTENSION_MIN_MAJOR: u32 = 17;

/// Parse the server's major version from the integer `SHOW server_version_num` banner
/// (`major*10000 + minor`, PG10+: `"160004"` → 16, `"170000"` → 17). Returns `None` for a
/// banner we cannot parse (the caller then stays on the conservative `--no-comments` path).
pub fn pg_server_major(server_version_num: &str) -> Option<u32> {
    server_version_num
        .trim()
        .parse::<u32>()
        .ok()
        .map(|n| n / 10000)
}

/// Build the `pg_dump` invocation for an EXPORT. Custom format (`-Fc`): compressed and
/// the natural input to `pg_restore`. `--data-only` emits only the data AND EXCLUDES the
/// host-owned migration ledger's rows (`boatramp_migrations.*`): the ledger is a schema
/// INSIDE the tenant database, so a plain `--data-only` dump would carry its rows and a
/// `pg_restore --data-only --exit-on-error` into the already-migrated target (the
/// matching-fingerprint case — the PRIMARY use) would hit a primary-key conflict on the
/// ledger and abort. Excluding it keeps the target's own `boatramp_migrations` ledger
/// intact (the stated property).
///
/// ## Extension-comment handling (`--no-comments` vs `--exclude-extension`)
/// The atomic shadow-restore applies the dump as a NON-SUPERUSER ephemeral role (the inc2
/// RCE-on-import guard), which cannot run a `COMMENT ON EXTENSION <ext>` — that is OWNER-only,
/// and a superuser pre-creates the operator trusted-extension allowlist (e.g. pgvector, whose
/// control file sets no `trusted = true`) in the shadow, so those extensions are SUPERUSER-owned
/// there. So a dump carrying `COMMENT ON EXTENSION <allowlisted>` would FAIL the non-superuser
/// apply. Two ways to keep it out of the dump:
/// - **PG16 and below** (no `--exclude-extension`): the blunt `--no-comments` — strips ALL
///   comments. Object (table/column) comments are then NOT carried through a project export; an
///   accepted FIDELITY limitation, not a correctness one.
/// - **PG17+**: `--exclude-extension=<ext>` per shadow-pre-created extension — drops just those
///   extensions (their `CREATE EXTENSION` + `COMMENT ON EXTENSION`) from the dump, which the
///   shadow already holds, so ALL OTHER comments (table/column/…) survive. The dump's objects
///   that USE the extension (e.g. a `vector`-typed column) still dump fine — the type exists in
///   the pre-created shadow. This narrowing applies ONLY where the shadow pre-creates the
///   extensions (the chunked managed path): pass `exclude_extensions` empty for the sidecar/
///   external path, whose restore NEEDS the dump's own `CREATE EXTENSION` (we never pre-create on
///   an operator's own DB), so it stays on `--no-comments` regardless of version.
///
/// A dump naming an extension NOT in `exclude_extensions` is unaffected: on the shadow path a
/// non-allowlisted `CREATE EXTENSION` still fails-closed under the non-superuser apply (correct —
/// an untrusted bundle must not install an arbitrary extension), the same outcome in both modes.
pub fn pg_dump_invocation(
    conn: &PgConnection,
    data_only: bool,
    server_version_num: &str,
    exclude_extensions: &[String],
    no_publications: bool,
) -> SqlInvocation {
    let mut argv = vec![
        "pg_dump".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
    ];
    // `--no-publications` for a `delta_capture` db (SQL true-delta): the ephemeral `brexp_pub_*`
    // capture publication must exist from base time (pgoutput decodes the WAL against the
    // historical catalog), but it is superuser-only to CREATE — so it must be kept OUT of the dump
    // or the non-superuser atomic-shadow restore fails. Excludes any publication from the dump (an
    // accepted fidelity limitation for a capture-enabled db, like `--no-comments` for extensions).
    if no_publications {
        argv.push("--no-publications".to_string());
    }
    let narrow = !exclude_extensions.is_empty()
        && pg_server_major(server_version_num).is_some_and(|m| m >= PG_EXCLUDE_EXTENSION_MIN_MAJOR);
    if narrow {
        // PG17+ with shadow-pre-created extensions: exclude exactly those, keep all other comments.
        for ext in exclude_extensions {
            argv.push(format!("--exclude-extension={ext}"));
        }
    } else {
        // PG16 (no --exclude-extension), or no shadow-pre-created extensions (sidecar/external):
        // the blunt strip. Object comments are not carried (accepted fidelity limitation).
        argv.push("--no-comments".to_string());
    }
    argv.push("-Fc".to_string());
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

/// Build a `psql` invocation that runs one **trusted, we-generate-it** DDL/utility statement
/// (inc2 Stage C). This is the SUPERUSER / maintenance side of the atomic-shadow split: it runs
/// ONLY our own generated control SQL — `CREATE DATABASE <shadow>`, `pg_terminate_backend`, the
/// `ALTER DATABASE … RENAME` swap, `DROP DATABASE` — never a byte of the attacker-crafted bundle
/// dump (that is applied by [`pg_restore_shadow_invocation`] as the NON-superuser target role).
///
/// `sql` is placed in argv (via `-c`): it is a constant/identifier-composed statement WE build
/// (never a credential, never bundle-derived data), so argv is correct here — the only secret, the
/// password, still rides in `PGPASSWORD` (the env), never argv. `-v ON_ERROR_STOP=1` makes a failed
/// statement a non-zero exit (so the driver never mistakes a failed `CREATE DATABASE` for success),
/// and `-tAc` keeps any output terse. The caller runs **one statement per invocation** because
/// `CREATE DATABASE` / `ALTER DATABASE … RENAME` cannot run inside a transaction block and psql
/// wraps a multi-statement `-c` string as one implicit transaction. The connect target (incl. the
/// maintenance `postgres` database for `CREATE/ALTER/DROP DATABASE`) rides in `conn.env`.
pub fn psql_invocation(conn: &PgConnection, sql: &str) -> SqlInvocation {
    let argv = vec![
        "psql".to_string(),
        "-v".to_string(),
        "ON_ERROR_STOP=1".to_string(),
        "-tAc".to_string(),
        sql.to_string(),
    ];
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the `pg_restore` invocation that applies the **attacker-crafted bundle dump** into a
/// pre-created SHADOW database (inc2 Stage C) — the UNTRUSTED side of the atomic-shadow split.
///
/// It targets the shadow database by NAME (`-d <shadow_db>`, NOT `conn.database`) and is meant to
/// run as the TARGET PROJECT'S own NON-SUPERUSER role (the driver resolves that credential), so a
/// crafted dump's superuser-only escapes (`COPY … TO/FROM PROGRAM/FILE`, `CREATE FUNCTION …
/// LANGUAGE c`, `CREATE EXTENSION`) FAIL at apply — Postgres denies them to a non-superuser. A FULL
/// restore (schema + data; never `--data-only`): `--single-transaction` makes the shadow restore
/// itself all-or-nothing, `--exit-on-error` aborts loudly on the first failed object, and
/// `--no-owner`/`--no-privileges` keep the restore from reassigning ownership/ACLs (so no `SET
/// ROLE`/`ALTER … OWNER` to the superuser is attempted). The dump is fed on stdin. NEVER pass `-j`
/// here: parallel restore needs a seekable archive, and the dump arrives as a non-seekable pipe.
/// `shadow_db` is a driver-derived identifier (`<db>__shadow_<ts>`), not a credential, so argv is
/// correct; the password stays in `PGPASSWORD`.
pub fn pg_restore_shadow_invocation(conn: &PgConnection, shadow_db: &str) -> SqlInvocation {
    let argv = vec![
        "pg_restore".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        "--exit-on-error".to_string(),
        "--single-transaction".to_string(),
        "-d".to_string(),
        shadow_db.to_string(),
    ];
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

/// Build the **tables-only FULL** `mysqldump` for the inc2 chunked/shadow path (Stage D). Unlike
/// the inc1 FULL dump ([`mysqldump_invocation`] with `--databases <db>`, which emits `CREATE
/// DATABASE`/`USE <original>` and so TARGETS THE ORIGINAL NAME), this dumps the db's TABLES ONLY —
/// a positional `<db>` with NO `--databases` — so the stream carries `CREATE TABLE` + data and NO
/// `CREATE DATABASE`/`USE`. That lets `mysql <shadow>` ([`mysql_shadow_invocation`]) apply it into a
/// freshly-created shadow database whose name differs from the source. `--single-transaction` takes
/// a consistent InnoDB snapshot without locking; `--no-tablespaces` avoids the `PROCESS` privilege.
/// Host/port/user are explicit (`mysqldump` ignores `MYSQL_HOST`); the password stays in `MYSQL_PWD`.
///
/// `--set-gtid-purged=OFF` is MANDATORY for the shadow path: when the server runs with
/// `gtid_mode=ON` (which `delta_capture` requires — see [`mysqldump_capture_base_invocation`]),
/// mysqldump's default (`AUTO`) injects an EXECUTABLE `SET @@GLOBAL.GTID_PURGED=…` plus a
/// `SET @@SESSION.SQL_LOG_BIN=0` toggle. Both need `SYSTEM_VARIABLES_ADMIN`/`SESSION_VARIABLES_ADMIN`,
/// which the least-privilege shadow apply user ([`mysql_shadow_invocation`]) does NOT hold — so the
/// non-superuser restore would fail. `OFF` suppresses both, keeping the tables-only dump a clean,
/// privilege-free stream that any shadow-scoped user can replay. (A non-gtid server ignores it.)
pub fn mysqldump_tables_only_invocation(conn: &MysqlConnection) -> SqlInvocation {
    let mut argv = vec![
        "mysqldump".to_string(),
        "--single-transaction".to_string(),
        "--no-tablespaces".to_string(),
        "--set-gtid-purged=OFF".to_string(),
    ];
    argv.extend(conn.conn_args());
    // Positional db, NO `--databases` ⇒ tables only, no `CREATE DATABASE`/`USE <original>`.
    argv.push(conn.database.clone());
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the **tables-only, SNAPSHOT-PINNED** `mysqldump` for the MySQL binlog TRUE-DELTA base
/// (SQL true-delta program — the mysql analogue of the pg capture slot). Identical to
/// [`mysqldump_tables_only_invocation`] (tables-only so it restores into a differently-named shadow)
/// EXCEPT it records the dump's consistent-snapshot binlog coordinate with
/// `--source-data=2 --set-gtid-purged=COMMENTED`:
/// - `--source-data=2` emits a COMMENTED `CHANGE MASTER TO MASTER_LOG_FILE='…'` — the binlog file the
///   delta capture streams from.
/// - `--set-gtid-purged=COMMENTED` emits a COMMENTED `SET @@GLOBAL.GTID_PURGED='+<gtid>'` — the EXACT
///   `gtid_executed` at the dump's snapshot, which the delta's `--exclude-gtids` replays from. Unlike
///   pg (whose slot pins a point BEFORE the dump, leaving an overlap window), mysqldump reports its
///   OWN snapshot coordinate, so the base is snapshot-pinned with NO overlap/gap.
///
/// Both coordinates are COMMENTED (inert on restore). But `--source-data` ALSO injects an EXECUTABLE
/// `SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN` / `SET @@SESSION.SQL_LOG_BIN=0` pair that the
/// least-privilege shadow user cannot run — the driver STRIPS those lines (see
/// `mysql_strip_sql_log_bin` in the node driver) before the member is committed, leaving a clean
/// member whose header still carries the two COMMENTED coordinates for parsing.
pub fn mysqldump_capture_base_invocation(conn: &MysqlConnection) -> SqlInvocation {
    let mut argv = vec![
        "mysqldump".to_string(),
        "--single-transaction".to_string(),
        "--no-tablespaces".to_string(),
        "--source-data=2".to_string(),
        "--set-gtid-purged=COMMENTED".to_string(),
    ];
    argv.extend(conn.conn_args());
    argv.push(conn.database.clone());
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the `mysqlbinlog --read-from-remote-server` invocation that CAPTURES + DB-SCOPES + REWRITES
/// the binlog delta (SQL true-delta drain). Connects to the live server like a replica (no
/// filesystem access to the data dir) as the EPHEMERAL least-privilege capture user (`REPLICATION
/// SLAVE, REPLICATION CLIENT` only), reading from `start_log` (the base dump's recorded
/// `MASTER_LOG_FILE`) `--to-last-log`, and DECODES to stdout (NOT `--raw`) — the member IS this SQL
/// stream (`BINLOG '…'` row events), directly pipeable to `mysql` at replay with no re-decode. The
/// flags are the SECURITY + correctness core:
/// - `--rewrite-db='<live>-><shadow>'` retargets the source db's events to the SHADOW at CAPTURE (the
///   member is applied verbatim at restore; SQL text cannot be rewritten after the fact).
/// - `--database=<shadow>` (applied AFTER the rewrite, filtering on the REWRITTEN name) keeps ONLY
///   the shadow's events and DROPS every other db's events — so the member NEVER contains `mysql`-
///   schema account DDL (`CREATE USER`/`GRANT`/`SET PASSWORD` with password hashes) or any other
///   tenant/db's rows. This is the DISCLOSURE fix: the exported member is strictly the app db's data,
///   never the server-global binlog (unlike a `--raw` capture, which byte-copies everything).
/// - `--skip-gtids` omits the `SET @@SESSION.GTID_NEXT=<source gtid>` statements, so the replay onto
///   the (same) server does not see each source GTID as already-executed and SKIP the transaction;
///   the replayed rows get fresh auto-assigned GTID values.
/// - `--exclude-gtids=<base_gtid>` drops everything already in the base dump's snapshot (the start
///   binlog file holds pre-base events) — no overlap.
///
/// `shadow`/`live`/`base_gtid`/`start_log` are driver-derived (binding + parsed dump coordinate),
/// never credentials. Host/port/user explicit; `mysqlbinlog` honors `MYSQL_PWD`, so the password
/// rides in the env, NEVER argv.
pub fn mysqlbinlog_capture_invocation(
    conn: &MysqlConnection,
    live_db: &str,
    shadow_db: &str,
    base_gtid: &str,
    start_log: &str,
) -> SqlInvocation {
    let argv = vec![
        "mysqlbinlog".to_string(),
        "--read-from-remote-server".to_string(),
        format!("--host={}", conn.host),
        format!("--port={}", conn.port),
        format!("--user={}", conn.user),
        format!("--rewrite-db={live_db}->{shadow_db}"),
        format!("--database={shadow_db}"),
        "--skip-gtids".to_string(),
        format!("--exclude-gtids={base_gtid}"),
        "--to-last-log".to_string(),
        start_log.to_string(),
    ];
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the `mysql` invocation that applies the **attacker-crafted** tables-only dump into a
/// pre-created SHADOW database by NAME (inc2 Stage D) — the UNTRUSTED side of the atomic-shadow
/// split. Meant to run as the TARGET PROJECT'S own NON-SUPERUSER role (the driver resolves that
/// credential) so a crafted statement needing elevated privileges (`LOAD DATA INFILE`, `INTO
/// OUTFILE`, creating a `LANGUAGE`-escalating routine) fails at apply. The dump (which carries NO
/// `USE`) is fed on stdin and lands in `shadow_db` because it is named as the default database
/// positionally. Host/port/user explicit; password in `MYSQL_PWD`; `shadow_db` is a driver-derived
/// identifier (not a credential), so argv is correct.
///
/// Used for BOTH the inc2 tables-only base restore AND the binlog true-delta member replay (both
/// apply attacker-crafted SQL as the least-privilege shadow user). `--local-infile=0` is
/// belt-and-suspenders: it disables client-side `LOAD DATA LOCAL INFILE`, so a crafted dump/member
/// cannot read a file off the ephemeral client container (the apply user already lacks `FILE`, which
/// blocks server-side `LOAD DATA INFILE`/`INTO OUTFILE`).
pub fn mysql_shadow_invocation(conn: &MysqlConnection, shadow_db: &str) -> SqlInvocation {
    let mut argv = vec!["mysql".to_string()];
    argv.extend(conn.conn_args());
    argv.push(conn.connect_timeout_arg());
    argv.push("--local-infile=0".to_string());
    argv.push(shadow_db.to_string());
    SqlInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build a `mysql` invocation that runs **trusted, we-generate-it** SQL fed on stdin — the
/// SUPERUSER / maintenance side of the inc2 mysql shadow split (Stage D): `CREATE DATABASE
/// <shadow>`, the atomic `RENAME TABLE` swap, `DROP DATABASE`, and the `information_schema` table
/// enumeration the swap is built from. No default database is named (so `CREATE DATABASE` works and
/// every object is schema-qualified in the SQL we build), `-N --batch` give header-less,
/// tab-separated output for the enumeration query. Host/port/user explicit; password in `MYSQL_PWD`.
pub fn mysql_admin_invocation(conn: &MysqlConnection) -> SqlInvocation {
    let mut argv = vec!["mysql".to_string()];
    argv.extend(conn.conn_args());
    argv.push(conn.connect_timeout_arg());
    argv.push("-N".to_string());
    argv.push("--batch".to_string());
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
        let dump_do = pg_dump_invocation(&conn(), true, "160004", &[], false);
        let dump_full = pg_dump_invocation(&conn(), false, "160004", &[], false);
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
    fn pg_server_major_parses_the_version_num_banner() {
        assert_eq!(pg_server_major("160004"), Some(16));
        assert_eq!(pg_server_major("170000"), Some(17));
        assert_eq!(pg_server_major(" 180002 "), Some(18));
        assert_eq!(pg_server_major("not-a-number"), None);
    }

    #[test]
    fn no_publications_toggles_the_dump_flag() {
        // A `delta_capture` db dumps with `--no-publications` so the ephemeral `brexp_pub_*`
        // capture publication (superuser-only to CREATE) never lands in the dump and cannot fail
        // the non-superuser atomic-shadow restore. Off ⇒ the flag is absent (publications dumped).
        let with = pg_dump_invocation(&conn(), false, "160004", &[], true);
        assert!(with.argv.iter().any(|a| a == "--no-publications"));
        let without = pg_dump_invocation(&conn(), false, "160004", &[], false);
        assert!(!without.argv.iter().any(|a| a == "--no-publications"));
    }

    #[test]
    fn exclude_extension_narrows_no_comments_only_on_pg17_with_a_shadow_allowlist() {
        let exts = vec!["vector".to_string(), "pg_trgm".to_string()];
        let has = |inv: &SqlInvocation, a: &str| inv.argv.iter().any(|x| x == a);
        let has_exclude = |inv: &SqlInvocation, e: &str| {
            inv.argv
                .iter()
                .any(|x| x == &format!("--exclude-extension={e}"))
        };

        // PG17 + a shadow-pre-created allowlist: NARROW — exclude exactly those extensions and
        // DROP `--no-comments`, so all OTHER (table/column) comments survive the export.
        let pg17 = pg_dump_invocation(&conn(), false, "170000", &exts, false);
        assert!(!has(&pg17, "--no-comments"), "PG17 keeps object comments");
        assert!(has_exclude(&pg17, "vector") && has_exclude(&pg17, "pg_trgm"));

        // PG16 + the SAME allowlist: no `--exclude-extension` exists, so fall back to the blunt
        // `--no-comments` and NEVER emit an `--exclude-extension` (unknown flag on PG16).
        let pg16 = pg_dump_invocation(&conn(), false, "160004", &exts, false);
        assert!(
            has(&pg16, "--no-comments"),
            "PG16 has no --exclude-extension → blunt strip"
        );
        assert!(
            !pg16
                .argv
                .iter()
                .any(|a| a.starts_with("--exclude-extension")),
            "PG16's pg_dump does not know --exclude-extension"
        );

        // PG17 but NO shadow allowlist (the sidecar/external path): the restore needs the dump's
        // own CREATE EXTENSION, so stay on `--no-comments` and exclude nothing.
        let sidecar = pg_dump_invocation(&conn(), false, "170000", &[], false);
        assert!(has(&sidecar, "--no-comments"));
        assert!(
            !sidecar
                .argv
                .iter()
                .any(|a| a.starts_with("--exclude-extension"))
        );

        // An unparseable banner is conservative: blunt strip, no exclude.
        let unknown = pg_dump_invocation(&conn(), false, "garbage", &exts, false);
        assert!(has(&unknown, "--no-comments"));
        assert!(
            !unknown
                .argv
                .iter()
                .any(|a| a.starts_with("--exclude-extension"))
        );
    }

    #[test]
    fn shadow_builders_split_trusted_ddl_from_untrusted_apply() {
        let c = conn();
        // The TRUSTED maintenance side: psql runs ONE generated statement; ON_ERROR_STOP so a
        // failed CREATE/ALTER/DROP DATABASE is a non-zero exit (never mistaken for success).
        let ddl = psql_invocation(&c, "CREATE DATABASE \"app__shadow_1\" OWNER \"owner\"");
        assert_eq!(ddl.argv[0], "psql");
        assert!(ddl.argv.iter().any(|a| a == "ON_ERROR_STOP=1"));
        assert!(
            ddl.argv
                .iter()
                .any(|a| a == "CREATE DATABASE \"app__shadow_1\" OWNER \"owner\"")
        );
        // The UNTRUSTED apply side: FULL restore (NEVER --data-only), single-transaction,
        // exit-on-error, no-owner/no-privileges, targeting the SHADOW by name — and NEVER `-j`
        // (parallel restore needs a seekable archive; the dump is a pipe).
        let apply = pg_restore_shadow_invocation(&c, "app__shadow_1");
        assert_eq!(apply.argv[0], "pg_restore");
        assert!(apply.argv.iter().any(|a| a == "--single-transaction"));
        assert!(apply.argv.iter().any(|a| a == "--exit-on-error"));
        assert!(apply.argv.iter().any(|a| a == "--no-owner"));
        assert!(apply.argv.iter().any(|a| a == "--no-privileges"));
        assert!(
            !apply.argv.iter().any(|a| a == "--data-only"),
            "the chunked pg shadow path is FULL-restore only (default #1)"
        );
        assert!(
            !apply
                .argv
                .iter()
                .any(|a| a == "-j" || a.starts_with("--jobs")),
            "NEVER parallel-restore a piped archive"
        );
        let pos = apply.argv.iter().position(|a| a == "-d").expect("-d");
        assert_eq!(
            apply.argv.get(pos + 1).map(String::as_str),
            Some("app__shadow_1"),
            "the shadow db (NOT conn.database) follows -d"
        );
        // Both still carry the credential ONLY in the env, never argv.
        for inv in [&ddl, &apply] {
            assert!(
                inv.env
                    .iter()
                    .any(|(k, v)| k == "PGPASSWORD" && v == &c.password)
            );
            for a in &inv.argv {
                assert!(
                    !a.contains(&c.password),
                    "credential leaked into argv: {a:?}"
                );
            }
        }
    }

    #[test]
    fn mysql_shadow_builders_are_tables_only_and_target_the_shadow() {
        let c = myconn();
        // Tables-only FULL dump: positional db, NO --databases (so no CREATE DATABASE/USE of the
        // ORIGINAL name), NO --no-create-info (schema + data), NO --connect-timeout (mysqldump
        // rejects it).
        let dump = mysqldump_tables_only_invocation(&c);
        assert_eq!(dump.argv[0], "mysqldump");
        assert!(!dump.argv.iter().any(|a| a == "--databases"));
        assert!(!dump.argv.iter().any(|a| a == "--no-create-info"));
        assert!(!dump.argv.iter().any(|a| a.starts_with("--connect-timeout")));
        // Clean under gtid_mode=ON: suppress mysqldump's AUTO `SET @@GLOBAL.GTID_PURGED` +
        // `SET @@SESSION.SQL_LOG_BIN` injections so the non-superuser shadow apply never hits them.
        assert!(
            dump.argv.iter().any(|a| a == "--set-gtid-purged=OFF"),
            "tables-only dump must suppress gtid/sql_log_bin statements: {:?}",
            dump.argv
        );
        assert!(
            dump.argv.last().map(String::as_str) == Some("app"),
            "the db is positional (tables only): {:?}",
            dump.argv
        );
        // The untrusted apply targets the SHADOW by name (positional default db).
        let apply = mysql_shadow_invocation(&c, "app__shadow_1");
        assert_eq!(apply.argv[0], "mysql");
        assert!(apply.argv.iter().any(|a| a == "app__shadow_1"));
        assert!(!apply.argv.iter().any(|a| a == "app"));
        // The untrusted apply disables client-side LOAD DATA LOCAL INFILE (defense in depth).
        assert!(apply.argv.iter().any(|a| a == "--local-infile=0"));
        // The trusted admin side names NO default db (so CREATE/DROP DATABASE + schema-qualified
        // RENAME TABLE work) and asks for header-less tab output for the table enumeration.
        let admin = mysql_admin_invocation(&c);
        assert_eq!(admin.argv[0], "mysql");
        assert!(admin.argv.iter().any(|a| a == "-N"));
        assert!(admin.argv.iter().any(|a| a == "--batch"));
        assert!(
            !admin
                .argv
                .iter()
                .any(|a| a == "app" || a == "app__shadow_1"),
            "the admin connection names no default database: {:?}",
            admin.argv
        );
        // Credential only in MYSQL_PWD, never argv; host explicit (mysqldump ignores MYSQL_HOST).
        for inv in [&dump, &apply, &admin] {
            assert!(
                inv.env
                    .iter()
                    .any(|(k, v)| k == "MYSQL_PWD" && v == &c.password)
            );
            assert!(inv.argv.iter().any(|a| a == &format!("--host={}", c.host)));
            for a in &inv.argv {
                assert!(
                    !a.contains(&c.password),
                    "credential leaked into argv: {a:?}"
                );
            }
        }
    }

    #[test]
    fn mysql_true_delta_capture_and_replay_builders() {
        let c = myconn();
        // BASE capture dump: tables-only + the snapshot-pinned coordinate flags. `--source-data=2`
        // (COMMENTED CHANGE MASTER) + `--set-gtid-purged=COMMENTED` (COMMENTED GTID_PURGED) so the
        // driver can parse the exact snapshot GTID + binlog file without polluting the restore.
        let base = mysqldump_capture_base_invocation(&c);
        assert_eq!(base.argv[0], "mysqldump");
        assert!(base.argv.iter().any(|a| a == "--source-data=2"));
        assert!(base.argv.iter().any(|a| a == "--set-gtid-purged=COMMENTED"));
        assert!(!base.argv.iter().any(|a| a == "--databases")); // tables-only (shadow-restorable)
        assert_eq!(base.argv.last().map(String::as_str), Some("app"));

        // CAPTURE: db-SCOPED + REWRITTEN at capture (member is app-only SQL text targeting the
        // shadow). NOT --raw (which byte-copies the whole-server binlog incl. account-DDL hashes);
        // `--database` filters on the REWRITTEN name (applied after `--rewrite-db`) — the DISCLOSURE
        // fix: foreign-db / `mysql`-schema events never enter the member.
        let cap = mysqlbinlog_capture_invocation(
            &c,
            "app",
            "app__shadow_1",
            "uuid:1-9",
            "mysql-bin.000007",
        );
        assert_eq!(cap.argv[0], "mysqlbinlog");
        assert!(cap.argv.iter().any(|a| a == "--read-from-remote-server"));
        assert!(
            !cap.argv.iter().any(|a| a == "--raw"),
            "capture is NON-raw (db-scoped SQL text), never --raw (whole-server disclosure): {:?}",
            cap.argv
        );
        assert!(
            cap.argv
                .iter()
                .any(|a| a == "--rewrite-db=app->app__shadow_1")
        );
        assert!(
            cap.argv.iter().any(|a| a == "--database=app__shadow_1"),
            "--database must filter on the REWRITTEN (shadow) name: {:?}",
            cap.argv
        );
        assert!(cap.argv.iter().any(|a| a == "--skip-gtids"));
        assert!(cap.argv.iter().any(|a| a == "--exclude-gtids=uuid:1-9"));
        assert!(cap.argv.iter().any(|a| a == "--to-last-log"));
        assert_eq!(
            cap.argv.last().map(String::as_str),
            Some("mysql-bin.000007")
        );
        assert!(cap.argv.iter().any(|a| a == &format!("--user={}", c.user)));

        // The capture dump + remote capture carry the password ONLY in MYSQL_PWD, never argv.
        for inv in [&base, &cap] {
            assert!(
                inv.env
                    .iter()
                    .any(|(k, v)| k == "MYSQL_PWD" && v == &c.password)
            );
            for a in &inv.argv {
                assert!(
                    !a.contains(&c.password),
                    "credential leaked into argv: {a:?}"
                );
                assert!(!a.contains("://"), "no DSN in argv: {a:?}");
            }
        }
    }

    #[test]
    fn credential_is_in_the_env_never_in_argv() {
        let c = conn();
        for inv in [
            pg_dump_invocation(&c, true, "160004", &[], false),
            // PG17 narrowing path too: the generated `--exclude-extension` args carry no credential.
            pg_dump_invocation(&c, false, "170000", &["vector".to_string()], false),
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
