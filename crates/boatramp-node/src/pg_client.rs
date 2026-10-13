//! Pure builders for the **Postgres export/import client invocation** that the driver
//! runs inside [`run_ephemeral`](boatramp_core::compute::ComputeBackend::run_ephemeral):
//! the `argv` and the process environment.
//!
//! ## The credential non-leak rule lives here
//! The password rides in the **`PGPASSWORD` environment variable**, NEVER in argv —
//! argv shows in `ps` and `docker inspect`, the environment does not. In fact no DSN
//! string is assembled at all: the discrete `PG*` connection variables connect the
//! client, so there is no connection string to accidentally `format!` into a log. The
//! only secret is `PGPASSWORD`, and it is in the environment.
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
pub struct PgInvocation {
    /// The command + args — NEVER carries a credential.
    pub argv: Vec<String>,
    /// The process environment — carries `PGPASSWORD`.
    pub env: Vec<(String, String)>,
}

/// Build the `pg_dump` invocation for an EXPORT. Custom format (`-Fc`): compressed and
/// the natural input to `pg_restore`. `--data-only` emits only the data.
pub fn pg_dump_invocation(conn: &PgConnection, data_only: bool) -> PgInvocation {
    let mut argv = vec![
        "pg_dump".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        "-Fc".to_string(),
    ];
    if data_only {
        argv.push("--data-only".to_string());
    }
    PgInvocation {
        argv,
        env: conn.env(),
    }
}

/// Build the `pg_restore` invocation for an IMPORT (reads the custom-format dump from
/// stdin). `--data-only` restores only the data into the target's existing migrated
/// schema; `--exit-on-error` aborts loudly on the first failed object.
pub fn pg_restore_invocation(conn: &PgConnection, data_only: bool) -> PgInvocation {
    let mut argv = vec![
        "pg_restore".to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        "--exit-on-error".to_string(),
    ];
    if data_only {
        argv.push("--data-only".to_string());
    }
    PgInvocation {
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
}
