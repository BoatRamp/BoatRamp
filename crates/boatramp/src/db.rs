//! `boatramp db` — a client for the declarative managed-database surface
//! (v0.6.0, #501 Stage B).
//!
//! `db ls | get <name> | status <name>` inspect the project's declared managed
//! databases (`Project·Read`). `db ensure database <name>` eager-provisions an
//! already-declared database idempotently (`Project·Admin`), so an operator can migrate
//! it *before* any component runs — `db ensure database default && sql exec --db default
//! --file schema.sql`. There is deliberately **NO `db create`**: the manifest
//! `databases:` block is the SOLE authoring surface (a create verb would compete as a
//! second source of truth); `ensure` provisions a database the manifest already declares,
//! it never declares one. To add a database, put a `databases:` entry in `apply.cfg` and
//! run `boatramp apply`.

use boatramp_core::compute::ApplyDatabase;

use crate::client::{self, ControlPlane};
use crate::config::ProjectConfig;

/// A failure in `boatramp db`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Resolving the server / building the client failed.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The `<name>` is not a safe URL path segment (validated client-side).
    #[error("{0}")]
    InvalidName(String),
    /// `ensure --wait` observed the database end in a `provision_failed` readiness: a
    /// post-launch action failed. The reconcile keeps retrying, but the operator asked to
    /// wait, so this is surfaced as a non-zero exit with the server's reason.
    #[error("database {name:?} failed to provision: {reason}")]
    EnsureFailed {
        /// The database binding name.
        name: String,
        /// The server-reported provisioning failure reason (no credential material).
        reason: String,
    },
}

/// `db` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// `boatramp db …` — inspect the project's declared managed databases (read-only).
#[derive(Debug, clap::Args)]
pub struct DbArgs {
    /// boatramp server base URL (overrides `[publish].server`).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: DbCommand,
}

/// The `db` subcommands — READ-ONLY only (no `create`; the manifest is the authoring
/// surface).
#[derive(Debug, clap::Subcommand)]
enum DbCommand {
    /// List the project's declared managed databases.
    Ls,
    /// Show one declared managed database's declaration.
    Get {
        /// The database binding name.
        name: String,
    },
    /// Show one declared managed database's read-only status (declaration + derived
    /// server workload handle + live readiness).
    Status {
        /// The database binding name.
        name: String,
    },
    /// Eager-provision an already-declared managed resource idempotently
    /// (`Project·Admin`). Provisions a database the manifest already declares so it can
    /// be migrated before any component runs — it never *declares* a new resource.
    Ensure {
        #[command(subcommand)]
        what: EnsureWhat,
    },
    /// Drop an operator-provisioned managed resource idempotently (`Project·Admin`).
    Drop {
        #[command(subcommand)]
        what: DropWhat,
    },
    /// Restart a managed database (`Project·Admin`): stop it so the reconcile loop
    /// relaunches it, applying any restart-requiring config change staged on the
    /// declaration in the process (e.g. a flipped `delta_capture`, which needs
    /// `wal_level=logical`/`--log-bin` in the launch argv to take effect). The
    /// explicit restart path a `restart_policy: manual` config change needs (see
    /// `db status`'s "pending restart" signal), and a general lever to bounce a
    /// database that needs no config change at all.
    Restart {
        /// The database binding name (defaults to the project's `default` database).
        #[arg(long = "db", default_value = "default")]
        db: String,
    },
}

/// What `db drop` removes. Idempotent: dropping an absent resource is a clean no-op.
#[derive(Debug, clap::Subcommand)]
enum DropWhat {
    /// Drop a login role from a managed database (the role + its sealed credential).
    User {
        /// The login role name (as given to `db ensure user`).
        name: String,
        /// The managed database whose server the role lives on.
        #[arg(long)]
        database: String,
    },
}

/// What `db ensure` provisions. `database` ensures a declared managed database exists;
/// `user` (a later increment) provisions a managed role. Each is idempotent.
#[derive(Debug, clap::Subcommand)]
enum EnsureWhat {
    /// Ensure an already-declared managed database is provisioned (idempotent).
    Database {
        /// The database binding name (defaults to the project's `default` database).
        #[arg(default_value = "default")]
        name: String,
        /// After provisioning, poll `db status` until the database is reported ready
        /// (or a post-launch action has failed), up to `--timeout` seconds.
        #[arg(long)]
        wait: bool,
        /// Max seconds to wait with `--wait` before returning the last observed state.
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
    /// Ensure a login role on a declared managed database (idempotent). By default mints
    /// and seals the role's password and prints it ONCE; re-ensuring is a no-op.
    User {
        /// The login role name to ensure.
        name: String,
        /// The managed database whose server the role is created on.
        #[arg(long)]
        database: String,
        /// Use an operator-supplied secret for the password instead of minting one (BYO):
        /// the value is the name of an env var the node reads (same resolution as a
        /// binding's `password_env`). The secret is never surfaced or logged.
        #[arg(long)]
        password_secret: Option<String>,
    },
}

/// Validate a `<name>` through the one canonical resource-identifier validator
/// (`kind = "database"`) before it is threaded into the request URL — the same rule the
/// server enforces — so a malformed name fails fast rather than an opaque server error.
fn validate_name(name: &str) -> Result<()> {
    boatramp_core::project::validate_resource_name("database", name).map_err(|e| {
        Error::InvalidName(format!(
            "{e}; {}",
            boatramp_core::project::INVALID_NAME_CURE
        ))
    })
}

/// The result of a `boatramp db` subcommand, rendered by [`crate::output`].
///
/// Each variant carries the actual declaration(s): the human view is a table, and
/// `--output-format json` serializes them structurally.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum DbOutput {
    /// `db ls` — the project's declared managed databases.
    Ls { databases: Vec<ApplyDatabase> },
    /// `db get <name>` — one declaration, plus whether a restart-requiring config
    /// change is pending (PLAN-sql-true-delta Stage 1b).
    // Boxed to keep this larger payload from dwarfing the other variants.
    Get {
        database: Box<ApplyDatabase>,
        pending_restart: bool,
    },
    /// `db status <name>` — the read-only status view (declaration + derived workload).
    Status {
        name: String,
        view: serde_json::Value,
    },
    /// `db ensure database <name>` — provisioned; `readiness` is the last observed state
    /// (`provisioned` / `service_ready` / `starting` / `pending`), with `reason` set only
    /// on a surfaced provisioning failure.
    Ensure {
        name: String,
        readiness: String,
        reason: Option<String>,
        waited: bool,
    },
    /// `db ensure user <name> --database <db>` — the role was ensured. `password` is
    /// present ONLY when freshly minted (shown once); absent on a re-ensure.
    EnsureUser {
        user: String,
        database: String,
        /// The actual cluster principal to connect as (per-tenant-qualified on Shared).
        role_name: String,
        created: bool,
        password: Option<String>,
        /// The operator supplied the password (`--password-secret`): nothing is minted or
        /// surfaced, so render a BYO-aware line rather than a created/already-exists one.
        byo: bool,
    },
    /// `db drop user <name> --database <db>` — the role + its credential were dropped.
    DropUser {
        user: String,
        database: String,
        role_name: String,
        existed: bool,
    },
    /// `db restart [--db <name>]` — the database was restarted; `config_applied` is
    /// whether a pending config change (e.g. a flipped `delta_capture`) was adopted in
    /// the process, `replicas_restarted` how many running replicas were stopped for
    /// the reconcile loop to relaunch.
    Restart {
        name: String,
        workload: String,
        config_applied: bool,
        replicas_restarted: usize,
    },
}

impl crate::output::Rendered for DbOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Ls { databases } => {
                if databases.is_empty() {
                    return writeln!(w, "no declared managed databases in this project");
                }
                write_header(w)?;
                for db in databases {
                    write_row(w, db)?;
                }
                Ok(())
            }
            Self::Get {
                database,
                pending_restart,
            } => {
                write_header(w)?;
                write_row(w, database)?;
                if *pending_restart {
                    writeln!(
                        w,
                        "  pending restart: a config change (e.g. delta_capture) is staged but \
                         not yet applied — run `boatramp db restart --db {}`",
                        database.name
                    )?;
                }
                Ok(())
            }
            Self::Status { name, view } => {
                let workload = view.get("workload").and_then(|v| v.as_str()).unwrap_or("?");
                let readiness = view
                    .get("readiness")
                    .and_then(|r| r.get("state"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                writeln!(w, "database `{name}`")?;
                writeln!(w, "  server workload: {workload}")?;
                writeln!(w, "  declared:        yes")?;
                write!(w, "  readiness:       {readiness}")?;
                if let Some(reason) = view
                    .get("readiness")
                    .and_then(|r| r.get("reason"))
                    .and_then(|v| v.as_str())
                {
                    write!(w, " ({reason})")?;
                }
                writeln!(w)?;
                // Pending-restart signal (PLAN-sql-true-delta Stage 1b): a config change (e.g.
                // a flipped `delta_capture`) is staged but not yet applied. Shown only when
                // true — the common case (no pending change) stays terse.
                if view
                    .get("pending_restart")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                {
                    writeln!(
                        w,
                        "  pending restart: yes — a staged config change has not been applied; \
                         run `boatramp db restart --db {name}`"
                    )?;
                }
                // The data-dir-ownership health signal: a filesystem fault (foreign-owned
                // files the managed database can't read) behind an otherwise-opaque
                // `starting` stall — the signal `/api/repair` can't give. Shown only when a
                // replica recorded an observation; a fault carries its own cure.
                if let Some(dd) = view.get("data_dir") {
                    let ok = dd
                        .get("ok")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true);
                    if ok {
                        writeln!(w, "  data-dir:        ownership ok")?;
                    } else {
                        let vol = dd.get("volume").and_then(|v| v.as_str()).unwrap_or("?");
                        let count = dd
                            .get("foreign_count")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0);
                        writeln!(
                            w,
                            "  data-dir:        FOREIGN-OWNED ({count} file(s) under volume `{vol}` not owned by the database process)"
                        )?;
                        if let Some(sample) = dd.get("sample") {
                            let path = sample.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                            let uid = sample
                                .get("uid")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0);
                            let gid = sample
                                .get("gid")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0);
                            let euid = dd
                                .get("expected_uid")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0);
                            let egid = dd
                                .get("expected_gid")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0);
                            writeln!(
                                w,
                                "                   e.g. `{path}` is owned by {uid}:{gid}, expected {euid}:{egid}"
                            )?;
                        }
                        writeln!(
                            w,
                            "                   the database cannot read its own cluster files; relaunch re-chowns the volume, or correct the volume/image uid. `/api/repair` does not fix filesystem permissions."
                        )?;
                    }
                }
                Ok(())
            }
            Self::Ensure {
                name,
                readiness,
                reason,
                waited,
            } => {
                writeln!(w, "ensured database `{name}`")?;
                write!(w, "  readiness: {readiness}")?;
                if let Some(reason) = reason {
                    write!(w, " ({reason})")?;
                }
                writeln!(w)?;
                if !waited && readiness != "provisioned" {
                    writeln!(
                        w,
                        "  (provisioning initiated; re-run `db status {name}` or pass --wait)"
                    )?;
                }
                Ok(())
            }
            Self::EnsureUser {
                user,
                database,
                role_name,
                created,
                password,
                byo,
            } => {
                // On a Shared binding the actual cluster role is per-tenant-qualified, so it
                // differs from the requested label — surface it as the name to connect as.
                let note_qualified = |w: &mut dyn std::io::Write| -> std::io::Result<()> {
                    if role_name != user {
                        writeln!(w, "  connect as:  {role_name}  (requested `{user}`)")
                    } else {
                        Ok(())
                    }
                };
                if *byo {
                    // BYO: the operator owns the password; nothing is minted or surfaced.
                    writeln!(
                        w,
                        "ensured login role `{role_name}` on database `{database}` with the supplied credential"
                    )?;
                    return note_qualified(w);
                }
                match password {
                    Some(pw) => {
                        writeln!(
                            w,
                            "created login role `{role_name}` on database `{database}`"
                        )?;
                        note_qualified(w)?;
                        writeln!(w, "  password:    {pw}")?;
                        writeln!(w, "  store this now — it will not be shown again")
                    }
                    None if *created => {
                        // Created but no password surfaced (e.g. a BYO secret was used).
                        writeln!(
                            w,
                            "created login role `{role_name}` on database `{database}`"
                        )?;
                        note_qualified(w)
                    }
                    None => {
                        writeln!(
                            w,
                            "login role `{role_name}` already exists on database `{database}` (no change)"
                        )?;
                        note_qualified(w)
                    }
                }
            }
            Self::DropUser {
                user,
                database,
                role_name,
                existed,
            } => {
                if *existed {
                    writeln!(
                        w,
                        "dropped login role `{role_name}` on database `{database}`"
                    )
                } else {
                    writeln!(
                        w,
                        "dropped login role `{role_name}` on database `{database}` (no sealed credential was present)"
                    )
                }?;
                if role_name != user {
                    writeln!(w, "  (requested `{user}`)")?;
                }
                Ok(())
            }
            Self::Restart {
                name,
                workload,
                config_applied,
                replicas_restarted,
            } => {
                writeln!(w, "restarted database `{name}` (workload `{workload}`)")?;
                if *config_applied {
                    writeln!(w, "  pending config change applied")?;
                }
                writeln!(
                    w,
                    "  replicas stopped: {replicas_restarted} (the reconcile loop will relaunch)"
                )
            }
        }
    }
}

/// Entry point for `boatramp db`.
pub async fn run(args: DbArgs, config: &ProjectConfig) -> Result<DbOutput> {
    let (server, http) = client::connect(args.server.clone(), config)?;
    let project = client::resolve_project(config);
    let cp = ControlPlane::new(server, http, project);
    match args.command {
        DbCommand::Ls => ls(&cp).await,
        DbCommand::Get { name } => {
            validate_name(&name)?;
            get(&cp, &name).await
        }
        DbCommand::Status { name } => {
            validate_name(&name)?;
            status(&cp, &name).await
        }
        DbCommand::Ensure { what } => match what {
            EnsureWhat::Database {
                name,
                wait,
                timeout,
            } => {
                validate_name(&name)?;
                ensure_database(&cp, &name, wait, timeout).await
            }
            EnsureWhat::User {
                name,
                database,
                password_secret,
            } => {
                validate_name(&name)?;
                validate_name(&database)?;
                ensure_user(&cp, &database, &name, password_secret.as_deref()).await
            }
        },
        DbCommand::Drop { what } => match what {
            DropWhat::User { name, database } => {
                validate_name(&name)?;
                validate_name(&database)?;
                drop_user(&cp, &database, &name).await
            }
        },
        DbCommand::Restart { db } => {
            validate_name(&db)?;
            restart(&cp, &db).await
        }
    }
}

/// `db ensure user <name> --database <db>` — ensure a login role, printing a freshly
/// minted password once.
async fn ensure_user(
    cp: &ControlPlane,
    database: &str,
    user: &str,
    password_secret: Option<&str>,
) -> Result<DbOutput> {
    let (created, role_name, password) = cp.ensure_user(database, user, password_secret).await?;
    Ok(DbOutput::EnsureUser {
        user: user.to_string(),
        database: database.to_string(),
        role_name,
        created,
        password,
        // BYO: the operator supplied the secret, so the server mints/returns nothing — the
        // CLI renders a BYO-aware line rather than a created/already-exists one.
        byo: password_secret.is_some(),
    })
}

/// `db drop user <name> --database <db>` — drop the login role + its sealed credential.
async fn drop_user(cp: &ControlPlane, database: &str, user: &str) -> Result<DbOutput> {
    let (existed, role_name) = cp.drop_user(database, user).await?;
    Ok(DbOutput::DropUser {
        user: user.to_string(),
        database: database.to_string(),
        role_name,
        existed,
    })
}

/// `db ls` — list the declared managed databases.
async fn ls(cp: &ControlPlane) -> Result<DbOutput> {
    let databases = cp.list_databases().await?;
    Ok(DbOutput::Ls { databases })
}

/// `db get <name>` — show one declaration, plus whether a restart-requiring config
/// change is pending. `get` itself returns only the plain declaration (it must stay a
/// clean `ApplyDatabase` on the wire), so this makes one additional, best-effort
/// `status` round trip to decorate it — a failure there (e.g. an older server) just
/// omits the pending signal rather than failing the whole command.
async fn get(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let db = cp.get_database(name).await?;
    let pending_restart = cp
        .database_status(name)
        .await
        .ok()
        .and_then(|v| {
            v.get("pending_restart")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false);
    Ok(DbOutput::Get {
        database: Box::new(db),
        pending_restart,
    })
}

/// `db status <name>` — the read-only status view (declaration + derived workload +
/// the "pending restart" signal).
async fn status(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let view = cp.database_status(name).await?;
    Ok(DbOutput::Status {
        name: name.to_string(),
        view,
    })
}

/// `db restart [--db <name>]` — restart a managed database, applying any pending
/// restart-requiring config change (e.g. a flipped `delta_capture`) in the process.
async fn restart(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let (workload, config_applied, replicas_restarted) = cp.restart_database(name).await?;
    Ok(DbOutput::Restart {
        name: name.to_string(),
        workload,
        config_applied,
        replicas_restarted,
    })
}

/// Read the current `(state, reason)` readiness of a managed database from its status
/// view. `reason` is `Some` only when the state is `provision_failed`. A missing field
/// (older server) reads as `unknown`.
async fn read_readiness(cp: &ControlPlane, name: &str) -> Result<(String, Option<String>)> {
    let view = cp.database_status(name).await?;
    let readiness = view.get("readiness");
    let state = readiness
        .and_then(|r| r.get("state"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let reason = readiness
        .and_then(|r| r.get("reason"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok((state, reason))
}

/// `db ensure database <name>` — eager-provision an already-declared managed database,
/// idempotently. Posts the ensure hook, then (with `--wait`) polls readiness until the
/// database is `provisioned` (success), a post-launch action has `provision_failed`
/// (error), or the timeout elapses (returns the last observed state — provisioning was
/// initiated and may still be coming up; a Shared-tenant database that `ensure` created
/// synchronously stays `pending` here because it has no container replica flag).
async fn ensure_database(
    cp: &ControlPlane,
    name: &str,
    wait: bool,
    timeout_secs: u64,
) -> Result<DbOutput> {
    use std::time::{Duration, Instant};

    cp.ensure_database(name).await?;

    if !wait {
        let (readiness, reason) = read_readiness(cp, name).await?;
        return Ok(DbOutput::Ensure {
            name: name.to_string(),
            readiness,
            reason,
            waited: false,
        });
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let (readiness, reason) = read_readiness(cp, name).await?;
        match readiness.as_str() {
            "provisioned" => {
                return Ok(DbOutput::Ensure {
                    name: name.to_string(),
                    readiness,
                    reason,
                    waited: true,
                });
            }
            "provision_failed" => {
                return Err(Error::EnsureFailed {
                    name: name.to_string(),
                    reason: reason.unwrap_or_else(|| "unknown".to_string()),
                });
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            // Timed out while still coming up (pending / starting / service_ready). Not an
            // error — provisioning was initiated; report the last observed state.
            return Ok(DbOutput::Ensure {
                name: name.to_string(),
                readiness,
                reason,
                waited: true,
            });
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// The human table header (shared by `ls` and `get`).
fn write_header(w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let (name, kind, tenant, scope, size) = ("NAME", "KIND", "TENANT", "SCOPE", "SIZE");
    writeln!(w, "{name:<24}  {kind:<10}  {tenant:<8}  {scope:<8}  {size}")
}

/// One human table row for a declared database.
fn write_row(w: &mut dyn std::io::Write, db: &ApplyDatabase) -> std::io::Result<()> {
    writeln!(
        w,
        "{:<24}  {:<10}  {:<8}  {:<8}  {:?}",
        db.name,
        format!("{:?}", db.kind).to_lowercase(),
        format!("{:?}", db.tenant).to_lowercase(),
        format!("{:?}", db.tenant_scope).to_lowercase(),
        db.size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Rendered;

    fn render(o: &DbOutput) -> String {
        let mut buf = Vec::new();
        o.render_human(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn ensure_provisioned_has_no_initiated_hint() {
        let out = render(&DbOutput::Ensure {
            name: "default".into(),
            readiness: "provisioned".into(),
            reason: None,
            waited: true,
        });
        assert!(out.contains("ensured database `default`"), "{out}");
        assert!(out.contains("readiness: provisioned"), "{out}");
        assert!(!out.contains("provisioning initiated"), "{out}");
    }

    #[test]
    fn ensure_unwaited_nonprovisioned_shows_initiated_hint() {
        // A no-wait ensure that comes back `pending` (e.g. a container still coming up, or
        // a Shared-tenant DB with no replica flag) tells the operator how to follow up.
        let out = render(&DbOutput::Ensure {
            name: "default".into(),
            readiness: "pending".into(),
            reason: None,
            waited: false,
        });
        assert!(out.contains("readiness: pending"), "{out}");
        assert!(out.contains("provisioning initiated"), "{out}");
        assert!(out.contains("--wait"), "{out}");
    }

    #[test]
    fn status_renders_a_data_dir_ownership_fault_with_its_cure() {
        // A managed pg stuck `starting` because its data dir carries foreign-owned files:
        // the status view carries a `data_dir` fault, and the human render names the
        // volume, a sample offending entry, and the fix — the signal `/api/repair` can't
        // give (it fixes only in-pg drift, never filesystem perms).
        let view = serde_json::json!({
            "workload": "bramp-db-acme-default",
            "declared": true,
            "readiness": { "state": "starting" },
            "data_dir": {
                "volume": "data",
                "ok": false,
                "expected_uid": 100_999,
                "expected_gid": 100_999,
                "foreign_count": 12,
                "sample": { "path": "global/pg_filenode.map", "uid": 0, "gid": 0 },
            },
        });
        let out = render(&DbOutput::Status {
            name: "default".into(),
            view,
        });
        assert!(out.contains("readiness:       starting"), "{out}");
        assert!(out.contains("FOREIGN-OWNED"), "{out}");
        assert!(out.contains("volume `data`"), "{out}");
        assert!(out.contains("global/pg_filenode.map"), "{out}");
        assert!(out.contains("0:0"), "{out}");
        assert!(out.contains("100999:100999"), "{out}");
        assert!(
            out.contains("/api/repair"),
            "names the plane relationship: {out}"
        );
    }

    #[test]
    fn status_renders_a_clean_data_dir_check() {
        let view = serde_json::json!({
            "workload": "bramp-db-acme-default",
            "declared": true,
            "readiness": { "state": "starting" },
            "data_dir": { "volume": "data", "ok": true, "expected_uid": 100_999, "expected_gid": 100_999, "foreign_count": 0 },
        });
        let out = render(&DbOutput::Status {
            name: "default".into(),
            view,
        });
        assert!(out.contains("data-dir:        ownership ok"), "{out}");
        assert!(!out.contains("FOREIGN-OWNED"), "{out}");
    }

    #[test]
    fn status_without_a_data_dir_observation_omits_the_line() {
        let view = serde_json::json!({
            "workload": "bramp-db-acme-default",
            "declared": true,
            "readiness": { "state": "provisioned" },
        });
        let out = render(&DbOutput::Status {
            name: "default".into(),
            view,
        });
        assert!(out.contains("readiness:       provisioned"), "{out}");
        assert!(!out.contains("data-dir:"), "no signal → no line: {out}");
    }

    #[test]
    fn status_surfaces_readiness_and_failure_reason() {
        let view = serde_json::json!({
            "database": {"name": "default"},
            "workload": "bramp-db-acme-default",
            "declared": true,
            "readiness": {"state": "provision_failed", "reason": "data dir perms"},
        });
        let out = render(&DbOutput::Status {
            name: "default".into(),
            view,
        });
        assert!(out.contains("readiness:       provision_failed"), "{out}");
        assert!(out.contains("(data dir perms)"), "{out}");
    }

    fn sample_db(name: &str) -> ApplyDatabase {
        serde_json::from_value(serde_json::json!({ "name": name, "kind": "postgres" }))
            .expect("minimal ApplyDatabase")
    }

    /// `db status` surfaces a pending-restart signal (PLAN-sql-true-delta Stage 1b) only
    /// when the server flags it true — the common case (no pending change) stays terse.
    #[test]
    fn status_surfaces_pending_restart_only_when_true() {
        let pending = serde_json::json!({
            "workload": "bramp-db-acme-app",
            "declared": true,
            "readiness": {"state": "provisioned"},
            "pending_restart": true,
        });
        let out = render(&DbOutput::Status {
            name: "app".into(),
            view: pending,
        });
        assert!(out.contains("pending restart: yes"), "{out}");
        assert!(out.contains("db restart --db app"), "{out}");

        let clear = serde_json::json!({
            "workload": "bramp-db-acme-app",
            "declared": true,
            "readiness": {"state": "provisioned"},
            "pending_restart": false,
        });
        let out = render(&DbOutput::Status {
            name: "app".into(),
            view: clear,
        });
        assert!(!out.contains("pending restart"), "{out}");
    }

    /// `db get` decorates the plain declaration with the pending-restart signal when the
    /// server reports one — and stays terse when it does not.
    #[test]
    fn get_surfaces_pending_restart_only_when_true() {
        let out = render(&DbOutput::Get {
            database: Box::new(sample_db("app")),
            pending_restart: true,
        });
        assert!(out.contains("pending restart:"), "{out}");
        assert!(out.contains("db restart --db app"), "{out}");

        let out = render(&DbOutput::Get {
            database: Box::new(sample_db("app")),
            pending_restart: false,
        });
        assert!(!out.contains("pending restart"), "{out}");
    }

    /// `db restart` reports the workload + whether a pending config change was adopted.
    #[test]
    fn restart_reports_config_applied_and_replica_count() {
        let out = render(&DbOutput::Restart {
            name: "app".into(),
            workload: "bramp-db-acme-app-abc123".into(),
            config_applied: true,
            replicas_restarted: 1,
        });
        assert!(out.contains("restarted database `app`"), "{out}");
        assert!(out.contains("bramp-db-acme-app-abc123"), "{out}");
        assert!(out.contains("pending config change applied"), "{out}");
        assert!(out.contains("replicas stopped: 1"), "{out}");

        // No pending change: no "applied" line, but still reports the bounce.
        let out = render(&DbOutput::Restart {
            name: "app".into(),
            workload: "bramp-db-acme-app-abc123".into(),
            config_applied: false,
            replicas_restarted: 0,
        });
        assert!(!out.contains("pending config change applied"), "{out}");
        assert!(out.contains("replicas stopped: 0"), "{out}");
    }
}
