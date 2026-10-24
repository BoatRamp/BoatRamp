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
        /// Use an operator-supplied secret ref for the password instead of minting one
        /// (BYO). (Not yet supported server-side; omit to mint + seal.)
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
    /// `db get <name>` — one declaration.
    // Boxed to keep this larger payload from dwarfing the other variants.
    Get { database: Box<ApplyDatabase> },
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
            Self::Get { database } => {
                write_header(w)?;
                write_row(w, database)
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
                writeln!(w)
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
    })
}

/// `db ls` — list the declared managed databases.
async fn ls(cp: &ControlPlane) -> Result<DbOutput> {
    let databases = cp.list_databases().await?;
    Ok(DbOutput::Ls { databases })
}

/// `db get <name>` — show one declaration.
async fn get(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let db = cp.get_database(name).await?;
    Ok(DbOutput::Get {
        database: Box::new(db),
    })
}

/// `db status <name>` — the read-only status view (declaration + derived workload).
async fn status(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let view = cp.database_status(name).await?;
    Ok(DbOutput::Status {
        name: name.to_string(),
        view,
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
}
