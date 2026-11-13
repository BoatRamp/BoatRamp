//! The per-tenant managed-database **data plane** (PLAN-per-tenant-db).
//!
//! A compute-backed managed `sql` binding is no longer a single shared database:
//! every such binding is **per-tenant**, along two independent axes declared in
//! [`ExternalDatabaseConfig`](crate::config::ExternalDatabaseConfig):
//!
//! - **Isolation** ([`TenantIsolation`](crate::config::TenantIsolation)) —
//!   `Single` (a *dedicated* database server / container per tenant; isolation by
//!   process) or `Shared` (one server hosting a per-tenant database + login role;
//!   isolation by grants).
//! - **Scope** ([`TenantScope`](crate::config::TenantScope)) — `Project` (a tenant
//!   is a project) or `Site` (a tenant is a site).
//!
//! Only a bring-your-own `url_env` binding stays a single shared endpoint.
//!
//! # The #1 invariant
//!
//! **Tenant A's database credential must never be able to reach tenant B's
//! database.** This module upholds it structurally:
//!
//! - Every tenant identity is derived from the *already-validated* `(project, site)`
//!   through [`tenant_provision::sanitize_ident`], which is **injective** — two
//!   distinct tenants can never collapse to the same identifier.
//! - `Shared`: each tenant gets its own database + login role, and the role is
//!   `REVOKE CONNECT … FROM PUBLIC` + owner-granted (Postgres) / db-scoped-granted
//!   (MySQL) — so a tenant's role can connect only to *its* databases. The
//!   superuser credential is used **only** to run provisioning DDL, never handed to
//!   a tenant's data-plane backend.
//! - `Single`: the container is the boundary; each tenant's server is initialized
//!   with, and reachable only through, its **own** sealed credential.
//! - Every per-tenant credential is stored under a KV key that includes the tenant,
//!   so no two tenants (and never the shared superuser) share a sealed credential.
//!
//! # The reserved default project stays "plain"
//!
//! A single-tenant install runs under the reserved `default` project. There, a
//! binding uses its **plain configured names** — the plain `database` (and, for
//! `Single`, the plain `compute` workload) — with **no** `_<hash>` suffix, so the
//! install is just one ordinary database exactly as before per-tenant existed.
//! [`tenant_key`] marks that case (`is_default = true`).
//!
//! # Deprovision safety — the engine/cell split (safe soft delete)
//!
//! A project/site delete tears the tenant's managed database down. An immediate
//! `DROP DATABASE` is **irreversible data loss** the instant the delete is issued,
//! so [`deprovision_tenant`] splits by cell:
//!
//! | Cell                     | Behavior on delete                                    |
//! |--------------------------|-------------------------------------------------------|
//! | **Shared + Postgres**    | **Soft** delete — recoverable within the grace window |
//! | **Shared + MySQL**       | Immediate hard drop — irreversible                    |
//! | **Single** (any engine)  | Immediate hard drop — irreversible                    |
//!
//! - **Shared + Postgres** is the only cell whose engine can rename a database, so
//!   the delete: (1) `pg_terminate_backend`s the tenant DB's live sessions, (2)
//!   `ALTER DATABASE … RENAME TO "<db>__deleted_<unixts>"` — which **frees the
//!   original name immediately** so a fresh same-named tenant is clean and can never
//!   alias the renamed-aside data, (3) `ALTER ROLE … NOLOGIN` so the (retained)
//!   sealed credential can't reach the renamed data, and (4) writes a
//!   [`Tombstone`](crate::tenant_tombstone::Tombstone). A
//!   [reaper](spawn_tenant_tombstone_reaper) hard-drops it once the grace window
//!   elapses; before then [`recover_tenant`] can restore it. The sealed credential is
//!   **kept** until the reaper hard-drops (recovery needs it).
//! - **Shared + MySQL** can't rename a database, so retaining it aside would collide
//!   or leak on a same-name re-create; it keeps the immediate `DROP DATABASE` +
//!   `DROP USER`. **Single**'s isolation unit is a whole container/volume, dropped
//!   immediately (workload + credential). Both are **irreversible** — no tombstone.
//!
//! # Grace period
//!
//! The grace window is `handlers.bindings.sql.deprovision_grace_secs` (env
//! `BOATRAMP_HANDLERS_SQL_DEPROVISION_GRACE_SECS`), default **7 days**. `0` disables
//! the soft path entirely — even Shared Postgres then hard-drops immediately (opt
//! back into the pre-safe-deprovision behavior).

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::compute::{
    BackendRegistry, ComputeWorkload, ManagedDbEngine, PlacementConstraints, managed_db_alias,
    managed_db_spec,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
use boatramp_core::sql::{DeclareError, RestartOutcome, SqlBackend, SqlError, SqlValue};
use boatramp_storage::ExternalSqlKind;
use boatramp_storage::sql_compute::{
    ComputeEndpointResolver, ComputeResolvedSqlBackend, SESSION_KEY_PROJECT, SESSION_KEY_SITE,
};
use boatramp_storage::sql_sqlx::PerTenantSqlResolver;
use boatramp_storage::tenant_provision::{
    RLS_ENABLE_NOT_FORCE_COUNT_SQL, force_rls_event_trigger_ddl, force_rls_sweep_ddl,
    grant_app_role_ddl, provision_ddl, recover_soft_deprovision_ddl, sanitize_ident,
    soft_deprovision_ddl, tenant_db_name, tenant_owner_role_name, tenant_role_name,
};

use crate::config::{ExternalDatabaseConfig, ServeAs, TenantIsolation, TenantScope};
use crate::managed_sql::{DeployEndpointResolver, ManagedSqlCredentials};
use crate::tenant_tombstone::{self, Tombstone};

/// 10 GiB — the default managed data-volume size when a `Single`-mode per-tenant
/// binding sets none (matches [`auto_register_managed_db_workloads`]).
const DEFAULT_VOLUME_MIB: u32 = 10 * 1024;

/// The default soft-delete grace window: **7 days** (in seconds). A soft-deleted
/// Shared-Postgres tenant is recoverable for this long before the reaper hard-drops
/// it. A grace of `0` disables the soft path (immediate hard drop everywhere).
pub const DEFAULT_DEPROVISION_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

/// How often the tombstone reaper sweeps for due (grace-elapsed) soft-deletes.
pub const TOMBSTONE_REAPER_TICK: std::time::Duration = std::time::Duration::from_secs(3600);

/// Current unix seconds (wall clock). Split out so the reaper's due-selection logic
/// can be unit-tested with an injected "now".
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map the config engine string to the enum, defensively (config validation already
/// rejects an unparsable engine before serve).
fn engine_of(kind: ExternalSqlKind) -> ManagedDbEngine {
    match kind {
        ExternalSqlKind::Postgres => ManagedDbEngine::Postgres,
        ExternalSqlKind::Mysql => ManagedDbEngine::Mysql,
    }
}

/// The **maintenance** database a superuser connects to when running per-tenant
/// provisioning DDL on a `Shared` server (a `CREATE DATABASE` cannot run *inside*
/// the database being created). Postgres has the always-present `postgres`
/// database; MySQL uses its always-present `mysql` catalog database.
pub(crate) fn maintenance_database(kind: ExternalSqlKind) -> &'static str {
    match kind {
        ExternalSqlKind::Postgres => "postgres",
        ExternalSqlKind::Mysql => "mysql",
    }
}

/// The tenant identity for a `(project, site)` request under a binding's grain.
///
/// Returns `(tenant_ident, is_default)`:
/// - **`Project` scope** — the tenant is the project; `tenant_ident = project`,
///   `is_default = (project == "default")`.
/// - **`Site` scope** — the tenant is the site *qualified by its project*;
///   `tenant_ident = "<project>/<site>"`, `is_default = false` (a site is never the
///   reserved default tenant, so it always gets a derived name).
///
/// The returned `tenant_ident` is the **raw** identity string; callers pass it
/// through [`sanitize_ident`] before it becomes a SQL identifier. `is_default`
/// selects the "plain configured names, no hash suffix" path so a single-tenant
/// install is one ordinary database.
pub fn tenant_key(scope: TenantScope, project: &str, site: &str) -> (String, bool) {
    match scope {
        TenantScope::Project => (project.to_string(), project == DEFAULT_PROJECT),
        TenantScope::Site => (format!("{project}/{site}"), false),
    }
}

/// The derived, sanitized names for a tenant of one binding on its server.
///
/// - `database` — the physical database the tenant's data lives in. For `Shared`,
///   per-binding: [`tenant_db_name`]`(binding.database, tenant_ident)`. For the
///   default tenant, the plain `binding.database`.
/// - `role` — the tenant's **login role** (one per `(tenant, server)`, shared across
///   the tenant's bindings on that server), derived from
///   [`tenant_role_name`]`(binding.compute, tenant_ident)` so a tenant with several
///   bindings on the same server shares ONE role granted on each of its databases.
///   Only meaningful for `Shared`.
/// - `workload` — the compute workload backing the connection. For `Single`,
///   `"<compute>-<tenant_ident>"` (the tenant's dedicated server; plain `<compute>`
///   for the default tenant). For `Shared`, always the plain `binding.compute`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantNames {
    /// The physical database name for this tenant + binding.
    pub database: String,
    /// The tenant's login role (per `(tenant, server)`); used only for `Shared`.
    pub role: String,
    /// The tenant's **owner/DDL role** (per `(tenant, server)`, Shared Postgres only) — the
    /// non-superuser role that owns the schema and runs migrations, distinct from `role` so the
    /// runtime role stays a non-owner and RLS holds. For the default tenant / Single it equals the
    /// plain identity (no separate role); migrations there run as the existing per-workload user.
    pub owner_role: String,
    /// The compute workload backing the connection.
    pub workload: String,
}

/// Derive the [`TenantNames`] for `binding` and the given tenant identity.
///
/// `compute` is the binding's configured workload name (the base for both the role
/// name and, for `Single`, the per-tenant workload name); `database` is the
/// binding's configured database name (the base for the physical database name).
/// `is_default` = the reserved default tenant, which keeps the plain configured
/// names (no `_<hash>` suffix).
pub(crate) fn tenant_names(
    isolation: TenantIsolation,
    compute: &str,
    database: &str,
    tenant_ident_raw: &str,
    is_default: bool,
) -> TenantNames {
    if is_default {
        // The reserved default tenant: plain configured names, no suffix — a
        // single-tenant install is one ordinary database on one ordinary server.
        return TenantNames {
            database: database.to_string(),
            role: database.to_string(),
            // Default tenant: no separate owner role — the plain configured user already owns its
            // one ordinary database, so a migration runs as it (already <= project-owner).
            owner_role: database.to_string(),
            workload: compute.to_string(),
        };
    }
    let ident = sanitize_ident(tenant_ident_raw);
    let (db, workload) = match isolation {
        // Shared: a per-tenant DATABASE on the shared `compute` server.
        TenantIsolation::Shared => (tenant_db_name(database, &ident), compute.to_string()),
        // Single: a dedicated per-tenant WORKLOAD; the DB name inside it is the plain
        // configured `database` (the container is the isolation, not the db name).
        TenantIsolation::Single => (database.to_string(), format!("{compute}-{ident}")),
    };
    TenantNames {
        database: db,
        // One role per (tenant, server): base = the SERVER (the binding's compute
        // workload), so a tenant with several bindings on the same shared server
        // shares ONE role, granted on each of its databases. Used only for Shared.
        role: tenant_role_name(compute, &ident),
        // One owner/DDL role per (tenant, server), same base as `role` (the server), so a tenant
        // with several bindings on one shared server shares ONE owner role. Shared Postgres only;
        // inert for Single (the per-workload user is the owner) and MySQL.
        owner_role: tenant_owner_role_name(compute, &ident),
        workload,
    }
}

/// The KV key under which a per-tenant sealed credential is stored — an extension of
/// the [`ManagedSqlCredentials`] scheme that folds in the tenant so no two tenants
/// (and never the shared superuser) can share a credential:
/// `<project-or-tenant>/<workload>/<tenant_ident>`.
///
/// `key_project` is the credential's project scope (the request's project, or the
/// reserved default for a single-tenant install) and becomes the `<project>` segment
/// of the underlying [`ManagedSqlCredentials::password`] key; the returned string is
/// the `workload` argument to that call, carrying the compute workload plus the
/// sanitized tenant identity.
pub(crate) fn credential_workload_key(compute: &str, tenant_ident: &str) -> String {
    format!("{compute}/{tenant_ident}")
}

/// The KV workload segment for a tenant's **owner/DDL-role** sealed credential (Shared Postgres
/// only) — the [`credential_workload_key`] scheme with a trailing `/owner`, so the owner-role
/// password is sealed under a key distinct from both the runtime-role password
/// (`<compute>/<ident>`) and the superuser (`<compute>` under the default project). The migration
/// path resolves this to connect as the owner role; it is never handed to the handler runtime.
pub(crate) fn owner_credential_workload_key(compute: &str, tenant_ident: &str) -> String {
    format!("{compute}/{tenant_ident}/owner")
}

/// The KV **project** segment for a `Single`-mode workload's sealed credential: the
/// reserved default project for the single-tenant install (matching the bare
/// `<compute>` server-init key), else the tenant's own project (matching the
/// per-tenant workload `<compute>-<ident>` under that project). Kept beside
/// [`credential_workload_key`] so the provision + resolve + env-injector paths
/// derive the identical key.
pub(crate) fn single_credential_project(project: &str, is_default: bool) -> String {
    if is_default {
        DEFAULT_PROJECT.to_string()
    } else {
        project.to_string()
    }
}

/// The data-volume name for a `Single`-mode managed workload.
///
/// The container backend backs a persistent volume at
/// `<data_dir>/compute/volumes/<name>`, **keyed by name only** — so if every managed
/// DB used the same literal `"data"`, each per-tenant Single container would mount the
/// *same* PGDATA: a per-tenant container would reuse another tenant's (or a prior
/// default / pre-per-tenant v0.3.9) data dir, Postgres would skip `initdb`, and the app
/// would fail auth against its own freshly-minted credential (the v0.3.11 fix).
///
/// So a **non-default** per-tenant container is keyed to its own `workload` (a unique,
/// already-sanitized single path component), giving each tenant an isolated volume. The
/// **default** single-tenant install keeps the historical `"data"`, so an existing
/// deployment's volume — and its data — is untouched on upgrade.
fn managed_volume_name(workload: &str, is_default: bool) -> String {
    if is_default {
        "data".to_string()
    } else {
        workload.to_string()
    }
}

// ---------------------------------------------------------------------------
// The managed-DB restart primitive (PLAN-sql-true-delta Stage 1b): a general "config
// change that only takes effect at start" lever. `delta_capture` is its first consumer
// (flipping `wal_level=logical` / `--log-bin` in the launch argv), but the mechanism is
// generic: re-mint the content-addressed `ComputeSpec` from the CURRENT declaration,
// roll the workload's `active` pointer if it changed, then stop every currently-observed
// replica so the reconcile loop relaunches it fresh against the new spec, reattaching
// the SAME data volume (the workload/volume name never changes — only the spec id does).
//
// Scope limit (documented, not a bug): only a `Single`/`Project`-scoped binding — the
// same tenancy `delta_capture`'s true-delta export requires — is supported. A `Shared`
// server hosts other tenants (restarting it has a wider blast radius than this
// per-project primitive should own); a `Site`-scoped binding has no single workload (its
// per-site containers are created lazily, one per site, by the `sql` resolver on first
// use) — both are refused with a clear, actionable error rather than guessing a target.
// ---------------------------------------------------------------------------

/// Resolve the managed-DB restart primitive's target `(workload, is_default, engine
/// kind)` for `binding` under `project`, or `None` when its tenancy is out of scope (see
/// the module-level note above). Pure + synchronous: mirrors EXACTLY the derivation
/// `provision_single` uses (via [`tenant_key`] + [`tenant_names`]), so a restart's target
/// never drifts from what a fresh provision would register.
fn restart_target(
    binding: &ExternalDatabaseConfig,
    project: &str,
) -> Option<(String, bool, ExternalSqlKind)> {
    if binding.tenant_scope != TenantScope::Project || binding.tenant != TenantIsolation::Single {
        return None;
    }
    let kind = ExternalSqlKind::parse(&binding.kind)?;
    let compute = binding.compute.as_deref().filter(|c| !c.is_empty())?;
    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
    let names = tenant_names(
        binding.tenant,
        compute,
        binding.database.as_deref().unwrap_or_default(),
        &tenant_ident_raw,
        is_default,
    );
    Some((names.workload, is_default, kind))
}

/// Whether `binding`'s tenancy is in scope for the restart primitive at all (`Single` +
/// `Project`-scoped) — the cheap pre-check `declare`'s `restart_policy: auto` hook uses
/// to decide whether to even attempt [`restart_pending`]/[`restart_managed_db`], so it
/// can log a clear one-time notice instead of treating "out of scope" the same as
/// "nothing changed".
pub(crate) fn restart_supported(binding: &ExternalDatabaseConfig, project: &str) -> bool {
    restart_target(binding, project).is_some()
}

/// The clear, actionable refusal for a restart request whose binding's tenancy
/// [`restart_target`] does not support (see the module-level scope-limit note above).
fn restart_scope_message(binding: &ExternalDatabaseConfig, name: &str) -> String {
    if binding.tenant_scope != TenantScope::Project {
        format!(
            "database {name:?}: restart is only supported for a project-scoped managed \
             database today; a site-scoped binding has no single workload to restart (its \
             per-site containers are created lazily)"
        )
    } else if binding.tenant != TenantIsolation::Single {
        format!(
            "database {name:?}: restart is only supported for a dedicated (tenant: single) \
             managed database today; a shared server hosts other tenants, so restarting it is \
             out of scope for this per-project primitive"
        )
    } else {
        format!("database {name:?}: not compute-backed or an unknown engine; nothing to restart")
    }
}

/// Re-mint the managed-DB [`ComputeSpec`](boatramp_core::compute::ComputeSpec) from
/// `binding`'s CURRENT fields — the EXACT construction `provision_single` /
/// `auto_register_managed_db_workloads` use (image, volume size, the `delta_capture`
/// launch argv, the startup-grace override, and — for a non-default tenant — the
/// isolated per-workload volume name) — so the restart primitive's remint can never
/// drift from what a fresh provision would produce.
fn remint_managed_db_spec(
    binding: &ExternalDatabaseConfig,
    kind: ExternalSqlKind,
    workload: &str,
    is_default: bool,
) -> boatramp_core::compute::ComputeSpec {
    let mut spec = managed_db_spec(
        engine_of(kind),
        binding.image.as_deref(),
        binding.volume_size_mib.unwrap_or(DEFAULT_VOLUME_MIB),
        binding.delta_capture,
    );
    if let Some(grace) = binding.startup_grace_secs {
        spec.startup_grace_secs = grace;
    }
    if let Some(vol) = spec.volumes.first_mut() {
        vol.name = managed_volume_name(workload, is_default);
    }
    spec
}

/// Whether `binding` (declared as `name` in `project`) has a restart-requiring config
/// change staged but not yet applied — backs [`ManagedDbDeclare::restart_pending`](
/// boatramp_core::sql::ManagedDbDeclare::restart_pending). `Ok(false)` (never an error)
/// when the tenancy is out of scope for the restart primitive, or the database has not
/// been provisioned yet (nothing to be "behind" relative to).
pub(crate) async fn restart_pending(
    deploy: &DeployStore,
    binding: &ExternalDatabaseConfig,
    project: &str,
) -> Result<bool, DeclareError> {
    let Some((workload, is_default, kind)) = restart_target(binding, project) else {
        return Ok(false);
    };
    let proj = ProjectRef::new(project);
    let Some(wl) = deploy
        .get_compute_workload(proj, &workload)
        .await
        .map_err(|e| DeclareError::Other(e.to_string()))?
    else {
        return Ok(false); // not yet provisioned — nothing pending.
    };
    let fresh = remint_managed_db_spec(binding, kind, &workload, is_default);
    Ok(fresh.id() != wl.active)
}

/// Restart managed database `name` (`binding`, already resolved + validated as the
/// managed-credential path) in `project` — backs
/// [`ManagedDbDeclare::restart`](boatramp_core::sql::ManagedDbDeclare::restart). Re-mints
/// the spec from the current binding, rolls the workload's `active` pointer if it
/// changed, then stops every currently-observed replica so the reconcile loop relaunches
/// it fresh (reattaching the same data volume). `backends` resolves each observed
/// replica's backend to call `stop` on; a replica whose backend is no longer registered
/// is just forgotten (its state is dropped so the reconcile treats it as missing).
pub(crate) async fn restart_managed_db(
    deploy: &DeployStore,
    backends: &BackendRegistry,
    binding: &ExternalDatabaseConfig,
    project: &str,
    name: &str,
) -> Result<RestartOutcome, DeclareError> {
    let Some((workload, is_default, kind)) = restart_target(binding, project) else {
        return Err(DeclareError::Other(restart_scope_message(binding, name)));
    };
    let proj = ProjectRef::new(project);
    let Some(wl) = deploy
        .get_compute_workload(proj, &workload)
        .await
        .map_err(|e| DeclareError::Other(e.to_string()))?
    else {
        return Err(DeclareError::NotProvisioned(name.to_string()));
    };

    let fresh = remint_managed_db_spec(binding, kind, &workload, is_default);
    let new_id = deploy
        .put_compute_spec(&fresh)
        .await
        .map_err(|e| DeclareError::Other(e.to_string()))?;
    let config_applied = new_id != wl.active;
    if config_applied {
        let rolled = ComputeWorkload {
            active: new_id,
            ..wl
        };
        deploy
            .set_compute_workload(proj, &rolled)
            .await
            .map_err(|e| DeclareError::Other(e.to_string()))?;
    }

    let states = deploy
        .list_replica_states(proj, &workload)
        .await
        .map_err(|e| DeclareError::Other(e.to_string()))?;
    // Mirrors `NodeComputeControl::restart`'s fail-closed semantics (Security review
    // LOW-2): a replica whose backend is not registered ON THIS NODE is left ALONE —
    // its state is NOT deleted — rather than silently forgotten. Deleting it anyway
    // (the prior behavior) could make the reconcile loop launch a FRESH replica while
    // the old one keeps running unstopped elsewhere, risking two servers on the same
    // data volume. The config change is still staged (the spec was already rolled
    // above); only the live bounce of this particular replica is refused.
    let mut replicas_restarted = 0usize;
    for state in &states {
        let Some(backend) = backends.get(&state.backend) else {
            return Err(DeclareError::Other(format!(
                "restart {workload}/{}: backend {:?} is not registered on this node; refusing \
                 to forget this replica (it may still be running) — the config change is \
                 staged and will apply on its next successful restart",
                state.handle.replica, state.backend
            )));
        };
        match backend.stop(&state.handle).await {
            Ok(()) => {}
            Err(boatramp_core::compute::BackendError::Unsupported) => {
                return Err(DeclareError::Other(format!(
                    "restart {workload}/{}: backend {:?} does not support stop",
                    state.handle.replica, state.backend
                )));
            }
            Err(e) => {
                return Err(DeclareError::Other(format!(
                    "restart {workload}/{}: stop: {e}",
                    state.handle.replica
                )));
            }
        }
        deploy
            .delete_replica_state(proj, &workload, state.handle.replica)
            .await
            .map_err(|e| DeclareError::Other(e.to_string()))?;
        replicas_restarted += 1;
    }

    Ok(RestartOutcome {
        workload,
        config_applied,
        replicas_restarted,
    })
}

/// The **compute-backed managed** bindings of a `databases` config — the ones this
/// module owns (every compute-backed binding is per-tenant; a bring-your-own
/// `url_env` binding is skipped). Returns `(name, engine, config)` tuples.
fn managed_bindings(
    databases: &std::collections::BTreeMap<String, ExternalDatabaseConfig>,
) -> Vec<(&str, ExternalSqlKind, &ExternalDatabaseConfig)> {
    databases
        .iter()
        .filter_map(|(name, db)| {
            db.compute.as_deref().filter(|c| !c.is_empty())?;
            let kind = ExternalSqlKind::parse(&db.kind)?;
            Some((name.as_str(), kind, db))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Provisioning (idempotent, callable at config time or from a create hook).
// ---------------------------------------------------------------------------

/// Provision **one** compute-backed managed binding for the tenant identified by
/// `(project, site)`. Idempotent: re-provisioning an existing tenant is harmless.
///
/// - **Shared** — connect to the shared workload **as the superuser** (the binding's
///   `user` + its sealed superuser password, keyed under the reserved default
///   project so it matches the server-init credential) to the maintenance database,
///   then run [`provision_ddl`] for the tenant's database + role + per-tenant
///   password through `run_script`. A Postgres "database already exists" error on the
///   `CREATE DATABASE` statement is treated as success (the engine contract).
/// - **Single** — register a **dedicated per-tenant compute workload**
///   (`<compute>-<tenant_ident>`) via the same path as
///   [`auto_register_managed_db_workloads`], with its own sealed credential. No role
///   DDL — the container is the isolation.
///
/// A bring-your-own (`url_env`) binding, or a binding whose engine is unparsable, is
/// a no-op.
pub async fn provision_tenant(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    project: &str,
    site: &str,
) -> Result<(), String> {
    let Some(compute) = binding.compute.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(()); // bring-your-own url_env binding — not ours.
    };
    let Some(kind) = ExternalSqlKind::parse(&binding.kind) else {
        return Ok(()); // config validation rejects this before serve.
    };
    let database = binding.database.as_deref().unwrap_or_default();
    let user = binding.user.as_deref().unwrap_or_default();

    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, site);
    let names = tenant_names(
        binding.tenant,
        compute,
        database,
        &tenant_ident_raw,
        is_default,
    );
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    match binding.tenant {
        TenantIsolation::Single => {
            provision_single(deploy, &creds, binding, kind, project, &names, is_default).await
        }
        TenantIsolation::Shared => {
            if is_default {
                // The single-tenant install on a shared server is just the plain
                // database initialized by the server's own env — nothing per-tenant
                // to provision (the superuser IS the app user here). No-op.
                return Ok(());
            }
            let ident = sanitize_ident(&tenant_ident_raw);
            provision_shared(
                deploy,
                &creds,
                kind,
                compute,
                user,
                project,
                &names,
                &ident,
                // FORCE follows the `serve_as` posture: installed iff this binding serves
                // `rls_session` AS the owner (the only posture `ENABLE` does not already bind).
                install_force_rls(binding.rls_session, binding.serve_as, kind),
            )
            .await
        }
    }
}

/// `Single`: register (if absent) the tenant's dedicated compute workload with its
/// own sealed credential. Non-clobbering + idempotent — an operator-declared or
/// already-registered workload wins, so a re-run is a no-op.
#[allow(clippy::too_many_arguments)]
async fn provision_single(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    kind: ExternalSqlKind,
    project: &str,
    names: &TenantNames,
    is_default: bool,
) -> Result<(), String> {
    // Materialise the sealed credential now, so the reconcile's launch env (which reads
    // the same key) initializes the container with exactly this password. For Single,
    // the credential key is the workload's OWN `(project, workload)` — the DEFAULT
    // tenant's bare `<compute>` under the reserved default project, a derived tenant's
    // `<compute>-<ident>` under its project — matching exactly the key the server-init
    // env injector resolves for that workload (see `ManagedDbEnv`). No `_role` suffix:
    // a Single tenant's isolation is its container, not a per-database role.
    let cred_project = single_credential_project(project, is_default);
    creds
        .password(&cred_project, &names.workload)
        .await
        .map_err(|e| format!("per-tenant credential ({}): {e}", names.workload))?;

    // The workload lives under the tenant's project scope so a project tenant's server
    // is addressed within its own project's replica namespace.
    let proj = ProjectRef::new(project);
    match deploy.get_compute_workload(proj, &names.workload).await {
        Ok(Some(_)) => return Ok(()), // already registered — idempotent.
        Ok(None) => {}
        Err(e) => return Err(format!("check workload {}: {e}", names.workload)),
    }
    let mut spec = managed_db_spec(
        engine_of(kind),
        binding.image.as_deref(),
        binding.volume_size_mib.unwrap_or(DEFAULT_VOLUME_MIB),
        binding.delta_capture,
    );
    // An operator-set startup grace overrides the engine default the synthesizer picked.
    // Applied identically here and in the shared `auto_register` path so the two
    // managed-registration paths build the byte-identical (content-addressed) spec.
    if let Some(grace) = binding.startup_grace_secs {
        spec.startup_grace_secs = grace;
    }
    // Isolate a per-tenant (non-default) Single container's data volume (see
    // [`managed_volume_name`]).
    if let Some(vol) = spec.volumes.first_mut() {
        vol.name = managed_volume_name(&names.workload, is_default);
    }
    let spec_id = deploy
        .put_compute_spec(&spec)
        .await
        .map_err(|e| format!("store spec for {}: {e}", names.workload))?;
    let wl = ComputeWorkload {
        version: 1,
        name: names.workload.clone(),
        active: spec_id,
        replicas: 1,
        placement: PlacementConstraints::default(),
    };
    deploy
        .set_compute_workload(proj, &wl)
        .await
        .map_err(|e| format!("register workload {}: {e}", names.workload))?;
    Ok(())
}

/// `Shared`: connect as the superuser to the maintenance database and run the
/// tenant's provisioning DDL (create database + role, lock to the role). Mints the
/// per-tenant login password under the per-tenant credential key.
#[allow(clippy::too_many_arguments)]
async fn provision_shared(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    kind: ExternalSqlKind,
    compute: &str,
    superuser: &str,
    project: &str,
    names: &TenantNames,
    tenant_ident: &str,
    install_force_rls: bool,
) -> Result<(), String> {
    // Superuser credential = the server's own managed credential, keyed under the
    // reserved default project + the bare workload (exactly as the server was
    // initialized and as the endpoint-injector resolves it). NEVER a tenant key.
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, compute)
        .await
        .map_err(|e| format!("superuser credential ({compute}): {e}"))?;

    // The per-tenant login password, under the per-tenant credential key.
    let cred_workload = credential_workload_key(compute, tenant_ident);
    let tenant_pw = creds
        .password(project, &cred_workload)
        .await
        .map_err(|e| format!("per-tenant credential ({}): {e}", names.role))?;

    // The per-tenant OWNER/DDL-role password, sealed under a distinct key. This is the identity a
    // schema migration connects as (a non-superuser role that owns this tenant's schema) — minted
    // here at provision so it is present before the first migration; the migrate path resolves the
    // same key. Never handed to the handler runtime.
    let owner_cred_workload = owner_credential_workload_key(compute, tenant_ident);
    let owner_pw = creds
        .password(project, &owner_cred_workload)
        .await
        .map_err(|e| format!("per-tenant owner credential ({}): {e}", names.owner_role))?;

    // Connect to the MAINTENANCE database as the superuser (CREATE DATABASE cannot run
    // inside the database being created). Reuses the same endpoint-resolving backend
    // the handler path uses, so it follows the server across restarts.
    let resolver = Arc::new(DeployEndpointResolver::new_ungated(
        deploy.clone(),
        DEFAULT_PROJECT,
    ));
    let admin = ComputeResolvedSqlBackend::new(
        resolver,
        compute,
        kind,
        maintenance_database(kind),
        superuser,
        superuser_pw.clone(),
        Some(1),
        false,
        Some(Duration::from_secs(10)),
    );

    // Run each statement in order. The "database already exists" tolerance is
    // scoped to ONLY the bare `CREATE DATABASE` statement (idempotency contract);
    // any other statement failing — crucially the `REVOKE CONNECT ... FROM PUBLIC`
    // and the per-role `GRANT`s that lock the database down — is FATAL, so we never
    // report a tenant provisioned while its isolation DDL didn't apply. Because the
    // caller (`resolve`) propagates this error and hands back no connection, a
    // partially-created (created-but-not-yet-revoked) database is never served; the
    // next resolve re-runs the idempotent DDL and completes the lockdown. (L2 + M2)
    // RLS fencing's event trigger is DATABASE-LOCAL (per-database object) and must run connected
    // to the tenant database, so it is NOT emitted here (this loop runs against the MAINTENANCE
    // database) — pass `false` to keep the maintenance DDL byte-identical. The FORCE-on-ENABLE
    // trigger is installed on the tenant-DB connection below (alongside the app-role grants).
    for stmt in provision_ddl(
        kind,
        &names.database,
        &names.role,
        &tenant_pw,
        &names.owner_role,
        &owner_pw,
        false,
    ) {
        if let Err(e) = admin.run_script(&stmt).await {
            let is_create_database = stmt.to_ascii_uppercase().contains("CREATE DATABASE");
            if is_create_database && is_database_exists_error(&e) {
                continue;
            }
            return Err(format!("provision {}: {e}", names.database));
        }
    }

    // Grant the tenant's non-superuser login role the everyday app privileges on the
    // objects in its OWN database (Postgres `Shared` only — schema objects are OWNER-role-owned
    // now, so without this the runtime role can't touch its tables; `grant_app_role_ddl` is empty
    // for MySQL, whose `db.*` grant already covers it). The `owner` argument is the per-project
    // OWNER role — so `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` fires on the objects a migration
    // (which runs as that owner role) creates; otherwise the runtime role would get
    // `permission denied` on every migration-created table. Runs INSIDE the tenant database —
    // schema grants + `ALTER DEFAULT PRIVILEGES` are database-local — as the superuser (which
    // bypasses the CONNECT gate and can set default privileges on behalf of any role). Idempotent;
    // the migrate path re-runs it after each apply so newly-created tables are covered too.
    let mut tenant_db_ddl = grant_app_role_ddl(kind, &names.role, &names.owner_role);
    // `serve_as: owner` RLS fencing (Postgres only): install the FORCE-on-ENABLE event trigger in
    // the TENANT database (event triggers are per-database objects, so they belong here, not on the
    // maintenance connection above). FORCE is installed IFF the binding serves `rls_session` AS the
    // owner (`install_force_rls` — computed by the caller from the posture) — the only posture whose
    // serving role operates as the owner, which plain `ENABLE` does not bind. A `non-owner` binding
    // serves a role `ENABLE` already binds, so no trigger is installed. The `SECURITY DEFINER`
    // function is owned by the per-tenant owner so it may FORCE RLS on the owner-owned tenant tables.
    // Idempotent; a re-provision re-runs it harmlessly. Empty for MySQL (no row-level security).
    if install_force_rls {
        tenant_db_ddl.extend(force_rls_event_trigger_ddl(kind, &names.owner_role));
    }
    if !tenant_db_ddl.is_empty() {
        let tenant_resolver = Arc::new(DeployEndpointResolver::new_ungated(
            deploy.clone(),
            DEFAULT_PROJECT,
        ));
        let tenant_admin = ComputeResolvedSqlBackend::new(
            tenant_resolver,
            compute,
            kind,
            names.database.clone(),
            superuser,
            superuser_pw,
            Some(1),
            false,
            Some(Duration::from_secs(10)),
        );
        for stmt in tenant_db_ddl {
            tenant_admin
                .run_script(&stmt)
                .await
                .map_err(|e| format!("provision tenant-db DDL on {}: {e}", names.database))?;
        }

        // `serve_as: owner` FORCE-LIVE invariant (Security FINDING 1) — owner-posture ONLY
        // (`install_force_rls` ⟺ `serve_as: owner`), so it NEVER touches the non-owner / REPLICATE
        // path (construens's deliberate ENABLE-not-FORCE shape stays byte-identical). The event
        // trigger installed above is SURGICAL / non-retroactive — it FORCEs only tables created or
        // altered AFTER install. A posture flip onto a POPULATED database, or a cross-posture
        // clone/sync (a non-owner source's ENABLE-only tables landing here), would otherwise leave
        // PRE-EXISTING ENABLE-only tables un-FORCED while the owner-serving role serves them, and
        // plain ENABLE does NOT bind the owner ⇒ within-app cross-tenant leak. So: (1) retroactively
        // FORCE-sweep every existing ENABLE-not-FORCE table, then (2) hard-assert ZERO remain —
        // REFUSE fail-closed if any slipped past the sweep. This makes owner-serving ⟺ FORCE
        // ACTUALLY LIVE (not merely posture-declared); it runs here (a DB connection exists), never
        // in `connection_parts` (which composes the DSN before the DB may be up).
        if install_force_rls {
            for stmt in force_rls_sweep_ddl(kind) {
                tenant_admin
                    .run_script(&stmt)
                    .await
                    .map_err(|e| format!("force-rls sweep on {}: {e}", names.database))?;
            }
            let rows = tenant_admin
                .run_query(RLS_ENABLE_NOT_FORCE_COUNT_SQL)
                .await
                .map_err(|e| format!("force-rls assert query on {}: {e}", names.database))?;
            let remaining = match rows.rows.into_iter().flatten().next() {
                Some(SqlValue::Integer(n)) => n,
                other => {
                    return Err(format!(
                        "force-rls assert on {}: unexpected count cell {other:?}",
                        names.database
                    ));
                }
            };
            if remaining != 0 {
                return Err(format!(
                    "serve_as: owner FORCE-live invariant violated on {}: {remaining} RLS-enabled \
                     table(s) remain ENABLE-but-NOT-FORCE after the FORCE-sweep — the owner-serving \
                     role could bypass their row-level security; refusing to provision (fail-closed)",
                    names.database
                ));
            }
        }
    }
    Ok(())
}

/// Whether a SQL error is a benign "database already exists" (Postgres SQLSTATE
/// 42P04, surfaced in the message by sqlx). Treated as success on the idempotent
/// `CREATE DATABASE` per the [`provision_ddl`] contract.
pub(crate) fn is_database_exists_error(err: &SqlError) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("already exists") && msg.contains("database")
}

/// Provision **every** compute-backed managed binding in a `databases` config for
/// the tenant `(project, site)`. Best-effort per binding is *not* used here — a
/// provisioning failure is returned so a create hook can surface it (the binding
/// would otherwise fail closed at first `open`); the caller decides fatality.
pub async fn provision_binding_for_tenants(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    databases: &std::collections::BTreeMap<String, ExternalDatabaseConfig>,
    project: &str,
    site: &str,
) -> Result<(), String> {
    for (_name, _kind, binding) in managed_bindings(databases) {
        provision_tenant(deploy, kv, envelope, binding, project, site).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deprovision (for project/site delete hooks).
// ---------------------------------------------------------------------------

/// Build the superuser **maintenance** backend for a Shared server — the same
/// endpoint-resolving path [`provision_shared`] uses to run tenant DDL. Connects as
/// the superuser (`user` + its sealed superuser password under the reserved default
/// project) to the engine's maintenance database.
async fn shared_admin_backend(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    kind: ExternalSqlKind,
    compute: &str,
    superuser: &str,
) -> Result<ComputeResolvedSqlBackend, String> {
    shared_admin_backend_for_db(
        deploy,
        creds,
        kind,
        compute,
        superuser,
        maintenance_database(kind),
    )
    .await
}

/// Build the superuser backend for a Shared server connected to a **specific** database
/// `database` (rather than the always-present maintenance db). Same endpoint-resolving,
/// same sealed superuser credential — only the connect-target database differs. Mirrors
/// the second-backend pattern [`provision_shared`] uses to run the tenant-db-local
/// `grant_app_role_ddl` inside the tenant's own database.
///
/// The provisioning drift-repair path needs BOTH: the maintenance-db connection for
/// `ALTER DATABASE … OWNER` (which can't run inside the db being altered) and a
/// **tenant-db** connection for `REASSIGN OWNED` + ledger re-ownership (which must run
/// connected to the tenant's own database). `database` is a caller-DERIVED, sanitized
/// tenant db name — never operator input; the repair path additionally asserts
/// `current_database()` equals it before any `REASSIGN OWNED` fires.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub(crate) async fn shared_admin_backend_for_db(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    kind: ExternalSqlKind,
    compute: &str,
    superuser: &str,
    database: &str,
) -> Result<ComputeResolvedSqlBackend, String> {
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, compute)
        .await
        .map_err(|e| format!("superuser credential ({compute}): {e}"))?;
    let resolver = Arc::new(DeployEndpointResolver::new_ungated(
        deploy.clone(),
        DEFAULT_PROJECT,
    ));
    Ok(ComputeResolvedSqlBackend::new(
        resolver,
        compute,
        kind,
        database.to_string(),
        superuser,
        superuser_pw,
        Some(1),
        false,
        Some(Duration::from_secs(10)),
    ))
}

/// Tear down one compute-backed managed binding for the tenant `(project, site)`.
///
/// **The delete behavior splits by cell** (see the module-level matrix) — because an
/// immediate `DROP DATABASE` is irreversible data loss:
///
/// - **Shared + Postgres** (renameable engine), `grace_secs > 0` — **soft delete**:
///   terminate the tenant DB's connections, `ALTER DATABASE … RENAME` it aside to
///   `<db>__deleted_<unixts>` (freeing the original name at once), `ALTER ROLE …
///   NOLOGIN`, and write a [`Tombstone`] with `delete_after = now + grace_secs`. The
///   sealed credential is **kept** (recovery needs it). Recoverable via
///   [`recover_tenant`] until the [reaper](spawn_tenant_tombstone_reaper) hard-drops.
/// - **Shared + MySQL** and **all Single** (or Shared-Postgres with `grace_secs =
///   0`) — **immediate hard delete** (irreversible): Shared runs
///   [`deprovision_ddl`](boatramp_storage::tenant_provision::deprovision_ddl)
///   (`DROP DATABASE/ROLE IF EXISTS`) then deletes the sealed credential; Single
///   deletes the dedicated compute workload (the reconcile tears down its container)
///   and its credential.
///
/// The reserved default tenant is left untouched (its "database" is the ordinary
/// single-tenant install; deprovisioning it would delete the whole install).
pub async fn deprovision_tenant(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    project: &str,
    site: &str,
    grace_secs: u64,
) -> Result<(), String> {
    let Some(plan) = plan_deprovision(binding, project, site, grace_secs, now_unix_secs()) else {
        return Ok(()); // not ours / bring-your-own / the reserved default tenant.
    };
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    match plan {
        DeprovisionPlan::SingleDrop { workload } => {
            // Single's isolation unit is a whole container/volume — dropped
            // immediately (there is no rename-aside for a container). Irreversible.
            deploy
                .delete_compute_workload(ProjectRef::new(project), &workload)
                .await
                .map_err(|e| format!("delete workload {workload}: {e}"))?;
            // The Single credential is keyed by the workload's own `(project, workload)`
            // (matching provision + the server-init env injector) — the bare derived
            // workload name under the tenant's project, no `credential_workload_key`.
            creds
                .delete(project, &workload)
                .await
                .map_err(|e| format!("delete credential {workload}: {e}"))?;
        }
        DeprovisionPlan::SharedImmediate {
            kind,
            compute,
            superuser,
            ddl,
            cred_workload,
            database,
        } => {
            // Shared + MySQL (no database rename) OR Shared-Postgres with grace = 0
            // (opted out): immediate hard drop. Irreversible.
            let admin = shared_admin_backend(deploy, &creds, kind, &compute, &superuser).await?;
            for stmt in ddl {
                admin
                    .run_script(&stmt)
                    .await
                    .map_err(|e| format!("deprovision {database}: {e}"))?;
            }
            creds
                .delete(project, &cred_workload)
                .await
                .map_err(|e| format!("delete credential {cred_workload}: {e}"))?;
        }
        DeprovisionPlan::SharedSoftPostgres { ddl, tombstone } => {
            // The ONE recoverable cell. terminate → RENAME (frees the original name) →
            // NOLOGIN via the superuser maintenance connection. Any statement failing
            // is fatal (returned Err); the caller logs it best-effort and the delete is
            // not blocked. No tombstone is written unless the DDL fully applied, so a
            // half-renamed database never leaves an orphan tombstone. The sealed
            // credential is deliberately KEPT (recovery needs it).
            let admin = shared_admin_backend(
                deploy,
                &creds,
                ExternalSqlKind::Postgres,
                &tombstone.compute,
                &tombstone.superuser,
            )
            .await?;
            for stmt in ddl {
                admin
                    .run_script(&stmt)
                    .await
                    .map_err(|e| format!("soft-deprovision {}: {e}", tombstone.original_db))?;
            }
            tenant_tombstone::put(kv, &tombstone).await?;
        }
    }
    Ok(())
}

/// HARD-drop an ORPHANED Shared-Postgres managed tenant BY IDENTITY — the operator
/// `db drop database --orphan` recovery verb for a tenant whose declaration is GONE but whose
/// physical database a prior failed `project sync` / `project rm` left behind, so the normal
/// declared deprovision ([`deprovision_tenant`]) cannot reach it (no declared binding to resolve).
///
/// DATA-LOSS-SENSITIVE + tenancy-sensitive — flagged for Security review. The hard scoping is
/// STRUCTURAL, not a string check: EVERY name (`compute`, the physical database, the login + owner
/// roles, the sealed credential keys) is DERIVED from `(binding, project)` through the SAME
/// `tenant_names` / credential-key helpers provisioning used — NEVER from an operator-supplied raw
/// name — so this can only ever target THIS project's own derived database within the node's managed
/// derived-name namespace. An arbitrary / foreign / system database name is unreachable by
/// construction (the caller names `(project, binding)`, and the physical name is computed here). The
/// reserved default tenant is refused (its database IS the single-tenant install). Idempotent: every
/// DROP is `IF EXISTS`, so clearing an already-absent orphan is a clean no-op.
///
/// Unlike [`deprovision_tenant`]'s immediate Shared cell (which drops only the DB + login role and
/// LEAKS the `_owner` role), this FULLY clears the per-tenant derived OWNER (`…_owner`) + login roles
/// — even when they still OWN OBJECTS the single-name `DROP DATABASE` cannot reach (a `__deleted_` /
/// `__old_` aside a prior failed sync left behind, owner-owned: the construens v0.59.4 sixth-layer
/// wall, where a plain `DROP ROLE` errors "cannot be dropped because some objects depend on it —
/// owner of database <aside>", leaking the roles + the aside). It does so DATA-LOSS-SAFELY: a role is
/// force-cleared ONLY when it belongs EXCLUSIVELY to THIS orphan (owns/is-granted on nothing but this
/// orphan's own derived database + bounded asides of it). A role SHARED with a STILL-LIVE sibling
/// binding (per-tenant roles are per-`(tenant, server)`, so a tenant with several bindings on one
/// shared server shares ONE owner + ONE login role, granted on each of its databases) is LEFT INTACT
/// and surfaced in the returned [`retained_roles`](HardDropOutcome::retained_roles) — never force-
/// cleared, because force-clearing it would destroy the live binding's objects (the HARD GUARD).
///
/// Returns the derived physical database name that was targeted + the roles deliberately retained.
///
/// Scoped to Shared Postgres (the construens per-tenant-db orphan shape): a Single tenant's isolation
/// unit is a whole dedicated container (torn down via the compute surface, not a DB drop), and MySQL
/// has no separate owner role; both are refused here with a clear message.
pub async fn hard_drop_orphan_tenant(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    project: &str,
) -> Result<HardDropOutcome, String> {
    let Some(compute) = binding.compute.as_deref().filter(|c| !c.is_empty()) else {
        return Err("orphan drop: binding is not a managed (compute-backed) database".to_string());
    };
    let Some(kind) = ExternalSqlKind::parse(&binding.kind) else {
        return Err(format!("orphan drop: unparsable engine {:?}", binding.kind));
    };
    if kind != ExternalSqlKind::Postgres {
        return Err(
            "orphan drop (`db drop database --orphan`) supports Shared Postgres managed databases \
             only; a MySQL or Single/dedicated tenant is torn down via its normal delete path"
                .to_string(),
        );
    }
    if !matches!(binding.tenant, TenantIsolation::Shared) {
        return Err(
            "orphan drop supports Shared-tenancy managed databases only (a Single/dedicated tenant's \
             isolation unit is a whole container, dropped via the compute surface)"
                .to_string(),
        );
    }
    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
    if is_default {
        return Err(
            "the reserved `default` tenant's database is the single-tenant install and cannot be \
             orphan-dropped"
                .to_string(),
        );
    }
    let database = binding.database.as_deref().unwrap_or_default();
    let superuser = binding.user.as_deref().unwrap_or_default();
    let ident = sanitize_ident(&tenant_ident_raw);
    let names = tenant_names(binding.tenant, compute, database, &tenant_ident_raw, false);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let admin = shared_admin_backend(deploy, &creds, kind, compute, superuser).await?;

    // 1. Terminate any lingering sessions on the orphan, then HARD-drop the database (fatal: the
    //    whole point is to clear the name so a re-sync's CREATE/rename lands). `IF EXISTS` ⇒ a clean
    //    no-op on an already-absent orphan (idempotent).
    // The physical name is a `sanitize_ident` output (safe `[a-z0-9_]` charset); the single-quote
    // doubling is defensive belt-and-suspenders for the terminate-sweep literal.
    let db_lit = format!("'{}'", names.database.replace('\'', "''"));
    let db_id = boatramp_storage::tenant_provision::quote_ident(kind, &names.database);
    admin
        .run_script(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = {db_lit} AND pid <> pg_backend_pid();"
        ))
        .await
        .map_err(|e| format!("orphan drop: terminate sessions on {}: {e}", names.database))?;
    admin
        .run_script(&format!("DROP DATABASE IF EXISTS {db_id};"))
        .await
        .map_err(|e| format!("orphan drop: DROP DATABASE {}: {e}", names.database))?;

    // 2. FULLY clear the per-tenant derived roles (login + owner), DATA-LOSS-SAFELY. The immediate
    //    declared drop merely `DROP ROLE IF EXISTS`es them, which ERRORS (and is best-effort-skipped)
    //    the moment a role still OWNS OBJECTS the single-name `DROP DATABASE` above did not reach — a
    //    `__deleted_`/`__old_` aside a prior failed sync left behind, owner-owned (construens's
    //    sixth-layer wall), so the roles + that aside LEAK. We clear them properly, but ONLY when
    //    they belong EXCLUSIVELY to THIS orphan.
    //
    //    THE HARD GUARD (fail-safe; the DATA-LOSS-sensitive seam a Security review gates): the derived
    //    login/owner roles are per-`(tenant, SERVER)`, so a tenant with SEVERAL bindings on one shared
    //    server shares ONE login + ONE owner role, granted on EACH of its databases. A role that also
    //    owns / is granted on a database OUTSIDE this orphan's own derived namespace is therefore
    //    SHARED with a STILL-LIVE sibling binding — force-clearing it would destroy the live binding's
    //    objects. So: enumerate (COMPREHENSIVELY) every database each role still depends on; if ANY is a
    //    FOREIGN database (not this orphan's own derived DB or a bounded aside of it), LEAVE every role
    //    intact + surface it, and NEVER force-clear. Otherwise every dependency is this orphan's own
    //    disposable data, so DROP the orphan's own aside databases and `DROP ROLE` each role —
    //    [`clear_exclusive_role`], a SELF-GUARDING `DROP ROLE` that Postgres refuses the moment a live
    //    dependency remains, so it can never force past one (it then LEAVES the role, never a blanket
    //    `DROP OWNED` that would revoke a live binding's shared-object privileges, never a foreign
    //    database dropped). Every name is STRUCTURAL (derived for, or read from the cluster for, THIS
    //    tenant's own roles) and the aside classifier only ever matches a
    //    `<this-orphan-derived-prefix><aside-marker><suffix>` name, so this can only ever touch THIS
    //    orphan's own databases.
    let maint_db = maintenance_database(kind);
    // Teardown reconcile: the primary db is ALREADY dropped (step 1), so clear EVERY one of the
    // orphan's own asides ([`ORPHAN_ASIDE_MARKERS`], tombstone included — the operator confirmed
    // disposal) AND `DROP ROLE` each exclusively-owned role. The shared-with-live fail-safe + the
    // self-guarding `DROP ROLE` live in the shared core; this is the `drop_roles = true` arm.
    let retained_roles = reconcile_derived_role_tangle(
        &admin,
        kind,
        &[names.role.as_str(), names.owner_role.as_str()],
        &names.database,
        maint_db,
        &ORPHAN_ASIDE_MARKERS,
        true,
    )
    .await?
    .retained_roles;

    // 3. Best-effort: delete the sealed per-tenant credentials (login + owner). Keeping them would
    //    only leave dead KV entries; a failure here never blocks the drop. (We keep the sealed creds
    //    for any role we deliberately RETAINED — a live sibling still resolves them.)
    if retained_roles.is_empty() {
        let login_cred = credential_workload_key(compute, &ident);
        let owner_cred = owner_credential_workload_key(compute, &ident);
        for cred in [&login_cred, &owner_cred] {
            if let Err(e) = creds.delete(project, cred).await {
                tracing::info!(cred = %cred, error = %e, "orphan drop: sealed credential delete skipped");
            }
        }
    }

    Ok(HardDropOutcome {
        database: names.database,
        retained_roles,
    })
}

/// The outcome of [`hard_drop_orphan_tenant`]: the derived physical database that was dropped, plus
/// any per-tenant derived roles deliberately RETAINED because they are shared with a still-live
/// sibling binding (the HARD GUARD — see that function). `retained_roles` is empty on the clean path.
#[derive(Debug, Clone)]
pub struct HardDropOutcome {
    pub database: String,
    pub retained_roles: Vec<String>,
}

/// The transient-copy name markers the managed-pg paths use when they rename a tenant's derived
/// database aside: the soft-delete tombstone (`__deleted_<unixts>`), the shadow-swap rename-aside
/// (`__old_<nanos>_<pid>`), and the restore shadow (`__shadow_<nanos>_<pid>`). An aside of a tenant
/// is composed SOLELY by [`boatramp_storage::tenant_provision::bounded_aside_db_name`] from that
/// tenant's own derived name + a marker + a numeric distinguisher; [`is_orphan_aside`] classifies by
/// inverting that constructor exactly. A live SIBLING binding's database is a distinct derived
/// PRIMARY (`tenant_db_name`), so it never reconstructs — the basis of the HARD GUARD's
/// foreign-vs-own classification.
const ORPHAN_ASIDE_MARKERS: [&str; 3] = ["__deleted_", "__old_", "__shadow_"];

/// The TRANSIENT swap-scratch aside markers ONLY — the rename-aside a failed swap leaves
/// (`__old_<nanos>_<pid>`) and a crashed restore's reassigned shadow (`__shadow_<nanos>_<pid>`) —
/// EXCLUDING the `__deleted_<unixts>` soft-delete tombstone (grace-recoverable, owned by the
/// grace machinery / the explicit `--orphan` drop). The SYNC-path role-tangle reconcile
/// ([`untangle_colliding_orphan_roles`]) clears only THESE from a re-synced tenant's own derived
/// namespace, so an automatic re-sync never destroys a grace-protected tombstone.
const TRANSIENT_ASIDE_MARKERS: [&str; 2] = ["__old_", "__shadow_"];

/// Whether `candidate` is a bounded aside database of the derived primary `base` (see
/// [`ORPHAN_ASIDE_MARKERS`]) — the DATA-LOSS-sensitive classifier the role-sharing guard relies on to
/// tell THIS orphan's own disposable asides from a FOREIGN live sibling binding's database (misreading
/// a live sibling as an aside hands it to [`drop_orphan_aside_db`]'s unconditional `DROP DATABASE`).
///
/// A genuine aside is produced SOLELY by
/// [`boatramp_storage::tenant_provision::bounded_aside_db_name`] (EVERY aside — the soft-delete
/// `tenant_sql` rename, the shadow/old `project_export` renames — composes through it), so we classify
/// by INVERTING that constructor EXACTLY, never by a loose prefix test. For each marker occurrence at
/// `pos` (we scan EVERY occurrence, since `base` itself may contain a marker substring) let
/// `suffix = candidate[pos + marker.len()..]` and accept only if
/// `candidate == bounded_aside_db_name(base, marker, suffix)`.
///
/// Reconstruction ALONE is not sufficient at the 63-byte `NAMEDATALEN` cap. A derived name routinely
/// sits AT 63 bytes (`sanitize_ident`: 37-byte body + `_` + 25-char digest), and the constructor's
/// truncation branch then keeps only `base[..keep]` with `keep = 63 − marker.len() − suffix.len()`. A
/// live sibling whose operator-chosen logical name is `<orphan-logical><marker><tail>` (e.g. orphan
/// `shd1`, sibling `shd1__old_x`) derives a 63-byte PRIMARY carrying the marker near its START; the
/// suffix extracted there is LONG, forcing a tiny `keep` that collapses `base[..keep]` back onto the
/// short shared prefix so the reconstruction MATCHES — misclassifying the LIVE sibling as a droppable
/// aside (silent data loss). So we additionally require the recovered `suffix` to be a GENUINE aside
/// distinguisher (see [`is_genuine_aside_suffix`]): the aside generators emit only a bounded decimal
/// timestamp (`now_unix_secs()`, a `u64`) or `<nanos>_<pid>` (`shadow_suffix()`), so each field is a
/// decimal shorter than the FIXED 25-char base-36 digest that ALWAYS trails a sibling's derived name
/// (zero-padded, so the digest can itself be all-decimal — a loose `[0-9_]*` test would be unsound).
/// Because that 25-char digit run is always the suffix's trailing field and 25 exceeds the genuine
/// field widths, a live sibling is rejected with probability 1 while every genuine short-form AND
/// cap-truncated aside is still accepted. Pure (no IO) so it is unit-testable.
fn is_orphan_aside(base: &str, candidate: &str) -> bool {
    is_orphan_aside_markers(base, candidate, &ORPHAN_ASIDE_MARKERS)
}

/// [`is_orphan_aside`] restricted to a SUBSET of the aside markers — so a caller can tell this
/// orphan's own TRANSIENT swap-scratch asides ([`TRANSIENT_ASIDE_MARKERS`]) apart from its
/// grace-protected `__deleted_` tombstone while using the EXACT same cap-safe reconstruction +
/// genuine-suffix soundness guard. `markers` must be a subset of [`ORPHAN_ASIDE_MARKERS`].
fn is_orphan_aside_markers(base: &str, candidate: &str, markers: &[&str]) -> bool {
    if candidate == base {
        return false; // the primary itself (already dropped), not an aside.
    }
    for marker in markers.iter().copied() {
        // Scan EVERY occurrence of the marker: the genuine split point may not be the first one
        // (e.g. `base` itself contains a marker substring), and the aside markers never overlap.
        let mut from = 0;
        while let Some(rel) = candidate[from..].find(marker) {
            let pos = from + rel;
            let suffix = &candidate[pos + marker.len()..];
            if is_genuine_aside_suffix(suffix)
                && candidate
                    == boatramp_storage::tenant_provision::bounded_aside_db_name(
                        base, marker, suffix,
                    )
            {
                return true;
            }
            from = pos + 1; // advance past this occurrence to find the next.
        }
    }
    false
}

/// Whether `suffix` matches EXACTLY one of the two shapes the aside generators emit, with EVERY field
/// width bounded BELOW the fixed 25-char digest length:
///   * `now_unix_secs()` — a bare `u64` decimal (≤ 20 digits, no separator); or
///   * `shadow_suffix()` = `format!("{nanos}_{pid}")` — `nanos` `_` `pid`, each a bounded decimal.
///
/// This is the SOUNDNESS guard that stops a LIVE sibling binding's derived-name tail from being
/// reconstructed as a droppable aside at the 63-byte `NAMEDATALEN` cap (see [`is_orphan_aside`]).
///
/// Why bounding EVERY field below 25 is both necessary and sufficient: a derived name ALWAYS ends in
/// `_` + a FIXED-WIDTH 25-char base-36 digest (`to_base36` zero-pads to
/// [`boatramp_storage::tenant_provision::HASH_B36_LEN`]), and that digest CAN be all-decimal (e.g.
/// `to_base36(5)` = 24 `0`s + `5`). Whatever split the cap-collapse forces, that 25-char digit run is a
/// `_`-delimited field of the recovered suffix. Because 25 exceeds EVERY field bound here (single-field
/// 20; `<nanos>_<pid>` → 20 and 10), a sibling's all-decimal digest can never masquerade as a genuine
/// distinguisher — rejected with probability 1 — while every genuine timestamp (`secs` ≤ 20 digits,
/// `nanos` ≤ 20 digits until ~year 5141, `pid` ≤ 10) still matches. The earlier loose `[0-9_]*` test
/// was UNSOUND: an all-decimal digest passed it, so a grind-crafted sibling could be `DROP`ped
/// (Security re-review FINDING 1).
///
/// Today the digest is always the suffix's TRAILING field, so bounding only the trailing field would
/// suffice; bounding `nanos` too (defense in depth, no false-negative since genuine `nanos` is ≤ 20
/// digits for ~3000 years) keeps the guard sound even if a future name producer ever appended a
/// trailing numeric field AFTER the digest — closing the one latent forward-invariant the audit flagged.
fn is_genuine_aside_suffix(suffix: &str) -> bool {
    // A non-empty run of ASCII decimal digits no longer than `max_len`. Every call site below bounds
    // `max_len` BELOW the fixed 25-char digest length, so no digest run can satisfy any field.
    fn bounded_decimal(s: &str, max_len: usize) -> bool {
        !s.is_empty() && s.len() <= max_len && s.bytes().all(|b| b.is_ascii_digit())
    }
    // Form 1 — `now_unix_secs()`: a bare u64 decimal, no separator (`u64::MAX` is 20 digits).
    if bounded_decimal(suffix, 20) {
        return true;
    }
    // Form 2 — `shadow_suffix()`: `<nanos>_<pid>`, exactly one `_`, `pid` a `u32` (≤ 10 digits) and
    // `nanos` an `as_nanos()` value (≤ 20 digits until ~year 5141 = 10^20 ns after the epoch). A suffix
    // with two or more `_` fails here (the `pid` slice then still contains a `_`, so it is not a
    // bounded decimal), as does any suffix carrying the 25-char digest at EITHER field.
    match suffix.split_once('_') {
        Some((nanos, pid)) => bounded_decimal(nanos, 20) && bounded_decimal(pid, 10),
        None => false,
    }
}

/// Whether a Postgres role exists (via the superuser/maintenance connection) — so an already-absent
/// derived role is a clean, idempotent skip rather than an error.
async fn role_exists(admin: &ComputeResolvedSqlBackend, role: &str) -> Result<bool, String> {
    let role_lit = format!("'{}'", role.replace('\'', "''"));
    let rows = admin
        .run_query(&format!(
            "SELECT 1 FROM pg_roles WHERE rolname = {role_lit}"
        ))
        .await
        .map_err(|e| format!("orphan drop: probe role {role}: {e}"))?;
    Ok(!rows.rows.is_empty())
}

/// Every database (by name) that `role` still OWNS or holds objects/privileges in — the full set of
/// databases the role is entangled with — read COMPREHENSIVELY from the cluster via the superuser/
/// maintenance connection, so NO entanglement is missed (a miss on a FOREIGN database would let the
/// guard force-clear a role shared with a live binding — the DATA-LOSS hazard). Three sources, combined:
///   1. `pg_shdepend` with `dbid <> 0` — objects/ACLs INSIDE a database (its `dbid` is that database).
///   2. `pg_shdepend` with `dbid = 0 AND classid = 'pg_database'` — database-level dependencies that
///      Postgres records as SHARED (`dbid = 0`) with the DATABASE as the referenced object: both a
///      database's OWNERSHIP and `GRANT … ON DATABASE … TO <role>` (CONNECT/TEMP/ALL). These do NOT
///      carry the containing db in `dbid`, so a naive `JOIN … ON d.oid = s.dbid` SILENTLY DROPS them —
///      the blind spot this arm closes by joining the OBJECT (`d.oid = s.objid`).
///   3. `pg_database.datdba = role` — ownership, belt-and-suspenders over (2)'s ownership row.
///
/// Excludes the maintenance database and the already-dropped `primary` (never a live sibling binding).
/// A name here that is NOT a [bounded aside](is_orphan_aside) of `primary` is a FOREIGN (live sibling)
/// database, so the role must be LEFT intact.
///
/// CAVEAT (Security review note): this enumerates DATABASE-scoped entanglements only. A role that
/// out-of-band owned a shared TABLESPACE, or held a membership in a still-live role, would NOT be
/// surfaced here and so would not trip the `shared_with_live` fail-safe. boatramp never grants a
/// derived per-tenant role a tablespace or a cross-role membership (provisioning mints only the
/// per-`(tenant, server)` login + owner roles and grants on the tenant's OWN database/objects), so
/// there is no such entanglement to miss today; a future producer that did would need this widened.
async fn role_dependency_databases(
    admin: &ComputeResolvedSqlBackend,
    role: &str,
    primary: &str,
    maint_db: &str,
) -> Result<Vec<String>, String> {
    let role_lit = format!("'{}'", role.replace('\'', "''"));
    let maint_lit = format!("'{}'", maint_db.replace('\'', "''"));
    let primary_lit = format!("'{}'", primary.replace('\'', "''"));
    let sql = format!(
        "SELECT DISTINCT dn FROM ( \
           SELECT d.datname AS dn FROM pg_shdepend s \
             JOIN pg_database d ON d.oid = s.dbid \
            WHERE s.refobjid = (SELECT oid FROM pg_roles WHERE rolname = {role_lit}) \
              AND s.dbid <> 0 \
           UNION \
           SELECT d.datname FROM pg_shdepend s \
             JOIN pg_database d ON d.oid = s.objid \
            WHERE s.refobjid = (SELECT oid FROM pg_roles WHERE rolname = {role_lit}) \
              AND s.dbid = 0 AND s.classid = 'pg_database'::regclass \
           UNION \
           SELECT d2.datname FROM pg_database d2 \
            WHERE d2.datdba = (SELECT oid FROM pg_roles WHERE rolname = {role_lit}) \
         ) q WHERE dn NOT IN ({maint_lit}, {primary_lit})"
    );
    let rows = admin
        .run_query(&sql)
        .await
        .map_err(|e| format!("orphan drop: enumerate role deps {role}: {e}"))?;
    Ok(rows
        .rows
        .into_iter()
        .filter_map(|r| match r.into_iter().next() {
            Some(SqlValue::Text(s)) => Some(s),
            _ => None,
        })
        .collect())
}

/// Whether a Postgres error is "role cannot be dropped because some objects depend on it" (SQLSTATE
/// `2BP01`, `DependentObjectsStillExist`) — the signal that a `DROP ROLE` was correctly REFUSED
/// because the role still owns objects / holds grants. It is the SELF-GUARD that makes attempting a
/// `DROP ROLE` safe: a refusal is caught (the role is LEFT intact), never forced past.
fn is_role_has_dependents_error(err: &SqlError) -> bool {
    let m = err.to_string().to_ascii_lowercase();
    m.contains("cannot be dropped because") && m.contains("depend")
}

/// Terminate sessions on, then `DROP DATABASE IF EXISTS`, THIS ORPHAN'S OWN database by name — either
/// a bounded aside (`<orphan-derived-prefix><aside-marker><suffix>` — see [`is_orphan_aside`]) OR the
/// orphan's live PRIMARY itself (the self-heal's step 2 hard-drops an EMPTY primary through here; a
/// POPULATED primary never reaches this — it is soft-deprovisioned to a recoverable tombstone). Every
/// name passed here is STRUCTURAL (derived for, or a classifier-matched aside of, THIS tenant), never
/// dump/guest content. Fatal on failure: clearing the orphan means the targeted db must go.
async fn drop_orphan_aside_db(
    admin: &ComputeResolvedSqlBackend,
    kind: ExternalSqlKind,
    aside: &str,
) -> Result<(), String> {
    let aside_lit = format!("'{}'", aside.replace('\'', "''"));
    let aside_id = boatramp_storage::tenant_provision::quote_ident(kind, aside);
    admin
        .run_script(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = {aside_lit} AND pid <> pg_backend_pid();"
        ))
        .await
        .map_err(|e| format!("orphan drop: terminate sessions on aside {aside}: {e}"))?;
    admin
        .run_script(&format!("DROP DATABASE IF EXISTS {aside_id};"))
        .await
        .map_err(|e| format!("orphan drop: DROP DATABASE aside {aside}: {e}"))?;
    Ok(())
}

/// Whether a database exists (by name) via the superuser/maintenance connection — so the self-heal can
/// pick a collision-free `__deleted_` tombstone name when it renames a populated orphan aside.
async fn db_exists(admin: &ComputeResolvedSqlBackend, db: &str) -> Result<bool, String> {
    let db_lit = format!("'{}'", db.replace('\'', "''"));
    let rows = admin
        .run_query(&format!(
            "SELECT 1 FROM pg_database WHERE datname = {db_lit}"
        ))
        .await
        .map_err(|e| format!("self-heal: probe database {db}: {e}"))?;
    Ok(!rows.rows.is_empty())
}

/// Whether a database holds any USER object (table/partition/matview/sequence/foreign-table or a large
/// object) — the POPULATED-vs-EMPTY classifier the self-heal uses to decide whether the live orphan is
/// disposable (EMPTY ⇒ hard-drop; POPULATED ⇒ soft-deprovision to a recoverable tombstone). Mirrors the
/// restore path's [`pg_db_has_user_tables`](crate::project_export) count EXACTLY (same catalog filter)
/// so both the fresh-dest occupant reconcile and the self-heal make the identical fail-safe call.
/// `admin_on_db` MUST already be connected to the database being probed. FAIL-CLOSED: an unparsable
/// count errors (never a silent "empty" that would license a clobber).
async fn db_has_user_tables(admin_on_db: &ComputeResolvedSqlBackend) -> Result<bool, String> {
    let rows = admin_on_db
        .run_query(
            "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
             AND c.relkind IN ('r', 'p', 'm', 'S', 'f')) \
             + (SELECT count(*) FROM pg_largeobject_metadata)",
        )
        .await
        .map_err(|e| format!("self-heal: probe user objects: {e}"))?;
    match rows.rows.into_iter().flatten().next() {
        Some(SqlValue::Integer(n)) => Ok(n > 0),
        Some(SqlValue::Text(s)) => s
            .trim()
            .parse::<i64>()
            .map(|n| n > 0)
            .map_err(|_| format!("self-heal: unparsable user-object count {s:?} (fail-closed)")),
        other => Err(format!(
            "self-heal: unexpected user-object count cell {other:?} (fail-closed)"
        )),
    }
}

/// Terminate sessions on `from`, then `ALTER DATABASE from RENAME TO to` — the self-heal's
/// soft-deprovision of a POPULATED live orphan (frees the derived target name while PRESERVING the
/// data under the `__deleted_` tombstone `to`). Both names are STRUCTURAL (the derived live name + a
/// bounded `__deleted_` aside of it), never dump/guest content.
async fn rename_db_aside(
    admin: &ComputeResolvedSqlBackend,
    kind: ExternalSqlKind,
    from: &str,
    to: &str,
) -> Result<(), String> {
    let from_lit = format!("'{}'", from.replace('\'', "''"));
    let from_id = boatramp_storage::tenant_provision::quote_ident(kind, from);
    let to_id = boatramp_storage::tenant_provision::quote_ident(kind, to);
    admin
        .run_script(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = {from_lit} AND pid <> pg_backend_pid();"
        ))
        .await
        .map_err(|e| format!("self-heal: terminate sessions on {from}: {e}"))?;
    admin
        .run_script(&format!("ALTER DATABASE {from_id} RENAME TO {to_id};"))
        .await
        .map_err(|e| format!("self-heal: rename populated orphan {from} aside to {to}: {e}"))?;
    Ok(())
}

/// The disposition [`clear_db_dataloss_safe`] took on a database it was asked to clear.
enum DbClear {
    /// The database did not exist — a clean no-op (the derived name is already free).
    Absent,
    /// The database was EMPTY (no user objects) — hard-dropped (nothing to lose).
    Dropped,
    /// The database was POPULATED — renamed aside to this recoverable `__deleted_` grace tombstone
    /// (its data PRESERVED; the caller reassigns it to the superuser).
    Preserved(String),
}

/// Clear a database the derived roles own, DATA-LOSS-SAFELY — the shared core of the self-heal's live
/// orphan handling AND its populated-`__old_` handling (Security review E1 + FINDING 1/2/3), mirroring
/// the fresh-dest occupant invariant [`crate::project_export`]'s `pg_reconcile_fresh_dest_occupant`:
///   * ABSENT (`db` does not exist) ⇒ [`DbClear::Absent`] — a clean no-op, NEVER a fail-connect abort
///     (FINDING 2: a crash can legitimately leave the derived name free).
///   * EMPTY (no user objects) ⇒ hard-drop ([`drop_orphan_aside_db`]) → [`DbClear::Dropped`].
///   * POPULATED ⇒ SOFT-DEPROVISION: rename `db` aside ([`rename_db_aside`]) to a collision-free
///     recoverable `__deleted_<ts>` grace tombstone of `derived_primary` (the tenant's derived live
///     name — so the tombstone is recognized as THIS orphan's own aside), FREEING `db`'s name →
///     [`DbClear::Preserved`]. A mid-restore failure then never loses the only data copy.
///
/// NEVER gated on `--drop-soft-deleted` (that flag governs only PRE-EXISTING `__deleted_` tombstones —
/// FINDING 3). Every name is STRUCTURAL (the derived live name + a bounded aside of it), never
/// dump/guest content.
#[allow(clippy::too_many_arguments)]
async fn clear_db_dataloss_safe(
    admin: &ComputeResolvedSqlBackend,
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    kind: ExternalSqlKind,
    compute: &str,
    superuser: &str,
    derived_primary: &str,
    db: &str,
) -> Result<DbClear, String> {
    if !db_exists(admin, db).await? {
        return Ok(DbClear::Absent);
    }
    let populated = {
        let on_db =
            shared_admin_backend_for_db(deploy, creds, kind, compute, superuser, db).await?;
        db_has_user_tables(&on_db).await?
    };
    if !populated {
        drop_orphan_aside_db(admin, kind, db).await?;
        return Ok(DbClear::Dropped);
    }
    // Pick a collision-free `__deleted_<ts>` tombstone name (bump the ts past any existing one, so two
    // populated things preserved in the same second — orphan + a populated `__old_` — never collide).
    let mut ts = now_unix_secs();
    let tombstone = loop {
        let cand = boatramp_storage::tenant_provision::bounded_aside_db_name(
            derived_primary,
            "__deleted_",
            &ts.to_string(),
        );
        if !db_exists(admin, &cand).await? {
            break cand;
        }
        ts = ts.saturating_add(1);
    };
    rename_db_aside(admin, kind, db, &tombstone).await?;
    Ok(DbClear::Preserved(tombstone))
}

/// Fully clear an EXCLUSIVELY-owned per-tenant derived `role` DATA-LOSS-SAFELY, returning `true` if it
/// was dropped and `false` if it was deliberately LEFT intact (a live dependency we must not force
/// past). The orphan's own aside databases have already been dropped by the caller, so for a truly
/// exclusive role the `DROP ROLE` just succeeds. A `DROP ROLE` is SELF-GUARDING (Postgres refuses to
/// drop a role any object still depends on), so this can never force past a live dependency:
/// - `DROP ROLE` succeeds ⇒ cleared (`true`).
/// - `DROP ROLE` is REFUSED for a dependency ⇒ the aside-drop did not reach everything the role is
///   tied to. RE-ENUMERATE its databases: if ANY is FOREIGN (a live sibling the proactive scan
///   under-reported), LEAVE the role (`false`) — fail-safe, the live binding is untouched. If they are
///   all this orphan's OWN asides (a transient read earlier missed one), DROP those and retry the
///   `DROP ROLE` ONCE; still refused ⇒ LEAVE it (`false`) rather than error.
///
/// It NEVER runs a blanket `DROP OWNED` (which would REVOKE a live binding's privileges on shared
/// objects) and NEVER drops a foreign database — so a live binding can never be clobbered here.
async fn clear_exclusive_role(
    admin: &ComputeResolvedSqlBackend,
    kind: ExternalSqlKind,
    role: &str,
    primary: &str,
    maint_db: &str,
) -> Result<bool, String> {
    let role_id = boatramp_storage::tenant_provision::quote_ident(kind, role);
    let drop_sql = format!("DROP ROLE IF EXISTS {role_id};");
    match admin.run_script(&drop_sql).await {
        Ok(()) => return Ok(true),
        Err(e) if is_role_has_dependents_error(&e) => {} // still tied to something — examine below.
        Err(e) => return Err(format!("orphan drop: DROP ROLE {role}: {e}")),
    }
    // Still has dependents. Re-enumerate: a FOREIGN database ⇒ shared with a live binding ⇒ LEAVE.
    let deps = role_dependency_databases(admin, role, primary, maint_db).await?;
    for db in &deps {
        if !is_orphan_aside(primary, db) {
            tracing::warn!(
                role = %role,
                foreign_db = %db,
                orphan = %primary,
                "orphan drop: per-tenant derived role is SHARED with a live binding — LEFT intact, \
                 not force-dropped (its objects/grants on the live binding must not be clobbered)"
            );
            return Ok(false);
        }
    }
    // Only this orphan's OWN asides remain — drop them and retry the DROP ROLE once.
    for db in &deps {
        drop_orphan_aside_db(admin, kind, db).await?;
    }
    match admin.run_script(&drop_sql).await {
        Ok(()) => Ok(true),
        Err(e) if is_role_has_dependents_error(&e) => {
            // Fail-safe: still refused after clearing every aside we can see — LEAVE it rather than
            // error (we never force-drop a role with a live dependency). Surfaced to the operator.
            tracing::warn!(
                role = %role,
                orphan = %primary,
                "orphan drop: per-tenant derived role still has a live dependency after clearing the \
                 orphan's own asides — LEFT intact, not force-dropped (fail-safe)"
            );
            Ok(false)
        }
        Err(e) => Err(format!("orphan drop: DROP ROLE {role}: {e}")),
    }
}

/// The outcome of [`reconcile_derived_role_tangle`]: the derived roles deliberately RETAINED (a live
/// sibling still uses them, or the self-guarding `DROP ROLE` refused one) and the orphan's own aside
/// databases that were CLEARED.
struct RoleTangleOutcome {
    retained_roles: Vec<String>,
    cleared_asides: Vec<String>,
}

/// The READ-ONLY classification of a derived-role tangle — the shared DETECTION the role-tangle
/// reconcile ([`reconcile_derived_role_tangle`]) AND the sync-path self-heal
/// ([`untangle_colliding_orphan_roles`]) both drive off, so the DATA-LOSS-sensitive own-vs-foreign
/// decision lives in ONE place (never a copied second scan). Pure reads (`role_exists` +
/// `role_dependency_databases` + the pure [`is_orphan_aside`] classifier), no mutation — so a caller
/// can DETECT a tangle and DECIDE what to do before touching anything.
struct RoleTangleClass {
    /// The subset of `roles` that actually EXIST (an already-absent role is a clean skip).
    existing_roles: Vec<String>,
    /// TRUE iff any role owns/depends on a database OUTSIDE this orphan's own derived namespace — a
    /// still-live SIBLING binding (the HARD GUARD trips: leave everything).
    shared_with_live: bool,
    /// Every database (besides `primary` + the maintenance db) the roles own/depend on that IS one of
    /// `primary`'s own [`ORPHAN_ASIDE_MARKERS`] asides (a tombstone / swap-scratch db) — this orphan's
    /// own disposable-or-preservable data.
    own_asides: std::collections::BTreeSet<String>,
}

/// Classify the derived roles' entanglement (read-only — see [`RoleTangleClass`]). Enumerates
/// COMPREHENSIVELY every database each role still owns/depends on (EXCLUDING `primary` + the
/// maintenance db) and splits them into THIS orphan's own [bounded asides](is_orphan_aside) vs a
/// FOREIGN live-sibling database (the fail-safe trigger).
async fn classify_role_tangle(
    admin: &ComputeResolvedSqlBackend,
    roles: &[&str],
    primary: &str,
    maint_db: &str,
) -> Result<RoleTangleClass, String> {
    let mut existing_roles: Vec<String> = Vec::new();
    let mut own_asides: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut shared_with_live = false;
    for role in roles.iter().copied() {
        if role.is_empty() || !role_exists(admin, role).await? {
            continue; // idempotent: an already-absent role is a clean skip.
        }
        existing_roles.push(role.to_string());
        for db in role_dependency_databases(admin, role, primary, maint_db).await? {
            if is_orphan_aside(primary, &db) {
                own_asides.insert(db);
            } else {
                shared_with_live = true;
                tracing::warn!(
                    role = %role,
                    foreign_db = %db,
                    orphan = %primary,
                    "role-tangle classify: per-tenant derived role is SHARED with a live binding \
                     (owns/depends on a database outside this orphan's derived namespace) — the \
                     reconcile/self-heal LEAVES it intact (force-clearing would clobber the live \
                     binding's data)"
                );
            }
        }
    }
    Ok(RoleTangleClass {
        existing_roles,
        shared_with_live,
        own_asides,
    })
}

/// The SHARED CORE of the derived-role tangle reconciliation — used by BOTH the explicit `--orphan`
/// teardown ([`hard_drop_orphan_tenant`]) and the sync-path colliding-orphan reconcile
/// ([`untangle_colliding_orphan_roles`]) so the DATA-LOSS-sensitive classification + fail-safe exist
/// in ONE place (never a copied second path).
///
/// Enumerates COMPREHENSIVELY every database each derived role (`roles` = login + owner) still
/// owns/depends on, EXCLUDING `primary` + the maintenance db (via [`role_dependency_databases`]). If
/// ANY dependency is a FOREIGN database (not one of `primary`'s own [`ORPHAN_ASIDE_MARKERS`] asides),
/// the role is SHARED with a still-live sibling binding, so it LEAVES EVERY role + aside intact
/// (the HARD GUARD) and surfaces them as `retained_roles` — never force-clearing a live binding's
/// data. Otherwise it drops the orphan's OWN aside databases whose marker is in `clear_markers`
/// (a subset of the full set, so the sync path can leave a grace `__deleted_` tombstone), and — iff
/// `drop_roles` — clears each role via the self-guarding [`clear_exclusive_role`].
///
/// The two callers differ ONLY in the injected seam: the teardown has ALREADY dropped `primary`, so
/// it passes `clear_markers = ORPHAN_ASIDE_MARKERS` + `drop_roles = true` and the `DROP ROLE`s
/// succeed; the sync path leaves the live `primary` in place and the roles REUSED, so it passes the
/// TRANSIENT markers + `drop_roles = false` (a `DROP ROLE` would self-guard-refuse anyway, the role
/// still owning the live db — the roles are untangled from stray junk, never dropped). NEVER a
/// blanket `DROP OWNED`, NEVER a foreign database dropped.
async fn reconcile_derived_role_tangle(
    admin: &ComputeResolvedSqlBackend,
    kind: ExternalSqlKind,
    roles: &[&str],
    primary: &str,
    maint_db: &str,
    clear_markers: &[&str],
    drop_roles: bool,
) -> Result<RoleTangleOutcome, String> {
    let class = classify_role_tangle(admin, roles, primary, maint_db).await?;

    if class.shared_with_live {
        // HARD GUARD / fail-safe: a role entangled with a live sibling binding is LEFT WHOLE (the
        // roles AND their asides), so a live binding's data can never be clobbered. Surfaced to the
        // caller as retained.
        return Ok(RoleTangleOutcome {
            retained_roles: class.existing_roles,
            cleared_asides: Vec::new(),
        });
    }

    // Every enumerated dependency is this orphan's own disposable data. Drop the clearable aside
    // databases FIRST (so the owner no longer owns them), then — iff teardown — clear each role. A
    // `DROP ROLE` is SELF-GUARDING (Postgres refuses to drop a role any object still depends on), so
    // it can NEVER force past a live dependency; [`clear_exclusive_role`] uses exactly that and NEVER
    // runs a blanket `DROP OWNED` nor drops a foreign database. Only asides whose marker is disposable
    // in THIS context are dropped (the sync path leaves a grace `__deleted_` tombstone by passing the
    // transient set).
    let asides_to_drop: Vec<String> = class
        .own_asides
        .iter()
        .filter(|db| is_orphan_aside_markers(primary, db, clear_markers))
        .cloned()
        .collect();
    for aside in &asides_to_drop {
        drop_orphan_aside_db(admin, kind, aside).await?;
    }
    let mut retained_roles: Vec<String> = Vec::new();
    if drop_roles {
        for role in &class.existing_roles {
            if !clear_exclusive_role(admin, kind, role, primary, maint_db).await? {
                retained_roles.push(role.clone());
            }
        }
    }
    Ok(RoleTangleOutcome {
        retained_roles,
        cleared_asides: asides_to_drop,
    })
}

/// PRESERVE one of THIS orphan's own aside databases (a grace `__deleted_` tombstone) across the
/// self-heal: fully DIVORCE the derived `roles` from it so a later `DROP ROLE` succeeds WITHOUT
/// dropping the aside — its grace-recoverable data survives. Connected to the aside, `REASSIGN OWNED
/// BY <roles> TO <maint_owner>` transfers every object the roles own there (and the aside DATABASE
/// itself — a shared object) to the stable superuser/maintenance owner, then `DROP OWNED BY <roles>`
/// revokes any residual privileges GRANTED to the roles there (so no `pg_shdepend` ACL row keeps the
/// role un-droppable). A belt-and-suspenders `ALTER DATABASE … OWNER` re-asserts the datdba. Every
/// name is STRUCTURAL (the derived role names + a bounded-aside name the classifier already matched),
/// never operator/dump content; `maint_owner` is the configured superuser (never dropped). This is
/// the ONLY place the self-heal runs `DROP OWNED`, and only in the EXCLUSIVE-tangle branch (a role
/// shared with a live sibling never reaches here — the HARD GUARD leaves everything), so it can never
/// revoke a live binding's shared-object privileges.
#[allow(clippy::too_many_arguments)]
async fn reassign_aside_to_owner(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    kind: ExternalSqlKind,
    compute: &str,
    superuser: &str,
    maint_owner: &str,
    aside: &str,
    roles: &[&str],
) -> Result<(), String> {
    // Connect to the aside itself — REASSIGN/DROP OWNED act on the CURRENT database's objects (plus
    // shared objects for REASSIGN), so they must run connected to the aside being preserved.
    let aside_admin =
        shared_admin_backend_for_db(deploy, creds, kind, compute, superuser, aside).await?;
    let present: Vec<&str> = {
        let mut v = Vec::new();
        for role in roles.iter().copied() {
            if !role.is_empty() && role_exists(&aside_admin, role).await? {
                v.push(role);
            }
        }
        v
    };
    if present.is_empty() {
        return Ok(()); // nothing owns it (idempotent)
    }
    let roles_list = present
        .iter()
        .map(|r| boatramp_storage::tenant_provision::quote_ident(kind, r))
        .collect::<Vec<_>>()
        .join(", ");
    let owner_id = boatramp_storage::tenant_provision::quote_ident(kind, maint_owner);
    aside_admin
        .run_script(&format!("REASSIGN OWNED BY {roles_list} TO {owner_id};"))
        .await
        .map_err(|e| format!("self-heal: REASSIGN OWNED on tombstone {aside}: {e}"))?;
    aside_admin
        .run_script(&format!("DROP OWNED BY {roles_list};"))
        .await
        .map_err(|e| format!("self-heal: DROP OWNED on tombstone {aside}: {e}"))?;
    // Belt-and-suspenders: re-assert the aside DATABASE's owner (REASSIGN OWNED above already moved
    // the shared db object, but an explicit ALTER is unambiguous and idempotent).
    let aside_id = boatramp_storage::tenant_provision::quote_ident(kind, aside);
    aside_admin
        .run_script(&format!("ALTER DATABASE {aside_id} OWNER TO {owner_id};"))
        .await
        .map_err(|e| format!("self-heal: ALTER DATABASE OWNER on tombstone {aside}: {e}"))?;
    Ok(())
}

/// The outcome of the SYNC-path self-heal ([`untangle_colliding_orphan_roles`]) — a legible report
/// for the restore path's logging + the FATAL decision (any `Err` aborts the restore so a detected
/// tangle can never be left half-healed silently).
#[derive(Debug, Clone)]
pub enum SelfHealReport {
    /// Not an applicable Shared-Postgres non-default managed tenant — a clean no-op.
    NotApplicable,
    /// A HEALTHY tenant (the derived roles own no stray object beyond the live db) — the roles are
    /// REUSED untouched (no drop, no credential churn, no reprovision). The gating that keeps a clean
    /// re-sync cheap.
    NoOp,
    /// FRESH-dest path: the LIGHT v0.59.4/v0.59.6 untangle (drop stray TRANSIENT swap-asides, reuse
    /// roles) — the fresh-dest occupant reconcile already preserved the occupant, so the aggressive
    /// drop+reprovision heal is reserved for the EXISTING-dest construens recovery.
    LightUntangle { cleared_asides: Vec<String> },
    /// FAIL-SAFE: the derived roles are SHARED with a still-live sibling binding — LEFT fully intact
    /// (roles + asides + tombstone), the live sibling's data never touched (the HARD GUARD).
    SharedWithLive { roles: Vec<String> },
    /// FULL SELF-HEAL of an EXCLUSIVE tangle: the orphan's stray asides were cleared; each `__deleted_`
    /// grace tombstone PRESERVED (reassigned to the superuser) unless `drop_soft_deleted`; the live
    /// orphan db cleared DATA-LOSS-SAFELY (a POPULATED orphan SOFT-DEPROVISIONED to a recoverable
    /// `__deleted_` tombstone — `preserved_tombstones` — so a mid-restore failure never clobbers it; an
    /// EMPTY orphan hard-dropped); BOTH derived roles DROPPED + their sealed credentials deleted; and
    /// the tenant REPROVISIONED fresh — so the subsequent shadow-swap restore lands clean.
    Healed {
        cleared_asides: Vec<String>,
        preserved_tombstones: Vec<String>,
        dropped_tombstones: Vec<String>,
        roles_reprovisioned: Vec<String>,
    },
}

/// SYNC-path colliding-orphan **SELF-HEAL** (v0.59.7; evolves the v0.59.6 light untangle). On a
/// `project sync --apply` into a Shared managed-pg tenant whose derived roles a PRIOR failed/crashed
/// sync left TANGLED — owning stray databases (a `__deleted_` grace tombstone, `__old_`/`__shadow_`
/// swap-scratch asides) and/or NON-DB objects beyond the live db — FULLY self-heal the tangle with
/// ZERO operator intervention (no `db drop --orphan`, no manual SQL), the construens requirement.
///
/// GATED on DETECTING a tangle ([`classify_role_tangle`]). A HEALTHY re-sync (the roles own no stray
/// object) is a cheap [`NoOp`](SelfHealReport::NoOp): the stable roles are REUSED — no DROP ROLE, no
/// credential churn, no reprovision. The aggressive heal fires ONLY on broken state.
///
/// On a DETECTED EXCLUSIVE tangle (existing-dest path, `fresh_dest = false` — where construens's
/// re-sync landed), it reuses [`hard_drop_orphan_tenant`]'s shared tangle-reconciliation primitives
/// ([`classify_role_tangle`], [`drop_orphan_aside_db`], [`clear_exclusive_role`]) in an ORDER chosen so
/// `REASSIGN OWNED`'s greedy shared-object sweep never touches a disposable aside:
///   A. Clears the TRANSIENT swap-scratch asides FIRST: `__shadow_` (incoming restore scratch) is a
///      safe hard-drop; a POPULATED `__old_` (a crash between the swap renames can leave it the ONLY
///      data copy) is soft-deprovisioned to a recoverable tombstone, an EMPTY one hard-dropped
///      ([`clear_db_dataloss_safe`] — FINDING 1).
///   B. The EXISTING `__deleted_` grace tombstones: DROP under `--drop-soft-deleted` (pre-existing
///      soft-deleted data ONLY — never the live orphan / a populated `__old_`), else PRESERVE.
///   C. CLEARS the live orphan db DATA-LOSS-SAFELY ([`clear_db_dataloss_safe`], Security review E1) —
///      the restore has NOT landed yet and a mid-restore failure leaves live untouched, so a POPULATED
///      orphan is SOFT-DEPROVISIONED (renamed to a recoverable `__deleted_` tombstone, mirroring the
///      fresh-dest invariant `pg_reconcile_fresh_dest_occupant`), an EMPTY one hard-dropped, and an
///      ABSENT one (a crash freed the name — FINDING 2) a clean skip, NOT a fail-connect abort. NEVER
///      gated on `--drop-soft-deleted` (FINDING 3 — the flag must not cause live-data loss).
///   D. REASSIGNS every PRESERVED tombstone (+ its inner objects) to the stable superuser
///      ([`reassign_aside_to_owner`] — its data SURVIVES while the roles are divorced from it). Done
///      AFTER (A) so the sweep touches only the tombstones.
///   E. DROPS BOTH derived roles ([`clear_exclusive_role`], self-guarding), then deletes their sealed
///      credentials and REPROVISIONS the tenant fresh — new roles, fresh credentials, a clean empty
///      live db — so the subsequent shadow-swap restore lands clean.
///
/// FAIL-SAFE (HARD, unchanged): a role SHARED with a still-live sibling binding is LEFT fully intact
/// ([`SharedWithLive`](SelfHealReport::SharedWithLive)) — the restore still proceeds, the live sibling
/// never clobbered. On the FRESH-dest path the LIGHT untangle is kept BY DESIGN (E3, known-safe
/// divergence): the fresh-dest occupant reconcile already preserved the occupant, and a role left
/// REUSED there may still own a grace `__deleted_` tombstone — intentional grace-preservation,
/// reconciled later by [`hard_drop_orphan_tenant`] / the grace reaper. A clean no-op /
/// [`NotApplicable`](SelfHealReport::NotApplicable) for any binding that is not an applicable
/// Shared-Postgres non-default managed tenant.
pub async fn untangle_colliding_orphan_roles(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    project: &str,
    fresh_dest: bool,
    drop_soft_deleted: bool,
) -> Result<SelfHealReport, String> {
    let Some(compute) = binding.compute.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(SelfHealReport::NotApplicable);
    };
    let Some(kind) = ExternalSqlKind::parse(&binding.kind) else {
        return Ok(SelfHealReport::NotApplicable);
    };
    // Scoped to the Shared-Postgres non-default cell (the only cell with a per-tenant-db + derived
    // owner/login roles that a stray aside can tangle); every other binding is a clean no-op.
    if kind != ExternalSqlKind::Postgres || !matches!(binding.tenant, TenantIsolation::Shared) {
        return Ok(SelfHealReport::NotApplicable);
    }
    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
    if is_default {
        return Ok(SelfHealReport::NotApplicable);
    }
    let database = binding.database.as_deref().unwrap_or_default();
    let superuser = binding.user.as_deref().unwrap_or_default();
    let ident = sanitize_ident(&tenant_ident_raw);
    let names = tenant_names(binding.tenant, compute, database, &tenant_ident_raw, false);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let admin = shared_admin_backend(deploy, &creds, kind, compute, superuser).await?;
    let maint_db = maintenance_database(kind);
    let roles = [names.role.as_str(), names.owner_role.as_str()];

    // DETECT (read-only): classify the roles' entanglement.
    let class = classify_role_tangle(&admin, &roles, &names.database, maint_db).await?;
    if class.existing_roles.is_empty() || (class.own_asides.is_empty() && !class.shared_with_live) {
        // HEALTHY / roles absent — REUSE the stable roles, touch nothing (the gating that keeps a
        // clean re-sync cheap: no DROP ROLE, no credential churn, no reprovision).
        return Ok(SelfHealReport::NoOp);
    }
    if class.shared_with_live {
        // FAIL-SAFE HARD GUARD: a role entangled with a live sibling binding is LEFT WHOLE.
        return Ok(SelfHealReport::SharedWithLive {
            roles: class.existing_roles,
        });
    }

    // FRESH-dest path: keep the LIGHT v0.59.4/v0.59.6 untangle (drop stray transient swap-asides,
    // REUSE roles) — the fresh-dest occupant reconcile already preserved the occupant, so the
    // aggressive drop+reprovision heal is reserved for the EXISTING-dest construens recovery below.
    if fresh_dest {
        let outcome = reconcile_derived_role_tangle(
            &admin,
            kind,
            &roles,
            &names.database,
            maint_db,
            &TRANSIENT_ASIDE_MARKERS,
            false,
        )
        .await?;
        return Ok(SelfHealReport::LightUntangle {
            cleared_asides: outcome.cleared_asides,
        });
    }

    // EXCLUSIVE TANGLE on the existing-dest re-sync → FULL SELF-HEAL.
    //
    // ORDERING is load-bearing (Security review E1 + the REASSIGN-OWNED global sweep): `REASSIGN OWNED
    // BY <role>` is GREEDY — it reassigns EVERY object the role owns, INCLUDING every shared database
    // (so reassigning ONE tombstone to the superuser sweeps ALL of the role's databases). So the
    // disposable TRANSIENT asides must be DROPPED FIRST (step A), before any reassign (step D) can
    // sweep them to the superuser and leave them un-cleared.
    let mut preserved_tombstones: Vec<String> = Vec::new();
    let mut dropped_tombstones: Vec<String> = Vec::new();
    let mut cleared_asides: Vec<String> = Vec::new();

    // (A) Clear the disposable TRANSIENT swap-scratch asides FIRST — before the reassign sweep below,
    //     which would otherwise reassign them to the superuser (never cleared). `__shadow_` is incoming
    //     restore SCRATCH (never the only copy of tenant data) → always a safe hard-drop. `__old_` is a
    //     swap RENAME-ASIDE of the live db — a crash between `pg_swap_shadow`'s renames can leave a
    //     POPULATED `__old_` as the ONLY data copy, so it is cleared DATA-LOSS-SAFELY (Security review
    //     FINDING 1): EMPTY → hard-drop, POPULATED → soft-deprovision to a recoverable `__deleted_`
    //     tombstone (preserved, reassigned to the superuser in step D).
    for aside in &class.own_asides {
        if is_orphan_aside_markers(&names.database, aside, &["__shadow_"]) {
            drop_orphan_aside_db(&admin, kind, aside).await?;
            cleared_asides.push(aside.clone());
        } else if is_orphan_aside_markers(&names.database, aside, &["__old_"]) {
            match clear_db_dataloss_safe(
                &admin,
                deploy,
                &creds,
                kind,
                compute,
                superuser,
                &names.database,
                aside,
            )
            .await?
            {
                DbClear::Dropped => cleared_asides.push(aside.clone()),
                DbClear::Preserved(tomb) => preserved_tombstones.push(tomb),
                DbClear::Absent => {}
            }
        }
    }

    // (B) The EXISTING `__deleted_` grace tombstones: DROP under `--drop-soft-deleted` (the operator's
    //     deliberate disposal of PRE-EXISTING soft-deleted data), else mark to PRESERVE (reassigned to
    //     the superuser in step D). The flag governs ONLY these pre-existing tombstones — NEVER the live
    //     orphan or a populated `__old_` (Security review FINDING 3: the flag must not cause live-data
    //     loss on a restore failure).
    for aside in &class.own_asides {
        if is_orphan_aside_markers(&names.database, aside, &["__deleted_"]) {
            if drop_soft_deleted {
                drop_orphan_aside_db(&admin, kind, aside).await?;
                dropped_tombstones.push(aside.clone());
            } else {
                preserved_tombstones.push(aside.clone());
            }
        }
    }

    // (C) Clear the live orphan db — DATA-LOSS-SAFELY, mirroring the fresh-dest occupant invariant
    //     (`pg_reconcile_fresh_dest_occupant`). The restore has NOT landed yet; a mid-restore failure
    //     tears the shadow down leaving live untouched, so HARD-dropping a POPULATED orphan here would
    //     leave the tenant with NEITHER the source NOR the orphan — unrecoverable (Security review E1).
    //     ALWAYS data-loss-safe (NEVER gated on `--drop-soft-deleted` — FINDING 3) and EXISTENCE-guarded
    //     (an ABSENT primary — a crash left the derived name free + a populated `__old_` — is a clean
    //     skip, NOT a fail-connect abort — FINDING 2): ABSENT → skip (reprovision recreates it); EMPTY →
    //     hard-drop (the swap recreates); POPULATED → soft-deprovision to a recoverable `__deleted_`
    //     tombstone (freeing the derived name for the restore), preserved so a failed restore is
    //     recoverable.
    match clear_db_dataloss_safe(
        &admin,
        deploy,
        &creds,
        kind,
        compute,
        superuser,
        &names.database,
        &names.database,
    )
    .await?
    {
        DbClear::Preserved(tomb) => preserved_tombstones.push(tomb),
        DbClear::Dropped | DbClear::Absent => {}
    }

    // (D) REASSIGN every PRESERVED tombstone (+ its inner objects) to the stable superuser, DIVORCING
    //     the derived roles (REASSIGN OWNED + DROP OWNED, per tombstone — the first call's REASSIGN
    //     sweeps the shared db ownerships, each call reassigns its own db's LOCAL objects). Now the
    //     transient asides are already gone (A), so the sweep touches ONLY the tombstones.
    for tomb in &preserved_tombstones {
        reassign_aside_to_owner(
            deploy, &creds, kind, compute, superuser, superuser, tomb, &roles,
        )
        .await?;
    }

    // (E) DROP ROLE both derived roles — they now own NOTHING (transients dropped, tombstones
    //     reassigned/dropped, the live orphan renamed-aside/dropped). The self-guarding
    //     [`clear_exclusive_role`] refuses a DROP ROLE with a live dependency, so a still-entangled
    //     role surfaces (FATAL) rather than leaving a half-healed tenant.
    for role in &class.existing_roles {
        if !clear_exclusive_role(&admin, kind, role, &names.database, maint_db).await? {
            return Err(format!(
                "self-heal: derived role {role:?} still has a live dependency after clearing the \
                 orphan's own objects — refusing to proceed (the tangle is not fully self-healed)"
            ));
        }
    }

    // (F) Delete the sealed per-tenant credentials so the reprovision mints FRESH ones.
    let login_cred = credential_workload_key(compute, &ident);
    let owner_cred = owner_credential_workload_key(compute, &ident);
    for cred in [&login_cred, &owner_cred] {
        if let Err(e) = creds.delete(project, cred).await {
            tracing::info!(cred = %cred, error = %e, "self-heal: sealed credential delete skipped");
        }
    }
    // (G) REPROVISION fresh — new roles + fresh credentials + a clean empty live db — so the
    //     subsequent shadow-swap restore lands clean.
    provision_tenant(deploy, kv, envelope, binding, project, "").await?;
    Ok(SelfHealReport::Healed {
        cleared_asides,
        preserved_tombstones,
        dropped_tombstones,
        roles_reprovisioned: class.existing_roles,
    })
}

/// The **pure** decision of how a delete tears a tenant down — the engine/cell split
/// (see the module matrix), with no IO so it is fully unit-testable. Returns `None`
/// for a binding this module doesn't own (bring-your-own `url_env`, unparsable
/// engine) or the reserved default tenant (its database IS the single-tenant install).
///
/// `now` is injected (unix seconds) so the renamed-aside name + tombstone timestamps
/// are deterministic in tests.
fn plan_deprovision(
    binding: &ExternalDatabaseConfig,
    project: &str,
    site: &str,
    grace_secs: u64,
    now: u64,
) -> Option<DeprovisionPlan> {
    let compute = binding.compute.as_deref().filter(|c| !c.is_empty())?;
    let kind = ExternalSqlKind::parse(&binding.kind)?;
    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, site);
    if is_default {
        return None; // never tear down the single-tenant install.
    }
    let database = binding.database.as_deref().unwrap_or_default();
    let superuser = binding.user.as_deref().unwrap_or_default();
    let ident = sanitize_ident(&tenant_ident_raw);
    let names = tenant_names(binding.tenant, compute, database, &tenant_ident_raw, false);

    Some(match binding.tenant {
        TenantIsolation::Single => DeprovisionPlan::SingleDrop {
            workload: names.workload,
        },
        // Shared + Postgres, with a non-zero grace: the ONE recoverable cell.
        TenantIsolation::Shared if kind == ExternalSqlKind::Postgres && grace_secs > 0 => {
            // The aside name carries the delete timestamp, so it's unique per
            // soft-delete and never collides with a same-named re-create's fresh
            // database (the freed original name can't alias the renamed-aside data).
            //
            // BOUNDED to Postgres's 63-byte NAMEDATALEN (truncating the live-db PREFIX, never the
            // `__deleted_<ts>` distinguisher): a per-tenant `names.database` is already capped AT
            // 63 bytes, so the naive `format!("{db}__deleted_{now}")` overflows → Postgres
            // truncates it back to its first 63 bytes → which, for a db already at the cap,
            // COLLAPSES RIGHT BACK to `names.database` → `ALTER DATABASE <db> RENAME TO <db>`
            // renames it to itself and fails `database "<db>" already exists`, orphaning the
            // delete (the construens soft-deprovision failure). The bounded helper keeps the
            // `__deleted_<ts>` tail intact so the aside name is always ≤ 63 bytes AND distinct
            // from the live name — the SAME bounding the shadow-restore aside names use.
            let renamed_db = boatramp_storage::tenant_provision::bounded_aside_db_name(
                &names.database,
                "__deleted_",
                &now.to_string(),
            );
            let ddl = soft_deprovision_ddl(&names.database, &renamed_db, &names.role);
            let tombstone = Tombstone {
                version: 1,
                project: project.to_string(),
                renamed_db,
                original_db: names.database.clone(),
                role: names.role.clone(),
                engine: "postgres".to_string(),
                compute: compute.to_string(),
                superuser: superuser.to_string(),
                cred_workload: credential_workload_key(compute, &ident),
                deleted_at: now,
                delete_after: now.saturating_add(grace_secs),
            };
            DeprovisionPlan::SharedSoftPostgres { ddl, tombstone }
        }
        // Shared + MySQL (no database rename) OR Shared-Postgres with grace = 0.
        TenantIsolation::Shared => DeprovisionPlan::SharedImmediate {
            kind,
            compute: compute.to_string(),
            superuser: superuser.to_string(),
            ddl: boatramp_storage::tenant_provision::deprovision_ddl(
                kind,
                &names.database,
                &names.role,
            ),
            cred_workload: credential_workload_key(compute, &ident),
            database: names.database,
        },
    })
}

/// The pure plan a delete follows, one variant per cell of the deprovision matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeprovisionPlan {
    /// Single (any engine): drop the dedicated workload + its credential. Immediate.
    SingleDrop { workload: String },
    /// Shared + MySQL, or Shared-Postgres with grace 0: hard-drop DDL + credential
    /// delete. Immediate + irreversible.
    SharedImmediate {
        kind: ExternalSqlKind,
        compute: String,
        superuser: String,
        ddl: Vec<String>,
        cred_workload: String,
        database: String,
    },
    /// Shared + Postgres with grace > 0: soft-delete DDL (RENAME + NOLOGIN) + a
    /// tombstone. Recoverable within the grace window; keeps the credential.
    SharedSoftPostgres {
        ddl: Vec<String>,
        tombstone: Tombstone,
    },
}

/// Reverse a soft delete (see [`deprovision_tenant`]) for the tombstone identified by
/// `(project, renamed_db)`, within its grace window: rename the aside database back to
/// its original name, `ALTER ROLE … LOGIN`, and delete the tombstone. The sealed
/// credential was never removed, so the recovered tenant connects exactly as before.
/// The superuser + server are taken from the tombstone, so recovery needs no binding
/// config.
///
/// Returns `Ok(false)` (a no-op) if no such tombstone exists — recovering an
/// already-reaped or never-soft-deleted tenant is harmless.
pub async fn recover_tenant(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    project: &str,
    renamed_db: &str,
) -> Result<bool, String> {
    let Some(ts) = tenant_tombstone::get(kv, project, renamed_db).await? else {
        return Ok(false);
    };
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let admin = shared_admin_backend(
        deploy,
        &creds,
        ExternalSqlKind::Postgres,
        &ts.compute,
        &ts.superuser,
    )
    .await?;
    for stmt in recover_soft_deprovision_ddl(&ts.renamed_db, &ts.original_db, &ts.role) {
        admin
            .run_script(&stmt)
            .await
            .map_err(|e| format!("recover {}: {e}", ts.original_db))?;
    }
    tenant_tombstone::delete(kv, &ts).await?;
    Ok(true)
}

/// The node's [`TenantDeprovisioner`] — the delete-time orchestrator over
/// [`deprovision_tenant`]. Holds everything a deprovision needs (the deploy store,
/// KV, the secrets envelope, and the `databases` binding map) so the delete handlers
/// can tear a deleted tenant's managed databases down after the store delete.
///
/// It walks the compute-backed **managed-credential** bindings and, matching each
/// binding's `tenant_scope` against the axis of the delete (project vs site), drops
/// exactly that tenant. Best-effort: every drop that fails is logged at `warn` and
/// the walk continues — a stuck database never blocks the delete. The reserved
/// `default` project is skipped outright (dropping the single-tenant install's
/// database on a stray delete would be catastrophic; [`deprovision_tenant`] also
/// guards it defensively).
///
/// [`TenantDeprovisioner`]: boatramp_core::sql::TenantDeprovisioner
pub struct NodeTenantDeprovisioner {
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
    databases: std::collections::BTreeMap<String, ExternalDatabaseConfig>,
    /// The soft-delete grace window in seconds (Shared-Postgres only); `0` = the
    /// soft path is disabled (immediate hard drop everywhere). See
    /// [`deprovision_tenant`].
    grace_secs: u64,
}

impl NodeTenantDeprovisioner {
    /// Build the deprovisioner from the wired managed-DB state. The same
    /// (deploy, KV, envelope, databases) the provisioning + resolver seams use, plus
    /// the configured soft-delete `grace_secs`
    /// (`handlers.bindings.sql.deprovision_grace_secs`, default
    /// [`DEFAULT_DEPROVISION_GRACE_SECS`]).
    pub fn new(
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
        databases: std::collections::BTreeMap<String, ExternalDatabaseConfig>,
        grace_secs: u64,
    ) -> Self {
        Self {
            deploy,
            kv,
            envelope,
            databases,
            grace_secs,
        }
    }

    /// Deprovision every compute-backed managed-credential binding whose
    /// `tenant_scope` matches `scope`, for the tenant `(project, site)`. Best-effort:
    /// log-and-continue on error, and never touch the reserved `default` project.
    ///
    /// TWO sources are walked (the ownership-accounting fix): the node operator's **static**
    /// `[handlers].bindings.sql.databases` map AND the deleted project's **own declared** managed
    /// databases (`project/<proj>/database/<name>`, the declarative front door `project sync` /
    /// `db ensure` provision through). Before this the deprovisioner only walked the static map, so
    /// a self-declared tenant database — the ONLY kind a cross-node `project sync` creates — was
    /// invisible to the delete and left orphaned (the construens `project rm` "owns nothing" shape).
    /// A declared name that ALSO appears in the static map is skipped here (the static walk owns it;
    /// the daemon-wins invariant forbids the two from denoting different databases anyway).
    async fn deprovision_scope(&self, scope: TenantScope, project: &str, site: &str) {
        if project == DEFAULT_PROJECT {
            // The reserved default project is the single-tenant install; its managed
            // database IS the install. A stray delete must never drop it.
            return;
        }
        // 1. Node-operator STATIC bindings (per-tenant templates applied to every project).
        for (name, _kind, binding) in managed_bindings(&self.databases) {
            // Only our managed-credential bindings on this delete's axis. A
            // bring-your-own binding is filtered out by `managed_bindings` already;
            // a `password_env` (operator-supplied credential) binding is left alone.
            if !binding.is_managed_credential() || binding.tenant_scope != scope {
                continue;
            }
            self.deprovision_one(name, binding, scope, project, site)
                .await;
        }
        // 2. The deleted project's OWN declared managed databases (the declarative front door). Each
        //    is lowered to the SAME managed-credential `ExternalDatabaseConfig` it was provisioned
        //    through (`managed_db_declare::lower`), so the derived tenant DB/role names match exactly
        //    what provision created — scoped to THIS project (names derive from `(project, binding)`),
        //    never another tenant. Read BEFORE the caller purges the project's KV (the force cascade
        //    deprovisions, then purges), so the declarations are still present here.
        match self
            .deploy
            .list_project_databases(ProjectRef::new(project))
            .await
        {
            Ok(declared) => {
                for db in declared {
                    // Daemon-wins: a name present in the static map is the operator's binding,
                    // already handled in step 1 — never shadow it with the project declaration.
                    if self.databases.contains_key(&db.name) {
                        continue;
                    }
                    let binding = crate::managed_db_declare::lower(project, &db);
                    if !binding.is_managed_credential() || binding.tenant_scope != scope {
                        continue;
                    }
                    self.deprovision_one(&db.name, &binding, scope, project, site)
                        .await;
                }
            }
            Err(e) => tracing::warn!(
                project,
                error = %e,
                "could not enumerate the project's declared managed databases for deprovision \
                 (best-effort; delete not blocked)"
            ),
        }
    }

    /// Deprovision ONE resolved managed-credential binding for `(project, site)`, best-effort:
    /// log success at `info`, log-and-continue on error at `warn` (a stuck database never blocks the
    /// delete — an orphaned DB is a lesser evil than a half-deleted project). Shared by the
    /// node-static and project-declared walks so both sources tear down identically.
    async fn deprovision_one(
        &self,
        name: &str,
        binding: &ExternalDatabaseConfig,
        scope: TenantScope,
        project: &str,
        site: &str,
    ) {
        match deprovision_tenant(
            &self.deploy,
            &self.kv,
            &self.envelope,
            binding,
            project,
            site,
            self.grace_secs,
        )
        .await
        {
            Ok(()) => {
                if matches!(scope, TenantScope::Site) {
                    tracing::info!(
                        binding = name,
                        project,
                        site,
                        "deprovisioned managed database for deleted site tenant"
                    );
                } else {
                    tracing::info!(
                        binding = name,
                        project,
                        "deprovisioned managed database for deleted project tenant"
                    );
                }
            }
            Err(e) => tracing::warn!(
                binding = name,
                project,
                site,
                error = %e,
                "managed-database deprovision failed (best-effort; delete not blocked)"
            ),
        }
    }
}

#[async_trait]
impl boatramp_core::sql::TenantDeprovisioner for NodeTenantDeprovisioner {
    async fn deprovision_project(&self, project: &str) {
        // A project tenant carries no site; the empty site is inert for Project scope.
        self.deprovision_scope(TenantScope::Project, project, "")
            .await;
    }

    async fn deprovision_site(&self, project: &str, site: &str) {
        self.deprovision_scope(TenantScope::Site, project, site)
            .await;
    }
}

// ---------------------------------------------------------------------------
// Tombstone reaper: leader-gated hard-drop of grace-elapsed soft-deletes.
// ---------------------------------------------------------------------------

/// Hard-drop one due (grace-elapsed) soft-deleted tenant: as the superuser, `DROP
/// DATABASE "<renamed_db>"` + `DROP ROLE "<role>"`, then delete the sealed credential
/// and the tombstone. This is the point of no return the grace window protected.
///
/// The DROPs go through the pure `deprovision_ddl` builder (same quoting as
/// everywhere else), targeting the **renamed** database. Only after both the DDL and
/// the credential delete succeed is the tombstone removed — so a partial failure
/// leaves the tombstone for the next sweep to retry (idempotent: `IF EXISTS` guards +
/// idempotent credential/tombstone deletes make a re-run harmless).
async fn hard_drop_tombstone(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    ts: &Tombstone,
) -> Result<(), String> {
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let admin = shared_admin_backend(
        deploy,
        &creds,
        ExternalSqlKind::Postgres,
        &ts.compute,
        &ts.superuser,
    )
    .await?;
    // DROP the RENAMED database + the role (IF EXISTS-guarded, so re-runnable).
    for stmt in boatramp_storage::tenant_provision::deprovision_ddl(
        ExternalSqlKind::Postgres,
        &ts.renamed_db,
        &ts.role,
    ) {
        admin
            .run_script(&stmt)
            .await
            .map_err(|e| format!("reap {}: {e}", ts.renamed_db))?;
    }
    // Now the credential can go (recovery is no longer possible), then the tombstone.
    creds
        .delete(&ts.project, &ts.cred_workload)
        .await
        .map_err(|e| format!("reap credential {}: {e}", ts.cred_workload))?;
    tenant_tombstone::delete(kv, ts).await
}

/// The tombstones **due** at wall-clock `now` — those whose grace window has elapsed
/// (`delete_after <= now`). Pure, so due-selection is unit-testable with an injected
/// `now` and no live clock or database.
fn due_tombstones(all: Vec<Tombstone>, now: u64) -> Vec<Tombstone> {
    all.into_iter().filter(|t| t.is_due(now)).collect()
}

/// Select the tombstones due at wall-clock `now` and hard-drop each, best-effort
/// (log-and-continue). Returns the number reaped. Split from the spawn loop with an
/// explicit `now` so due-selection is unit-testable without a live clock.
async fn reap_due(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    now: u64,
) -> usize {
    let tombstones = match tenant_tombstone::list(kv).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "tenant tombstone reaper: could not list tombstones");
            return 0;
        }
    };
    let mut reaped = 0;
    for ts in due_tombstones(tombstones, now) {
        match hard_drop_tombstone(deploy, kv, envelope, &ts).await {
            Ok(()) => {
                reaped += 1;
                tracing::info!(
                    project = %ts.project,
                    renamed_db = %ts.renamed_db,
                    "tenant tombstone reaper: hard-dropped a soft-deleted tenant past its grace window"
                );
            }
            Err(e) => tracing::warn!(
                project = %ts.project,
                renamed_db = %ts.renamed_db,
                error = %e,
                "tenant tombstone reaper: hard-drop failed (best-effort; retried next sweep)"
            ),
        }
    }
    reaped
}

/// Spawn the leader-gated **tombstone reaper**: every [`TOMBSTONE_REAPER_TICK`], on
/// the leader, hard-drop any soft-deleted Shared-Postgres tenant whose grace window
/// has elapsed (see [`deprovision_tenant`]). Mirrors
/// [`boatramp_server::spawn_compute_reconcile`] / the domain-verify reconcile — the
/// leader gate makes it a single-writer in a cluster. A no-op while not leader or
/// with no due tombstones. Detached for the process lifetime; the returned handle is
/// collected into [`RunningNode::reconcile`](crate::RunningNode).
///
/// Each tombstone records its own server + superuser, so the reaper needs no binding
/// config. A tenant is only ever soft-deleted (⇒ a tombstone written) when its
/// configured `grace_secs > 0`; if grace is `0` everywhere, no tombstones exist and
/// the sweep is inert — but the loop still runs so a config that later raises the
/// grace still gets swept.
pub fn spawn_tenant_tombstone_reaper(
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
    is_leader: boatramp_server::CronLeaderGate,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        // `interval` fires immediately; skip that first tick so the sweep waits a
        // full period before its first run (matches the domain-verify reconcile).
        interval.tick().await;
        loop {
            interval.tick().await;
            if !is_leader() {
                continue;
            }
            let n = reap_due(&deploy, &kv, &envelope, now_unix_secs()).await;
            if n > 0 {
                tracing::info!(reaped = n, "tenant tombstone reaper sweep");
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Resolver seam: the node-side PerTenantSqlResolver.
// ---------------------------------------------------------------------------

/// The node's [`PerTenantSqlResolver`] for one compute-backed managed binding.
///
/// On `resolve(project, site)` it derives the tenant, resolves the per-tenant sealed
/// credential, and builds a [`ComputeResolvedSqlBackend`] that connects **as the
/// tenant's role to the tenant's database** — the isolation perimeter:
///
/// - **Shared** — target the shared `compute` workload, `db = tenant_db`,
///   `user = tenant_role`, password = the per-tenant credential.
/// - **Single** — target the per-tenant workload `<compute>-<tenant_ident>`,
///   `db = binding.database`, `user = binding.user`, password = the per-tenant
///   workload's credential.
///
/// When the binding sets `rls_session = true`, the built backend also injects the
/// request's `boatramp.project` / `boatramp.site` at every transaction start.
pub struct NodeTenantSqlResolver {
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
    kind: ExternalSqlKind,
    compute: String,
    // The binding's plain configured names (bases for derivation).
    database: String,
    user: String,
    isolation: TenantIsolation,
    scope: TenantScope,
    rls_session: bool,
    // The declared serving posture (Shared + rls_session + Postgres only). Selects whether the
    // serving identity is the non-owner runtime role (`NonOwner`, the default) or the owner role
    // (`Owner`), and — via provisioning — whether the FORCE-on-ENABLE RLS trigger is installed.
    serve_as: ServeAs,
    pool_max: Option<u32>,
    // Opt-in warm floor for the per-tenant storefront pool. Held PER TENANT (one pool per
    // resolved tenant), so a non-zero value keeps that many idle DB sessions per tenant —
    // honored only because it is explicit per-binding `pool_min` config. Default none.
    pool_min: Option<u32>,
    read_only: bool,
    connect_timeout: Option<Duration>,
    // The full binding, kept so `resolve` can lazily provision the tenant (idempotent)
    // before handing back a connection — the server is up by the time a request arrives.
    binding: ExternalDatabaseConfig,
}

impl NodeTenantSqlResolver {
    /// Build a resolver for `binding` (which must be a compute-backed managed
    /// binding). Returns `None` for a bring-your-own `url_env` binding or an
    /// unparsable engine — such a binding is not per-tenant and is not registered
    /// through this seam.
    pub fn new(
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
        binding: &ExternalDatabaseConfig,
    ) -> Option<Self> {
        let compute = binding.compute.as_deref().filter(|c| !c.is_empty())?;
        let kind = ExternalSqlKind::parse(&binding.kind)?;
        Some(Self {
            deploy,
            kv,
            envelope,
            kind,
            compute: compute.to_string(),
            database: binding.database.clone().unwrap_or_default(),
            user: binding.user.clone().unwrap_or_default(),
            isolation: binding.tenant,
            scope: binding.tenant_scope,
            rls_session: binding.rls_session,
            serve_as: binding.serve_as,
            pool_max: binding.pool_max,
            pool_min: binding.pool_min,
            read_only: binding.read_only,
            connect_timeout: binding.connect_timeout_secs.map(Duration::from_secs),
            binding: binding.clone(),
        })
    }

    /// Whether the binding's grain is `Site` — used by the composite to key its cache.
    pub fn site_scoped(&self) -> bool {
        matches!(self.scope, TenantScope::Site)
    }
}

#[async_trait]
impl PerTenantSqlResolver for NodeTenantSqlResolver {
    async fn resolve(&self, project: &str, site: &str) -> Result<Arc<dyn SqlBackend>, SqlError> {
        // Lazily provision this tenant's database/role (Shared) or dedicated workload
        // (Single) before connecting — idempotent, and the composite caches the built
        // backend per tenant so this runs once per tenant, when the server is already
        // serving (so the maintenance connection for Shared DDL succeeds). This is the
        // provisioning trigger; a create-time hook can also call `provision_tenant`
        // ahead of the first request, but this guarantees the tenant is ready.
        provision_tenant(
            &self.deploy,
            &self.kv,
            &self.envelope,
            &self.binding,
            project,
            site,
        )
        .await
        .map_err(SqlError::other)?;
        self.build_backend(project, site).await
    }
}

/// Whether to install the FORCE-on-ENABLE RLS event trigger for a managed binding — the
/// provisioning half of the `serve_as` posture. `FORCE` is installed **iff** the binding serves
/// `rls_session` AS the owner on the Shared-Postgres owner/runtime split: an owner-serving session
/// operates as the table owner, which plain `ENABLE ROW LEVEL SECURITY` does NOT bind, so `FORCE` is
/// required there. A `non-owner` posture (the default) serves a role `ENABLE` already binds, so no
/// `FORCE` is installed (and none is needed). Postgres-only; MySQL has no row-level security.
pub(crate) fn install_force_rls(
    rls_session: bool,
    serve_as: ServeAs,
    kind: ExternalSqlKind,
) -> bool {
    rls_session && serve_as == ServeAs::Owner && kind == ExternalSqlKind::Postgres
}

/// The `rls_session` **owner-serving tenancy invariant**, as a pure predicate shared by BOTH guard
/// sites ([`NodeTenantSqlResolver::build_backend`] and
/// [`NodeTenantSqlResolver::connection_parts`]'s `Runtime` role) so the fail-closed decision is ONE
/// place and is unit-testable with the owner-serving-without-FORCE mutation.
///
/// Returns `true` when serving MUST be refused: the resolved serving role is the tenant table
/// **owner** on the Shared, non-default, Postgres `rls_session` cell, but the binding did **not**
/// declare [`ServeAs::Owner`] — the posture that installs the FORCE-on-ENABLE trigger ([`install_force_rls`]).
/// Without `FORCE`, plain `ENABLE` does not bind the owner, so an owner serving role would
/// un-enforce the app's row-level security and leak cross-tenant (proven live in the
/// `managed_rls_nonowner_runtime_sqlx_live` gate's owner arm). Under [`ServeAs::Owner`] the serving
/// role is legitimately the owner AND `FORCE` is installed, so this returns `false` (permitted). The
/// invariant it enforces: **owner-serving ⟺ `FORCE` present** — the serving role resolves to the
/// owner ONLY under the owner posture, and the owner posture is the ONLY thing that installs `FORCE`,
/// so any OTHER route to the owner identity on the serving path (a future refactor) is caught here.
fn owner_serving_without_force(
    rls_session: bool,
    kind: ExternalSqlKind,
    isolation: TenantIsolation,
    is_default: bool,
    serving_user: &str,
    owner_role: &str,
    serve_as: ServeAs,
) -> bool {
    rls_session
        && kind == ExternalSqlKind::Postgres
        && isolation == TenantIsolation::Shared
        && !is_default
        && serving_user == owner_role
        && serve_as != ServeAs::Owner
}

/// The fail-closed error returned by both guard sites when [`owner_serving_without_force`] holds.
fn owner_serving_without_force_error(user: &str) -> SqlError {
    SqlError::other(format!(
        "rls_session tenancy invariant: the resolved serving role ({user}) is the tenant table \
         OWNER but this binding did not declare `serve_as: owner`, so boatramp did NOT install the \
         FORCE-on-ENABLE RLS trigger — plain ENABLE RLS does not bind the owner, so serving here \
         would un-enforce the app's row-level security; refusing (fail-closed). Invariant: \
         owner-serving ⟺ FORCE present (declare `serve_as: owner` to install FORCE, or \
         `serve_as: non-owner` to serve as the non-owner runtime role)."
    ))
}

impl NodeTenantSqlResolver {
    /// The Shared, non-default **serving identity** `(cred_workload, user)` for the declared posture:
    /// [`ServeAs::Owner`] (Postgres only) → the per-tenant **owner** role + its sealed owner
    /// credential (operate-as-owner, FORCE-bound); otherwise (the default `non-owner`, or any MySQL
    /// binding — which has no owner/runtime split) → the per-tenant **non-owner** runtime role + its
    /// credential. The SAME selection drives [`build_backend`](Self::build_backend) and
    /// [`connection_parts`](Self::connection_parts)'s `Runtime` role, so a handler's `sql.open()` DSN
    /// and a sibling container's `{{sql.dsn}}` serve as the IDENTICAL posture-selected role.
    fn shared_serving_identity(&self, ident: &str, names: &TenantNames) -> (String, String) {
        if self.serve_as == ServeAs::Owner && self.kind == ExternalSqlKind::Postgres {
            (
                owner_credential_workload_key(&self.compute, ident),
                names.owner_role.clone(),
            )
        } else {
            (
                credential_workload_key(&self.compute, ident),
                names.role.clone(),
            )
        }
    }

    /// Build the per-tenant backend: resolve the endpoint, seal + fetch the
    /// per-tenant credential, and construct the connection. Split out from `resolve`
    /// so it can be unit-tested without a live server — `resolve` runs the
    /// (server-requiring) provisioning first, then calls this.
    async fn build_backend(
        &self,
        project: &str,
        site: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError> {
        let (tenant_ident_raw, is_default) = tenant_key(self.scope, project, site);
        let names = tenant_names(
            self.isolation,
            &self.compute,
            &self.database,
            &tenant_ident_raw,
            is_default,
        );

        // The endpoint resolver + connection user/password/db differ by isolation.
        let (cred_project, cred_workload, user) = match self.isolation {
            // Shared: connect as the tenant's ROLE with its per-tenant credential.
            // The default tenant uses the superuser (its role == the plain user,
            // credential under the default project + bare workload).
            TenantIsolation::Shared => {
                if is_default {
                    (
                        DEFAULT_PROJECT.to_string(),
                        self.compute.clone(),
                        self.user.clone(),
                    )
                } else {
                    // The serving role follows the declared `serve_as` posture: the non-owner runtime
                    // role (default) or — under `serve_as: owner` — the owner role (FORCE-bound).
                    let ident = sanitize_ident(&tenant_ident_raw);
                    let (cred_workload, user) = self.shared_serving_identity(&ident, &names);
                    (project.to_string(), cred_workload, user)
                }
            }
            // Single: connect as the plain configured user to the per-tenant server,
            // keyed by the workload's OWN `(project, workload)` — the bare `<compute>`
            // for the DEFAULT tenant (matching the server-init env key of a
            // single-tenant install), else `<compute>-<ident>` under the tenant's
            // project (matching that per-tenant workload's server-init key).
            TenantIsolation::Single => (
                single_credential_project(project, is_default),
                names.workload.clone(),
                self.user.clone(),
            ),
        };

        // TENANCY INVARIANT (fail-closed) — the `rls_session` **owner-serving** contract. With
        // `rls_session` on, the app's row-level security is enforced against THIS serving role. Under
        // the `serve_as` posture (v0.59.4 "Option C") a Shared-Postgres binding serves either the
        // NON-OWNER runtime role (default — bound by plain `ENABLE`, no `FORCE`) or — with
        // `serve_as: owner` — the owner role, for which boatramp installs the FORCE-on-ENABLE trigger
        // ([`install_force_rls`]) because `ENABLE` does NOT bind the owner. The GUARD permits the
        // owner serving role ONLY under the `serve_as: owner` posture (⇒ FORCE present), and refuses
        // the owner identity on the serving path by ANY OTHER route (a future refactor) — enforcing
        // **owner-serving ⟺ FORCE present** fail-closed. Shared non-default Postgres only (the sole
        // cell with a distinct owner role); everywhere else the runtime identity is the owning login.
        if owner_serving_without_force(
            self.rls_session,
            self.kind,
            self.isolation,
            is_default,
            &user,
            &names.owner_role,
            self.serve_as,
        ) {
            return Err(owner_serving_without_force_error(&user));
        }

        let password = ManagedSqlCredentials::new(self.kv.clone(), self.envelope.clone())
            .password(&cred_project, &cred_workload)
            .await
            .map_err(SqlError::other)?;

        // The workload's replica endpoints are scoped to the project that owns them:
        // Single per-tenant workloads live under the request's project; the Shared
        // server + the default install live under the reserved default project.
        let endpoint_project = match self.isolation {
            TenantIsolation::Single if !is_default => project.to_string(),
            _ => DEFAULT_PROJECT.to_string(),
        };
        // Handler-runtime routing — gate at the DB's configured `routing` readiness level
        // (default `Provisioned`): a request is routed to a replica only once it meets it.
        let resolver: Arc<dyn ComputeEndpointResolver> =
            Arc::new(DeployEndpointResolver::new_gated(
                self.deploy.clone(),
                endpoint_project,
                self.binding.readiness_gate.routing,
            ));

        let mut backend = ComputeResolvedSqlBackend::new(
            resolver,
            names.workload.clone(),
            self.kind,
            names.database.clone(),
            user,
            password,
            self.pool_max,
            self.read_only,
            self.connect_timeout,
        )
        .with_pool_min(self.pool_min);
        if self.rls_session {
            backend = backend.with_session_context(vec![
                (SESSION_KEY_PROJECT, project.to_string()),
                (SESSION_KEY_SITE, site.to_string()),
            ]);
            // v0.4.20: also expose the host-resolved TENANT (and anonymous session) as the
            // operator's RLS GUCs, so an app's Postgres RLS mirrors boatramp's injected predicate.
            // The NAMES are per-binding config; the handler binding sets the per-request/per-write
            // VALUE. Only when a tenant GUC name is configured (else today's project/site-only).
            if let Some(tenant) = self.binding.tenant_guc.clone().filter(|s| !s.is_empty()) {
                // The principal-class GUC (a `cron-system-principal` request) is DERIVED from the
                // tenant GUC's own namespace (`app.tenant_id` ⇒ `app.principal_kind`) — no extra
                // operator config, and it is inherently in the tenant GUC's reserved leading segment
                // (plus `reserved_names` lists it), so a guest can never forge it. A Postgres custom
                // GUC is always `namespace.name`, so the split succeeds; absent a `.`, no class GUC.
                let kind = tenant
                    .rsplit_once('.')
                    .map(|(ns, _)| format!("{ns}.principal_kind"));
                backend = backend.with_rls_guc(Some(boatramp_core::sql::RlsGuc {
                    tenant,
                    session: self.binding.session_guc.clone().filter(|s| !s.is_empty()),
                    // v0.4.21: the reserved all-read marker. Empty/whitespace-only ⇒ None ⇒ `all`
                    // reads stay fail-closed (v0.4.20 behavior) — and the marker can never collide
                    // with the empty-string deny sentinel `defend_write_marker` restores to.
                    all_marker: self
                        .binding
                        .tenant_all_marker
                        .clone()
                        .filter(|s| !s.trim().is_empty()),
                    kind,
                }));
            }
        }
        Ok(Arc::new(backend))
    }

    /// Resolve the raw CONNECTION PARTS for `(project, site)` as `role` — the SAME
    /// per-tenant derivation [`build_backend`](Self::build_backend) uses
    /// ([`tenant_names`] + the sealed per-tenant credential), but returning the parts a
    /// SIBLING compute workload composes into a real `postgres://` / `mysql://` DSN,
    /// instead of a pooled backend (PLAN-compute-managed-db-dsn Phase 1).
    ///
    /// # Reachability — the internal-DNS name, not a bridge IP
    ///
    /// `host` is the managed DB's per-project SD **alias** — [`managed_db_alias`] of its workload
    /// name ([`TenantNames::workload`]), the SAME short, DNS-valid label `boatramp-docker`'s
    /// `launch` publishes as the endpoint alias (both derive it from `names.workload`, so they
    /// always match). It is the alias, not the raw workload name, because a `Single` managed-DB
    /// name can exceed the 63-octet DNS-label cap and Docker 29 then refuses to register it.
    /// A sibling resolves this name to the DB's live healthy replica (`compute.internal_dns`, on
    /// by default). Deliberately NOT the numeric replica IP:
    /// the DSN is injected into the sibling's env at launch and is static for its life, so
    /// a name (which re-resolves at connect time, and survives a DB relaunch onto a new
    /// bridge IP) is correct where a captured IP would go stale. `port` is the engine's
    /// standard in-container bridge port (the stock image's port; boatramp never remaps
    /// it). No deploy-store/endpoint lookup happens here, so a workload can launch before
    /// its managed DB's first replica is healthy (the driver retries, DNS resolves once up).
    ///
    /// # The credential (`password`) is unsealed SERVER-SIDE
    ///
    /// The per-tenant managed credential is unsealed from the `[secrets]` envelope on the
    /// node; it is returned in-memory for the DSN composition and MUST NEVER be logged.
    ///
    /// Phase-1 reachability limit (documented): a `Shared`, non-default-project managed DB
    /// runs under the reserved default project, which a non-default project's container
    /// cannot resolve by internal name — use the default `tenant: single` isolation for a
    /// compute-bound managed DB.
    pub(crate) async fn connection_parts(
        &self,
        project: &str,
        site: &str,
        role: ConnRole,
    ) -> Result<SqlConnParts, SqlError> {
        let (tenant_ident_raw, is_default) = tenant_key(self.scope, project, site);
        let names = tenant_names(
            self.isolation,
            &self.compute,
            &self.database,
            &tenant_ident_raw,
            is_default,
        );
        let creds = ManagedSqlCredentials::new(self.kv.clone(), self.envelope.clone());
        let port = match self.kind {
            ExternalSqlKind::Postgres => PG_BRIDGE_PORT,
            ExternalSqlKind::Mysql => MYSQL_BRIDGE_PORT,
        };

        // The MIGRATION/DDL identity: only a Shared, non-default Postgres tenant has a
        // DISTINCT owner role + sealed owner credential (the owner-role split that keeps the
        // runtime role a non-owner). Prefer it when an owner credential is ALREADY sealed —
        // read-only (`get_sealed_password`), NEVER minting one here (provisioning owns the
        // owner credential; minting a fresh random one would not match the role's real
        // password). Everywhere else — `Single` (its per-workload user owns its database),
        // the default tenant (its plain user owns its one database), and MySQL (no
        // owner/runtime split; managed-MySQL migration is a separate, currently-refused
        // path) — the migration identity IS the runtime identity, so we fall through.
        if role == ConnRole::Migration
            && self.isolation == TenantIsolation::Shared
            && self.kind == ExternalSqlKind::Postgres
            && !is_default
        {
            let ident = sanitize_ident(&tenant_ident_raw);
            let owner_workload = owner_credential_workload_key(&self.compute, &ident);
            if let Some(password) = creds
                .get_sealed_password(project, &owner_workload)
                .await
                .map_err(SqlError::other)?
            {
                return Ok(SqlConnParts {
                    kind: self.kind,
                    // The DSN host is the DB's SD ALIAS, not its (possibly > 63-octet) workload
                    // name — see `managed_db_alias`. It MUST equal the alias `boatramp-docker`
                    // publishes (both derive it from `names.workload`), or Docker 29 won't resolve.
                    host: managed_db_alias(&names.workload),
                    port,
                    user: names.owner_role,
                    password,
                    database: names.database,
                });
            }
        }

        // The RUNTIME identity — byte-identical to `build_backend`'s derivation, so the
        // injected DSN authenticates as exactly what a handler's `sql.open()` would. The
        // per-tenant password is minted-or-read under the SAME key the managed DB server
        // initializes with, so it is consistent regardless of launch order.
        let (cred_project, cred_workload, user) = match self.isolation {
            TenantIsolation::Shared if is_default => (
                DEFAULT_PROJECT.to_string(),
                self.compute.clone(),
                self.user.clone(),
            ),
            TenantIsolation::Shared => {
                // The sibling-DSN RUNTIME identity follows the SAME `serve_as` posture selection as
                // `build_backend`, so a container's `{{sql.dsn}}` serves as the identical role a
                // handler's `sql.open()` would (non-owner by default; the owner role under
                // `serve_as: owner`). When `serve_as: owner`, the Phase-2 operate-as-owner dynamic
                // per-replica role (also gated on the owner posture in `dynamic_creds`) overrides
                // this static owner identity in the DSN resolver — both are owner-posture, both
                // FORCE-bound.
                let ident = sanitize_ident(&tenant_ident_raw);
                let (cred_workload, user) = self.shared_serving_identity(&ident, &names);
                (project.to_string(), cred_workload, user)
            }
            TenantIsolation::Single => (
                single_credential_project(project, is_default),
                names.workload.clone(),
                self.user.clone(),
            ),
        };

        // TENANCY INVARIANT (fail-closed) — the SAME owner-serving guard `build_backend` applies,
        // mirrored onto the Phase-1 sibling-DSN serving identity (the `{{sql.*}}` / `url_env` RUNTIME
        // parts a container composes). Scoped to `ConnRole::Runtime` only: the `ConnRole::Migration`
        // identity is DELIBERATELY the owner and already returned above, and a Migration call that
        // FELL THROUGH to here resolves the runtime identity (no sealed owner cred), which must not be
        // refused. The shared [`owner_serving_without_force`] predicate enforces **owner-serving ⟺
        // FORCE present**: an owner serving role is permitted only under `serve_as: owner` (which
        // installs FORCE); any other route to it is refused fail-closed.
        if role == ConnRole::Runtime
            && owner_serving_without_force(
                self.rls_session,
                self.kind,
                self.isolation,
                is_default,
                &user,
                &names.owner_role,
                self.serve_as,
            )
        {
            return Err(owner_serving_without_force_error(&user));
        }

        let password = creds
            .password(&cred_project, &cred_workload)
            .await
            .map_err(SqlError::other)?;

        Ok(SqlConnParts {
            kind: self.kind,
            // The DSN host is the DB's SD ALIAS (`managed_db_alias`), which equals the alias
            // `boatramp-docker`'s `launch` publishes — a valid DNS label even when the workload
            // name exceeds the 63-octet cap Docker 29's embedded DNS enforces. `names.workload`
            // (the long identity) still keys the sealed credential above (`cred_workload`).
            host: managed_db_alias(&names.workload),
            port,
            user,
            password,
            database: names.database,
        })
    }
}

/// The standard in-container listen port a managed co-located **Postgres** container
/// exposes on the compute bridge (the stock image's port; boatramp never remaps it). A
/// sibling workload reaching the DB by its internal-DNS name connects here.
pub(crate) const PG_BRIDGE_PORT: u16 = 5432;
/// The MySQL analogue of [`PG_BRIDGE_PORT`].
pub(crate) const MYSQL_BRIDGE_PORT: u16 = 3306;

/// Which role a resolved [`SqlConnParts`] authenticates as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnRole {
    /// The per-tenant RUNTIME login — what a handler's `sql.open()` uses (the binding's
    /// `url_env` DSN).
    Runtime,
    /// The schema-migration / DDL identity (the owner-role analog; the binding's
    /// `migration_url_env` DSN).
    Migration,
}

/// The resolved connection PARTS for a managed co-located SQL database, reachable from a
/// SIBLING compute workload in the same project. `password` is already unsealed
/// (server-side) — it MUST NEVER be logged. Consumed only to compose a `postgres://` /
/// `mysql://` DSN + fill `{{sql.*}}` template variables.
#[derive(Clone)]
pub(crate) struct SqlConnParts {
    /// Engine (selects the DSN scheme + default port).
    pub kind: ExternalSqlKind,
    /// The reachable host — the managed DB's per-project SD alias ([`managed_db_alias`] of the
    /// workload name), a valid DNS label matching the endpoint alias docker publishes (see
    /// [`NodeTenantSqlResolver::connection_parts`]).
    pub host: String,
    /// The engine's standard bridge port.
    pub port: u16,
    /// The role to connect as.
    pub user: String,
    /// The unsealed password (the ONLY secret) — never logged.
    pub password: String,
    /// The physical database to connect to.
    pub database: String,
}

impl SqlConnParts {
    /// The full `postgres://user:pass@host:port/db` (or `mysql://…`) DSN, user/password
    /// percent-encoded. The one place a DSN string is assembled — reuses the handler
    /// runtime's [`build_url`](boatramp_storage::sql_compute::build_url).
    pub(crate) fn dsn(&self) -> String {
        boatramp_storage::sql_compute::build_url(
            self.kind,
            &self.user,
            &self.password,
            &self.host,
            self.port,
            &self.database,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- tenant_key ------------------------------------------------------

    #[test]
    fn tenant_key_project_scope_marks_default() {
        // The reserved default project is the single-tenant install: plain names.
        assert_eq!(
            tenant_key(TenantScope::Project, "default", "blog"),
            ("default".to_string(), true)
        );
        // A non-default project is a distinct tenant, derived names.
        assert_eq!(
            tenant_key(TenantScope::Project, "acme", "blog"),
            ("acme".to_string(), false)
        );
    }

    #[test]
    fn tenant_key_site_scope_is_qualified_and_never_default() {
        // A site tenant is qualified by its project and is never the reserved default.
        assert_eq!(
            tenant_key(TenantScope::Site, "default", "blog"),
            ("default/blog".to_string(), false)
        );
        assert_eq!(
            tenant_key(TenantScope::Site, "acme", "shop"),
            ("acme/shop".to_string(), false)
        );
    }

    // ---- tenant_names: the default tenant stays "plain" ------------------

    #[test]
    fn default_tenant_uses_plain_names_no_hash() {
        // Shared + default: plain database, plain compute workload, no `_<hash>`.
        let n = tenant_names(TenantIsolation::Shared, "pg", "appdb", "default", true);
        assert_eq!(n.database, "appdb");
        assert_eq!(n.workload, "pg");
        assert!(!n.database.contains('_') || n.database == "appdb");

        // Single + default: plain workload (no `-<ident>`), plain database.
        let s = tenant_names(TenantIsolation::Single, "pg", "appdb", "default", true);
        assert_eq!(s.database, "appdb");
        assert_eq!(s.workload, "pg");
    }

    /// The v0.3.11 fix: a non-default Single container's data volume is keyed to its own
    /// workload (isolated), while the default install keeps the shared `"data"` (so an
    /// existing deployment isn't re-initdb'd on upgrade). Two tenants never collide.
    #[test]
    fn managed_volume_name_isolates_non_default_tenants() {
        // Default single-tenant install: unchanged historical volume name.
        assert_eq!(managed_volume_name("pg", true), "data");
        // Two distinct non-default Single tenants → distinct workloads → distinct volume
        // dirs, and neither is the shared "data" (the bug was all of them sharing it).
        let a = tenant_names(TenantIsolation::Single, "pg", "appdb", "acme", false).workload;
        let b = tenant_names(TenantIsolation::Single, "pg", "appdb", "globex", false).workload;
        assert_eq!(
            managed_volume_name(&a, false),
            a,
            "keyed to its own workload"
        );
        assert_ne!(managed_volume_name(&a, false), "data");
        assert_ne!(
            managed_volume_name(&a, false),
            managed_volume_name(&b, false),
            "distinct tenants must not share a volume"
        );
    }

    // ---- tenant_names: Shared derivation + isolation ---------------------

    #[test]
    fn shared_tenant_derives_distinct_db_and_role_from_workload_base() {
        let ident = sanitize_ident("acme");
        let n = tenant_names(TenantIsolation::Shared, "pg", "appdb", "acme", false);
        // The database is derived from the binding's database base…
        assert_eq!(n.database, tenant_db_name("appdb", &ident));
        // …the role from the SERVER (compute workload) base, so it is shared across
        // this tenant's bindings on the same server.
        assert_eq!(n.role, tenant_role_name("pg", &ident));
        // Shared targets the plain shared workload.
        assert_eq!(n.workload, "pg");
        // The derived names are not the plain configured ones (tenant != default).
        assert_ne!(n.database, "appdb");
    }

    #[test]
    fn shared_two_bindings_same_server_share_one_role_distinct_dbs() {
        // Two bindings for the SAME tenant on the SAME server (compute "pg") but with
        // different configured databases: ONE role (server-based), two databases.
        let a = tenant_names(TenantIsolation::Shared, "pg", "appdb", "acme", false);
        let b = tenant_names(TenantIsolation::Shared, "pg", "analytics", "acme", false);
        assert_eq!(a.role, b.role, "same (tenant, server) ⇒ one shared role");
        assert_ne!(a.database, b.database, "distinct databases per binding");
    }

    #[test]
    fn shared_distinct_tenants_are_isolated() {
        // Two DIFFERENT tenants on the same server + binding: distinct db AND role.
        let a = tenant_names(TenantIsolation::Shared, "pg", "appdb", "acme", false);
        let b = tenant_names(TenantIsolation::Shared, "pg", "appdb", "globex", false);
        assert_ne!(a.database, b.database, "cross-tenant database collision!");
        assert_ne!(a.role, b.role, "cross-tenant role collision!");
    }

    // ---- tenant_names: Single derivation ---------------------------------

    #[test]
    fn single_tenant_derives_dedicated_workload_plain_db() {
        let ident = sanitize_ident("acme");
        let n = tenant_names(TenantIsolation::Single, "pg", "appdb", "acme", false);
        // A dedicated per-tenant workload; the db name inside it is the plain config.
        assert_eq!(n.workload, format!("pg-{ident}"));
        assert_eq!(n.database, "appdb");
    }

    #[test]
    fn single_distinct_tenants_get_distinct_workloads() {
        let a = tenant_names(TenantIsolation::Single, "pg", "appdb", "acme", false);
        let b = tenant_names(TenantIsolation::Single, "pg", "appdb", "globex", false);
        assert_ne!(a.workload, b.workload, "cross-tenant workload collision!");
    }

    // ---- site vs project grain both derive isolated names ----------------

    #[test]
    fn site_grain_isolates_two_sites_of_one_project() {
        // Under Site scope two sites of one project are distinct tenants.
        let (ta, da) = tenant_key(TenantScope::Site, "acme", "blog");
        let (tb, db) = tenant_key(TenantScope::Site, "acme", "shop");
        assert!(!da && !db);
        let na = tenant_names(TenantIsolation::Shared, "pg", "appdb", &ta, false);
        let nb = tenant_names(TenantIsolation::Shared, "pg", "appdb", &tb, false);
        assert_ne!(na.database, nb.database);
        assert_ne!(na.role, nb.role);
    }

    // ---- credential key scheme -------------------------------------------

    #[test]
    fn credential_key_folds_in_the_tenant() {
        let ident = sanitize_ident("acme");
        let k = credential_workload_key("pg", &ident);
        // The compute workload plus the sanitized tenant identity — distinct per tenant
        // and never the bare superuser workload.
        assert!(k.starts_with("pg/"));
        assert_ne!(
            k, "pg",
            "must never collide with the superuser workload key"
        );
        assert_ne!(
            credential_workload_key("pg", &sanitize_ident("acme")),
            credential_workload_key("pg", &sanitize_ident("globex")),
            "distinct tenants ⇒ distinct credential keys"
        );
    }

    // ---- maintenance database + engine mapping ---------------------------

    #[test]
    fn maintenance_database_per_engine() {
        assert_eq!(maintenance_database(ExternalSqlKind::Postgres), "postgres");
        assert_eq!(maintenance_database(ExternalSqlKind::Mysql), "mysql");
    }

    // ---- orphan-drop aside classifier (the DATA-LOSS-sensitive role-sharing guard) -------------

    #[test]
    fn is_orphan_aside_classifies_asides_vs_live_siblings() {
        use boatramp_storage::tenant_provision::bounded_aside_db_name;

        let base = "appdb_proj_1a2b3c4d5e6f7g8h9i0j";
        // Genuine SHORT-FORM asides of THIS orphan (base fully present) — IN SCOPE. Each distinguisher
        // is a GENUINE one the aside generators emit: a unix timestamp (`now_unix_secs()`) or
        // `<nanos>_<pid>` (`shadow_suffix()`) — ASCII digits and `_` only.
        assert!(is_orphan_aside(
            base,
            &format!("{base}__deleted_1794417073")
        ));
        assert!(is_orphan_aside(base, &format!("{base}__old_1700000000_42")));
        assert!(is_orphan_aside(
            base,
            &format!("{base}__shadow_1700000000_42")
        ));

        // A GENUINE cap-truncated aside: a 63-byte base overflows `NAMEDATALEN`, so the constructor
        // keeps only `base[..keep]` before the marker. We build it through the SAME constructor the
        // production paths use, so the classifier's inverse must accept it (don't regress real
        // aside-clearing). Assert the base really sits at the cap and the aside really was truncated.
        let base63 = tenant_db_name(
            "appdb",
            &sanitize_ident("some-long-tenant-name-for-the-cap"),
        );
        assert_eq!(base63.len(), 63, "fixture base must sit AT the 63-byte cap");
        let truncated = bounded_aside_db_name(&base63, "__deleted_", "1794417073");
        assert_eq!(truncated.len(), 63);
        assert_ne!(
            truncated,
            format!("{base63}__deleted_1794417073"),
            "fixture must be a GENUINELY truncated aside (base prefix cut), not the short form"
        );
        assert!(is_orphan_aside(&base63, &truncated));

        // ===== THE ADVERSARIAL LIVE-SIBLING FALSE POSITIVE (the DATA-LOSS defect this fix closes) =====
        // A co-located sibling binding whose operator-chosen logical db name is `<orphan>__old_x`
        // derives a 63-byte PRIMARY that carries the `__old_` marker right after the shared `shd1`
        // prefix. The OLD loose `base.starts_with(pre)` test (and a bare `bounded_aside_db_name`
        // reconstruction, which at the cap collapses `base[..keep=4]` onto `shd1`) both classify this
        // LIVE sibling as an aside → unconditional `DROP DATABASE` → silent clobber. The fix REJECTS
        // it: the recovered suffix carries the sibling's tenant ident (letters) + digest, so it is not
        // a genuine all-numeric aside distinguisher.
        let sib_ident = sanitize_ident("oor-shar-ab12cd34");
        let orphan_db = tenant_db_name("shd1", &sib_ident);
        let sibling_db = tenant_db_name("shd1__old_x", &sib_ident);
        assert_eq!(orphan_db.len(), 63);
        assert_eq!(sibling_db.len(), 63);
        assert!(
            sibling_db.contains("__old_") && orphan_db.starts_with("shd1"),
            "fixture precondition: the sibling carries the marker over the orphan's shared prefix \
             (what the OLD loose check keyed on)"
        );
        assert!(
            !is_orphan_aside(&orphan_db, &sibling_db),
            "a LIVE sibling binding's derived PRIMARY must NEVER be classified as the orphan's aside \
             (it would be DROPped — silent data loss); this is the fix's core invariant"
        );
        // Same shape for the `__deleted_` and `__shadow_` markers (all three aside markers).
        assert!(!is_orphan_aside(
            &tenant_db_name("shd1", &sib_ident),
            &tenant_db_name("shd1__deleted_9", &sib_ident)
        ));
        assert!(!is_orphan_aside(
            &tenant_db_name("shd1", &sib_ident),
            &tenant_db_name("shd1__shadow_z", &sib_ident)
        ));

        // A live SIBLING binding's PRIMARY derived db (markerless, different base) — FOREIGN: the
        // guard must NEVER classify it as this orphan's own (force-clearing would clobber live data).
        assert!(!is_orphan_aside(base, "otherdb_proj_zz9y8x7w6v5u4t3s2r1q"));
        // A sibling binding's own ASIDE (marker + numeric suffix, but a DIFFERENT derived base) — FOREIGN.
        assert!(!is_orphan_aside(
            base,
            "otherdb_proj_zz9y8x7w__deleted_1794417073"
        ));
        // The primary itself (already dropped) is not an aside.
        assert!(!is_orphan_aside(base, base));
        // Marker present but empty distinguisher — not a valid aside.
        assert!(!is_orphan_aside(base, &format!("{base}__deleted_")));
        // Empty pre-marker (marker at the very start) — never this orphan's.
        assert!(!is_orphan_aside(base, "__deleted_1794417073"));
        // A non-numeric distinguisher (letters) is NOT a genuine aside suffix even if it would
        // reconstruct — the soundness guard that rejects the live-sibling tail above.
        assert!(!is_orphan_aside(base, &format!("{base}__deleted_abc123")));

        // ===== THE ALL-DECIMAL-DIGEST BYPASS (Security re-review FINDING 1) =====
        // `to_base36` ZERO-PADS every derived-name digest to a fixed 25 chars, so the digest CAN be
        // all decimal (e.g. `to_base36(5)` = 24 `0`s + `5`) — no letter to rely on. A live sibling
        // whose digest is all-decimal has a cap-collapse suffix that is entirely `[0-9_]`, so the
        // loose `[0-9_]*` guard this fix replaced would have PASSED it → unconditional `DROP DATABASE`
        // on a live sibling. Grinding SHA-256 to a real all-decimal digest in a test is ~2^46, so we
        // hand-craft the exact 63-byte name shape. Preconditions prove the suffix is all-numeric (the
        // old guard's blind spot) AND that a BARE reconstruction collapses onto the shared prefix and
        // MATCHES — so the suffix grammar is the SOLE thing standing between this live sibling and the
        // DROP.
        let orphan63 = "shd1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_1a2b3c4d5e6f7g8h9i0jq9z8y";
        let sibling_all_decimal = "shd1__old_000000000000000000000000000_1234567890123456789012345";
        assert_eq!(
            orphan63.len(),
            63,
            "fixture orphan must sit AT the 63-byte cap"
        );
        assert_eq!(
            sibling_all_decimal.len(),
            63,
            "fixture sibling must sit AT the 63-byte cap (body 37 + `_` + 25-char all-decimal digest)"
        );
        let adversarial_suffix = &sibling_all_decimal["shd1__old_".len()..];
        assert!(
            adversarial_suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'_'),
            "precondition: the recovered suffix is entirely [0-9_] — exactly what the loose guard accepted"
        );
        assert_eq!(
            bounded_aside_db_name(orphan63, "__old_", adversarial_suffix),
            sibling_all_decimal,
            "precondition: a BARE reconstruction collapses `base[..keep]` onto the shared `shd1` prefix \
             and MATCHES — reconstruction alone is fooled, so the suffix grammar is load-bearing"
        );
        assert!(
            !is_orphan_aside(orphan63, sibling_all_decimal),
            "a live sibling whose 25-char digest is ALL DECIMAL must STILL be rejected (re-review \
             FINDING 1): the 25-char digit run exceeds the genuine distinguisher field widths, so it \
             is not a genuine aside suffix"
        );
        // Direct guard-level checks: the fixed-width digest run always overflows the field bounds,
        // while every genuine distinguisher the generators emit is accepted.
        assert!(!is_genuine_aside_suffix("1234567890123456789012345")); // 25-digit digest, sole field
        assert!(!is_genuine_aside_suffix(
            "000000000000000000000000000_1234567890123456789012345"
        )); // trailing 25-digit digest
        assert!(is_genuine_aside_suffix("1794417073")); // now_unix_secs()
        assert!(is_genuine_aside_suffix("18446744073709551615")); // u64::MAX secs (20 digits)
        assert!(is_genuine_aside_suffix("1700000000000000000_4194967")); // <nanos>_<pid>
        assert!(is_genuine_aside_suffix("1700000000000000000_4294967295")); // pid = u32::MAX (10 digits)
        assert!(!is_genuine_aside_suffix("1700000000000000000_42949672950")); // pid 11 digits > u32 width
        assert!(!is_genuine_aside_suffix("123_456_789")); // two `_` — not a `<nanos>_<pid>` token
        assert!(!is_genuine_aside_suffix("")); // empty — no distinguisher
        assert!(!is_genuine_aside_suffix("abc123")); // letters — never a genuine suffix
        // FORWARD-INVARIANT PIN (audit informational #1): no current producer appends a numeric field
        // AFTER the 25-char digest, but if one ever did, the digest must not masquerade as the LEADING
        // `nanos` field with a short trailing field. Bounding `nanos` ≤ 20 (< 25) rejects it. This also
        // guards against regressing the `nanos` bound back to ≥ 25 (which would reopen the bypass).
        assert!(!is_genuine_aside_suffix("1234567890123456789012345_42")); // digest(25) _ shard(2)
        assert!(!is_genuine_aside_suffix("123456789012345678901_4")); // 21-digit leading field (> 20)
    }

    #[test]
    fn database_exists_error_is_recognized() {
        assert!(is_database_exists_error(&SqlError::Other(
            "database \"appdb_acme\" already exists".into()
        )));
        // A different error is NOT swallowed (fail closed).
        assert!(!is_database_exists_error(&SqlError::Other(
            "connection refused".into()
        )));
        assert!(!is_database_exists_error(&SqlError::Other(
            "role \"x\" already exists".into()
        )));
    }

    // ---- resolver seam: credential-key isolation (the #1 invariant) ------

    use async_trait::async_trait as _async_trait;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

    /// A reversible test "envelope" (NOT encryption) — proves sealing round-trips.
    struct RevEnvelope;
    #[_async_trait]
    impl KeyEnvelope for RevEnvelope {
        async fn wrap(&self, p: &[u8]) -> std::result::Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().rev().copied().collect())
        }
        async fn unwrap(&self, w: &[u8]) -> std::result::Result<Vec<u8>, EnvelopeError> {
            Ok(w.iter().rev().copied().collect())
        }
    }

    /// A no-op object store so a `DeployStore` can be built (KV-only paths are used).
    struct NullStorage;
    #[_async_trait]
    impl Storage for NullStorage {
        async fn get(&self, _: &str) -> std::result::Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> std::result::Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: ByteStream,
            _: PutMeta,
        ) -> std::result::Result<ObjectMeta, StorageError> {
            Err(StorageError::unsupported("null"))
        }
        async fn head(&self, _: &str) -> std::result::Result<ObjectMeta, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> std::result::Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> std::result::Result<Vec<ObjectMeta>, StorageError> {
            Ok(Vec::new())
        }
    }

    fn shared_binding() -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("appdb".into()),
            user: Some("super".into()),
            tenant: TenantIsolation::Shared,
            tenant_scope: TenantScope::Project,
            ..Default::default()
        }
    }

    fn build_resolver(
        binding: &ExternalDatabaseConfig,
    ) -> (Arc<dyn KvStore>, NodeTenantSqlResolver) {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
        let resolver = NodeTenantSqlResolver::new(deploy, kv.clone(), envelope, binding)
            .expect("compute-backed managed binding builds a resolver");
        (kv, resolver)
    }

    /// Resolving a **Shared** binding for two distinct tenants seals two DISTINCT
    /// per-tenant credentials — and NEITHER is the shared superuser credential. This
    /// is the credential half of "tenant A can never reach tenant B": each tenant's
    /// data-plane backend is built with its own sealed password under its own key.
    #[tokio::test]
    async fn shared_resolve_seals_isolated_per_tenant_credentials() {
        let binding = shared_binding();
        let (kv, resolver) = build_resolver(&binding);

        // No live DB: resolve builds the backend lazily but DOES seal the credential.
        let _ = resolver.build_backend("acme", "blog").await.unwrap();
        let _ = resolver.build_backend("globex", "shop").await.unwrap();

        let acme_ident = sanitize_ident("acme");
        let globex_ident = sanitize_ident("globex");
        let acme_key = format!(
            "managed-sql-cred/acme/{}",
            credential_workload_key("pg", &acme_ident)
        );
        let globex_key = format!(
            "managed-sql-cred/globex/{}",
            credential_workload_key("pg", &globex_ident)
        );
        let acme = kv.get(&acme_key).await.unwrap().expect("acme cred sealed");
        let globex = kv
            .get(&globex_key)
            .await
            .unwrap()
            .expect("globex cred sealed");
        // Two tenants ⇒ two independently-generated sealed credentials.
        assert_ne!(acme, globex, "cross-tenant credential reuse!");
        // The shared superuser credential key (bare workload, default project) is a
        // SEPARATE key that a tenant resolve never mints for a derived tenant.
        assert!(
            kv.get("managed-sql-cred/default/pg")
                .await
                .unwrap()
                .is_none(),
            "a derived tenant must not touch the superuser credential"
        );
    }

    /// The reserved **default** tenant on a Shared server reuses the plain server
    /// (superuser) credential — the single-tenant install is one ordinary database.
    #[tokio::test]
    async fn shared_default_tenant_uses_plain_superuser_credential() {
        let binding = shared_binding();
        let (kv, resolver) = build_resolver(&binding);
        let _ = resolver.build_backend("default", "blog").await.unwrap();
        // Sealed under the plain `<default>/<compute>` key (matches server-init env),
        // NOT a per-tenant `pg/<ident>` key.
        assert!(
            kv.get("managed-sql-cred/default/pg")
                .await
                .unwrap()
                .is_some()
        );
    }

    // ---- connection_parts: the managed-DB DSN composition path ------------

    fn single_pg_binding() -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("appdb".into()),
            user: Some("app".into()),
            tenant: TenantIsolation::Single,
            tenant_scope: TenantScope::Project,
            ..Default::default()
        }
    }

    /// A `Single`-project managed Postgres resolves to the right parts: host = the managed
    /// DB workload's internal-DNS name, the engine bridge port, the configured user +
    /// database, and a password that round-trips the sealed credential. The default tenant
    /// uses the bare `<compute>` workload.
    #[tokio::test]
    async fn connection_parts_single_pg_default_tenant() {
        let binding = single_pg_binding();
        let (kv, resolver) = build_resolver(&binding);
        let parts = resolver
            .connection_parts("default", "simertec", ConnRole::Runtime)
            .await
            .unwrap();
        assert_eq!(parts.kind, ExternalSqlKind::Postgres);
        assert_eq!(parts.host, "pg", "default tenant → bare compute workload");
        assert_eq!(parts.port, PG_BRIDGE_PORT);
        assert_eq!(parts.user, "app");
        assert_eq!(parts.database, "appdb");
        assert!(
            !parts.password.is_empty(),
            "the managed credential is unsealed"
        );
        // The DSN is a real postgres:// URL (scheme + host/port/db present).
        assert!(parts.dsn().starts_with("postgres://app:"));
        assert!(parts.dsn().ends_with("@pg:5432/appdb"));
        // The password round-trips the sealed credential (RevEnvelope reverses).
        let sealed = kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .expect("default managed credential sealed");
        let plain: String = sealed.iter().rev().map(|b| *b as char).collect();
        assert_eq!(plain, parts.password);
        // Single has NO owner/runtime split → the migration identity IS the runtime one.
        let mig = resolver
            .connection_parts("default", "simertec", ConnRole::Migration)
            .await
            .unwrap();
        assert_eq!(mig.user, parts.user);
        assert_eq!(mig.password, parts.password);
        assert_eq!(mig.dsn(), parts.dsn());
    }

    /// Tenancy: a non-default project resolves to its OWN per-tenant workload (host) and a
    /// DISTINCT sealed credential — a workload can never compose another tenant's DSN.
    #[tokio::test]
    async fn connection_parts_single_pg_is_tenant_isolated() {
        let binding = single_pg_binding();
        let (_kv, resolver) = build_resolver(&binding);
        let acme = resolver
            .connection_parts("acme", "simertec", ConnRole::Runtime)
            .await
            .unwrap();
        let globex = resolver
            .connection_parts("globex", "simertec", ConnRole::Runtime)
            .await
            .unwrap();
        // The host is the dedicated per-tenant workload's internal-DNS name
        // `pg-<sanitized-ident>` (the sanitizer appends a collision-resistant suffix, e.g.
        // `pg-acme_3f9c…` as in the docs) — distinct per tenant.
        assert!(
            acme.host.starts_with("pg-acme"),
            "non-default → dedicated per-tenant workload: {}",
            acme.host
        );
        assert!(globex.host.starts_with("pg-globex"), "{}", globex.host);
        assert_ne!(acme.host, globex.host, "distinct tenants ⇒ distinct hosts");
        assert_ne!(
            acme.password, globex.password,
            "distinct tenants ⇒ distinct per-tenant credentials"
        );
        assert_ne!(acme.dsn(), globex.dsn());
    }

    /// Bug D (Docker 29 SD registration), VERSION-INDEPENDENT: when the managed-DB `compute` is a
    /// derived `bramp-db-<25>` name (an auto-registered `database` declaration), a `Single`
    /// non-default tenant's workload is `bramp-db-<25>-<ident>_<25>` — OVER the 63-octet DNS-label
    /// cap Docker 29.9.1 enforces. The resolved DSN `host` MUST be the SHORT alias
    /// (`managed_db_alias` of that workload), a valid DNS label ≤ 63 octets, so a sibling can
    /// resolve it — AND it must equal the alias `boatramp-docker` publishes (both apply the same
    /// function to the same workload name). No docker daemon needed; this catches the regression on
    /// any host. The credential key still uses the full long workload (identity), unaffected.
    #[tokio::test]
    async fn connection_parts_host_is_a_dns_valid_alias_for_a_long_managed_db_workload() {
        use boatramp_core::compute::{DNS_LABEL_MAX_LEN, is_valid_dns_label};
        // `compute` = the real auto-registered derived managed-DB server name (`bramp-db-<25>`).
        let compute =
            boatramp_storage::tenant_provision::derived_managed_db_workload("acme", "orders");
        assert!(compute.starts_with("bramp-db-"));
        let binding = ExternalDatabaseConfig {
            compute: Some(compute.clone()),
            ..single_pg_binding()
        };
        let (_kv, resolver) = build_resolver(&binding);
        // Reconstruct the RAW workload name the DB launches under (= container identity) to prove
        // it really exceeds the DNS-label cap — the precondition for the bug.
        let raw_workload =
            tenant_names(TenantIsolation::Single, &compute, "appdb", "acme", false).workload;
        assert!(
            raw_workload.len() > DNS_LABEL_MAX_LEN,
            "fixture must reproduce the > 63-octet managed-DB workload (the bug): {} octets ({raw_workload})",
            raw_workload.len()
        );

        let parts = resolver
            .connection_parts("acme", "simertec", ConnRole::Runtime)
            .await
            .unwrap();
        // The DSN host is a valid DNS label (≤ 63) — NOT the raw > 63-octet workload name.
        assert!(
            is_valid_dns_label(&parts.host) && parts.host.len() <= DNS_LABEL_MAX_LEN,
            "DSN host must be a resolvable DNS label, got {:?} ({} octets)",
            parts.host,
            parts.host.len()
        );
        // And it is EXACTLY `managed_db_alias(workload)` — the string docker publishes as the alias.
        assert_eq!(
            parts.host,
            managed_db_alias(&raw_workload),
            "the DSN host and the published SD alias must be the identical string"
        );
        assert!(parts.dsn().contains(&format!("@{}:", parts.host)));
    }

    /// The MySQL analogue: `mysql://` scheme + the MySQL bridge port.
    #[tokio::test]
    async fn connection_parts_single_mysql() {
        let binding = ExternalDatabaseConfig {
            kind: "mysql".into(),
            ..single_pg_binding()
        };
        let (_kv, resolver) = build_resolver(&binding);
        let parts = resolver
            .connection_parts("acme", "simertec", ConnRole::Runtime)
            .await
            .unwrap();
        assert_eq!(parts.kind, ExternalSqlKind::Mysql);
        assert_eq!(parts.port, MYSQL_BRIDGE_PORT);
        assert!(parts.host.starts_with("pg-acme"), "{}", parts.host);
        assert!(parts.dsn().starts_with("mysql://app:"));
        assert!(parts.dsn().ends_with(":3306/appdb"));
    }

    /// `deprovision_project("acme")` tears down EXACTLY acme's derived tenant (its
    /// dedicated `Single` workload + sealed credential) and NEVER the reserved
    /// `default` tenant's — the default-project guard. Uses `Single` isolation so the
    /// teardown is observable without a live database: provisioning registers a
    /// compute workload + seals a credential, and deprovision must remove acme's while
    /// leaving default's (the single-tenant install) intact.
    #[tokio::test]
    async fn deprovision_project_targets_the_tenant_and_skips_default() {
        use boatramp_core::sql::TenantDeprovisioner as _;

        let binding = ExternalDatabaseConfig {
            tenant: TenantIsolation::Single,
            tenant_scope: TenantScope::Project,
            ..shared_binding()
        };
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

        // Provision two project tenants: the reserved `default` (single-tenant
        // install, plain names) and the derived `acme`.
        provision_tenant(&deploy, &kv, &envelope, &binding, "default", "")
            .await
            .unwrap();
        provision_tenant(&deploy, &kv, &envelope, &binding, "acme", "")
            .await
            .unwrap();

        let ident = sanitize_ident("acme");
        let acme_wl = format!("pg-{ident}"); // acme's dedicated Single workload
        let acme_cred = format!("managed-sql-cred/acme/pg-{ident}");
        let default_cred = "managed-sql-cred/default/pg"; // the install's own key

        // Preconditions: both tenants provisioned.
        assert!(
            deploy
                .get_compute_workload(ProjectRef::new("acme"), &acme_wl)
                .await
                .unwrap()
                .is_some()
        );
        assert!(kv.get(&acme_cred).await.unwrap().is_some());
        assert!(kv.get(default_cred).await.unwrap().is_some());

        let deprovisioner = NodeTenantDeprovisioner::new(
            deploy.clone(),
            kv.clone(),
            envelope.clone(),
            std::iter::once(("pg".to_string(), binding.clone())).collect(),
            // Grace is irrelevant for a Single tenant (always an immediate hard drop);
            // pass the default so the constructor signature is exercised.
            DEFAULT_DEPROVISION_GRACE_SECS,
        );

        // Deleting the `default` project is a no-op (the default-project guard) — the
        // single-tenant install must survive a stray delete.
        deprovisioner.deprovision_project("default").await;
        assert!(
            kv.get(default_cred).await.unwrap().is_some(),
            "default-project guard: the single-tenant install must never be dropped"
        );

        // Deleting `acme` tears down EXACTLY acme's workload + credential.
        deprovisioner.deprovision_project("acme").await;
        assert!(
            deploy
                .get_compute_workload(ProjectRef::new("acme"), &acme_wl)
                .await
                .unwrap()
                .is_none(),
            "acme's dedicated Single workload must be gone"
        );
        assert!(
            kv.get(&acme_cred).await.unwrap().is_none(),
            "acme's sealed credential must be gone"
        );
        // …and the default install is STILL untouched by the acme delete.
        assert!(
            kv.get(default_cred).await.unwrap().is_some(),
            "acme delete must not touch the default install's credential"
        );
    }

    /// THE OWNERSHIP-ACCOUNTING FIX (gap 1): the deprovisioner tears down a project's OWN DECLARED
    /// managed database (the declarative front door / `project sync` path, stored under
    /// `project/<proj>/database/<name>`) even when the NODE-STATIC map is EMPTY. A `Single`
    /// declaration makes the teardown observable without a live database (a workload + sealed
    /// credential). MUTATION: before the fix, `deprovision_scope` walked ONLY `self.databases`, so an
    /// empty static map enumerated nothing and the declared tenant's workload + credential were
    /// orphaned on `project rm` (the construens "owns nothing" shape).
    #[tokio::test]
    async fn deprovision_enumerates_project_declared_databases() {
        use boatramp_core::sql::TenantDeprovisioner as _;

        // A project-DECLARED Single managed DB — NOT in the node-static map.
        let db: boatramp_core::compute::ApplyDatabase = serde_json::from_value(serde_json::json!({
            "name": "orphanapp",
            "kind": "postgres",
            "tenant": "single",
            "tenant_scope": "project",
        }))
        .expect("minimal ApplyDatabase");
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

        // Persist the declaration + provision via the SAME lowered binding the declare/sync path uses.
        deploy
            .set_project_database(ProjectRef::new("acme"), &db)
            .await
            .unwrap();
        let binding = crate::managed_db_declare::lower("acme", &db);
        provision_tenant(&deploy, &kv, &envelope, &binding, "acme", "")
            .await
            .unwrap();

        // The derived Single workload + its sealed credential now exist.
        let ident = sanitize_ident("acme");
        let compute = crate::managed_db_declare::derived_workload("acme", "orphanapp");
        let wl = format!("{compute}-{ident}");
        let cred = format!("managed-sql-cred/acme/{compute}-{ident}");
        assert!(
            deploy
                .get_compute_workload(ProjectRef::new("acme"), &wl)
                .await
                .unwrap()
                .is_some(),
            "precondition: the declared Single workload is registered"
        );
        assert!(kv.get(&cred).await.unwrap().is_some());

        // The deprovisioner has an EMPTY node-static map — it must STILL find + tear down the
        // project-declared database by enumerating the project's own declarations.
        let deprovisioner = NodeTenantDeprovisioner::new(
            deploy.clone(),
            kv.clone(),
            envelope.clone(),
            std::collections::BTreeMap::new(), // EMPTY node-static map
            DEFAULT_DEPROVISION_GRACE_SECS,
        );
        deprovisioner.deprovision_project("acme").await;

        assert!(
            deploy
                .get_compute_workload(ProjectRef::new("acme"), &wl)
                .await
                .unwrap()
                .is_none(),
            "the project-declared Single workload must be torn down even with an EMPTY static map"
        );
        assert!(
            kv.get(&cred).await.unwrap().is_none(),
            "the project-declared tenant's sealed credential must be gone"
        );
    }

    /// An operator-set per-binding `startup_grace_secs` flows into the spec
    /// `provision_single` stores (overriding the engine default), and it matches the
    /// same override the shared `auto_register` path applies — the two managed
    /// registration paths build the byte-identical (content-addressed) spec.
    #[tokio::test]
    async fn single_startup_grace_override_flows_into_the_stored_spec() {
        let binding = ExternalDatabaseConfig {
            tenant: TenantIsolation::Single,
            tenant_scope: TenantScope::Project,
            startup_grace_secs: Some(77),
            ..shared_binding()
        };
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

        // Provision the reserved default tenant (bare `pg` workload under DEFAULT).
        provision_tenant(&deploy, &kv, &envelope, &binding, "default", "")
            .await
            .unwrap();

        let wl = deploy
            .get_compute_workload(ProjectRef::DEFAULT, "pg")
            .await
            .unwrap()
            .expect("default Single workload registered");
        let stored = deploy
            .get_compute_spec(&wl.active)
            .await
            .unwrap()
            .expect("active spec stored");
        assert_eq!(
            stored.startup_grace_secs, 77,
            "the operator grace overrides the engine default in the stored spec"
        );

        // The stored spec equals `managed_db_spec(...)` + the same grace override the
        // shared auto-register path applies — proving both paths are byte-identical
        // (the default tenant keeps the base volume name, so no per-tenant divergence).
        let mut expected =
            managed_db_spec(ManagedDbEngine::Postgres, None, DEFAULT_VOLUME_MIB, false);
        expected.startup_grace_secs = binding.startup_grace_secs.unwrap();
        assert_eq!(
            stored.id(),
            expected.id(),
            "both managed-registration paths build the identical content-addressed spec"
        );
    }

    /// A **Single** binding's default tenant seals its credential under the bare
    /// workload key (the server-init key), and a derived tenant seals under its own
    /// per-tenant workload key — never the same key.
    #[tokio::test]
    async fn single_resolve_keys_default_and_derived_distinctly() {
        let binding = ExternalDatabaseConfig {
            tenant: TenantIsolation::Single,
            ..shared_binding()
        };
        let (kv, resolver) = build_resolver(&binding);
        let _ = resolver.build_backend("default", "blog").await.unwrap();
        let _ = resolver.build_backend("acme", "blog").await.unwrap();

        // Default: bare `<default>/pg` (the server-init key of a single-tenant install).
        assert!(
            kv.get("managed-sql-cred/default/pg")
                .await
                .unwrap()
                .is_some()
        );
        // Derived: `<project>/<compute>-<ident>` (the per-tenant container's own key).
        let ident = sanitize_ident("acme");
        assert!(
            kv.get(&format!("managed-sql-cred/acme/pg-{ident}"))
                .await
                .unwrap()
                .is_some()
        );
    }

    // ---- safe (soft) deprovision: the engine/cell split ------------------

    fn mysql_shared_binding() -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: "mysql".into(),
            ..shared_binding()
        }
    }

    fn single_binding() -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            tenant: TenantIsolation::Single,
            ..shared_binding()
        }
    }

    /// **Shared + Postgres** with a positive grace is the ONE recoverable cell: the
    /// plan is a *soft* delete — it emits the RENAME-aside + NOLOGIN DDL (never DROP)
    /// and carries a tombstone whose `delete_after = now + grace`. This is the emitted
    /// SQL the deprovision path would run.
    #[test]
    fn plan_shared_postgres_soft_deletes_renames_not_drops() {
        let binding = shared_binding();
        let now = 1_700_000_000;
        let grace = DEFAULT_DEPROVISION_GRACE_SECS;
        let plan = plan_deprovision(&binding, "acme", "", grace, now).expect("a plan");
        let DeprovisionPlan::SharedSoftPostgres { ddl, tombstone } = plan else {
            panic!("Shared+Postgres+grace>0 must be a soft delete, got {plan:?}");
        };
        let joined = ddl.join("\n");
        // Soft: rename aside + disable login; NEVER a DROP.
        assert!(joined.contains("ALTER DATABASE"), "must RENAME:\n{joined}");
        assert!(joined.contains("RENAME TO"), "must RENAME aside:\n{joined}");
        assert!(
            joined.contains("NOLOGIN"),
            "must disable the role:\n{joined}"
        );
        assert!(
            joined.contains("pg_terminate_backend"),
            "must evict sessions"
        );
        assert!(
            !joined.to_ascii_uppercase().contains("DROP DATABASE"),
            "soft delete must NOT drop the database:\n{joined}"
        );
        assert!(!joined.to_ascii_uppercase().contains("DROP ROLE"));
        // Tombstone: recoverable window + the identity a reaper/recovery needs.
        assert_eq!(tombstone.delete_after, now + grace);
        assert_eq!(tombstone.deleted_at, now);
        assert_eq!(tombstone.project, "acme");
        assert_eq!(tombstone.engine, "postgres");
        assert_eq!(tombstone.compute, "pg");
        assert_eq!(tombstone.superuser, "super");
        // The renamed name carries the timestamp distinguisher, is BOUNDED to Postgres's 63-byte
        // identifier limit (a long tenant db has its PREFIX truncated, never the `__deleted_<ts>`
        // tail — the fix for the overflow→truncate→collapse-to-live bug), and is DISTINCT from the
        // original (it never collapses back to it, so the RENAME can't rename the db to itself).
        assert!(tombstone.renamed_db.ends_with(&format!("__deleted_{now}")));
        assert!(
            tombstone.renamed_db.len() <= 63,
            "aside name must fit NAMEDATALEN (≤63 bytes), got {} bytes: {}",
            tombstone.renamed_db.len(),
            tombstone.renamed_db
        );
        assert_ne!(
            tombstone.renamed_db, tombstone.original_db,
            "the aside name must never collapse back to the live name"
        );
        // The RENAME target in the DDL is exactly the tombstone's renamed name.
        assert!(joined.contains(&tombstone.renamed_db));
    }

    /// The freed original name can't alias the renamed-aside data: the DDL renames the
    /// original away (so a same-named re-create is a fresh, distinct database) and the
    /// renamed name is timestamp-unique, distinct from the original.
    #[test]
    fn soft_delete_frees_original_name_without_aliasing() {
        let binding = shared_binding();
        let now = 1_700_000_000;
        let plan = plan_deprovision(&binding, "acme", "", 60, now).expect("a plan");
        let DeprovisionPlan::SharedSoftPostgres { ddl, tombstone } = plan else {
            panic!("expected a soft delete");
        };
        // Original ≠ renamed (the data moved aside), and the original name is now free.
        assert_ne!(tombstone.original_db, tombstone.renamed_db);
        let joined = ddl.join("\n");
        // The RENAME's *source* is the original name (it is vacated), its *target* is
        // the timestamped aside name — so nothing keeps living under the original name.
        assert!(joined.contains(&format!("RENAME TO \"{}\"", tombstone.renamed_db)));
    }

    /// **Shared + MySQL** keeps the IMMEDIATE hard delete — MySQL can't rename a
    /// database, so a soft-aside would collide/leak on a same-name re-create. The plan
    /// emits `DROP DATABASE`/`DROP USER`, no tombstone.
    #[test]
    fn plan_shared_mysql_hard_drops_immediately() {
        let binding = mysql_shared_binding();
        let plan = plan_deprovision(&binding, "acme", "", DEFAULT_DEPROVISION_GRACE_SECS, 0)
            .expect("a plan");
        let DeprovisionPlan::SharedImmediate { ddl, kind, .. } = plan else {
            panic!("Shared+MySQL must be an immediate drop, got {plan:?}");
        };
        assert_eq!(kind, ExternalSqlKind::Mysql);
        let joined = ddl.join("\n");
        assert!(
            joined.contains("DROP DATABASE IF EXISTS"),
            "MySQL must hard-drop:\n{joined}"
        );
        assert!(joined.contains("DROP USER IF EXISTS"));
        assert!(!joined.contains("RENAME TO"), "MySQL must NOT soft-rename");
    }

    /// **Single** (any engine) keeps the IMMEDIATE drop — its unit is a whole
    /// container/volume. The plan is `SingleDrop` (workload + credential), regardless
    /// of grace.
    #[test]
    fn plan_single_drops_the_workload_immediately() {
        let binding = single_binding();
        let plan = plan_deprovision(&binding, "acme", "", DEFAULT_DEPROVISION_GRACE_SECS, 0)
            .expect("a plan");
        let ident = sanitize_ident("acme");
        assert_eq!(
            plan,
            DeprovisionPlan::SingleDrop {
                workload: format!("pg-{ident}")
            }
        );
    }

    /// A grace of `0` disables the soft path even for Shared + Postgres — the operator
    /// opted back into the immediate, irreversible hard drop.
    #[test]
    fn plan_grace_zero_takes_the_immediate_path_for_shared_postgres() {
        let binding = shared_binding();
        let plan = plan_deprovision(&binding, "acme", "", 0, 1_700_000_000).expect("a plan");
        let DeprovisionPlan::SharedImmediate { ddl, kind, .. } = plan else {
            panic!("grace=0 must be an immediate drop, got {plan:?}");
        };
        assert_eq!(kind, ExternalSqlKind::Postgres);
        let joined = ddl.join("\n");
        assert!(
            joined.contains("DROP DATABASE IF EXISTS"),
            "grace=0 must hard-drop:\n{joined}"
        );
        assert!(
            !joined.contains("RENAME TO"),
            "grace=0 must NOT soft-rename"
        );
    }

    /// The reserved default tenant and a bring-your-own binding yield no plan (the
    /// single-tenant install is never torn down; a `url_env` binding isn't ours).
    #[test]
    fn plan_skips_default_tenant_and_bring_your_own() {
        // Default project ⇒ no plan.
        assert!(plan_deprovision(&shared_binding(), "default", "", 60, 0).is_none());
        // Bring-your-own (no compute) ⇒ no plan.
        let byo = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: None,
            url_env: "PG_URL".into(),
            ..Default::default()
        };
        assert!(plan_deprovision(&byo, "acme", "", 60, 0).is_none());
    }

    /// The reaper selects only tombstones whose grace window has elapsed
    /// (`delete_after <= now`), with an injected fixed `now`.
    #[test]
    fn reaper_selects_only_due_tombstones() {
        let mk = |renamed: &str, delete_after: u64| Tombstone {
            version: 1,
            project: "acme".into(),
            renamed_db: renamed.into(),
            original_db: "appdb_acme".into(),
            role: "appdb_acme_role".into(),
            engine: "postgres".into(),
            compute: "pg".into(),
            superuser: "super".into(),
            cred_workload: "pg/x".into(),
            deleted_at: 0,
            delete_after,
        };
        let now = 1_000;
        let past = mk("db__deleted_1", now - 1); // due (before now)
        let exact = mk("db__deleted_2", now); // due (== now)
        let future = mk("db__deleted_3", now + 1); // NOT due (after now)

        let due = due_tombstones(vec![past.clone(), exact.clone(), future.clone()], now);
        assert!(due.contains(&past), "an elapsed tombstone is due");
        assert!(due.contains(&exact), "delete_after == now is due");
        assert!(
            !due.contains(&future),
            "a tombstone still inside its grace window must NOT be reaped"
        );
        assert_eq!(due.len(), 2);
    }

    /// End-to-end recover selection: a soft-delete writes a tombstone; `recover_tenant`
    /// on an ABSENT tombstone is a harmless no-op (`Ok(false)`), and the reverse DDL a
    /// present tombstone would run is the RENAME-back + LOGIN (asserted at the pure DDL
    /// builder). This exercises the recover fn's lookup + no-op path without a live DB.
    #[tokio::test]
    async fn recover_absent_tombstone_is_a_noop() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
        let recovered = recover_tenant(&deploy, &kv, &envelope, "acme", "nope__deleted_1")
            .await
            .unwrap();
        assert!(!recovered, "recovering an absent tombstone is a no-op");

        // The reverse DDL a present tombstone would emit: RENAME back + LOGIN, in order.
        let ddl = recover_soft_deprovision_ddl("appdb__deleted_1", "appdb", "appdb_role");
        assert!(ddl[0].contains("RENAME TO \"appdb\""), "renames back");
        assert!(ddl[1].contains("LOGIN") && !ddl[1].contains("NOLOGIN"));
    }

    // ---- serve_as posture: serving-role selection + the owner-serving ⟺ FORCE guard --------

    /// A Shared, project-scoped, `rls_session` Postgres binding with an explicit serving posture.
    fn shared_rls_binding(serve_as: ServeAs) -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("appdb".into()),
            user: Some("super".into()),
            tenant: TenantIsolation::Shared,
            tenant_scope: TenantScope::Project,
            rls_session: true,
            serve_as,
            ..Default::default()
        }
    }

    /// `install_force_rls` truth table: FORCE is installed IFF `rls_session` + owner posture +
    /// Postgres. The default (non-owner) posture installs none (the runtime role `ENABLE` binds).
    #[test]
    fn install_force_rls_only_for_owner_posture_postgres() {
        use ExternalSqlKind::{Mysql, Postgres};
        assert!(install_force_rls(true, ServeAs::Owner, Postgres));
        assert!(
            !install_force_rls(true, ServeAs::NonOwner, Postgres),
            "non-owner posture installs NO FORCE"
        );
        assert!(
            !install_force_rls(false, ServeAs::Owner, Postgres),
            "no rls_session ⇒ no FORCE"
        );
        assert!(
            !install_force_rls(true, ServeAs::Owner, Mysql),
            "MySQL has no row-level security / FORCE"
        );
    }

    /// The shared owner-serving tenancy-invariant predicate — the GUARD both serving paths call.
    /// THE MUTATION arm: an owner serving identity under a NON-owner posture (⇒ FORCE was NOT
    /// installed) ⇒ REFUSE (fail-closed); under the owner posture (⇒ FORCE installed) ⇒ permitted;
    /// the default non-owner runtime identity never trips it; every off-cell is out of scope.
    #[test]
    fn owner_serving_without_force_guard_decision() {
        let k = ExternalSqlKind::Postgres;
        let owner = "appdb_acme_owner";
        let runtime = "appdb_acme_role";
        // MUTATION — serving AS the owner while the binding is NON-owner posture ⇒ no FORCE ⇒ REFUSE.
        assert!(
            owner_serving_without_force(
                true,
                k,
                TenantIsolation::Shared,
                false,
                owner,
                owner,
                ServeAs::NonOwner
            ),
            "owner-serving without the FORCE-installing posture must be refused (fail-closed)"
        );
        // Owner posture (⇒ FORCE installed at provision) ⇒ owner-serving is PERMITTED.
        assert!(!owner_serving_without_force(
            true,
            k,
            TenantIsolation::Shared,
            false,
            owner,
            owner,
            ServeAs::Owner
        ));
        // The default non-owner RUNTIME identity never trips the guard (any posture).
        assert!(!owner_serving_without_force(
            true,
            k,
            TenantIsolation::Shared,
            false,
            runtime,
            owner,
            ServeAs::NonOwner
        ));
        // Off-cell: no rls_session / the default tenant / Single / MySQL are all out of scope.
        assert!(!owner_serving_without_force(
            false,
            k,
            TenantIsolation::Shared,
            false,
            owner,
            owner,
            ServeAs::NonOwner
        ));
        assert!(!owner_serving_without_force(
            true,
            k,
            TenantIsolation::Shared,
            true,
            owner,
            owner,
            ServeAs::NonOwner
        ));
        assert!(!owner_serving_without_force(
            true,
            k,
            TenantIsolation::Single,
            false,
            owner,
            owner,
            ServeAs::NonOwner
        ));
        assert!(!owner_serving_without_force(
            true,
            ExternalSqlKind::Mysql,
            TenantIsolation::Shared,
            false,
            owner,
            owner,
            ServeAs::NonOwner
        ));
    }

    /// `serve_as: non-owner` (the default) — BOTH the sibling-DSN `Runtime` identity and the handler
    /// path serve the per-tenant NON-OWNER runtime `_role` (ENABLE binds it; the guard never trips).
    #[tokio::test]
    async fn serve_as_non_owner_serves_the_runtime_role() {
        let binding = shared_rls_binding(ServeAs::NonOwner);
        let (_kv, resolver) = build_resolver(&binding);
        let ident = sanitize_ident("acme");
        let parts = resolver
            .connection_parts("acme", "web", ConnRole::Runtime)
            .await
            .unwrap();
        assert_eq!(
            parts.user,
            tenant_role_name("pg", &ident),
            "non-owner posture serves the runtime _role"
        );
        assert_ne!(parts.user, tenant_owner_role_name("pg", &ident));
        // The handler path agrees + is permitted (no guard trip under non-owner posture).
        resolver
            .build_backend("acme", "web")
            .await
            .expect("non-owner serving is permitted");
    }

    /// `serve_as: owner` — BOTH paths serve the per-tenant OWNER role, sealed under the OWNER
    /// credential key, and the guard PERMITS it (owner posture ⇒ provision installs FORCE). This is
    /// the end of the posture wiring: the same owner the Phase-2 operate-as-owner dynamic role acts as.
    #[tokio::test]
    async fn serve_as_owner_serves_the_owner_role_and_is_permitted() {
        let binding = shared_rls_binding(ServeAs::Owner);
        let (kv, resolver) = build_resolver(&binding);
        let ident = sanitize_ident("acme");
        let parts = resolver
            .connection_parts("acme", "web", ConnRole::Runtime)
            .await
            .unwrap();
        assert_eq!(
            parts.user,
            tenant_owner_role_name("pg", &ident),
            "owner posture serves the _owner role"
        );
        // The serving credential is the sealed OWNER credential (`…/owner`), not the runtime-role key.
        let owner_key = format!(
            "managed-sql-cred/acme/{}",
            owner_credential_workload_key("pg", &ident)
        );
        assert!(
            kv.get(&owner_key).await.unwrap().is_some(),
            "owner posture seals + serves the owner credential"
        );
        // The handler path serves the owner too and is PERMITTED (the guard allows under this posture).
        resolver
            .build_backend("acme", "web")
            .await
            .expect("owner serving is permitted under serve_as: owner");
    }
}
