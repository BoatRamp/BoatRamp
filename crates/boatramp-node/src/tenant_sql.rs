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
    managed_db_spec, ComputeWorkload, ManagedDbEngine, PlacementConstraints,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::{ProjectRef, DEFAULT_PROJECT};
use boatramp_core::sql::{SqlBackend, SqlError};
use boatramp_storage::sql_compute::{
    ComputeEndpointResolver, ComputeResolvedSqlBackend, SESSION_KEY_PROJECT, SESSION_KEY_SITE,
};
use boatramp_storage::sql_sqlx::PerTenantSqlResolver;
use boatramp_storage::tenant_provision::{
    grant_app_role_ddl, provision_ddl, recover_soft_deprovision_ddl, sanitize_ident,
    soft_deprovision_ddl, tenant_db_name, tenant_role_name,
};
use boatramp_storage::ExternalSqlKind;

use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
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
fn maintenance_database(kind: ExternalSqlKind) -> &'static str {
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
            provision_shared(deploy, &creds, kind, compute, user, project, &names, &ident).await
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

    // Connect to the MAINTENANCE database as the superuser (CREATE DATABASE cannot run
    // inside the database being created). Reuses the same endpoint-resolving backend
    // the handler path uses, so it follows the server across restarts.
    let resolver = Arc::new(DeployEndpointResolver::new(deploy.clone(), DEFAULT_PROJECT));
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
    for stmt in provision_ddl(kind, &names.database, &names.role, &tenant_pw) {
        if let Err(e) = admin.run_script(&stmt).await {
            let is_create_database = stmt.to_ascii_uppercase().contains("CREATE DATABASE");
            if is_create_database && is_database_exists_error(&e) {
                continue;
            }
            return Err(format!("provision {}: {e}", names.database));
        }
    }

    // Grant the tenant's non-superuser login role the everyday app privileges on the
    // objects in its OWN database (Postgres `Shared` only — the schema is loaded by the
    // superuser, so without this the role can't touch its tables; `grant_app_role_ddl`
    // is empty for MySQL, whose `db.*` grant already covers it). Runs INSIDE the tenant
    // database — schema grants + `ALTER DEFAULT PRIVILEGES` are database-local, so this
    // needs its own connection (the loop above is on the maintenance database). The
    // superuser reaches the locked-down database because superusers bypass the
    // `CONNECT` gate. Idempotent, so a re-provision (incl. the lazy per-resolve one that
    // heals a tenant provisioned by an older version) is safe.
    let grants = grant_app_role_ddl(kind, &names.role, superuser);
    if !grants.is_empty() {
        let tenant_resolver =
            Arc::new(DeployEndpointResolver::new(deploy.clone(), DEFAULT_PROJECT));
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
        for stmt in grants {
            tenant_admin
                .run_script(&stmt)
                .await
                .map_err(|e| format!("grant app role on {}: {e}", names.database))?;
        }
    }
    Ok(())
}

/// Whether a SQL error is a benign "database already exists" (Postgres SQLSTATE
/// 42P04, surfaced in the message by sqlx). Treated as success on the idempotent
/// `CREATE DATABASE` per the [`provision_ddl`] contract.
fn is_database_exists_error(err: &SqlError) -> bool {
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
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, compute)
        .await
        .map_err(|e| format!("superuser credential ({compute}): {e}"))?;
    let resolver = Arc::new(DeployEndpointResolver::new(deploy.clone(), DEFAULT_PROJECT));
    Ok(ComputeResolvedSqlBackend::new(
        resolver,
        compute,
        kind,
        maintenance_database(kind),
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
            let renamed_db = format!("{}__deleted_{now}", names.database);
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
    async fn deprovision_scope(&self, scope: TenantScope, project: &str, site: &str) {
        if project == DEFAULT_PROJECT {
            // The reserved default project is the single-tenant install; its managed
            // database IS the install. A stray delete must never drop it.
            return;
        }
        for (name, _kind, binding) in managed_bindings(&self.databases) {
            // Only our managed-credential bindings on this delete's axis. A
            // bring-your-own binding is filtered out by `managed_bindings` already;
            // a `password_env` (operator-supplied credential) binding is left alone.
            if !binding.is_managed_credential() || binding.tenant_scope != scope {
                continue;
            }
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
    pool_max: Option<u32>,
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
            pool_max: binding.pool_max,
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

impl NodeTenantSqlResolver {
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
                    let ident = sanitize_ident(&tenant_ident_raw);
                    (
                        project.to_string(),
                        credential_workload_key(&self.compute, &ident),
                        names.role.clone(),
                    )
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
        let resolver: Arc<dyn ComputeEndpointResolver> = Arc::new(DeployEndpointResolver::new(
            self.deploy.clone(),
            endpoint_project,
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
        );
        if self.rls_session {
            backend = backend.with_session_context(vec![
                (SESSION_KEY_PROJECT, project.to_string()),
                (SESSION_KEY_SITE, site.to_string()),
            ]);
        }
        Ok(Arc::new(backend))
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
        assert!(kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .is_some());
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
        assert!(deploy
            .get_compute_workload(ProjectRef::new("acme"), &acme_wl)
            .await
            .unwrap()
            .is_some());
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
        let mut expected = managed_db_spec(ManagedDbEngine::Postgres, None, DEFAULT_VOLUME_MIB);
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
        assert!(kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .is_some());
        // Derived: `<project>/<compute>-<ident>` (the per-tenant container's own key).
        let ident = sanitize_ident("acme");
        assert!(kv
            .get(&format!("managed-sql-cred/acme/pg-{ident}"))
            .await
            .unwrap()
            .is_some());
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
        // The renamed name carries the timestamp; the original is recorded for recovery.
        assert!(tombstone.renamed_db.ends_with(&format!("__deleted_{now}")));
        assert!(tombstone.renamed_db.starts_with(&tombstone.original_db));
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
}
