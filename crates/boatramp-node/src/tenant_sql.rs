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
    provision_ddl, sanitize_ident, tenant_db_name, tenant_role_name,
};
use boatramp_storage::ExternalSqlKind;

use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use crate::managed_sql::{DeployEndpointResolver, ManagedSqlCredentials};

/// 10 GiB — the default managed data-volume size when a `Single`-mode per-tenant
/// binding sets none (matches [`auto_register_managed_db_workloads`]).
const DEFAULT_VOLUME_MIB: u32 = 10 * 1024;

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
fn tenant_names(
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
fn credential_workload_key(compute: &str, tenant_ident: &str) -> String {
    format!("{compute}/{tenant_ident}")
}

/// The KV **project** segment for a `Single`-mode workload's sealed credential: the
/// reserved default project for the single-tenant install (matching the bare
/// `<compute>` server-init key), else the tenant's own project (matching the
/// per-tenant workload `<compute>-<ident>` under that project). Kept beside
/// [`credential_workload_key`] so the provision + resolve + env-injector paths
/// derive the identical key.
fn single_credential_project(project: &str, is_default: bool) -> String {
    if is_default {
        DEFAULT_PROJECT.to_string()
    } else {
        project.to_string()
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
    let spec = managed_db_spec(
        engine_of(kind),
        binding.image.as_deref(),
        binding.volume_size_mib.unwrap_or(DEFAULT_VOLUME_MIB),
    );
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
        superuser_pw,
        Some(1),
        false,
        Some(Duration::from_secs(10)),
    );

    // Run each statement; a Postgres "database already exists" on the bare
    // CREATE DATABASE is the caller's documented OK-to-ignore (idempotency).
    for stmt in provision_ddl(kind, &names.database, &names.role, &tenant_pw) {
        if let Err(e) = admin.run_script(&stmt).await {
            if is_database_exists_error(&e) {
                continue;
            }
            return Err(format!("provision {}: {e}", names.database));
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

/// Tear down one compute-backed managed binding for the tenant `(project, site)`.
///
/// - **Shared** — connect as the superuser and run
///   [`deprovision_ddl`](boatramp_storage::tenant_provision::deprovision_ddl)
///   (`DROP DATABASE/ROLE IF EXISTS`), then delete the tenant's sealed credential.
/// - **Single** — delete the tenant's dedicated compute workload (the reconcile
///   tears down its container) and its sealed credential.
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
) -> Result<(), String> {
    let Some(compute) = binding.compute.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(());
    };
    let Some(kind) = ExternalSqlKind::parse(&binding.kind) else {
        return Ok(());
    };
    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, site);
    if is_default {
        return Ok(()); // never tear down the single-tenant install.
    }
    let database = binding.database.as_deref().unwrap_or_default();
    let user = binding.user.as_deref().unwrap_or_default();
    let ident = sanitize_ident(&tenant_ident_raw);
    let names = tenant_names(binding.tenant, compute, database, &tenant_ident_raw, false);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    match binding.tenant {
        TenantIsolation::Single => {
            deploy
                .delete_compute_workload(ProjectRef::new(project), &names.workload)
                .await
                .map_err(|e| format!("delete workload {}: {e}", names.workload))?;
            // The Single credential is keyed by the workload's own `(project, workload)`
            // (matching provision + the server-init env injector) — the bare derived
            // workload name under the tenant's project, no `credential_workload_key`.
            creds
                .delete(project, &names.workload)
                .await
                .map_err(|e| format!("delete credential {}: {e}", names.workload))?;
        }
        TenantIsolation::Shared => {
            let superuser_pw = creds
                .password(DEFAULT_PROJECT, compute)
                .await
                .map_err(|e| format!("superuser credential ({compute}): {e}"))?;
            let resolver = Arc::new(DeployEndpointResolver::new(deploy.clone(), DEFAULT_PROJECT));
            let admin = ComputeResolvedSqlBackend::new(
                resolver,
                compute,
                kind,
                maintenance_database(kind),
                user,
                superuser_pw,
                Some(1),
                false,
                Some(Duration::from_secs(10)),
            );
            for stmt in boatramp_storage::tenant_provision::deprovision_ddl(
                kind,
                &names.database,
                &names.role,
            ) {
                admin
                    .run_script(&stmt)
                    .await
                    .map_err(|e| format!("deprovision {}: {e}", names.database))?;
            }
            let cred_workload = credential_workload_key(compute, &ident);
            creds
                .delete(project, &cred_workload)
                .await
                .map_err(|e| format!("delete credential {}: {e}", names.role))?;
        }
    }
    Ok(())
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
        let _ = resolver.resolve("acme", "blog").await.unwrap();
        let _ = resolver.resolve("globex", "shop").await.unwrap();

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
        let _ = resolver.resolve("default", "blog").await.unwrap();
        // Sealed under the plain `<default>/<compute>` key (matches server-init env),
        // NOT a per-tenant `pg/<ident>` key.
        assert!(kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .is_some());
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
        let _ = resolver.resolve("default", "blog").await.unwrap();
        let _ = resolver.resolve("acme", "blog").await.unwrap();

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
}
