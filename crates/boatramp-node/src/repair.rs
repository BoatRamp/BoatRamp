//! Provisioning **drift-repair / reconcile** for a managed shared-Postgres tenant
//! (PLAN-provisioning-drift-repair, #491).
//!
//! An owner-gated (`Project·Admin`, audited), **idempotent**, **data-preserving**
//! `repair` verb that diffs a managed tenant's ACTUAL provisioning against what a fresh
//! provision of the same binding would produce and **converges the delta** — never
//! `DROP`/`TRUNCATE`/`DELETE`/`UPDATE` of tenant rows, only roles / ownership / grants /
//! sealed credentials / ledger scaffolding.
//!
//! The first drift class it subsumes is the **pre-v0.4.25 owner-model retrofit**: an
//! older-model shared tenant whose physical database is owned by the *runtime* role,
//! with **no `_owner` role**, so the migrate surface (which connects as the sealed owner
//! role) is denied. `repair --apply` creates + seals the owner role, re-owns the db and
//! its objects to it, and scaffolds the ledger — so `boatramp project migrate` then
//! works, WITHOUT touching a single tenant row.
//!
//! # The model — drift-detect → probe → verdict → converge → re-probe
//!
//! Each check is `(probe, verdict, converge-DDL)`. A **dry-run** runs probes + reports
//! verdicts + the DDL it WOULD run, changing nothing (no DDL, no KV write, no seal). An
//! **apply** runs the converge DDL on a drifted check, re-probes, and reports `repaired`.
//! Every check is independent + fail-closed: a probe that can't be resolved is a per-check
//! `error`, and the rest still run.
//!
//! # Security invariants (the panel conditions)
//!
//! - **Derived-names-only.** Every db / runtime-role / owner-role name comes ONLY from
//!   [`tenant_provision`](boatramp_storage::tenant_provision) derivation over the
//!   ALREADY-VALIDATED `(project, db-binding)`, never from operator input or a probe
//!   result. A probe result is used solely as an `==` verdict; the emitted
//!   `REASSIGN OWNED` / `ALTER … OWNER TO` always names the DERIVED role even if a probe
//!   returned `postgres` or a shared role.
//! - **Superuser precondition.** The privileged checks (object re-ownership) assert the
//!   maintenance identity is superuser first; if not, they report a terminal, loud
//!   `error` — never a `GRANT <role> TO <maint>` membership workaround.
//! - **Connection routing.** `ALTER DATABASE … OWNER` runs on the MAINTENANCE db; object
//!   re-ownership + ledger re-own run CONNECTED TO THE TENANT'S OWN db, guarded by a
//!   `current_database()` == derived-db assertion before any `REASSIGN OWNED` fires.
//! - **Soft-delete exclusion.** Every probe keys on the EXACT derived live name (`==`,
//!   never `LIKE`/prefix) and skips any `<db>__deleted_<ts>` sibling / `NOLOGIN` role; if
//!   only a soft-deleted sibling exists the run is a no-op.
//! - **Dry-run purity.** A dry-run runs only read-only probes (`SELECT …`, `is_sealed`,
//!   `get_sealed_password`); it emits no DDL and no KV write. In particular the terminal
//!   connectivity probe + the dedicated/MySQL diagnostic backends resolve their managed
//!   credential with `get_sealed_password` (a pure `kv.get` + unseal) on a dry-run — NEVER
//!   `password()` (create-if-absent + seal). An as-yet-unsealed credential on a dry-run is a
//!   benign `skipped` ("verified after apply"), so a `repair --dry-run` over a pre-v0.4.25 tenant
//!   (owner credential absent) leaves the KV byte-for-byte untouched (Security HIGH-1).
//! - **`quote_ident` on every emitted identifier — with ONE documented exception.** Every db /
//!   schema / table / role name emitted in DDL goes through `quote_ident`. The SOLE probe string
//!   NOT `quote_ident`'d is a function's `pg_get_function_identity_arguments` type-signature
//!   fragment (a type list like `integer, text`, not a single identifier), pasted into
//!   `ALTER FUNCTION …(<args>)`. It is Postgres's own canonical rendering for a function that
//!   provably exists in the already-confined tenant db (not operator/guest input); as
//!   defense-in-depth `targeted_reown_ddl` SKIPS (fails closed, emits no DDL for) any such object
//!   whose args contain a `;` or an unbalanced quote.
//! - **Audit.** The derived `(db, runtime_role, owner_role)` triple + the maintenance
//!   identity + every executed statement are logged.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::sql::{
    RepairCheck, RepairError, RepairMode, RepairReport, RepairStatus, SqlBackend, SqlError,
    SqlValue,
};
use boatramp_storage::tenant_provision::{
    grant_app_role_ddl, provision_ddl, quote_ident, sanitize_ident,
};
use boatramp_storage::ExternalSqlKind;

use boatramp_core::project::ProjectRef;

use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use crate::managed_sql::{DeployEndpointResolver, ManagedSqlCredentials};
use crate::tenant_sql::{
    owner_credential_workload_key, shared_admin_backend_for_db, single_credential_project,
    tenant_key, tenant_names,
};

/// The host-owned migration-ledger schema + table (matching `NodeMigrationRunner`), which
/// the ledger check (7) scaffolds + re-owns to the owner role.
const LEDGER_SCHEMA: &str = "boatramp_migrations";
const LEDGER_TABLE: &str = "schema_migrations";

/// The node-side [`TenantRepair`](boatramp_core::sql::TenantRepair): the owner-model
/// drift-repair capability over the handler `sql` `databases`. Backs the
/// `Project·Admin`-gated `/api/repair/{db}` + `/dry-run`. Shares the same
/// deploy/kv/envelope the provisioner uses; derives every name deterministically.
pub struct NodeTenantRepair {
    databases: std::collections::BTreeMap<String, ExternalDatabaseConfig>,
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Option<Arc<dyn KeyEnvelope>>,
}

impl NodeTenantRepair {
    /// Build over the handler `sql` `databases` config + the shared deploy/kv/envelope.
    pub fn new(
        databases: std::collections::BTreeMap<String, ExternalDatabaseConfig>,
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Option<Arc<dyn KeyEnvelope>>,
    ) -> Self {
        Self {
            databases,
            deploy,
            kv,
            envelope,
        }
    }
}

#[async_trait]
impl boatramp_core::sql::TenantRepair for NodeTenantRepair {
    async fn repair(
        &self,
        project: &str,
        db: &str,
        mode: RepairMode,
    ) -> Result<RepairReport, RepairError> {
        // Defense-in-depth: the API path param + CLI `--db` are validated before they reach
        // here, but this is a privileged, host-derived-DDL choke point, so re-run the one
        // canonical validator to fail closed on any db name that is not a safe path segment.
        boatramp_core::project::validate_resource_name("database", db)
            .map_err(|e| RepairError::Other(e.to_string()))?;

        let binding = self.databases.get(db).ok_or(RepairError::NotConfigured)?;

        let envelope = self.envelope.clone().ok_or_else(|| {
            RepairError::Other(format!(
                "managed database {db:?} needs a [secrets] envelope to repair its sealed credentials"
            ))
        })?;
        let creds = ManagedSqlCredentials::new(self.kv.clone(), envelope);

        repair_tenant(&self.deploy, &creds, binding, db, project, mode).await
    }
}

/// The `(project, db)`-derived identity a repair targets — everything downstream reads
/// DERIVED names from here, never a probe result.
struct Derived {
    /// The engine (Postgres for the full owner-model surface).
    kind: ExternalSqlKind,
    /// The binding's compute workload (the shared server) — the base for the role names.
    compute: String,
    /// The binding's configured superuser/connect user.
    superuser: String,
    /// The sanitized tenant identity (from the validated `(project, site="")`).
    ident: String,
    /// The derived, sanitized tenant DATABASE name (the exact live name — `==`, never `LIKE`).
    database: String,
    /// The derived runtime login role (the `<old>` for a `REASSIGN OWNED`).
    runtime_role: String,
    /// The derived owner/DDL role (the `<owner>` target of every re-ownership).
    owner_role: String,
    /// The tenant's project (the KV credential-key `<project>` segment).
    project: String,
}

/// The per-backend provisioning model a `repair` run reconciles. Every backend has ONE — none
/// returns a blanket "not applicable"; each reconciles the provisioning boatramp actually owns for
/// that engine/topology, rendered by the same [`RepairReport`]/CLI. The shared-Postgres model is
/// the full owner-model retrofit (9 checks); the others reconcile their own (smaller) surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepairModel {
    /// Shared Postgres (`tenant = shared`, compute-backed): the three-identity owner model —
    /// per-tenant db + runtime role + owner role, RLS-isolated. The full 9-check retrofit.
    SharedPostgres,
    /// Dedicated/single Postgres (`tenant = single`, compute-backed): the CONTAINER is the
    /// isolation boundary — no shared owner/runtime role split. Reconciles the per-tenant
    /// workload + sealed credential + db/user + ledger + connectivity.
    DedicatedPostgres,
    /// MySQL (compute-backed managed OR external): no owner/runtime role split. Reconciles the
    /// runtime user + `GRANT ALL ON <db>.*`, the DISTINCT DDL identity (`migration_url_env`), the
    /// ledger DATABASE + table, and connectivity.
    Mysql,
    /// Embedded libsql/SQLite (single-node `path`): the FILE is the boundary — no roles/RLS.
    /// Reconciles the on-disk db file + the reserved-prefix ledger table + connectivity.
    Libsql,
    /// External / bring-your-own (`url_env`, no managed compute): boatramp owns no roles — it
    /// reconciles ONLY the migrate-ledger scaffolding it owns + connectivity.
    External,
}

/// Classify `binding` into its [`RepairModel`]. The mapping mirrors how each backend is
/// PROVISIONED (`tenant_sql::provision_single`/`provision_shared`, `managed_sql`'s MySQL DDL
/// identity + the libsql runner), so repair reconciles the same model that provision produced.
fn classify_model(binding: &ExternalDatabaseConfig) -> RepairModel {
    let compute_backed = binding.compute.as_deref().is_some_and(|c| !c.is_empty());
    match ExternalSqlKind::parse(&binding.kind) {
        Some(ExternalSqlKind::Postgres) if compute_backed => match binding.tenant {
            TenantIsolation::Shared => RepairModel::SharedPostgres,
            TenantIsolation::Single => RepairModel::DedicatedPostgres,
        },
        // A bring-your-own Postgres (url_env, no compute) is operator-owned — External.
        Some(ExternalSqlKind::Postgres) => RepairModel::External,
        // MySQL (managed or external) — one model; the runner branches on compute-backed inside.
        Some(ExternalSqlKind::Mysql) => RepairModel::Mysql,
        // Unknown to sqlx: libsql/SQLite (kind libsql/sqlite/sqlite3), else genuinely external.
        None => {
            if is_libsql_kind(&binding.kind) {
                RepairModel::Libsql
            } else {
                RepairModel::External
            }
        }
    }
}

/// The top-level orchestrator. Classifies the binding into its per-backend [`RepairModel`] and
/// dispatches to that model's check runner. EVERY backend reconciles its own provisioning model —
/// none returns a blanket "skipped/not-applicable"; a check that does not apply to a model carries
/// a `skipped` reason and the op still exits 0. Returns a full report even when drift is found or a
/// check errors; an `Err` is only for a run that could not produce a report at all.
pub async fn repair_tenant(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    db_binding_name: &str,
    project: &str,
    mode: RepairMode,
) -> Result<RepairReport, RepairError> {
    let backend_class = classify_backend(binding);
    let model = classify_model(binding);

    tracing::info!(
        target: "boatramp::repair",
        project = %project,
        binding = %db_binding_name,
        mode = %mode.as_str(),
        backend = %backend_class,
        model = ?model,
        "repair: classified backend model"
    );

    match model {
        RepairModel::SharedPostgres => {
            repair_shared_postgres(deploy, creds, binding, db_binding_name, project, mode).await
        }
        RepairModel::DedicatedPostgres => {
            Ok(
                repair_dedicated_postgres(deploy, creds, binding, project, mode, &backend_class)
                    .await,
            )
        }
        RepairModel::Mysql => {
            Ok(repair_mysql(deploy, creds, binding, project, mode, &backend_class).await)
        }
        RepairModel::Libsql => Ok(repair_libsql(binding, project, mode, &backend_class).await),
        RepairModel::External => Ok(repair_external(binding, project, mode, &backend_class).await),
    }
}

/// The shared-Postgres owner model (the full 9-check retrofit). Resolves the derived
/// `(db, runtime_role, owner_role)` triple, gates the two non-owner-model sub-cases (site-scoped,
/// reserved default tenant) as `skipped`, then runs the checks.
async fn repair_shared_postgres(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    db_binding_name: &str,
    project: &str,
    mode: RepairMode,
) -> Result<RepairReport, RepairError> {
    let backend_class = classify_backend(binding);
    // Classification guarantees compute-backed shared Postgres; unwrap the parts defensively.
    let compute = binding
        .compute
        .as_deref()
        .filter(|c| !c.is_empty())
        .unwrap_or_default();

    // Site-scoped operator repair has no single project-level database (like operator sql),
    // so report it as skipped rather than silently targeting the wrong DB.
    if matches!(binding.tenant_scope, TenantScope::Site) {
        let mut report = base_report(binding, project, &backend_class, mode);
        report.tenant = format!("{}@{compute} (site-scoped)", binding_db(binding));
        report.checks.push(skip_check(
            "topology",
            "site-scoped managed database; operator repair is project-level and cannot target a \
             specific site's database",
        ));
        return Ok(report);
    }

    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
    if is_default {
        // The reserved default tenant is the ordinary single-tenant install (the superuser IS
        // the app user; there is no per-tenant owner model). Nothing to reconcile.
        let mut report = base_report(binding, project, &backend_class, mode);
        report.tenant = format!("{}@{compute} (default tenant)", binding_db(binding));
        report.checks.push(skip_check(
            "topology",
            "reserved default tenant (single-tenant install); no per-tenant owner model to \
             reconcile",
        ));
        return Ok(report);
    }

    let database = binding_db(binding);
    let names = tenant_names(
        binding.tenant,
        compute,
        &database,
        &tenant_ident_raw,
        is_default,
    );
    let derived = Derived {
        kind: ExternalSqlKind::Postgres,
        compute: compute.to_string(),
        superuser: binding.user.as_deref().unwrap_or_default().to_string(),
        ident: sanitize_ident(&tenant_ident_raw),
        database: names.database.clone(),
        runtime_role: names.role.clone(),
        owner_role: names.owner_role.clone(),
        project: project.to_string(),
    };

    // Audit the derived identity + maintenance identity BEFORE any statement runs, so the
    // trail always records the exact triple a run acted on (Security: audit completeness).
    tracing::info!(
        target: "boatramp::repair",
        project = %derived.project,
        binding = %db_binding_name,
        mode = %mode.as_str(),
        derived_db = %derived.database,
        derived_runtime_role = %derived.runtime_role,
        derived_owner_role = %derived.owner_role,
        maintenance_user = %derived.superuser,
        compute = %derived.compute,
        "repair: resolved derived tenant identity"
    );

    let mut report = base_report(binding, project, &backend_class, mode);
    report.tenant = derived.database.clone();

    run_shared_postgres_checks(deploy, creds, &derived, mode, &mut report).await;
    Ok(report)
}

/// Run the 9 ordered shared-Postgres owner-model checks. Ordering matters: owner-role
/// existence (1) is a **precondition** — if the owner role is not (yet) present, the checks
/// that name it as a DDL target (2, 3, 4, 7) are skipped rather than emit
/// `ALTER … OWNER TO <nonexistent>`.
async fn run_shared_postgres_checks(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    // The MAINTENANCE-db superuser backend (role DDL + `ALTER DATABASE OWNER` + the db/role
    // probes). A connect failure surfaces as a terminal error, not a whole-run Err.
    let maint = match build_backend(deploy, creds, d, maintenance_db(d.kind)).await {
        Ok(b) => b,
        Err(e) => {
            report.checks.push(error_check(
                "connectivity",
                format!("could not build the maintenance connection: {e}"),
            ));
            return;
        }
    };

    // ---- soft-delete exclusion (Security MEDIUM-3) -----------------------------------
    match probe_live_or_soft_deleted(&maint, d).await {
        Ok(LiveState::Live) => {}
        Ok(LiveState::SoftDeletedOnly) => {
            report.checks.push(skip_check(
                "soft-delete",
                format!(
                    "only a soft-deleted sibling of {:?} exists (recover it first); repair changed \
                     nothing",
                    d.database
                ),
            ));
            return;
        }
        Ok(LiveState::Absent) => {
            report.checks.push(skip_check(
                "database",
                format!(
                    "no database {:?} (nor a soft-deleted sibling) exists — this tenant was never \
                     provisioned; use the provisioning path, not repair",
                    d.database
                ),
            ));
            return;
        }
        Err(e) => {
            report.checks.push(error_check(
                "soft-delete",
                format!("could not probe the database's live/soft-deleted state: {e}"),
            ));
            return;
        }
    }

    // ---- precondition: is the maintenance identity a superuser? -----------------------
    let maint_is_superuser = match probe_current_user_superuser(&maint).await {
        Ok(v) => v,
        Err(e) => {
            report.checks.push(error_check(
                "superuser-precondition",
                format!("could not determine whether the maintenance identity is a superuser: {e}"),
            ));
            false
        }
    };

    // ---- 1. owner role exists (precondition for 2/3/4/7) ------------------------------
    let owner_ready = check_owner_role_exists(creds, d, &maint, mode, report).await;

    // ---- 2. owner role attributes -----------------------------------------------------
    if owner_ready {
        check_owner_role_attrs(&maint, d, mode, report).await;
    } else {
        report.checks.push(skip_check(
            "owner-role-attrs",
            "owner role is not (yet) present (see owner-role-exists)",
        ));
    }

    // ---- 3. db owner (on the MAINTENANCE db) ------------------------------------------
    if owner_ready {
        check_db_owner(&maint, d, mode, report).await;
    } else {
        report.checks.push(skip_check(
            "db-owner",
            "owner role is not (yet) present, so `ALTER DATABASE … OWNER TO <owner>` is not emitted",
        ));
    }

    // ---- 4. object ownership (on the TENANT db) ---------------------------------------
    if owner_ready {
        check_object_ownership(deploy, creds, d, maint_is_superuser, mode, report).await;
    } else {
        report.checks.push(skip_check(
            "object-ownership",
            "owner role is not (yet) present, so object re-ownership is not emitted",
        ));
    }

    // ---- 5. connect grants ------------------------------------------------------------
    check_connect_grants(&maint, d, mode, report).await;

    // ---- 6. runtime DML + owner-keyed default privileges (on the TENANT db) -----------
    check_runtime_dml_grants(deploy, creds, d, mode, report).await;

    // ---- 7. ledger (on the TENANT db) -------------------------------------------------
    if owner_ready {
        check_ledger(deploy, creds, d, mode, report).await;
    } else {
        report.checks.push(skip_check(
            "ledger",
            "owner role is not (yet) present, so ledger scaffolding + re-ownership is deferred",
        ));
    }

    // ---- 8. owner credential sealed ---------------------------------------------------
    check_owner_credential_sealed(creds, d, mode, report).await;

    // ---- 9. connectivity (terminal report) --------------------------------------------
    check_connectivity(deploy, creds, d, mode, report).await;
}

// ===========================================================================
// Model: Dedicated / single Postgres (container is the boundary)
// ===========================================================================

/// The `Single`/dedicated-Postgres model: the container is the isolation boundary — there is NO
/// shared owner/runtime role split (the configured user IS the app + DDL identity of its own
/// dedicated server). So the owner-model checks (owner role, `REASSIGN OWNED`, object re-ownership)
/// are `skipped` with a reason; what repair reconciles here is that the tenant's dedicated server
/// exists + is credentialled + carries its ledger:
///
/// 1. `compute-workload` — the per-tenant workload `<compute>-<ident>` (bare `<compute>` for the
///    default tenant) is registered (`deploy.get_compute_workload`). Read-only; on a dry-run it is
///    only reported, on an apply it is NOT auto-created (provisioning, not repair — repair never
///    spawns a server; it reports the drift so the operator provisions it).
/// 2. `owner-credential-sealed` → reused as `credential-sealed`: the workload's sealed credential
///    is present (`is_sealed`, read-only in dry-run; sealed on apply — the server was inited with it).
/// 3. `ledger` — the `boatramp_migrations` schema + `schema_migrations` table exist in the tenant
///    db (connectivity permitting).
/// 4. `connectivity` — connect as the configured user with the sealed credential + `SELECT 1`.
///
/// The role-model checks (`owner-role`, `object-ownership`, `connect-grants`, `runtime-grants`) are
/// `skipped` ("dedicated Postgres — the container is the boundary").
async fn repair_dedicated_postgres(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    project: &str,
    mode: RepairMode,
    backend_class: &str,
) -> RepairReport {
    let mut report = base_report(binding, project, backend_class, mode);
    let compute = binding
        .compute
        .as_deref()
        .filter(|c| !c.is_empty())
        .unwrap_or_default();
    let database = binding_db(binding);
    let user = binding.user.as_deref().unwrap_or_default().to_string();
    let kind = ExternalSqlKind::Postgres;

    // Derive the per-tenant workload + credential key EXACTLY as `provision_single` / the resolver
    // do (never operator input).
    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
    if matches!(binding.tenant_scope, TenantScope::Site) {
        report.tenant = format!("{database}@{compute} (site-scoped)");
        report.checks.push(skip_check(
            "topology",
            "site-scoped managed database; operator repair is project-level and cannot target a \
             specific site's database",
        ));
        return report;
    }
    let names = tenant_names(
        binding.tenant,
        compute,
        &database,
        &tenant_ident_raw,
        is_default,
    );
    let cred_project = single_credential_project(project, is_default);
    let cred_workload = names.workload.clone();
    report.tenant = format!("{}@{}", names.database, names.workload);

    // Role-model checks do not apply — the container is the boundary. Emit them as skips so the
    // model is self-explaining (never a blanket single "not applicable").
    let boundary = "dedicated Postgres — the container is the isolation boundary (no shared \
                    owner/runtime role split, no RLS)";
    for check in [
        "owner-role",
        "object-ownership",
        "connect-grants",
        "runtime-grants",
    ] {
        report.checks.push(skip_check(check, boundary));
    }

    // 1. The tenant's dedicated compute workload is registered.
    match deploy
        .get_compute_workload(ProjectRef::new(project), &names.workload)
        .await
    {
        Ok(Some(_)) => report.checks.push(ok_check(
            "compute-workload",
            format!("dedicated workload {:?} is registered", names.workload),
        )),
        Ok(None) => report.checks.push(RepairCheck {
            check: "compute-workload".to_string(),
            status: RepairStatus::Drift,
            detail: format!(
                "dedicated workload {:?} is not registered; provision the tenant (repair does not \
                 spawn a server — it reconciles an EXISTING one)",
                names.workload
            ),
            ddl: None,
        }),
        Err(e) => report.checks.push(error_check(
            "compute-workload",
            format!(
                "could not check the compute workload {:?}: {e}",
                names.workload
            ),
        )),
    }

    // 2. The workload's sealed credential (server-init password) is present.
    check_credential_sealed(
        creds,
        &cred_project,
        &cred_workload,
        mode,
        "credential-sealed",
        &mut report,
    )
    .await;

    // Build the tenant backend (the configured user + sealed credential to the tenant db on its
    // dedicated workload) — used for the ledger probe/converge + connectivity.
    let endpoint_project = if is_default {
        boatramp_core::project::DEFAULT_PROJECT.to_string()
    } else {
        project.to_string()
    };
    let backend = build_compute_backend(
        deploy,
        creds,
        kind,
        &names.workload,
        &names.database,
        &user,
        &cred_project,
        &cred_workload,
        &endpoint_project,
        mode,
    )
    .await;

    match backend {
        Ok(backend) => {
            // 3. Ledger present (schema + table). No re-ownership on a dedicated server — the
            //    configured user already owns everything it creates; we only ensure existence.
            check_pg_ledger_exists(&backend, kind, mode, &mut report).await;
            // 4. Connectivity (terminal SELECT 1).
            match backend.run_query("SELECT 1;").await {
                Ok(_) => report.checks.push(ok_check(
                    "connectivity",
                    format!("connected to {:?} as {:?}", names.database, user),
                )),
                Err(e) => report.checks.push(error_check(
                    "connectivity",
                    format!(
                        "could not connect to {:?} as {:?}: {e}",
                        names.database, user
                    ),
                )),
            }
        }
        // Dry-run + the server credential not yet sealed: benign — never seal on a dry-run
        // (Security HIGH-1). Report the connectivity-dependent checks as `skipped`, op exits 0.
        Err(BackendBuildError::Unsealed) => {
            report.checks.push(skip_check(
                "ledger",
                "skipped — the server credential is not yet sealed; a dry-run does not seal it \
                 (the ledger + connectivity are verified after apply)",
            ));
            report.checks.push(skip_check(
                "connectivity",
                "the server credential is not yet sealed — connectivity verified after apply",
            ));
        }
        Err(e) => {
            report.checks.push(skip_check(
                "ledger",
                format!("skipped — could not build the tenant connection: {e}"),
            ));
            report.checks.push(error_check(
                "connectivity",
                format!("could not build the tenant connection: {e}"),
            ));
        }
    }
    report
}

// ===========================================================================
// Model: MySQL (no owner/runtime role split; distinct DDL identity required)
// ===========================================================================

/// The MySQL model (managed OR external). MySQL has NO owner/runtime role split — the runtime user
/// gets `GRANT ALL ON <db>.*` and is itself DDL-capable within its schema, so migrations require a
/// DISTINCT DDL identity supplied via `migration_url_env` (the v0.5.1 refusal logic). Repair
/// reconciles:
///
/// 1. `runtime-user` — the runtime user exists with `GRANT ALL ON <db>.*` (probed via
///    `information_schema` grants) — coarse: reported, converge is left to provisioning.
/// 2. `database` — the tenant database exists.
/// 3. `ddl-identity` — a DISTINCT DDL identity is configured (`migration_url_env`), distinct from
///    the runtime (byte + `mysql_dsn_username`), and REACHABLE. A compute-backed managed MySQL with
///    NO derivable DDL identity is a terminal `error` (mirrors the v0.5.1 migrate refusal — NOT a
///    silent skip).
/// 4. `ledger` — the ledger DATABASE `boatramp_migrations` + its `schema_migrations` table exist.
/// 5. `connectivity` — connect as the runtime identity + `SELECT 1`.
///
/// Every probe is read-only (no `GRANT`/DDL in either mode — MySQL provisioning grants are minted by
/// the provision path, not repair; repair reports the drift). Data-preserving throughout.
async fn repair_mysql(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    project: &str,
    mode: RepairMode,
    backend_class: &str,
) -> RepairReport {
    let mut report = base_report(binding, project, backend_class, mode);
    let kind = ExternalSqlKind::Mysql;
    let database = binding_db(binding);
    let compute_backed = binding.compute.as_deref().is_some_and(|c| !c.is_empty());

    // Resolve the runtime backend (managed: compute + sealed credential; external: `url_env`).
    let runtime = build_runtime_backend(deploy, creds, binding, kind, project, mode).await;

    if compute_backed {
        if matches!(binding.tenant_scope, TenantScope::Site) {
            report.tenant = format!("{database}@mysql (site-scoped)");
            report.checks.push(skip_check(
                "topology",
                "site-scoped managed database; operator repair is project-level and cannot target \
                 a specific site's database",
            ));
            return report;
        }
        let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
        let compute = binding.compute.as_deref().unwrap_or_default();
        let names = tenant_names(
            binding.tenant,
            compute,
            &database,
            &tenant_ident_raw,
            is_default,
        );
        report.tenant = format!("{}@{}", names.database, names.workload);
    } else {
        report.tenant = format!("{database}@{} (external mysql)", binding.url_env);
    }

    // 3. The DISTINCT DDL identity: reconcile it BEFORE the connectivity-dependent probes so the
    //    core migrate precondition is always in the report (even if the runtime is unreachable).
    check_mysql_ddl_identity(binding, &database, compute_backed, &mut report);

    // The runtime backend powers checks 1/2/4/5. If it can't be built (e.g. external url_env unset),
    // report each dependent as error/skip rather than dropping them.
    let runtime = match runtime {
        Ok(b) => b,
        // Dry-run + the managed runtime credential not yet sealed: benign — a dry-run must not
        // seal it (Security HIGH-1). Report every runtime-dependent check as `skipped`, op exits 0.
        Err(BackendBuildError::Unsealed) => {
            for check in ["runtime-user", "database", "ledger"] {
                report.checks.push(skip_check(
                    check,
                    "skipped — the runtime credential is not yet sealed; a dry-run does not seal \
                     it (verified after apply)",
                ));
            }
            report.checks.push(skip_check(
                "connectivity",
                "the runtime credential is not yet sealed — connectivity verified after apply",
            ));
            return report;
        }
        Err(e) => {
            for check in ["runtime-user", "database", "ledger"] {
                report.checks.push(skip_check(
                    check,
                    format!("skipped — could not build the runtime connection: {e}"),
                ));
            }
            report.checks.push(error_check(
                "connectivity",
                format!("could not build the runtime connection: {e}"),
            ));
            return report;
        }
    };

    // 1. The runtime user has `GRANT ALL ON <db>.*` (coarse: any schema-level grant present).
    check_mysql_runtime_grant(&runtime, &database, &mut report).await;
    // 2. The tenant database exists.
    check_mysql_database_exists(&runtime, &database, &mut report).await;
    // 4. The ledger database + table exist.
    check_mysql_ledger_exists(&runtime, &mut report).await;
    // 5. Connectivity.
    match runtime.run_query("SELECT 1;").await {
        Ok(_) => report.checks.push(ok_check(
            "connectivity",
            format!("connected to the MySQL runtime for {database:?}"),
        )),
        Err(e) => report.checks.push(error_check(
            "connectivity",
            format!("could not connect to the MySQL runtime for {database:?}: {e}"),
        )),
    }
    report
}

// ===========================================================================
// Model: libsql / SQLite (the file is the boundary)
// ===========================================================================

/// The libsql/SQLite model: no roles, no RLS — the FILE is the trust boundary. Repair reconciles
/// only what boatramp owns for a single-node `libsql` binding:
///
/// 1. `db-file` — the on-disk single-node `path` exists. (A remote-sqld `libsql` binding, which
///    uses `url_env` with no local file, is reported `skipped` — its namespace lives on the sqld
///    server, not a boatramp-owned file.)
/// 2. `ledger` — the reserved-prefix ledger table `boatramp_migrations_schema_migrations` is
///    present in the file (connectivity permitting).
/// 3. `connectivity` — open the file + `SELECT 1`.
///
/// Everything role-related is `skipped` ("libsql/SQLite — the file is the boundary; no roles/RLS").
/// The dry-run opens the file READ-ONLY-style (a bare open + `SELECT` — SQLite `open_local` creates
/// the file if absent, so the dry-run FIRST stats the path and only opens when it already exists, to
/// stay side-effect-free — it must never CREATE the db file on a dry-run).
async fn repair_libsql(
    binding: &ExternalDatabaseConfig,
    project: &str,
    mode: RepairMode,
    backend_class: &str,
) -> RepairReport {
    let mut report = base_report(binding, project, backend_class, mode);

    // Role-model checks never apply on SQLite (the file is the boundary — no roles/RLS).
    let boundary = "libsql/SQLite — the file is the trust boundary; there are no roles/RLS to \
                    reconcile";
    for check in [
        "owner-role",
        "object-ownership",
        "connect-grants",
        "runtime-grants",
    ] {
        report.checks.push(skip_check(check, boundary));
    }

    // The file-specific reconcile needs the embedded libsql runner (`feature = "migrate"`); a
    // build without it can still classify + report the topology, but can't open the file.
    libsql_file_reconcile(binding, mode, report).await
}

/// The file-specific libsql reconcile (needs the embedded libsql engine). Present only under
/// `feature = "migrate"`. Reports `db-file` / `ledger` / `connectivity`; a dry-run over a
/// non-existent file NEVER opens (thus never creates) it.
#[cfg(feature = "migrate")]
async fn libsql_file_reconcile(
    binding: &ExternalDatabaseConfig,
    mode: RepairMode,
    mut report: RepairReport,
) -> RepairReport {
    // A remote-sqld binding (url_env, no path) has no boatramp-owned local file.
    let Some(path) = binding
        .path
        .as_deref()
        .filter(|p| !p.as_os_str().is_empty())
    else {
        report.tenant = format!("{}@libsql (remote sqld)", binding_db(binding));
        report.checks.push(skip_check(
            "db-file",
            "remote-sqld libsql binding (url_env, no single-node `path`); the namespace lives on \
             the sqld server — not a boatramp-owned local file to reconcile",
        ));
        report.checks.push(skip_check(
            "ledger",
            "skipped — a remote-sqld libsql binding has no local file to probe",
        ));
        report.checks.push(skip_check(
            "connectivity",
            "skipped — a remote-sqld libsql binding is not a single-node file target",
        ));
        return report;
    };
    report.tenant = format!("{}@{}", binding_db(binding), path.display());

    // 1. The on-disk file exists. On a dry-run we MUST NOT create it (SQLite `open_local` creates
    //    on open), so `stat` the path first and only open when it already exists.
    let exists = path.is_file();
    if exists {
        report.checks.push(ok_check(
            "db-file",
            format!("db file {} exists", path.display()),
        ));
    } else {
        report.checks.push(RepairCheck {
            check: "db-file".to_string(),
            status: RepairStatus::Drift,
            detail: format!(
                "db file {} does not exist; it is created lazily on first use / migrate — repair \
                 does not create it (a dry-run must be side-effect-free, and creating an empty db \
                 is provisioning, not repair)",
                path.display()
            ),
            ddl: None,
        });
    }

    // If the file is absent AND this is a dry-run, do not open it (that would create it). On an
    // apply, opening + ensuring the ledger IS the reconcile — the file is created then.
    if !exists && matches!(mode, RepairMode::DryRun) {
        report.checks.push(skip_check(
            "ledger",
            "skipped — the db file does not exist and a dry-run must not create it",
        ));
        report.checks.push(skip_check(
            "connectivity",
            "skipped — the db file does not exist (dry-run does not create it)",
        ));
        return report;
    }

    match boatramp_storage::LibsqlSql::open_local(path).await {
        Ok(sql) => {
            check_libsql_ledger(&sql, mode, &mut report).await;
            use boatramp_core::sql::SqlBackend;
            match sql.run_query("SELECT 1;").await {
                Ok(_) => report.checks.push(ok_check(
                    "connectivity",
                    format!("opened {} and ran SELECT 1", path.display()),
                )),
                Err(e) => report.checks.push(error_check(
                    "connectivity",
                    format!("could not query {}: {e}", path.display()),
                )),
            }
        }
        Err(e) => {
            report.checks.push(error_check(
                "ledger",
                format!("could not open {} to probe the ledger: {e}", path.display()),
            ));
            report.checks.push(error_check(
                "connectivity",
                format!("could not open {}: {e}", path.display()),
            ));
        }
    }
    report
}

/// The no-libsql-engine fallback: without `feature = "migrate"` there is no embedded libsql runner,
/// so the file can't be opened. Report the topology honestly (a `skipped` with the reason) rather
/// than pretend to reconcile — still a per-model report, never a panic.
#[cfg(not(feature = "migrate"))]
async fn libsql_file_reconcile(
    binding: &ExternalDatabaseConfig,
    _mode: RepairMode,
    mut report: RepairReport,
) -> RepairReport {
    report.tenant = format!("{}@libsql", binding_db(binding));
    report.checks.push(skip_check(
        "topology",
        "libsql repair needs the `migrate` feature (the embedded libsql substrate); this build has \
         no libsql runner to open the file",
    ));
    report
}

// ===========================================================================
// Model: External / bring-your-own (operator owns the roles)
// ===========================================================================

/// The external / bring-your-own model (`url_env`, no managed compute): boatramp owns NO roles /
/// database / ownership on the operator's server — it reconciles ONLY what it owns: the migrate
/// ledger scaffolding + connectivity. Everything role/ownership/grant is `skipped`
/// ("operator-owned binding").
///
/// The ledger existence probe + connectivity connect as the configured runtime `url_env` identity.
/// (For an external Postgres this is honest: the migrate path's owner-role analog would be the
/// operator's own DDL login; for external MySQL the [`repair_mysql`] model already covers it, so
/// this model is reached only for a bring-your-own Postgres — kind postgres, no compute — or a
/// genuinely-unknown engine, which reports its ledger probe as engine-appropriate or errors.)
async fn repair_external(
    binding: &ExternalDatabaseConfig,
    project: &str,
    mode: RepairMode,
    backend_class: &str,
) -> RepairReport {
    let _ = project;
    let mut report = base_report(binding, project, backend_class, mode);
    report.tenant = format!("{}@{} (external)", binding_db(binding), binding.url_env);

    let operator_owned =
        "operator-owned binding (bring-your-own url_env); boatramp owns no roles / \
                          ownership / grants here — nothing to reconcile";
    for check in [
        "owner-role",
        "object-ownership",
        "connect-grants",
        "runtime-grants",
    ] {
        report.checks.push(skip_check(check, operator_owned));
    }

    // The ledger + connectivity connect as the runtime `url_env` identity, if the engine is a sqlx
    // one this build supports; else report the topology honestly.
    let kind = ExternalSqlKind::parse(&binding.kind);
    match kind {
        Some(kind) => match build_external_backend(binding, kind) {
            Ok(backend) => {
                check_pg_or_mysql_ledger_exists(&backend, kind, mode, &mut report).await;
                match backend.run_query("SELECT 1;").await {
                    Ok(_) => report.checks.push(ok_check(
                        "connectivity",
                        format!(
                            "connected to the external {} via {}",
                            binding.kind, binding.url_env
                        ),
                    )),
                    Err(e) => report.checks.push(error_check(
                        "connectivity",
                        format!("could not connect to the external database: {e}"),
                    )),
                }
            }
            Err(e) => {
                report.checks.push(skip_check(
                    "ledger",
                    format!("skipped — could not build the external connection: {e}"),
                ));
                report.checks.push(error_check(
                    "connectivity",
                    format!("could not build the external connection: {e}"),
                ));
            }
        },
        None => {
            report.checks.push(skip_check(
                "ledger",
                format!(
                    "engine {:?} is not a sqlx engine this build reconciles the ledger for; only \
                     connectivity/topology is inspectable",
                    binding.kind
                ),
            ));
            report.checks.push(skip_check(
                "connectivity",
                format!("engine {:?} is not a recognized sqlx engine", binding.kind),
            ));
        }
    }
    report
}

// ===========================================================================
// Check 1 — owner role exists
// ===========================================================================

/// Probe whether the derived owner role exists (exact name, LOGIN only — a NOLOGIN
/// same-named role is a deprovision artifact, not the owner). On drift: converge =
/// `provision_ddl`'s idempotent owner-arm `CREATE ROLE … NOSUPERUSER …` bound to a
/// freshly sealed owner credential (apply only; the dry-run emits the DDL with a
/// placeholder password and seals nothing). Returns whether the owner role is (now)
/// present, so 2/3/4/7 know whether to run.
async fn check_owner_role_exists(
    creds: &ManagedSqlCredentials,
    d: &Derived,
    maint: &Arc<dyn SqlBackend>,
    mode: RepairMode,
    report: &mut RepairReport,
) -> bool {
    let present = match probe_role_exists(maint, &d.owner_role).await {
        Ok(v) => v,
        Err(e) => {
            report.checks.push(error_check(
                "owner-role-exists",
                format!("could not probe owner role {:?}: {e}", d.owner_role),
            ));
            return false;
        }
    };
    if present {
        report.checks.push(RepairCheck {
            check: "owner-role-exists".to_string(),
            status: RepairStatus::Ok,
            detail: format!("owner role {:?} exists", d.owner_role),
            ddl: None,
        });
        return true;
    }

    match mode {
        RepairMode::DryRun => {
            report.checks.push(RepairCheck {
                check: "owner-role-exists".to_string(),
                status: RepairStatus::Drift,
                detail: format!(
                    "owner role {:?} is missing; apply would CREATE it (NOSUPERUSER NOCREATEDB \
                     NOCREATEROLE NOBYPASSRLS NOREPLICATION) and seal its credential",
                    d.owner_role
                ),
                ddl: Some(owner_role_ddl(d, "<sealed-owner-password>").join("\n")),
            });
            false
        }
        RepairMode::Apply => {
            // Seal the owner credential FIRST (create-if-absent + seal), so the CREATE ROLE's
            // password matches what the migrate path will later connect with.
            let owner_cred_workload = owner_credential_workload_key(&d.compute, &d.ident);
            let owner_pw = match creds.password(&d.project, &owner_cred_workload).await {
                Ok(pw) => pw,
                Err(e) => {
                    report.checks.push(error_check(
                        "owner-role-exists",
                        format!("could not seal the owner credential: {e}"),
                    ));
                    return false;
                }
            };
            let stmts = owner_role_ddl(d, &owner_pw);
            for stmt in &stmts {
                if let Err(e) = maint.run_script(stmt).await {
                    report.checks.push(error_check(
                        "owner-role-exists",
                        format!("creating owner role {:?} failed: {e}", d.owner_role),
                    ));
                    return false;
                }
            }
            audit_stmts("owner-role-exists", d, &redact_pw(&stmts));
            // Re-probe.
            match probe_role_exists(maint, &d.owner_role).await {
                Ok(true) => {
                    report.checks.push(RepairCheck {
                        check: "owner-role-exists".to_string(),
                        status: RepairStatus::Repaired,
                        detail: format!(
                            "created owner role {:?} (NOSUPERUSER …) and sealed its credential",
                            d.owner_role
                        ),
                        ddl: Some(redact_pw(&stmts).join("\n")),
                    });
                    true
                }
                Ok(false) => {
                    report.checks.push(error_check(
                        "owner-role-exists",
                        format!(
                            "owner role {:?} still absent after CREATE ROLE (unexpected)",
                            d.owner_role
                        ),
                    ));
                    false
                }
                Err(e) => {
                    report.checks.push(error_check(
                        "owner-role-exists",
                        format!("re-probe after creating owner role failed: {e}"),
                    ));
                    false
                }
            }
        }
    }
}

/// The owner-role statements from `provision_ddl` (the idempotent create + the safe-attr
/// re-assert) — sliced from the SAME builder a fresh provision uses, so repair emits
/// byte-identical role DDL. The full builder is fed a throwaway runtime password (every
/// non-owner statement is dropped), and the owner statements carry `owner_pw`.
fn owner_role_ddl(d: &Derived, owner_pw: &str) -> Vec<String> {
    provision_ddl(
        d.kind,
        &d.database,
        &d.runtime_role,
        "unused-runtime-password",
        &d.owner_role,
        owner_pw,
    )
    .into_iter()
    // Keep ONLY the two owner-ROLE statements (the idempotent `DO … CREATE ROLE` + the
    // `ALTER ROLE … NOSUPERUSER …` re-assert). Exclude every other statement that also mentions the
    // owner name — the `CREATE DATABASE … OWNER <owner>` (repair never re-CREATEs the db) and the
    // `GRANT CONNECT … TO <owner>` (that is check 5's atomic connect-grant unit). Match on the
    // `ROLE` keyword + the owner name, and drop DATABASE/GRANT/REVOKE.
    .filter(|s| {
        let upper = s.to_ascii_uppercase();
        s.contains(&d.owner_role)
            && upper.contains("ROLE")
            && !upper.contains("CREATE DATABASE")
            && !upper.contains("GRANT ")
            && !upper.contains("REVOKE ")
    })
    .collect()
}

// ===========================================================================
// Check 2 — owner role attributes
// ===========================================================================

/// Probe the owner role's safe attributes (must be NOSUPERUSER / NOCREATEDB / NOCREATEROLE
/// / NOBYPASSRLS); on drift converge = `ALTER ROLE … NOSUPERUSER NOCREATEDB NOCREATEROLE
/// NOBYPASSRLS NOREPLICATION`.
async fn check_owner_role_attrs(
    maint: &Arc<dyn SqlBackend>,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let owner_lit = pg_literal(&d.owner_role);
    let rows = match maint
        .run_query(&format!(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication \
             FROM pg_roles WHERE rolname = {owner_lit};"
        ))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            report.checks.push(error_check(
                "owner-role-attrs",
                format!("could not probe owner-role attributes: {e}"),
            ));
            return;
        }
    };
    let Some(row) = rows.rows.first() else {
        report.checks.push(error_check(
            "owner-role-attrs",
            "owner role vanished between checks (unexpected)",
        ));
        return;
    };
    // Any of these being true is drift.
    let unsafe_attr = row.iter().take(5).any(sql_bool);
    let alter = format!(
        "ALTER ROLE {} WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;",
        quote_ident(d.kind, &d.owner_role)
    );
    if !unsafe_attr {
        report.checks.push(RepairCheck {
            check: "owner-role-attrs".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "owner role {:?} has the safe (NOSUPERUSER …) attributes",
                d.owner_role
            ),
            ddl: None,
        });
        return;
    }
    converge_ddl(
        maint,
        d,
        "owner-role-attrs",
        &[alter],
        mode,
        report,
        format!(
            "owner role {:?} has an unsafe attribute (SUPERUSER/CREATEDB/CREATEROLE/BYPASSRLS/\
             REPLICATION); would reset to NOSUPERUSER …",
            d.owner_role
        ),
        format!("reset owner role {:?} to the safe attributes", d.owner_role),
    )
    .await;
}

// ===========================================================================
// Check 3 — db owner (on the MAINTENANCE db)
// ===========================================================================

/// Probe `pg_database.datdba::regrole` for the derived db; on drift converge =
/// `ALTER DATABASE <db> OWNER TO <owner>` (run on the maintenance db — an `ALTER DATABASE`
/// cannot run inside the db being altered).
async fn check_db_owner(
    maint: &Arc<dyn SqlBackend>,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let db_lit = pg_literal(&d.database);
    let rows = match maint
        .run_query(&format!(
            "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = {db_lit};"
        ))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            report.checks.push(error_check(
                "db-owner",
                format!("could not probe the database owner: {e}"),
            ));
            return;
        }
    };
    let actual = rows.rows.first().and_then(|r| r.first()).map(sql_text);
    let Some(actual) = actual else {
        report.checks.push(error_check(
            "db-owner",
            "database owner probe returned no row",
        ));
        return;
    };
    // The probe result is used ONLY as an `==` verdict against the DERIVED owner — never fed
    // into the emitted DDL (Security MEDIUM-2).
    let alter = format!(
        "ALTER DATABASE {} OWNER TO {};",
        quote_ident(d.kind, &d.database),
        quote_ident(d.kind, &d.owner_role)
    );
    if actual == d.owner_role {
        report.checks.push(RepairCheck {
            check: "db-owner".to_string(),
            status: RepairStatus::Ok,
            detail: format!("database {:?} is owned by {:?}", d.database, d.owner_role),
            ddl: None,
        });
        return;
    }
    converge_ddl(
        maint,
        d,
        "db-owner",
        &[alter],
        mode,
        report,
        format!(
            "database {:?} is owned by {actual:?}, not the owner role {:?}; would re-own it",
            d.database, d.owner_role
        ),
        format!("re-owned database {:?} to {:?}", d.database, d.owner_role),
    )
    .await;
}

// ===========================================================================
// Check 4 — object ownership (on the TENANT db)
// ===========================================================================

/// Probe ACTUAL object owners in the tenant db (`pg_class.relowner` / `pg_proc.proowner`
/// joined to `pg_namespace`, excluding system schemas) and re-own anything not owned by the
/// derived owner. Two converge shapes:
///
/// - runtime-owned objects → `REASSIGN OWNED BY <derived runtime> TO <owner>` (bulk).
/// - superuser-owned objects (a shared tenant's schema is superuser-loaded) → targeted
///   `ALTER TABLE/SEQUENCE/FUNCTION … OWNER TO <owner>`. NEVER `REASSIGN OWNED BY <superuser>`
///   (which would sweep unrelated cluster objects).
///
/// Runs CONNECTED TO THE TENANT DB, guarded by a `current_database()` == derived-db assertion
/// before any `REASSIGN OWNED` fires. Requires the maintenance identity to be a superuser
/// (a `REASSIGN`/`ALTER … OWNER` across roles needs it); else a terminal, loud `error`.
///
/// The enumeration EXCLUDES the `boatramp_migrations` ledger schema (`n.nspname <>
/// 'boatramp_migrations'` on both the `pg_class` and `pg_proc` arms) so the ledger is never swept
/// into the bulk `REASSIGN`; the ledger is reconciled ONLY by check 7 (its explicit
/// `ALTER SCHEMA`/`ALTER TABLE … OWNER`), keeping the two reconcilers from fighting over it.
async fn check_object_ownership(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    maint_is_superuser: bool,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    // Connect to the TENANT db (never the maintenance db) for object enumeration + re-own.
    let tenant = match build_backend(deploy, creds, d, &d.database).await {
        Ok(b) => b,
        Err(e) => {
            report.checks.push(error_check(
                "object-ownership",
                format!("could not connect to the tenant database: {e}"),
            ));
            return;
        }
    };

    // Guard: assert we are actually on the derived tenant db before ANY re-ownership fires.
    match probe_current_database(&tenant).await {
        Ok(cur) if cur == d.database => {}
        Ok(cur) => {
            report.checks.push(error_check(
                "object-ownership",
                format!(
                    "refusing object re-ownership: connected to {cur:?}, expected the derived \
                     tenant database {:?}",
                    d.database
                ),
            ));
            return;
        }
        Err(e) => {
            report.checks.push(error_check(
                "object-ownership",
                format!("could not confirm the current database before re-ownership: {e}"),
            ));
            return;
        }
    }

    // Enumerate non-owner objects, carrying a KIND discriminator so a superuser-owned object is
    // re-owned by the CORRECT `ALTER TABLE`/`ALTER SEQUENCE`/`ALTER FUNCTION` variant (a bare
    // `ALTER TABLE` never re-owns a sequence or a function). `relowner`/`proowner` → role name.
    // For a function we also project `pg_get_function_identity_arguments(p.oid)` — the arg
    // signature `ALTER FUNCTION` requires to disambiguate overloads; it is empty (`''`) for the
    // relation rows. Column order: nspname, objname, owner, objkind, args.
    let owner_lit = pg_literal(&d.owner_role);
    let non_owner = match tenant
        .run_query(&format!(
            "SELECT n.nspname, c.relname, pg_catalog.pg_get_userbyid(c.relowner) AS owner, \
                    CASE WHEN c.relkind = 'S' THEN 'sequence' ELSE 'table' END AS objkind, \
                    '' AS args \
             FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname NOT IN ('pg_catalog','information_schema') \
               AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' \
               AND n.nspname <> 'boatramp_migrations' \
               AND c.relkind IN ('r','p','S','v','m') \
               AND pg_catalog.pg_get_userbyid(c.relowner) <> {owner_lit} \
             UNION ALL \
             SELECT n.nspname, p.proname, pg_catalog.pg_get_userbyid(p.proowner) AS owner, \
                    'function' AS objkind, \
                    pg_catalog.pg_get_function_identity_arguments(p.oid) AS args \
             FROM pg_catalog.pg_proc p \
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname NOT IN ('pg_catalog','information_schema') \
               AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' \
               AND n.nspname <> 'boatramp_migrations' \
               AND pg_catalog.pg_get_userbyid(p.proowner) <> {owner_lit};"
        ))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            report.checks.push(error_check(
                "object-ownership",
                format!("could not enumerate object owners: {e}"),
            ));
            return;
        }
    };

    if non_owner.rows.is_empty() {
        report.checks.push(RepairCheck {
            check: "object-ownership".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "all objects in {:?} are owned by {:?}",
                d.database, d.owner_role
            ),
            ddl: None,
        });
        return;
    }

    // Any non-owner object that is owned by the DERIVED runtime role → a single bulk
    // `REASSIGN OWNED`. Everything else (superuser-loaded shared schema) → targeted ALTERs.
    // We build the converge from the DERIVED runtime role + the enumerated object names/kind/args,
    // never feeding the probe's *owner* string back into a REASSIGN.
    let mut ddl: Vec<String> = Vec::new();
    let mut runtime_owned = 0usize;
    let mut other_owned = 0usize;
    // Objects a defensive guard SKIPPED (a function whose identity-args are not `quote_ident`'d and
    // fail the balance/`;` check — Security defense-in-depth). Reported in the check `detail`, and
    // NOT counted as re-owned, so the check never claims a skipped object was converged.
    let mut skipped_notes: Vec<String> = Vec::new();
    for row in &non_owner.rows {
        let schema = row.first().map(sql_text).unwrap_or_default();
        let name = row.get(1).map(sql_text).unwrap_or_default();
        let owner = row.get(2).map(sql_text).unwrap_or_default();
        let objkind = row.get(3).map(sql_text).unwrap_or_default();
        let args = row.get(4).map(sql_text).unwrap_or_default();
        if owner == d.runtime_role {
            runtime_owned += 1;
        } else {
            // Targeted re-own, KIND-CORRECT: a table/view/matview → `ALTER TABLE`, a sequence →
            // `ALTER SEQUENCE`, a function → `ALTER FUNCTION … (<args>)`. The NAMES/args are the
            // enumerated actual objects (safe: within the already-confined tenant db); the TARGET
            // is always the DERIVED owner (never the probe's owner string, Security MEDIUM-2).
            match targeted_reown_ddl(d, &schema, &name, &objkind, &args) {
                Ok(stmt) => {
                    other_owned += 1;
                    ddl.push(stmt);
                }
                Err(reason) => {
                    // Fail this ONE object closed (skip it, no DDL) — never emit a statement whose
                    // un-`quote_ident`'d function-arg fragment failed the defensive guard.
                    tracing::warn!(
                        target: "boatramp::repair",
                        derived_db = %d.database,
                        object = %format!("{schema}.{name}"),
                        objkind = %objkind,
                        "object-ownership: skipping targeted re-own (defensive guard): {reason}"
                    );
                    skipped_notes.push(format!("{schema:?}.{name:?}: {reason}"));
                }
            }
        }
    }
    // The bulk REASSIGN for the runtime-owned objects — named by the DERIVED runtime role, even
    // if a probe returned `postgres`/a shared role (Security MEDIUM-2). NEVER a superuser as `<old>`.
    if runtime_owned > 0 {
        ddl.insert(
            0,
            format!(
                "REASSIGN OWNED BY {} TO {};",
                quote_ident(d.kind, &d.runtime_role),
                quote_ident(d.kind, &d.owner_role)
            ),
        );
    }

    // Superuser-owned objects need a superuser to `ALTER … OWNER`; refuse (terminal error)
    // rather than a membership workaround, if the maintenance identity is not one.
    if other_owned > 0 && !maint_is_superuser {
        report.checks.push(error_check(
            "object-ownership",
            format!(
                "{other_owned} object(s) are owned by a superuser-loaded identity and re-owning \
                 them requires a superuser maintenance connection (the current identity is not \
                 one); refusing — never a GRANT <role> TO <maint> workaround"
            ),
        ));
        return;
    }
    // Even the bulk REASSIGN needs superuser (REASSIGN across roles requires it unless the
    // maintenance role is a member of both) — assert the precondition uniformly.
    if runtime_owned > 0 && !maint_is_superuser {
        report.checks.push(error_check(
            "object-ownership",
            "re-owning runtime-owned objects requires a superuser maintenance connection (the \
             current identity is not one); refusing — never a GRANT <role> TO <maint> workaround",
        ));
        return;
    }

    // A note appended to the check detail for every object the defensive guard skipped.
    let skip_note = if skipped_notes.is_empty() {
        String::new()
    } else {
        format!(
            " (skipped {} object(s) whose function args failed the defensive guard: {})",
            skipped_notes.len(),
            skipped_notes.join("; ")
        )
    };

    // If the ONLY drift was guard-skipped objects (nothing safe to converge), don't emit an empty
    // converge — report a `skipped` verdict naming what was fenced off, so the run is honest and
    // exits 0 without pretending it re-owned anything.
    if ddl.is_empty() {
        report.checks.push(skip_check(
            "object-ownership",
            format!(
                "no object re-ownership emitted; every non-owner object was fenced off by the \
                 defensive guard{skip_note}"
            ),
        ));
        return;
    }

    let drift_detail = format!(
        "{runtime_owned} runtime-owned + {other_owned} superuser-owned object(s) are not owned by \
         {:?}; would re-own them to it{skip_note}",
        d.owner_role
    );
    let repaired_detail = format!(
        "re-owned {runtime_owned} runtime-owned + {other_owned} superuser-owned object(s) to \
         {:?}{skip_note}",
        d.owner_role
    );
    converge_ddl_on(
        &tenant,
        d,
        "object-ownership",
        &ddl,
        mode,
        report,
        drift_detail,
        repaired_detail,
    )
    .await;
}

/// Build the KIND-CORRECT targeted re-ownership statement for one enumerated superuser-owned
/// object. `objkind` is the probe's discriminator (`table`/`sequence`/`function`); `args` is the
/// function's `pg_get_function_identity_arguments` signature (empty for relations). The schema /
/// name / args come from the probe of the tenant's OWN (already-confined) database, so they are
/// safe to name; the OWNER TARGET is always the DERIVED owner role, never a probe result.
///
/// - `table` (also views/matviews — a bare `ALTER TABLE` re-owns those too) →
///   `ALTER TABLE IF EXISTS "<schema>"."<name>" OWNER TO "<owner>"`.
/// - `sequence` → `ALTER SEQUENCE IF EXISTS "<schema>"."<name>" OWNER TO "<owner>"` (a sequence is
///   NOT re-owned by `ALTER TABLE`; needs its own statement).
/// - `function` → `ALTER FUNCTION "<schema>"."<name>"(<args>) OWNER TO "<owner>"`. `ALTER FUNCTION`
///   has **no `IF EXISTS`** form that also takes an argument list in older Postgres, and the arg
///   signature is required to disambiguate overloads — so it is emitted WITHOUT `IF EXISTS`, keyed
///   on the exact identity args the probe returned.
///
/// **Security — the one un-`quote_ident`'d probe string.** `<args>` is
/// `pg_get_function_identity_arguments`'s output pasted VERBATIM (it is a type-signature fragment
/// like `integer, text`, not a single identifier `quote_ident` could quote). It is Postgres's own
/// canonical rendering for a function that provably exists in this already-confined tenant db, not
/// operator/guest input — but as defense-in-depth this fn returns `Err(reason)` (the object is
/// SKIPPED, no DDL emitted) if `args` contains a `;` or an UNBALANCED number of single/double
/// quotes, so a pathological signature can never break out of the `ALTER FUNCTION …(<args>)` frame.
/// Every other arm quotes both identifiers and never interpolates `args`, so they cannot fail.
fn targeted_reown_ddl(
    d: &Derived,
    schema: &str,
    name: &str,
    objkind: &str,
    args: &str,
) -> Result<String, String> {
    let qname = format!(
        "{}.{}",
        quote_ident(d.kind, schema),
        quote_ident(d.kind, name)
    );
    let owner_id = quote_ident(d.kind, &d.owner_role);
    match objkind {
        "sequence" => Ok(format!(
            "ALTER SEQUENCE IF EXISTS {qname} OWNER TO {owner_id};"
        )),
        "function" => {
            // Defensive guard on the ONE un-`quote_ident`'d probe fragment: a `;` (statement break)
            // or an odd count of either quote (an unterminated string/identifier) means the
            // signature is not the well-formed type list we expect — fail this object closed.
            if args.contains(';') {
                return Err(format!(
                    "function identity-args {args:?} contain a ';' (statement separator); refusing \
                     to emit ALTER FUNCTION — reconcile this object manually"
                ));
            }
            if args.matches('\'').count() % 2 != 0 || args.matches('"').count() % 2 != 0 {
                return Err(format!(
                    "function identity-args {args:?} have an unbalanced quote; refusing to emit \
                     ALTER FUNCTION — reconcile this object manually"
                ));
            }
            Ok(format!(
                "ALTER FUNCTION {qname}({args}) OWNER TO {owner_id};"
            ))
        }
        // "table" and any unexpected kind fall through to the table form (the historical default,
        // covering tables/views/matviews). An unknown kind is thus re-owned harmlessly as a table.
        _ => Ok(format!(
            "ALTER TABLE IF EXISTS {qname} OWNER TO {owner_id};"
        )),
    }
}

// ===========================================================================
// Check 5 — connect grants (on the MAINTENANCE db)
// ===========================================================================

/// Probe `REVOKE CONNECT … FROM PUBLIC` + `GRANT CONNECT` to owner + runtime; on drift
/// converge = the REVOKE + both GRANTs as ONE ordered all-or-nothing unit (grants FIRST so
/// a partial apply can never lock the runtime out — Security MEDIUM-4).
async fn check_connect_grants(
    maint: &Arc<dyn SqlBackend>,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let db_lit = pg_literal(&d.database);
    // Does PUBLIC still hold CONNECT? Do owner + runtime hold it?
    let public_has = match probe_has_connect(maint, &db_lit, "'public'").await {
        Ok(v) => v,
        Err(e) => return report_probe_err(report, "connect-grants", e),
    };
    let owner_has = match probe_has_connect(maint, &db_lit, &pg_literal(&d.owner_role)).await {
        Ok(v) => v,
        Err(e) => return report_probe_err(report, "connect-grants", e),
    };
    let runtime_has = match probe_has_connect(maint, &db_lit, &pg_literal(&d.runtime_role)).await {
        Ok(v) => v,
        Err(e) => return report_probe_err(report, "connect-grants", e),
    };

    if !public_has && owner_has && runtime_has {
        report.checks.push(RepairCheck {
            check: "connect-grants".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "CONNECT on {:?} is revoked from PUBLIC and granted to owner + runtime",
                d.database
            ),
            ddl: None,
        });
        return;
    }
    let db_id = quote_ident(d.kind, &d.database);
    let owner_id = quote_ident(d.kind, &d.owner_role);
    let runtime_id = quote_ident(d.kind, &d.runtime_role);
    // Grants FIRST (atomic, never lock the runtime out), THEN the REVOKE.
    let ddl = vec![
        format!("GRANT CONNECT ON DATABASE {db_id} TO {owner_id};"),
        format!("GRANT CONNECT ON DATABASE {db_id} TO {runtime_id};"),
        format!("REVOKE CONNECT ON DATABASE {db_id} FROM PUBLIC;"),
    ];
    converge_ddl(
        maint,
        d,
        "connect-grants",
        &ddl,
        mode,
        report,
        format!(
            "CONNECT lockdown on {:?} has drifted (public_has_connect={public_has}, \
             owner_granted={owner_has}, runtime_granted={runtime_has}); would re-issue grants \
             then revoke from PUBLIC",
            d.database
        ),
        format!("re-issued the CONNECT lockdown on {:?}", d.database),
    )
    .await;
}

/// Whether `grantee` holds `CONNECT` on the database (via `has_database_privilege`). The
/// db + grantee literals are already-quoted string literals.
async fn probe_has_connect(
    maint: &Arc<dyn SqlBackend>,
    db_lit: &str,
    grantee_lit: &str,
) -> Result<bool, SqlError> {
    let rows = maint
        .run_query(&format!(
            "SELECT has_database_privilege({grantee_lit}, {db_lit}, 'CONNECT');"
        ))
        .await?;
    Ok(rows
        .rows
        .first()
        .and_then(|r| r.first())
        .map(sql_bool)
        .unwrap_or(false))
}

// ===========================================================================
// Check 6 — runtime DML + owner-keyed default privileges (on the TENANT db)
// ===========================================================================

/// The runtime-grants verdict (Security HIGH-2, extracted pure so it is unit-testable): the check
/// is `ok` ONLY when the runtime role holds `USAGE` on `public` AND there are ZERO public tables it
/// cannot `SELECT` (`tables_without_select == 0`). A missing USAGE, or ≥1 unreadable table (e.g.
/// after check 4's `REASSIGN OWNED` stripped the runtime's implicit owner SELECT), is drift → the
/// idempotent `grant_app_role_ddl` re-grant. A fully-granted tenant is a clean no-op (idempotency:
/// repair-then-repair emits zero actions).
fn runtime_dml_grants_ok(has_usage: bool, tables_without_select: i64) -> bool {
    has_usage && tables_without_select == 0
}

/// Re-run the idempotent `grant_app_role_ddl` inside the tenant db (grants the runtime
/// role app DML on `public` + sets `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`). Idempotent,
/// so on an apply we always (re-)assert; the converge is safe to run regardless (it never revokes).
///
/// **Accuracy (Security HIGH-2).** The probe must detect the drift that check 4's
/// `REASSIGN OWNED BY <runtime> TO <owner>` INDUCES: re-owning the runtime's tables to the owner
/// STRIPS the runtime's implicit owner privileges, so it can no longer SELECT its own (now
/// owner-owned) tables — yet schema `USAGE` on `public` SURVIVES the reassign. A `USAGE`-only
/// probe therefore falsely reports `ok` and skips `grant_app_role_ddl`, leaving the app with
/// `permission denied` on its own data. So the probe requires `USAGE` on `public` AND that the
/// runtime holds `SELECT` on EVERY public table (zero tables missing the grant). Only then is it
/// `ok`; otherwise it converges the idempotent `grant_app_role_ddl` (which re-grants table DML).
/// A fully-granted tenant stays a clean no-op — so repair-then-repair is zero-action (idempotent).
async fn check_runtime_dml_grants(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let tenant = match build_backend(deploy, creds, d, &d.database).await {
        Ok(b) => b,
        Err(e) => {
            report.checks.push(error_check(
                "runtime-grants",
                format!("could not connect to the tenant database: {e}"),
            ));
            return;
        }
    };
    let runtime_lit = pg_literal(&d.runtime_role);
    // (a) The runtime role has USAGE on `public`. Necessary but NOT sufficient — USAGE survives a
    //     `REASSIGN OWNED`, so it alone can't tell whether the runtime can still read its tables.
    let has_usage = match tenant
        .run_query(&format!(
            "SELECT has_schema_privilege({runtime_lit}, 'public', 'USAGE');"
        ))
        .await
    {
        Ok(rows) => rows
            .rows
            .first()
            .and_then(|r| r.first())
            .map(sql_bool)
            .unwrap_or(false),
        Err(e) => {
            report.checks.push(error_check(
                "runtime-grants",
                format!("could not probe the runtime role's schema privileges: {e}"),
            ));
            return;
        }
    };
    // (b) The runtime role holds SELECT on EVERY public table — count the public tables it CANNOT
    //     SELECT. This is what catches check 4's reassign: a re-owned table loses the runtime's
    //     implicit owner SELECT and shows up here as a missing grant. (Ledger tables live in the
    //     `boatramp_migrations` schema, so they are excluded by `schemaname = 'public'`; the app's
    //     own tables are the ones that must stay readable.) 0 missing ⇒ fully granted.
    let tables_without_select = match tenant
        .run_query(&format!(
            "SELECT count(*)::bigint FROM pg_catalog.pg_tables \
             WHERE schemaname = 'public' \
               AND NOT has_table_privilege({runtime_lit}, \
                                           format('%I.%I', schemaname, tablename), 'SELECT');"
        ))
        .await
    {
        Ok(rows) => rows
            .rows
            .first()
            .and_then(|r| r.first())
            .map(sql_i64)
            .unwrap_or(1),
        Err(e) => {
            report.checks.push(error_check(
                "runtime-grants",
                format!("could not probe the runtime role's table privileges: {e}"),
            ));
            return;
        }
    };
    let ddl = grant_app_role_ddl(d.kind, &d.runtime_role, &d.owner_role);
    if runtime_dml_grants_ok(has_usage, tables_without_select) {
        report.checks.push(RepairCheck {
            check: "runtime-grants".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "runtime role {:?} has USAGE on public + SELECT on every public table \
                 (owner-keyed default privileges assumed present)",
                d.runtime_role
            ),
            ddl: None,
        });
        return;
    }
    let drift_reason = if !has_usage {
        format!("runtime role {:?} lacks USAGE on public", d.runtime_role)
    } else {
        format!(
            "runtime role {:?} lacks SELECT on {tables_without_select} public table(s) (e.g. after \
             a re-ownership REASSIGN stripped its implicit owner privileges)",
            d.runtime_role
        )
    };
    converge_ddl_on(
        &tenant,
        d,
        "runtime-grants",
        &ddl,
        mode,
        report,
        format!("{drift_reason}; would (re-)grant DML + set owner-keyed default privileges"),
        format!(
            "granted runtime role {:?} app DML + owner-keyed default privileges",
            d.runtime_role
        ),
    )
    .await;
}

// ===========================================================================
// Check 7 — ledger schema/table exist + owned by owner (on the TENANT db)
// ===========================================================================

/// Probe the ledger schema `boatramp_migrations` + table `schema_migrations` exist AND are
/// owned by the owner role; converge = `CREATE SCHEMA/TABLE IF NOT EXISTS` (mirrors
/// `ensure_ledger`) + EXPLICIT `ALTER SCHEMA … OWNER TO <owner>` + `ALTER TABLE … OWNER TO
/// <owner>` (the `IF NOT EXISTS` does NOT fix ownership of an existing runtime-owned ledger).
/// Runs in the tenant db.
async fn check_ledger(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let tenant = match build_backend(deploy, creds, d, &d.database).await {
        Ok(b) => b,
        Err(e) => {
            report.checks.push(error_check(
                "ledger",
                format!("could not connect to the tenant database: {e}"),
            ));
            return;
        }
    };
    let schema_lit = pg_literal(LEDGER_SCHEMA);
    let table_lit = pg_literal(LEDGER_TABLE);
    // Schema present + its owner.
    let schema_owner = match tenant
        .run_query(&format!(
            "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace \
             WHERE nspname = {schema_lit};"
        ))
        .await
    {
        Ok(rows) => rows.rows.first().and_then(|r| r.first()).map(sql_text),
        Err(e) => {
            report.checks.push(error_check(
                "ledger",
                format!("could not probe the ledger schema: {e}"),
            ));
            return;
        }
    };
    // Table present + its owner.
    let table_owner = match tenant
        .run_query(&format!(
            "SELECT tableowner FROM pg_catalog.pg_tables \
             WHERE schemaname = {schema_lit} AND tablename = {table_lit};"
        ))
        .await
    {
        Ok(rows) => rows.rows.first().and_then(|r| r.first()).map(sql_text),
        Err(e) => {
            report.checks.push(error_check(
                "ledger",
                format!("could not probe the ledger table: {e}"),
            ));
            return;
        }
    };

    let schema_id = quote_ident(d.kind, LEDGER_SCHEMA);
    let ledger_id = format!(
        "{}.{}",
        quote_ident(d.kind, LEDGER_SCHEMA),
        quote_ident(d.kind, LEDGER_TABLE)
    );
    let owner_id = quote_ident(d.kind, &d.owner_role);
    let schema_ok = schema_owner.as_deref() == Some(d.owner_role.as_str());
    let table_ok = table_owner.as_deref() == Some(d.owner_role.as_str());

    if schema_ok && table_ok {
        report.checks.push(RepairCheck {
            check: "ledger".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "ledger schema + table exist and are owned by {:?}",
                d.owner_role
            ),
            ddl: None,
        });
        return;
    }
    // Converge: ensure-exists (idempotent) then EXPLICIT re-own (fixes an existing
    // runtime-owned ledger that IF NOT EXISTS would leave alone).
    let ddl = vec![
        format!("CREATE SCHEMA IF NOT EXISTS {schema_id};"),
        format!(
            "CREATE TABLE IF NOT EXISTS {ledger_id} (id text PRIMARY KEY, ordinal integer NOT NULL, \
             content_hash text NOT NULL, kind text NOT NULL, applied_at timestamptz NOT NULL \
             DEFAULT now(), applied_by text);"
        ),
        format!("ALTER SCHEMA {schema_id} OWNER TO {owner_id};"),
        format!("ALTER TABLE {ledger_id} OWNER TO {owner_id};"),
    ];
    converge_ddl_on(
        &tenant,
        d,
        "ledger",
        &ddl,
        mode,
        report,
        format!(
            "ledger drift (schema_owner={:?}, table_owner={:?}); would scaffold + re-own to {:?}",
            schema_owner, table_owner, d.owner_role
        ),
        format!("scaffolded + re-owned the ledger to {:?}", d.owner_role),
    )
    .await;
}

// ===========================================================================
// Check 8 — owner credential sealed (KV, no SQL)
// ===========================================================================

/// Probe (read-only, `is_sealed` — `kv.get` only) whether the owner credential is sealed in
/// KV; converge (apply only) = `password()` (create-if-absent + seal). Shown as a
/// parenthetical in `detail` — NEVER fake SQL (`ddl = None`).
async fn check_owner_credential_sealed(
    creds: &ManagedSqlCredentials,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let owner_cred_workload = owner_credential_workload_key(&d.compute, &d.ident);
    let sealed = match creds.is_sealed(&d.project, &owner_cred_workload).await {
        Ok(v) => v,
        Err(e) => {
            report.checks.push(error_check(
                "owner-credential-sealed",
                format!("could not probe the owner credential: {e}"),
            ));
            return;
        }
    };
    if sealed {
        report.checks.push(RepairCheck {
            check: "owner-credential-sealed".to_string(),
            status: RepairStatus::Ok,
            detail: "owner credential is sealed in the control-plane KV".to_string(),
            ddl: None,
        });
        return;
    }
    match mode {
        RepairMode::DryRun => report.checks.push(RepairCheck {
            check: "owner-credential-sealed".to_string(),
            status: RepairStatus::Drift,
            detail: "owner credential is not sealed; apply would generate + seal it \
                     (a control-plane KV write, not SQL)"
                .to_string(),
            ddl: None,
        }),
        RepairMode::Apply => {
            // Note: if check 1 already sealed it (owner-role-exists apply path), this reads sealed
            // and reports `ok` — the two are idempotent by the same key.
            match creds.password(&d.project, &owner_cred_workload).await {
                Ok(_) => report.checks.push(RepairCheck {
                    check: "owner-credential-sealed".to_string(),
                    status: RepairStatus::Repaired,
                    detail: "generated + sealed the owner credential (control-plane KV write)"
                        .to_string(),
                    ddl: None,
                }),
                Err(e) => report.checks.push(error_check(
                    "owner-credential-sealed",
                    format!("could not seal the owner credential: {e}"),
                )),
            }
        }
    }
}

// ===========================================================================
// Check 9 — connectivity (terminal report)
// ===========================================================================

/// Terminal check: can we connect as the owner AND the runtime role to the tenant db? A
/// read-only probe (a trivial `SELECT 1`) as each identity. Reports `ok` / `error` / `skipped`;
/// never a converge (it is a diagnostic). Runs in both modes.
///
/// **Dry-run purity (Security HIGH-1).** The probe resolves each role's credential via
/// [`probe_role_can_connect`], which — on a `DryRun` — reads the credential with
/// [`ManagedSqlCredentials::get_sealed_password`] (a pure `kv.get` + unseal, NEVER
/// create-if-absent + seal). If a role's credential is not yet sealed (e.g. a pre-v0.4.25 tenant
/// whose owner role never existed), the dry-run reports its connectivity as a benign `skipped`
/// ("credential not yet sealed — verified after apply"), never sealing it and never an error.
/// On an `Apply` the credential the run just sealed is present, so [`probe_role_can_connect`]
/// uses it (via `password()`, which is a no-op read when already sealed) and the probe verifies.
async fn check_connectivity(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let owner_cred_workload = owner_credential_workload_key(&d.compute, &d.ident);
    let owner = probe_role_can_connect(
        deploy,
        creds,
        d,
        &d.owner_role,
        &d.project,
        &owner_cred_workload,
        mode,
    )
    .await;
    let runtime_cred_workload = crate::tenant_sql::credential_workload_key(&d.compute, &d.ident);
    let runtime = probe_role_can_connect(
        deploy,
        creds,
        d,
        &d.runtime_role,
        &d.project,
        &runtime_cred_workload,
        mode,
    )
    .await;

    // A run where BOTH roles verify is `ok`. A run where the only non-verified roles are
    // dry-run-unsealed (`ConnectProbe::Unsealed`) is a benign `skipped` (verified after apply),
    // NOT an error — a pre-v0.4.25 tenant on a dry-run has no owner credential yet, and sealing
    // it just to probe would violate dry-run purity. Anything else (a clean auth refusal or a
    // transport error) is a real `error`.
    let mut skipped = Vec::new();
    let mut problems = Vec::new();
    for (label, role, res) in [
        ("owner", &d.owner_role, owner),
        ("runtime", &d.runtime_role, runtime),
    ] {
        match res {
            ConnectProbe::Connected => {}
            ConnectProbe::Unsealed => skipped.push(format!(
                "{label} role {role:?} credential not yet sealed — connectivity verified after apply"
            )),
            ConnectProbe::Refused => {
                problems.push(format!("{label} role {role:?} could not connect"))
            }
            ConnectProbe::Failed(e) => problems.push(format!("{label}-connect probe failed: {e}")),
        }
    }

    if !problems.is_empty() {
        report
            .checks
            .push(error_check("connectivity", problems.join("; ")));
    } else if !skipped.is_empty() {
        // Every non-verified role was merely unsealed on a dry-run — benign, op still exits 0.
        report
            .checks
            .push(skip_check("connectivity", skipped.join("; ")));
    } else {
        report.checks.push(RepairCheck {
            check: "connectivity".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "both the owner ({:?}) and runtime ({:?}) roles connect to {:?}",
                d.owner_role, d.runtime_role, d.database
            ),
            ddl: None,
        });
    }
}

/// The verdict of a diagnostic role-connect probe.
enum ConnectProbe {
    /// The role connected + ran the trivial query.
    Connected,
    /// A clean auth/permission refusal (the role/credential exists but was denied).
    Refused,
    /// The role's credential is not yet sealed and this is a `DryRun`, so the probe did NOT
    /// seal it (dry-run purity) and could not attempt a connect — verifiable after an apply.
    Unsealed,
    /// A transport/other error while probing.
    Failed(String),
}

/// Try a `SELECT 1` connecting to the tenant db as `role` with its sealed credential.
///
/// **Dry-run purity.** On `DryRun` the credential is resolved with
/// [`ManagedSqlCredentials::get_sealed_password`] — a pure read that returns `Ok(None)` when the
/// credential is absent, NEVER create-if-absent + seal. An absent credential on a dry-run is
/// reported as [`ConnectProbe::Unsealed`] (skip, verify after apply), never sealed. On `Apply`
/// the credential the run just sealed is present, so `password()` reads it (create-if-absent is a
/// no-op read when already sealed); an apply is the reconcile, so sealing there is expected.
async fn probe_role_can_connect(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    role: &str,
    cred_project: &str,
    cred_workload: &str,
    mode: RepairMode,
) -> ConnectProbe {
    use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
    let password = match mode {
        // Dry-run: pure read only — an absent credential is `Unsealed`, never sealed here.
        RepairMode::DryRun => match creds.get_sealed_password(cred_project, cred_workload).await {
            Ok(Some(pw)) => pw,
            Ok(None) => return ConnectProbe::Unsealed,
            Err(e) => return ConnectProbe::Failed(e),
        },
        // Apply: the credential is sealed (this run sealed it, or provisioning did). `password()`
        // is a no-op read when present; sealing on an apply is the reconcile, not a dry-run leak.
        RepairMode::Apply => match creds.password(cred_project, cred_workload).await {
            Ok(pw) => pw,
            Err(_) => return ConnectProbe::Refused,
        },
    };
    let resolver = Arc::new(crate::managed_sql::DeployEndpointResolver::new(
        deploy.clone(),
        boatramp_core::project::DEFAULT_PROJECT,
    ));
    let backend = ComputeResolvedSqlBackend::new(
        resolver,
        &d.compute,
        d.kind,
        d.database.clone(),
        role,
        password,
        Some(1),
        true, // read-only: a diagnostic connect
        Some(std::time::Duration::from_secs(10)),
    );
    match backend.run_query("SELECT 1;").await {
        Ok(_) => ConnectProbe::Connected,
        Err(SqlError::Unavailable(m)) => ConnectProbe::Failed(m),
        // An auth/permission refusal is a clean "no"; a transport error is a Failed.
        Err(e) => {
            let msg = e.to_string().to_ascii_lowercase();
            if msg.contains("password") || msg.contains("authentication") || msg.contains("denied")
            {
                ConnectProbe::Refused
            } else {
                ConnectProbe::Failed(e.to_string())
            }
        }
    }
}

// ===========================================================================
// Converge helpers
// ===========================================================================

/// Converge a drifted check by running `ddl` on the maintenance backend (or reporting it on
/// a dry-run). See [`converge_ddl_on`] — this is the maintenance-db variant.
#[allow(clippy::too_many_arguments)]
async fn converge_ddl(
    backend: &Arc<dyn SqlBackend>,
    d: &Derived,
    check: &str,
    ddl: &[String],
    mode: RepairMode,
    report: &mut RepairReport,
    drift_detail: String,
    repaired_detail: String,
) {
    converge_ddl_on(
        backend,
        d,
        check,
        ddl,
        mode,
        report,
        drift_detail,
        repaired_detail,
    )
    .await;
}

/// Converge a drifted check: on `DryRun` report `drift` + the DDL; on `Apply` run each
/// statement (fail-closed on the first error) then report `repaired`. `ddl` is already
/// fully quoted + host-derived. Every executed statement is audited.
#[allow(clippy::too_many_arguments)]
async fn converge_ddl_on(
    backend: &Arc<dyn SqlBackend>,
    d: &Derived,
    check: &str,
    ddl: &[String],
    mode: RepairMode,
    report: &mut RepairReport,
    drift_detail: String,
    repaired_detail: String,
) {
    let joined = ddl.join("\n");
    match mode {
        RepairMode::DryRun => report.checks.push(RepairCheck {
            check: check.to_string(),
            status: RepairStatus::Drift,
            detail: drift_detail,
            ddl: Some(joined),
        }),
        RepairMode::Apply => {
            for stmt in ddl {
                if let Err(e) = backend.run_script(stmt).await {
                    report.checks.push(RepairCheck {
                        check: check.to_string(),
                        status: RepairStatus::Error,
                        detail: format!("converge failed at `{stmt}`: {e}"),
                        ddl: Some(joined),
                    });
                    return;
                }
            }
            audit_stmts(check, d, ddl);
            report.checks.push(RepairCheck {
                check: check.to_string(),
                status: RepairStatus::Repaired,
                detail: repaired_detail,
                ddl: Some(joined),
            });
        }
    }
}

/// Build a superuser backend to `database` (the maintenance db or the tenant db) for this
/// tenant's shared server — an `Arc<dyn SqlBackend>` so probes/converges are uniform.
async fn build_backend(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    database: &str,
) -> Result<Arc<dyn SqlBackend>, String> {
    let b = shared_admin_backend_for_db(deploy, creds, d.kind, &d.compute, &d.superuser, database)
        .await?;
    Ok(Arc::new(b) as Arc<dyn SqlBackend>)
}

// ===========================================================================
// Per-model backend builders + shared checks (dedicated-PG / MySQL / libsql / external)
// ===========================================================================

/// Why a diagnostic compute/runtime backend could not be built. `Unsealed` is the benign
/// dry-run case (the managed credential is not yet sealed and a dry-run must NOT seal it —
/// Security HIGH-1); the caller reports the dependent connectivity check as `skipped`, not
/// `error`. `Other` is a real build/connect failure.
enum BackendBuildError {
    /// Dry-run + the managed credential is not yet sealed; the dry-run did not seal it.
    Unsealed,
    /// Any other failure (endpoint unresolved, external `url_env` unset, transport, …).
    Other(String),
}

impl std::fmt::Display for BackendBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsealed => write!(
                f,
                "managed credential not yet sealed — connectivity verified after apply"
            ),
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

/// Resolve a managed credential for a diagnostic connect WITHOUT ever sealing on a dry-run
/// (Security HIGH-1). On `DryRun` this is a pure read via `get_sealed_password` (an absent
/// credential ⇒ [`BackendBuildError::Unsealed`], never create-if-absent). On `Apply` it uses
/// `password()` — an apply is the reconcile, so create-if-absent there is expected, and a
/// credential the run already sealed is simply read.
async fn resolve_diagnostic_password(
    creds: &ManagedSqlCredentials,
    cred_project: &str,
    cred_workload: &str,
    mode: RepairMode,
) -> Result<String, BackendBuildError> {
    match mode {
        RepairMode::DryRun => match creds.get_sealed_password(cred_project, cred_workload).await {
            Ok(Some(pw)) => Ok(pw),
            Ok(None) => Err(BackendBuildError::Unsealed),
            Err(e) => Err(BackendBuildError::Other(e)),
        },
        RepairMode::Apply => creds
            .password(cred_project, cred_workload)
            .await
            .map_err(BackendBuildError::Other),
    }
}

/// Build a compute-backed managed connection (a `ComputeResolvedSqlBackend`) as `user` with the
/// sealed credential keyed `(cred_project, cred_workload)` to `database` on `workload`. Used by the
/// dedicated-Postgres + managed-MySQL models. Read-only, 10s timeout — a diagnostic connection.
///
/// **Dry-run purity (Security HIGH-1).** On a `DryRun` the credential is read (never sealed): an
/// absent one returns [`BackendBuildError::Unsealed`] so the caller reports connectivity as a
/// benign `skipped`. On an `Apply` the credential is resolved via `password()` (create-if-absent
/// is the reconcile, not a dry-run leak).
#[allow(clippy::too_many_arguments)]
async fn build_compute_backend(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    kind: ExternalSqlKind,
    workload: &str,
    database: &str,
    user: &str,
    cred_project: &str,
    cred_workload: &str,
    endpoint_project: &str,
    mode: RepairMode,
) -> Result<Arc<dyn SqlBackend>, BackendBuildError> {
    use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
    let password = resolve_diagnostic_password(creds, cred_project, cred_workload, mode).await?;
    let resolver = Arc::new(DeployEndpointResolver::new(
        deploy.clone(),
        endpoint_project.to_string(),
    ));
    Ok(Arc::new(ComputeResolvedSqlBackend::new(
        resolver,
        workload,
        kind,
        database.to_string(),
        user,
        password,
        Some(1),
        true, // read-only: a diagnostic connection (never writes tenant rows)
        Some(std::time::Duration::from_secs(10)),
    )) as Arc<dyn SqlBackend>)
}

/// Build the RUNTIME connection for a MySQL binding — managed (compute + sealed credential, the
/// tenant-derived workload/db/user) or external (`url_env`). The `read_only` connection is used for
/// the runtime-grant / database / ledger probes + the connectivity `SELECT 1`.
///
/// **Dry-run purity (Security HIGH-1).** A managed binding resolves its sealed credential via
/// [`build_compute_backend`], which on a `DryRun` reads (never seals) — an unsealed credential
/// surfaces as [`BackendBuildError::Unsealed`] so the caller reports connectivity as `skipped`.
async fn build_runtime_backend(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    kind: ExternalSqlKind,
    project: &str,
    mode: RepairMode,
) -> Result<Arc<dyn SqlBackend>, BackendBuildError> {
    let compute_backed = binding.compute.as_deref().is_some_and(|c| !c.is_empty());
    if compute_backed {
        let compute = binding.compute.as_deref().unwrap_or_default();
        let database = binding_db(binding);
        let user = binding.user.as_deref().unwrap_or_default();
        let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, project, "");
        let names = tenant_names(
            binding.tenant,
            compute,
            &database,
            &tenant_ident_raw,
            is_default,
        );
        let (cred_project, cred_workload) = match binding.tenant {
            TenantIsolation::Single => (
                single_credential_project(project, is_default),
                names.workload.clone(),
            ),
            TenantIsolation::Shared => (
                boatramp_core::project::DEFAULT_PROJECT.to_string(),
                compute.to_string(),
            ),
        };
        let endpoint_project = match binding.tenant {
            TenantIsolation::Single if !is_default => project.to_string(),
            _ => boatramp_core::project::DEFAULT_PROJECT.to_string(),
        };
        build_compute_backend(
            deploy,
            creds,
            kind,
            &names.workload,
            &names.database,
            user,
            &cred_project,
            &cred_workload,
            &endpoint_project,
            mode,
        )
        .await
    } else {
        build_external_backend(binding, kind).map_err(|e| BackendBuildError::Other(e.to_string()))
    }
}

/// Build a bring-your-own (`url_env`) connection for `binding` of `kind` — reads the runtime DSN
/// from the environment (never operator-file input) and connects `read_only`. The credential stays
/// on the node, as with every other `sql` connection.
fn build_external_backend(
    binding: &ExternalDatabaseConfig,
    kind: ExternalSqlKind,
) -> Result<Arc<dyn SqlBackend>, SqlError> {
    use boatramp_storage::sql_sqlx::{connect, ExternalSqlOptions};
    if binding.url_env.is_empty() {
        return Err(SqlError::other(
            "external binding has no `url_env` set".to_string(),
        ));
    }
    let url = std::env::var(&binding.url_env)
        .map_err(|_| SqlError::other(format!("env var {} (url) is unset", binding.url_env)))?;
    let timeout = binding
        .connect_timeout_secs
        .map(std::time::Duration::from_secs);
    let opts = ExternalSqlOptions::new(url)
        .with_max_connections(Some(1))
        .read_only(true)
        .with_connect_timeout(timeout);
    connect(kind, &opts)
}

/// A read-only credential-presence check (`is_sealed`, never `password()`/`put` — dry-run safe).
/// On an apply it seals (create-if-absent) the credential; on a dry-run it only reports.
async fn check_credential_sealed(
    creds: &ManagedSqlCredentials,
    cred_project: &str,
    cred_workload: &str,
    mode: RepairMode,
    check: &str,
    report: &mut RepairReport,
) {
    let sealed = match creds.is_sealed(cred_project, cred_workload).await {
        Ok(v) => v,
        Err(e) => {
            report.checks.push(error_check(
                check,
                format!("could not probe the sealed credential: {e}"),
            ));
            return;
        }
    };
    if sealed {
        report.checks.push(ok_check(
            check,
            "the sealed server credential is present in the control-plane KV",
        ));
        return;
    }
    match mode {
        RepairMode::DryRun => report.checks.push(RepairCheck {
            check: check.to_string(),
            status: RepairStatus::Drift,
            detail: "the sealed server credential is not present; apply would generate + seal it \
                     (a control-plane KV write, not SQL)"
                .to_string(),
            ddl: None,
        }),
        RepairMode::Apply => match creds.password(cred_project, cred_workload).await {
            Ok(_) => report.checks.push(RepairCheck {
                check: check.to_string(),
                status: RepairStatus::Repaired,
                detail: "generated + sealed the server credential (control-plane KV write)"
                    .to_string(),
                ddl: None,
            }),
            Err(e) => report.checks.push(error_check(
                check,
                format!("could not seal the server credential: {e}"),
            )),
        },
    }
}

/// Probe that the Postgres migrate ledger (schema `boatramp_migrations` + table
/// `schema_migrations`) exists; converge (apply only) = `CREATE SCHEMA/TABLE IF NOT EXISTS`
/// (idempotent, data-preserving — never re-owns here; the dedicated/external identity already owns
/// what it creates). A read-only existence probe on a dry-run.
async fn check_pg_ledger_exists(
    backend: &Arc<dyn SqlBackend>,
    kind: ExternalSqlKind,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let schema_lit = pg_literal(LEDGER_SCHEMA);
    let table_lit = pg_literal(LEDGER_TABLE);
    let present = match backend
        .run_query(&format!(
            "SELECT 1 FROM pg_catalog.pg_tables WHERE schemaname = {schema_lit} \
             AND tablename = {table_lit};"
        ))
        .await
    {
        Ok(rows) => !rows.rows.is_empty(),
        Err(e) => {
            report.checks.push(error_check(
                "ledger",
                format!("could not probe the migrate ledger: {e}"),
            ));
            return;
        }
    };
    if present {
        report.checks.push(ok_check(
            "ledger",
            "the migrate ledger (boatramp_migrations.schema_migrations) exists",
        ));
        return;
    }
    let schema_id = quote_ident(kind, LEDGER_SCHEMA);
    let ledger_id = format!(
        "{}.{}",
        quote_ident(kind, LEDGER_SCHEMA),
        quote_ident(kind, LEDGER_TABLE)
    );
    let ddl = vec![
        format!("CREATE SCHEMA IF NOT EXISTS {schema_id};"),
        format!(
            "CREATE TABLE IF NOT EXISTS {ledger_id} (id text PRIMARY KEY, ordinal integer NOT \
             NULL, content_hash text NOT NULL, kind text NOT NULL, applied_at timestamptz NOT \
             NULL DEFAULT now(), applied_by text);"
        ),
    ];
    converge_ledger(backend, &ddl, mode, report).await;
}

/// Probe that the MySQL migrate ledger (DATABASE `boatramp_migrations` + table
/// `schema_migrations`) exists; converge (apply only) = `CREATE DATABASE/TABLE IF NOT EXISTS`
/// (idempotent, data-preserving). Read-only existence probe on a dry-run.
async fn check_mysql_ledger_exists(runtime: &Arc<dyn SqlBackend>, report: &mut RepairReport) {
    // The RUNTIME identity has no privilege on the ledger database (by design — the ledger lives in
    // a separate database only the DDL identity owns), so a runtime-connection probe can only see
    // whether the database exists via information_schema (visible metadata), not read the table.
    let db_lit = pg_literal(LEDGER_SCHEMA);
    match runtime
        .run_query(&format!(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = {db_lit};"
        ))
        .await
    {
        Ok(rows) if !rows.rows.is_empty() => report.checks.push(ok_check(
            "ledger",
            "the migrate ledger database (boatramp_migrations) exists",
        )),
        Ok(_) => report.checks.push(RepairCheck {
            check: "ledger".to_string(),
            status: RepairStatus::Drift,
            detail: "the migrate ledger database (boatramp_migrations) does not exist; it is \
                     created by the DISTINCT DDL identity on first migrate (repair reconciles the \
                     runtime side; the ledger is created by the migrate path as the DDL identity)"
                .to_string(),
            ddl: None,
        }),
        Err(e) => report.checks.push(error_check(
            "ledger",
            format!("could not probe the migrate ledger database: {e}"),
        )),
    }
}

/// Dispatch a ledger-existence probe to the engine-appropriate check (Postgres schema.table vs
/// MySQL database) for the external model. Both are read-only probes; the Postgres converge is
/// `CREATE … IF NOT EXISTS`, the MySQL one is reported (the DDL identity creates it at migrate).
async fn check_pg_or_mysql_ledger_exists(
    backend: &Arc<dyn SqlBackend>,
    kind: ExternalSqlKind,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    match kind {
        ExternalSqlKind::Postgres => check_pg_ledger_exists(backend, kind, mode, report).await,
        ExternalSqlKind::Mysql => check_mysql_ledger_exists(backend, report).await,
    }
}

/// Run a ledger-scaffolding converge (`CREATE … IF NOT EXISTS`) or, on a dry-run, report the drift.
/// The ledger `CREATE`s are idempotent + data-preserving (never DROP/DELETE), so re-running is a
/// no-op — but a dry-run still runs nothing (purity).
async fn converge_ledger(
    backend: &Arc<dyn SqlBackend>,
    ddl: &[String],
    mode: RepairMode,
    report: &mut RepairReport,
) {
    let joined = ddl.join("\n");
    match mode {
        RepairMode::DryRun => report.checks.push(RepairCheck {
            check: "ledger".to_string(),
            status: RepairStatus::Drift,
            detail:
                "the migrate ledger is absent; apply would scaffold it (CREATE … IF NOT EXISTS)"
                    .to_string(),
            ddl: Some(joined),
        }),
        RepairMode::Apply => {
            for stmt in ddl {
                if let Err(e) = backend.run_script(stmt).await {
                    report.checks.push(RepairCheck {
                        check: "ledger".to_string(),
                        status: RepairStatus::Error,
                        detail: format!("scaffolding the ledger failed at `{stmt}`: {e}"),
                        ddl: Some(joined),
                    });
                    return;
                }
            }
            report.checks.push(RepairCheck {
                check: "ledger".to_string(),
                status: RepairStatus::Repaired,
                detail: "scaffolded the migrate ledger (CREATE … IF NOT EXISTS)".to_string(),
                ddl: Some(joined),
            });
        }
    }
}

/// Reconcile the MySQL DISTINCT DDL identity precondition — the whole point of the MySQL migrate
/// surface. Mirrors [`NodeOperatorSql::mysql_ddl_backend_for`]'s refusal logic exactly (byte +
/// `mysql_dsn_username` distinctness), but as a REPORT check (no connection): the DDL identity must
/// be configured (`migration_url_env`), present in the env, and DISTINCT from the runtime. A
/// compute-backed managed MySQL with NO derivable DDL identity is a terminal `error` — NOT a
/// silent skip (it is the same condition the migrate path refuses fail-closed).
fn check_mysql_ddl_identity(
    binding: &ExternalDatabaseConfig,
    db: &str,
    compute_backed: bool,
    report: &mut RepairReport,
) {
    // [Security review HIGH-2 parity] Compute-backed managed MySQL cannot derive a distinct
    // least-privilege DDL identity — migrate refuses it, so repair reports a terminal error too.
    if compute_backed && binding.url_env.is_empty() {
        report.checks.push(error_check(
            "ddl-identity",
            format!(
                "database {db:?}: compute-backed managed MySQL has no derivable distinct DDL \
                 identity — migrate is refused fail-closed (boatramp cannot yet auto-mint a \
                 least-privilege DDL grant); use an external MySQL binding with a distinct \
                 `migration_url_env`, or await the auto-minted DDL-grant follow-up"
            ),
        ));
        return;
    }

    let Some(migration_var) = binding
        .migration_url_env
        .as_deref()
        .filter(|v| !v.is_empty())
    else {
        report.checks.push(RepairCheck {
            check: "ddl-identity".to_string(),
            status: RepairStatus::Drift,
            detail: format!(
                "database {db:?}: MySQL migrations require a DISTINCT DDL identity — set \
                 `migration_url_env` to an admin/DDL login that is NOT the runtime `user`/`url_env` \
                 (MySQL has no owner/runtime role split; running DDL as the runtime user is refused)"
            ),
            ddl: None,
        });
        return;
    };
    let ddl_url = match std::env::var(migration_var) {
        Ok(u) => u,
        Err(_) => {
            report.checks.push(error_check(
                "ddl-identity",
                format!(
                    "env var {migration_var} (the MySQL DDL/migration url for {db:?}) is unset — \
                     the distinct DDL identity is configured but not reachable"
                ),
            ));
            return;
        }
    };
    // Distinctness vs the runtime `url_env` (byte + username), the fail-closed invariant.
    if !binding.url_env.is_empty() {
        if let Ok(runtime_url) = std::env::var(&binding.url_env) {
            if runtime_url == ddl_url {
                report.checks.push(error_check(
                    "ddl-identity",
                    format!(
                        "database {db:?}: `migration_url_env` resolves to the SAME connection as \
                         the runtime `url_env` — the DDL identity must be DISTINCT (refused)"
                    ),
                ));
                return;
            }
            #[cfg(feature = "sql-mysql")]
            {
                let ddl_user = boatramp_storage::sql_sqlx::mysql_dsn_username(&ddl_url);
                let runtime_user = boatramp_storage::sql_sqlx::mysql_dsn_username(&runtime_url);
                if let (Some(du), Some(ru)) = (&ddl_user, &runtime_user) {
                    if du == ru {
                        report.checks.push(error_check(
                            "ddl-identity",
                            format!(
                                "database {db:?}: `migration_url_env` authenticates as the SAME \
                                 MySQL user ({du:?}) as the runtime — the DDL login must be a \
                                 DISTINCT identity (refused)"
                            ),
                        ));
                        return;
                    }
                }
            }
        }
    }
    report.checks.push(ok_check(
        "ddl-identity",
        format!(
            "a distinct DDL identity is configured (`{migration_var}`) and distinct from the runtime"
        ),
    ));
}

/// Coarse probe that the MySQL runtime user has schema-level privileges on its database (any grant
/// row in `information_schema.schema_privileges` for `current_user()` on `db`). Reported only —
/// the `GRANT ALL ON <db>.*` is minted by the provision path, not repair (repair reports the drift
/// so an operator re-provisions; it never issues a GRANT).
async fn check_mysql_runtime_grant(
    runtime: &Arc<dyn SqlBackend>,
    db: &str,
    report: &mut RepairReport,
) {
    let db_lit = pg_literal(db);
    // `SCHEMA_PRIVILEGES.TABLE_SCHEMA` is the granted schema; GRANTEE is `'user'@'host'`. Match the
    // current login's schema grants for the tenant db.
    match runtime
        .run_query(&format!(
            "SELECT 1 FROM information_schema.schema_privileges \
             WHERE table_schema = {db_lit} \
               AND grantee LIKE CONCAT('''', SUBSTRING_INDEX(CURRENT_USER(), '@', 1), '''@%') \
             LIMIT 1;"
        ))
        .await
    {
        Ok(rows) if !rows.rows.is_empty() => report.checks.push(ok_check(
            "runtime-user",
            format!("the runtime user holds schema privileges on {db:?}"),
        )),
        Ok(_) => report.checks.push(RepairCheck {
            check: "runtime-user".to_string(),
            status: RepairStatus::Drift,
            detail: format!(
                "the runtime user has no visible schema-level grant on {db:?}; provisioning grants \
                 `ALL ON {db}.*` — repair reports this (it never issues a GRANT itself)"
            ),
            ddl: None,
        }),
        Err(e) => report.checks.push(error_check(
            "runtime-user",
            format!("could not probe the runtime user's schema privileges on {db:?}: {e}"),
        )),
    }
}

/// Probe that the tenant MySQL database exists (`information_schema.schemata`). Read-only; reported
/// (a managed server is created by the provision path — repair reconciles it, never `CREATE`s).
async fn check_mysql_database_exists(
    runtime: &Arc<dyn SqlBackend>,
    db: &str,
    report: &mut RepairReport,
) {
    let db_lit = pg_literal(db);
    match runtime
        .run_query(&format!(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = {db_lit};"
        ))
        .await
    {
        Ok(rows) if !rows.rows.is_empty() => report.checks.push(ok_check(
            "database",
            format!("the tenant database {db:?} exists"),
        )),
        Ok(_) => report.checks.push(RepairCheck {
            check: "database".to_string(),
            status: RepairStatus::Drift,
            detail: format!(
                "the tenant database {db:?} does not exist; provision the tenant (repair reconciles \
                 an existing server, it does not CREATE the database)"
            ),
            ddl: None,
        }),
        Err(e) => report.checks.push(error_check(
            "database",
            format!("could not probe the tenant database {db:?}: {e}"),
        )),
    }
}

/// Probe (+ apply-converge) that the libsql reserved-prefix ledger TABLE
/// `boatramp_migrations_schema_migrations` exists in the open file. Read-only probe; the apply
/// converge is `CREATE TABLE IF NOT EXISTS` (idempotent, data-preserving). Only reached when the
/// file was opened (a dry-run over a non-existent file never opens it, so this is not called then).
#[cfg(feature = "migrate")]
async fn check_libsql_ledger(
    sql: &boatramp_storage::LibsqlSql,
    mode: RepairMode,
    report: &mut RepairReport,
) {
    use boatramp_core::sql::SqlBackend;
    // The reserved-prefix ledger table name (matches the libsql migrate substrate).
    const LIBSQL_LEDGER: &str = "boatramp_migrations_schema_migrations";
    let name_lit = pg_literal(LIBSQL_LEDGER);
    let present = match sql
        .run_query(&format!(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = {name_lit};"
        ))
        .await
    {
        Ok(rows) => !rows.rows.is_empty(),
        Err(e) => {
            report.checks.push(error_check(
                "ledger",
                format!("could not probe the libsql ledger table: {e}"),
            ));
            return;
        }
    };
    if present {
        report.checks.push(ok_check(
            "ledger",
            format!("the libsql ledger table {LIBSQL_LEDGER:?} exists"),
        ));
        return;
    }
    let create = format!(
        "CREATE TABLE IF NOT EXISTS \"{LIBSQL_LEDGER}\" (id TEXT PRIMARY KEY, ordinal INTEGER NOT \
         NULL, content_hash TEXT NOT NULL, kind TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT \
         CURRENT_TIMESTAMP, applied_by TEXT);"
    );
    match mode {
        RepairMode::DryRun => report.checks.push(RepairCheck {
            check: "ledger".to_string(),
            status: RepairStatus::Drift,
            detail: format!(
                "the libsql ledger table {LIBSQL_LEDGER:?} is absent; apply would scaffold it \
                 (CREATE TABLE IF NOT EXISTS)"
            ),
            ddl: Some(create),
        }),
        RepairMode::Apply => match sql.run_script(&create).await {
            Ok(()) => report.checks.push(RepairCheck {
                check: "ledger".to_string(),
                status: RepairStatus::Repaired,
                detail: format!("scaffolded the libsql ledger table {LIBSQL_LEDGER:?}"),
                ddl: Some(create),
            }),
            Err(e) => report.checks.push(error_check(
                "ledger",
                format!("scaffolding the libsql ledger table failed: {e}"),
            )),
        },
    }
}

/// Whether a config `kind` string names the embedded libsql/SQLite engine (case-insensitive) —
/// always available (unlike `managed_sql::kind_is_libsql`, which is gated on `feature = "migrate"`),
/// so the model classifier can route a libsql binding regardless of the compiled feature set.
fn is_libsql_kind(kind: &str) -> bool {
    matches!(
        kind.trim().to_ascii_lowercase().as_str(),
        "libsql" | "sqlite" | "sqlite3"
    )
}

/// Audit every executed statement + the derived triple + maintenance identity.
fn audit_stmts(check: &str, d: &Derived, stmts: &[String]) {
    for stmt in stmts {
        tracing::info!(
            target: "boatramp::repair",
            project = %d.project,
            check = %check,
            derived_db = %d.database,
            derived_runtime_role = %d.runtime_role,
            derived_owner_role = %d.owner_role,
            maintenance_user = %d.superuser,
            statement = %stmt,
            "repair: executed converge statement"
        );
    }
}

/// Redact a password literal from an owner-role CREATE/ALTER before it lands in the report
/// `ddl` (the report is operator-visible + audited; the sealed password must not leak). The
/// `PASSWORD '…'` literal is replaced with a placeholder; the rest of the statement is intact.
fn redact_pw(stmts: &[String]) -> Vec<String> {
    stmts.iter().map(|s| redact_password_literal(s)).collect()
}

/// Replace a `PASSWORD '…'` literal (Postgres) with `PASSWORD '<redacted>'`. Case-insensitive
/// on the keyword; handles a doubled-quote escaped literal by scanning to the matching close.
fn redact_password_literal(stmt: &str) -> String {
    let upper = stmt.to_ascii_uppercase();
    let Some(kw) = upper.find("PASSWORD ") else {
        return stmt.to_string();
    };
    // Find the opening quote after the keyword.
    let after = kw + "PASSWORD ".len();
    let bytes = stmt.as_bytes();
    let Some(open_rel) = stmt[after..].find('\'') else {
        return stmt.to_string();
    };
    let open = after + open_rel;
    // Scan for the closing quote (a doubled '' is an escaped quote, not a close).
    let mut i = open + 1;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            break;
        }
        i += 1;
    }
    let close = i.min(bytes.len().saturating_sub(1));
    format!(
        "{}'<redacted>'{}",
        &stmt[..open],
        &stmt[(close + 1).min(stmt.len())..]
    )
}

/// Report a probe error uniformly.
fn report_probe_err(report: &mut RepairReport, check: &str, e: SqlError) {
    report
        .checks
        .push(error_check(check, format!("probe failed: {e}")));
}

// ===========================================================================
// Backend / topology classification + report scaffolding
// ===========================================================================

/// The backend/topology class label for the report header — names the ENGINE + topology so a
/// per-model report is self-explaining. Keyed on the same classification the dispatch uses:
/// `shared-postgres` / `single-postgres` for compute-backed Postgres, `mysql` (managed or
/// external — the model is one), `libsql` for a libsql/SQLite binding, `external` for a
/// bring-your-own Postgres or an unknown engine.
fn classify_backend(binding: &ExternalDatabaseConfig) -> String {
    let compute_backed = binding.compute.as_deref().is_some_and(|c| !c.is_empty());
    match ExternalSqlKind::parse(&binding.kind) {
        Some(ExternalSqlKind::Postgres) if compute_backed => {
            let iso = match binding.tenant {
                TenantIsolation::Shared => "shared",
                TenantIsolation::Single => "single",
            };
            format!("{iso}-postgres")
        }
        Some(ExternalSqlKind::Postgres) => "external".to_string(),
        Some(ExternalSqlKind::Mysql) => "mysql".to_string(),
        None if is_libsql_kind(&binding.kind) => "libsql".to_string(),
        None => "external".to_string(),
    }
}

/// The binding's configured base database name (defaulting empty).
fn binding_db(binding: &ExternalDatabaseConfig) -> String {
    binding.database.as_deref().unwrap_or_default().to_string()
}

/// The maintenance database for the engine (Postgres `postgres`).
fn maintenance_db(kind: ExternalSqlKind) -> &'static str {
    match kind {
        ExternalSqlKind::Postgres => "postgres",
        ExternalSqlKind::Mysql => "mysql",
    }
}

/// An empty report with the header (`tenant`/`backend`/`mode`) filled — the tenant is
/// overwritten by the caller with the derived name once known.
fn base_report(
    binding: &ExternalDatabaseConfig,
    project: &str,
    backend_class: &str,
    mode: RepairMode,
) -> RepairReport {
    RepairReport {
        tenant: format!("{}@{}", binding_db(binding), project),
        backend: backend_class.to_string(),
        mode: mode.as_str().to_string(),
        checks: Vec::new(),
    }
}

/// An `ok` check with a detail (the probe found the invariant already satisfied).
fn ok_check(check: &str, detail: impl Into<String>) -> RepairCheck {
    RepairCheck {
        check: check.to_string(),
        status: RepairStatus::Ok,
        detail: detail.into(),
        ddl: None,
    }
}

/// A `skipped` check with a reason.
fn skip_check(check: &str, detail: impl Into<String>) -> RepairCheck {
    RepairCheck {
        check: check.to_string(),
        status: RepairStatus::Skipped,
        detail: detail.into(),
        ddl: None,
    }
}

/// An `error` check with a reason.
fn error_check(check: &str, detail: impl Into<String>) -> RepairCheck {
    RepairCheck {
        check: check.to_string(),
        status: RepairStatus::Error,
        detail: detail.into(),
        ddl: None,
    }
}

// ===========================================================================
// Probes (read-only — safe on a dry-run)
// ===========================================================================

/// The live-vs-soft-deleted state of the derived database name.
enum LiveState {
    /// The exact derived database exists.
    Live,
    /// Only a `<db>__deleted_<ts>` soft-deleted sibling exists (recover first).
    SoftDeletedOnly,
    /// Neither exists — never provisioned.
    Absent,
}

/// Probe whether the EXACT derived database exists (`==`), and — only if it doesn't —
/// whether a soft-deleted sibling `<db>__deleted_%` does. The live check is exact-equality
/// (never `LIKE`); the sibling check uses a bounded, `_`-escaped `LIKE` ONLY to distinguish
/// "soft-deleted, recover first" from "never provisioned".
async fn probe_live_or_soft_deleted(
    maint: &Arc<dyn SqlBackend>,
    d: &Derived,
) -> Result<LiveState, SqlError> {
    let db_lit = pg_literal(&d.database);
    let exact = maint
        .run_query(&format!(
            "SELECT 1 FROM pg_database WHERE datname = {db_lit};"
        ))
        .await?;
    if !exact.rows.is_empty() {
        return Ok(LiveState::Live);
    }
    let prefix_lit = pg_literal(&format!("{}__deleted\\_%", d.database));
    let sibling = maint
        .run_query(&format!(
            "SELECT 1 FROM pg_database WHERE datname LIKE {prefix_lit} ESCAPE '\\';"
        ))
        .await?;
    if !sibling.rows.is_empty() {
        Ok(LiveState::SoftDeletedOnly)
    } else {
        Ok(LiveState::Absent)
    }
}

/// Whether the CURRENT connection identity is a superuser.
async fn probe_current_user_superuser(maint: &Arc<dyn SqlBackend>) -> Result<bool, SqlError> {
    let rows = maint
        .run_query("SELECT rolsuper FROM pg_roles WHERE rolname = current_user;")
        .await?;
    Ok(rows
        .rows
        .first()
        .and_then(|r| r.first())
        .map(sql_bool)
        .unwrap_or(false))
}

/// The current database name (guards `REASSIGN OWNED` — must equal the derived tenant db).
async fn probe_current_database(backend: &Arc<dyn SqlBackend>) -> Result<String, SqlError> {
    let rows = backend.run_query("SELECT current_database();").await?;
    Ok(rows
        .rows
        .first()
        .and_then(|r| r.first())
        .map(sql_text)
        .unwrap_or_default())
}

/// Whether a role exists — keyed on the EXACT derived name (`=`) and EXCLUDING a disabled
/// (`NOLOGIN`) soft-deleted sibling (the owner/runtime role always has LOGIN; a NOLOGIN role
/// of the same name is a deprovision artifact).
async fn probe_role_exists(maint: &Arc<dyn SqlBackend>, role: &str) -> Result<bool, SqlError> {
    let role_lit = pg_literal(role);
    let rows = maint
        .run_query(&format!(
            "SELECT 1 FROM pg_roles WHERE rolname = {role_lit} AND rolcanlogin;"
        ))
        .await?;
    Ok(!rows.rows.is_empty())
}

/// Extract a bool from a `SqlValue` (Postgres returns `Boolean`; be lenient on Integer/Text).
fn sql_bool(v: &SqlValue) -> bool {
    match v {
        SqlValue::Boolean(b) => *b,
        SqlValue::Integer(n) => *n != 0,
        SqlValue::Text(s) => matches!(s.as_str(), "t" | "true" | "TRUE" | "1"),
        _ => false,
    }
}

/// Extract an `i64` from a `SqlValue` (Postgres `count(*)::bigint` → `Integer`; be lenient on a
/// text-decoded numeric). A non-numeric value returns `1` — a conservative "assume drift" for the
/// runtime-grants table-count probe, so an unparsable count never silently reads as fully-granted.
fn sql_i64(v: &SqlValue) -> i64 {
    match v {
        SqlValue::Integer(n) => *n,
        SqlValue::Text(s) => s.trim().parse::<i64>().unwrap_or(1),
        SqlValue::Real(f) => *f as i64,
        _ => 1,
    }
}

/// Extract text from a `SqlValue` (best-effort).
fn sql_text(v: &SqlValue) -> String {
    match v {
        SqlValue::Text(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// A single-quoted Postgres string literal (doubling embedded `'`). Used only for probe
/// literals; every emitted IDENTIFIER goes through [`quote_ident`].
fn pg_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests;
