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
//! - **Dry-run purity.** A dry-run runs only read-only probes (`SELECT …`, `is_sealed`);
//!   it emits no DDL and no KV write.
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

use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use crate::managed_sql::ManagedSqlCredentials;
use crate::tenant_sql::{
    owner_credential_workload_key, shared_admin_backend_for_db, tenant_key, tenant_names,
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

/// The top-level orchestrator. Resolves the tenant identity + backend class, gates on
/// topology/engine, then runs the 9 shared-Postgres checks. Returns a full report even
/// when drift is found or a check errors; an `Err` is only for a run that could not
/// produce a report at all.
pub async fn repair_tenant(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    binding: &ExternalDatabaseConfig,
    db_binding_name: &str,
    project: &str,
    mode: RepairMode,
) -> Result<RepairReport, RepairError> {
    let backend_class = classify_backend(binding);
    let compute = binding.compute.as_deref().filter(|c| !c.is_empty());
    let kind = ExternalSqlKind::parse(&binding.kind);

    // Not shared-Postgres → the owner model does not apply. Report the topology as one
    // skipped-with-reason check; the op still exits 0.
    let (Some(compute), Some(ExternalSqlKind::Postgres)) = (compute, kind) else {
        return Ok(topology_skipped_report(binding, project, &backend_class));
    };
    if !matches!(binding.tenant, TenantIsolation::Shared) {
        return Ok(topology_skipped_report(binding, project, &backend_class));
    }

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
    check_connectivity(deploy, creds, d, report).await;
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

    // Enumerate non-owner objects. `relowner`/`proowner` → role name; count those owned by
    // the derived runtime role vs the current-user superuser vs anyone else.
    let owner_lit = pg_literal(&d.owner_role);
    let non_owner = match tenant
        .run_query(&format!(
            "SELECT n.nspname, c.relname, pg_catalog.pg_get_userbyid(c.relowner) AS owner \
             FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname NOT IN ('pg_catalog','information_schema') \
               AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' \
               AND c.relkind IN ('r','p','S','v','m') \
               AND pg_catalog.pg_get_userbyid(c.relowner) <> {owner_lit} \
             UNION ALL \
             SELECT n.nspname, p.proname, pg_catalog.pg_get_userbyid(p.proowner) AS owner \
             FROM pg_catalog.pg_proc p \
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname NOT IN ('pg_catalog','information_schema') \
               AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' \
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
    // We build the converge from the DERIVED runtime role + the enumerated object names, never
    // feeding the probe's *owner* string back into a REASSIGN.
    let mut ddl: Vec<String> = Vec::new();
    let mut runtime_owned = 0usize;
    let mut other_owned = 0usize;
    for row in &non_owner.rows {
        let schema = row.first().map(sql_text).unwrap_or_default();
        let name = row.get(1).map(sql_text).unwrap_or_default();
        let owner = row.get(2).map(sql_text).unwrap_or_default();
        if owner == d.runtime_role {
            runtime_owned += 1;
        } else {
            other_owned += 1;
            // Targeted re-own. We can't cheaply tell a table from a sequence/function here in a
            // portable way; `ALTER TABLE` covers tables/views/matviews, and we emit sequence +
            // function variants too, all `IF EXISTS`-guarded so a wrong-kind ALTER is a harmless
            // no-op. The NAMES are the enumerated actual objects; the target is the DERIVED owner.
            let qname = format!(
                "{}.{}",
                quote_ident(d.kind, &schema),
                quote_ident(d.kind, &name)
            );
            let owner_id = quote_ident(d.kind, &d.owner_role);
            ddl.push(format!(
                "ALTER TABLE IF EXISTS {qname} OWNER TO {owner_id};"
            ));
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

    let drift_detail = format!(
        "{runtime_owned} runtime-owned + {other_owned} superuser-owned object(s) are not owned by \
         {:?}; would re-own them to it",
        d.owner_role
    );
    let repaired_detail = format!(
        "re-owned {runtime_owned} runtime-owned + {other_owned} superuser-owned object(s) to {:?}",
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

/// Re-run the idempotent `grant_app_role_ddl` inside the tenant db (grants the runtime
/// role app DML on `public` + sets `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`). Idempotent,
/// so on an apply we always (re-)assert; the probe here is coarse — we report `ok` when a
/// representative table privilege is present, else `drift`, but the converge is safe to run
/// regardless (it never revokes).
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
    // Coarse probe: does the runtime role have USAGE on `public`? (A cheap, representative
    // signal; the converge is idempotent so a false "drift" only re-asserts safe grants.)
    let runtime_lit = pg_literal(&d.runtime_role);
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
    let ddl = grant_app_role_ddl(d.kind, &d.runtime_role, &d.owner_role);
    if has_usage {
        report.checks.push(RepairCheck {
            check: "runtime-grants".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "runtime role {:?} has app privileges on public (owner-keyed default privileges \
                 assumed present)",
                d.runtime_role
            ),
            ddl: None,
        });
        return;
    }
    converge_ddl_on(
        &tenant,
        d,
        "runtime-grants",
        &ddl,
        mode,
        report,
        format!(
            "runtime role {:?} lacks app privileges on public; would (re-)grant DML + set \
             owner-keyed default privileges",
            d.runtime_role
        ),
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
/// read-only probe (a trivial `SELECT 1`) as each identity. Reports `ok` / `error`; never a
/// converge (it is a diagnostic). Runs in both modes (a dry-run wants the same signal).
async fn check_connectivity(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    report: &mut RepairReport,
) {
    let owner_cred_workload = owner_credential_workload_key(&d.compute, &d.ident);
    let owner_ok = probe_role_can_connect(
        deploy,
        creds,
        d,
        &d.owner_role,
        &d.project,
        &owner_cred_workload,
    )
    .await;
    let runtime_cred_workload = crate::tenant_sql::credential_workload_key(&d.compute, &d.ident);
    let runtime_ok = probe_role_can_connect(
        deploy,
        creds,
        d,
        &d.runtime_role,
        &d.project,
        &runtime_cred_workload,
    )
    .await;

    match (owner_ok, runtime_ok) {
        (Ok(true), Ok(true)) => report.checks.push(RepairCheck {
            check: "connectivity".to_string(),
            status: RepairStatus::Ok,
            detail: format!(
                "both the owner ({:?}) and runtime ({:?}) roles connect to {:?}",
                d.owner_role, d.runtime_role, d.database
            ),
            ddl: None,
        }),
        (owner, runtime) => {
            let mut parts = Vec::new();
            match owner {
                Ok(true) => {}
                Ok(false) => parts.push(format!("owner role {:?} could not connect", d.owner_role)),
                Err(e) => parts.push(format!("owner-connect probe failed: {e}")),
            }
            match runtime {
                Ok(true) => {}
                Ok(false) => parts.push(format!(
                    "runtime role {:?} could not connect",
                    d.runtime_role
                )),
                Err(e) => parts.push(format!("runtime-connect probe failed: {e}")),
            }
            report
                .checks
                .push(error_check("connectivity", parts.join("; ")));
        }
    }
}

/// Try a `SELECT 1` connecting to the tenant db as `role` with its sealed credential (the
/// credential must already exist — a repair apply that sealed it makes this pass). Returns
/// `Ok(true)` on a successful trivial query, `Ok(false)` on a clean auth-style refusal, or
/// `Err` on a transport/other error.
async fn probe_role_can_connect(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    d: &Derived,
    role: &str,
    cred_project: &str,
    cred_workload: &str,
) -> Result<bool, String> {
    use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
    let password = match creds.password(cred_project, cred_workload).await {
        Ok(pw) => pw,
        // Missing credential (never sealed) ⇒ can't connect, but that's a "false" not a hard err.
        Err(_) => return Ok(false),
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
        Ok(_) => Ok(true),
        Err(SqlError::Unavailable(m)) => Err(m),
        // An auth/permission refusal is a clean "no"; a transport error is an Err.
        Err(e) => {
            let msg = e.to_string().to_ascii_lowercase();
            if msg.contains("password") || msg.contains("authentication") || msg.contains("denied")
            {
                Ok(false)
            } else {
                Err(e.to_string())
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

/// The backend/topology class label for the report header + skip reasons.
fn classify_backend(binding: &ExternalDatabaseConfig) -> String {
    let engine = match ExternalSqlKind::parse(&binding.kind) {
        Some(ExternalSqlKind::Postgres) => "postgres",
        Some(ExternalSqlKind::Mysql) => "mysql",
        None => "libsql",
    };
    let iso = match binding.tenant {
        TenantIsolation::Shared => "shared",
        TenantIsolation::Single => "single",
    };
    if binding.compute.as_deref().is_some_and(|c| !c.is_empty()) {
        format!("{iso}-{engine}")
    } else {
        "external".to_string()
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

/// The report for a topology/engine the owner-model repair does not apply to: a single
/// `topology` check with a `skipped` reason. The op exits 0.
fn topology_skipped_report(
    binding: &ExternalDatabaseConfig,
    project: &str,
    backend_class: &str,
) -> RepairReport {
    let mut report = base_report(binding, project, backend_class, RepairMode::DryRun);
    let reason = match (
        ExternalSqlKind::parse(&binding.kind),
        binding.tenant,
        binding.compute.as_deref().filter(|c| !c.is_empty()),
    ) {
        (Some(ExternalSqlKind::Postgres), TenantIsolation::Single, Some(_)) => {
            "single/dedicated Postgres: the container is the isolation boundary (no role model); \
             the owner-model checks are not applicable"
        }
        (Some(ExternalSqlKind::Mysql), _, _) => {
            "MySQL: the three-identity owner model is Postgres-only; nothing to reconcile"
        }
        (None, _, _) | (_, _, None) => {
            "not a compute-backed managed Postgres binding (bring-your-own / libsql): the owner \
             model does not apply"
        }
        _ => "not a shared-Postgres owner-model tenant; nothing to reconcile",
    };
    report.checks.push(skip_check("topology", reason));
    report
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
