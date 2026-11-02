//! Ownership-safe **per-replica DYNAMIC** managed-database credentials — the node-side
//! lifecycle for PLAN-compute-managed-db **phase 2**.
//!
//! Phase 1 (on `feat/compute-managed-db-dsn`) injects a real `postgres://`/`mysql://` DSN
//! into a compute workload's environment from a STATIC managed role. Phase 2 swaps that
//! static role for a credential that is **minted per REPLICA at launch and dropped at
//! stop** — without the Postgres object-ownership orphaning that breaks schema management
//! across rotations. The pure, engine-level SQL + name derivation (and its live
//! ownership-safety proof) live in
//! [`boatramp_storage::tenant_provision`]; this module is the node-side executor that
//! resolves the tenant, seals the ephemeral credential, and runs the mint/drop DDL against
//! the live managed server over the SAME superuser path
//! [`provision_shared`](crate::tenant_sql) uses.
//!
//! # The ownership-safe model (verified live on pg16 — see the gate)
//!
//! The STABLE, boatramp-managed per-tenant **owner role**
//! ([`tenant_owner_role_name`](boatramp_storage::tenant_provision::tenant_owner_role_name)),
//! created at DB-provision time and NEVER dropped, owns the tenant database + all its
//! objects. The per-replica dynamic role is minted as a **member of that owner** and
//! configured to **operate AS the owner** (`ALTER ROLE <dyn> SET role = '<owner>'`), so
//! everything it creates is owned by the stable owner and the dynamic role owns nothing.
//! On stop it is dropped with `REASSIGN OWNED … TO <owner>` (a safety net for a GUC escape)
//! → `DROP OWNED` → `DROP ROLE`, which is clean precisely because it owns nothing. MySQL
//! has no object ownership, so its dynamic user is grant-based (`GRANT ALL ON <db>.*`) and
//! `DROP USER` is clean with nothing to orphan.
//!
//! # Scope (phase 2)
//!
//! Only a **Shared** (one server, per-tenant database + roles), **non-default**,
//! compute-backed managed binding has the owner-role model this builds on, so phase 2
//! applies there and [`mint_dynamic_role`] / [`revoke_dynamic_role`] return `None` (no-op)
//! for every other cell — a bring-your-own `url_env` binding, the reserved `default` tenant
//! (its plain configured user already owns its one ordinary database), and `Single`
//! isolation (a dedicated per-tenant container; its own user is the owner). Phase 1 falls
//! back to the static per-tenant credential there. The tenant is derived from the
//! **consumer's own project** (the replica's `(project, …)` identity — never a request
//! field), so a replica can only ever mint a role on its own tenant's database.
//!
//! # The phase-1 seam
//!
//! [`mint_dynamic_role`] seals the ephemeral password under a per-replica KV key
//! ([`dynamic_cred_workload_key`]) and returns a [`DynamicDbCredential`]; phase 1 builds
//! the DSN from it (or reads it back later with [`resolve_dynamic_credential`], which never
//! mints). Phase 2 owns the credential's LIFECYCLE (mint-on-launch, revoke-on-stop, keyed
//! by [`compute_instance_id`](boatramp_core::compute::compute_instance_id)); phase 1 owns
//! the DSN templating. The two touch no shared file beyond this documented seam.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::DEFAULT_PROJECT;
use boatramp_core::sql::SqlBackend;
use boatramp_storage::ExternalSqlKind;
use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
use boatramp_storage::tenant_provision::{
    drop_dynamic_role_ddl, dynamic_role_name, mint_dynamic_role_ddl, sanitize_ident,
};

use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use crate::managed_sql::{DeployEndpointResolver, ManagedSqlCredentials};
use crate::tenant_sql::{maintenance_database, tenant_key, tenant_names};

/// The ephemeral, per-replica credential phase 2 minted — the input phase 1 builds the
/// DSN from (host/port come from the existing endpoint resolver phase 1 already uses; this
/// carries only the parts phase 2 owns).
#[derive(Clone, PartialEq, Eq)]
pub struct DynamicDbCredential {
    /// The engine (so phase 1 picks `postgres://` vs `mysql://`).
    pub kind: ExternalSqlKind,
    /// The tenant's physical database the role is scoped to.
    pub database: String,
    /// The per-replica dynamic role / user name to connect as.
    pub role: String,
    /// The role's fresh login password (hex). Ephemeral: deleted on
    /// [`revoke_dynamic_role`]. REDACTED by `Debug` (LOW-1) — do not derive `Debug`.
    pub password: String,
}

/// Hand-written `Debug` that REDACTS the cleartext password, matching the codebase
/// convention (`boatramp_core::registry_auth::RegistryCredential`,
/// `managed_db_declare`'s error redaction). A `{:?}` of this struct — in a log line, a
/// `tracing` field, a boxed error chain — must never surface the sealed login secret.
impl std::fmt::Debug for DynamicDbCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicDbCredential")
            .field("kind", &self.kind)
            .field("database", &self.database)
            .field("role", &self.role)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// The KV **workload** segment for a per-replica dynamic credential: the
/// [`credential_workload_key`](crate::tenant_sql) scheme (`<compute>/<tenant_ident>`) with a
/// trailing `/dyn/<instance_id>`, so a dynamic password is sealed under a key distinct from
/// the runtime-role (`<compute>/<ident>`), owner-role (`<compute>/<ident>/owner`), and
/// superuser (`<compute>` under the default project) credentials — and distinct PER REPLICA.
/// `instance_id` is the replica identity
/// ([`compute_instance_id`](boatramp_core::compute::compute_instance_id)).
pub(crate) fn dynamic_cred_workload_key(
    compute: &str,
    tenant_ident: &str,
    instance_id: &str,
) -> String {
    format!("{compute}/{tenant_ident}/dyn/{instance_id}")
}

/// The facts parsed back out of a **full** sealed dynamic-cred KV key
/// (`managed-sql-cred/<consumer_project>/<compute>/<tenant_ident>/dyn/<instance_id>` — the
/// [`ManagedSqlCredentials`](crate::managed_sql::ManagedSqlCredentials) prefix followed by a
/// [`dynamic_cred_workload_key`]). The inverse of how the key is built, for the orphan sweep:
/// `instance_id` decides whether the owning replica is still live, and
/// `consumer_project` + `compute` rebuild the revoke target.
pub(crate) struct ParsedDynCredKey {
    pub consumer_project: String,
    pub compute: String,
    pub tenant_ident: String,
    pub instance_id: String,
}

/// Parse a full `managed-sql-cred/…` key, returning `Some` ONLY for a per-replica DYNAMIC
/// credential key (exactly `<project>/<compute>/<tenant_ident>/dyn/<instance_id>` after the
/// prefix). Every other sealed credential — the runtime role (`<proj>/<compute>`), the owner
/// role (`…/owner`), the superuser (`default/<compute>`), or a workload literally named
/// `dyn` — has a different segment count / shape and returns `None`, so the sweep can never
/// touch a persistent credential. All segments are `/`-free by construction (resource names
/// are `[a-z0-9-]`, the tenant ident is sanitized, the instance id carries no `/`).
pub(crate) fn parse_dynamic_cred_key(key: &str) -> Option<ParsedDynCredKey> {
    let rest = key.strip_prefix(crate::managed_sql::ManagedSqlCredentials::CRED_PREFIX)?;
    // [consumer_project, compute, tenant_ident, "dyn", instance_id]
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 5 || parts[3] != "dyn" || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(ParsedDynCredKey {
        consumer_project: parts[0].to_string(),
        compute: parts[1].to_string(),
        tenant_ident: parts[2].to_string(),
        instance_id: parts[4].to_string(),
    })
}

/// The derived facts phase 2 needs for one `(binding, consumer_project, instance_id)`, or
/// `None` when phase 2 does not apply (see the module scope note). Pure + synchronous so the
/// no-op gating is unit-testable without IO; [`mint_dynamic_role`] / [`revoke_dynamic_role`]
/// / [`resolve_dynamic_credential`] all derive through it so their targets can never drift.
struct DynTarget {
    kind: ExternalSqlKind,
    /// The shared server workload (base for the role family + the superuser credential).
    compute: String,
    /// The binding's superuser login name (runs the mint/drop DDL).
    superuser: String,
    /// The tenant's physical database.
    database: String,
    /// The stable per-tenant owner role (the dynamic role operates AS this).
    owner_role: String,
    /// The per-replica dynamic role name.
    dyn_role: String,
    /// The KV project scope for the ephemeral credential (the consumer's project).
    cred_project: String,
    /// The KV workload key for the ephemeral credential.
    cred_workload: String,
}

/// Resolve [`DynTarget`] for a managed binding consumed by a replica in `consumer_project`,
/// or `None` when phase 2 does not apply (bring-your-own `url_env`, unparsable engine, the
/// reserved `default` tenant, or non-`Shared` isolation; a `Site`-scoped binding has no
/// single compute-consumer tenant, so it is also out of scope — a decision to confirm).
fn resolve_target(
    binding: &ExternalDatabaseConfig,
    consumer_project: &str,
    instance_id: &str,
) -> Option<DynTarget> {
    let compute = binding.compute.as_deref().filter(|c| !c.is_empty())?;
    let kind = ExternalSqlKind::parse(&binding.kind)?;
    // Phase 2 builds on the Shared owner-role model only.
    if binding.tenant != TenantIsolation::Shared {
        return None;
    }
    // A compute consumer's tenant is its own project; site-scoped bindings are out of scope.
    if binding.tenant_scope != TenantScope::Project {
        return None;
    }
    let database = binding.database.as_deref().unwrap_or_default();
    let superuser = binding.user.as_deref().unwrap_or_default().to_string();

    let (tenant_ident_raw, is_default) = tenant_key(binding.tenant_scope, consumer_project, "");
    // The reserved default tenant has no per-tenant owner role (its plain user owns its one
    // ordinary database) — phase 2 does not apply; phase 1 uses the plain static credential.
    if is_default {
        return None;
    }
    let names = tenant_names(
        binding.tenant,
        compute,
        database,
        &tenant_ident_raw,
        is_default,
    );
    let tenant_ident = sanitize_ident(&tenant_ident_raw);
    let dyn_role = dynamic_role_name(compute, &tenant_ident, instance_id);
    Some(DynTarget {
        kind,
        compute: compute.to_string(),
        superuser,
        database: names.database,
        owner_role: names.owner_role,
        dyn_role,
        cred_project: consumer_project.to_string(),
        cred_workload: dynamic_cred_workload_key(compute, &tenant_ident, instance_id),
    })
}

/// Build the superuser backend for a Shared server connected to `database` — the same
/// endpoint-resolving, same sealed superuser credential (`<compute>` under the reserved
/// default project) [`provision_shared`](crate::tenant_sql) uses. Mint connects to the
/// maintenance database; revoke connects to the tenant database (where `REASSIGN`/`DROP
/// OWNED` must run).
async fn superuser_backend(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    t: &DynTarget,
    database: &str,
) -> Result<ComputeResolvedSqlBackend, String> {
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, &t.compute)
        .await
        .map_err(|e| format!("superuser credential ({}): {e}", t.compute))?;
    let resolver = Arc::new(DeployEndpointResolver::new_ungated(
        deploy.clone(),
        DEFAULT_PROJECT,
    ));
    Ok(ComputeResolvedSqlBackend::new(
        resolver,
        t.compute.as_str(),
        t.kind,
        database,
        t.superuser.as_str(),
        superuser_pw,
        Some(1),
        false,
        Some(Duration::from_secs(10)),
    ))
}

/// Whether a drop-DDL error is a benign "role does not exist" — tolerated on the
/// `REASSIGN OWNED` / `DROP OWNED` statements so revoking an already-gone dynamic role is a
/// no-op (idempotent), exactly the contract
/// [`drop_dynamic_role_ddl`](boatramp_storage::tenant_provision::drop_dynamic_role_ddl)
/// documents. `DROP ROLE IF EXISTS` never errors on absence.
fn is_missing_role_error(err: &str) -> bool {
    let m = err.to_ascii_lowercase();
    m.contains("does not exist") && m.contains("role")
}

/// **Mint** this replica's per-replica dynamic credential: seal a fresh ephemeral password
/// and run the ownership-safe mint DDL against the live managed server (as the superuser, on
/// the maintenance database). Returns `Some(cred)` after minting, or `None` when phase 2
/// does not apply (see the module scope note) — phase 1 then falls back to the static
/// credential. **Idempotent within a launch cycle**: the ephemeral password is sealed
/// under the per-replica KV key and reused until [`revoke_dynamic_role`] deletes it, so a
/// re-run (a reconcile that re-launches) resyncs the same role+password rather than churning
/// it; a fresh launch after a stop gets a fresh password.
pub async fn mint_dynamic_role(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    consumer_project: &str,
    instance_id: &str,
) -> Result<Option<DynamicDbCredential>, String> {
    let Some(t) = resolve_target(binding, consumer_project, instance_id) else {
        return Ok(None);
    };
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // Fresh (per launch cycle) ephemeral password, sealed under the per-replica key.
    let dyn_pw = creds
        .password(&t.cred_project, &t.cred_workload)
        .await
        .map_err(|e| format!("dynamic credential ({}): {e}", t.dyn_role))?;

    // Run the mint DDL as the superuser on the maintenance database (CREATE ROLE / GRANT /
    // ALTER ROLE SET role / GRANT CONNECT are all cluster-global or shared-object, so none
    // needs a connection to the tenant database itself).
    let admin = superuser_backend(deploy, &creds, &t, maintenance_database(t.kind)).await?;
    for stmt in mint_dynamic_role_ddl(t.kind, &t.database, &t.owner_role, &t.dyn_role, &dyn_pw) {
        admin
            .run_script(&stmt)
            .await
            .map_err(|e| format!("mint dynamic role {}: {e}", t.dyn_role))?;
    }

    Ok(Some(DynamicDbCredential {
        kind: t.kind,
        database: t.database,
        role: t.dyn_role,
        password: dyn_pw,
    }))
}

/// **Revoke** this replica's dynamic credential: run the clean-drop DDL (`REASSIGN OWNED …
/// TO <owner>` → `DROP OWNED` → `DROP ROLE`) as the superuser **connected to the tenant
/// database** (where the role's privileges + any escaped objects live), then delete the
/// sealed ephemeral password. Idempotent: a `No`-target binding, an already-gone role, and
/// an already-deleted credential are all no-ops, so a re-run (or a revoke of a replica that
/// never minted) is harmless — which also makes it safe to call from the orphan reaper.
pub async fn revoke_dynamic_role(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    consumer_project: &str,
    instance_id: &str,
) -> Result<(), String> {
    let Some(t) = resolve_target(binding, consumer_project, instance_id) else {
        return Ok(());
    };
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // Connect to the TENANT database: REASSIGN/DROP OWNED are database-local; DROP ROLE runs
    // fine from that same connection.
    let admin = superuser_backend(deploy, &creds, &t, &t.database).await?;
    for stmt in drop_dynamic_role_ddl(t.kind, &t.dyn_role, &t.owner_role) {
        if let Err(e) = admin.run_script(&stmt).await {
            let msg = e.to_string();
            // Tolerate "role does not exist" on REASSIGN/DROP OWNED (already gone) — the
            // idempotency contract; every other failure is surfaced.
            if is_missing_role_error(&msg) {
                continue;
            }
            return Err(format!("revoke dynamic role {}: {msg}", t.dyn_role));
        }
    }

    // Delete the sealed ephemeral password so a relaunch mints a fresh one (idempotent).
    creds
        .delete(&t.cred_project, &t.cred_workload)
        .await
        .map_err(|e| format!("delete dynamic credential ({}): {e}", t.dyn_role))?;
    Ok(())
}

/// Read back a previously-minted dynamic credential **without minting** — the phase-1
/// DSN-injection seam. Returns `Some(cred)` if [`mint_dynamic_role`] has sealed one for this
/// replica, `None` if not yet minted or phase 2 does not apply (a provably side-effect-free
/// `kv.get`/unseal only — never create-if-absent, so it is safe on any read path).
pub async fn resolve_dynamic_credential(
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    consumer_project: &str,
    instance_id: &str,
) -> Result<Option<DynamicDbCredential>, String> {
    let Some(t) = resolve_target(binding, consumer_project, instance_id) else {
        return Ok(None);
    };
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let Some(pw) = creds
        .get_sealed_password(&t.cred_project, &t.cred_workload)
        .await
        .map_err(|e| format!("resolve dynamic credential ({}): {e}", t.dyn_role))?
    else {
        return Ok(None);
    };
    Ok(Some(DynamicDbCredential {
        kind: t.kind,
        database: t.database,
        role: t.dyn_role,
        password: pw,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TenantIsolation, TenantScope};

    fn shared_pg_binding() -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: "postgres".to_string(),
            compute: Some("pg".to_string()),
            database: Some("appdb".to_string()),
            user: Some("postgres".to_string()),
            tenant: TenantIsolation::Shared,
            tenant_scope: TenantScope::Project,
            ..ExternalDatabaseConfig::default()
        }
    }

    /// LOW-1: the credential's `Debug` REDACTS the cleartext password (a `{:?}` in a log line
    /// / `tracing` field must never surface the sealed login secret), while keeping the
    /// non-secret fields for diagnostics.
    #[test]
    fn debug_redacts_the_password() {
        let cred = DynamicDbCredential {
            kind: ExternalSqlKind::Postgres,
            database: "appdb_acme".into(),
            role: "appdb_acme_d_acme_web_0".into(),
            password: "s3cr3t_hex_password".into(),
        };
        let dbg = format!("{cred:?}");
        assert!(
            !dbg.contains("s3cr3t_hex_password"),
            "password leaked in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected a redaction marker: {dbg}"
        );
        // Non-secret fields stay visible for diagnostics.
        assert!(dbg.contains("appdb_acme_d_acme_web_0"));
        assert!(dbg.contains("appdb_acme"));
    }

    /// The sweep's key parser is the exact inverse of how a dynamic-cred key is built, and —
    /// crucially — returns `None` for EVERY non-dynamic credential key, so the orphan sweep
    /// can never touch a persistent runtime/owner/superuser credential.
    #[test]
    fn parse_dynamic_cred_key_round_trips_and_rejects_non_dynamic() {
        let prefix = crate::managed_sql::ManagedSqlCredentials::CRED_PREFIX;
        let full = format!(
            "{prefix}acme/{}",
            dynamic_cred_workload_key("pg", "acme_abc", "acme-web-0")
        );
        let p = parse_dynamic_cred_key(&full).expect("a dynamic key parses");
        assert_eq!(p.consumer_project, "acme");
        assert_eq!(p.compute, "pg");
        assert_eq!(p.tenant_ident, "acme_abc");
        assert_eq!(p.instance_id, "acme-web-0");
        // Non-dynamic credential keys never parse.
        assert!(parse_dynamic_cred_key(&format!("{prefix}acme/pg")).is_none()); // runtime role
        assert!(parse_dynamic_cred_key(&format!("{prefix}acme/pg/owner")).is_none()); // owner role
        assert!(parse_dynamic_cred_key(&format!("{prefix}default/pg")).is_none()); // superuser
        assert!(parse_dynamic_cred_key(&format!("{prefix}acme/pg/acme_abc/notdyn/x")).is_none());
        // A key under a different prefix never parses.
        assert!(parse_dynamic_cred_key("other/acme/pg/acme_abc/dyn/acme-web-0").is_none());
    }

    /// The per-replica credential key is distinct from the runtime/owner keys AND distinct
    /// per replica — so a dropped dynamic cred can never collide with a persistent one.
    #[test]
    fn dynamic_cred_key_is_per_replica_and_distinct() {
        let k0 = dynamic_cred_workload_key("pg", "acme_abc", "acme-web-0");
        let k1 = dynamic_cred_workload_key("pg", "acme_abc", "acme-web-1");
        assert_ne!(k0, k1, "per-replica keys must differ");
        assert!(k0.ends_with("/dyn/acme-web-0"));
        // Distinct from the runtime-role key (`<compute>/<ident>`) and owner key (`…/owner`).
        assert_ne!(k0, "pg/acme_abc");
        assert_ne!(k0, "pg/acme_abc/owner");
    }

    /// Phase 2 applies to a Shared, non-default, project-scoped, compute-backed Postgres
    /// binding: the target resolves with the owner role + a per-replica dynamic role.
    #[test]
    fn resolve_target_shared_project_pg_applies() {
        let b = shared_pg_binding();
        let t = resolve_target(&b, "acme", "acme-web-0").expect("phase 2 applies");
        assert_eq!(t.kind, ExternalSqlKind::Postgres);
        assert_eq!(t.compute, "pg");
        assert_eq!(t.superuser, "postgres");
        assert!(
            t.database.contains("appdb"),
            "tenant db derived: {}",
            t.database
        );
        // The owner role is derived + bounded; its cosmetic `_owner` marker may truncate
        // away under the 32-char role cap (distinctness rides the digest, not the marker).
        assert!(
            !t.owner_role.is_empty() && t.owner_role.len() <= 32,
            "owner role: {}",
            t.owner_role
        );
        assert_ne!(
            t.dyn_role, t.owner_role,
            "dynamic role must differ from the owner"
        );
        assert!(
            t.dyn_role.len() <= 32,
            "dynamic role must fit the MySQL cap: {}",
            t.dyn_role
        );
        assert!(t.cred_workload.contains("/dyn/acme-web-0"));
        assert_eq!(t.cred_project, "acme");
    }

    /// No-op cells: the reserved default tenant, `Single` isolation, a `Site`-scoped
    /// binding, a bring-your-own `url_env` binding, and an unparsable engine all resolve to
    /// `None` (phase 1 falls back to the static credential there).
    #[test]
    fn resolve_target_no_op_cells() {
        // default tenant.
        assert!(resolve_target(&shared_pg_binding(), DEFAULT_PROJECT, "web-0").is_none());
        // Single isolation.
        let mut single = shared_pg_binding();
        single.tenant = TenantIsolation::Single;
        assert!(resolve_target(&single, "acme", "acme-web-0").is_none());
        // Site scope.
        let mut site = shared_pg_binding();
        site.tenant_scope = TenantScope::Site;
        assert!(resolve_target(&site, "acme", "acme-web-0").is_none());
        // bring-your-own (no compute).
        let mut byo = shared_pg_binding();
        byo.compute = None;
        assert!(resolve_target(&byo, "acme", "acme-web-0").is_none());
        // unparsable engine.
        let mut bad = shared_pg_binding();
        bad.kind = "sqlite".to_string();
        assert!(resolve_target(&bad, "acme", "acme-web-0").is_none());
    }

    /// Two distinct tenants (projects) derive distinct dynamic roles + databases on the same
    /// shared server — the per-tenant isolation the role name carries through its digest.
    #[test]
    fn resolve_target_is_per_tenant() {
        let b = shared_pg_binding();
        let a = resolve_target(&b, "acme", "acme-web-0").unwrap();
        let g = resolve_target(&b, "globex", "globex-web-0").unwrap();
        assert_ne!(
            a.dyn_role, g.dyn_role,
            "distinct tenants → distinct dynamic roles"
        );
        assert_ne!(
            a.database, g.database,
            "distinct tenants → distinct databases"
        );
        assert_ne!(
            a.owner_role, g.owner_role,
            "distinct tenants → distinct owner roles"
        );
    }
}
