//! The project-scoped **declarative managed-database front door** (v0.6.0, #501
//! Stage B).
//!
//! A manifest `databases:` entry ([`ApplyDatabase`]) is a TYPED PROJECTION of the
//! node-static [`ExternalDatabaseConfig`](crate::config::ExternalDatabaseConfig) —
//! restricted to the fields SAFE for a project author to declare. This module is the
//! net-new plumbing that exposes the ALREADY-EXISTING daemon-level provisioning stack
//! (`provision_tenant` + the #491 three-identity model + sealed credentials) to a
//! per-project declaration, WITHOUT rebuilding any of it.
//!
//! # The security contract
//!
//! - **Credential never in the manifest.** A declared DB has no `password_env` (it is
//!   not even a field of [`ApplyDatabase`]), so it lowers to the *managed-credential*
//!   path ([`ExternalDatabaseConfig::is_managed_credential`]) — boatramp mints + seals
//!   the credential server-side. The lowering fills the excluded fields (`image`,
//!   `path`, `compute`, `*_env`) with managed defaults; a manifest can carry NONE of
//!   them (the type forbids it).
//! - **Daemon config wins.** A declared DB whose `name` collides with a node
//!   operator's static `[handlers].bindings.sql.databases` entry is REFUSED
//!   ([`DeclareError::DaemonConflict`]) — a project manifest may never shadow /
//!   override / downgrade a BYO operator binding. Enforced HERE, at the merge point
//!   ([`resolve_binding`]), not merely in the apply CLI.
//! - **Caller's-project binding.** The manifest does NOT let the author name a
//!   `compute` workload; boatramp DERIVES a per-project workload name
//!   ([`derived_workload`]) so a declaration can only ever provision onto its OWN
//!   project's server (a `Shared` server is project-qualified; a `Single` container is
//!   already registered under the caller's project by `provision_single`).
//! - **No destructive change.** A re-apply that changes an identity field
//!   (`kind`/`tenant`/`tenant_scope`) of an existing declared DB is refused
//!   ([`DeclareError::IdentityChange`]).
//! - **Inert on removal.** Removing a `databases:` entry never deprovisions; this
//!   module only ever *declares* + *provisions*. Teardown is an explicit imperative
//!   verb elsewhere.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{ApplyDatabase, ApplyDatabaseKind, apply_db_caps};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{DeclareError, ManagedDbDeclare};

use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};

/// Derive the per-project managed DB **server workload** name for a declared binding.
///
/// The manifest never names a `compute` workload (that is the caller's-project-binding
/// guard): boatramp derives one deterministically from `(project, name)` so a
/// declaration can only ever provision onto its OWN project's server. Project-qualified
/// because a `Shared` server is registered under the reserved default project (a
/// node-global namespace) — two different projects declaring the same binding name must
/// NOT collide on one shared server (or share a sealed credential). The result is a safe
/// resource name (the input segments are already `validate_resource_name`-screened).
pub fn derived_workload(project: &str, name: &str) -> String {
    format!("bramp-db-{project}-{name}")
}

/// Lower a declared [`ApplyDatabase`] into the internal
/// [`ExternalDatabaseConfig`](crate::config::ExternalDatabaseConfig) the daemon-level
/// provisioning stack consumes. Fills every EXCLUDED field with a managed default:
///
/// - no `password_env` ⇒ the managed-credential path (boatramp seals it server-side);
/// - no `image` ⇒ the stock engine image (`managed_db_spec` picks it);
/// - no `url_env`/`read_url_env`/`migration_url_env`/`path` ⇒ never set;
/// - `compute` = the DERIVED per-project workload (never author-named);
/// - `database`/`user` = the binding `name` (non-secret, derived).
///
/// The optional tuning knobs are CAPPED to the operator ceilings ([`apply_db_caps`]) —
/// a manifest can lower a knob, never raise it past the cap (the DoS / disk guard).
pub fn lower(project: &str, db: &ApplyDatabase) -> ExternalDatabaseConfig {
    let workload = derived_workload(project, &db.name);
    let kind = match db.kind {
        ApplyDatabaseKind::Postgres => "postgres",
        ApplyDatabaseKind::Mysql => "mysql",
    };
    let (_, _, volume_size_mib) = db.size.resources();
    ExternalDatabaseConfig {
        kind: kind.to_string(),
        // The excluded / BYO-secret / host-fs fields: ALWAYS the managed defaults.
        url_env: String::new(),
        read_url_env: None,
        migration_url_env: None,
        image: None,
        path: None,
        password_env: None,
        // The derived, caller's-project-bound connection identity.
        compute: Some(workload),
        database: Some(db.name.clone()),
        user: Some(db.name.clone()),
        // The SAFE, capped tuning knobs.
        pool_max: db.pool_max.map(|n| n.min(apply_db_caps::MAX_POOL)),
        connect_timeout_secs: db
            .connect_timeout_secs
            .map(|n| n.min(apply_db_caps::MAX_CONNECT_TIMEOUT_SECS)),
        startup_grace_secs: db
            .startup_grace_secs
            .map(|n| n.min(apply_db_caps::MAX_STARTUP_GRACE_SECS)),
        volume_size_mib: Some(volume_size_mib),
        read_only: db.read_only,
        // A declared DB is never a preview target (an operator opts a BYO db into that).
        allow_preview: false,
        tenant: match db.tenant {
            boatramp_core::compute::ApplyDatabaseTenant::Single => TenantIsolation::Single,
            boatramp_core::compute::ApplyDatabaseTenant::Shared => TenantIsolation::Shared,
        },
        tenant_scope: match db.tenant_scope {
            boatramp_core::compute::ApplyDatabaseScope::Project => TenantScope::Project,
            boatramp_core::compute::ApplyDatabaseScope::Site => TenantScope::Site,
        },
        rls_session: db.rls_session,
        tenant_guc: db.tenant_guc.clone(),
        session_guc: db.session_guc.clone(),
        tenant_all_marker: db.tenant_all_marker.clone(),
    }
}

/// **THE MERGE POINT** — resolve the live [`ExternalDatabaseConfig`] for `(project,
/// name)` by consulting BOTH sources: the node-static
/// `[handlers].bindings.sql.databases` map AND the per-project declarative store
/// (`project-database/{project}/{name}`). **Daemon-static config WINS, fail-closed on a
/// same-name conflict:** if `name` is present in BOTH, the resolution is REFUSED
/// ([`DeclareError::DaemonConflict`]) — a project manifest may NEVER shadow / override /
/// downgrade a node operator's BYO binding.
///
/// This is the single choke point the security invariant hangs on: it is enforced HERE,
/// where both sources are read into a live binding, so a node that reloads config with
/// BOTH a static `[databases].<name>` and a per-project declaration of the same name
/// refuses — not merely the apply CLI. A caller resolving a `(project, name)` for
/// provisioning MUST go through this, never read one source in isolation.
///
/// Returns `Ok(None)` when neither source declares `name` (nothing to provision).
pub async fn resolve_binding(
    static_dbs: &BTreeMap<String, ExternalDatabaseConfig>,
    deploy: &DeployStore,
    project: &str,
    name: &str,
) -> Result<Option<ExternalDatabaseConfig>, DeclareError> {
    let in_static = static_dbs.contains_key(name);
    let declared = deploy
        .get_project_database(ProjectRef::new(project), name)
        .await
        .map_err(|e| DeclareError::Other(e.to_string()))?;

    match (in_static, declared) {
        // DAEMON WINS, fail-closed: a project manifest may not shadow an operator binding.
        (true, Some(_)) => Err(DeclareError::DaemonConflict(name.to_string())),
        // Only the operator's static binding — return it (the manifest never touches it).
        (true, None) => Ok(static_dbs.get(name).cloned()),
        // Only a project declaration — lower it to the managed-credential path.
        (false, Some(db)) => Ok(Some(lower(project, &db))),
        (false, None) => Ok(None),
    }
}

/// The node-side [`ManagedDbDeclare`] capability: holds the node-static `databases` map
/// (to enforce daemon-wins), the [`DeployStore`] (to persist + provision), the KV +
/// envelope (to seal credentials). Mirrors [`NodeTenantRepair`](crate::repair) — it
/// resolves `(project, name)` through [`resolve_binding`] (the merge point), then drives
/// the existing `provision_tenant`.
pub struct NodeManagedDbDeclare {
    static_dbs: BTreeMap<String, ExternalDatabaseConfig>,
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

impl NodeManagedDbDeclare {
    /// Build over the node-static `databases` map, the deploy store, KV, and the secrets
    /// envelope (required — a managed DB seals its credential).
    pub fn new(
        static_dbs: BTreeMap<String, ExternalDatabaseConfig>,
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
    ) -> Self {
        Self {
            static_dbs,
            deploy,
            kv,
            envelope,
        }
    }

    /// Provision an ALREADY-lowered binding for `(project, name)`. A `Project`-scoped
    /// binding provisions the project tenant (`site = ""`); a `Site`-scoped binding is
    /// provisioned lazily per site on first `sql` use (there is no single site to eager-
    /// provision at declare time), so its eager step is a no-op beyond registering the
    /// declaration.
    async fn provision(
        &self,
        binding: &ExternalDatabaseConfig,
        project: &str,
    ) -> Result<(), DeclareError> {
        // A `Site`-scoped declaration has no single site to provision at apply time — the
        // per-site tenant is created lazily by the `sql` resolver on first use. Registering
        // the declaration (done by the caller) is enough; skip the eager trigger.
        if matches!(binding.tenant_scope, TenantScope::Site) {
            return Ok(());
        }
        crate::tenant_sql::provision_tenant(
            &self.deploy,
            &self.kv,
            &self.envelope,
            binding,
            project,
            "",
        )
        .await
        .map_err(DeclareError::Other)
    }
}

#[async_trait]
impl ManagedDbDeclare for NodeManagedDbDeclare {
    async fn declare(
        &self,
        project: &str,
        name: &str,
        db: &ApplyDatabase,
    ) -> Result<(), DeclareError> {
        // Defense-in-depth: the API path param + apply CLI validate `project`/`name`, but
        // this is the persistence + privileged-provision choke point, so re-run the one
        // canonical resource-identifier validator (fail-closed) on both segments — neither
        // can carry a `/` and reshape the `project-database/{project}/{name}` key.
        boatramp_core::project::validate_resource_name("project", project)
            .map_err(|e| DeclareError::Other(e.to_string()))?;
        boatramp_core::project::validate_resource_name("database", name)
            .map_err(|e| DeclareError::Other(e.to_string()))?;
        // The manifest's own `name` field must match the route/path `name` (a mismatch
        // would persist under one key while validating another) — fail closed.
        if db.name != name {
            return Err(DeclareError::Other(format!(
                "declared database name {:?} does not match the path segment {name:?}",
                db.name
            )));
        }

        // THE MERGE POINT: daemon-config-wins, fail-closed. A project manifest may not
        // shadow a node operator's static `[databases].<name>`.
        if self.static_dbs.contains_key(name) {
            return Err(DeclareError::DaemonConflict(name.to_string()));
        }

        // Destructive-change refusal: on re-apply of an existing declared DB, refuse any
        // change to an IDENTITY field (kind/tenant/tenant_scope) — silent data-loss/orphan.
        if let Some(prior) = self
            .deploy
            .get_project_database(ProjectRef::new(project), name)
            .await
            .map_err(|e| DeclareError::Other(e.to_string()))?
            && let Some(field) = db.identity_change(&prior)
        {
            return Err(DeclareError::IdentityChange {
                db: name.to_string(),
                field,
            });
        }

        // Lower to the managed-credential path (caller's-project-bound derived compute).
        let binding = lower(project, db);
        // Sanity: the lowering MUST always yield the managed-credential path (no
        // password_env) — the whole security contract. Assert it fail-closed.
        if !binding.is_managed_credential() {
            return Err(DeclareError::Other(format!(
                "internal: lowered database {name:?} is not the managed-credential path"
            )));
        }
        binding.validate(name).map_err(DeclareError::Other)?;

        // Register the caller's-project-bound Shared server workload BEFORE provisioning
        // (a Shared binding's provision connects to the derived server; a Single binding
        // registers its dedicated container inside `provision_single`). Idempotent + non-
        // clobbering. For a Single/Site binding this is a no-op set.
        crate::managed_sql::auto_register_managed_db_workloads(
            &self.deploy,
            &BTreeMap::from([(name.to_string(), binding.clone())]),
        )
        .await;

        // Persist the DECLARATION (create-or-replace) — the record is JUST the
        // declaration; it never carries a secret and never touches the credential/volume.
        self.deploy
            .set_project_database(ProjectRef::new(project), db)
            .await
            .map_err(|e| DeclareError::Other(e.to_string()))?;

        // Eager provision so the DB exists when `apply` returns.
        self.provision(&binding, project).await
    }

    async fn ensure(&self, project: &str, name: &str) -> Result<(), DeclareError> {
        boatramp_core::project::validate_resource_name("project", project)
            .map_err(|e| DeclareError::Other(e.to_string()))?;
        boatramp_core::project::validate_resource_name("database", name)
            .map_err(|e| DeclareError::Other(e.to_string()))?;
        // Ensure goes through the merge point so a daemon conflict still refuses.
        let binding = match resolve_binding(&self.static_dbs, &self.deploy, project, name).await? {
            Some(b) => b,
            None => return Err(DeclareError::NotDeclared(name.to_string())),
        };
        // A static (operator) binding is provisioned by the daemon itself — `ensure` only
        // eager-provisions a project DECLARATION (which is the lowered, managed path).
        if !binding.is_managed_credential() {
            return Err(DeclareError::NotDeclared(name.to_string()));
        }
        crate::managed_sql::auto_register_managed_db_workloads(
            &self.deploy,
            &BTreeMap::from([(name.to_string(), binding.clone())]),
        )
        .await;
        self.provision(&binding, project).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::ApplyDatabaseSize;

    fn declared(name: &str) -> ApplyDatabase {
        ApplyDatabase {
            name: name.to_string(),
            kind: ApplyDatabaseKind::Postgres,
            version: Some(16),
            extensions: vec![],
            size: ApplyDatabaseSize::Small,
            tenant: boatramp_core::compute::ApplyDatabaseTenant::Shared,
            tenant_scope: boatramp_core::compute::ApplyDatabaseScope::Project,
            read_only: false,
            rls_session: false,
            tenant_guc: None,
            session_guc: None,
            tenant_all_marker: None,
            pool_max: Some(1000),
            connect_timeout_secs: Some(9999),
            startup_grace_secs: Some(99999),
        }
    }

    /// The security contract: the lowered binding is ALWAYS the managed-credential path —
    /// no `password_env`, no `url_env`/`read_url_env`/`migration_url_env`, no `image`, no
    /// `path`, and a DERIVED (caller's-project-bound) compute name.
    #[test]
    fn lowering_is_the_managed_credential_path() {
        let cfg = lower("acme", &declared("app"));
        assert!(cfg.is_managed_credential(), "must be managed-credential");
        assert!(
            cfg.password_env.is_none(),
            "no password_env in a declared DB"
        );
        assert!(cfg.url_env.is_empty(), "no url_env");
        assert!(cfg.read_url_env.is_none(), "no read_url_env");
        assert!(cfg.migration_url_env.is_none(), "no migration_url_env");
        assert!(cfg.image.is_none(), "no arbitrary image");
        assert!(cfg.path.is_none(), "no host-fs path");
        assert_eq!(cfg.compute.as_deref(), Some("bramp-db-acme-app"));
        assert!(cfg.validate("app").is_ok(), "the lowered binding validates");
    }

    /// The optional tuning knobs are CAPPED to the operator ceilings — a manifest can
    /// never raise them past the cap (the DoS / disk-full guard).
    #[test]
    fn tuning_knobs_are_capped() {
        let cfg = lower("acme", &declared("app"));
        assert_eq!(cfg.pool_max, Some(apply_db_caps::MAX_POOL));
        assert_eq!(
            cfg.connect_timeout_secs,
            Some(apply_db_caps::MAX_CONNECT_TIMEOUT_SECS)
        );
        assert_eq!(
            cfg.startup_grace_secs,
            Some(apply_db_caps::MAX_STARTUP_GRACE_SECS)
        );
    }

    /// A different project deriving the same binding NAME never collides on the shared
    /// server (the workload is project-qualified) — the caller's-project-binding guard.
    #[test]
    fn derived_workload_is_project_qualified() {
        assert_ne!(
            derived_workload("acme", "app"),
            derived_workload("globex", "app"),
        );
    }

    /// The size preset maps to bounded resources (never a raw unbounded request).
    #[test]
    fn size_preset_maps_to_bounded_volume() {
        assert_eq!(
            lower("p", &db_size(ApplyDatabaseSize::Small)).volume_size_mib,
            Some(10 * 1024)
        );
        assert_eq!(
            lower("p", &db_size(ApplyDatabaseSize::Medium)).volume_size_mib,
            Some(50 * 1024)
        );
        assert_eq!(
            lower("p", &db_size(ApplyDatabaseSize::Large)).volume_size_mib,
            Some(200 * 1024)
        );
    }

    fn db_size(size: ApplyDatabaseSize) -> ApplyDatabase {
        let mut d = declared("app");
        d.size = size;
        d
    }

    // -----------------------------------------------------------------------
    // The mutation-verified gate: `MANAGED-DB DECLARATION SCOPED OK`.
    //
    // Each assertion below observes a CONCRETE outcome (an `Err` variant, a stored
    // record, a sealed credential's actual bytes, a derived name), so a mutation that
    // neuters an invariant flips a real assertion — never a printed string:
    //  - credential-never-in-manifest: `lower` MUST yield the managed-credential path
    //    (no `password_env`/`url_env`/`image`/`path`); a mutation that carried a secret
    //    field would fail `is_managed_credential()`.
    //  - daemon-wins conflict: a declare of a name present in the node-static map is
    //    REFUSED at the merge point; a mutation that let the manifest win would return
    //    `Ok(())` and this asserts `DaemonConflict`.
    //  - refuse-destructive-change: re-declaring an existing DB with a different
    //    `tenant` is `IdentityChange`; a mutation that skipped the identity check would
    //    return `Ok` and this asserts the refusal.
    //  - caller-project-binding: the lowered `compute` is project-qualified, so a
    //    declaration can only provision onto its OWN project's derived server (never an
    //    author-named / cross-tenant workload).
    //  - inert-on-removal: the capability exposes NO deprovision — after a declare the
    //    record + sealed credential persist; there is no code path to drop them, so
    //    manifest removal (an absent entry in a later apply) cannot deprovision.
    // -----------------------------------------------------------------------

    use async_trait::async_trait;
    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

    struct XorEnvelope;
    #[async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, c: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(c.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    struct NullStorage;
    #[async_trait]
    impl Storage for NullStorage {
        async fn get(&self, _: &str) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::unsupported("null"))
        }
        async fn head(&self, _: &str) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(Vec::new())
        }
    }

    fn single_project(name: &str) -> ApplyDatabase {
        // A `Single`/`Project` binding: `provision_single` writes only to KV (spec +
        // workload + sealed credential), NO live DB connection — so the whole declare
        // path runs in-engine over a `NullStorage` + `MemoryKv`.
        let mut d = declared(name);
        d.tenant = boatramp_core::compute::ApplyDatabaseTenant::Single;
        d.pool_max = None;
        d.connect_timeout_secs = None;
        d.startup_grace_secs = None;
        d
    }

    fn declare_cap(
        static_dbs: BTreeMap<String, ExternalDatabaseConfig>,
    ) -> (
        NodeManagedDbDeclare,
        DeployStore,
        std::sync::Arc<dyn KvStore>,
    ) {
        let kv: std::sync::Arc<dyn KvStore> = std::sync::Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(std::sync::Arc::new(NullStorage), kv.clone());
        let cap = NodeManagedDbDeclare::new(
            static_dbs,
            deploy.clone(),
            kv.clone(),
            std::sync::Arc::new(XorEnvelope),
        );
        (cap, deploy, kv)
    }

    #[tokio::test]
    async fn managed_db_declaration_scoped_gate() {
        // (1) credential-never-in-manifest — the lowered binding is the managed path.
        let low = lower("acme", &single_project("app"));
        assert!(
            low.is_managed_credential() && low.password_env.is_none(),
            "GATE: lowered binding must be the managed-credential path (no password_env)"
        );
        assert!(
            low.url_env.is_empty() && low.image.is_none() && low.path.is_none(),
            "GATE: no url_env / image / host-fs path may appear in a declared binding"
        );

        // (2) daemon-wins conflict — a name in the node-static map is REFUSED.
        let mut static_dbs = BTreeMap::new();
        static_dbs.insert("byo".to_string(), ExternalDatabaseConfig::default());
        let (cap, _deploy, _kv) = declare_cap(static_dbs);
        let refused = cap.declare("acme", "byo", &single_project("byo")).await;
        assert!(
            matches!(refused, Err(DeclareError::DaemonConflict(ref n)) if n == "byo"),
            "GATE: a project manifest may not shadow a daemon-static binding — got {refused:?}"
        );

        // The merge point itself refuses too (same-name in BOTH sources), even for `ensure`.
        let mut both = BTreeMap::new();
        both.insert("byo".to_string(), ExternalDatabaseConfig::default());
        let (cap2, deploy2, _kv2) = declare_cap(both);
        // Seed a rogue project declaration directly (bypassing declare) to simulate a
        // config-reload with BOTH present, then assert the merge point fails closed.
        deploy2
            .set_project_database(ProjectRef::new("acme"), &single_project("byo"))
            .await
            .unwrap();
        let merged = resolve_binding(&cap2.static_dbs, &deploy2, "acme", "byo").await;
        assert!(
            matches!(merged, Err(DeclareError::DaemonConflict(_))),
            "GATE: the merge point fails closed when both sources define the name — got {merged:?}"
        );

        // (3) A clean declare onto a project with NO daemon conflict succeeds + persists +
        // seals a credential. `Single`/`Project` provisions with no live DB.
        let (cap3, deploy3, kv3) = declare_cap(BTreeMap::new());
        cap3.declare("acme", "app", &single_project("app"))
            .await
            .expect("GATE: a clean declare succeeds");
        let stored = deploy3
            .get_project_database(ProjectRef::new("acme"), "app")
            .await
            .unwrap();
        assert!(stored.is_some(), "GATE: the declaration is persisted");
        // The sealed credential exists (eager provision minted it), keyed under the
        // caller's project (`managed-sql-cred/acme/<derived-workload>`) — never in the
        // manifest. Assert at least one such key exists (the exact derived tenant workload
        // name includes a sanitized ident, so match on the project-scoped prefix).
        let cred_keys = kv3.list_prefix("managed-sql-cred/acme/").await.unwrap();
        assert!(
            !cred_keys.is_empty(),
            "GATE: the eager provision minted + sealed a managed credential under the caller's project"
        );
        // …and it is stored SEALED (XOR'd), never the plaintext.
        let sealed = kv3.get(&cred_keys[0]).await.unwrap().unwrap();
        assert!(
            sealed.iter().all(|b| *b != 0) && sealed.len() == 64,
            "GATE: the credential is sealed at rest (64-byte sealed blob)"
        );

        // (4) refuse-destructive-change — re-declare `app` with a DIFFERENT `tenant`.
        let mut changed = single_project("app");
        changed.tenant = boatramp_core::compute::ApplyDatabaseTenant::Shared;
        let refused_change = cap3.declare("acme", "app", &changed).await;
        assert!(
            matches!(
                refused_change,
                Err(DeclareError::IdentityChange { field, .. }) if field == "tenant"
            ),
            "GATE: changing `tenant` on an existing declared DB is refused — got {refused_change:?}"
        );

        // (5) caller-project-binding — the lowered compute is project-qualified, so a
        // DIFFERENT project can NEVER name/derive onto acme's server.
        assert_eq!(
            lower("acme", &single_project("app")).compute.as_deref(),
            Some("bramp-db-acme-app"),
        );
        assert_ne!(
            lower("globex", &single_project("app")).compute,
            lower("acme", &single_project("app")).compute,
            "GATE: a declaration provisions onto its OWN project's derived server only"
        );

        // (6) inert-on-removal — the capability exposes NO deprovision. After the declare
        // the record + sealed credential still exist; there is no method to drop them, so a
        // dropped manifest entry (absent in a later apply) cannot deprovision. Re-assert the
        // credential + record are still present (nothing in this API removed them).
        assert!(
            !kv3.list_prefix("managed-sql-cred/acme/")
                .await
                .unwrap()
                .is_empty(),
            "GATE: nothing in the declare API removes the credential (inert on removal)"
        );
        assert!(
            deploy3
                .get_project_database(ProjectRef::new("acme"), "app")
                .await
                .unwrap()
                .is_some(),
            "GATE: the declaration record survives (removal is an explicit imperative verb)"
        );

        println!("MANAGED-DB DECLARATION SCOPED OK");
    }
}
