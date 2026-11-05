//! Serve-time wiring of a project-**declared** (apply-managed) database as a runtime
//! `sql` binding (mailroom cap-req #28 defect B).
//!
//! # The gap this closes
//!
//! A managed database declared through the manifest front door
//! (`databases: [(name: "default", kind: postgres, …)]`, persisted to
//! `project/{project}/database/{name}`) is provisioned, listed by `db ls`, and reachable
//! by the operator SQL surfaces — but until now it was NEVER wired as a runtime handler
//! binding. `build_sql_backends` only overlaid the node-STATIC
//! `[handlers.bindings.sql.databases]` config onto the libsql default, so when a node had
//! no static entry (the apply-managed `default` was MEANT to BE the binding), a handler's
//! `sql.open("")` fell through to the built-in libsql/SQLite store instead of the declared
//! Postgres — the exact mailroom-live symptom (`SQLite failure: no such table: …`).
//!
//! # How it closes it
//!
//! [`NodeDeclaredDbResolver`] implements the storage-crate
//! [`DeclaredDbResolver`](boatramp_storage::sql_sqlx::DeclaredDbResolver) hook the
//! [`CompositeSqlBackends`](boatramp_storage::sql_sqlx::CompositeSqlBackends) consults for
//! a name it has no static binding for, BEFORE falling through to libsql. Given the
//! request's `(project, site)` and a (default-aliased) binding name, it reads the project's
//! declaration from the [`DeployStore`], lowers it through the SAME
//! [`lower`](crate::managed_db_declare::lower) the provisioner uses, and resolves it with
//! the SAME per-tenant machinery a static managed binding uses
//! ([`NodeTenantSqlResolver`](crate::tenant_sql::NodeTenantSqlResolver)) — so a declared
//! binding reaches exactly the caller's own tenant database, isolation intact, and
//! `provision_tenant` runs (idempotent) before the first connection.
//!
//! # Merge point + safety
//!
//! The daemon-static config still WINS: the composite reaches this resolver only for a
//! name absent from its static maps, and this resolver additionally refuses a name the
//! operator declared statically (a manifest may never shadow a BYO operator binding). A
//! declared DB lowers with `allow_preview = false`, and the composite deliberately does not
//! consult this resolver on the preview path — a preview deployment gets an isolated libsql
//! database, never the live managed data.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{SqlBackend, SqlError};
use boatramp_storage::sql_sqlx::{DeclaredDbResolver, PerTenantSqlResolver};

use crate::config::{ExternalDatabaseConfig, TenantScope};
use crate::managed_db_declare::lower;
use crate::tenant_sql::NodeTenantSqlResolver;

/// How long a "this project declared no managed DB by that name" result is remembered, so
/// the common libsql-default path does not pay a [`DeployStore`] read on every
/// `sql.open()`. Short on purpose: a DB `apply`'d while serve is running is picked up
/// within this window (and a freshly-declared managed DB is not ready to serve for tens of
/// seconds anyway — `initdb` + provisioning — so the window never serves stale data past
/// the point the DB could actually answer). A positive resolution is cached by tenant grain
/// and never re-reads the store.
const NEGATIVE_TTL: Duration = Duration::from_secs(3);

/// The node's [`DeclaredDbResolver`]: bridges the per-project declarative store into the
/// serve-time `sql` binding composite (cap-req #28 B). See the module docs.
pub struct NodeDeclaredDbResolver {
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
    /// The node-static `[handlers.bindings.sql.databases]` names — a name present here is
    /// an operator binding the composite already handles, so this resolver refuses it
    /// (daemon-static wins; a manifest may never shadow a BYO operator binding).
    static_names: BTreeMap<String, ()>,
    /// Resolved per-tenant backends, keyed by `(project[/site], name)` per the binding's
    /// tenant grain — so a hot path reuses the connection pool instead of re-provisioning +
    /// reconnecting each `sql.open()`. Mirrors the composite's own per-tenant cache.
    ///
    /// This positive cache has NO expiry (a backend, once resolved, is kept for the life of
    /// the process), so a managed-DB credential ROTATION or revocation is not observed until
    /// the serve process restarts (cap-req #28 review, F3). This is deliberately the SAME
    /// lifetime the static per-tenant path has (the composite's own per-tenant cache and
    /// `NodeTenantSqlResolver` cache a resolved backend for the process lifetime too), so the
    /// declared fallback adds no new staleness window beyond the inherited one. It is keyed by
    /// tenant grain, so it is NEVER a cross-tenant exposure — a stale entry only ever re-serves
    /// the SAME tenant its own (now-rotated) backend. Left as-is on purpose (behavior unchanged):
    /// a bounded TTL here would also expire the SQL connection pool a hot path depends on.
    resolved: Mutex<HashMap<String, Arc<dyn SqlBackend>>>,
    /// Negative cache: `(project, name)` → expiry, for names the project has NOT declared
    /// (see [`NEGATIVE_TTL`]).
    negative: Mutex<HashMap<String, Instant>>,
}

impl NodeDeclaredDbResolver {
    /// Build over the deploy store, KV, the secrets envelope (required — a managed DB seals
    /// its credential), and the node-static binding names (for the daemon-wins refusal).
    pub fn new(
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
        static_dbs: &BTreeMap<String, ExternalDatabaseConfig>,
    ) -> Self {
        Self {
            deploy,
            kv,
            envelope,
            static_names: static_dbs.keys().map(|k| (k.clone(), ())).collect(),
            resolved: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
        }
    }

    /// The positive-cache key for `(project, site, name)` at the binding's tenant grain: a
    /// project tenant caches by `(project, name)`; a finer site tenant by
    /// `(project, site, name)`. (A `\u{1f}` unit separator keeps segments unambiguous.)
    fn positive_key(project: &str, site: &str, name: &str, site_scoped: bool) -> String {
        if site_scoped {
            format!("{project}\u{1f}{site}\u{1f}{name}")
        } else {
            format!("{project}\u{1f}{name}")
        }
    }

    /// The `(project, name)` negative-cache key (declaration existence is per project+name,
    /// independent of site).
    fn negative_key(project: &str, name: &str) -> String {
        format!("{project}\u{1f}{name}")
    }

    /// Whether `(project, name)` is negatively cached (known-not-declared) and unexpired.
    fn negative_hit(&self, project: &str, name: &str) -> bool {
        let key = Self::negative_key(project, name);
        let mut guard = self
            .negative
            .lock()
            .expect("declared-db negative cache poisoned");
        match guard.get(&key) {
            Some(&expiry) if expiry > Instant::now() => true,
            Some(_) => {
                // Expired — drop it so the map does not grow without bound.
                guard.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Record that `(project, name)` has no declaration (for [`NEGATIVE_TTL`]).
    fn negative_insert(&self, project: &str, name: &str) {
        self.negative
            .lock()
            .expect("declared-db negative cache poisoned")
            .insert(
                Self::negative_key(project, name),
                Instant::now() + NEGATIVE_TTL,
            );
    }
}

#[async_trait]
impl DeclaredDbResolver for NodeDeclaredDbResolver {
    async fn resolve(
        &self,
        project: &str,
        site: &str,
        name: &str,
    ) -> Result<Option<Arc<dyn SqlBackend>>, SqlError> {
        // Daemon-static wins (defense in depth): the composite matches its static maps
        // before reaching here, so a static name should never arrive — but refuse it
        // anyway, so a manifest can never shadow a BYO operator binding through this seam.
        if self.static_names.contains_key(name) {
            return Ok(None);
        }
        // Negative cache: skip the store read for the common "no declared DB by that name"
        // case (the libsql-default path).
        if self.negative_hit(project, name) {
            return Ok(None);
        }
        // Read the project's declaration. A store error is PROPAGATED (never silently
        // treated as "not declared" — that would route a handler expecting the managed
        // Postgres to the libsql default and silently diverge its data). It is classified
        // as `Unavailable` (NOT `Other`) on purpose: `open_bindings_sql` / `build_bindings`
        // only turn `is_unavailable()` errors into the readiness-gated, retryable 503 the
        // module doc promises — a transient DeployStore blip wrapped as `Other` would fall
        // into the "binding left ungranted" arm and hand the guest a hard, non-retryable
        // "sql not granted" instead (cap-req #28 review, F1). This stays fail-closed: the
        // resolver returns `Err`, so the composite's `?` propagates it and NEVER falls
        // through to the libsql default on a store error. Do NOT negative-cache a transient
        // error.
        let declared = self
            .deploy
            .get_project_database(ProjectRef::new(project), name)
            .await
            .map_err(|e| SqlError::unavailable(format!("read declared database {name:?}: {e}")))?;
        let Some(apply_db) = declared else {
            self.negative_insert(project, name);
            return Ok(None);
        };

        // Lower through the SAME path the provisioner uses, so the serve binding never
        // drifts from what was provisioned. A declaration always lowers to the managed-
        // credential path; anything else is a misconfiguration we fall through on (libsql),
        // not a hard failure.
        let binding = lower(project, &apply_db);
        if !binding.is_managed_credential() {
            self.negative_insert(project, name);
            return Ok(None);
        }

        let site_scoped = matches!(binding.tenant_scope, TenantScope::Site);
        let key = Self::positive_key(project, site, name, site_scoped);
        if let Some(hit) = self
            .resolved
            .lock()
            .expect("declared-db resolved cache poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(Some(hit));
        }

        // Resolve with the SAME per-tenant machinery a static managed binding uses: it
        // provisions the tenant (idempotent) then connects as the caller's own tenant
        // identity. `None` only for a non-compute-backed binding, which `is_managed_
        // credential()` already excluded.
        let resolver = NodeTenantSqlResolver::new(
            self.deploy.clone(),
            self.kv.clone(),
            self.envelope.clone(),
            &binding,
        )
        .ok_or_else(|| {
            SqlError::other(format!(
                "declared database {name:?} is not a resolvable managed binding"
            ))
        })?;
        let backend = resolver.resolve(project, site).await?;
        self.resolved
            .lock()
            .expect("declared-db resolved cache poisoned")
            .insert(key, backend.clone());
        Ok(Some(backend))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::{
        ApplyDatabase, ApplyDatabaseKind, ApplyDatabaseScope, ApplyDatabaseSize,
        ApplyDatabaseTenant,
    };
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

    // A reversible test envelope (NOT encryption) — the resolver seals credentials through
    // it on the positive path.
    struct ReverseEnvelope;
    #[async_trait]
    impl KeyEnvelope for ReverseEnvelope {
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

    fn deploy() -> DeployStore {
        DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()))
    }

    fn resolver(
        deploy: DeployStore,
        static_dbs: &BTreeMap<String, ExternalDatabaseConfig>,
    ) -> NodeDeclaredDbResolver {
        NodeDeclaredDbResolver::new(
            deploy,
            Arc::new(MemoryKv::new()),
            Arc::new(ReverseEnvelope),
            static_dbs,
        )
    }

    // A `Single`/`Project` Postgres declaration: `provision_tenant` for this shape writes
    // only to KV (spec + workload + sealed credential), so the resolver's positive path
    // runs without a live server up to the endpoint-connect step.
    fn single_default() -> ApplyDatabase {
        ApplyDatabase {
            name: "default".to_string(),
            kind: ApplyDatabaseKind::Postgres,
            version: None,
            extensions: vec![],
            size: ApplyDatabaseSize::Small,
            tenant: ApplyDatabaseTenant::Single,
            tenant_scope: ApplyDatabaseScope::Project,
            read_only: false,
            rls_session: false,
            tenant_guc: None,
            session_guc: None,
            tenant_all_marker: None,
            pool_max: None,
            connect_timeout_secs: None,
            startup_grace_secs: None,
            readiness_gate: Default::default(),
            delta_capture: false,
            restart_policy: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_static_name_is_refused_so_the_operator_binding_wins() {
        // `default` is a node-static operator binding → the resolver must return None
        // (daemon-wins), never shadow it with a project declaration.
        let mut static_dbs = BTreeMap::new();
        static_dbs.insert("default".to_string(), ExternalDatabaseConfig::default());
        let r = resolver(deploy(), &static_dbs);
        let out = r.resolve("default", "", "default").await.unwrap();
        assert!(
            out.is_none(),
            "a static-bound name must not resolve via the declared fallback"
        );
    }

    #[tokio::test]
    async fn an_undeclared_name_falls_through_to_none() {
        // Empty store → no declaration → None (the composite then uses the libsql default).
        let r = resolver(deploy(), &BTreeMap::new());
        let out = r.resolve("default", "", "default").await.unwrap();
        assert!(out.is_none());
        // A second lookup (now negative-cached) is still None.
        assert!(r.resolve("default", "", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_declared_default_resolves_to_a_managed_backend_not_libsql() {
        // Seed a declared `default` managed DB, then resolve it. The resolver must RECOGNIZE
        // it and resolve it to a MANAGED backend — `Ok(Some(_))`, NOT `Ok(None)` (which
        // would fall the composite through to the built-in libsql default, the exact
        // pre-fix defect-B symptom). The compute-backed backend's endpoint is resolved
        // lazily per connection, so building the handle succeeds here without a live
        // replica (a query would then surface the readiness gate).
        let d = deploy();
        d.set_project_database(ProjectRef::new("default"), &single_default())
            .await
            .expect("seed declaration");
        let r = resolver(d, &BTreeMap::new());
        // Map to a Debug-able shape (Arc<dyn SqlBackend> is not Debug).
        let outcome: Result<bool, String> = match r.resolve("default", "", "default").await {
            Ok(opt) => Ok(opt.is_some()),
            Err(e) => Err(e.to_string()),
        };
        assert!(
            matches!(outcome, Ok(true)),
            "a declared default must resolve to a managed backend, not fall through to the \
             libsql default: {outcome:?}"
        );
    }
}
