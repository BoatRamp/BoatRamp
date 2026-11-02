//! The compute **managed-DB DSN** binding resolver (PLAN-compute-managed-db-dsn, Phase 1).
//!
//! A plain container / micro-VM workload cannot import the WASI `sql` host interface a
//! handler uses, and the per-node **sql-shim** ([`crate::sql_shim`]) only speaks libsql's
//! hrana-over-HTTP — which an off-the-shelf Postgres/MySQL driver can't use. So a workload
//! bound to a boatramp-managed **co-located Postgres/MySQL** database gets, instead, a
//! **real `postgres://` / `mysql://` DSN** injected into its env, built from the DB's
//! internal-DNS endpoint + the unsealed per-tenant managed credential. An off-the-shelf
//! app / ORM / migration tool with a standard driver then Just Works — no boatramp shim or
//! token to understand.
//!
//! ## Branch by backend kind (no regression)
//!
//! This resolver takes the `sql` resolver slot and WRAPS the libsql sql-shim. For each
//! `sql` binding it resolves the live [`ExternalDatabaseConfig`] through the SAME merge
//! point the runtime uses ([`resolve_binding`]) and auto-detects the backend:
//!
//! - a **managed co-located Postgres/MySQL** DB (a compute-backed binding an engine
//!   recognizes) → compose + inject a real DSN here;
//! - a **per-site libsql** default (or any other `sql` binding the managed path does not
//!   own) → delegate to the wrapped sql-shim (endpoint + token), exactly as before.
//!
//! Auto-detection is safe: nothing relies on the shim path for a co-located pg/mysql
//! binding (it would hand a libsql client a Postgres backend — a wire/dialect mismatch, and
//! not a documented path), and the site-default libsql binding resolves to no `databases`
//! entry, so it falls through to the shim untouched.
//!
//! ## Operator-templatable env
//!
//! The operator (who manages the workload) decides exactly what env the workload receives.
//! The resolved connection is exposed as template variables the operator references from
//! the workload's own `env:` map:
//!
//! - `{{sql.host}}` `{{sql.port}}` `{{sql.user}}` `{{sql.password}}` `{{sql.database}}`,
//!   the ready-made `{{sql.dsn}}`, and the migration/DDL identity
//!   `{{sql.migration_user}}` `{{sql.migration_password}}` `{{sql.migration_dsn}}`;
//! - a named binding `sql:analytics` also under `{{sql.analytics.*}}`;
//! - a referenced sealed secret `{{secret.<NAME>}}` (unsealed SERVER-SIDE here).
//!
//! An operator writes e.g.
//! `SIMERTEC_DATABASE_URL = "postgres://{{sql.user}}:{{sql.password}}@{{sql.host}}:{{sql.port}}/{{sql.database}}?sslmode=require"`,
//! or discrete `PGHOST={{sql.host}}` … or any mix of DB parts, static params, and a sealed
//! secret. A value containing a `{{…}}` placeholder is rendered here and REPLACES the raw
//! template at launch (see `launch_one`); a hand-set literal is left untouched.
//!
//! ## Default (simple case Just Works)
//!
//! A workload that references no template still gets the binding's `url_env` (the full
//! runtime DSN) + `migration_url_env` (the DDL-identity DSN) injected, so the simple case
//! needs no template. Templating is the general mechanism; these are the defaults.
//!
//! ## Phase-1 trade-off (documented)
//!
//! The managed credential sits in the workload's env as a STATIC DSN (owner-accepted for
//! Phase 1). The follow-up replaces it with a dynamic, per-replica role minted at launch
//! and revoked on stop, anchored to a stable owner role — tracked at [`DYNAMIC_ROLE_TODO`].
//! Nothing here blocks it: the only seam a workload sees is its env DSN, which the follow-up
//! fills from a short-lived role instead of the static managed credential.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{BindingKind, ComputeBinding, ComputeBindingResolver};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;

use crate::config::ExternalDatabaseConfig;
use crate::managed_db_declare::resolve_binding;
use crate::tenant_sql::{ConnRole, NodeTenantSqlResolver, SqlConnParts};

/// The Phase-2 follow-up this Phase-1 resolver leaves room for: replace the STATIC managed
/// credential in the workload's env DSN with a DYNAMIC, per-replica role minted at launch
/// and revoked on stop, anchored to a stable owner role. Not implemented here; the env DSN
/// is the only seam a workload sees, so the follow-up changes how the password is sourced
/// without touching the workload contract. (PLAN-compute-managed-db-dsn Phase 2.)
pub const DYNAMIC_ROLE_TODO: &str = "PLAN-compute-managed-db-dsn Phase 2: dynamic per-replica role";

/// Resolves a workload's `sql` [`ComputeBinding`]s, injecting a real `postgres://` /
/// `mysql://` DSN for a managed co-located Postgres/MySQL target and delegating every other
/// `sql` binding (per-site libsql, external) to the wrapped sql-shim. See the module docs.
pub struct ManagedDbDsnResolver {
    /// The node-static handler `sql` `databases` map — the daemon side of the
    /// [`resolve_binding`] merge point.
    databases: BTreeMap<String, ExternalDatabaseConfig>,
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    /// The `[secrets]` envelope — unseals the per-tenant managed credential AND any
    /// `{{secret.<NAME>}}` the operator references. Server-side only.
    envelope: Arc<dyn KeyEnvelope>,
    /// The project-scoped sealed-secret store for `{{secret.<NAME>}}`. `None` ⇒ secret
    /// references cannot be resolved (the render fails closed for that value).
    secret_store: Option<Arc<SecretStore>>,
    /// The wrapped libsql sql-shim resolver — the fallback for any `sql` binding the managed
    /// path does not own. `None` ⇒ no shim configured (a libsql binding then gets no env).
    shim: Option<Arc<dyn ComputeBindingResolver>>,
}

/// A managed-DB `sql` binding resolved to its runtime + migration connection parts.
struct ManagedBinding {
    binding: ComputeBinding,
    runtime: SqlConnParts,
    migration: SqlConnParts,
}

impl ManagedDbDsnResolver {
    /// Wrap the libsql sql-shim (`shim`) with the managed-DB DSN path. `databases` is the
    /// node-static handler `sql` config; `secret_store` backs `{{secret.<NAME>}}`
    /// (`None` ⇒ unavailable). An `envelope` is required (it unseals the managed credential).
    pub fn wrap(
        shim: Option<Arc<dyn ComputeBindingResolver>>,
        databases: BTreeMap<String, ExternalDatabaseConfig>,
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
        secret_store: Option<Arc<SecretStore>>,
    ) -> Self {
        Self {
            databases,
            deploy,
            kv,
            envelope,
            secret_store,
            shim,
        }
    }

    /// Resolve `binding` to its managed-DB connection parts (runtime + migration), or
    /// `Ok(None)` when it is NOT a managed co-located Postgres/MySQL binding (so the caller
    /// delegates it to the wrapped shim). `Err` is a resolution failure (surfaced, never
    /// guessed) — the binding is then skipped (its env is not injected) so the workload
    /// fails loudly rather than receiving a half-built DSN.
    async fn resolve_managed(
        &self,
        project: &str,
        workload: &str,
        binding: &ComputeBinding,
    ) -> Result<Option<ManagedBinding>, String> {
        let cfg = match resolve_binding(&self.databases, &self.deploy, project, &binding.name).await
        {
            Ok(Some(cfg)) => cfg,
            // Not declared (e.g. the site-default libsql database) — shim owns it.
            Ok(None) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        // `NodeTenantSqlResolver::new` returns `Some` IFF the binding is a compute-backed
        // Postgres/MySQL (an engine it recognizes) — which is EXACTLY the managed co-located
        // DSN path. A libsql or external (`url_env`) binding returns `None` → shim owns it.
        let Some(resolver) = NodeTenantSqlResolver::new(
            self.deploy.clone(),
            self.kv.clone(),
            self.envelope.clone(),
            &cfg,
        ) else {
            return Ok(None);
        };
        // The compute binding's tenant is `(project, site = workload)` — the SAME tenant a
        // handler for that workload would resolve (the shim passes `workload` as the site),
        // so a workload can never reach another tenant's database.
        let runtime = resolver
            .connection_parts(project, workload, ConnRole::Runtime)
            .await
            .map_err(|e| e.to_string())?;
        let migration = resolver
            .connection_parts(project, workload, ConnRole::Migration)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Some(ManagedBinding {
            binding: binding.clone(),
            runtime,
            migration,
        }))
    }

    /// Unseal the project-scoped sealed secret `name` to its UTF-8 value. `Ok(None)` when no
    /// secret store is wired or the secret is absent. The value is NEVER logged.
    async fn resolve_secret(&self, project: &str, name: &str) -> Result<Option<String>, String> {
        let Some(store) = &self.secret_store else {
            return Ok(None);
        };
        match store.get(ProjectRef::new(project), name).await {
            Ok(Some(bytes)) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| format!("secret {name:?} is not valid UTF-8")),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// The core of [`resolve`](ComputeBindingResolver::resolve) /
    /// [`resolve_with_env`](ComputeBindingResolver::resolve_with_env): resolve the `sql`
    /// bindings, build template variables, render the operator's `env` templates, inject the
    /// defaults, and delegate the rest to the shim. `workload_env` is the operator-declared
    /// env (empty for the token-repopulation / no-env path).
    async fn resolve_inner(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        workload_env: &BTreeMap<String, String>,
    ) -> Vec<(String, String)> {
        // 1. Classify each `sql` binding: managed co-located pg/mysql vs shim-owned.
        let mut managed: Vec<ManagedBinding> = Vec::new();
        let mut shim_bindings: Vec<ComputeBinding> = Vec::new();
        for binding in bindings {
            if binding.kind != BindingKind::Sql {
                // Not ours — the chained blob/kv/messaging resolvers own the other kinds.
                continue;
            }
            match self.resolve_managed(project, workload, binding).await {
                Ok(Some(m)) => managed.push(m),
                Ok(None) => shim_bindings.push(binding.clone()),
                Err(e) => tracing::warn!(
                    %project,
                    %workload,
                    binding = %binding.name,
                    error = %e,
                    "managed-db DSN: binding resolve failed; skipping (no env injected)"
                ),
            }
        }

        let mut out: Vec<(String, String)> = Vec::new();

        if !managed.is_empty() {
            // 2. Build template variables from the managed bindings.
            let single = managed.len() == 1;
            let mut vars: BTreeMap<String, String> = BTreeMap::new();
            for m in &managed {
                // `sql.<name>` for a named binding; bare `sql` for the empty-name (site
                // default) binding OR the sole managed binding (the common single case, so
                // `sql:app` still answers `{{sql.host}}`).
                if m.binding.name.is_empty() || single {
                    register_parts(&mut vars, "sql", &m.runtime, &m.migration);
                }
                if !m.binding.name.is_empty() {
                    register_parts(
                        &mut vars,
                        &format!("sql.{}", m.binding.name),
                        &m.runtime,
                        &m.migration,
                    );
                }
            }

            // 3. Resolve any `{{secret.<NAME>}}` referenced by a template value — SERVER-SIDE.
            let mut secret_names: BTreeSet<String> = BTreeSet::new();
            for value in workload_env.values() {
                if value.contains("{{") {
                    for key in referenced_keys(value) {
                        if let Some(name) = key.strip_prefix("secret.") {
                            secret_names.insert(name.to_string());
                        }
                    }
                }
            }
            for name in &secret_names {
                match self.resolve_secret(project, name).await {
                    Ok(Some(value)) => {
                        vars.insert(format!("secret.{name}"), value);
                    }
                    // Absent/unavailable → leave unresolved so the render fails closed for
                    // that value (never inject an empty/partial secret). Never log the value.
                    Ok(None) => tracing::warn!(
                        %project,
                        %workload,
                        secret = %name,
                        "managed-db DSN: referenced secret is unset or no secret store configured"
                    ),
                    Err(e) => tracing::warn!(
                        %project,
                        %workload,
                        secret = %name,
                        error = %e,
                        "managed-db DSN: referenced secret could not be unsealed"
                    ),
                }
            }

            // 4. Render the operator's env templates. A value with a `{{…}}` placeholder is
            // rendered and REPLACES the raw template at launch; a render error leaves the raw
            // template in place (diagnosable) and injects nothing for that key.
            for (key, value) in workload_env {
                if !value.contains("{{") {
                    continue;
                }
                match render(value, &vars) {
                    Ok(rendered) => out.push((key.clone(), rendered)),
                    Err(e) => tracing::warn!(
                        %project,
                        %workload,
                        key = %key,
                        error = %e,
                        "managed-db DSN: env template left unrendered"
                    ),
                }
            }

            // 5. Defaults (simple case): inject `url_env`=runtime DSN + `migration_url_env`=
            // DDL DSN for each managed binding, UNLESS the operator already set that key
            // (a template rendered in step 4, or a hand-set literal).
            for m in &managed {
                let url_key = m.binding.url_env();
                if !workload_env.contains_key(&url_key) {
                    out.push((url_key, m.runtime.dsn()));
                }
                let migration_key = m.binding.migration_url_env();
                if !workload_env.contains_key(&migration_key) {
                    out.push((migration_key, m.migration.dsn()));
                }
            }
        }

        // 6. Delegate every shim-owned `sql` binding (per-site libsql, external) to the
        // wrapped sql-shim — endpoint + token, exactly as before.
        if let Some(shim) = &self.shim
            && !shim_bindings.is_empty()
        {
            out.extend(
                shim.resolve_with_env(project, workload, replica, &shim_bindings, workload_env)
                    .await,
            );
        }
        out
    }
}

#[async_trait]
impl ComputeBindingResolver for ManagedDbDsnResolver {
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)> {
        // No operator env available (the reconcile's token-repopulation path): inject the
        // defaults for managed bindings + re-register the shim's libsql tokens.
        self.resolve_inner(project, workload, replica, bindings, &BTreeMap::new())
            .await
    }

    async fn resolve_with_env(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        workload_env: &BTreeMap<String, String>,
    ) -> Vec<(String, String)> {
        self.resolve_inner(project, workload, replica, bindings, workload_env)
            .await
    }

    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) {
        // The managed-DB DSN path registers no per-replica state (the credential is static
        // and sealed), so there is nothing of ours to release. Delegate to the shim so its
        // libsql tokens are revoked. (Deregistering a token the managed path never
        // registered is a harmless no-op.)
        if let Some(shim) = &self.shim {
            shim.release(project, workload, replica, bindings).await;
        }
    }
}

/// Register a managed binding's parts under a template namespace `ns`: the runtime
/// identity as `<ns>.{host,port,user,password,database,dsn}` and the migration/DDL identity
/// as `<ns>.{migration_user,migration_password,migration_dsn}` (host/port are shared).
fn register_parts(
    vars: &mut BTreeMap<String, String>,
    ns: &str,
    runtime: &SqlConnParts,
    migration: &SqlConnParts,
) {
    vars.insert(format!("{ns}.host"), runtime.host.clone());
    vars.insert(format!("{ns}.port"), runtime.port.to_string());
    vars.insert(format!("{ns}.user"), runtime.user.clone());
    vars.insert(format!("{ns}.password"), runtime.password.clone());
    vars.insert(format!("{ns}.database"), runtime.database.clone());
    vars.insert(format!("{ns}.dsn"), runtime.dsn());
    vars.insert(format!("{ns}.migration_user"), migration.user.clone());
    vars.insert(
        format!("{ns}.migration_password"),
        migration.password.clone(),
    );
    vars.insert(format!("{ns}.migration_dsn"), migration.dsn());
}

/// The template keys referenced by `{{key}}` placeholders in `text` (keys trimmed). A
/// minimal, documented placeholder syntax: `{{` opens, `}}` closes; an unclosed `{{` ends
/// the scan. Used to pre-collect `secret.<NAME>` references so they are unsealed before the
/// (synchronous) [`render`].
fn referenced_keys(text: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            break;
        };
        let key = after[..close].trim();
        if !key.is_empty() {
            keys.push(key.to_string());
        }
        rest = &after[close + 2..];
    }
    keys
}

/// Render `{{key}}` placeholders in `template` from `vars`. Literal text passes through; an
/// unknown placeholder or an unclosed `{{` is an error (fail closed — the caller then leaves
/// the raw template in place rather than inject a half-rendered value). The one place a
/// template is expanded.
fn render(template: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = after
            .find("}}")
            .ok_or_else(|| "unclosed `{{` placeholder".to_string())?;
        let key = after[..close].trim();
        let value = vars
            .get(key)
            .ok_or_else(|| format!("unknown placeholder `{{{{{key}}}}}`"))?;
        out.push_str(value);
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("sql.host".to_string(), "pg-acme".to_string()),
            ("sql.port".to_string(), "5432".to_string()),
            ("sql.user".to_string(), "app".to_string()),
            ("sql.password".to_string(), "s3cr3t".to_string()),
            ("sql.database".to_string(), "appdb".to_string()),
            ("secret.API_KEY".to_string(), "xyz".to_string()),
        ])
    }

    #[test]
    fn render_fills_placeholders_and_passes_literals() {
        let v = vars();
        assert_eq!(
            render(
                "postgres://{{sql.user}}:{{sql.password}}@{{sql.host}}:{{sql.port}}/{{sql.database}}?sslmode=require",
                &v
            )
            .unwrap(),
            "postgres://app:s3cr3t@pg-acme:5432/appdb?sslmode=require"
        );
        // Discrete + whitespace in the placeholder + a static literal mixed in.
        assert_eq!(render("{{ sql.host }}", &v).unwrap(), "pg-acme");
        assert_eq!(
            render("key={{secret.API_KEY}};x=1", &v).unwrap(),
            "key=xyz;x=1"
        );
        assert_eq!(
            render("no placeholders here", &v).unwrap(),
            "no placeholders here"
        );
    }

    #[test]
    fn render_fails_closed_on_unknown_or_unclosed() {
        let v = vars();
        assert!(render("{{sql.nope}}", &v).is_err());
        assert!(render("{{secret.MISSING}}", &v).is_err());
        assert!(render("{{sql.host", &v).is_err());
    }

    #[test]
    fn referenced_keys_collects_each_placeholder() {
        let keys = referenced_keys("{{sql.user}}@{{sql.host}} {{secret.API_KEY}}");
        assert_eq!(keys, vec!["sql.user", "sql.host", "secret.API_KEY"]);
        // Only `secret.*` keys become secret lookups.
        let secrets: Vec<&str> = keys
            .iter()
            .filter_map(|k| k.strip_prefix("secret."))
            .collect();
        assert_eq!(secrets, vec!["API_KEY"]);
    }

    // ---- end-to-end resolve_with_env over a managed co-located Postgres ----

    use async_trait::async_trait as _async_trait;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
    use std::sync::Mutex;

    /// A reversible test "envelope" (NOT encryption) — the managed credential round-trips.
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

    /// A no-op object store so a `DeployStore` can be built (only its KV paths are used).
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

    /// A fake sql-shim: records the bindings it was asked to resolve and returns a sentinel
    /// env, so a test can prove a non-managed (libsql/external) `sql` binding is delegated to
    /// the shim rather than given a DSN.
    #[derive(Default)]
    struct FakeShim {
        seen: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl ComputeBindingResolver for FakeShim {
        async fn resolve(
            &self,
            _project: &str,
            _workload: &str,
            _replica: u32,
            bindings: &[ComputeBinding],
        ) -> Vec<(String, String)> {
            let mut out = Vec::new();
            let mut seen = self.seen.lock().unwrap();
            for b in bindings {
                seen.push(b.name.clone());
                out.push((format!("SHIM_{}", b.name), "shim-endpoint".to_string()));
            }
            out
        }
        async fn release(&self, _: &str, _: &str, _: u32, _: &[ComputeBinding]) {}
    }

    fn pg_binding_cfg() -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("appdb".into()),
            user: Some("app".into()),
            tenant: crate::config::TenantIsolation::Single,
            tenant_scope: crate::config::TenantScope::Project,
            ..Default::default()
        }
    }

    /// Build a resolver with one managed Postgres `databases` entry named "app", wrapping a
    /// `FakeShim`.
    fn resolver() -> (Arc<FakeShim>, ManagedDbDsnResolver) {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
        let shim = Arc::new(FakeShim::default());
        let databases = BTreeMap::from([("app".to_string(), pg_binding_cfg())]);
        let resolver =
            ManagedDbDsnResolver::wrap(Some(shim.clone()), databases, deploy, kv, envelope, None);
        (shim, resolver)
    }

    fn sql_binding(name: &str) -> ComputeBinding {
        ComputeBinding {
            kind: BindingKind::Sql,
            name: name.to_string(),
            url_env: None,
            migration_url_env: None,
        }
    }

    fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// A managed Postgres binding with a templated `env` value: the template is rendered
    /// SERVER-SIDE to a real DSN, AND the discrete `url_env`/`migration_url_env` defaults are
    /// injected. No shim call (the binding is managed, not libsql).
    #[tokio::test]
    async fn managed_pg_renders_template_and_injects_defaults() {
        let (shim, resolver) = resolver();
        let env = BTreeMap::from([(
            "SIMERTEC_DATABASE_URL".to_string(),
            "postgres://{{sql.user}}:{{sql.password}}@{{sql.host}}:{{sql.port}}/{{sql.database}}?sslmode=require"
                .to_string(),
        )]);
        let out = resolver
            .resolve_with_env("acme", "simertec", 0, &[sql_binding("app")], &env)
            .await;

        // The operator template is rendered to a real DSN (host = the per-tenant managed DB
        // workload's internal-DNS name, `pg-acme_<hash>`).
        let rendered = get(&out, "SIMERTEC_DATABASE_URL").expect("template rendered");
        assert!(rendered.starts_with("postgres://app:"));
        assert!(
            rendered.contains("@pg-acme"),
            "host is the per-tenant DB workload: {rendered}"
        );
        assert!(
            rendered.ends_with(":5432/appdb?sslmode=require"),
            "{rendered}"
        );
        // The discrete defaults are injected too (simple case Just Works).
        let default_url = get(&out, "BOATRAMP_SQL_URL").expect("default url_env injected");
        assert!(default_url.starts_with("postgres://app:"));
        assert!(default_url.contains("@pg-acme"));
        assert!(default_url.ends_with(":5432/appdb"));
        assert!(
            get(&out, "BOATRAMP_SQL_URL_MIGRATION").is_some(),
            "the migration DSN default is injected"
        );
        // The managed binding was NEVER delegated to the shim.
        assert!(shim.seen.lock().unwrap().is_empty());
    }

    /// The simple case: no template at all still injects the full runtime DSN + migration DSN.
    #[tokio::test]
    async fn managed_pg_default_injection_with_no_template() {
        let (_shim, resolver) = resolver();
        let out = resolver
            .resolve_with_env(
                "acme",
                "simertec",
                0,
                &[sql_binding("app")],
                &BTreeMap::new(),
            )
            .await;
        let url = get(&out, "BOATRAMP_SQL_URL").expect("default DSN injected");
        assert!(url.contains("@pg-acme"));
        assert!(url.ends_with(":5432/appdb"));
        assert!(get(&out, "BOATRAMP_SQL_URL_MIGRATION").is_some());
    }

    /// No-regression: a `sql` binding that is NOT a managed co-located pg/mysql DB (here an
    /// undeclared name = the per-site libsql default) is delegated to the shim, and gets NO
    /// DSN env.
    #[tokio::test]
    async fn libsql_or_undeclared_binding_falls_through_to_the_shim() {
        let (shim, resolver) = resolver();
        let out = resolver
            .resolve_with_env(
                "acme",
                "simertec",
                0,
                &[sql_binding("logs")],
                &BTreeMap::new(),
            )
            .await;
        // Delegated to the shim (its sentinel env is present), and no DSN env was composed.
        assert_eq!(get(&out, "SHIM_logs"), Some("shim-endpoint"));
        assert!(get(&out, "BOATRAMP_SQL_URL").is_none());
        assert_eq!(shim.seen.lock().unwrap().as_slice(), ["logs"]);
    }

    /// A hand-set LITERAL env value (no `{{…}}`) is left for the operator — the resolver
    /// neither renders it nor injects a default that would compete with it.
    #[tokio::test]
    async fn literal_operator_value_is_not_overridden() {
        let (_shim, resolver) = resolver();
        let env = BTreeMap::from([(
            "BOATRAMP_SQL_URL".to_string(),
            "postgres://hand:set@elsewhere/db".to_string(),
        )]);
        let out = resolver
            .resolve_with_env("acme", "simertec", 0, &[sql_binding("app")], &env)
            .await;
        // The resolver does not emit BOATRAMP_SQL_URL (the launch fold keeps the literal).
        assert!(
            get(&out, "BOATRAMP_SQL_URL").is_none(),
            "a literal must not be clobbered by the default DSN"
        );
        // The migration default (a key the operator did not set) is still injected.
        assert!(get(&out, "BOATRAMP_SQL_URL_MIGRATION").is_some());
    }

    /// Tenancy: two projects get DISTINCT DSNs (different per-tenant workload host).
    #[tokio::test]
    async fn dsn_is_tenant_scoped() {
        let (_shim, resolver) = resolver();
        let acme = resolver
            .resolve_with_env(
                "acme",
                "simertec",
                0,
                &[sql_binding("app")],
                &BTreeMap::new(),
            )
            .await;
        let globex = resolver
            .resolve_with_env(
                "globex",
                "simertec",
                0,
                &[sql_binding("app")],
                &BTreeMap::new(),
            )
            .await;
        assert!(get(&acme, "BOATRAMP_SQL_URL").unwrap().contains("@pg-acme"));
        assert!(
            get(&globex, "BOATRAMP_SQL_URL")
                .unwrap()
                .contains("@pg-globex")
        );
        assert_ne!(
            get(&acme, "BOATRAMP_SQL_URL"),
            get(&globex, "BOATRAMP_SQL_URL")
        );
    }
}
