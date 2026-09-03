//! Managed credentials for a boatramp-run SQL database (PLAN-managed-compute-sql,
//! Phase 2). boatramp generates a strong password on first use, seals it with the
//! secrets [`KeyEnvelope`], and persists it in the control-plane KV — **stable
//! across restarts** (the DB server was initialized with it) and **never stored in
//! cleartext**. The same password configures the DB workload's server env at launch
//! and connects the handler `sql` binding, so an operator sets no DB secret at all.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{ManagedDbEnvResolver, PrivilegeDirective, ReplicaPhase};

use crate::config::ManagedDbPrivilege;
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::SqlError;
use boatramp_storage::sql_compute::{ComputeEndpointResolver, ReplicaDiag};
use boatramp_storage::ExternalSqlKind;

/// The env vars a managed DB server image reads to **initialize on first boot** with
/// boatramp's managed credential — so the handler can then connect as `user`/`password`
/// to `database`. (Postgres: `POSTGRES_*`; MySQL: `MYSQL_*`, incl. a root password —
/// unused by handlers but required by the image to init.) Injected into the DB
/// workload's env at launch (P2-b); the values come from [`ManagedSqlCredentials`].
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub fn managed_db_server_env(
    kind: ExternalSqlKind,
    database: &str,
    user: &str,
    password: &str,
) -> Vec<(String, String)> {
    match kind {
        ExternalSqlKind::Postgres => vec![
            ("POSTGRES_USER".into(), user.into()),
            ("POSTGRES_PASSWORD".into(), password.into()),
            ("POSTGRES_DB".into(), database.into()),
        ],
        ExternalSqlKind::Mysql => vec![
            ("MYSQL_USER".into(), user.into()),
            ("MYSQL_PASSWORD".into(), password.into()),
            ("MYSQL_DATABASE".into(), database.into()),
            // The image requires a root password to initialize; reuse the managed
            // secret (root is not exposed to handlers, which connect as `user`).
            ("MYSQL_ROOT_PASSWORD".into(), password.into()),
        ],
    }
}

/// Generates + seals + persists a stable password per managed-DB workload.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct ManagedSqlCredentials {
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

impl ManagedSqlCredentials {
    /// Build over the control-plane KV and the secrets envelope. A managed DB
    /// requires an envelope (`[secrets]`) so the password is never stored in clear.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn new(kv: Arc<dyn KvStore>, envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { kv, envelope }
    }

    /// KV key holding a workload's sealed password.
    fn key(project: &str, workload: &str) -> String {
        format!("managed-sql-cred/{project}/{workload}")
    }

    /// The stable password for managed DB `workload` in `project`: unsealed from the
    /// store if present, else generated (32 random bytes → hex), sealed, and stored.
    /// Idempotent + stable across restarts, so the DB (initialized with it on first
    /// boot) keeps accepting the same credential.
    ///
    /// Single-node correct (get-then-put). A cluster where two nodes generate
    /// concurrently would race to a mismatch; that needs a put-if-absent (tracked in
    /// the plan) — not yet implemented here.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub async fn password(&self, project: &str, workload: &str) -> Result<String, String> {
        let key = Self::key(project, workload);
        if let Some(sealed) = self.kv.get(&key).await.map_err(|e| e.to_string())? {
            let plain = self
                .envelope
                .unwrap(&sealed)
                .await
                .map_err(|e| e.to_string())?;
            return String::from_utf8(plain).map_err(|_| {
                format!("managed sql credential for {workload:?} is not valid UTF-8")
            });
        }
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("rng: {e}"))?;
        let password: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let sealed = self
            .envelope
            .wrap(password.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        self.kv.put(&key, sealed).await.map_err(|e| e.to_string())?;
        Ok(password)
    }

    /// Delete a workload's sealed credential (a tenant deprovision hook). Idempotent:
    /// deleting an absent credential is a no-op (the underlying KV `delete` treats a
    /// missing key as success), so re-running a teardown is harmless.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub async fn delete(&self, project: &str, workload: &str) -> Result<(), String> {
        self.kv
            .delete(&Self::key(project, workload))
            .await
            .map_err(|e| e.to_string())
    }
}

/// One managed database's non-secret connection parts, keyed in [`ManagedDbEnv`]
/// by the compute **workload** that backs it.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
struct ManagedDbSpec {
    kind: ExternalSqlKind,
    database: String,
    user: String,
    /// The binding's isolation mechanism. A `Single` binding may also back a
    /// **per-tenant** workload named `<base>-<tenant_ident>`, so its server-init env
    /// must be resolvable under that derived name too (with a per-tenant credential
    /// keyed by the derived workload). A `Shared` binding never spawns a separate
    /// per-tenant workload (its per-tenant databases live inside the base server), so
    /// only its exact base name resolves.
    tenant: crate::config::TenantIsolation,
}

/// The node's [`ManagedDbEnvResolver`]: the set of managed databases (from the
/// handler `sql` config) keyed by backing workload, plus the sealed-credential
/// store. At launch the reconcile asks this for a workload's server-init env; a
/// non-managed workload gets nothing. Both sides (this injector and the handler's
/// [`ComputeResolvedSqlBackend`]) read the **same** sealed credential, so the DB is
/// initialized with exactly the password the handler later connects with.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct ManagedDbEnv {
    dbs: HashMap<String, ManagedDbSpec>,
    creds: ManagedSqlCredentials,
    /// How a managed DB's stock image runs on a shared-kernel backend so it can init
    /// (`[compute].managed_db_privilege`).
    privilege: ManagedDbPrivilege,
}

/// The uid:gid a stock DB image runs its server process as — both the official
/// `postgres` and `mysql` images use `999:999`. Used for the rootless strategy so the
/// entrypoint owns its pre-chowned volume without needing any capability.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
fn managed_db_default_ids(_kind: ExternalSqlKind) -> (u32, u32) {
    (999, 999)
}

/// The minimal capabilities a stock DB entrypoint needs when it runs as root: `chown`
/// its data dir + socket dir, then `gosu`/`su-exec` drop to the DB user.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
fn managed_db_caps() -> Vec<String> {
    ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

impl ManagedDbEnv {
    /// Build from the handler `sql` `databases` config + the credential store,
    /// selecting only the **managed** ones (compute-backed, no `password_env`).
    /// A database with an unparsable engine or missing parts is skipped (config
    /// validation already rejects those before serve).
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn from_config(
        databases: &std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
        creds: ManagedSqlCredentials,
        privilege: ManagedDbPrivilege,
    ) -> Self {
        let mut dbs = HashMap::new();
        for db in databases.values() {
            if !db.is_managed_credential() {
                continue;
            }
            let (Some(workload), Some(kind), Some(database), Some(user)) = (
                db.compute.clone(),
                ExternalSqlKind::parse(&db.kind),
                db.database.clone(),
                db.user.clone(),
            ) else {
                continue;
            };
            dbs.insert(
                workload,
                ManagedDbSpec {
                    kind,
                    database,
                    user,
                    tenant: db.tenant,
                },
            );
        }
        Self {
            dbs,
            creds,
            privilege,
        }
    }

    /// No managed databases configured — the caller can skip wiring this resolver.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.dbs.is_empty()
    }

    /// Resolve the launched `workload` to the [`ManagedDbSpec`] whose server-init env
    /// it needs. An exact match wins (the base workload — the shared server, or a
    /// single-tenant install). Otherwise a **`Single` per-tenant** workload
    /// `<base>-<tenant_ident>` maps back to its `Single` base spec, so a dedicated
    /// per-tenant container is initialized from the same binding — with its OWN
    /// per-tenant credential, keyed by its OWN `(project, workload)` (the reconcile
    /// passes the derived workload name, so `password(project, workload)` already
    /// keys per tenant). A `Shared` base never matches a `-suffixed` name (it spawns
    /// no per-tenant workload), so a stray derived name can never smuggle a Shared
    /// server's credential.
    fn resolve_spec(&self, workload: &str) -> Option<&ManagedDbSpec> {
        if let Some(spec) = self.dbs.get(workload) {
            return Some(spec);
        }
        // A `Single` per-tenant workload `<base>-<ident>`: match the `Single` base whose
        // name is a `-`-separated prefix of `workload`. `find_map` over a HashMap is
        // non-deterministic, and if one base is itself a `-`-prefix of another (e.g.
        // `pg` and `pg-metrics`, so `pg-metrics-<ident>` matches both) iteration order
        // would decide which spec's database/user fills the server-init env. Resolve to
        // the **longest** matching base instead — `pg-metrics` wins over `pg` — so the
        // choice is deterministic and unambiguous. (The credential key is exact, so this
        // is a robustness/correctness fix, not a cross-tenant reach.)
        self.dbs
            .iter()
            .filter(|(base, spec)| {
                matches!(spec.tenant, crate::config::TenantIsolation::Single)
                    && workload
                        .strip_prefix(base.as_str())
                        .is_some_and(|rest| rest.starts_with('-') && rest.len() > 1)
            })
            .max_by_key(|(base, _)| base.len())
            .map(|(_, spec)| spec)
    }
}

#[async_trait]
impl ManagedDbEnvResolver for ManagedDbEnv {
    async fn managed_db_env(&self, project: &str, workload: &str) -> Vec<(String, String)> {
        let Some(db) = self.resolve_spec(workload) else {
            return Vec::new();
        };
        // The credential key is the launched `(project, workload)` itself — the bare
        // base for the shared server / single-tenant install, or the derived
        // `<base>-<ident>` for a Single per-tenant container. So the init password and
        // the handler's connection password agree by construction (the resolver keys
        // it identically).
        match self.creds.password(project, workload).await {
            Ok(password) => managed_db_server_env(db.kind, &db.database, &db.user, &password),
            Err(e) => {
                // Fail closed on the env: without the sealed credential we must not
                // launch the DB with a blank/default password. An empty env means
                // the image refuses to initialize, which surfaces the misconfig.
                tracing::error!(
                    %workload,
                    error = %e,
                    "managed sql: could not resolve the sealed credential; DB launched without managed env"
                );
                Vec::new()
            }
        }
    }

    fn managed_db_privilege(&self, _project: &str, workload: &str) -> Option<PrivilegeDirective> {
        let db = self.resolve_spec(workload)?;
        Some(match self.privilege {
            ManagedDbPrivilege::Rootless => {
                let (uid, gid) = managed_db_default_ids(db.kind);
                PrivilegeDirective::Rootless { uid, gid }
            }
            ManagedDbPrivilege::Caps => PrivilegeDirective::Caps(managed_db_caps()),
        })
    }
}

/// Auto-register the compute workload(s) backing each **managed co-located** database
/// (compute-backed, no `password_env`), so declaring the `databases` binding is enough
/// to boot the DB at serve time — no separate `compute set` / apply step (turnkey from
/// a stock image on a bare host). Idempotent and non-clobbering: a workload the
/// operator declared explicitly (apply / admin API) always wins; this only fills an
/// absent one, and re-running is a no-op. Best-effort — a failure is logged, never
/// fatal (serving proceeds; the reconcile simply has nothing to launch for that DB
/// until its workload exists).
///
/// **Every compute-backed managed binding is per-tenant**, so this is tenant-aware —
/// it must never register a tenant-blind bare `<compute>`/`default` workload that would
/// collide with the tenant-aware `<compute>-<ident>` the resolver/provisioner produce
/// (two servers, two `initdb` passwords, auth chaos). Per isolation:
///
/// - **`Shared`** — one shared server hosts every tenant's per-tenant database + role,
///   so there IS exactly one server workload: the bare `<compute>` under the reserved
///   default project, initialized from the binding's own env. Register it (non-clobbering);
///   per-tenant DDL stays lazy (no boot-time connection).
/// - **`Single`** — each tenant gets a *dedicated* container `<compute>-<ident>`, created
///   durably by [`provision_single`](crate::tenant_sql::provision_single) /
///   [`provision_tenant`](crate::tenant_sql::provision_tenant) on the tenant's first `sql`
///   resolve (the lazy path), and relaunched by the reconcile on every boot. So there is
///   **nothing to warm at boot**: a tenant that has ever used the DB is already registered
///   (and thus relaunched), and a project that has never used `sql` — e.g. a static-only
///   `default` — must NOT get a spurious `pg`/`pg-<ident>`. The old boot-warm enumerated
///   any project with a *site or function* (not one that uses `sql`), which over-warmed
///   static-only projects into a running DB; dropped entirely here. (Result: a Single
///   binding registers no workload at boot; the first `sql` resolve provisions it.)
///
/// The synthesized spec comes from [`managed_db_spec`](boatramp_core::compute::managed_db_spec)
/// — the same builder the container capability gate exercises — so the shipped
/// managed-DB workload never diverges from the tested one.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub async fn auto_register_managed_db_workloads(
    deploy: &DeployStore,
    databases: &std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
) {
    use crate::config::TenantIsolation;

    for db in databases.values() {
        if !db.is_managed_credential() {
            continue;
        }
        let Some(workload) = db.compute.as_deref().filter(|c| !c.is_empty()) else {
            continue;
        };
        // Config validation rejects an unparsable engine before serve; skip defensively.
        if ExternalSqlKind::parse(&db.kind).is_none() {
            continue;
        }
        match db.tenant {
            // One shared server for all tenants: register the bare `<compute>` under the
            // reserved default project (per-tenant databases live inside it, provisioned
            // lazily — no boot-time connection).
            TenantIsolation::Shared => {
                register_shared_server(deploy, db, workload).await;
            }
            // A dedicated container per tenant, created durably by the lazy resolve
            // (`provision_single`) on first `sql` use and relaunched by the reconcile on
            // each boot. Nothing to warm at boot — warming any project with a site/function
            // (not one that uses `sql`) over-warmed static-only projects into a running DB.
            TenantIsolation::Single => {}
        }
    }
}

/// Register the ONE shared server workload for a `Shared` binding: the bare `<compute>`
/// under the reserved default project, non-clobbering (an operator-declared workload
/// wins; a re-run is a no-op). The synthesized spec is the tested `managed_db_spec` with
/// the historical `"data"` volume (a shared server is never per-tenant-volume-isolated).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
async fn register_shared_server(
    deploy: &DeployStore,
    db: &crate::config::ExternalDatabaseConfig,
    workload: &str,
) {
    use boatramp_core::compute::{
        managed_db_spec, ComputeWorkload, ManagedDbEngine, PlacementConstraints,
    };

    /// 10 GiB — the default managed data-volume size when the config sets none.
    const DEFAULT_VOLUME_MIB: u32 = 10 * 1024;

    let engine = match ExternalSqlKind::parse(&db.kind) {
        Some(ExternalSqlKind::Postgres) => ManagedDbEngine::Postgres,
        Some(ExternalSqlKind::Mysql) => ManagedDbEngine::Mysql,
        None => return,
    };
    // Non-clobbering: only fill an absent workload — an operator-declared one
    // (apply / admin API) always wins, which also makes re-runs idempotent.
    match deploy
        .get_compute_workload(ProjectRef::DEFAULT, workload)
        .await
    {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(%workload, error = %e, "managed sql: could not check for an existing compute workload; skipping auto-register");
            return;
        }
    }
    let image = db.image.as_deref();
    let mut spec = managed_db_spec(
        engine,
        image,
        db.volume_size_mib.unwrap_or(DEFAULT_VOLUME_MIB),
    );
    // An operator-set startup grace overrides the engine default the synthesizer picked.
    // Applied identically here and in `provision_single` so the two managed-registration
    // paths build the byte-identical (content-addressed) spec.
    if let Some(grace) = db.startup_grace_secs {
        spec.startup_grace_secs = grace;
    }
    let spec_id = match deploy.put_compute_spec(&spec).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(%workload, error = %e, "managed sql: could not store the auto-registered compute spec");
            return;
        }
    };
    let wl = ComputeWorkload {
        version: 1,
        name: workload.to_string(),
        active: spec_id,
        replicas: 1,
        placement: PlacementConstraints::default(),
    };
    match deploy.set_compute_workload(ProjectRef::DEFAULT, &wl).await {
        Ok(()) => tracing::info!(
            %workload,
            image = %image.unwrap_or_else(|| engine.default_image()),
            "managed sql: auto-registered the shared co-located database compute workload"
        ),
        Err(e) => {
            tracing::warn!(%workload, error = %e, "managed sql: could not register the auto-registered compute workload")
        }
    }
}

/// A [`ComputeEndpointResolver`] backed by the control-plane replica state: it
/// lists a workload's **healthy, running** replicas (primary-first by replica
/// index) as `(host, port)`, scoped to a fixed project. Backs the handler's
/// [`ComputeResolvedSqlBackend`](boatramp_storage::sql_compute::ComputeResolvedSqlBackend)
/// so a managed `sql` binding follows its DB workload across restarts.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct DeployEndpointResolver {
    deploy: DeployStore,
    project: String,
}

impl DeployEndpointResolver {
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn new(deploy: DeployStore, project: impl Into<String>) -> Self {
        Self {
            deploy,
            project: project.into(),
        }
    }
}

#[async_trait]
impl ComputeEndpointResolver for DeployEndpointResolver {
    async fn endpoints(&self, workload: &str) -> Result<Vec<(String, u16)>, SqlError> {
        let states = self
            .deploy
            .list_replica_states(ProjectRef::new(&self.project), workload)
            .await
            .map_err(SqlError::other)?;
        Ok(states
            .into_iter()
            .filter(|s| s.phase == ReplicaPhase::Running && s.healthy)
            .map(|s| (s.endpoint.host, s.endpoint.port))
            .collect())
    }

    /// Every replica state the control plane holds for `workload` (healthy or not), so
    /// a "no healthy replica" error can honestly say whether replicas exist but none
    /// passed the readiness probe — the reachability/health vs missing-workload split.
    /// Off the hot path (only when `endpoints` came back empty); a store error yields no
    /// diagnostics (the caller then falls back to the plainer message).
    async fn replica_diagnostics(&self, workload: &str) -> Vec<ReplicaDiag> {
        let states = match self
            .deploy
            .list_replica_states(ProjectRef::new(&self.project), workload)
            .await
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        states
            .into_iter()
            .map(|s| ReplicaDiag {
                endpoint: format!("{}:{}", s.endpoint.host, s.endpoint.port),
                healthy: s.healthy,
                phase: format!("{:?}", s.phase),
            })
            .collect()
    }
}

/// The node's [`OperatorSql`](boatramp_core::sql::OperatorSql): the operator-facing
/// migration/query capability over the handler `sql` `databases`. For a requested
/// database name it (re)builds the same connection the handler runtime uses — a
/// managed credential resolved + unsealed, or a bring-your-own URL from the
/// environment — and runs the script/query server-side (the credential never leaves
/// the node). Backs `POST /api/sql/{db}/{exec,query}`; admin-gated at the API.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub struct NodeOperatorSql {
    databases: std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
    kv: Arc<dyn KvStore>,
    envelope: Option<Arc<dyn KeyEnvelope>>,
    deploy: DeployStore,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl NodeOperatorSql {
    /// Build over the handler `sql` `databases` config + the credential store.
    pub fn new(
        databases: std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
        kv: Arc<dyn KvStore>,
        envelope: Option<Arc<dyn KeyEnvelope>>,
        deploy: DeployStore,
    ) -> Self {
        Self {
            databases,
            kv,
            envelope,
            deploy,
        }
    }

    /// Resolve + connect the SQL backend for database `db` in `project` (managed or
    /// bring-your-own), mirroring the handler runtime's per-database construction.
    async fn backend_for(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlOptions};
        let cfg = self
            .databases
            .get(db)
            .ok_or_else(|| SqlError::other(format!("no database named {db:?}")))?;
        let kind = ExternalSqlKind::parse(&cfg.kind).ok_or_else(|| {
            SqlError::other(format!("database {db:?}: unknown engine {:?}", cfg.kind))
        })?;
        let timeout = cfg.connect_timeout_secs.map(std::time::Duration::from_secs);
        if cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) {
            // Managed or brought-credential compute-backed database. Every compute-backed
            // binding is **per-tenant**, so derive the tenant the SAME way the resolver
            // does — otherwise operator `sql exec/query` would target the tenant-blind
            // bare `<compute>`/`default` (Bug 2's operator arm) and reach the wrong DB.
            let target = operator_target(cfg, project, db)?;

            // The password source: an operator-supplied `password_env` (brought
            // credential) reads the env var as before; a managed credential is unsealed
            // under EXACTLY the key the provisioner/resolver used for this tenant.
            let password = match cfg.password_env.as_deref().filter(|v| !v.is_empty()) {
                Some(var) => std::env::var(var)
                    .map_err(|_| SqlError::other(format!("env var {var} (password) is unset")))?,
                None => {
                    let envelope = self.envelope.clone().ok_or_else(|| {
                        SqlError::other(format!(
                            "managed database {db:?} needs a [secrets] envelope to unseal its credential"
                        ))
                    })?;
                    ManagedSqlCredentials::new(self.kv.clone(), envelope)
                        .password(&target.cred_project, &target.cred_workload)
                        .await
                        .map_err(SqlError::other)?
                }
            };

            let resolver = Arc::new(DeployEndpointResolver::new(
                self.deploy.clone(),
                target.endpoint_project,
            ));
            Ok(Arc::new(ComputeResolvedSqlBackend::new(
                resolver,
                target.workload,
                kind,
                target.database,
                target.user,
                password,
                cfg.pool_max,
                cfg.read_only,
                timeout,
            )))
        } else {
            // Bring-your-own URL (a secret named indirectly by an env var).
            let url = std::env::var(&cfg.url_env)
                .map_err(|_| SqlError::other(format!("env var {} (url) is unset", cfg.url_env)))?;
            let read_url =
                match &cfg.read_url_env {
                    Some(var) => Some(std::env::var(var).map_err(|_| {
                        SqlError::other(format!("env var {var} (read url) is unset"))
                    })?),
                    None => None,
                };
            let opts = ExternalSqlOptions::new(url)
                .with_read_url(read_url)
                .with_max_connections(cfg.pool_max)
                .read_only(cfg.read_only)
                .with_connect_timeout(timeout);
            connect(kind, &opts)
        }
    }
}

/// The tenant-resolved connection target for operator SQL against a compute-backed
/// managed binding — the SAME derivation the per-tenant resolver
/// (`NodeTenantSqlResolver::build_backend`) uses, so `sql exec/query` reaches the
/// tenant's OWN database + credential rather than the tenant-blind bare
/// `<compute>`/`default`. Pure (no IO), so the derivation is unit-testable.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[derive(Debug)]
pub(crate) struct OperatorTarget {
    /// The compute workload backing the connection (per-tenant for Single).
    pub workload: String,
    /// The physical database to connect to (the tenant's DB).
    pub database: String,
    /// The role/user to connect as.
    pub user: String,
    /// The project scope the workload's replica endpoints live under.
    pub endpoint_project: String,
    /// The `<project>` segment of the sealed credential's KV key.
    pub cred_project: String,
    /// The `<workload>` segment of the sealed credential's KV key.
    pub cred_workload: String,
}

/// Derive the operator-SQL connection target for a compute-backed managed binding.
///
/// Operator SQL is **project-level** (there is no site in a `POST /api/sql/{db}/...`
/// request), so the tenant is the project: `tenant_key(scope, project, "")`. A
/// **site-scoped** managed DB has no single database at the project level, so this
/// fails with a clear error rather than silently targeting the wrong (e.g. default) DB.
///
/// - **Single** — target the per-tenant workload `<compute>-<ident>` (bare `<compute>`
///   for the default tenant), connect as the configured `user` to `names.database`,
///   credential keyed by the workload's own `(single_credential_project, workload)`.
/// - **Shared** — target the shared `<compute>` server, connect as the configured
///   `user` (the server superuser, so an operator migration can touch any tenant's DB)
///   to `names.database`, credential = the superuser's under `(DEFAULT_PROJECT,
///   <compute>)`, never a per-tenant key.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub(crate) fn operator_target(
    cfg: &crate::config::ExternalDatabaseConfig,
    project: &str,
    db: &str,
) -> Result<OperatorTarget, SqlError> {
    use crate::config::{TenantIsolation, TenantScope};
    use crate::tenant_sql::{single_credential_project, tenant_key, tenant_names};
    use boatramp_core::project::DEFAULT_PROJECT;

    let compute = cfg
        .compute
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| SqlError::other(format!("database {db:?}: not compute-backed")))?;
    let database = cfg.database.as_deref().unwrap_or_default();
    let user = cfg.user.as_deref().unwrap_or_default();

    if matches!(cfg.tenant_scope, TenantScope::Site) {
        return Err(SqlError::other(format!(
            "database {db:?} is a site-scoped managed database; operator sql exec/query is \
             project-level and cannot target a specific site's database"
        )));
    }

    let (tenant_ident_raw, is_default) = tenant_key(cfg.tenant_scope, project, "");
    let names = tenant_names(cfg.tenant, compute, database, &tenant_ident_raw, is_default);

    let (cred_project, cred_workload) = match cfg.tenant {
        TenantIsolation::Single => (
            single_credential_project(project, is_default),
            names.workload.clone(),
        ),
        // Shared: the superuser credential, under the reserved default project + the
        // bare `<compute>` (exactly the server-init key), never a per-tenant key.
        TenantIsolation::Shared => (DEFAULT_PROJECT.to_string(), compute.to_string()),
    };
    let endpoint_project = match cfg.tenant {
        TenantIsolation::Single if !is_default => project.to_string(),
        _ => DEFAULT_PROJECT.to_string(),
    };

    Ok(OperatorTarget {
        workload: names.workload,
        database: names.database,
        user: user.to_string(),
        endpoint_project,
        cred_project,
        cred_workload,
    })
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[async_trait]
impl boatramp_core::sql::OperatorSql for NodeOperatorSql {
    async fn exec_script(&self, project: &str, db: &str, script: &str) -> Result<(), SqlError> {
        self.backend_for(project, db)
            .await?
            .run_script(script)
            .await
    }

    async fn query(
        &self,
        project: &str,
        db: &str,
        sql: &str,
    ) -> Result<boatramp_core::sql::SqlRows, SqlError> {
        self.backend_for(project, db).await?.run_query(sql).await
    }

    async fn ping(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Vec<boatramp_core::sql::SqlPingReplica>, SqlError> {
        use boatramp_core::sql::SqlPingReplica;
        use std::time::Duration;
        let cfg = self
            .databases
            .get(db)
            .ok_or_else(|| SqlError::other(format!("no database named {db:?}")))?;
        // A bring-your-own-URL binding isn't compute-backed, so there is no replica
        // fleet to probe — ping is for managed co-located databases.
        if !cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) {
            return Err(SqlError::other(format!(
                "database {db:?} is not compute-backed; `sql ping` probes managed co-located \
                 replicas only"
            )));
        }
        // Derive the tenant's workload + endpoint project EXACTLY as `backend_for` does,
        // then read ALL replicas (healthy or not) from the resolver — bypassing the
        // healthy filter that `query` would hit — and actively TCP-probe each.
        let target = operator_target(cfg, project, db)?;
        let resolver = DeployEndpointResolver::new(self.deploy.clone(), target.endpoint_project);
        let diags = resolver.replica_diagnostics(&target.workload).await;
        let mut out = Vec::with_capacity(diags.len());
        for d in diags {
            let reachable = match d.endpoint.parse::<std::net::SocketAddr>() {
                Ok(addr) => matches!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::TcpStream::connect(addr),
                    )
                    .await,
                    Ok(Ok(_))
                ),
                // An unparsable endpoint can't be probed — report it as unreachable.
                Err(_) => false,
            };
            out.push(SqlPingReplica {
                endpoint: d.endpoint,
                healthy: d.healthy,
                phase: d.phase,
                tcp_reachable: reachable,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;

    /// A trivial reversible "envelope" for tests — NOT encryption; it just proves the
    /// stored blob is transformed (sealed) and round-trips (cf. cert.rs's test double).
    struct ReverseEnvelope;
    #[async_trait]
    impl KeyEnvelope for ReverseEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().rev().copied().collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().rev().copied().collect())
        }
    }

    #[tokio::test]
    async fn password_is_generated_once_sealed_and_stable() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let creds = ManagedSqlCredentials::new(kv.clone(), Arc::new(ReverseEnvelope));

        let pw = creds.password("default", "pg").await.unwrap();
        assert_eq!(pw.len(), 64, "32 random bytes, hex-encoded");

        // Stable: a second call unseals the stored value, it is not regenerated.
        assert_eq!(creds.password("default", "pg").await.unwrap(), pw);

        // Stored SEALED, never in cleartext.
        let raw = kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            raw,
            pw.as_bytes(),
            "the stored blob is sealed, not the password"
        );
        assert_eq!(
            raw.iter().rev().copied().collect::<Vec<u8>>(),
            pw.as_bytes()
        );

        // A fresh store instance (a restart) unseals the SAME password.
        let after_restart = ManagedSqlCredentials::new(kv, Arc::new(ReverseEnvelope));
        assert_eq!(after_restart.password("default", "pg").await.unwrap(), pw);

        // A different workload gets a different password.
        assert_ne!(creds.password("default", "other").await.unwrap(), pw);
    }

    #[test]
    fn server_env_recipe_per_engine() {
        let pg = managed_db_server_env(ExternalSqlKind::Postgres, "analytics", "app", "pw");
        assert_eq!(
            pg,
            vec![
                ("POSTGRES_USER".into(), "app".into()),
                ("POSTGRES_PASSWORD".into(), "pw".into()),
                ("POSTGRES_DB".into(), "analytics".into()),
            ]
        );
        let my = managed_db_server_env(ExternalSqlKind::Mysql, "shop", "app", "pw");
        // MySQL needs a root password to initialize, plus the app user/db.
        assert!(my.contains(&("MYSQL_USER".into(), "app".into())));
        assert!(my.contains(&("MYSQL_DATABASE".into(), "shop".into())));
        assert!(my.contains(&("MYSQL_ROOT_PASSWORD".into(), "pw".into())));
    }

    use crate::config::ExternalDatabaseConfig;
    use std::collections::BTreeMap;

    fn db(
        kind: &str,
        compute: Option<&str>,
        url_env: &str,
        pw_env: Option<&str>,
    ) -> ExternalDatabaseConfig {
        ExternalDatabaseConfig {
            kind: kind.into(),
            url_env: url_env.into(),
            compute: compute.map(Into::into),
            database: compute.map(|_| "analytics".into()),
            user: compute.map(|_| "app".into()),
            password_env: pw_env.map(Into::into),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn managed_db_env_only_covers_managed_workloads() {
        let mut dbs = BTreeMap::new();
        // Managed: compute-backed, no password_env.
        dbs.insert(
            "analytics".to_string(),
            db("postgres", Some("pg"), "", None),
        );
        // Bring-your-own credential: compute-backed WITH password_env → not managed.
        dbs.insert(
            "byo".to_string(),
            db("postgres", Some("pg2"), "", Some("PG2_PW")),
        );
        // Bring-your-own URL: not compute-backed → not managed.
        dbs.insert("ext".to_string(), db("mysql", None, "MYSQL_URL", None));

        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let creds = ManagedSqlCredentials::new(kv, Arc::new(ReverseEnvelope));
        let env = ManagedDbEnv::from_config(&dbs, creds, ManagedDbPrivilege::default());
        assert!(!env.is_empty());

        // The managed workload gets a rootless privilege directive by default; the
        // non-managed ones get none.
        assert_eq!(
            env.managed_db_privilege("default", "pg"),
            Some(PrivilegeDirective::Rootless { uid: 999, gid: 999 })
        );
        assert_eq!(env.managed_db_privilege("default", "nope"), None);

        // The managed workload gets its server-init env, sealed-password-derived.
        let pg = env.managed_db_env("default", "pg").await;
        assert!(pg.contains(&("POSTGRES_USER".into(), "app".into())));
        assert!(pg.contains(&("POSTGRES_DB".into(), "analytics".into())));
        let password = pg
            .iter()
            .find(|(k, _)| k == "POSTGRES_PASSWORD")
            .map(|(_, v)| v.clone())
            .expect("password present");
        assert_eq!(password.len(), 64, "managed 32-byte hex password");
        // Idempotent: the same sealed credential each call.
        let pg2 = env.managed_db_env("default", "pg").await;
        assert_eq!(pg, pg2);

        // The BYO-credential + BYO-URL workloads are NOT managed here.
        assert!(env.managed_db_env("default", "pg2").await.is_empty());
        assert!(env.managed_db_env("default", "nope").await.is_empty());
    }

    /// L3: when one `Single` compute base (`pg`) is a `-`-prefix of another
    /// (`pg-metrics`), a per-tenant workload `pg-metrics-<ident>` is a valid derived
    /// name for BOTH. `resolve_spec` must pick the **longest** matching base
    /// deterministically (`pg-metrics`), not whichever the HashMap iterates first, so
    /// the server-init env is filled from the right binding's database/user.
    #[tokio::test]
    async fn resolve_spec_prefers_the_longest_matching_single_base() {
        use crate::config::TenantIsolation;

        // Two Single bindings whose compute names are prefix-related. Give them
        // distinct databases so the resolved spec is observable.
        let mut pg = db("postgres", Some("pg"), "", None);
        pg.tenant = TenantIsolation::Single;
        pg.database = Some("appdb".into());
        pg.user = Some("app".into());

        let mut pg_metrics = db("postgres", Some("pg-metrics"), "", None);
        pg_metrics.tenant = TenantIsolation::Single;
        pg_metrics.database = Some("metricsdb".into());
        pg_metrics.user = Some("metrics".into());

        let mut dbs = BTreeMap::new();
        dbs.insert("analytics".to_string(), pg);
        dbs.insert("metrics".to_string(), pg_metrics);

        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let creds = ManagedSqlCredentials::new(kv, Arc::new(ReverseEnvelope));
        let env = ManagedDbEnv::from_config(&dbs, creds, ManagedDbPrivilege::default());

        // A per-tenant workload of `pg-metrics` matches both `pg` and `pg-metrics`;
        // the longest base (`pg-metrics`) must win → the metrics database/user.
        let e = env.managed_db_env("acme", "pg-metrics-acme").await;
        assert!(
            e.contains(&("POSTGRES_DB".into(), "metricsdb".into())),
            "longest base (`pg-metrics`) must win over `pg`: {e:?}"
        );
        assert!(e.contains(&("POSTGRES_USER".into(), "metrics".into())));

        // A per-tenant workload of the shorter base still resolves to `pg`.
        let e = env.managed_db_env("acme", "pg-acme").await;
        assert!(e.contains(&("POSTGRES_DB".into(), "appdb".into())));
        assert!(e.contains(&("POSTGRES_USER".into(), "app".into())));

        // The privilege lookup uses the same resolver, so it is unambiguous too.
        assert_eq!(
            env.managed_db_privilege("acme", "pg-metrics-acme"),
            Some(PrivilegeDirective::Rootless { uid: 999, gid: 999 })
        );
    }

    // A no-op object store so a `DeployStore` can be built for the KV-only replica
    // state the endpoint resolver reads.
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
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

    fn replica(
        workload: &str,
        replica: u32,
        host: &str,
        port: u16,
        healthy: bool,
        phase: ReplicaPhase,
    ) -> boatramp_core::compute::ObservedInstance {
        use boatramp_core::compute::{Endpoint, InstanceHandle, Scheme};
        boatramp_core::compute::ObservedInstance {
            handle: InstanceHandle {
                project: "default".into(),
                workload: workload.into(),
                replica,
                backend_ref: String::new(),
            },
            node: 0,
            backend: "fake".into(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: host.into(),
                port,
            },
            region: None,
            healthy,
            started_at: None,
            phase,
            snapshot: None,
        }
    }

    #[tokio::test]
    async fn endpoint_resolver_returns_only_healthy_running_replicas() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let p = ProjectRef::DEFAULT;
        // Two healthy running replicas, one unhealthy, one parked (Zero).
        deploy
            .set_replica_state(
                p,
                &replica("pg", 0, "10.0.0.1", 5432, true, ReplicaPhase::Running),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                p,
                &replica("pg", 1, "10.0.0.2", 5432, true, ReplicaPhase::Running),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                p,
                &replica("pg", 2, "10.0.0.3", 5432, false, ReplicaPhase::Running),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                p,
                &replica("pg", 3, "10.0.0.4", 5432, false, ReplicaPhase::Zero),
            )
            .await
            .unwrap();

        let resolver = DeployEndpointResolver::new(deploy, "default");
        let mut eps = resolver.endpoints("pg").await.unwrap();
        eps.sort();
        assert_eq!(
            eps,
            vec![
                ("10.0.0.1".to_string(), 5432),
                ("10.0.0.2".to_string(), 5432)
            ],
            "only the healthy running replicas, unhealthy + Zero filtered out"
        );
        // A workload with no replicas resolves to nothing (a clear no-endpoint state).
        assert!(resolver.endpoints("absent").await.unwrap().is_empty());
    }

    /// A `Shared` binding registers exactly ONE shared server (bare `<compute>` under
    /// the reserved default project), idempotently + non-clobbering. Per-tenant DDL is
    /// lazy, so no envelope is needed for Shared boot-warm.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[tokio::test]
    async fn auto_register_shared_registers_one_server_idempotently_and_never_clobbers() {
        use crate::config::TenantIsolation;
        use boatramp_core::compute::{ComputeWorkload, PlacementConstraints};

        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let p = ProjectRef::DEFAULT;

        let mut shared = db("postgres", Some("pg"), "", None);
        shared.tenant = TenantIsolation::Shared;

        let mut dbs = BTreeMap::new();
        dbs.insert("analytics".to_string(), shared);
        // BYO credential (compute-backed WITH password_env) → NOT managed, NOT registered.
        dbs.insert(
            "byo".to_string(),
            db("postgres", Some("byopg"), "", Some("PW")),
        );
        // BYO URL (not compute-backed) → NOT registered.
        dbs.insert("ext".to_string(), db("mysql", None, "MYSQL_URL", None));

        auto_register_managed_db_workloads(&deploy, &dbs).await;

        // The shared server workload was registered, desired 1 replica, spec stored.
        let wl = deploy
            .get_compute_workload(p, "pg")
            .await
            .unwrap()
            .expect("shared server workload `pg` auto-registered");
        assert_eq!(wl.replicas, 1);
        assert!(!wl.active.is_empty(), "an active spec hash was stored");
        assert!(
            deploy
                .get_compute_workload(p, "byopg")
                .await
                .unwrap()
                .is_none(),
            "a BYO-credential DB is not auto-registered"
        );

        // Idempotent: a second pass leaves the same active spec (no churn).
        auto_register_managed_db_workloads(&deploy, &dbs).await;
        let wl2 = deploy.get_compute_workload(p, "pg").await.unwrap().unwrap();
        assert_eq!(wl2.active, wl.active, "re-run is a no-op");

        // Non-clobbering: an operator-declared workload (apply / admin API) wins.
        let operator = ComputeWorkload {
            version: 1,
            name: "pg".to_string(),
            active: "operatorspec".to_string(),
            replicas: 3,
            placement: PlacementConstraints::default(),
        };
        deploy.set_compute_workload(p, &operator).await.unwrap();
        auto_register_managed_db_workloads(&deploy, &dbs).await;
        let after = deploy.get_compute_workload(p, "pg").await.unwrap().unwrap();
        assert_eq!(
            after.replicas, 3,
            "auto-register must not overwrite the operator's workload"
        );
        assert_eq!(after.active, "operatorspec");
    }

    /// Seed a `project` that exists (so `list_projects` returns it) and has a deployed
    /// `site` (so `list_sites` returns it — the "has resources" signal). The project
    /// pointer goes through `put_project`; the site's current-deployment pointer is
    /// written directly (`project/<proj>/current/<site>`, per `deploy::keys::current`) —
    /// exactly what `activate` leaves behind, without needing a real blob backend.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    async fn seed_project_with_site(
        deploy: &DeployStore,
        kv: &Arc<dyn KvStore>,
        project: &str,
        site: &str,
    ) {
        deploy
            .put_project(&boatramp_core::project::Project {
                version: 1,
                name: project.to_string(),
                created_at: 0,
                meta: Default::default(),
                config: Default::default(),
                secrets_ref: None,
            })
            .await
            .expect("seed the project pointer");
        let key = format!("project/{project}/current/{site}");
        kv.put(&key, b"deadbeef".to_vec())
            .await
            .expect("seed a current site deployment pointer");
    }

    /// Fix 1: a `Single` binding registers **nothing at boot** — even for a project with
    /// deployed resources. The per-tenant `pg-<ident>` is created durably by the lazy
    /// resolve (`provision_single`/`provision_tenant`) on the first `sql` use and
    /// relaunched by the reconcile; the old boot-warm enumerated projects by
    /// site/function (not `sql` use) and so over-warmed static-only projects into a
    /// spurious DB. There must be no bare `pg`/`default` and no `pg-<ident>` at boot.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[tokio::test]
    async fn auto_register_single_registers_nothing_at_boot() {
        use crate::config::{TenantIsolation, TenantScope};
        use crate::tenant_sql::tenant_key;
        use boatramp_storage::tenant_provision::sanitize_ident;

        let store_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), store_kv.clone());

        // A `construens` project that HAS a site — under the old boot-warm this would have
        // been enumerated + provisioned into a `pg-<ident>`. It must NOT be now.
        seed_project_with_site(&deploy, &store_kv, "construens", "app").await;

        let mut single = db("postgres", Some("pg"), "", None);
        single.tenant = TenantIsolation::Single; // (the default, made explicit)
        single.tenant_scope = TenantScope::Project;

        let mut dbs = BTreeMap::new();
        dbs.insert("main".to_string(), single);

        auto_register_managed_db_workloads(&deploy, &dbs).await;

        // No per-tenant `pg-<ident>` under the resourced project.
        let (raw, _is_default) = tenant_key(TenantScope::Project, "construens", "");
        let derived = format!("pg-{}", sanitize_ident(&raw));
        assert!(
            deploy
                .get_compute_workload(ProjectRef::new("construens"), &derived)
                .await
                .unwrap()
                .is_none(),
            "a Single binding must NOT boot-warm a per-tenant `pg-<ident>` (that is the lazy \
             resolve's job on first `sql` use)"
        );
        // No tenant-blind bare `pg`/`default` either.
        assert!(
            deploy
                .get_compute_workload(ProjectRef::DEFAULT, "pg")
                .await
                .unwrap()
                .is_none(),
            "a Single binding must NOT register a tenant-blind bare `pg`/`default`"
        );
        // Nothing anywhere — a Single binding is a complete no-op at boot.
        assert!(
            deploy
                .list_compute_workloads_all()
                .await
                .unwrap()
                .is_empty(),
            "a Single binding registers no managed workload at boot"
        );
    }

    /// Fix 1 (the over-warming bug proper): a `Single` binding + a project that owns ONLY
    /// a static site (never used `sql`) must register **no** managed workload at boot —
    /// no spurious `pg`/`pg-<ident>`. This is the exact construens repro (a static-only
    /// `default` was getting a bogus `pg`).
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[tokio::test]
    async fn auto_register_single_static_only_project_gets_no_db_at_boot() {
        use crate::config::{TenantIsolation, TenantScope};

        let store_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(Arc::new(NullStorage), store_kv.clone());

        // The reserved `default` project owns only a static site — it has never resolved
        // `sql`, so no managed DB should ever be provisioned for it.
        seed_project_with_site(&deploy, &store_kv, "default", "www").await;

        let mut single = db("postgres", Some("pg"), "", None);
        single.tenant = TenantIsolation::Single;
        single.tenant_scope = TenantScope::Project;

        let mut dbs = BTreeMap::new();
        dbs.insert("main".to_string(), single);

        auto_register_managed_db_workloads(&deploy, &dbs).await;

        assert!(
            deploy
                .list_compute_workloads_all()
                .await
                .unwrap()
                .is_empty(),
            "a static-only project must not get a spurious managed `pg` at boot"
        );
    }

    /// Fix 2 (Bug 2, operator arm): for a `Single` project-scoped binding, operator
    /// `sql exec/query` must target the per-tenant workload `pg-<ident>` under the
    /// tenant's project and the per-tenant credential key — NOT the tenant-blind bare
    /// `pg`/`default`. Asserted on the pure `operator_target` derivation.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn operator_target_single_targets_per_tenant_workload_and_cred() {
        use crate::config::{TenantIsolation, TenantScope};
        use crate::tenant_sql::tenant_key;
        use boatramp_storage::tenant_provision::sanitize_ident;

        let mut single = db("postgres", Some("pg"), "", None);
        single.tenant = TenantIsolation::Single;
        single.tenant_scope = TenantScope::Project;
        single.database = Some("appdb".into());
        single.user = Some("app".into());

        // Non-default project tenant → derived per-tenant workload under its project.
        let (raw, is_default) = tenant_key(TenantScope::Project, "construens", "");
        assert!(!is_default);
        let ident = sanitize_ident(&raw);
        let derived = format!("pg-{ident}");

        let t = operator_target(&single, "construens", "main").unwrap();
        assert_eq!(
            t.workload, derived,
            "targets the per-tenant workload, not bare `pg`"
        );
        assert_eq!(t.database, "appdb");
        assert_eq!(t.user, "app");
        assert_eq!(
            t.endpoint_project, "construens",
            "a Single per-tenant workload's replicas live under its project"
        );
        // The credential key is the workload's OWN `(project, workload)` — matching
        // provision_single + the server-init env injector, so operator SQL unseals the
        // SAME password the container was initialized with.
        assert_eq!(t.cred_project, "construens");
        assert_eq!(t.cred_workload, derived);
        assert_ne!(
            t.cred_workload, "pg",
            "never the bare tenant-blind workload"
        );

        // The reserved default project keeps the plain names (single-tenant install).
        let d = operator_target(&single, "default", "main").unwrap();
        assert_eq!(d.workload, "pg");
        assert_eq!(d.cred_project, "default");
        assert_eq!(d.cred_workload, "pg");
        assert_eq!(d.endpoint_project, "default");
    }

    /// Fix 2: a `Shared` binding's operator SQL targets the shared server as the
    /// superuser (credential under the reserved default project + bare `<compute>`)
    /// against the tenant's per-tenant database.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn operator_target_shared_uses_superuser_cred_against_tenant_db() {
        use crate::config::{TenantIsolation, TenantScope};
        use crate::tenant_sql::tenant_key;
        use boatramp_core::project::DEFAULT_PROJECT;
        use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name};

        let mut shared = db("postgres", Some("pg"), "", None);
        shared.tenant = TenantIsolation::Shared;
        shared.tenant_scope = TenantScope::Project;
        shared.database = Some("appdb".into());
        shared.user = Some("postgres".into());

        let (raw, _) = tenant_key(TenantScope::Project, "construens", "");
        let ident = sanitize_ident(&raw);

        let t = operator_target(&shared, "construens", "main").unwrap();
        // The shared server workload, the tenant's per-tenant database, superuser user.
        assert_eq!(t.workload, "pg");
        assert_eq!(t.database, tenant_db_name("appdb", &ident));
        assert_eq!(t.user, "postgres");
        // The superuser credential key — reserved default project + bare `<compute>`.
        assert_eq!(t.cred_project, DEFAULT_PROJECT);
        assert_eq!(t.cred_workload, "pg");
        assert_eq!(t.endpoint_project, DEFAULT_PROJECT);
    }

    /// Fix 2: a **site-scoped** managed DB has no single project-level database, so
    /// operator SQL fails with a clear error rather than hitting the wrong DB.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn operator_target_site_scoped_errors_clearly() {
        use crate::config::{TenantIsolation, TenantScope};

        let mut site = db("postgres", Some("pg"), "", None);
        site.tenant = TenantIsolation::Single;
        site.tenant_scope = TenantScope::Site;

        let err = operator_target(&site, "construens", "main").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("site-scoped"),
            "the error explains a site-scoped DB needs a site: {msg}"
        );
    }
}
