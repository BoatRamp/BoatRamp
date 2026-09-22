//! Managed credentials for a boatramp-run SQL database (PLAN-managed-compute-sql,
//! Phase 2). boatramp generates a strong password on first use, seals it with the
//! secrets [`KeyEnvelope`], and persists it in the control-plane KV — **stable
//! across restarts** (the DB server was initialized with it) and **never stored in
//! cleartext**. The same password configures the DB workload's server env at launch
//! and connects the handler `sql` binding, so an operator sets no DB secret at all.

use std::sync::Arc;

use async_trait::async_trait;

// The Postgres/MySQL managed-credential + operator-SQL machinery (sqlx) uses these; a migrate-only
// build (embedded libsql substrate, no sqlx engine) does not, so they are gated on the sqlx features.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use crate::config::ManagedDbPrivilege;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_core::compute::{ManagedDbEnvResolver, PrivilegeDirective, ReplicaPhase};
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_core::deploy::DeployStore;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_core::envelope::KeyEnvelope;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_core::kv::KvStore;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_core::project::ProjectRef;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_core::sql::SqlError;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
use boatramp_core::sql::{
    AppliedMigration, LedgerOrigin, MigrateDdl, MigrateDdlError, MigrationError, MigrationStep,
    MigrationSubstrate, SubstrateStepOutcome,
};
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_storage::sql_compute::{ComputeEndpointResolver, ReplicaDiag};
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use boatramp_storage::ExternalSqlKind;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
use std::collections::HashMap;

/// The env vars a managed DB server image reads to **initialize on first boot** with
/// boatramp's managed credential — so the handler can then connect as `user`/`password`
/// to `database`. (Postgres: `POSTGRES_*`; MySQL: `MYSQL_*`, incl. a root password —
/// unused by handlers but required by the image to init.) Injected into the DB
/// workload's env at launch (P2-b); the values come from [`ManagedSqlCredentials`].
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct ManagedSqlCredentials {
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
fn managed_db_default_ids(_kind: ExternalSqlKind) -> (u32, u32) {
    (999, 999)
}

/// The minimal capabilities a stock DB entrypoint needs when it runs as root: `chown`
/// its data dir + socket dir, then `gosu`/`su-exec` drop to the DB user.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
fn managed_db_caps() -> Vec<String> {
    ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct DeployEndpointResolver {
    deploy: DeployStore,
    project: String,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl DeployEndpointResolver {
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn new(deploy: DeployStore, project: impl Into<String>) -> Self {
        Self {
            deploy,
            project: project.into(),
        }
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
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
    /// bring-your-own), mirroring the handler runtime's per-database construction. The
    /// operator path (`sql exec/query/ping`) — connects as the configured identity (the
    /// superuser on a Shared server).
    pub(crate) async fn backend_for(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        self.connect_for(project, db, false).await
    }

    /// Resolve + connect as the project **owner** role (the schema-migration path). Identical
    /// to [`backend_for`](Self::backend_for) except on a Shared server it connects as the
    /// per-project non-superuser owner role with the sealed owner credential — never the
    /// cluster superuser (see [`owner_target`]).
    pub(crate) async fn owner_backend_for(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        self.connect_for(project, db, true).await
    }

    /// The SQL engine of managed database `db`, if configured (for the migration runner's
    /// engine gate).
    pub(crate) fn engine_kind(&self, db: &str) -> Option<ExternalSqlKind> {
        self.databases
            .get(db)
            .and_then(|cfg| ExternalSqlKind::parse(&cfg.kind))
    }

    /// Connect as the **MySQL DDL identity** — the owner-role analog for a backend with no
    /// owner/runtime role split. MySQL never mints a separate DDL user at provision (the runtime
    /// user gets `GRANT ALL ON <db>.*`, so it is itself DDL-capable within its schema); running
    /// migration DDL as that runtime tenant identity would violate the surface's core safety
    /// (`DDL runs as a non-runtime identity`). So the DDL identity must be supplied **explicitly**
    /// via `migration_url_env`, and it must be a **distinct login** from the runtime binding. Absent
    /// it — or if it resolves to the same URL, or authenticates as the same **username**, as the
    /// runtime `url_env` — we **refuse** fail-closed rather than run owner-DDL as the runtime user
    /// (there is no owner-role fallback on MySQL). The distinctness invariant is "DDL login ≠ runtime
    /// tenant login," not "different string" ([Security review HIGH-1]) — two equivalent DSNs that
    /// authenticate as the same user are treated as the same identity.
    ///
    /// A **compute-backed managed** MySQL binding (`compute` set, empty `url_env`) is **refused
    /// outright** this release ([Security review HIGH-2]): there is no runtime URL to check the DDL
    /// identity against, and boatramp cannot yet auto-mint a distinct least-privilege DDL grant for a
    /// managed MySQL database — so running migration DDL for it would skip the distinctness barrier.
    ///
    /// The DDL URL is read from the environment (the operator supplies an admin/DDL login DSN,
    /// e.g. a purpose-made `_migrate` grant or an admin account), never from anything a guest
    /// influences. The credential stays on the node (as with every other `sql` connection).
    async fn mysql_ddl_backend_for(
        &self,
        db: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlOptions};
        let cfg = self
            .databases
            .get(db)
            .ok_or_else(|| SqlError::other(format!("no database named {db:?}")))?;

        // [Security review HIGH-2] A **compute-backed managed** MySQL binding (`compute` set, no
        // runtime `url_env`) gets NO distinctness enforcement in the block below (there is no
        // runtime URL to compare against), and boatramp cannot yet auto-mint a distinct
        // least-privilege DDL identity for a managed MySQL database. Rather than run migration DDL
        // as an under-checked identity, refuse it fail-closed this release. (Auto-minting a
        // `<db>_migrate` grant is a documented follow-up.)
        let compute_backed = cfg.compute.as_deref().is_some_and(|c| !c.is_empty());
        if compute_backed && cfg.url_env.is_empty() {
            return Err(SqlError::other(format!(
                "database {db:?}: compute-backed managed MySQL migration is not supported this \
                 release: boatramp cannot yet auto-derive a distinct least-privilege DDL identity \
                 for a managed MySQL database; use an external MySQL binding with a distinct \
                 `migration_url_env`, or await the auto-minted DDL-grant follow-up"
            )));
        }

        let migration_var = cfg
            .migration_url_env
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                SqlError::other(format!(
                    "database {db:?}: MySQL schema migrations require a distinct DDL identity — set \
                     `migration_url_env` to an admin/DDL connection URL that is NOT the runtime \
                     `user`/`url_env` (MySQL has no owner/runtime role split; running DDL as the \
                     runtime tenant user is refused fail-closed)"
                ))
            })?;
        let ddl_url = std::env::var(migration_var).map_err(|_| {
            SqlError::other(format!(
                "env var {migration_var} (migration/DDL url for {db:?}) is unset"
            ))
        })?;

        // Fail closed if the DDL URL is the SAME identity as the runtime binding. For a
        // bring-your-own-URL binding the runtime identity IS `url_env` (a compute-backed managed
        // binding was already refused above). The invariant is "DDL login ≠ runtime tenant login,"
        // NOT "different string" ([Security review HIGH-1]) — so parse both DSNs and refuse when the
        // **username** matches (two equivalent DSNs like `…/db` vs `…/db?charset=utf8` authenticate
        // as the same user). The byte-equality check is kept as an additional cheap catch; a DSN
        // that won't parse falls back to it (fail-closed on the strictest available signal).
        if !cfg.url_env.is_empty() {
            if let Ok(runtime_url) = std::env::var(&cfg.url_env) {
                if runtime_url == ddl_url {
                    return Err(SqlError::other(format!(
                        "database {db:?}: `migration_url_env` resolves to the SAME connection as the \
                         runtime `url_env` — the MySQL DDL identity must be distinct from the runtime \
                         user (refused fail-closed)"
                    )));
                }
                // The username-distinctness parse needs sqlx's MySQL DSN parser (the `sql-mysql`
                // feature). A MySQL binding can only actually connect under that feature anyway (the
                // `connect(Mysql, …)` below refuses without it), so a `sql-postgres`-only build keeps
                // just the byte-equality catch above — it can never run MySQL DDL regardless.
                #[cfg(feature = "sql-mysql")]
                {
                    let ddl_user = boatramp_storage::sql_sqlx::mysql_dsn_username(&ddl_url);
                    let runtime_user = boatramp_storage::sql_sqlx::mysql_dsn_username(&runtime_url);
                    if let (Some(ddl_user), Some(runtime_user)) = (&ddl_user, &runtime_user) {
                        if ddl_user == runtime_user {
                            return Err(SqlError::other(format!(
                                "database {db:?}: `migration_url_env` authenticates as the SAME \
                                 MySQL user ({ddl_user:?}) as the runtime `url_env` — the DDL login \
                                 must be a DISTINCT identity from the runtime tenant login (refused \
                                 fail-closed)"
                            )));
                        }
                    }
                }
            }
        }

        let timeout = cfg.connect_timeout_secs.map(std::time::Duration::from_secs);
        let opts = ExternalSqlOptions::new(ddl_url)
            .with_max_connections(cfg.pool_max)
            // The DDL connection must be writable — never inherit the binding's `read_only`.
            .read_only(false)
            .with_connect_timeout(timeout);
        connect(ExternalSqlKind::Mysql, &opts)
    }

    /// Shared body of [`backend_for`](Self::backend_for) / [`owner_backend_for`](Self::owner_backend_for):
    /// `owner` selects [`owner_target`] (the non-superuser owner role) over [`operator_target`]
    /// (the configured/superuser identity) for the compute-backed case.
    async fn connect_for(
        &self,
        project: &str,
        db: &str,
        owner: bool,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
        use boatramp_storage::sql_sqlx::{connect, ExternalSqlOptions};
        // Defense-in-depth: the API path param + CLI `--db` are validated before they
        // reach here, but this is the single lookup choke point for every operator
        // SQL / migration caller, so re-run the one canonical validator (`database`)
        // to fail closed on any db name that is not a safe URL path segment.
        boatramp_core::project::validate_resource_name("database", db)
            .map_err(|err| SqlError::other(err.to_string()))?;
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
            let target = if owner {
                owner_target(cfg, project, db)?
            } else {
                operator_target(cfg, project, db)?
            };

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

/// Derive the connection target for a **schema migration** against a compute-backed managed
/// binding — identical to [`operator_target`] EXCEPT, on a multi-tenant **Shared** server, it
/// connects as the per-project non-superuser **owner role** with the sealed owner credential,
/// NOT the cluster superuser. This is the whole point of the owner-gated migration surface: DDL
/// runs bounded to project-owner authority (Postgres denies the owner role cross-database /
/// role-escalation / `COPY … TO PROGRAM` by privilege), never as a cluster superuser.
///
/// - **Shared, real tenant** — user = `names.owner_role`, credential keyed by
///   `(project, owner_credential_workload_key(<compute>, <ident>))` (the sealed owner password
///   minted at provision). This is the security-critical deviation from `operator_target`.
/// - **Shared, default tenant** / **Single** / **bring-your-own** — identical to `operator_target`
///   (the configured user is already the DB owner and is `<= project-owner`: a single-tenant
///   install's own user, a per-workload Single user, or the operator's own external credential).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub(crate) fn owner_target(
    cfg: &crate::config::ExternalDatabaseConfig,
    project: &str,
    db: &str,
) -> Result<OperatorTarget, SqlError> {
    use crate::config::{TenantIsolation, TenantScope};
    use crate::tenant_sql::{owner_credential_workload_key, tenant_key, tenant_names};

    // Start from the operator derivation, then override the identity/credential for the one case
    // that must NOT be the superuser: a real tenant on a Shared server.
    let mut target = operator_target(cfg, project, db)?;

    if matches!(cfg.tenant, TenantIsolation::Shared)
        && !matches!(cfg.tenant_scope, TenantScope::Site)
    {
        let compute = cfg.compute.as_deref().unwrap_or_default();
        let database = cfg.database.as_deref().unwrap_or_default();
        let (tenant_ident_raw, is_default) = tenant_key(cfg.tenant_scope, project, "");
        if !is_default {
            let names = tenant_names(cfg.tenant, compute, database, &tenant_ident_raw, is_default);
            let ident = boatramp_storage::tenant_provision::sanitize_ident(&tenant_ident_raw);
            target.user = names.owner_role;
            target.cred_project = project.to_string();
            target.cred_workload = owner_credential_workload_key(compute, &ident);
        }
    }
    Ok(target)
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
        if cfg.compute.as_deref().is_none_or(|c| c.is_empty()) {
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

/// The schema-migration runner (Postgres + MySQL). Owns the ordered `schema_migrations` ledger and
/// applies the pending suffix of a step set, once each, connecting as a **DDL identity distinct from
/// the runtime user** for the ledger + `sql` steps:
///
/// - **Postgres** — the per-project non-superuser **owner** role (via
///   [`NodeOperatorSql::owner_backend_for`]); transactional DDL, so a `sql` step + its ledger row
///   commit atomically. `extension` steps run the allowlist-gated, host-templated `CREATE EXTENSION`
///   via the superuser ([`NodeOperatorSql::backend_for`]).
/// - **MySQL** — an operator-supplied DDL login (`migration_url_env`, via
///   [`NodeOperatorSql::mysql_ddl_backend_for`]), refused fail-closed if absent or identical to the
///   runtime identity (no owner/runtime role split to fall back on). MySQL **implicitly commits per
///   DDL statement**, so a `sql` step is NOT atomic: the DDL runs first, then the ledger row is
///   recorded, and a mid-step failure is reported as a **partially-applied** step (never claimed
///   atomic). The `extension` step kind is **refused** on MySQL (no `CREATE EXTENSION`).
///
/// boatramp owns ordering/idempotency; the caller supplies the ordered steps. `Project·Admin`-gated
/// at the API.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub struct NodeMigrationRunner {
    op: Arc<NodeOperatorSql>,
    /// The operator's trusted-extension allowlist — the ONLY extensions an `Extension` step may
    /// enable (a name not here is refused fail-closed).
    trusted_extensions: std::collections::BTreeSet<String>,
}

/// The host-owned schema (Postgres) / database (MySQL) holding the migration ledger.
///
/// - **Postgres** — a SCHEMA `boatramp_migrations` inside the tenant database, owner-role-owned and
///   NOT in `public`, so the runtime tenant role (which only gets DML on `public` via
///   `grant_app_role_ddl`) has no access: the ledger is append-only from the app's perspective by
///   schema isolation.
/// - **MySQL** — a separate DATABASE `boatramp_migrations` (MySQL has no schema-within-database
///   namespace), created + owned by the DDL identity. The append-only-by-isolation property holds
///   for the **runtime tenant user** only: it was granted `GRANT … ON <its-db>.*`, so it has NO
///   privilege on the `boatramp_migrations` database at all. It does **NOT** hold for the DDL/root
///   login the migrate path (and the guest `migrate-ddl` seam) uses — that identity reaches
///   `boatramp_migrations` fully (it created + owns it), so on MySQL the S3 ledger-schema guard
///   ([`mentions_ledger_schema`], which refuses any step touching `boatramp_migrations`) is the
///   **sole** barrier protecting the ledger from the DDL identity, not belt-and-braces with the
///   grant isolation (which only fences the runtime user).
/// - **SQLite/libsql** — SQLite has no schema namespace at all; the ledger is a single table named
///   `boatramp_migrations_schema_migrations` in the tenant's own database file (see
///   [`libsql_ledger`]). Isolation is by the file boundary + the same S3/S4 word-scan guards.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
const LEDGER_SCHEMA: &str = "boatramp_migrations";
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
const LEDGER_TABLE: &str = "schema_migrations";

/// Quote a SQL string literal (single-quoted, doubling embedded `'`). The ledger id/hash reaching
/// this are already validated ([`valid_migration_id`]) / hex, but we quote defensively so no value
/// can break out of its literal in the host-built ledger INSERT.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
fn sql_quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A migration id is restricted to `[A-Za-z0-9._-]+` (non-empty) — defensive belt beside the
/// literal-quoting, and it keeps ledger ids clean/greppable. Anything else is refused fail-closed.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
fn valid_migration_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Whether `script` contains a `CREATE EXTENSION` statement. Raw `sql` steps are refused if so —
/// extensions must go through an allowlist-gated `Extension` step. (A UX/allowlist-consistency guard;
/// the security boundary is that the owner role is non-superuser and so cannot create an UNtrusted
/// extension regardless.) Delegates to the comment-/casing-immune tokenizer ([Security review
/// HIGH-1]: a byte scan is evadable via `CREATE/**/EXTENSION`; the tokenizer strips comments and
/// fails closed on an unlexable script).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn mentions_create_extension(script: &str, kind: ExternalSqlKind) -> bool {
    boatramp_core::sql::script_has_create_extension_in(script, guard_dialect(kind))
}

/// The [`boatramp_core::sql::GuardDialect`] for a managed engine — so a raw `sql` step is tokenized
/// under the ENGINE's own comment/quote rules (MySQL `#` line comments + backtick identifiers),
/// closing an engine-specific evasion the generic lexer wouldn't catch.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn guard_dialect(kind: ExternalSqlKind) -> boatramp_core::sql::GuardDialect {
    match kind {
        ExternalSqlKind::Mysql => boatramp_core::sql::GuardDialect::Mysql,
        ExternalSqlKind::Postgres => boatramp_core::sql::GuardDialect::Postgres,
    }
}

/// Whether `script` issues its own transaction control (`BEGIN`/`START`/`COMMIT`/`END`/`ROLLBACK`/
/// `ABORT`/`SAVEPOINT`/`RELEASE`). A transactional (`!no_transaction`) step is wrapped by the runner
/// in `BEGIN;…;<ledger-insert>;COMMIT;`, so an author's own `COMMIT`/`ROLLBACK` would desync that
/// wrapper (a `ROLLBACK` reverts the DDL but the ledger INSERT then auto-commits, recording a step
/// that didn't apply). Reject it fail-closed so the ledger can never diverge from applied state; an
/// author that genuinely needs its own transaction control uses a `no_transaction` step.
///
/// Delegates to the SQL **tokenizer** ([Security review HIGH-1/HIGH-2]): the earlier byte scan was
/// comment-evadable (`COMMIT-- x`, `/*c*/BEGIN`), missed `ABORT`/`SAVEPOINT`/`RELEASE`, and
/// false-positived on `CASE … END` and PL/pgSQL `$$ BEGIN … END $$` bodies. The tokenizer is
/// comment-/casing-/string-immune, CASE-aware, and fails closed on an unlexable script.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn mentions_txn_control(script: &str, kind: ExternalSqlKind) -> bool {
    boatramp_core::sql::script_has_txn_control_in(script, guard_dialect(kind))
}

/// Whether `script` references the host-owned migration-ledger schema (`boatramp_migrations`). The
/// owner role OWNS that schema, so an unguarded `migrate::exec` from a function step could rewrite
/// prefix-consistency/immutability history. Refused fail-closed (Security S3). Uses the tokenizer so
/// a reference can't be hidden in a comment ([Security review HIGH-1]) and a string literal
/// mentioning the name is not a false positive; matches the schema as a whole word token (quoted or
/// not). Belt-and-braces beside the schema isolation (the runtime tenant role has no grant on it at
/// all); this stops the OWNER-role path a function step runs on.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn mentions_ledger_schema(script: &str, kind: ExternalSqlKind) -> bool {
    boatramp_core::sql::script_references_word_in(script, LEDGER_SCHEMA, guard_dialect(kind))
}

/// The host-mediated owner-role DDL seam backing the guest `migrate-ddl` capability of a `function`
/// step (Security S5). Holds the orchestrator-owned OWNER-role backend for one `(project, db)`; the
/// guest never holds the credential. Each call enforces the ledger-schema (S3) + transaction-control
/// (S4) guards host-side before touching the wire, then auto-commits via `run_script`/`run_query`.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub(crate) struct OwnerDdl {
    owner: Arc<dyn boatramp_core::sql::SqlBackend>,
    /// The target engine — selects the dialect-aware guard tokenizer (MySQL `#` comments +
    /// backticks) so an engine-specific evasion can't slip a guarded construct past.
    kind: ExternalSqlKind,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl OwnerDdl {
    /// Guard a guest-supplied script/query: refuse a ledger-schema reference (S3) or its own
    /// transaction control (S4) before it reaches the owner connection. Tokenized under the target
    /// engine's dialect. On MySQL, transaction control is doubly meaningful: DDL implicitly commits,
    /// so a guest `BEGIN` would not even bound the following statements — refusing it keeps the
    /// per-statement auto-commit contract explicit and identical across engines.
    fn guard(&self, script: &str) -> Result<(), MigrateDdlError> {
        if mentions_ledger_schema(script, self.kind) {
            return Err(MigrateDdlError::LedgerProtected);
        }
        if mentions_txn_control(script, self.kind) {
            return Err(MigrateDdlError::TxnControl);
        }
        Ok(())
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[async_trait]
impl MigrateDdl for OwnerDdl {
    async fn exec(&self, script: &str) -> Result<(), MigrateDdlError> {
        self.guard(script)?;
        self.owner
            .run_script(script)
            .await
            .map_err(|e| MigrateDdlError::Sql(sanitize_migration_error(&e.to_string())))
    }

    async fn exec_batch(&self, scripts: Vec<String>) -> Result<(), MigrateDdlError> {
        for script in &scripts {
            self.exec(script).await?;
        }
        Ok(())
    }

    async fn query(&self, sql: &str) -> Result<boatramp_core::sql::SqlRows, MigrateDdlError> {
        self.guard(sql)?;
        let rows = self
            .owner
            .run_query(sql)
            .await
            .map_err(|e| MigrateDdlError::Sql(sanitize_migration_error(&e.to_string())))?;
        // Bound the result handed to the guest ([Security review MEDIUM-2]): a verification query
        // is expected to return a small, checkable set; refuse an unbounded read rather than encode
        // a huge JSON blob into host memory + across the boundary. The author adds a `LIMIT`.
        if rows.rows.len() > MIGRATE_QUERY_MAX_ROWS {
            return Err(MigrateDdlError::Sql(format!(
                "query returned {} rows (cap {MIGRATE_QUERY_MAX_ROWS}); add a LIMIT — a migration \
                 verification query should read a bounded set",
                rows.rows.len()
            )));
        }
        Ok(rows)
    }
}

/// The row cap on a `migrate-ddl` `query` result (Security MEDIUM-2). A verification query reads a
/// bounded, checkable set; beyond this it is refused so a migration function can't drive an unbounded
/// owner-visibility read into a huge host-side JSON string.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
const MIGRATE_QUERY_MAX_ROWS: usize = 100_000;

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl NodeMigrationRunner {
    /// Build over a [`NodeOperatorSql`] (for the owner + superuser backends) and the operator's
    /// trusted-extension allowlist.
    pub fn new(
        op: Arc<NodeOperatorSql>,
        trusted_extensions: std::collections::BTreeSet<String>,
    ) -> Self {
        Self {
            op,
            trusted_extensions,
        }
    }

    /// The fully-qualified, quoted ledger table name for `kind` — `"boatramp_migrations"."schema_migrations"`
    /// on Postgres (schema.table), `` `boatramp_migrations`.`schema_migrations` `` on MySQL (database.table).
    fn ledger(kind: ExternalSqlKind) -> String {
        use boatramp_storage::tenant_provision::quote_ident;
        format!(
            "{}.{}",
            quote_ident(kind, LEDGER_SCHEMA),
            quote_ident(kind, LEDGER_TABLE)
        )
    }

    /// The host-built ledger INSERT for one recorded step (all values host-controlled + quoted). The
    /// orchestrator supplies the **effective** hash (== the intrinsic content hash for sql/extension;
    /// blob-bound for a function step) and the `origin` (`apply` vs `baseline`, recorded in
    /// `applied_by` for the U6 marker). Column list + literal quoting are identical across engines.
    fn ledger_insert(
        kind: ExternalSqlKind,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
        origin: LedgerOrigin,
    ) -> String {
        format!(
            "INSERT INTO {ledger} (id, ordinal, content_hash, kind, applied_by) \
             VALUES ({id}, {ord}, {hash}, {step_kind}, {origin});",
            ledger = Self::ledger(kind),
            id = sql_quote_literal(&step.id),
            ord = ordinal,
            hash = sql_quote_literal(effective_hash),
            step_kind = sql_quote_literal(step.kind()),
            origin = sql_quote_literal(origin.as_str()),
        )
    }

    /// Ensure the ledger schema/database + table exist (idempotent), as the DDL identity.
    ///
    /// - **Postgres** — a SCHEMA inside the tenant database + a table with `timestamptz DEFAULT now()`.
    /// - **MySQL** — a separate DATABASE (no schema-within-db) + an InnoDB table with bounded
    ///   `VARCHAR` keys (MySQL can't use an unbounded `TEXT`/`BLOB` as a PRIMARY KEY without a prefix
    ///   length) and a `TIMESTAMP DEFAULT CURRENT_TIMESTAMP`.
    async fn ensure_ledger(
        &self,
        kind: ExternalSqlKind,
        owner: &Arc<dyn boatramp_core::sql::SqlBackend>,
    ) -> Result<(), SqlError> {
        use boatramp_storage::tenant_provision::quote_ident;
        match kind {
            ExternalSqlKind::Postgres => {
                let schema = quote_ident(kind, LEDGER_SCHEMA);
                owner
                    .run_script(&format!("CREATE SCHEMA IF NOT EXISTS {schema};"))
                    .await?;
                owner
                    .run_script(&format!(
                        "CREATE TABLE IF NOT EXISTS {ledger} (\
                         id text PRIMARY KEY, \
                         ordinal integer NOT NULL, \
                         content_hash text NOT NULL, \
                         kind text NOT NULL, \
                         applied_at timestamptz NOT NULL DEFAULT now(), \
                         applied_by text);",
                        ledger = Self::ledger(kind)
                    ))
                    .await?;
            }
            ExternalSqlKind::Mysql => {
                let db = quote_ident(kind, LEDGER_SCHEMA);
                owner
                    .run_script(&format!("CREATE DATABASE IF NOT EXISTS {db};"))
                    .await?;
                owner
                    .run_script(&format!(
                        "CREATE TABLE IF NOT EXISTS {ledger} (\
                         id VARCHAR(255) PRIMARY KEY, \
                         ordinal INT NOT NULL, \
                         content_hash VARCHAR(255) NOT NULL, \
                         kind VARCHAR(32) NOT NULL, \
                         applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                         applied_by VARCHAR(32)) ENGINE=InnoDB;",
                        ledger = Self::ledger(kind)
                    ))
                    .await?;
            }
        }
        Ok(())
    }

    /// Read the applied ledger rows, ordered by `ordinal`. `applied_by` maps to the row `origin`
    /// (`baseline` when it was baselined, else `apply` — covering NULL/legacy rows via the default).
    /// The `applied_at` cast differs by dialect (`::text` on Postgres, `CAST(… AS CHAR)` on MySQL).
    async fn read_applied(
        &self,
        kind: ExternalSqlKind,
        owner: &Arc<dyn boatramp_core::sql::SqlBackend>,
    ) -> Result<Vec<AppliedMigration>, SqlError> {
        use boatramp_core::sql::SqlValue;
        let applied_at = match kind {
            ExternalSqlKind::Postgres => "applied_at::text",
            ExternalSqlKind::Mysql => "CAST(applied_at AS CHAR)",
        };
        let rows = owner
            .run_query(&format!(
                "SELECT id, ordinal, content_hash, kind, {applied_at}, applied_by \
                 FROM {ledger} ORDER BY ordinal;",
                ledger = Self::ledger(kind)
            ))
            .await?;
        let text = |v: &SqlValue| match v {
            SqlValue::Text(s) => s.clone(),
            other => format!("{other:?}"),
        };
        let int = |v: &SqlValue| match v {
            SqlValue::Integer(n) => *n,
            _ => 0,
        };
        Ok(rows
            .rows
            .iter()
            .map(|r| {
                let origin = match r.get(5) {
                    Some(SqlValue::Text(s)) if s == LedgerOrigin::Baseline.as_str() => {
                        LedgerOrigin::Baseline.as_str().to_string()
                    }
                    _ => LedgerOrigin::Apply.as_str().to_string(),
                };
                AppliedMigration {
                    id: r.first().map(&text).unwrap_or_default(),
                    ordinal: r.get(1).map(&int).unwrap_or_default(),
                    content_hash: r.get(2).map(&text).unwrap_or_default(),
                    kind: r.get(3).map(&text).unwrap_or_default(),
                    applied_at: r.get(4).map(&text).unwrap_or_default(),
                    origin,
                }
            })
            .collect())
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl NodeMigrationRunner {
    /// Engine gate: **Postgres and MySQL** are supported. The embedded libsql/SQLite backend has no
    /// migration substrate yet (a later parity phase) — but it is not an [`ExternalSqlKind`], so it
    /// never reaches here; a database of an unknown/unconfigured engine returns `NotConfigured`. Fail
    /// closed + clear. Returns the resolved engine so callers thread it into the dialect-aware ledger.
    fn engine_gate(&self, db: &str) -> Result<ExternalSqlKind, MigrationError> {
        match self.op.engine_kind(db) {
            Some(kind @ (ExternalSqlKind::Postgres | ExternalSqlKind::Mysql)) => Ok(kind),
            None => Err(MigrationError::NotConfigured),
        }
    }

    /// Connect as the migration **DDL identity** — never the runtime tenant user.
    ///
    /// - **Postgres** — the per-project non-superuser owner role (via `owner_backend_for`); the
    ///   default-tenant / single-tenant case connects as the configured user, which is already the
    ///   DB owner (`<= project-owner`).
    /// - **MySQL** — the operator-supplied `migration_url_env` DDL login (via
    ///   `mysql_ddl_backend_for`), refused fail-closed if absent or identical to the runtime
    ///   identity. There is NO owner-role fallback: MySQL never mints a distinct DDL role, so
    ///   without an explicit distinct identity we cannot run DDL off the runtime user.
    ///
    /// A managed DB still starting surfaces as `Unavailable` → a retryable 503 at the API, not a
    /// permanent failure.
    async fn connect_ddl(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, MigrationError> {
        let kind = self.engine_gate(db)?;
        let result = match kind {
            ExternalSqlKind::Postgres => self.op.owner_backend_for(project, db).await,
            ExternalSqlKind::Mysql => self.op.mysql_ddl_backend_for(db).await,
        };
        result.map_err(|e| match e {
            SqlError::Unavailable(m) => MigrationError::Unavailable(m),
            other => MigrationError::Sql(other),
        })
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[async_trait]
impl MigrationSubstrate for NodeMigrationRunner {
    async fn preflight(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Vec<AppliedMigration>, MigrationError> {
        let kind = self.engine_gate(db)?;
        let owner = self.connect_ddl(project, db).await?;
        self.ensure_ledger(kind, &owner).await?;
        Ok(self.read_applied(kind, &owner).await?)
    }

    async fn apply_substrate_step(
        &self,
        project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
    ) -> Result<SubstrateStepOutcome, MigrationError> {
        use boatramp_core::sql::MigrationAction;

        // Defensive: the orchestrator already validated ids, but this layer builds the ledger SQL, so
        // re-check (a bad id is a per-step failure, not an infra error).
        if !valid_migration_id(&step.id) {
            return Ok(SubstrateStepOutcome::Failed(
                "invalid migration id (allowed: A-Za-z0-9._-)".to_string(),
            ));
        }
        let kind = self.engine_gate(db)?;
        let owner = self.connect_ddl(project, db).await?;
        let ledger_insert =
            Self::ledger_insert(kind, step, ordinal, effective_hash, LedgerOrigin::Apply);
        let outcome: Result<(), String> = match &step.action {
            MigrationAction::Sql {
                script,
                no_transaction,
            } => {
                if mentions_create_extension(script, kind) {
                    let hint = match kind {
                        ExternalSqlKind::Postgres => "use an extension step",
                        ExternalSqlKind::Mysql => "MySQL has no CREATE EXTENSION",
                    };
                    Err(format!("a sql step may not CREATE EXTENSION — {hint}"))
                } else if mentions_ledger_schema(script, kind) {
                    Err(
                        "a sql step may not reference the host-owned migration-ledger schema"
                            .to_string(),
                    )
                } else if mentions_txn_control(script, kind)
                    && (kind == ExternalSqlKind::Mysql || !*no_transaction)
                {
                    // Postgres: a transactional step may not carry its own txn control (it would
                    // desync the atomic wrapper) — a `no_transaction` step may. MySQL: DDL implicitly
                    // commits, so there is NO atomic wrapper and a guest BEGIN/COMMIT is always
                    // meaningless/misleading — refuse it regardless of `no_transaction`.
                    let why = match kind {
                        ExternalSqlKind::Postgres => {
                            "a transactional sql step may not contain its own BEGIN/COMMIT/ROLLBACK \
                             (it would desync the atomic wrapper) — use a no_transaction step to \
                             manage the transaction yourself"
                        }
                        ExternalSqlKind::Mysql => {
                            "a MySQL sql step may not contain its own BEGIN/COMMIT/ROLLBACK — DDL \
                             implicitly commits on MySQL, so there is no transaction to control (a \
                             multi-DDL step is applied per-statement, not atomically)"
                        }
                    };
                    Err(why.to_string())
                } else {
                    match kind {
                        ExternalSqlKind::Postgres if !*no_transaction => {
                            // Atomic (Postgres transactional DDL): DDL + ledger insert commit together
                            // (or roll back together). A trailing `;` after the script guards a script
                            // that omits its own final semicolon (else it would merge with the ledger
                            // INSERT into one invalid statement); a doubled `;;` is an empty statement.
                            let batch = format!("BEGIN;\n{script};\n{ledger_insert}\nCOMMIT;");
                            owner.run_script(&batch).await.map_err(|e| e.to_string())
                        }
                        // Postgres `no_transaction`, OR **every** MySQL sql step (MySQL DDL is never
                        // transactional): run the script, then record the ledger row as a following
                        // statement. NOT atomic — see [`mysql_partial_apply_note`].
                        _ => match owner.run_script(script).await {
                            Ok(()) => owner
                                .run_script(&ledger_insert)
                                .await
                                // The DDL applied but its ledger row did not — mark the honest partial
                                // (a re-apply re-runs the WHOLE step; author-idempotent, S7).
                                .map_err(|e| {
                                    mysql_partial_apply_note(kind, &step.id, &e.to_string())
                                }),
                            Err(e) => Err(mysql_multi_ddl_note(kind, &step.id, &e.to_string())),
                        },
                    }
                }
            }
            MigrationAction::Extension { name } => match kind {
                // No `CREATE EXTENSION` on MySQL → the extension step kind is refused outright.
                ExternalSqlKind::Mysql => Err(format!(
                    "extension step {name:?} is not supported on MySQL (MySQL has no CREATE \
                     EXTENSION) — install any plugin operator-side and use a plain sql step"
                )),
                ExternalSqlKind::Postgres => {
                    if !self.trusted_extensions.contains(name) {
                        Err(format!(
                            "extension {name:?} is not on the operator trusted-extension allowlist"
                        ))
                    } else {
                        use boatramp_storage::tenant_provision::quote_ident;
                        // Host-templated + allowlist-bounded; run via the superuser so an allowlisted
                        // superuser-only extension also works. IF NOT EXISTS keeps it idempotent, so a
                        // crash before the ledger insert re-runs harmlessly.
                        let create = format!(
                            "CREATE EXTENSION IF NOT EXISTS {};",
                            quote_ident(kind, name)
                        );
                        match self.op.backend_for(project, db).await {
                            Ok(su) => match su.run_script(&create).await {
                                Ok(()) => owner
                                    .run_script(&ledger_insert)
                                    .await
                                    .map_err(|e| e.to_string()),
                                Err(e) => Err(e.to_string()),
                            },
                            Err(e) => Err(e.to_string()),
                        }
                    }
                }
            },
            // A `function` step is invoked by the server-side orchestrator (it needs the invoke
            // kernel) and recorded via `record` — it must never reach the substrate executor.
            MigrationAction::Function { .. } => {
                return Err(MigrationError::Other(
                    "internal: a function step must be invoked by the orchestrator, not the \
                     substrate"
                        .to_string(),
                ))
            }
        };
        Ok(match outcome {
            Ok(()) => SubstrateStepOutcome::Applied,
            Err(error) => SubstrateStepOutcome::Failed(sanitize_migration_error(&error)),
        })
    }

    async fn record(
        &self,
        project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
        origin: LedgerOrigin,
    ) -> Result<(), MigrationError> {
        if !valid_migration_id(&step.id) {
            return Err(MigrationError::Other(format!(
                "invalid migration id {:?} (allowed: A-Za-z0-9._-)",
                step.id
            )));
        }
        let kind = self.engine_gate(db)?;
        let owner = self.connect_ddl(project, db).await?;
        self.ensure_ledger(kind, &owner).await?;
        owner
            .run_script(&Self::ledger_insert(
                kind,
                step,
                ordinal,
                effective_hash,
                origin,
            ))
            .await?;
        Ok(())
    }

    async fn owner_ddl(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Arc<dyn MigrateDdl>, MigrationError> {
        let kind = self.engine_gate(db)?;
        let owner = self.connect_ddl(project, db).await?;
        Ok(Arc::new(OwnerDdl { owner, kind }))
    }
}

/// Annotate a MySQL `sql`-step failure whose (multi-statement) DDL errored **mid-way**: on MySQL
/// each DDL implicitly commits, so any statements before the failing one have ALREADY applied and
/// are NOT rolled back. The step is recorded as failed (no ledger row), and a re-apply re-runs the
/// WHOLE step — so the migration author must make each DDL step idempotent (or one DDL per step). On
/// Postgres this can't happen for a transactional step (the whole thing rolls back), so the note is
/// MySQL-only.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn mysql_multi_ddl_note(kind: ExternalSqlKind, id: &str, err: &str) -> String {
    match kind {
        ExternalSqlKind::Mysql => format!(
            "step {id:?} failed mid-way and may be PARTIALLY APPLIED (MySQL commits each DDL \
             statement implicitly; earlier statements were not rolled back). Re-apply re-runs the \
             whole step — make it idempotent. Underlying error: {err}"
        ),
        ExternalSqlKind::Postgres => err.to_string(),
    }
}

/// Annotate the honest partial-apply case where a MySQL step's DDL SUCCEEDED but recording its
/// ledger row then failed: the schema change is live but unrecorded. A re-apply re-runs the whole
/// step (author-idempotent, S7), so this is recoverable — but it must be reported as partial, never
/// as applied.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn mysql_partial_apply_note(kind: ExternalSqlKind, id: &str, err: &str) -> String {
    match kind {
        ExternalSqlKind::Mysql => format!(
            "step {id:?} DDL applied but its ledger row could not be recorded — the step is \
             PARTIALLY APPLIED (schema changed, unrecorded). Re-apply re-runs the whole step \
             (make it idempotent). Underlying error: {err}"
        ),
        ExternalSqlKind::Postgres => err.to_string(),
    }
}

/// Trim a driver error string to a first line and a bounded length so a migration failure returned
/// to the client can't carry a wall of internal DSN/schema detail (defense against info leakage).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
fn sanitize_migration_error(e: &str) -> String {
    let first = e.lines().next().unwrap_or(e);
    // Truncate on a CHAR boundary, not a byte index ([Security review MEDIUM-3]): a driver error can
    // carry multi-byte UTF-8 (non-ASCII table/collation names, a localized Postgres message) that a
    // migration author influences, so `&first[..300]` could panic mid-codepoint.
    if first.chars().count() > 300 {
        let truncated: String = first.chars().take(300).collect();
        format!("{truncated}…")
    } else {
        first.to_string()
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// Embedded libsql / SQLite migration substrate (PLAN-migrate-backend-parity, libsql stage).
//
// The third staged backend, mirroring the Postgres + MySQL substrate above but SQLite-shaped. The
// orchestrator (`boatramp-server::migrate`) is unchanged — same step model, same ledger contract
// (append-only / prefix-consistent / content-hash-immutable / baseline), same `migrate-ddl` guest
// ABI — only the substrate differs.
//
// Backend-honest semantics (the plan's rule: never a guarantee the engine can't keep):
//   * **No owner/runtime split, N/A owner-role safety.** SQLite is a single-connection file — no
//     roles, no RLS. There is NOTHING to enforce a non-runtime DDL identity against: the FILE is the
//     trust boundary (whoever can open it can do anything). We state this plainly rather than pretend
//     an owner role exists — there is no `migration_url_env` analog and no superuser to avoid. The
//     guest still NEVER holds a DB credential/handle: every statement is host-mediated, exactly as on
//     Postgres/MySQL (the host owns the `LibsqlSql`; the guest calls `migrate-ddl` functions).
//   * **Transactional per-step DDL (libsql's strength).** SQLite has transactional DDL, so a `sql`
//     step runs its DDL + its ledger row inside ONE transaction and rolls back cleanly on any
//     failure — the INVERSE of MySQL's non-atomic partial-apply. A step whose 2nd statement fails
//     leaves the 1st statement's effect ROLLED BACK and no ledger row (asserted in the live gate).
//   * **`extension` step refused.** SQLite loadable extensions are native host-controlled `.so`/`.dll`
//     files, never guest-loadable; the `extension` step kind is refused outright with a clear error.
//   * **`function` steps work.** The host runs the guest's `migrate::exec`/`exec-batch`/`query` on the
//     libsql connection via the `migrate-ddl` capability (unchanged ABI), each call auto-committing.
//   * **Guards ported under the SQLite dialect.** The comment-immune sqlparser guards tokenize a raw
//     `sql` step / a `migrate-ddl` script under `GuardDialect::Sqlite` (sqlparser `SQLiteDialect`), so
//     transaction control (`COMMIT`/`BEGIN`) or the ledger-table name can't be smuggled past under a
//     SQLite comment/quoted-identifier form the generic lexer wouldn't strip.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Resolve the on-disk libsql file for a named single-node `libsql` managed database from the handler
/// `sql` `databases` config. Independent of the Postgres/MySQL `NodeOperatorSql` (libsql has no
/// compute/credential/resolver machinery — it's a local file), so the libsql substrate compiles under
/// `feature = "migrate"` with no dependency on the sqlx engines.
#[cfg(feature = "migrate")]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct LibsqlMigrationRunner {
    databases: std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
}

/// Whether a config `kind` string names the embedded libsql/SQLite engine (case-insensitive). The
/// engine gate keys on this — libsql is NOT an [`ExternalSqlKind`] (the sqlx enum is Postgres/MySQL
/// only), so a libsql binding is identified here by its `kind` alone.
#[cfg(feature = "migrate")]
pub(crate) fn kind_is_libsql(kind: &str) -> bool {
    matches!(
        kind.trim().to_ascii_lowercase().as_str(),
        "libsql" | "sqlite" | "sqlite3"
    )
}

/// The bare (unquoted) libsql ledger **table** name — the reserved-prefixed single table SQLite uses
/// for the ledger. Also the **word token** the ledger-reference guard ([`LibsqlDdl::guard`],
/// [`LibsqlMigrationRunner::apply_substrate_step`]) matches: on SQLite the ledger is ONE table named
/// `boatramp_migrations_schema_migrations`, so a reference to it lexes as this single identifier token
/// (unlike Postgres, whose `boatramp_migrations.schema_migrations` has a distinct `boatramp_migrations`
/// schema-name token). Matching the full table name is exactly the protection needed — a migration
/// step may not touch the host-owned ledger.
#[cfg(feature = "migrate")]
const LIBSQL_LEDGER_WORD: &str = concat!("boatramp_migrations", "_", "schema_migrations");

/// The fully-qualified, quoted libsql ledger table name — `"boatramp_migrations_schema_migrations"`.
/// SQLite has **no schema-within-database namespace** (no `CREATE SCHEMA`, and `ATTACH` is a separate
/// file), so — unlike Postgres (a schema) / MySQL (a separate database) — the ledger is a single
/// table in the site's own database, its name PREFIXED with the reserved `boatramp_migrations_`
/// namespace so it can't collide with an app table. Double-quoted (SQLite's standard identifier quote)
/// so the reserved name is inert even if it somehow contained a keyword.
#[cfg(feature = "migrate")]
fn libsql_ledger() -> String {
    format!("\"{LEDGER_SCHEMA}_{LEDGER_TABLE}\"")
}

#[cfg(feature = "migrate")]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
impl LibsqlMigrationRunner {
    /// Build over the handler `sql` `databases` config (the same map the Postgres/MySQL runner reads).
    /// Only `libsql`-kind entries are ever addressed; a non-libsql name returns `NotConfigured`.
    pub fn new(
        databases: std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
    ) -> Self {
        Self { databases }
    }

    /// Whether database `db` is a configured single-node `libsql` binding (for the engine gate).
    pub(crate) fn is_libsql(&self, db: &str) -> bool {
        self.databases
            .get(db)
            .is_some_and(|cfg| kind_is_libsql(&cfg.kind))
    }

    /// Engine gate: the database must be a configured **`libsql`** binding, else `NotConfigured`.
    /// (A Postgres/MySQL binding is handled by the sqlx runner, not this one.)
    fn engine_gate(&self, db: &str) -> Result<(), MigrationError> {
        if self.is_libsql(db) {
            Ok(())
        } else {
            Err(MigrationError::NotConfigured)
        }
    }

    /// Open the `LibsqlSql` for a single-node `libsql` binding.
    ///
    /// The FILE is the whole trust boundary (no owner/runtime role split exists on SQLite — the
    /// owner-role safety Postgres provides is N/A here), and the host owns this handle: the guest
    /// never receives a connection/credential. Only the single-node (`path`) case is supported for
    /// migrations today; a remote-sqld `libsql` binding (`url_env`) returns a clear error rather than
    /// silently running DDL against a shared cluster primary.
    async fn open(&self, db: &str) -> Result<boatramp_storage::LibsqlSql, MigrationError> {
        let cfg = self
            .databases
            .get(db)
            .ok_or(MigrationError::NotConfigured)?;
        let Some(path) = cfg.path.as_deref().filter(|p| !p.as_os_str().is_empty()) else {
            return Err(MigrationError::Other(format!(
                "libsql database {db:?}: schema migrations need a single-node `path` (the embedded \
                 file); a remote-sqld `libsql` binding is not a migration target"
            )));
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| MigrationError::Other(format!("libsql database {db:?}: {e}")))?;
            }
        }
        boatramp_storage::LibsqlSql::open_local(path)
            .await
            .map_err(MigrationError::Sql)
    }

    /// The host-built ledger INSERT for one recorded step — identical column shape + literal quoting
    /// to the Postgres/MySQL runner ([`NodeMigrationRunner::ledger_insert`]), against the libsql
    /// ledger table. All values are host-controlled + quoted.
    fn ledger_insert(
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
        origin: LedgerOrigin,
    ) -> String {
        format!(
            "INSERT INTO {ledger} (id, ordinal, content_hash, kind, applied_by) \
             VALUES ({id}, {ord}, {hash}, {step_kind}, {origin});",
            ledger = libsql_ledger(),
            id = sql_quote_literal(&step.id),
            ord = ordinal,
            hash = sql_quote_literal(effective_hash),
            step_kind = sql_quote_literal(step.kind()),
            origin = sql_quote_literal(origin.as_str()),
        )
    }

    /// Ensure the ledger table exists (idempotent). A single SQLite table (no schema/db namespace) with
    /// a `TEXT` primary key and a `CURRENT_TIMESTAMP` default — the same columns/semantics the other
    /// engines use.
    async fn ensure_ledger(&self, sql: &boatramp_storage::LibsqlSql) -> Result<(), MigrationError> {
        use boatramp_core::sql::SqlBackend;
        sql.run_script(&format!(
            "CREATE TABLE IF NOT EXISTS {ledger} (\
             id TEXT PRIMARY KEY, \
             ordinal INTEGER NOT NULL, \
             content_hash TEXT NOT NULL, \
             kind TEXT NOT NULL, \
             applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             applied_by TEXT);",
            ledger = libsql_ledger()
        ))
        .await
        .map_err(MigrationError::Sql)
    }

    /// Read the applied ledger rows, ordered by `ordinal` (same shape as the sqlx runner's
    /// `read_applied`). `applied_by` maps to the row origin (`baseline` when baselined, else `apply`).
    async fn read_applied(
        &self,
        sql: &boatramp_storage::LibsqlSql,
    ) -> Result<Vec<AppliedMigration>, MigrationError> {
        use boatramp_core::sql::{SqlBackend, SqlValue};
        let rows = sql
            .run_query(&format!(
                "SELECT id, ordinal, content_hash, kind, applied_at, applied_by \
                 FROM {ledger} ORDER BY ordinal;",
                ledger = libsql_ledger()
            ))
            .await
            .map_err(MigrationError::Sql)?;
        let text = |v: &SqlValue| match v {
            SqlValue::Text(s) => s.clone(),
            other => format!("{other:?}"),
        };
        let int = |v: &SqlValue| match v {
            SqlValue::Integer(n) => *n,
            _ => 0,
        };
        Ok(rows
            .rows
            .iter()
            .map(|r| {
                let origin = match r.get(5) {
                    Some(SqlValue::Text(s)) if s == LedgerOrigin::Baseline.as_str() => {
                        LedgerOrigin::Baseline.as_str().to_string()
                    }
                    _ => LedgerOrigin::Apply.as_str().to_string(),
                };
                AppliedMigration {
                    id: r.first().map(&text).unwrap_or_default(),
                    ordinal: r.get(1).map(&int).unwrap_or_default(),
                    content_hash: r.get(2).map(&text).unwrap_or_default(),
                    kind: r.get(3).map(&text).unwrap_or_default(),
                    applied_at: r.get(4).map(&text).unwrap_or_default(),
                    origin,
                }
            })
            .collect())
    }
}

#[cfg(feature = "migrate")]
#[async_trait]
impl MigrationSubstrate for LibsqlMigrationRunner {
    async fn preflight(
        &self,
        _project: &str,
        db: &str,
    ) -> Result<Vec<AppliedMigration>, MigrationError> {
        self.engine_gate(db)?;
        let sql = self.open(db).await?;
        self.ensure_ledger(&sql).await?;
        self.read_applied(&sql).await
    }

    async fn apply_substrate_step(
        &self,
        _project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
    ) -> Result<SubstrateStepOutcome, MigrationError> {
        use boatramp_core::sql::{MigrationAction, SqlBackend};

        if !valid_migration_id(&step.id) {
            return Ok(SubstrateStepOutcome::Failed(
                "invalid migration id (allowed: A-Za-z0-9._-)".to_string(),
            ));
        }
        self.engine_gate(db)?;
        let sql = self.open(db).await?;
        let ledger_insert = Self::ledger_insert(step, ordinal, effective_hash, LedgerOrigin::Apply);
        let dialect = boatramp_core::sql::GuardDialect::Sqlite;

        let outcome: Result<(), String> = match &step.action {
            MigrationAction::Sql {
                script,
                no_transaction,
            } => {
                if boatramp_core::sql::script_has_create_extension_in(script, dialect) {
                    Err(
                        "a sql step may not CREATE EXTENSION — SQLite loadable extensions are \
                         host-controlled, never enabled by a migration step"
                            .to_string(),
                    )
                } else if boatramp_core::sql::script_references_word_in(
                    script,
                    LIBSQL_LEDGER_WORD,
                    dialect,
                ) {
                    Err(
                        "a sql step may not reference the host-owned migration-ledger table"
                            .to_string(),
                    )
                } else if boatramp_core::sql::script_has_txn_control_in(script, dialect)
                    && !*no_transaction
                {
                    // A transactional step may not carry its own BEGIN/COMMIT/ROLLBACK — it would
                    // desync the atomic wrapper (SQLite has transactional DDL, so the wrapper is real).
                    // A `no_transaction` step manages its own transaction (parity with Postgres).
                    Err("a transactional sql step may not contain its own BEGIN/COMMIT/ROLLBACK (it \
                         would desync the atomic wrapper) — use a no_transaction step to manage the \
                         transaction yourself"
                        .to_string())
                } else if *no_transaction {
                    // Author-managed transaction (for the rare DDL that can't run inside one): run the
                    // script, then record the ledger row as a following statement (NOT atomic — the
                    // author owns idempotency, same contract as Postgres `no_transaction`).
                    match sql.run_script(script).await {
                        Ok(()) => sql
                            .run_script(&ledger_insert)
                            .await
                            .map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    }
                } else {
                    // The atomic path (SQLite transactional DDL): BEGIN → DDL → ledger row → COMMIT,
                    // rolling the WHOLE thing back on ANY failure. This is libsql's strength — the
                    // inverse of MySQL's per-DDL implicit commit.
                    sql.run_migration_txn(script, &ledger_insert)
                        .await
                        .map_err(|e| e.to_string())
                }
            }
            MigrationAction::Extension { name } => Err(format!(
                "extension step {name:?} is not supported on libsql/SQLite — SQLite loadable \
                 extensions are native host-controlled files, never enabled by a migration step; \
                 install any extension operator-side and use a plain sql step"
            )),
            MigrationAction::Function { .. } => {
                return Err(MigrationError::Other(
                    "internal: a function step must be invoked by the orchestrator, not the \
                     substrate"
                        .to_string(),
                ))
            }
        };
        Ok(match outcome {
            Ok(()) => SubstrateStepOutcome::Applied,
            Err(error) => SubstrateStepOutcome::Failed(sanitize_migration_error(&error)),
        })
    }

    async fn record(
        &self,
        _project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
        origin: LedgerOrigin,
    ) -> Result<(), MigrationError> {
        use boatramp_core::sql::SqlBackend;
        if !valid_migration_id(&step.id) {
            return Err(MigrationError::Other(format!(
                "invalid migration id {:?} (allowed: A-Za-z0-9._-)",
                step.id
            )));
        }
        self.engine_gate(db)?;
        let sql = self.open(db).await?;
        self.ensure_ledger(&sql).await?;
        sql.run_script(&Self::ledger_insert(step, ordinal, effective_hash, origin))
            .await
            .map_err(MigrationError::Sql)
    }

    async fn owner_ddl(
        &self,
        _project: &str,
        db: &str,
    ) -> Result<Arc<dyn MigrateDdl>, MigrationError> {
        self.engine_gate(db)?;
        let sql = self.open(db).await?;
        Ok(Arc::new(LibsqlDdl { sql }))
    }
}

/// The host-mediated DDL seam backing the guest `migrate-ddl` capability of a `function` step on
/// libsql (Security S5, SQLite shape). Holds the orchestrator-owned `LibsqlSql` for one database; the
/// guest NEVER holds the handle or any credential — it calls the `migrate-ddl` functions and the host
/// runs each statement on the connection it owns. Each call enforces the ledger-table (S3) +
/// transaction-control (S4) guards host-side under the SQLite dialect, then auto-commits via
/// `run_script`/`run_query`.
#[cfg(feature = "migrate")]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub(crate) struct LibsqlDdl {
    sql: boatramp_storage::LibsqlSql,
}

#[cfg(feature = "migrate")]
impl LibsqlDdl {
    /// Guard a guest-supplied script/query: refuse a ledger-table reference (S3) or its own
    /// transaction control (S4) before it reaches the connection. Tokenized under the SQLite dialect
    /// so a SQLite comment/quoted-identifier form can't hide the construct.
    fn guard(&self, script: &str) -> Result<(), MigrateDdlError> {
        let dialect = boatramp_core::sql::GuardDialect::Sqlite;
        if boatramp_core::sql::script_references_word_in(script, LIBSQL_LEDGER_WORD, dialect) {
            return Err(MigrateDdlError::LedgerProtected);
        }
        if boatramp_core::sql::script_has_txn_control_in(script, dialect) {
            return Err(MigrateDdlError::TxnControl);
        }
        Ok(())
    }
}

#[cfg(feature = "migrate")]
#[async_trait]
impl MigrateDdl for LibsqlDdl {
    async fn exec(&self, script: &str) -> Result<(), MigrateDdlError> {
        use boatramp_core::sql::SqlBackend;
        self.guard(script)?;
        self.sql
            .run_script(script)
            .await
            .map_err(|e| MigrateDdlError::Sql(sanitize_migration_error(&e.to_string())))
    }

    async fn exec_batch(&self, scripts: Vec<String>) -> Result<(), MigrateDdlError> {
        for script in &scripts {
            self.exec(script).await?;
        }
        Ok(())
    }

    async fn query(&self, sql: &str) -> Result<boatramp_core::sql::SqlRows, MigrateDdlError> {
        use boatramp_core::sql::SqlBackend;
        self.guard(sql)?;
        let rows = self
            .sql
            .run_query(sql)
            .await
            .map_err(|e| MigrateDdlError::Sql(sanitize_migration_error(&e.to_string())))?;
        if rows.rows.len() > MIGRATE_QUERY_MAX_ROWS {
            return Err(MigrateDdlError::Sql(format!(
                "query returned {} rows (cap {MIGRATE_QUERY_MAX_ROWS}); add a LIMIT — a migration \
                 verification query should read a bounded set",
                rows.rows.len()
            )));
        }
        Ok(rows)
    }
}

/// The node's single [`MigrationSubstrate`], dispatching each `(project, db)` to the substrate for
/// that database's engine: the sqlx [`NodeMigrationRunner`] for a Postgres/MySQL binding, the
/// [`LibsqlMigrationRunner`] for a `libsql` binding. The orchestrator sees ONE substrate; the
/// dispatch is by the named binding's `kind`, so a node can carry an external Postgres/MySQL AND the
/// embedded libsql default at once, each migrating on its own engine-honest semantics.
///
/// A database that matches neither configured engine returns `NotConfigured` (fail-closed) — the same
/// error the individual runners give for an unknown name.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct DispatchMigrationRunner {
    /// The Postgres/MySQL substrate (owner-role/DDL-identity + sqlx). Present only when a sqlx engine
    /// is compiled in.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    sqlx: NodeMigrationRunner,
    /// The embedded libsql/SQLite substrate. Present only when `migrate` (⇒ libsql) is compiled in.
    #[cfg(feature = "migrate")]
    libsql: LibsqlMigrationRunner,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
impl DispatchMigrationRunner {
    /// Build the dispatcher from the shared operator-SQL handle (Postgres/MySQL), the extension
    /// allowlist, and the handler `sql` `databases` config (for the libsql arm). Each arm is only
    /// wired for the engine features actually compiled in.
    pub fn new(
        #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))] op: Arc<NodeOperatorSql>,
        #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
        trusted_extensions: std::collections::BTreeSet<String>,
        #[cfg(feature = "migrate")] databases: std::collections::BTreeMap<
            String,
            crate::config::ExternalDatabaseConfig,
        >,
    ) -> Self {
        Self {
            #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
            sqlx: NodeMigrationRunner::new(op, trusted_extensions),
            #[cfg(feature = "migrate")]
            libsql: LibsqlMigrationRunner::new(databases),
        }
    }

    /// Whether `db` is a `libsql` binding (routes to the libsql substrate). Only defined — and only
    /// called — when the `migrate` feature (⇒ the embedded libsql runner) is compiled in; the dispatch
    /// methods gate their libsql arm on the same feature, so without `migrate` there is nothing to
    /// route and this helper is absent.
    #[cfg(feature = "migrate")]
    fn routes_to_libsql(&self, db: &str) -> bool {
        self.libsql.is_libsql(db)
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
#[async_trait]
impl MigrationSubstrate for DispatchMigrationRunner {
    async fn preflight(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Vec<AppliedMigration>, MigrationError> {
        #[cfg(feature = "migrate")]
        if self.routes_to_libsql(db) {
            return self.libsql.preflight(project, db).await;
        }
        #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
        {
            return self.sqlx.preflight(project, db).await;
        }
        #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
        {
            let _ = (project, db);
            Err(MigrationError::NotConfigured)
        }
    }

    async fn apply_substrate_step(
        &self,
        project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
    ) -> Result<SubstrateStepOutcome, MigrationError> {
        #[cfg(feature = "migrate")]
        if self.routes_to_libsql(db) {
            return self
                .libsql
                .apply_substrate_step(project, db, step, ordinal, effective_hash)
                .await;
        }
        #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
        {
            return self
                .sqlx
                .apply_substrate_step(project, db, step, ordinal, effective_hash)
                .await;
        }
        #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
        {
            let _ = (project, db, step, ordinal, effective_hash);
            Err(MigrationError::NotConfigured)
        }
    }

    async fn record(
        &self,
        project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
        origin: LedgerOrigin,
    ) -> Result<(), MigrationError> {
        #[cfg(feature = "migrate")]
        if self.routes_to_libsql(db) {
            return self
                .libsql
                .record(project, db, step, ordinal, effective_hash, origin)
                .await;
        }
        #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
        {
            return self
                .sqlx
                .record(project, db, step, ordinal, effective_hash, origin)
                .await;
        }
        #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
        {
            let _ = (project, db, step, ordinal, effective_hash, origin);
            Err(MigrationError::NotConfigured)
        }
    }

    async fn owner_ddl(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Arc<dyn MigrateDdl>, MigrationError> {
        #[cfg(feature = "migrate")]
        if self.routes_to_libsql(db) {
            return self.libsql.owner_ddl(project, db).await;
        }
        #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
        {
            return self.sqlx.owner_ddl(project, db).await;
        }
        #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
        {
            let _ = (project, db);
            Err(MigrationError::NotConfigured)
        }
    }
}

// The Postgres/MySQL managed-SQL tests exercise the sqlx credential/env/operator-target/runner
// machinery, so they compile only with a sqlx engine. The embedded-libsql substrate tests are a
// separate `libsql_migrate_tests` module (gated on `migrate`).
#[cfg(all(test, any(feature = "sql-postgres", feature = "sql-mysql")))]
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

    // ---------------------------------------------------------------------------------------------
    // MySQL migration-substrate parity (host-side, no live DB needed).
    // ---------------------------------------------------------------------------------------------

    /// A [`NodeOperatorSql`] over a single bring-your-own-URL binding named `main` of engine `kind`,
    /// with optional `migration_url_env`. Runtime `url_env = RUNTIME_URL_ENV`.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    fn op_for(kind: &str, migration_url_env: Option<&str>) -> Arc<NodeOperatorSql> {
        use crate::config::{TenantIsolation, TenantScope};
        let mut databases = BTreeMap::new();
        databases.insert(
            "main".to_string(),
            ExternalDatabaseConfig {
                kind: kind.to_string(),
                url_env: "RUNTIME_URL_ENV".to_string(),
                migration_url_env: migration_url_env.map(Into::into),
                pool_max: Some(2),
                read_only: false,
                connect_timeout_secs: Some(5),
                tenant: TenantIsolation::Shared,
                tenant_scope: TenantScope::Project,
                ..Default::default()
            },
        );
        Arc::new(NodeOperatorSql::new(
            databases,
            Arc::new(MemoryKv::new()),
            None,
            DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new())),
        ))
    }

    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    fn runner_over(op: Arc<NodeOperatorSql>) -> NodeMigrationRunner {
        NodeMigrationRunner::new(op, std::collections::BTreeSet::new())
    }

    /// The engine gate admits BOTH Postgres and MySQL now (parity), and returns the resolved engine;
    /// an unconfigured database is `NotConfigured`.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn engine_gate_admits_postgres_and_mysql() {
        let pg = runner_over(op_for("postgres", None));
        assert!(matches!(
            pg.engine_gate("main"),
            Ok(ExternalSqlKind::Postgres)
        ));
        let my = runner_over(op_for("mysql", Some("X")));
        assert!(matches!(my.engine_gate("main"), Ok(ExternalSqlKind::Mysql)));
        // An unknown database name is NotConfigured, not a panic.
        assert!(matches!(
            pg.engine_gate("absent"),
            Err(MigrationError::NotConfigured)
        ));
    }

    /// MySQL migrations REFUSE fail-closed when no distinct DDL identity is supplied (no
    /// `migration_url_env`) — the owner-role analog is mandatory; we never run DDL as the runtime
    /// tenant user. `preflight` surfaces the refusal (via `connect_ddl`).
    #[cfg(feature = "sql-mysql")]
    #[tokio::test]
    async fn mysql_refuses_without_a_distinct_ddl_user() {
        let sub = runner_over(op_for("mysql", None));
        let err = sub.preflight("default", "main").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("migration_url_env") && msg.contains("distinct"),
            "MySQL migrate must refuse without a distinct DDL identity: {msg}"
        );
    }

    /// MySQL migrations REFUSE when `migration_url_env` resolves to the SAME connection as the
    /// runtime `url_env` — the DDL identity must be distinct from the runtime user.
    #[cfg(feature = "sql-mysql")]
    #[tokio::test]
    async fn mysql_refuses_when_ddl_url_equals_runtime_url() {
        // Same value for both env vars → refused.
        std::env::set_var("RUNTIME_URL_ENV", "mysql://app:pw@localhost:3306/appdb");
        std::env::set_var(
            "MIGRATE_URL_ENV_SAME",
            "mysql://app:pw@localhost:3306/appdb",
        );
        let sub = runner_over(op_for("mysql", Some("MIGRATE_URL_ENV_SAME")));
        let err = sub.preflight("default", "main").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SAME connection") || msg.contains("distinct"),
            "a DDL url identical to the runtime url must be refused: {msg}"
        );
        std::env::remove_var("RUNTIME_URL_ENV");
        std::env::remove_var("MIGRATE_URL_ENV_SAME");
    }

    /// The MySQL DDL identity's env var being unset (declared but absent) is a clear error, not a
    /// silent fallback to the runtime user.
    #[cfg(feature = "sql-mysql")]
    #[tokio::test]
    async fn mysql_ddl_url_env_unset_is_a_clear_error() {
        std::env::remove_var("MIGRATE_URL_ENV_MISSING");
        let sub = runner_over(op_for("mysql", Some("MIGRATE_URL_ENV_MISSING")));
        let err = sub.preflight("default", "main").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("MIGRATE_URL_ENV_MISSING") && msg.contains("unset"),
            "an unset migration url env must be reported clearly: {msg}"
        );
    }

    /// A [`NodeMigrationRunner`] over a single MySQL binding whose runtime `url_env` and
    /// `migration_url_env` are the NAMED env vars, so a test can vary each independently (the shared
    /// `op_for` hardcodes `RUNTIME_URL_ENV`, which would race across parallel env-mutating tests).
    #[cfg(feature = "sql-mysql")]
    fn mysql_runner_with_env(runtime_env: &str, migrate_env: &str) -> NodeMigrationRunner {
        use crate::config::{TenantIsolation, TenantScope};
        let mut databases = BTreeMap::new();
        databases.insert(
            "main".to_string(),
            ExternalDatabaseConfig {
                kind: "mysql".to_string(),
                url_env: runtime_env.to_string(),
                migration_url_env: Some(migrate_env.to_string()),
                pool_max: Some(2),
                read_only: false,
                connect_timeout_secs: Some(5),
                tenant: TenantIsolation::Shared,
                tenant_scope: TenantScope::Project,
                ..Default::default()
            },
        );
        runner_over(Arc::new(NodeOperatorSql::new(
            databases,
            Arc::new(MemoryKv::new()),
            None,
            DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new())),
        )))
    }

    /// [Security review HIGH-1] Distinctness is by **login username**, not byte-equality: a DDL DSN
    /// that authenticates as the SAME MySQL user as the runtime DSN is refused even when the two
    /// strings differ (equivalent DSNs — added query param, omitted default port, trailing `/`). A
    /// genuinely different username is allowed through the distinctness check (it then fails later
    /// only because there is no live DB, which is not this refusal).
    #[cfg(feature = "sql-mysql")]
    #[tokio::test]
    async fn mysql_refuses_same_username_even_when_dsn_strings_differ() {
        // Each pair: (runtime DSN, DDL DSN) that are byte-different but the SAME user → REFUSED.
        let same_user_pairs = [
            // Added `?charset=…` query param.
            (
                "mysql://app:pw@host:3306/db",
                "mysql://app:pw@host:3306/db?charset=utf8",
            ),
            // Default port present vs omitted.
            ("mysql://app:pw@host:3306/db", "mysql://app:pw@host/db"),
            // Trailing slash / no database segment.
            ("mysql://app:pw@host:3306/db", "mysql://app:pw@host:3306/"),
            // Same user, different password (still the same LOGIN identity for our purposes).
            (
                "mysql://app:pw@host/db",
                "mysql://app:other@host:3306/otherdb",
            ),
        ];
        for (i, (runtime, ddl)) in same_user_pairs.iter().enumerate() {
            let rvar = format!("HIGH1_RT_{i}");
            let mvar = format!("HIGH1_DDL_{i}");
            std::env::set_var(&rvar, runtime);
            std::env::set_var(&mvar, ddl);
            let sub = mysql_runner_with_env(&rvar, &mvar);
            let err = sub.preflight("default", "main").await.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("SAME MySQL user") || msg.contains("SAME connection"),
                "same-username DSNs {runtime:?} vs {ddl:?} must be refused: {msg}"
            );
            std::env::remove_var(&rvar);
            std::env::remove_var(&mvar);
        }
    }

    /// [Security review HIGH-1] A genuinely DISTINCT username passes the distinctness check (it does
    /// NOT trip the same-user / same-connection refusal). It then fails only because no live MySQL
    /// is reachable — proving the refusal we assert against is the username barrier, not a connect
    /// failure.
    #[cfg(feature = "sql-mysql")]
    #[tokio::test]
    async fn mysql_allows_a_distinct_ddl_username() {
        // A connection-refused loopback port keeps the (expected) connect failure fast + offline.
        std::env::set_var("HIGH1_RT_OK", "mysql://app:pw@127.0.0.1:1/db");
        std::env::set_var("HIGH1_DDL_OK", "mysql://root_migrate:pw@127.0.0.1:1/db");
        let sub = mysql_runner_with_env("HIGH1_RT_OK", "HIGH1_DDL_OK");
        // preflight will try to connect lazily; with no live DB it errors, but NOT with the
        // distinctness refusal — that is the point of this test.
        let err = sub.preflight("default", "main").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("SAME MySQL user") && !msg.contains("SAME connection"),
            "a distinct DDL username must pass the distinctness barrier: {msg}"
        );
        std::env::remove_var("HIGH1_RT_OK");
        std::env::remove_var("HIGH1_DDL_OK");
    }

    /// [Security review HIGH-2] A **compute-backed managed** MySQL binding (`compute` set, empty
    /// `url_env`) is refused outright for migration — boatramp cannot yet auto-derive a distinct
    /// least-privilege DDL identity, so the distinctness barrier can't be enforced and we fail
    /// closed rather than run DDL under-checked. The error names the unsupported case and the
    /// remedy.
    #[cfg(feature = "sql-mysql")]
    #[tokio::test]
    async fn mysql_refuses_compute_backed_managed_migration() {
        use crate::config::{TenantIsolation, TenantScope};
        let mut databases = BTreeMap::new();
        // Compute-backed managed: `compute` set, empty `url_env`, no `password_env` (managed cred).
        let mut cfg = db("mysql", Some("my-compute"), "", None);
        cfg.tenant = TenantIsolation::Shared;
        cfg.tenant_scope = TenantScope::Project;
        // Even if an operator ALSO set a migration_url_env, a compute-backed managed binding is
        // still refused this release (the runtime identity is the managed per-tenant user, which we
        // have no runtime URL to compare against).
        cfg.migration_url_env = Some("SOME_DDL_URL".to_string());
        databases.insert("main".to_string(), cfg);
        let sub = runner_over(Arc::new(NodeOperatorSql::new(
            databases,
            Arc::new(MemoryKv::new()),
            None,
            DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new())),
        )));
        let err = sub.preflight("default", "main").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("compute-backed managed MySQL migration is not supported"),
            "compute-backed managed MySQL migrate must be refused fail-closed: {msg}"
        );
    }

    /// The ledger identifier is dialect-quoted: `"…"."…"` on Postgres, `` `…`.`…` `` on MySQL —
    /// and the same InnoDB `boatramp_migrations` database name on MySQL.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn ledger_name_is_dialect_quoted() {
        assert_eq!(
            NodeMigrationRunner::ledger(ExternalSqlKind::Postgres),
            "\"boatramp_migrations\".\"schema_migrations\""
        );
        assert_eq!(
            NodeMigrationRunner::ledger(ExternalSqlKind::Mysql),
            "`boatramp_migrations`.`schema_migrations`"
        );
    }

    /// The ledger INSERT is host-built, value-quoted, and identical in column shape across engines.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn ledger_insert_quotes_all_values() {
        use boatramp_core::sql::{MigrationAction, MigrationStep};
        let step = MigrationStep {
            id: "0001_init".to_string(),
            action: MigrationAction::Sql {
                script: "CREATE TABLE t (id int)".to_string(),
                no_transaction: false,
            },
        };
        let sql = NodeMigrationRunner::ledger_insert(
            ExternalSqlKind::Mysql,
            &step,
            0,
            "abc123",
            LedgerOrigin::Apply,
        );
        assert!(sql.contains("`boatramp_migrations`.`schema_migrations`"));
        assert!(sql.contains("'0001_init'"));
        assert!(sql.contains("'abc123'"));
        assert!(sql.contains("'sql'"));
        assert!(sql.contains("'apply'"));
    }

    /// The guard tokenizer dialect follows the engine (MySQL vs Postgres).
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn guard_dialect_follows_engine() {
        use boatramp_core::sql::GuardDialect;
        assert_eq!(guard_dialect(ExternalSqlKind::Mysql), GuardDialect::Mysql);
        assert_eq!(
            guard_dialect(ExternalSqlKind::Postgres),
            GuardDialect::Postgres
        );
        // A MySQL `#` line comment hiding a COMMIT is NOT flagged (the engine strips it), while a
        // real COMMIT is — proving the substrate uses the MySQL lexer.
        assert!(!mentions_txn_control(
            "CREATE TABLE t (id int) # COMMIT",
            ExternalSqlKind::Mysql
        ));
        assert!(mentions_txn_control(
            "DROP TABLE t; COMMIT",
            ExternalSqlKind::Mysql
        ));
    }

    /// The partial-apply / mid-DDL notes carry the greppable `PARTIALLY APPLIED` marker on MySQL
    /// (an honest non-atomic report) and pass the raw error through untouched on Postgres.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[test]
    fn mysql_partial_apply_notes_are_marked_and_postgres_passthrough() {
        let my_mid = mysql_multi_ddl_note(ExternalSqlKind::Mysql, "0002_x", "boom");
        assert!(my_mid.contains("PARTIALLY APPLIED") && my_mid.contains("0002_x"));
        assert!(my_mid.contains("boom"));
        let my_ledger = mysql_partial_apply_note(ExternalSqlKind::Mysql, "0002_x", "ledger down");
        assert!(my_ledger.contains("PARTIALLY APPLIED") && my_ledger.contains("unrecorded"));
        // Postgres passes the raw error through (its transactional path can't partially apply).
        assert_eq!(
            mysql_multi_ddl_note(ExternalSqlKind::Postgres, "0002_x", "boom"),
            "boom"
        );
        assert_eq!(
            mysql_partial_apply_note(ExternalSqlKind::Postgres, "0002_x", "boom"),
            "boom"
        );
    }

    /// The dispatcher routes each `(project, db)` to the correct engine's substrate: a `libsql` binding
    /// to the libsql runner, a Postgres/MySQL binding to the sqlx runner, and an unknown name to
    /// `NotConfigured` fail-closed. Asserted on the pure `routes_to_libsql` decision (no live DB), so a
    /// wrong route can't silently send a libsql DB to the sqlx path (or vice versa).
    #[cfg(feature = "migrate")]
    #[test]
    fn dispatch_routes_by_engine_kind() {
        let mut databases = BTreeMap::new();
        databases.insert("lite".to_string(), db("libsql", None, "", None));
        databases.get_mut("lite").unwrap().path = Some("/tmp/lite.db".into());
        databases.insert("pg".to_string(), db("postgres", None, "PG_URL", None));

        let op = Arc::new(NodeOperatorSql::new(
            databases.clone(),
            Arc::new(MemoryKv::new()),
            None,
            DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new())),
        ));
        let dispatch =
            DispatchMigrationRunner::new(op, std::collections::BTreeSet::new(), databases);

        assert!(
            dispatch.routes_to_libsql("lite"),
            "a libsql binding routes to the libsql substrate"
        );
        assert!(
            !dispatch.routes_to_libsql("pg"),
            "a postgres binding does NOT route to the libsql substrate"
        );
        assert!(
            !dispatch.routes_to_libsql("absent"),
            "an unknown name does not route to libsql (the sqlx path then returns NotConfigured)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Embedded libsql / SQLite migration-substrate tests. Self-contained (no sqlx helpers), so they
// compile under `feature = "migrate"` alone (the libsql substrate's gate). The pure host-side tests
// (ledger name, extension-refused, guard-under-SQLite-dialect, guest-holds-no-credential) always run;
// the tests that open a real embedded libsql file are `#[ignore]`d (a static-musl test binary
// segfaults in libsql's bundled SQLite — the same runtime quirk the orm-tenancy gate documents) and
// run unignored on the host toolchain in the migrate-libsql live gate.
#[cfg(all(test, feature = "migrate"))]
mod libsql_migrate_tests {
    use super::*;
    use boatramp_core::sql::{
        GuardDialect, LedgerOrigin, MigrateDdl, MigrateDdlError, MigrationAction, MigrationStep,
        MigrationSubstrate, SubstrateStepOutcome,
    };
    use std::collections::BTreeMap;

    fn sql_step(id: &str, script: &str) -> MigrationStep {
        MigrationStep {
            id: id.to_string(),
            action: MigrationAction::Sql {
                script: script.to_string(),
                no_transaction: false,
            },
        }
    }

    /// A libsql-kind binding named `app`, backed by a throwaway file under a per-process temp dir.
    fn runner_and_db(tag: &str) -> (LibsqlMigrationRunner, String) {
        let dir = std::env::temp_dir().join(format!(
            "boatramp-migrate-libsql-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.db");
        let mut databases = BTreeMap::new();
        databases.insert(
            "app".to_string(),
            crate::config::ExternalDatabaseConfig {
                kind: "libsql".to_string(),
                path: Some(path),
                ..Default::default()
            },
        );
        (LibsqlMigrationRunner::new(databases), "app".to_string())
    }

    /// The libsql ledger is a single reserved-prefixed table (no schema/db namespace on SQLite),
    /// double-quoted so the name is inert.
    #[test]
    fn libsql_ledger_name_is_a_single_prefixed_table() {
        assert_eq!(libsql_ledger(), "\"boatramp_migrations_schema_migrations\"");
    }

    /// The engine gate admits ONLY a `libsql`/`sqlite` binding; any other kind (or an unknown name)
    /// is `NotConfigured` (the Postgres/MySQL runner owns those).
    #[test]
    fn engine_gate_admits_only_libsql_kinds() {
        assert!(kind_is_libsql("libsql"));
        assert!(kind_is_libsql("LibSQL"));
        assert!(kind_is_libsql("sqlite"));
        assert!(kind_is_libsql("sqlite3"));
        assert!(!kind_is_libsql("postgres"));
        assert!(!kind_is_libsql("mysql"));

        let mut databases = BTreeMap::new();
        databases.insert(
            "app".to_string(),
            crate::config::ExternalDatabaseConfig {
                kind: "libsql".to_string(),
                path: Some("/tmp/x.db".into()),
                ..Default::default()
            },
        );
        databases.insert(
            "pg".to_string(),
            crate::config::ExternalDatabaseConfig {
                kind: "postgres".to_string(),
                url_env: "X".into(),
                ..Default::default()
            },
        );
        let sub = LibsqlMigrationRunner::new(databases);
        assert!(sub.is_libsql("app"));
        assert!(!sub.is_libsql("pg"));
        assert!(!sub.is_libsql("absent"));
        assert!(matches!(
            sub.engine_gate("pg"),
            Err(MigrationError::NotConfigured)
        ));
        assert!(matches!(
            sub.engine_gate("absent"),
            Err(MigrationError::NotConfigured)
        ));
        assert!(sub.engine_gate("app").is_ok());
    }

    /// The ledger INSERT is host-built, value-quoted, and identical in column shape to the other
    /// engines — against the libsql ledger table.
    #[test]
    fn libsql_ledger_insert_quotes_all_values() {
        let step = sql_step("0001_init", "CREATE TABLE t (id integer)");
        let sql = LibsqlMigrationRunner::ledger_insert(&step, 0, "abc123", LedgerOrigin::Apply);
        assert!(sql.contains("\"boatramp_migrations_schema_migrations\""));
        assert!(sql.contains("'0001_init'"));
        assert!(sql.contains("'abc123'"));
        assert!(sql.contains("'sql'"));
        assert!(sql.contains("'apply'"));
    }

    /// The guards are tokenized under the SQLite dialect (sqlparser `SQLiteDialect`): a `COMMIT`
    /// hidden behind a SQLite `--` comment is stripped (not flagged), a real one is; the ledger-table
    /// name is caught under SQLite `[bracketed]` / `` `backtick` `` identifier forms the generic lexer
    /// wouldn't. This is the LibsqlDdl guard the `migrate-ddl` seam runs.
    #[test]
    fn libsql_guards_use_the_sqlite_dialect() {
        // Sanity on the dialect selection itself.
        assert!(boatramp_core::sql::script_has_txn_control_in(
            "DROP TABLE t; COMMIT",
            GuardDialect::Sqlite
        ));
        assert!(!boatramp_core::sql::script_has_txn_control_in(
            "CREATE TABLE t (id int) -- COMMIT",
            GuardDialect::Sqlite
        ));
        // On SQLite the ledger is ONE table `boatramp_migrations_schema_migrations`; a reference to
        // it lexes as that single identifier token (bracketed, backtick, or bare), which the guard
        // needle `LIBSQL_LEDGER_WORD` matches.
        assert!(boatramp_core::sql::script_references_word_in(
            "SELECT * FROM [boatramp_migrations_schema_migrations]",
            LIBSQL_LEDGER_WORD,
            GuardDialect::Sqlite
        ));
        assert!(boatramp_core::sql::script_references_word_in(
            "DROP TABLE `boatramp_migrations_schema_migrations`",
            LIBSQL_LEDGER_WORD,
            GuardDialect::Sqlite
        ));

        // The LibsqlDdl guard maps those to the fail-closed MigrateDdlError variants. Build one over a
        // throwaway file so `guard` (pure, no IO) can be exercised.
        let dir =
            std::env::temp_dir().join(format!("boatramp-libsql-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sql = futures_lite_block_on(boatramp_storage::LibsqlSql::open_local(dir.join("g.db")))
            .unwrap();
        let ddl = LibsqlDdl { sql };
        assert!(matches!(
            ddl.guard("SELECT * FROM `boatramp_migrations_schema_migrations`"),
            Err(MigrateDdlError::LedgerProtected)
        ));
        assert!(matches!(
            ddl.guard("BEGIN; CREATE TABLE x(i int); COMMIT"),
            Err(MigrateDdlError::TxnControl)
        ));
        // Plain owner DDL passes the guard.
        assert!(ddl.guard("CREATE TABLE x (i integer)").is_ok());
    }

    /// A tiny synchronous block-on so the one guard test above can open a file without a tokio
    /// runtime (the async tests below use `#[tokio::test]`).
    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        // A minimal executor: the libsql `open_local` future is driven to completion on a fresh
        // current-thread tokio runtime.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// The guest NEVER holds a DB credential or handle: `owner_ddl` returns a host-owned
    /// `Arc<dyn MigrateDdl>` (a `LibsqlDdl` wrapping the host's `LibsqlSql`) — the guest only ever
    /// calls the `migrate-ddl` functions, and every statement runs on the host-owned connection. There
    /// is no path to a raw connection/path/credential in the returned trait object. (The file is the
    /// trust boundary; there is no owner/runtime role split to model on SQLite — stated plainly.)
    #[tokio::test]
    #[ignore = "opens a real embedded libsql file; run unignored on the host toolchain (static-musl segfaults in libsql)"]
    async fn owner_ddl_is_host_mediated_guest_holds_no_credential() {
        let (sub, db) = runner_and_db("nocred");
        let ddl: Arc<dyn MigrateDdl> = sub.owner_ddl("default", &db).await.unwrap();
        // The returned object is a MigrateDdl trait object — the ONLY surface is exec/exec_batch/query.
        // It runs host-side (auto-commit) and enforces the guards; there is no accessor for the file
        // path / connection. A real exec proves the host runs it.
        ddl.exec("CREATE TABLE proof (n integer)").await.unwrap();
        ddl.exec("INSERT INTO proof (n) VALUES (1)").await.unwrap();
        let rows = ddl.query("SELECT n FROM proof").await.unwrap();
        assert_eq!(rows.rows.len(), 1);
        // And the guards fire on the host-mediated seam.
        assert!(matches!(
            ddl.exec("SELECT * FROM boatramp_migrations_schema_migrations")
                .await
                .unwrap_err(),
            MigrateDdlError::LedgerProtected
        ));
    }

    /// TRANSACTIONAL ROLLBACK (the SQLite strength, inverse of MySQL): a `sql` step whose 2nd
    /// statement fails leaves the 1st statement's effect ROLLED BACK and no ledger row — the whole
    /// step is atomic. This is the core libsql-parity guarantee.
    #[tokio::test]
    #[ignore = "opens a real embedded libsql file; run unignored on the host toolchain (static-musl segfaults in libsql)"]
    async fn sql_step_rolls_back_cleanly_on_failure() {
        let (sub, db) = runner_and_db("rollback");

        // preflight on an empty ledger returns nothing + creates the ledger table.
        assert!(sub.preflight("default", &db).await.unwrap().is_empty());

        // A step whose 2nd statement errors (duplicate table) must roll the 1st back entirely.
        let bad = sql_step(
            "0001_atomic",
            "CREATE TABLE widget (id integer primary key); \
             CREATE TABLE widget (id integer primary key)", // 2nd fails: already exists
        );
        let eff = bad.content_hash();
        match sub
            .apply_substrate_step("default", &db, &bad, 0, &eff)
            .await
            .unwrap()
        {
            SubstrateStepOutcome::Failed(_) => {}
            other => panic!("expected a failed step, got {other:?}"),
        }
        // No ledger row for the failed step…
        let applied = sub.preflight("default", &db).await.unwrap();
        assert!(!applied.iter().any(|a| a.id == "0001_atomic"));

        // …and the 1st statement's table was ROLLED BACK — a clean recreate succeeds (it would fail
        // with "table widget already exists" if the 1st CREATE had leaked, as it does on MySQL).
        let good = sql_step(
            "0001_atomic",
            "CREATE TABLE widget (id integer primary key)",
        );
        assert!(matches!(
            sub.apply_substrate_step("default", &db, &good, 0, &good.content_hash())
                .await
                .unwrap(),
            SubstrateStepOutcome::Applied
        ));
        let applied = sub.preflight("default", &db).await.unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].id, "0001_atomic");
        assert_eq!(applied[0].origin, "apply");
        assert_eq!(
            applied[0].content_hash,
            good.content_hash(),
            "the ledger records the effective hash"
        );
    }

    /// An `extension` step is refused outright on libsql/SQLite (no guest-loadable native extensions).
    #[tokio::test]
    #[ignore = "opens a real embedded libsql file; run unignored on the host toolchain (static-musl segfaults in libsql)"]
    async fn extension_step_is_refused_on_libsql() {
        let (sub, db) = runner_and_db("ext");
        let step = MigrationStep {
            id: "0001_ext".to_string(),
            action: MigrationAction::Extension {
                name: "spellfix".to_string(),
            },
        };
        match sub
            .apply_substrate_step("default", &db, &step, 0, &step.content_hash())
            .await
            .unwrap()
        {
            SubstrateStepOutcome::Failed(msg) => {
                assert!(
                    msg.contains("libsql") || msg.contains("SQLite"),
                    "extension refused on libsql: {msg}"
                );
            }
            other => panic!("expected extension refused, got {other:?}"),
        }
        // A raw `CREATE EXTENSION` inside a sql step is likewise refused.
        let raw = sql_step("0001_rawext", "CREATE EXTENSION IF NOT EXISTS whatever");
        assert!(matches!(
            sub.apply_substrate_step("default", &db, &raw, 0, &raw.content_hash())
                .await
                .unwrap(),
            SubstrateStepOutcome::Failed(_)
        ));
    }

    /// A transactional `sql` step carrying its own BEGIN/COMMIT is refused under the SQLite dialect
    /// (it would desync the atomic wrapper) — and a ledger-table reference is refused too.
    #[tokio::test]
    #[ignore = "opens a real embedded libsql file; run unignored on the host toolchain (static-musl segfaults in libsql)"]
    async fn txn_control_and_ledger_reference_are_refused_under_sqlite_dialect() {
        let (sub, db) = runner_and_db("guards");
        let txn = sql_step("0001_txn", "BEGIN; CREATE TABLE x (i int); COMMIT");
        assert!(matches!(
            sub.apply_substrate_step("default", &db, &txn, 0, &txn.content_hash())
                .await
                .unwrap(),
            SubstrateStepOutcome::Failed(_)
        ));
        let ledger = sql_step(
            "0001_led",
            "INSERT INTO boatramp_migrations_schema_migrations (id) VALUES ('x')",
        );
        assert!(matches!(
            sub.apply_substrate_step("default", &db, &ledger, 0, &ledger.content_hash())
                .await
                .unwrap(),
            SubstrateStepOutcome::Failed(_)
        ));
    }

    /// baseline: `record(…, Baseline)` writes a ledger row WITHOUT running the step, read back with
    /// origin=baseline; and prefix ordering is preserved.
    #[tokio::test]
    #[ignore = "opens a real embedded libsql file; run unignored on the host toolchain (static-musl segfaults in libsql)"]
    async fn baseline_records_without_running() {
        let (sub, db) = runner_and_db("baseline");
        let baselined = sql_step("0001_baselined", "CREATE TABLE never_run (id integer)");
        sub.record(
            "default",
            &db,
            &baselined,
            0,
            &baselined.content_hash(),
            LedgerOrigin::Baseline,
        )
        .await
        .unwrap();
        let applied = sub.preflight("default", &db).await.unwrap();
        let row = applied
            .iter()
            .find(|a| a.id == "0001_baselined")
            .expect("baselined row present");
        assert_eq!(row.origin, "baseline");
        // The step was NOT run: the table doesn't exist, so a fresh CREATE of the same name succeeds.
        let good = sql_step("0002_after", "CREATE TABLE never_run (id integer)");
        assert!(matches!(
            sub.apply_substrate_step("default", &db, &good, 1, &good.content_hash())
                .await
                .unwrap(),
            SubstrateStepOutcome::Applied
        ));
    }
}
