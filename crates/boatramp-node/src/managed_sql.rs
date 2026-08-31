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
use boatramp_storage::sql_compute::ComputeEndpointResolver;
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
}

/// One managed database's non-secret connection parts, keyed in [`ManagedDbEnv`]
/// by the compute **workload** that backs it.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
struct ManagedDbSpec {
    kind: ExternalSqlKind,
    database: String,
    user: String,
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
}

#[async_trait]
impl ManagedDbEnvResolver for ManagedDbEnv {
    async fn managed_db_env(&self, project: &str, workload: &str) -> Vec<(String, String)> {
        let Some(db) = self.dbs.get(workload) else {
            return Vec::new();
        };
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
        let db = self.dbs.get(workload)?;
        Some(match self.privilege {
            ManagedDbPrivilege::Rootless => {
                let (uid, gid) = managed_db_default_ids(db.kind);
                PrivilegeDirective::Rootless { uid, gid }
            }
            ManagedDbPrivilege::Caps => PrivilegeDirective::Caps(managed_db_caps()),
        })
    }
}

/// Auto-register the compute workload backing each **managed co-located** database
/// (compute-backed, no `password_env`) that has no workload yet, so declaring the
/// `databases` binding is enough to boot the DB — no separate `compute set` / apply
/// step (turnkey from a stock image on a bare host). Idempotent and non-clobbering:
/// a workload the operator declared explicitly (apply / admin API) always wins;
/// this only fills an absent one, and re-running is a no-op. Best-effort — a write
/// failure is logged, never fatal (serving proceeds; the reconcile simply has
/// nothing to launch for that DB until its workload exists).
///
/// The synthesized spec comes from [`managed_db_spec`](boatramp_core::compute::managed_db_spec)
/// — the same builder the container capability gate exercises — so the shipped
/// managed-DB workload never diverges from the tested one.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub async fn auto_register_managed_db_workloads(
    deploy: &DeployStore,
    databases: &std::collections::BTreeMap<String, crate::config::ExternalDatabaseConfig>,
) {
    use boatramp_core::compute::{
        managed_db_spec, ComputeWorkload, ManagedDbEngine, PlacementConstraints,
    };

    /// 10 GiB — the default managed data-volume size when the config sets none.
    const DEFAULT_VOLUME_MIB: u32 = 10 * 1024;

    for db in databases.values() {
        if !db.is_managed_credential() {
            continue;
        }
        let Some(workload) = db.compute.as_deref().filter(|c| !c.is_empty()) else {
            continue;
        };
        let engine = match ExternalSqlKind::parse(&db.kind) {
            Some(ExternalSqlKind::Postgres) => ManagedDbEngine::Postgres,
            Some(ExternalSqlKind::Mysql) => ManagedDbEngine::Mysql,
            // Config validation rejects an unparsable engine before serve; skip defensively.
            None => continue,
        };
        // Non-clobbering: only fill an absent workload — an operator-declared one
        // (apply / admin API) always wins, which also makes re-runs idempotent.
        match deploy
            .get_compute_workload(ProjectRef::DEFAULT, workload)
            .await
        {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%workload, error = %e, "managed sql: could not check for an existing compute workload; skipping auto-register");
                continue;
            }
        }
        let image = db.image.as_deref();
        let spec = managed_db_spec(
            engine,
            image,
            db.volume_size_mib.unwrap_or(DEFAULT_VOLUME_MIB),
        );
        let spec_id = match deploy.put_compute_spec(&spec).await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(%workload, error = %e, "managed sql: could not store the auto-registered compute spec");
                continue;
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
                "managed sql: auto-registered the co-located database compute workload"
            ),
            Err(e) => {
                tracing::warn!(%workload, error = %e, "managed sql: could not register the auto-registered compute workload")
            }
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
        if let Some(workload) = cfg.compute.as_deref().filter(|c| !c.is_empty()) {
            // Managed or brought-credential compute-backed database.
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
                        .password(project, workload)
                        .await
                        .map_err(SqlError::other)?
                }
            };
            let resolver = Arc::new(DeployEndpointResolver::new(self.deploy.clone(), project));
            Ok(Arc::new(ComputeResolvedSqlBackend::new(
                resolver,
                workload,
                kind,
                cfg.database.clone().unwrap_or_default(),
                cfg.user.clone().unwrap_or_default(),
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

    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[tokio::test]
    async fn auto_register_creates_managed_workloads_idempotently_and_never_clobbers() {
        use boatramp_core::compute::{ComputeWorkload, PlacementConstraints};

        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let p = ProjectRef::DEFAULT;

        let mut dbs = BTreeMap::new();
        // Managed (compute-backed, no password_env) → auto-registered.
        dbs.insert(
            "analytics".to_string(),
            db("postgres", Some("pg"), "", None),
        );
        // BYO credential (compute-backed WITH password_env) → NOT managed, NOT registered.
        dbs.insert(
            "byo".to_string(),
            db("postgres", Some("byopg"), "", Some("PW")),
        );
        // BYO URL (not compute-backed) → NOT registered.
        dbs.insert("ext".to_string(), db("mysql", None, "MYSQL_URL", None));

        auto_register_managed_db_workloads(&deploy, &dbs).await;

        // Only the managed workload was registered, desired 1 replica, spec stored.
        let wl = deploy
            .get_compute_workload(p, "pg")
            .await
            .unwrap()
            .expect("managed workload `pg` auto-registered");
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
}
