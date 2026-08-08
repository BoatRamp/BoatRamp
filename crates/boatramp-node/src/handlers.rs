//! WebAssembly handler-runtime assembly (moved from the binary — node-library N2b).
//!
//! Builds `boatramp_server::HandlerRuntime` from `[handlers]` config: the wasmtime
//! engine plus the libsql `sql` binding (single-node file per site, a cluster sqld
//! namespace, or an external Postgres/MySQL). Handlers-gated; a lean node gets a
//! disabled runtime. Lives here (not the backend-agnostic `boatramp-server`)
//! because it drives the concrete `boatramp-storage` SQL backends.

#[cfg(feature = "handlers")]
use crate::error::Error;
use crate::error::Result;
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use std::path::Path;
use std::sync::Arc;

/// Build the WebAssembly handler runtime. With the `handlers` feature it wraps a
/// wasmtime engine serving the kv/blob bindings from the server's own backends;
/// otherwise it is an empty placeholder (handler routes fall through to static).
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub async fn build_handler_runtime(
    kv: Arc<dyn KvStore>,
    storage: Arc<dyn boatramp_core::Storage>,
    data_dir: &Path,
    handlers_cfg: Option<&crate::config::HandlersConfig>,
    messaging_override: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    max_blob_bytes: u64,
    max_component_bytes: u64,
    // The deploy store (for a managed compute-backed `sql` database's endpoint
    // resolution) and the `[secrets]` envelope (to seal a managed credential).
    deploy: &DeployStore,
    secrets_envelope: Option<Arc<dyn KeyEnvelope>>,
) -> Result<boatramp_server::HandlerRuntime> {
    // Opt-in pooling allocator: faster instantiation, large
    // up-front virtual reservation — benchmark before enabling.
    let limits = boatramp_handlers::Limits::default();
    let engine = if handlers_cfg.is_some_and(|h| h.pooling) {
        boatramp_handlers::HandlerEngine::with_pooling(limits, 64)?
    } else {
        boatramp_handlers::HandlerEngine::new(limits, 64)?
    };
    let sql = build_sql_backends(
        handlers_cfg.and_then(|h| h.bindings.sql.as_ref()),
        data_dir,
        deploy,
        &kv,
        secrets_envelope.as_ref(),
    )
    .await?;
    // The `wasi:messaging` substrate: single-node `LogMessaging` over the same
    // blob/KV backends by default, or the cluster coordinator when one is given.
    let messaging: Arc<dyn boatramp_core::messaging::Messaging> = messaging_override
        .unwrap_or_else(|| {
            Arc::new(boatramp_core::messaging::LogMessaging::new(
                storage.clone(),
                kv.clone(),
            ))
        });
    let runtime =
        boatramp_server::HandlerRuntime::new(engine, kv, storage, Some(sql), Some(messaging));
    // Apply the posture's host-side blob cap + component-size cap.
    runtime.set_max_blob_bytes(max_blob_bytes);
    runtime.set_max_component_bytes(max_component_bytes);
    Ok(runtime)
}

/// Resolve the `[handlers.bindings.sql]` config to the libsql SQL backend.
/// Single-node by default (an embedded file per site under `<data-dir>`); set
/// `url` to bind a shared sqld cluster (a namespace per site). Either way sites
/// get a real database boundary — see `boatramp_core::sql`.
#[cfg(feature = "handlers")]
async fn build_sql_backends(
    cfg: Option<&crate::config::SqlBindingConfig>,
    data_dir: &Path,
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    secrets_envelope: Option<&Arc<dyn KeyEnvelope>>,
) -> Result<Arc<dyn boatramp_core::sql::SqlBackends>> {
    let resolve_env = |var: &Option<String>| -> Result<Option<String>> {
        match var {
            Some(var) => Ok(Some(
                std::env::var(var).map_err(|_| Error::SqlEnvUnset(var.clone()))?,
            )),
            None => Ok(None),
        }
    };

    let backend = match cfg.and_then(|c| c.url.as_ref()) {
        // Cluster: a sqld namespace per site. Auth tokens come from the
        // environment, never the config file.
        Some(url) => {
            let cfg = cfg.expect("url implies cfg");
            let admin_url = cfg.admin_url.as_ref().ok_or(Error::SqlAdminUrlRequired)?;
            let token = resolve_env(&cfg.token_env)?.unwrap_or_default();
            let admin_token = resolve_env(&cfg.admin_token_env)?;
            let backends = boatramp_storage::LibsqlSqlBackends::remote(
                url.clone(),
                admin_url.clone(),
                token,
                admin_token,
            );
            // Optional read-replica routing: reads → replica, writes → primary.
            match &cfg.replica_url {
                Some(replica_url) => backends.with_read_replica(replica_url.clone()),
                None => backends,
            }
        }
        // Single-node: an embedded file per site.
        None => {
            let dir = cfg
                .and_then(|c| c.dir.clone())
                .unwrap_or_else(|| data_dir.join("handlers-sql"));
            boatramp_storage::LibsqlSqlBackends::local(dir)
        }
    };
    // Preview SQL policy (how preview deployments relate to live data).
    let preview_mode = match cfg.and_then(|c| c.preview_mode.as_deref()) {
        None | Some("empty") => boatramp_core::sql::PreviewSqlMode::Empty,
        Some("branch") => boatramp_core::sql::PreviewSqlMode::Branch,
        Some("shared") => boatramp_core::sql::PreviewSqlMode::Shared,
        Some(other) => return Err(Error::UnknownPreviewMode(other.to_string())),
    };
    let preview_init = match cfg.and_then(|c| c.preview_init.as_ref()) {
        Some(path) => {
            Some(
                std::fs::read_to_string(path).map_err(|err| Error::PreviewInitRead {
                    path: path.clone(),
                    source: err,
                })?,
            )
        }
        None => None,
    };
    let default: Arc<dyn boatramp_core::sql::SqlBackends> =
        Arc::new(backend.with_preview_policy(preview_mode, preview_init));

    // Overlay any external (bring-your-own) databases on the managed default.
    // With none configured the default is returned unchanged (and a build
    // without an external SQL engine never has to link the sqlx path).
    let databases = cfg.map(|c| &c.databases);
    if databases.is_none_or(std::collections::BTreeMap::is_empty) {
        return Ok(default);
    }
    let databases = databases.expect("checked non-empty above");

    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    {
        use boatramp_core::project::DEFAULT_PROJECT;
        use boatramp_core::sql::SqlBackend;
        use boatramp_storage::sql_compute::ComputeResolvedSqlBackend;
        use boatramp_storage::sql_sqlx::{
            connect, CompositeSqlBackends, ExternalSqlKind, ExternalSqlOptions,
        };
        let timeout = |db: &crate::config::ExternalDatabaseConfig| {
            db.connect_timeout_secs.map(std::time::Duration::from_secs)
        };
        let mut composite = CompositeSqlBackends::new(default);
        for (name, db) in databases {
            let kind = ExternalSqlKind::parse(&db.kind).ok_or_else(|| Error::SqlExternalKind {
                name: name.clone(),
                kind: db.kind.clone(),
            })?;
            let external: Arc<dyn SqlBackend> = if let Some(workload) =
                db.compute.as_deref().filter(|c| !c.is_empty())
            {
                // Compute-backed: resolve the workload's live endpoint on demand and
                // build the connection. The credential is either brought
                // (`password_env`) or **boatramp-managed** (generated + sealed).
                let password = match db.password_env.as_deref().filter(|v| !v.is_empty()) {
                    Some(var) => std::env::var(var).map_err(|_| Error::SqlEnvUnset(var.into()))?,
                    None => {
                        // Managed credential: fail closed without a secrets envelope
                        // (we will not persist a DB password in cleartext).
                        let envelope = secrets_envelope
                            .cloned()
                            .ok_or_else(|| Error::SqlManagedNeedsSecrets(name.clone()))?;
                        crate::managed_sql::ManagedSqlCredentials::new(kv.clone(), envelope)
                            .password(DEFAULT_PROJECT, workload)
                            .await
                            .map_err(|reason| Error::SqlManagedCredential {
                                name: name.clone(),
                                reason,
                            })?
                    }
                };
                let resolver = Arc::new(crate::managed_sql::DeployEndpointResolver::new(
                    deploy.clone(),
                    DEFAULT_PROJECT,
                ));
                Arc::new(ComputeResolvedSqlBackend::new(
                    resolver,
                    workload,
                    kind,
                    db.database.clone().unwrap_or_default(),
                    db.user.clone().unwrap_or_default(),
                    password,
                    db.pool_max,
                    db.read_only,
                    timeout(db),
                ))
            } else {
                // Bring-your-own URL: the connection URL(s) are secrets, resolved
                // from the environment.
                if db.url_env.trim().is_empty() {
                    return Err(Error::SqlExternalUrlEnvMissing(name.clone()));
                }
                let url = std::env::var(&db.url_env)
                    .map_err(|_| Error::SqlEnvUnset(db.url_env.clone()))?;
                let read_url = match &db.read_url_env {
                    Some(var) => {
                        Some(std::env::var(var).map_err(|_| Error::SqlEnvUnset(var.clone()))?)
                    }
                    None => None,
                };
                let opts = ExternalSqlOptions::new(url)
                    .with_read_url(read_url)
                    .with_max_connections(db.pool_max)
                    .read_only(db.read_only)
                    .with_connect_timeout(timeout(db));
                connect(kind, &opts).map_err(|source| Error::SqlExternalConnect {
                    name: name.clone(),
                    source,
                })?
            };
            composite = composite.with_external(name.clone(), external, db.allow_preview);
        }
        Ok(Arc::new(composite))
    }
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    {
        // The compute-backed arm (the only consumer of these) is compiled out
        // without a SQL engine; a `databases` entry then can't be served at all.
        let _ = (deploy, kv, secrets_envelope);
        let name = databases.keys().next().cloned().unwrap_or_default();
        Err(Error::SqlExternalUnavailable(name))
    }
}

#[cfg(not(feature = "handlers"))]
#[allow(clippy::too_many_arguments)]
pub async fn build_handler_runtime(
    _kv: Arc<dyn KvStore>,
    _storage: Arc<dyn boatramp_core::Storage>,
    _data_dir: &Path,
    _handlers_cfg: Option<&crate::config::HandlersConfig>,
    _messaging_override: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    _max_blob_bytes: u64,
    _max_component_bytes: u64,
    _deploy: &DeployStore,
    _secrets_envelope: Option<Arc<dyn KeyEnvelope>>,
) -> Result<boatramp_server::HandlerRuntime> {
    Ok(boatramp_server::HandlerRuntime::disabled())
}

#[cfg(all(test, any(feature = "sql-postgres", feature = "sql-mysql")))]
mod tests {
    use super::*;
    // `super::*` brings the crate's 1-arg `Result` alias into scope; the trait impls
    // below need the std 2-arg `Result`, so shadow it back (explicit beats glob).
    use std::result::Result;

    use async_trait::async_trait;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

    /// A reversible test envelope (NOT encryption) — proves sealing round-trips.
    struct TestEnvelope;
    #[async_trait]
    impl KeyEnvelope for TestEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().rev().copied().collect())
        }
        async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(w.iter().rev().copied().collect())
        }
    }

    /// A no-op object store, so a `DeployStore` can be built (the endpoint resolver
    /// only reads KV replica state, which is empty here — the backend is lazy).
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

    /// A `sql` binding with one managed (compute-backed, no `password_env`) database.
    fn managed_sql_cfg() -> crate::config::SqlBindingConfig {
        let mut databases = std::collections::BTreeMap::new();
        databases.insert(
            "analytics".to_string(),
            crate::config::ExternalDatabaseConfig {
                kind: "postgres".into(),
                compute: Some("pg".into()),
                database: Some("analytics".into()),
                user: Some("app".into()),
                ..Default::default()
            },
        );
        crate::config::SqlBindingConfig {
            databases,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn managed_sql_fails_closed_without_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let cfg = managed_sql_cfg();
        // `Arc<dyn SqlBackends>` isn't `Debug`, so match rather than `unwrap_err`.
        match build_sql_backends(Some(&cfg), tmp.path(), &deploy, &kv, None).await {
            Err(Error::SqlManagedNeedsSecrets(name)) => assert_eq!(name, "analytics"),
            Ok(_) => panic!("a managed DB without [secrets] must fail closed, got Ok"),
            Err(other) => panic!("expected SqlManagedNeedsSecrets, got: {other}"),
        }
    }

    #[tokio::test]
    async fn managed_sql_builds_lazily_and_seals_the_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(TestEnvelope);
        let cfg = managed_sql_cfg();
        // No DB is running: the backend resolves the endpoint on first use, so
        // assembly succeeds without a connection and the credential is sealed now.
        let backends = build_sql_backends(Some(&cfg), tmp.path(), &deploy, &kv, Some(&envelope))
            .await
            .expect("managed sql builds without a live DB (lazy connect)");
        let sealed = kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .expect("managed credential sealed at build under the default project");
        assert_ne!(sealed.len(), 0);
        // Sanity: the composite is usable as a provider (no connection yet).
        let _: Arc<dyn boatramp_core::sql::SqlBackends> = backends;
    }
}
