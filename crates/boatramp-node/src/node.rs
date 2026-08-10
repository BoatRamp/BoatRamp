//! The node-graph assembly: given a built store (blobs + KV), a configured
//! [`Auth`](boatramp_server::Auth), and resolved
//! [`ServerOptions`](boatramp_server::ServerOptions), wire the deploy store,
//! handler runtime, compute reconcile loop, and domain-verify reconcile loop
//! into a [`RunningNode`] ready to hand to a transport (`serve_with` & friends).
//!
//! This is the headline extraction of `PLAN-node-library`: the binary's
//! `serve::run` used to inline this wiring, so no embedder or in-process test
//! could exercise the same graph the `boatramp serve` binary runs. `run` now
//! resolves the *environment* (args -> backends -> store, signal handlers,
//! migration, auth) and calls [`assemble`]; the cluster path keeps its own inline
//! copy until a later step converges it here.

use std::path::Path;
use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::KvStore;
use boatramp_core::Storage;

use crate::config::ServerConfig;
use crate::error::{Error, Result};

/// How often the compute reconcile loop converges desired vs actual workloads.
/// Defaults to 30s; override with `BOATRAMP_COMPUTE_RECONCILE_TICK_MS` (milliseconds)
/// so compute-backed tests can converge in a fraction of a second instead of
/// waiting a full tick for the launch/scale reconcile.
pub fn compute_reconcile_tick() -> std::time::Duration {
    std::env::var("BOATRAMP_COMPUTE_RECONCILE_TICK_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map(std::time::Duration::from_millis)
        .unwrap_or(std::time::Duration::from_secs(30))
}
/// How often the domain-verify reconcile loop re-checks pending challenges.
pub const DOMAIN_VERIFY_RECONCILE_TICK: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a compute workload may be idle before scale-to-zero sleeps it.
pub const COMPUTE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The built store + resolved config handed to [`assemble`]. Owns the blob/KV
/// backends and the auth/options the caller already resolved; borrows the parsed
/// config and data directory.
pub struct NodeInput<'a> {
    /// The full parsed server config (the handler + compute sections are read here).
    pub config: &'a ServerConfig,
    /// The node data directory (per-site SQL, handler state).
    pub data_dir: &'a Path,
    /// The object store built by [`crate::blobs::build_blobs`].
    pub storage: Arc<dyn Storage>,
    /// The metadata KV, already cache-fronted, built by [`crate::backends::build_kv`].
    pub kv: Arc<dyn KvStore>,
    /// The control-plane auth built by [`crate::auth::configure_auth`].
    pub auth: boatramp_server::Auth,
    /// Server options, already carrying the resolved posture, daemon runtime, and
    /// (post-`configure_auth`/`configure_oidc`) issuer / OIDC verifier.
    pub options: boatramp_server::ServerOptions,
    /// The cloud blob-change watch provider (FA-5b2), if the backend is a cloud one.
    pub watch_provider: Option<Arc<dyn boatramp_core::blob_provision::WatchProvider>>,
    /// The provisioning tier for the watch provider.
    pub provision_tier: boatramp_core::blob_notify::ProvisionTier,
    /// The `wasi:messaging` substrate override for the handler runtime. `None` uses
    /// the single-node default (`LogMessaging` over the same backends); the cluster
    /// path passes its Raft-backed coordinator.
    pub messaging: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    /// The single leader gate for cron firing + the compute / domain-verify reconcile
    /// loops. Single-node passes an always-true gate (there is one node); the cluster
    /// passes its Raft `is_leader` check so a single node drives each sweep.
    pub is_leader: boatramp_server::CronLeaderGate,
    /// This node's compute scheduler id (`0` single-node; the cluster node id in a
    /// fleet, so replicas are tagged to the right node).
    pub node_id: u64,
}

/// A fully wired node: the deploy store, handler runtime, auth, and options a
/// transport consumes, plus the detached reconcile loops kept alive for the
/// node's serving life. Destructure it and hold `reconcile` across the serve
/// await so the loops outlive assembly.
pub struct RunningNode {
    /// The deploy store (blob + KV) the router serves from.
    pub deploy: DeployStore,
    /// The handler runtime for wasm handlers (a disabled build ⇒ a no-op runtime).
    pub handlers: boatramp_server::HandlerRuntime,
    /// The control-plane auth.
    pub auth: boatramp_server::Auth,
    /// The resolved server options.
    pub options: boatramp_server::ServerOptions,
    /// The detached reconcile loops (compute + domain-verify). Tokio `JoinHandle`s
    /// do not abort on drop, so the loops run for the process life regardless; the
    /// handles are retained so an embedder can join/abort them on shutdown.
    pub reconcile: Vec<tokio::task::JoinHandle<()>>,
}

/// Wire [`NodeInput`] into a [`RunningNode`]: build the handler runtime, the
/// deploy store (materializing the reserved `default` project), the compute
/// backends + reconcile loop, and the domain-verify reconcile loop.
///
/// The caller has already built the store and configured auth/OIDC on `options`;
/// this is the pure node-graph wiring, identical to what `boatramp serve` runs.
pub async fn assemble(input: NodeInput<'_>) -> Result<RunningNode> {
    let NodeInput {
        config,
        data_dir,
        storage,
        kv,
        auth,
        options,
        watch_provider,
        provision_tier,
        messaging,
        is_leader,
        node_id,
    } = input;
    // Copy out the posture scalars up front so `options` can be moved into the
    // returned `RunningNode` without a lingering borrow.
    let max_handler_blob_bytes = options.posture.max_handler_blob_bytes;
    let max_component_bytes = options.posture.max_component_bytes;
    let allow_shared_kernel = options.posture.allow_shared_kernel_compute;
    let domain_verify_allow_private = options.posture.domain_verify_allow_private;

    // The deploy store the router serves from — built up front so the handler
    // runtime's managed compute-backed `sql` binding can resolve DB endpoints from
    // the same store the reconcile writes.
    let compute_storage = storage.clone();
    let deploy = DeployStore::new(storage, kv.clone());
    // The `[secrets]` envelope (local KEK / Vault) that seals a managed SQL
    // credential at rest. `None` ⇒ no wrapping (a managed DB then fails closed).
    let secrets_envelope = build_secrets_envelope(config.secrets.as_ref(), data_dir)?;

    // The handler runtime reuses the same blob/KV backends (per-site prefixed)
    // for its wasi:blobstore/keyvalue bindings; the sql binding is selected by
    // `[handlers.bindings.sql]` (default: per-site libsql files under <data-dir>).
    let handlers = crate::handlers::build_handler_runtime(
        kv.clone(),
        compute_storage.clone(),
        data_dir,
        config.handlers.as_ref(),
        messaging,
        max_handler_blob_bytes,
        max_component_bytes,
        &deploy,
        secrets_envelope.clone(),
    )
    .await?;
    // Leader-gate cron firing (cluster: only the Raft leader fires; single-node: an
    // always-true gate, equivalent to the unset default). The same gate drives the
    // reconcile loops below, so all three converge on one leader per fleet. Only the
    // handler runtime has a scheduler, so this is a no-op without the `handlers` feature.
    #[cfg(feature = "handlers")]
    handlers.set_cron_leader_gate(is_leader.clone());
    // FA-5b2: on a cloud backend, wire the blob-change notification provisioner +
    // its tier so adding a `blob` trigger provisions (and removing it retracts).
    #[cfg(feature = "handlers")]
    if let Some(provider) = watch_provider {
        handlers.set_watch_provider(provider);
        handlers.set_provision_tier(provision_tier);
    }
    #[cfg(not(feature = "handlers"))]
    let _ = (watch_provider, provision_tier);

    // Materialize the reserved `default` project so `project ls` / `project show
    // default` reflect it on a fresh install, not only after a migration. Best
    // effort: the reader backstop keeps listings correct even if this write can't
    // land, so a transient failure must never block serving.
    match deploy.ensure_default_project().await {
        Ok(true) => tracing::info!("materialized the reserved `default` project record"),
        Ok(false) => {}
        Err(e) => tracing::warn!(
            error = %e,
            "could not materialize the `default` project record; readers use the synthesized default"
        ),
    }
    // Wire the function-to-function invoke resolver now the deploy store exists,
    // so a function granted `invoke` can call a sibling in-process (FI).
    #[cfg(feature = "handlers")]
    handlers.set_invoker(deploy.clone());

    // Compute reconcile loop. Single-node is always the "leader". Backends are
    // built from the `[compute]` config + capability detection; a no-op when none
    // are registered. Detached for the server's life.
    let (compute_backends, compute_node) = crate::compute::build_compute(
        config.compute.as_ref(),
        compute_storage,
        data_dir,
        node_id,
        !allow_shared_kernel,
        options.daemon_runtime.clone(),
    )
    .await;
    // Activate the compute sql-shim (PLAN-compute-bindings): bind its listener +
    // build the resolver when a sql provider and `compute.sql_shim_url` are both present.
    #[cfg(feature = "handlers")]
    let sql_resolver = boatramp_server::sql_shim::spawn_sql_shim(
        handlers.sql_backends(),
        config.compute.as_ref().and_then(|c| c.sql_shim_url.clone()),
    )
    .await;
    #[cfg(not(feature = "handlers"))]
    let sql_resolver: Option<Arc<dyn boatramp_core::compute::ComputeBindingResolver>> = None;

    // Managed compute-backed SQL (PLAN-managed-compute-sql P2-b): if the handler
    // `sql` config declares any managed database, inject its `POSTGRES_*`/`MYSQL_*`
    // server-init env into the DB workload at launch from the sealed credential.
    // Reaching here with a managed DB implies an envelope (build_handler_runtime
    // fails closed otherwise), so the credential store always has one to seal with.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let managed_db_resolver: Option<Arc<dyn boatramp_core::compute::ManagedDbEnvResolver>> = match (
        config
            .handlers
            .as_ref()
            .and_then(|h| h.bindings.sql.as_ref()),
        secrets_envelope,
    ) {
        (Some(sql), Some(envelope)) if !sql.databases.is_empty() => {
            let creds = crate::managed_sql::ManagedSqlCredentials::new(kv.clone(), envelope);
            let env = crate::managed_sql::ManagedDbEnv::from_config(&sql.databases, creds);
            (!env.is_empty()).then(|| Arc::new(env) as Arc<_>)
        }
        _ => None,
    };
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    let managed_db_resolver: Option<Arc<dyn boatramp_core::compute::ManagedDbEnvResolver>> = None;

    let compute_reconcile = boatramp_server::spawn_compute_reconcile(
        deploy.clone(),
        compute_backends,
        vec![compute_node],
        boatramp_core::compute::BackendPolicy::from_shared_kernel_allowed(allow_shared_kernel),
        is_leader.clone(),
        compute_reconcile_tick(),
        COMPUTE_IDLE_TIMEOUT,
        sql_resolver,
        managed_db_resolver,
    );

    // Domain-verify auto-complete: periodically re-check every site's pending
    // ownership challenges and attach any that now pass — a published token (e.g.
    // via `domain add --provider`) converges without a manual `domain verify`.
    let dv_reconcile = boatramp_server::spawn_domain_verify_reconcile(
        deploy.clone(),
        domain_verify_allow_private,
        is_leader,
        DOMAIN_VERIFY_RECONCILE_TICK,
    );

    Ok(RunningNode {
        deploy,
        handlers,
        auth,
        options,
        reconcile: vec![compute_reconcile, dv_reconcile],
    })
}

/// Build the `[secrets]` envelope (secrets-at-rest wrapping) from `boatramp.cfg`'s
/// `[secrets]` section: `local` (a machine-local AES-256-GCM KEK) or `vault` (Vault
/// Transit). `None`/empty ⇒ no wrapping. The Vault token is read from the
/// environment (`token_env`), never a file. This seals a managed SQL credential at
/// rest; a managed database fails closed without it.
fn build_secrets_envelope(
    secrets: Option<&crate::config::SecretsConfig>,
    data_dir: &Path,
) -> Result<Option<Arc<dyn boatramp_core::envelope::KeyEnvelope>>> {
    use boatramp_server::envelope::{build_envelope, EnvelopeSpec};
    let Some(cfg) = secrets else {
        return Ok(None);
    };
    let spec = match cfg.envelope.as_str() {
        "" => EnvelopeSpec::None,
        "local" => EnvelopeSpec::Local {
            kek_file: cfg
                .kek_file
                .clone()
                .unwrap_or_else(|| data_dir.join("secrets/kek")),
        },
        "vault" => {
            let v = cfg.vault.as_ref().ok_or_else(|| {
                Error::Envelope(
                    "secrets.envelope = \"vault\" needs a [secrets.vault] section".into(),
                )
            })?;
            let token = std::env::var(&v.token_env).map_err(|_| {
                Error::Envelope(format!("Vault token env `{}` is not set", v.token_env))
            })?;
            EnvelopeSpec::Vault {
                addr: v.addr.clone(),
                key: v.key.clone(),
                token,
            }
        }
        other => {
            return Err(Error::Envelope(format!(
                "unknown secrets.envelope {other:?} (want \"local\" or \"vault\")"
            )))
        }
    };
    build_envelope(spec).map_err(|e| Error::Envelope(e.to_string()))
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::security::SecurityProfile;

    /// The headline in-process fidelity check (PLAN-node-library N2b.3): `assemble`
    /// over a temp `FsStorage` + `MemoryKv` produces a `RunningNode` whose deploy
    /// store is live (the reserved `default` project was materialized during
    /// assembly) and whose router — the exact one `boatramp serve` builds — answers
    /// `/healthz`. No listener is bound: the request is driven through the router
    /// via `tower::oneshot`, so the whole assembly runs in-process.
    #[tokio::test]
    async fn assemble_produces_a_serving_node_over_a_temp_store() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let tmp = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(boatramp_storage::FsStorage::new(tmp.path()));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let config = ServerConfig::default();
        let options = boatramp_server::ServerOptions {
            // The strict `multi-tenant` posture, as an unconfigured `serve` resolves.
            posture: SecurityProfile::MultiTenant.preset(),
            ..Default::default()
        };

        let node = assemble(NodeInput {
            config: &config,
            data_dir: tmp.path(),
            storage,
            kv,
            auth: boatramp_server::Auth::disabled(),
            options,
            watch_provider: None,
            provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
            messaging: None,
            is_leader: Arc::new(|| true),
            node_id: 0,
        })
        .await
        .expect("assemble a node over a temp store");

        // The deploy store is live: `assemble` already materialized the reserved
        // `default` project, so a second ensure reports "already present" (`false`).
        assert!(
            !node
                .deploy
                .ensure_default_project()
                .await
                .expect("read the default project"),
            "assemble should have materialized the default project"
        );

        // The assembled router (the same wiring `serve` binds) answers /healthz.
        let router =
            boatramp_server::router_with(node.deploy, node.auth, node.handlers, node.options);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("route /healthz");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
