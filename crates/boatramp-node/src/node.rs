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
use crate::error::Result;

/// How often the compute reconcile loop converges desired vs actual workloads.
pub const COMPUTE_RECONCILE_TICK: std::time::Duration = std::time::Duration::from_secs(30);
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
    } = input;
    // Copy out the posture scalars up front so `options` can be moved into the
    // returned `RunningNode` without a lingering borrow.
    let max_handler_blob_bytes = options.posture.max_handler_blob_bytes;
    let max_component_bytes = options.posture.max_component_bytes;
    let allow_shared_kernel = options.posture.allow_shared_kernel_compute;
    let domain_verify_allow_private = options.posture.domain_verify_allow_private;

    // The handler runtime reuses the same blob/KV backends (per-site prefixed)
    // for its wasi:blobstore/keyvalue bindings; the sql binding is selected by
    // `[handlers.bindings.sql]` (default: per-site libsql files under <data-dir>).
    let handlers = crate::handlers::build_handler_runtime(
        kv.clone(),
        storage.clone(),
        data_dir,
        config.handlers.as_ref(),
        None,
        max_handler_blob_bytes,
        max_component_bytes,
    )?;
    // FA-5b2: on a cloud backend, wire the blob-change notification provisioner +
    // its tier so adding a `blob` trigger provisions (and removing it retracts).
    #[cfg(feature = "handlers")]
    if let Some(provider) = watch_provider {
        handlers.set_watch_provider(provider);
        handlers.set_provision_tier(provision_tier);
    }
    #[cfg(not(feature = "handlers"))]
    let _ = (watch_provider, provision_tier);

    let compute_storage = storage.clone();
    let deploy = DeployStore::new(storage, kv);
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
        0,
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
    let compute_reconcile = boatramp_server::spawn_compute_reconcile(
        deploy.clone(),
        compute_backends,
        vec![compute_node],
        boatramp_core::compute::BackendPolicy::from_shared_kernel_allowed(allow_shared_kernel),
        Arc::new(|| true),
        COMPUTE_RECONCILE_TICK,
        COMPUTE_IDLE_TIMEOUT,
        sql_resolver,
    );

    // Domain-verify auto-complete: periodically re-check every site's pending
    // ownership challenges and attach any that now pass — a published token (e.g.
    // via `domain add --provider`) converges without a manual `domain verify`.
    let dv_reconcile = boatramp_server::spawn_domain_verify_reconcile(
        deploy.clone(),
        domain_verify_allow_private,
        Arc::new(|| true),
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
