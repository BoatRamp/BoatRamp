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
    /// The public HTTP serve bind address, if known — used (under
    /// `allow_guest_self_egress`) to let a handler guest's `wasi:http` reach this
    /// instance's own front door over loopback. `None` (an in-process embedder with no
    /// listener) disables self-egress.
    pub serve_addr: Option<std::net::SocketAddr>,
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
    /// The binary the re-exec'd compute workers run as — the container backend's
    /// `__sandbox` jailer and the microVM backends' `__vmm-run`/`__vz-run` VM hosts.
    /// `None` uses this process's own executable (`current_exe`), which is what
    /// `boatramp serve` wants (the child *is* boatramp). An **embedding harness**
    /// whose own binary doesn't implement those subcommands should point this at a
    /// built `boatramp` binary, so it can drive the real container/microVM backends
    /// in-process (only the per-workload worker re-execs; the serving plane stays
    /// embedded). The docker backend needs neither — it talks to a daemon.
    pub worker_exe: Option<std::path::PathBuf>,
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

/// The instance's own serve socket(s) a guest self-call may reach, given the bind `addr` and
/// whether the posture (`allow_guest_self_egress`) permits it. A wildcard bind
/// (`0.0.0.0`/`::`) is reachable over loopback, so it normalizes to `127.0.0.1` **and** `::1`
/// on the serve port; a specific bind is reachable at itself. Empty when disabled or no
/// listener.
fn self_egress_addrs(
    addr: Option<std::net::SocketAddr>,
    enabled: bool,
) -> Vec<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let Some(addr) = addr.filter(|_| enabled) else {
        return Vec::new();
    };
    if addr.ip().is_unspecified() {
        let port = addr.port();
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ]
    } else {
        vec![addr]
    }
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
        serve_addr,
        watch_provider,
        provision_tier,
        messaging,
        is_leader,
        node_id,
        worker_exe,
    } = input;
    // Copy out the posture scalars up front so `options` can be moved into the
    // returned `RunningNode` without a lingering borrow.
    let max_handler_blob_bytes = options.posture.max_handler_blob_bytes;
    let max_component_bytes = options.posture.max_component_bytes;
    let allow_guest_private_egress = options.posture.allow_guest_private_egress;
    let allow_env_secret_refs = options.posture.allow_env_secret_refs;
    // The instance's own serve socket(s) a guest self-call may reach, when the posture allows
    // it: a wildcard bind (`0.0.0.0`/`::`) is reachable on loopback, so normalize to
    // `127.0.0.1`/`::1`; a specific bind is itself.
    let self_egress_addrs = self_egress_addrs(serve_addr, options.posture.allow_guest_self_egress);
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
    // The project-scoped internal secret store, built from the same KV + `[secrets]`
    // envelope that seal managed-DB credentials. Backs both the `boatramp:<name>`
    // resolver (wired into the handler runtime below, when that feature is present)
    // and the admin secrets API (threaded into `ServerOptions` unconditionally, so it
    // works on a lean node too). `None` when no envelope is configured — the admin
    // endpoints then fail closed with a clear 501, never a panic.
    let secret_store = secrets_envelope.clone().map(|envelope| {
        Arc::new(boatramp_core::secret_store::SecretStore::new(
            kv.clone(),
            envelope,
        ))
    });

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
        allow_guest_private_egress,
        self_egress_addrs,
        allow_env_secret_refs,
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
        worker_exe.as_deref(),
    )
    .await;
    // Adopt the IPs of already-running replicas into each backend's fresh-on-boot
    // IP pool BEFORE the reconcile loop starts allocating. A backend with a per-node
    // pool (the native container backend) rebuilds it empty each process start; without
    // this the boot reconcile could re-hand a live address to a different workload —
    // the container-IP collision — or move a replica's endpoint on relaunch. Feeds
    // every persisted replica's `(workload, replica, endpoint-ip)`; each backend keeps
    // only the IPs in its own subnet (a cheap no-op for docker/cloudflare/VMM).
    crate::compute::adopt_running_replica_ips(&deploy, &compute_backends).await;
    // Per-project internal DNS (service discovery): start the resolver on the bridge
    // gateway so a guest resolves peers by name within its project. On by default;
    // starts only when the container backend + bridge are up (Linux). Detached for
    // the node's serving life (pushed into `reconcile` below). Started before the
    // reconcile loop consumes `compute_backends` — it borrows the registry to check
    // the container backend is present.
    let internal_dns =
        crate::compute::spawn_internal_dns(config.compute.as_ref(), &compute_backends, &deploy);
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
    // Keep a clone of the secrets envelope for the operator-SQL capability below
    // (the managed_db_resolver match moves the original).
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let operator_envelope = secrets_envelope.clone();
    // …and a second clone for the tenant-deprovision capability (drops a deleted
    // tenant's managed DB/role/credential on project/site delete). It needs a real
    // envelope to seal/unseal + delete per-tenant credentials, so it is wired only
    // when one is present (same fail-closed gating as the managed-DB paths).
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let deprovision_envelope = secrets_envelope.clone();
    // …and a third clone for the soft-delete tombstone reaper (the leader-gated task
    // that hard-drops a Shared-Postgres tenant once its grace window elapses). It, too,
    // needs a real envelope to unseal the superuser credential + delete the per-tenant
    // one on hard-drop.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let reaper_envelope = secrets_envelope.clone();
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
            let privilege = config
                .compute
                .as_ref()
                .map(|c| c.managed_db_privilege)
                .unwrap_or_default();
            let env =
                crate::managed_sql::ManagedDbEnv::from_config(&sql.databases, creds, privilege);
            (!env.is_empty()).then(|| Arc::new(env) as Arc<_>)
        }
        _ => None,
    };
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    let managed_db_resolver: Option<Arc<dyn boatramp_core::compute::ManagedDbEnvResolver>> = None;

    // Turnkey managed DB: auto-register the compute workload(s) backing each managed
    // co-located database that has none yet, so declaring the `databases` binding is
    // enough to boot the DB (no separate `compute set` / apply). Tenant-aware — a
    // `Shared` binding registers its one shared server; a `Single` binding registers
    // nothing at boot (its per-tenant `<compute>-<ident>` is created durably by the lazy
    // resolve on first `sql` use and relaunched by the reconcile, so a project that never
    // uses `sql` — e.g. a static-only site — never gets a spurious DB). Non-clobbering +
    // idempotent; runs before the reconcile loop so its first tick can launch what it
    // registered.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    if let Some(sql) = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref())
        .filter(|sql| !sql.databases.is_empty())
    {
        crate::managed_sql::auto_register_managed_db_workloads(&deploy, &sql.databases).await;
    }

    // Operator SQL capability (managed-DB migrations/queries via the sealed
    // credential, resolved server-side) — backs `POST /api/sql/{db}/{exec,query}`.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let operator_sql: Option<Arc<dyn boatramp_core::sql::OperatorSql>> = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref())
        .filter(|sql| !sql.databases.is_empty())
        .map(|sql| {
            Arc::new(crate::managed_sql::NodeOperatorSql::new(
                sql.databases.clone(),
                kv.clone(),
                operator_envelope,
                deploy.clone(),
            )) as Arc<_>
        });
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    let operator_sql: Option<Arc<dyn boatramp_core::sql::OperatorSql>> = None;

    // Tenant-deprovision capability (drop a deleted tenant's managed DB/role/sealed
    // credential on project/site delete). Wired only when a compute-backed managed
    // database + a secrets envelope are both present — same gating as operator_sql,
    // plus the envelope requirement (it must seal/unseal per-tenant credentials).
    // The soft-delete grace window for a Shared-Postgres managed tenant
    // (`handlers.bindings.sql.deprovision_grace_secs`, env-settable). Default 7 days;
    // `0` disables the soft path (immediate hard drop). Threaded to the deprovisioner
    // (which soft-deletes) and implicitly honored by the reaper (which only ever finds
    // tombstones a >0 grace produced).
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let deprovision_grace_secs = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref())
        .and_then(|sql| sql.deprovision_grace_secs)
        .unwrap_or(crate::tenant_sql::DEFAULT_DEPROVISION_GRACE_SECS);
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let tenant_deprovisioner: Option<Arc<dyn boatramp_core::sql::TenantDeprovisioner>> = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref())
        .filter(|sql| !sql.databases.is_empty())
        .zip(deprovision_envelope)
        .map(|(sql, envelope)| {
            Arc::new(crate::tenant_sql::NodeTenantDeprovisioner::new(
                deploy.clone(),
                kv.clone(),
                envelope,
                sql.databases.clone(),
                deprovision_grace_secs,
            )) as Arc<_>
        });
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    let tenant_deprovisioner: Option<Arc<dyn boatramp_core::sql::TenantDeprovisioner>> = None;

    // Operator compute-exec capability (run a command inside a running workload) —
    // backs `POST /api/compute/{name}/exec`, gated by the `allow_compute_exec`
    // posture. Clone the backend registry before the reconcile loop consumes it.
    let compute_exec: Option<Arc<dyn boatramp_core::compute::ComputeExec>> = Some(Arc::new(
        crate::compute::NodeComputeExec::new(compute_backends.clone(), deploy.clone()),
    ) as Arc<_>);

    // Operator volume-reclamation capability (list + remove persistent volumes) —
    // backs `GET /api/compute/volumes` + `DELETE /api/compute/volumes/{name}`.
    // Same admin-scoped `/api/compute/*` gate; clone the registry before the
    // reconcile loop consumes the original below.
    let compute_volumes: Option<Arc<dyn boatramp_core::compute::ComputeVolumes>> = Some(Arc::new(
        crate::compute::NodeComputeVolumes::new(compute_backends.clone(), deploy.clone()),
    )
        as Arc<_>);

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

    // Tenant tombstone reaper: leader-gated hard-drop of soft-deleted Shared-Postgres
    // tenants past their grace window (safe deprovision — see `tenant_sql`). Wired only
    // when a compute-backed managed database + a secrets envelope are both present
    // (same gating as the deprovisioner); each tombstone carries its own server +
    // superuser, so the reaper needs no per-binding config. A `0` grace never writes a
    // tombstone, so the sweep is simply inert then.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    let tombstone_reaper: Option<tokio::task::JoinHandle<()>> = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref())
        .filter(|sql| !sql.databases.is_empty())
        .zip(reaper_envelope)
        .map(|(_sql, envelope)| {
            crate::tenant_sql::spawn_tenant_tombstone_reaper(
                deploy.clone(),
                kv.clone(),
                envelope,
                is_leader.clone(),
                crate::tenant_sql::TOMBSTONE_REAPER_TICK,
            )
        });
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    let tombstone_reaper: Option<tokio::task::JoinHandle<()>> = None;

    // Domain-verify auto-complete: periodically re-check every site's pending
    // ownership challenges and attach any that now pass — a published token (e.g.
    // via `domain add --provider`) converges without a manual `domain verify`.
    let dv_reconcile = boatramp_server::spawn_domain_verify_reconcile(
        deploy.clone(),
        domain_verify_allow_private,
        is_leader,
        DOMAIN_VERIFY_RECONCILE_TICK,
    );

    // Wire the operator capabilities onto the options the router is built from.
    let mut options = options;
    options.operator_sql = operator_sql;
    options.tenant_deprovisioner = tenant_deprovisioner;
    options.compute_exec = compute_exec;
    options.compute_volumes = compute_volumes;
    // The internal secret store backs the admin secrets API (set/list/delete). Not
    // handlers-gated — it must be reachable even on a lean node.
    options.secret_store = secret_store;

    // The detached reconcile loops: the always-present compute + domain-verify ones,
    // plus the optional tenant-tombstone reaper (only when a managed DB is configured).
    let mut reconcile = vec![compute_reconcile, dv_reconcile];
    if let Some(reaper) = tombstone_reaper {
        reconcile.push(reaper);
    }
    if let Some(dns) = internal_dns {
        reconcile.push(dns);
    }

    Ok(RunningNode {
        deploy,
        handlers,
        auth,
        options,
        reconcile,
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
            serve_addr: None,
            watch_provider: None,
            provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
            messaging: None,
            is_leader: Arc::new(|| true),
            node_id: 0,
            worker_exe: None,
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
