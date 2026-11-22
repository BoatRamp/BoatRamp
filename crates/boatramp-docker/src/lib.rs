//! The remote-Docker [`ComputeBackend`].
//!
//! Delegated: boatramp targets an **existing** Docker daemon via the Engine API
//! ([`bollard`]) — it does not install or manage Docker. `materialize` pulls the
//! image, `launch` creates + starts a container (entrypoint, env, cpu/mem limits,
//! restart policy) and discovers its IP\:port, `stop` stops + removes it, and
//! `health` inspects its running state. The daemon endpoint + TLS/SSH creds come
//! from the environment (`DOCKER_HOST`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`),
//! never from the spec — per the secrets rule.
//!
//! Cross-platform (it's an API client). The actual daemon round-trip is the
//! live/integration seam (a self-skipping test against a local dockerd, like the
//! S3/MinIO pattern); the orchestration here is what's compiled + linted.

use async_trait::async_trait;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeBinding, ComputeSpec, Endpoint,
    ExecOutput, Health, Instance, InstanceHandle, IsolationClass, LaunchRequest, PullPolicy,
    RestartPolicy, RootSource, RootSourceKind, Scheme, SourceSupport, VolumeInfo, VolumeRef,
    compute_instance_id, managed_db_alias,
};
use boatramp_core::registry_auth::RegistryAuth;
use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::container::{
    AttachContainerOptions, Config, CreateContainerOptions, KillContainerOptions, LogOutput,
    NetworkingConfig, RemoveContainerOptions, StopContainerOptions, WaitContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;
use bollard::models::{
    ContainerState, ContainerStateStatusEnum, EndpointSettings, HealthStatusEnum, HostConfig,
    Mount, MountTypeEnum, Network, PortBinding, RestartPolicy as DockerRestartPolicy,
    RestartPolicyNameEnum,
};
use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions, InspectNetworkOptions};
use bollard::volume::{ListVolumesOptions, RemoveVolumeOptions};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// How the remote-Docker backend reports a launched workload's reachable endpoint.
///
/// The default `Published` publishes the container port on the host loopback
/// (`127.0.0.1:<ephemeral>`) and routes to that, so it works whenever `boatramp
/// serve` runs on the host — including Docker Desktop / macOS, where the daemon runs
/// in a VM and the container bridge IP is **not** host-routable. Binding to loopback
/// (not `0.0.0.0`) keeps the workload port off the network, matching the hardened
/// posture.
///
/// `Bridge` routes to the container's bridge IP directly (the pre-0.2.1 behavior). It
/// is only reachable when `serve` shares the daemon's network — e.g. `serve` itself
/// runs in a container on the same Docker bridge (docker-out-of-docker) — but avoids
/// publishing a host port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerEndpoint {
    /// Publish the container port on `127.0.0.1:<ephemeral>` and route there (default).
    #[default]
    Published,
    /// Route to the container's bridge IP directly (serve must share the network).
    Bridge,
}

/// How the remote-Docker backend backs a workload's persistent [`VolumeRef`]s.
///
/// `Named` (the default) attaches a daemon-managed `docker volume` by name — it
/// works with a **remote** daemon and Docker Desktop / macOS (where a client host
/// path isn't the daemon's filesystem). `Bind` bind-mounts a host directory under
/// `<data_dir>/compute/volumes/<name>` (matching the native-container convention),
/// so it is **local-daemon only** but keeps the data on the node's own filesystem.
/// Either way the volume is node-local and outside the blob-snapshot durability
/// story (consistent with the docker backend's `scale_to_zero: false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerVolumeMode {
    /// A daemon-managed named volume (`docker volume`), portable across daemons.
    #[default]
    Named,
    /// A host bind mount under `<data_dir>/compute/volumes/<name>` (local daemon only).
    Bind,
}

/// The docker named-volume for boatramp volume `name` — prefixed so it never
/// clobbers an unrelated volume on a shared daemon.
fn docker_volume_name(name: &str) -> String {
    format!("boatramp-{name}")
}

/// The host backing directory for a `Bind`-mode volume `name`
/// (`<data_dir>/compute/volumes/<name>`), matching the native-container layout.
fn volume_dir(data_dir: &Path, name: &str) -> PathBuf {
    data_dir.join("compute").join("volumes").join(name)
}

/// Parse a `ComputeSpec.user` (`"uid"` or `"uid:gid"`, numeric) into `(uid, gid)`,
/// defaulting `gid` to `uid`. Returns `None` for a non-numeric value (the caller then
/// leaves ownership untouched — the endpoint still passes the raw string to Docker,
/// which resolves an image username itself).
fn parse_uid_gid(user: &str) -> Option<(u32, u32)> {
    match user.split_once(':') {
        Some((u, g)) => Some((u.parse().ok()?, g.parse().ok()?)),
        None => {
            let uid = user.parse().ok()?;
            Some((uid, uid))
        }
    }
}

/// `chown` a bind-volume host directory so a rootless image can own its data
/// (e.g. Postgres' `PGDATA`). Non-recursive: only the mount root, so an already
/// initialized volume's nested ownership is left alone. A no-op off unix.
#[cfg(unix)]
fn chown_dir(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}
#[cfg(not(unix))]
fn chown_dir(_path: &Path, _uid: u32, _gid: u32) -> std::io::Result<()> {
    Ok(())
}

/// The reserved prefix the native `container` backend gives a per-(project, workload)
/// SCOPED volume directory (`<data_dir>/compute/volumes/@<scope>/…`). Docker's own
/// volumes are FLAT, so this backend must never create or remove an `@`-prefixed entry —
/// otherwise, on a node whose `data_dir` is SHARED with a native-container backend
/// (Bind mode), a docker `remove_volume("@<victimscope>")` would `remove_dir_all` another
/// backend's scoped PGDATA. Mirrors the native backend's `SCOPE_DIR_PREFIX` guard.
const SCOPE_DIR_PREFIX: &str = "@";

/// Reject a volume whose `name` or `mount` could escape its sandboxed location
/// (mirrors the native-container guard): `name` backs a docker volume / a
/// `<data_dir>/compute/volumes/<name>` bind, so it must be a single normal path
/// component and must NOT claim the reserved `@`-scope prefix; `mount` is the
/// in-container target, so it must be absolute with no `..`/`.`.
fn validate_volume(name: &str, mount: &str) -> Result<(), BackendError> {
    use std::path::Component;
    let name_ok = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    );
    if !name_ok {
        return Err(BackendError::Launch(format!(
            "invalid volume name {name:?}: must be a single path component"
        )));
    }
    // DiD (Finding 4): never let a docker operation address a native-container scoped
    // volume dir (`@<scope>`) when the two backends share a `data_dir`.
    if name.starts_with(SCOPE_DIR_PREFIX) {
        return Err(BackendError::Launch(format!(
            "invalid volume name {name:?}: the {SCOPE_DIR_PREFIX:?} prefix is reserved for \
             per-(project, workload) volume scopes (owned by the native container backend)"
        )));
    }
    let m = Path::new(mount);
    let mount_ok = m.is_absolute()
        && m.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !mount_ok {
        return Err(BackendError::Launch(format!(
            "invalid volume mount {mount:?}: must be an absolute path with no `..`"
        )));
    }
    Ok(())
}

/// Build the bollard [`Mount`] for one volume in the selected mode (a writable
/// mount). Pure: `Bind` mode's host directory is created separately by
/// [`DockerBackend::stage_volumes`] before the container is created.
fn volume_mount(vol: &VolumeRef, mode: DockerVolumeMode, data_dir: &Path) -> Mount {
    let (typ, source) = match mode {
        DockerVolumeMode::Named => (MountTypeEnum::VOLUME, docker_volume_name(&vol.name)),
        DockerVolumeMode::Bind => (
            MountTypeEnum::BIND,
            volume_dir(data_dir, &vol.name).display().to_string(),
        ),
    };
    Mount {
        target: Some(vol.mount.clone()),
        source: Some(source),
        typ: Some(typ),
        read_only: Some(false),
        ..Default::default()
    }
}

/// The remote-Docker compute backend: a connected Engine API client.
pub struct DockerBackend {
    docker: Docker,
    endpoint: DockerEndpoint,
    /// How persistent volumes are backed (named daemon volume vs host bind).
    volume_mode: DockerVolumeMode,
    /// Node data directory, for `Bind`-mode volume host paths.
    data_dir: PathBuf,
    /// Whether a spec's `writable_root` is honored here. Set from the isolation
    /// posture (single-tenant only); off under the multi-tenant guard, so a
    /// writable-root spec is forced back to the hardened read-only root.
    writable_root_allowed: bool,
    /// Whether a spec's `cap_add` is honored here. Set from the isolation posture
    /// (single-tenant only); off under the multi-tenant guard, so a cap-add spec is
    /// forced back to the dropped-`ALL` default.
    cap_add_allowed: bool,
    /// Whether a spec's `pull_policy` of `IfNotPresent`/`Never` (local-image **reuse**) is
    /// honored here. Set from the isolation posture (single-tenant only); off under the
    /// multi-tenant guard, where it is **refused** (never silently re-pulled). Local reuse
    /// on the daemon's **shared** image store is a cross-tenant relaxation: reusing an image
    /// a co-tenant cached under the same `name:tag`/digest would run that image with NO
    /// per-tenant registry-auth check (bypassing this workload's `--pull-secret` fail-closed
    /// — the classic k8s `IfNotPresent` cross-tenant leak, which digest-pinning does not
    /// close) and exposes mutable-tag poisoning. So it rides the single-tenant posture
    /// exactly like [`writable_root_allowed`] / [`cap_add_allowed`].
    local_image_reuse_allowed: bool,
    /// Wall-clock backstop for a single [`run_ephemeral`](ComputeBackend::run_ephemeral)
    /// invocation (export/import client run). Generous by default
    /// ([`EPHEMERAL_RUN_TIMEOUT`]); the operator raises it for a very large migration so
    /// the backstop never kills legitimate work (the real unreachable-DSN hang is bounded
    /// far tighter by the client's own connect timeout).
    ephemeral_timeout: std::time::Duration,
    /// The node-global **guest-log secret redaction default** — tier 1 of the two-tier
    /// opt-out (v0.70.0). Whether the guest-log forwarder **redacts secret-sourced env
    /// values** out of the forwarded stream (the per-container log file + the
    /// `boatramp::guest` tracing target). On by default; a node operator opts OUT via the
    /// node-global `[compute].redact_guest_log_secrets = false` (System·Admin config — never a
    /// tenant knob), wired by [`Self::with_guest_log_redaction`]. When off, NOTHING on this
    /// node is redacted and no per-project setting can re-enable it. The redaction SET is
    /// per-launch (carried in [`LaunchRequest::redaction`]); this flag is the node default in
    /// [`boatramp_guestlog::should_redact`].
    redact_guest_log_secrets: bool,
    /// The node-global **admission gate** for a per-project redaction opt-out — tier 2 of the
    /// two-tier opt-out (v0.70.0). Default `false`: a stored per-project opt-out
    /// ([`LaunchRequest::redaction`]`.project_opt_out()`) is IGNORED unless this is on, so an
    /// operator cannot opt a project out of redaction unless the node globally permits
    /// per-project overrides first. Wired from `[compute].allow_per_project_redaction_override`
    /// (System·Admin config) by [`Self::with_per_project_redaction_override`]. Composed with
    /// the node default + the per-project preference in [`boatramp_guestlog::should_redact`].
    allow_per_project_redaction_override: bool,
}

impl DockerBackend {
    /// Connect to the Docker daemon configured by the environment
    /// (`DOCKER_HOST` + TLS/SSH vars, or the platform default socket).
    pub fn connect() -> Result<Self, BackendError> {
        let docker = Docker::connect_with_defaults()
            .map_err(|e| BackendError::Other(format!("connect to docker: {e}")))?;
        Ok(Self {
            docker,
            endpoint: DockerEndpoint::default(),
            volume_mode: DockerVolumeMode::default(),
            data_dir: PathBuf::from("."),
            writable_root_allowed: false,
            cap_add_allowed: false,
            local_image_reuse_allowed: false,
            ephemeral_timeout: EPHEMERAL_RUN_TIMEOUT,
            redact_guest_log_secrets: true,
            allow_per_project_redaction_override: false,
        })
    }

    /// Wrap an already-connected client (for tests / custom transports).
    pub fn with_client(docker: Docker) -> Self {
        Self {
            docker,
            endpoint: DockerEndpoint::default(),
            volume_mode: DockerVolumeMode::default(),
            data_dir: PathBuf::from("."),
            writable_root_allowed: false,
            cap_add_allowed: false,
            local_image_reuse_allowed: false,
            ephemeral_timeout: EPHEMERAL_RUN_TIMEOUT,
            redact_guest_log_secrets: true,
            allow_per_project_redaction_override: false,
        }
    }

    /// Set the wall-clock backstop for a single `run_ephemeral` invocation (0 ⇒ keep the
    /// generous default). Wired from `[compute] docker_ephemeral_timeout_secs`.
    pub fn with_ephemeral_timeout(mut self, timeout: std::time::Duration) -> Self {
        if !timeout.is_zero() {
            self.ephemeral_timeout = timeout;
        }
        self
    }

    /// Select how a launched workload's endpoint is reported (see [`DockerEndpoint`]).
    pub fn with_endpoint(mut self, endpoint: DockerEndpoint) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Enable/disable **guest-log secret redaction** (tier-1 node default; default enabled).
    /// The node wires this from the node-global `[compute].redact_guest_log_secrets`
    /// (System·Admin config); `false` forwards guest logs unredacted. See
    /// [`redact_guest_log_secrets`](Self::redact_guest_log_secrets).
    #[must_use]
    pub fn with_guest_log_redaction(mut self, enabled: bool) -> Self {
        self.redact_guest_log_secrets = enabled;
        self
    }

    /// Admit (or not) a **per-project redaction opt-out** (tier-2 node admission gate; default
    /// NOT admitted). The node wires this from the node-global
    /// `[compute].allow_per_project_redaction_override` (System·Admin config). When `false`, a
    /// project's stored opt-out is ignored and redaction follows the node default; when
    /// `true`, a project that opted out has its guest logs forwarded unredacted. See
    /// [`allow_per_project_redaction_override`](Self::allow_per_project_redaction_override).
    #[must_use]
    pub fn with_per_project_redaction_override(mut self, admit: bool) -> Self {
        self.allow_per_project_redaction_override = admit;
        self
    }

    /// Allow a spec's `writable_root` to relax the read-only root here (single-tenant
    /// posture). Off by default, so the multi-tenant guard keeps the hardened root.
    pub fn with_writable_root_allowed(mut self, allowed: bool) -> Self {
        self.writable_root_allowed = allowed;
        self
    }

    /// Allow a spec's `cap_add` to add capabilities back on top of the dropped-`ALL`
    /// default here (single-tenant posture). Off by default, so the multi-tenant guard
    /// keeps every capability dropped.
    pub fn with_cap_add_allowed(mut self, allowed: bool) -> Self {
        self.cap_add_allowed = allowed;
        self
    }

    /// Allow a spec's `pull_policy` of `IfNotPresent`/`Never` (local-image reuse) to be
    /// honored here (single-tenant posture). Off by default, so the multi-tenant guard
    /// REFUSES a reuse policy rather than trust the shared image store (see
    /// [`local_image_reuse_allowed`](Self::local_image_reuse_allowed)).
    pub fn with_local_image_reuse_allowed(mut self, allowed: bool) -> Self {
        self.local_image_reuse_allowed = allowed;
        self
    }

    /// Select how persistent volumes are backed (see [`DockerVolumeMode`]).
    pub fn with_volume_mode(mut self, mode: DockerVolumeMode) -> Self {
        self.volume_mode = mode;
        self
    }

    /// Set the node data directory used for `Bind`-mode volume host paths.
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = data_dir.into();
        self
    }

    /// Whether the daemon answers a `ping` — used to decide whether to register
    /// this backend (a connected client doesn't imply a reachable daemon).
    pub async fn reachable(&self) -> bool {
        self.docker.ping().await.is_ok()
    }

    /// Root for per-container guest-log files (`<data_dir>/compute/logs`), the SAME
    /// convention the native container backend uses.
    fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("compute").join("logs")
    }

    /// Spawn the background guest-log forwarder for a just-launched long-running
    /// container. Observability parity with the native backend: it attaches to the
    /// container's stdout/stderr, decodes the multiplexed Docker frame stream into
    /// lines, and feeds the SAME shared sink (`tracing` target `boatramp::guest` +
    /// `<data_dir>/compute/logs/<id>.log`). Detached — it NEVER blocks the launch
    /// path — and ends cleanly when the container exits or is removed.
    ///
    /// `docker_container_id` is the daemon's opaque id (what we attach to);
    /// `log_id` is the stable boatramp instance id used for the tracing tag + the
    /// per-container log-file name (matching the native backend's keying).
    fn spawn_log_forwarder(
        &self,
        docker_container_id: String,
        log_id: String,
        redactor: Option<std::sync::Arc<boatramp_guestlog::Redactor>>,
    ) {
        let docker = self.docker.clone();
        let logs_dir = self.logs_dir();
        tokio::spawn(forward_container_logs(
            docker,
            docker_container_id,
            log_id,
            logs_dir,
            redactor,
        ));
    }

    /// Build this launch's guest-log redactor from the request's secret-sourced redaction set
    /// under the **two-tier opt-out** (v0.70.0). The forwarder runs with no redactor (the
    /// stream forwards unredacted) when the composed [`boatramp_guestlog::should_redact`]
    /// decision is off — the node default is off, OR a per-project opt-out is both stored AND
    /// admitted by the node — or when the set is empty (no secret-sourced env). The decision
    /// combines the two node-global flags with the request's carried per-project opt-out
    /// preference, in ONE place shared with the native container backend.
    fn build_log_redactor(
        &self,
        req: &LaunchRequest,
    ) -> Option<std::sync::Arc<boatramp_guestlog::Redactor>> {
        if !boatramp_guestlog::should_redact(
            self.redact_guest_log_secrets,
            self.allow_per_project_redaction_override,
            req.redaction.project_opt_out(),
        ) || req.redaction.is_empty()
        {
            return None;
        }
        boatramp_guestlog::Redactor::build(req.redaction.values().iter().cloned())
    }

    /// Validate + stage the spec's persistent volumes into bollard [`Mount`]s: each
    /// name/mount is checked for traversal, and a `Bind`-mode volume's host
    /// directory is created (idempotent) so the daemon can bind it. A named volume
    /// is auto-created by the daemon on container create. Returns the mounts to
    /// attach (empty ⇒ no volumes).
    async fn stage_volumes(&self, spec: &ComputeSpec) -> Result<Vec<Mount>, BackendError> {
        // A rootless `user` (`uid[:gid]`) means the entrypoint runs unprivileged, so a
        // bind volume it must write (a database's data dir) needs to be owned by that
        // uid — the host owns the dir, so pre-chown it. Only meaningful for `Bind` mode.
        let chown = spec.user.as_deref().and_then(parse_uid_gid);
        let mut mounts = Vec::with_capacity(spec.volumes.len());
        for vol in &spec.volumes {
            validate_volume(&vol.name, &vol.mount)?;
            if self.volume_mode == DockerVolumeMode::Bind {
                let dir = volume_dir(&self.data_dir, &vol.name);
                tokio::fs::create_dir_all(&dir).await.map_err(|e| {
                    BackendError::Launch(format!("create volume {} dir: {e}", vol.name))
                })?;
                if let Some((uid, gid)) = chown {
                    chown_dir(&dir, uid, gid).map_err(|e| {
                        BackendError::Launch(format!(
                            "chown volume {} to {uid}:{gid}: {e}",
                            vol.name
                        ))
                    })?;
                }
            }
            mounts.push(volume_mount(vol, self.volume_mode, &self.data_dir));
        }
        Ok(mounts)
    }

    /// Create a labeled user-defined `bridge` network named `name` if it does not already exist.
    /// Idempotent: a 409 Conflict (the network already exists — from a prior/concurrent launch
    /// into the same project) is treated as success, so two workloads of one project never race
    /// each other to an error. `labels` tag it as boatramp-managed (and, for a project network,
    /// which project) so an operator can identify + reclaim it.
    async fn create_bridge_network(
        &self,
        name: &str,
        labels: HashMap<String, String>,
    ) -> Result<(), BackendError> {
        let options = CreateNetworkOptions {
            name: name.to_string(),
            driver: "bridge".to_string(),
            check_duplicate: true,
            labels,
            // Pin the Linux bridge interface name to a boatramp-SCOPED, bounded, deterministic
            // name (`project_bridge_name`) via the bridge driver-opt, instead of docker's unscoped
            // `br-<hash>`. This lets the NixOS compute-firewall admit the shim-port traffic on a
            // `boatramp-`-prefixed interface (see PROJECT_BRIDGE_PREFIX) rather than trusting the
            // broad `br-+`. The opt applies only at CREATE: an interface cannot be renamed on a
            // live network, so a network that already exists keeps whatever bridge name it was born
            // with. A network born BEFORE this driver-opt existed (a legacy unscoped `br-<hash>`)
            // is migrated by `ensure_project_network`, which detects the stale bridge and — when
            // the network is empty — removes + recreates it through THIS scoped path.
            options: HashMap::from([(BRIDGE_NAME_OPT.to_string(), project_bridge_name(name))]),
            ..Default::default()
        };
        match self.docker.create_network(options).await {
            Ok(_) => Ok(()),
            // Already exists — the idempotent, concurrency-safe success path.
            Err(e) if is_network_conflict(&e) => Ok(()),
            Err(e) => Err(BackendError::Launch(format!(
                "create project network {name}: {e}"
            ))),
        }
    }

    /// Ensure the per-project user-defined network ([`project_network_name`]) exists (create-if-
    /// absent) and return its name. Every workload of `project` joins this ONE network with a DNS
    /// alias = its workload name, so siblings resolve each other by name over docker's embedded DNS
    /// while a different project (a different network) can neither resolve nor reach them.
    ///
    /// **Legacy-bridge upgrade (the stale-`br-<hash>` migration).** A per-project network created
    /// BEFORE the scoped-bridge driver-opt existed carries docker's unscoped `br-<hash>` bridge,
    /// which the NixOS compute-firewall (scoped to the `boatramp-` prefix) never admits — so the
    /// shim traffic is dropped and `compute restart` cannot help, because the bridge name is fixed
    /// for a network's life. This method makes the migration AUTOMATIC: on launch it inspects an
    /// existing network and, if its bridge is not the scoped [`project_bridge_name`] AND the
    /// network has NO attached containers (the instant between the old container's stop+remove and
    /// the new one's attach — a plain `compute restart` of the project's last workload), it removes
    /// and recreates the network through the scoped [`create_bridge_network`](Self::create_bridge_network)
    /// path, preserving the per-project isolation labels. A network that still has a LIVE attached
    /// container is NEVER torn down (that would sever a serving endpoint): it is left as-is with a
    /// `warn!` that a workload cycle is needed to migrate it, and the same for a network whose
    /// attachment set cannot be determined (fail safe). The remaining old GC path (the best-effort
    /// `remove_network` in [`stop`](ComputeBackend::stop)) raced the reconcile relaunch and so could
    /// never win; this upgrade-on-launch does not depend on that reap landing first.
    ///
    /// Concurrency + idempotency: two workloads of one project launching together are safe. A 409
    /// on the recreate (a sibling created the scoped network first) is success. A `remove_network`
    /// that fails because a sibling just attached a container is tolerated — docker refuses to
    /// remove a network with active endpoints, which is the backstop under our emptiness check — and
    /// the subsequent `create_bridge_network` 409s, so we fall through to using the existing network
    /// either way. No live network is ever destroyed.
    async fn ensure_project_network(&self, project: &str) -> Result<String, BackendError> {
        let name = project_network_name(project);
        let labels = project_network_labels(project);
        match self
            .docker
            .inspect_network(&name, None::<InspectNetworkOptions<String>>)
            .await
        {
            // Absent — create it scoped (the create-if-absent steady state).
            Err(e) if is_not_found(&e) => {
                self.create_bridge_network(&name, labels).await?;
            }
            // Inspect failed for some other reason — surface it rather than guess at the state and
            // risk tearing down a network we could not read.
            Err(e) => {
                return Err(BackendError::Launch(format!(
                    "inspect project network {name}: {e}"
                )));
            }
            // Exists — keep it, or migrate a legacy unscoped bridge when it is safe.
            Ok(net) => {
                let expected = project_bridge_name(&name);
                match classify_project_network(&net, &expected) {
                    // Already on the scoped bridge — keep (the idempotent steady state).
                    ProjectNetworkBridge::Scoped => {}
                    // Unscoped AND empty at this instant — the safe upgrade: remove + recreate
                    // scoped. If a sibling launch attached a container between our inspect and this
                    // remove, docker REFUSES the remove (active endpoints); we ignore that and the
                    // recreate 409s as success, leaving the existing (now occupied) network in
                    // place. The scoped labels are reapplied so it stays the SAME per-project
                    // isolated network — only the bridge name changes.
                    ProjectNetworkBridge::UnscopedEmpty => {
                        let _ = self.docker.remove_network(&name).await;
                        self.create_bridge_network(&name, labels).await?;
                    }
                    // Unscoped but a LIVE container is attached — never rebuild a serving network.
                    // A workload cycle (stop every replica, then relaunch) empties it and the next
                    // launch migrates it through the UnscopedEmpty arm above.
                    ProjectNetworkBridge::UnscopedOccupied => {
                        tracing::warn!(
                            project,
                            network = %name,
                            "per-project docker network is still on a legacy unscoped bridge while \
                             a workload is attached; the NixOS compute-firewall admits only the \
                             scoped boatramp- bridge, so cycle the project's workloads (stop all, \
                             then relaunch) to migrate it"
                        );
                    }
                    // Unscoped and we could not determine the attachment set — fail SAFE: leave it
                    // untouched rather than risk removing a network that may be live.
                    ProjectNetworkBridge::UnscopedUnknown => {
                        tracing::warn!(
                            project,
                            network = %name,
                            "per-project docker network is on a legacy unscoped bridge and its \
                             attachment set could not be determined; leaving it untouched (fail \
                             safe, no teardown)"
                        );
                    }
                }
            }
        }
        Ok(name)
    }
}

/// The docker network driver-opt that pins the Linux bridge interface name. Set at network create
/// to the scoped [`project_bridge_name`] (see [`DockerBackend::create_bridge_network`]); read back
/// from a network's `Options` to tell a scoped bridge from a legacy auto-generated `br-<hash>`
/// (which docker does NOT report under this key).
const BRIDGE_NAME_OPT: &str = "com.docker.network.bridge.name";

/// The per-project isolation labels every per-project network carries (`boatramp.managed=true` +
/// `boatramp.project=<project>`), so an operator can identify + reclaim it and so the legacy-bridge
/// upgrade in [`ensure_project_network`](DockerBackend::ensure_project_network) reapplies the SAME
/// labels when it recreates a network — keeping it the SAME per-project isolated network, only the
/// bridge name changing. One source of truth shared by the create-if-absent and the recreate paths.
fn project_network_labels(project: &str) -> HashMap<String, String> {
    HashMap::from([
        ("boatramp.managed".to_string(), "true".to_string()),
        ("boatramp.project".to_string(), project.to_string()),
    ])
}

/// How an EXISTING per-project network's Linux bridge compares to the scoped [`project_bridge_name`],
/// deciding whether a launch may migrate a legacy unscoped `br-<hash>` bridge. See
/// [`DockerBackend::ensure_project_network`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectNetworkBridge {
    /// The bridge is already the scoped name — keep it (the idempotent steady state).
    Scoped,
    /// The bridge is NOT the scoped name (a legacy docker `br-<hash>` reported as an absent opt, or
    /// any other value) AND the network has NO attached containers — safe to remove + recreate
    /// scoped at this instant (the old workload is stopped+removed, the new one not yet attached).
    UnscopedEmpty,
    /// The bridge is NOT the scoped name but the network HAS ≥ 1 attached container — leave it
    /// untouched: a live network cannot be rebuilt without severing its endpoint.
    UnscopedOccupied,
    /// The bridge is NOT the scoped name and the network's attachment set could not be determined
    /// (`Containers` absent) — fail safe and leave it untouched.
    UnscopedUnknown,
}

/// Classify an existing per-project `net` against the `expected` scoped bridge name
/// ([`project_bridge_name`] of the network's own name). The bridge actually in effect is the
/// [`BRIDGE_NAME_OPT`] driver-opt docker reports in `Options`; docker does NOT report an
/// auto-generated `br-<hash>` there, so an ABSENT (or differing) opt is a legacy unscoped bridge.
/// Guards strictly on emptiness via `Containers`: a non-empty map is occupied, an EMPTY map is
/// safe to rebuild, and an ABSENT map is treated as indeterminate (never torn down). Pure (no I/O),
/// so the detect/guard decision is unit-testable without a daemon.
fn classify_project_network(net: &Network, expected: &str) -> ProjectNetworkBridge {
    let is_scoped = net
        .options
        .as_ref()
        .and_then(|o| o.get(BRIDGE_NAME_OPT))
        .is_some_and(|bridge| bridge == expected);
    if is_scoped {
        return ProjectNetworkBridge::Scoped;
    }
    match net.containers.as_ref() {
        None => ProjectNetworkBridge::UnscopedUnknown,
        Some(containers) if containers.is_empty() => ProjectNetworkBridge::UnscopedEmpty,
        Some(_) => ProjectNetworkBridge::UnscopedOccupied,
    }
}

/// Container name for a workload replica (`boatramp-<id>`), where the id is
/// project-qualified for a non-`default` project so two projects' same-named
/// workloads never collide on the docker daemon; `default` keeps the bare
/// `boatramp-<workload>-<replica>` name (byte-identical to pre-v0.3.12).
fn container_name(project: &str, workload: &str, replica: u32) -> String {
    format!(
        "boatramp-{}",
        compute_instance_id(project, workload, replica)
    )
}

/// The reserved process-env key by which the node asks the remote-Docker backend to ALSO connect a
/// one-shot [`run_ephemeral`](ComputeBackend::run_ephemeral) client container to a specific
/// per-project network, so a `pg_dump`/`pg_restore`/`psql`/`mysql` client can reach a managed DB
/// that lives on that isolated network (see [`project_network_name`]).
///
/// The backend **consumes** it: the pair is stripped from the process environment before the
/// client is started, so the internal hint never reaches the client. Its value is the exact
/// network name to join. The one-shot ALWAYS keeps the daemon's default network (NAT egress +
/// default-bridge reach); when this hint is present it is ADDITIONALLY connected to the named
/// per-project network. That dual attachment is deliberate: it lets the client reach the managed
/// DB whether the DB sits on the default bridge (an external DSN, a managed DB launched before this
/// backend grew per-project networks and not yet relaunched, or a colocated test DB) OR on its
/// isolated per-project network (the relaunched shape) — the node cannot always know which, and a
/// stale persisted endpoint must keep working across the upgrade. Absent ⇒ the one-shot runs on
/// the daemon's default network alone (the external-DSN path, reachable via the daemon's NAT
/// egress).
pub const EPHEMERAL_NETWORK_ENV: &str = "BOATRAMP_EPHEMERAL_NETWORK";

/// The deterministic, per-project user-defined docker network name for `project`.
///
/// The remote-Docker backend places every one of a project's workload containers on THIS network
/// (create-if-absent at launch) and attaches each with a network ALIAS equal to its workload name,
/// so a sibling in the same project resolves `<workload>:<port>` via docker's embedded DNS — which
/// a user-defined network has and the default bridge does **not** (the managed-DB DSN is
/// name-based). The network is **per-project**, so docker's inter-network isolation keeps one
/// project's containers from resolving or reaching another project's: that boundary is the tenancy
/// gate. The reserved `default` project (and an empty project id) share the one `default` network —
/// a single-tenant install is still its own isolated network, never a shared node-wide one.
///
/// `project` is a validated resource slug (`[A-Za-z0-9][A-Za-z0-9_-]*`, ≤ 63 bytes), a subset of
/// the docker network-name grammar (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`), so the `boatramp-net-` prefix
/// yields an always-valid name that can never clobber an unrelated network on a shared daemon.
pub fn project_network_name(project: &str) -> String {
    let p = if project.is_empty() {
        boatramp_core::project::DEFAULT_PROJECT
    } else {
        project
    };
    format!("{PROJECT_NETWORK_PREFIX}{p}")
}

/// The fixed prefix every per-project network name carries (see [`project_network_name`]). Factored
/// out so a holder of the name alone can recover the project (strip the prefix) — used by the
/// export/import one-shot to label a create-if-absent network identically to the launch path.
pub const PROJECT_NETWORK_PREFIX: &str = "boatramp-net-";

/// The fixed prefix every per-project **Linux bridge interface** name carries (see
/// [`project_bridge_name`]). Factored out as the single source of truth the NixOS module's
/// compute-firewall rule matches on (`nix/nixos-module.nix`): the firewall admits the shim-port
/// traffic on an interface whose name begins with this prefix (plus the static `br-boatramp` the
/// native-container/firecracker backends use), so a boatramp-scoped match — NOT the broad docker
/// `br-+` — can trust every per-project bridge without trusting an unrelated docker network or the
/// LAN. If this prefix ever changes, the module's matcher MUST change with it.
pub const PROJECT_BRIDGE_PREFIX: &str = "boatramp-";

/// The Linux `IFNAMSIZ` budget for an interface name: 16 bytes including the trailing NUL, so a
/// name is at most **15 bytes**. A docker driver-opt bridge name over this is silently truncated
/// (or rejected), so [`project_bridge_name`] is bounded to fit.
const MAX_IFNAME_LEN: usize = 15;

/// The deterministic, SCOPED Linux bridge interface name for the per-project network `network`
/// (the `boatramp-net-<project>` name [`project_network_name`] returns). Set as the
/// `com.docker.network.bridge.name` driver-opt at network-create (see [`DockerBackend::create_bridge_network`])
/// so the kernel bridge is e.g. `boatramp-1a2b3c` instead of docker's unscoped `br-<hash>`.
///
/// Scheme — `boatramp-<6 hex>`, exactly 15 bytes (the [`MAX_IFNAME_LEN`] ceiling):
/// - `boatramp-` (9 bytes) is the [`PROJECT_BRIDGE_PREFIX`] the firewall trusts.
/// - `<6 hex>` is the low 24 bits of a stable [FNV-1a] hash of the FULL network name. A raw project
///   name cannot be used verbatim — a slug is up to 63 bytes, far over the 15-byte `IFNAMSIZ`
///   ceiling — so it is hashed to a fixed, bounded, name-safe (`[0-9a-f]`) token.
///
/// The hash is **deterministic** (a fixed algorithm, not the std hasher — whose seed is unspecified
/// and release-unstable): the same project always derives the same bridge name, so the
/// create-if-absent launch path and the export/import one-shot converge on ONE bridge per project
/// across restarts. Docker keys the network by its NAME (unique per project), so the bridge name is
/// only a host-side label; a 24-bit space collides (birthday) near ~4.8 k concurrent projects on
/// ONE node, far past any realistic per-node project count, and a collision fails the *second*
/// network's create loudly (the Linux ifname is already in use) rather than merging two projects —
/// never a tenancy leak.
///
/// [FNV-1a]: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
pub fn project_bridge_name(network: &str) -> String {
    // 64-bit FNV-1a — a tiny, dependency-free, deterministic hash (std's `DefaultHasher` seed is
    // unspecified and may shift between releases, which would rename every bridge on upgrade).
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in network.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    // Low 24 bits → 6 lowercase-hex chars. `boatramp-` (9) + 6 = 15 = MAX_IFNAME_LEN.
    let name = format!("{PROJECT_BRIDGE_PREFIX}{:06x}", hash & 0x00ff_ffff);
    debug_assert!(name.len() <= MAX_IFNAME_LEN, "bridge name exceeds IFNAMSIZ");
    name
}

/// The container-side hostname boatramp injects into a docker workload's `/etc/hosts` (via
/// [`HOST_GATEWAY_EXTRA_HOST`]) and rewrites a bind-local shim URL's host to (see
/// [`rewrite_shim_host_for_docker`]). `host.docker.internal` is docker's conventional name for
/// "the host", and `host-gateway` resolves it — from ANY bridge, including a per-project
/// user-defined one — to the daemon's host-gateway IP (default `172.17.0.1`). That one stable name
/// reaches the host from every per-project network, so a bridged workload reaches its compute shims
/// without the operator pinning a per-bridge gateway IP into each guest.
const GUEST_HOST_ALIAS: &str = "host.docker.internal";

/// The `ExtraHosts` entry that makes [`GUEST_HOST_ALIAS`] resolve to the host from inside a
/// container on ANY docker network. `host-gateway` is docker's daemon-wide alias for the host's
/// bridge-reachable address; on Linux it is NOT added automatically, so boatramp adds it to every
/// launched workload.
const HOST_GATEWAY_EXTRA_HOST: &str = "host.docker.internal:host-gateway";

/// Rewrite a compute-shim base URL so a bridged docker container can reach it, returning the
/// rewritten URL when a rewrite applies and `None` when the URL is already guest-reachable (left
/// untouched).
///
/// A rewrite applies ONLY when the URL's host is an address a bridged container cannot route to the
/// host with: a **loopback** (`127.0.0.0/8`, `::1`, or the literal `localhost`) — which inside a
/// container is the container's OWN loopback, never the host's — or an **unspecified** bind address
/// (`0.0.0.0`, `::`) — which names no destination at all. In both cases the host portion is
/// replaced with [`GUEST_HOST_ALIAS`] (`host.docker.internal`), preserving the scheme, port, path,
/// and query verbatim; paired with [`HOST_GATEWAY_EXTRA_HOST`] the guest then reaches the host's
/// gateway IP from any per-project bridge.
///
/// A host that already names a routable destination — an explicit IP such as the host-gateway
/// `172.17.0.1`, or a DNS name such as a sibling's [`managed_db_alias`] (a managed-DB DSN reached
/// over the per-project net's embedded DNS) or an external FQDN — is returned as `None` (NOT
/// rewritten): the operator pointed it at a real address and the container can already reach it.
/// This is what keeps the rewrite from clobbering a managed-database DSN or an external endpoint.
fn rewrite_shim_host_for_docker(url: &str) -> Option<String> {
    // Split `scheme://authority/rest` without a URL crate (the remote client stays dependency-lean,
    // mirroring the server's hand-rolled `shim_bind_addr`). Require an explicit scheme so a bare
    // `host:port` (ambiguous with `scheme:path`) is left alone.
    let (scheme, after_scheme) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return None;
    }
    // The authority ends at the first `/`, `?`, or `#`; the remainder (path/query/fragment) is kept
    // byte-for-byte.
    let auth_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let (authority, rest) = after_scheme.split_at(auth_end);
    // An authority may carry `user[:pass]@` before the host — preserve it untouched.
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, hp)) => (Some(u), hp),
        None => (None, authority),
    };
    // Separate host from `:port`. An IPv6 literal is bracketed (`[::1]:8080`); otherwise the LAST
    // `:` (if any) starts the port (a bare IPv6 without brackets has no port form here).
    let (host, port) = if let Some(end) = hostport.strip_prefix('[') {
        let (h, tail) = end.split_once(']')?;
        (h, tail.strip_prefix(':').map(|p| (":", p)))
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        (h, Some((":", p)))
    } else {
        (hostport, None)
    };
    if !host_is_bind_local(host) {
        return None;
    }
    let port = port.map(|(sep, p)| format!("{sep}{p}")).unwrap_or_default();
    let userinfo = userinfo.map(|u| format!("{u}@")).unwrap_or_default();
    Some(format!(
        "{scheme}://{userinfo}{GUEST_HOST_ALIAS}{port}{rest}"
    ))
}

/// Whether `host` is a bind-side address that names no destination a bridged container can route to
/// the host with: loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`, `::`), or the literal
/// `localhost`. See [`rewrite_shim_host_for_docker`].
fn host_is_bind_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_unspecified(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        // A DNS name (a managed-DB alias, an external FQDN) — a real destination, never rewritten.
        Err(_) => false,
    }
}

/// Make a docker workload's declared compute-binding shims reachable from its per-project bridge:
/// rewrite each binding URL whose host is bind-local to `host.docker.internal` (see
/// [`rewrite_shim_host_for_docker`]) IN PLACE in `env`, and return the `ExtraHosts` entries the
/// container needs for that name to resolve. A pure function over the (env, bindings) pair so the
/// rewrite + the `/etc/hosts` injection are unit-testable without a daemon.
///
/// `ExtraHosts` is returned unconditionally (not only when a rewrite happened): the
/// `host.docker.internal` mapping is docker-idiomatic and harmless when unused, and it keeps a
/// workload that reaches the host by that name working regardless of how its shim URL was spelled.
fn docker_binding_reachability(
    env: &mut std::collections::BTreeMap<String, String>,
    bindings: &[ComputeBinding],
) -> Vec<String> {
    for binding in bindings {
        // A binding injects its endpoint URL at `url_env()` (and, for a managed-DB migration DSN,
        // at `migration_url_env()`); the credential at `<url_env>_AUTH_TOKEN` is never a URL and is
        // not touched.
        for key in [binding.url_env(), binding.migration_url_env()] {
            if let Some(value) = env.get(&key)
                && let Some(rewritten) = rewrite_shim_host_for_docker(value)
            {
                env.insert(key, rewritten);
            }
        }
    }
    vec![HOST_GATEWAY_EXTRA_HOST.to_string()]
}

/// Build the [`NetworkingConfig`] attaching a container to `network` with the given DNS `aliases`
/// (the workload's [`managed_db_alias`] for a server a sibling resolves by name; empty for a
/// one-shot client that only needs to reach peers). Each alias MUST be a valid DNS label (≤ 63
/// octets) — Docker 29's embedded DNS will not register a longer one (see [`managed_db_alias`]).
/// Supplying this at container-create means the container joins ONLY this one network — never the
/// shared default bridge — so docker's inter-network isolation is the tenancy boundary (a container
/// can resolve/reach only its own project's peers).
fn network_config(network: &str, aliases: Vec<String>) -> NetworkingConfig<String> {
    let endpoint = EndpointSettings {
        aliases: (!aliases.is_empty()).then_some(aliases),
        ..Default::default()
    };
    NetworkingConfig {
        endpoints_config: HashMap::from([(network.to_string(), endpoint)]),
    }
}

/// Whether a docker API error is a **409 Conflict**. For `create_network`, a 409 means the network
/// already exists, which the create-if-absent path treats as success (idempotent) — so a second
/// workload launching into an existing per-project network never errors.
fn is_network_conflict(err: &bollard::errors::Error) -> bool {
    matches!(
        err,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 409,
            ..
        }
    )
}

/// Whether a docker API error is a **404 Not Found** — the daemon has no such object.
/// For [`DockerBackend::remove_volume`] a 404 means the volume is already gone, which is
/// an idempotent `Ok(false)` ("nothing existed"), never an error.
fn is_not_found(err: &bollard::errors::Error) -> bool {
    matches!(
        err,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

/// Encode `<name>@<ip>:<port>` into the handle ref so `stop`/`health` need no
/// in-memory state (name → stop/inspect, ip\:port → health/route).
fn encode_ref(name: &str, ip: &str, port: u16) -> String {
    format!("{name}@{ip}:{port}")
}

/// Decode `<name>@<ip>:<port>`.
fn decode_ref(s: &str) -> Option<(String, String, u16)> {
    let (name, rest) = s.split_once('@')?;
    let (ip, port) = rest.rsplit_once(':')?;
    Some((name.to_string(), ip.to_string(), port.parse().ok()?))
}

/// Convert a host-resolved [`RegistryAuth`] into bollard's [`DockerCredentials`] for the
/// `create_image` `X-Registry-Auth`. Only `username`/`password`/`serveraddress` are set
/// (basic registry auth); the rest stay `None`. The resulting struct is passed straight to
/// the daemon and dropped — it is never logged (bollard's own `Debug` would print it, so it
/// is never formatted into an error here; see `pull_image`).
fn docker_credentials(auth: &RegistryAuth) -> DockerCredentials {
    DockerCredentials {
        username: Some(auth.username.clone()),
        password: Some(auth.password.clone()),
        serveraddress: Some(auth.serveraddress.clone()),
        ..Default::default()
    }
}

/// Split an image reference into the `fromImage` name + `tag` the daemon's
/// `create_image` wants, defaulting an untagged reference to `latest`. A tag is a
/// `:` in the **last path component** (so a registry `host:port/repo` port isn't
/// mistaken for one); a digest-pinned reference (`name@sha256:…`) is returned whole
/// with an empty tag.
fn image_pull_target(reference: &str) -> (String, String) {
    if reference.contains('@') {
        return (reference.to_string(), String::new()); // digest-pinned
    }
    let last = reference.rsplit('/').next().unwrap_or(reference);
    if last.contains(':') {
        // Tagged: the tag is after the final `:`.
        let (name, tag) = reference.rsplit_once(':').expect("last has ':'");
        (name.to_string(), tag.to_string())
    } else {
        (reference.to_string(), "latest".to_string())
    }
}

/// What `materialize` should do with an image under a given [`PullPolicy`], once it knows
/// whether the image is already in the daemon's local store. Factored out of the daemon call
/// path so the policy's semantics are unit-testable without a Docker daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PullAction {
    /// Reuse the locally-present image as-referenced (no registry round-trip).
    UseLocal,
    /// Pull the image from its registry.
    Pull,
    /// The image is absent and the policy forbids pulling — fail the materialize.
    FailAbsent,
}

/// The pull decision for a `(PullPolicy, locally-present?)` pair:
/// - [`PullPolicy::Always`] always pulls (never trusts the shared local store);
/// - [`PullPolicy::IfNotPresent`] reuses a present image, else pulls;
/// - [`PullPolicy::Never`] reuses a present image, else fails (no pull).
fn pull_action(policy: PullPolicy, local_present: bool) -> PullAction {
    match policy {
        PullPolicy::Always => PullAction::Pull,
        PullPolicy::IfNotPresent if local_present => PullAction::UseLocal,
        PullPolicy::IfNotPresent => PullAction::Pull,
        PullPolicy::Never if local_present => PullAction::UseLocal,
        PullPolicy::Never => PullAction::FailAbsent,
    }
}

/// F1 (Security review): whether `policy` must be **refused** given the backend posture.
/// Local-image reuse (`IfNotPresent`/`Never`) is a cross-tenant relaxation on the daemon's
/// SHARED image store — honored only under the single-tenant posture (`reuse_allowed`). Under
/// the multi-tenant guard a reuse policy is refused outright (never silently downgraded to a
/// pull), mirroring how `writable_root`/`cap_add` are gated. Pure, so the gate is unit-testable
/// without a daemon.
fn local_reuse_refused(policy: PullPolicy, reuse_allowed: bool) -> bool {
    policy.allows_local_reuse() && !reuse_allowed
}

/// Map a boatramp [`RestartPolicy`] to a Docker `HostConfig.restart_policy`.
fn restart_policy(policy: RestartPolicy) -> DockerRestartPolicy {
    let name = match policy {
        RestartPolicy::Never => RestartPolicyNameEnum::NO,
        RestartPolicy::OnFailure => RestartPolicyNameEnum::ON_FAILURE,
        RestartPolicy::Always => RestartPolicyNameEnum::ALWAYS,
    };
    DockerRestartPolicy {
        name: Some(name),
        maximum_retry_count: None,
    }
}

/// Whether a container's live PRIMARY network (`HostConfig.NetworkMode`) is already the
/// expected per-project network — the auto-heal idempotency check behind `needs_redeploy`.
///
/// A container created by the current launch path has `NetworkMode == "boatramp-net-<proj>"`
/// (current → no recreate). One created before the per-project net became the PRIMARY
/// attachment has `"bridge"` / `"default"` / an empty/absent mode (stale → recreate so a
/// relaunch puts it primary on the per-project net, where embedded DNS + service discovery
/// make `<workload>` resolve). Anything that is not exactly the expected net is treated as
/// stale.
fn primary_network_is_current(network_mode: Option<&str>, expected_net: &str) -> bool {
    network_mode == Some(expected_net)
}

/// Whether a container already advertises `expected_alias` among its live DNS `aliases` on the
/// per-project network — the second idempotency check behind `needs_redeploy`, for the UPGRADE
/// path (Bug D).
///
/// `launch` publishes [`managed_db_alias`]`(workload)` as the container's `--network-alias`. A
/// container created before that alias was applied (or under a longer workload name) carries its
/// OLD alias here and lacks the current one, so a sibling resolving the CURRENT alias gets
/// NXDOMAIN until the producer is recreated. A workload whose name already fits a DNS label
/// computes the SAME alias, so it is reported current (no spurious recreate). `None`/absent
/// aliases ⇒ not current (recreate), matching `primary_network_is_current` for a wrongly-attached one.
fn container_alias_is_current(aliases: Option<&[String]>, expected_alias: &str) -> bool {
    aliases.is_some_and(|a| a.iter().any(|x| x == expected_alias))
}

/// Map a docker `inspect` container `State` to the runner-level [`Health`], GROUNDED in
/// the container's ACTUAL state rather than its desired one.
///
/// The bug this fixes: a crash-looping container (the app can't reach its DB) is kept
/// alive IN PLACE by its `restart: always` policy and docker reports it as
/// `Status: "restarting"`. The old check read only the `State.Running` bool — which is
/// momentarily `true` during each restart's brief up-window (and which docker's own API
/// docs warn is *also* `true` for a merely *paused* container) — so a crash loop was
/// masked as `Healthy`, and both the reconcile's health refresh and `boatramp compute
/// status` reported a dead workload as up.
///
/// We instead key on the authoritative `Status` string: only a genuinely `running`
/// container is `Healthy`; `restarting` (the crash loop), `exited`, `dead`, `created`,
/// `paused`, and `removing` are all `Unhealthy`. A declared HEALTHCHECK that is reporting
/// `unhealthy` overrides a bare "running" (the app itself says it is not serving); a
/// `starting` healthcheck does NOT (runner-level health is "the process is up" — the
/// reconcile's separate readiness pass owns service-level readiness). `Status` absent (an
/// older daemon) falls back to the `Running` bool.
fn health_from_state(state: Option<&ContainerState>) -> Health {
    let Some(state) = state else {
        return Health::Unhealthy;
    };
    // A healthcheck that has gone unhealthy is decisive, regardless of run state.
    if matches!(
        state.health.as_ref().and_then(|h| h.status),
        Some(HealthStatusEnum::UNHEALTHY)
    ) {
        return Health::Unhealthy;
    }
    match state.status {
        Some(ContainerStateStatusEnum::RUNNING) => Health::Healthy,
        // A restart loop lands in RESTARTING — the crash loop the old check masked.
        Some(
            ContainerStateStatusEnum::RESTARTING
            | ContainerStateStatusEnum::EXITED
            | ContainerStateStatusEnum::DEAD
            | ContainerStateStatusEnum::CREATED
            | ContainerStateStatusEnum::PAUSED
            | ContainerStateStatusEnum::REMOVING
            | ContainerStateStatusEnum::EMPTY,
        ) => Health::Unhealthy,
        // Older daemon without a Status string: fall back to the Running bool.
        None => {
            if state.running.unwrap_or(false) {
                Health::Healthy
            } else {
                Health::Unhealthy
            }
        }
    }
}

/// PID cap for a launched container — a fork-bomb guard. Generous
/// for normal app workloads, bounded so a runaway can't exhaust host PIDs.
const MAX_PIDS: i64 = 512;

/// Build a **hardened** `HostConfig` for a launched workload. Beyond
/// the mem/cpu/restart limits, a shared-kernel Docker workload runs least-
/// privilege by default: no privilege escalation (`no-new-privileges`), **all**
/// Linux capabilities dropped, a **read-only root filesystem** (with small
/// `noexec`/`nosuid` tmpfs mounts for `/tmp` + `/run` so temp/runtime writes
/// still work), and a **PID cap**. Running as a non-root *user* is left to the
/// image — forcing a UID breaks images that expect their own user, and
/// `no-new-privileges` already blocks setuid escalation.
///
/// The tmpfs mounts are `mode=1777` (world-writable + sticky, like a real `/tmp`
/// and `/run`). Docker special-cases a bare `/run` tmpfs to `0755 root:root`,
/// which a **non-root** image cannot write — so an entrypoint that creates its own
/// runtime dir there (a stock Postgres `mkdir -p /var/run/postgresql` for its unix
/// socket, MySQL's `/run/mysqld`, nginx's `/run/nginx`, …) silently fails and the
/// service never comes up. `1777` restores exactly the pre-owned, writable runtime
/// dir the image expects, generally and without special-casing any image, while
/// `noexec`/`nosuid`/`size` keep the mount hardened.
///
/// `writable_root` relaxes only the read-only-root default (caller-gated to the
/// single-tenant posture); every other hardening stays on. The idiomatic path for
/// app writes is a persistent volume, not a writable root.
///
/// `cap_add` names capabilities (short form, no `CAP_` prefix) to grant back on top of
/// the dropped-`ALL` default — also caller-gated to single-tenant — for an image whose
/// entrypoint genuinely needs one (a stock database that `chown`s its data dir and
/// drops privileges). `cap_drop: ALL` still applies, so it is an explicit allowlist,
/// and `no-new-privileges` stays on. Empty ⇒ the strict dropped-`ALL` default.
fn hardened_host_config(
    mem_mib: u32,
    vcpus: u32,
    restart: RestartPolicy,
    writable_root: bool,
    cap_add: &[String],
) -> HostConfig {
    let tmpfs = std::collections::HashMap::from([
        (
            "/tmp".to_string(),
            "rw,noexec,nosuid,size=64m,mode=1777".to_string(),
        ),
        (
            "/run".to_string(),
            "rw,noexec,nosuid,size=16m,mode=1777".to_string(),
        ),
    ]);
    HostConfig {
        memory: Some(i64::from(mem_mib) * 1024 * 1024),
        nano_cpus: Some(i64::from(vcpus.max(1)) * 1_000_000_000),
        restart_policy: Some(restart_policy(restart)),
        // Hardening:
        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
        cap_drop: Some(vec!["ALL".to_string()]),
        // Add back only the explicitly-allowlisted capabilities (empty by default).
        cap_add: (!cap_add.is_empty()).then(|| cap_add.to_vec()),
        readonly_rootfs: Some(!writable_root),
        tmpfs: Some(tmpfs),
        pids_limit: Some(MAX_PIDS),
        ..Default::default()
    }
}

#[async_trait]
impl ComputeBackend for DockerBackend {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            isolation: IsolationClass::Container,
            scale_to_zero: false,
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
            // Directly scheduled against the node ledger — a preemption participant.
            preemptible: true,
        }
    }

    fn source_support(&self) -> SourceSupport {
        // The docker backend pulls an OCI **image** reference (`materialize` rejects a
        // tar/rootfs source) and authenticates the pull with the host-resolved registry
        // credential (`pull_image(…, pull_auth)`): image-only, private-registry-capable.
        SourceSupport {
            accepted_sources: vec![RootSourceKind::Image],
            private_registry_credential: true,
            primary_source: Some(RootSourceKind::Image),
        }
    }

    async fn materialize(
        &self,
        _project: &str,
        _workload: &str,
        spec: &ComputeSpec,
        pull_auth: Option<&RegistryAuth>,
    ) -> Result<Artifact, BackendError> {
        // The docker backend pulls an OCI **image reference** (registry/repo:tag or a
        // digest); an ext4 rootfs is not runnable here.
        let reference = match &spec.root {
            RootSource::Image(reference) => reference.clone(),
            RootSource::Tar(_) | RootSource::Rootfs(_) => {
                return Err(BackendError::Materialize(
                    "docker backend requires an image reference (RootSource::Image)".into(),
                ));
            }
        };
        // F1 (Security review): local-image reuse (`IfNotPresent`/`Never`) is a cross-tenant
        // relaxation on the daemon's SHARED image store — reusing an image a co-tenant cached
        // under this `name:tag`/digest would run it with NO per-tenant registry-auth check
        // (bypassing `--pull-secret` fail-closed — the classic k8s `IfNotPresent` leak, which
        // digest-pinning does not close) and exposes mutable-tag poisoning. Honor it ONLY under
        // the single-tenant posture; under the multi-tenant guard REFUSE outright (never a
        // silent re-pull), mirroring how `writable_root`/`cap_add` are stripped.
        if local_reuse_refused(spec.pull_policy, self.local_image_reuse_allowed) {
            return Err(BackendError::Materialize(format!(
                "pull_policy={} (local-image reuse) is refused under the multi-tenant posture: \
                 the Docker daemon's image store is shared across tenants, so reusing a \
                 locally-cached image would bypass this tenant's registry-auth check and expose \
                 tag poisoning. Use pull_policy=always (re-pull every launch), or run under the \
                 single-tenant posture where `docker load`'d local images are safe.",
                match spec.pull_policy {
                    PullPolicy::IfNotPresent => "if-not-present",
                    PullPolicy::Never => "never",
                    PullPolicy::Always => "always",
                }
            )));
        }
        // Pull policy (PLAN-compute-dx #3 / `imagePullPolicy` parity). The DEFAULT
        // (`Always`) re-pulls on every materialize — the safe posture, because the Docker
        // daemon's image store is SHARED across every tenant on this node, so a mutable
        // `name:tag` in it is ambient, poisonable state. `IfNotPresent`/`Never` reuse a
        // locally-present image (a `docker load`'d tarball, a pre-pulled/pinned image) and
        // are opt-in (single-tenant only, gated above); reuse is sound only for a
        // digest-pinned reference (surfaced by the set-time advisory in the server, not
        // re-litigated here per launch). Only the non-`Always` policies consult the local
        // store (via `inspect_image`) — `Always` never inspects, keeping the default path's
        // behavior and cost identical to before.
        let local_present = match spec.pull_policy {
            PullPolicy::Always => false,
            PullPolicy::IfNotPresent | PullPolicy::Never => self.image_present(&reference).await,
        };
        match pull_action(spec.pull_policy, local_present) {
            // Authenticate the pull with the host-resolved registry credential (private
            // image), or `None` for a public/anonymous pull. The credential is a sealed
            // secret resolved fail-closed before launch — it never appears in config/argv.
            PullAction::Pull => {
                let reference = self.pull_image(&reference, pull_auth).await?;
                Ok(Artifact::Image { reference })
            }
            // Reuse the locally-present image as-referenced — no registry round-trip.
            PullAction::UseLocal => Ok(Artifact::Image { reference }),
            PullAction::FailAbsent => Err(BackendError::Materialize(format!(
                "image {reference} is not present in the local store and pull_policy=never \
                 forbids pulling it; `docker load` / pull it first, or use \
                 pull_policy=if-not-present (pull on absence) / always (always pull)"
            ))),
        }
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let reference = match &req.artifact {
            Artifact::Image { reference } => reference.clone(),
            _ => {
                return Err(BackendError::Launch(
                    "docker backend requires an Image artifact".into(),
                ));
            }
        };
        let name = container_name(&req.project, &req.workload, req.replica);
        // Make the workload's compute-binding shims reachable from its per-project bridge. A
        // container cannot reach a shim the operator bound on the host loopback (`127.0.0.1` — the
        // container's OWN loopback) or on `0.0.0.0` (no routable destination); and with MULTIPLE
        // per-project bridges there is no single gateway IP to pin into every guest. So rewrite any
        // bind-local shim URL's host to `host.docker.internal` and add the matching `host-gateway`
        // ExtraHost (`docker_binding_reachability`): that one stable name resolves to the host from
        // every per-project network. A shim bound on a routable host-gateway IP (e.g.
        // `172.17.0.1`), a managed-DB DSN (a sibling's DNS alias), or an external endpoint already
        // names a reachable destination and is left untouched. The off-node security boundary is
        // NOT weakened here — it is the shim's own bind scope plus the node firewall (which admits
        // the shim port only on the boatramp compute bridges); see the crate/module docs.
        let mut env_map = req.spec.env.clone();
        let extra_hosts = docker_binding_reachability(&mut env_map, &req.spec.bindings);
        let env: Vec<String> = env_map.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let port = req.spec.port;
        let port_key = format!("{port}/tcp");
        // Honor `writable_root` only where the posture allows it (single-tenant);
        // otherwise the hardened read-only root stands.
        let writable_root = req.spec.writable_root && self.writable_root_allowed;
        // Same posture gate for `cap_add`: single-tenant may add capabilities back,
        // the multi-tenant guard keeps the dropped-`ALL` default.
        let cap_add: &[String] = if self.cap_add_allowed {
            &req.spec.cap_add
        } else {
            &[]
        };
        let mut host_config = hardened_host_config(
            req.spec.mem_mib,
            req.spec.vcpus,
            req.spec.restart,
            writable_root,
            cap_add,
        );
        // `host.docker.internal:host-gateway` (see `docker_binding_reachability`) — so a bridged
        // workload resolves the host from any per-project network to reach its compute shims.
        host_config.extra_hosts = Some(extra_hosts);
        // Attach the spec's persistent volumes (validated; bind dirs created).
        let mounts = self.stage_volumes(&req.spec).await?;
        if !mounts.is_empty() {
            host_config.mounts = Some(mounts);
        }
        let mut config = Config {
            image: Some(reference),
            cmd: Some(req.spec.entrypoint.clone()),
            env: Some(env),
            // Run the entrypoint as this user (`uid[:gid]`) so a stock image runs
            // rootless against its pre-chowned volume — no capabilities needed. Passed
            // to Docker verbatim; `None` keeps the image's own user.
            user: req.spec.user.clone(),
            ..Default::default()
        };
        // In the default `Published` mode, publish the container port on the host
        // loopback with an ephemeral host port (discovered after start), so a
        // host-native `serve` can reach it even when the bridge IP is not host-routable
        // (Docker Desktop / macOS). `Bridge` leaves the container unpublished.
        //
        // Only when the workload actually HAS a port: a no-port workload (`port == 0`) must NOT
        // emit a `0/tcp` spec — Docker 29.x rejects it with 400 ("invalid port specification:
        // 0/tcp"), where Docker 28 tolerated it (the same 28→29 strictness class as the 63-octet
        // DNS-label cap above). A port-0 workload publishes nothing and has no host endpoint.
        if self.endpoint == DockerEndpoint::Published && port != 0 {
            config.exposed_ports = Some(HashMap::from([(port_key.clone(), HashMap::new())]));
            host_config.port_bindings = Some(HashMap::from([(
                port_key.clone(),
                Some(vec![PortBinding {
                    host_ip: Some("127.0.0.1".to_string()),
                    host_port: Some("0".to_string()),
                }]),
            )]));
        }
        // Create-if-absent the PER-PROJECT user-defined network and make it the container's
        // PRIMARY network (`HostConfig.NetworkMode`), attaching it AT CREATE with a DNS ALIAS
        // equal to the workload name (`networking_config` for that SAME network).
        //
        // This is the load-bearing DNS fix (Bug C). v0.55.0 set `networking_config` for the
        // per-project net but left `NetworkMode` at its default, so the container's PRIMARY
        // attachment was the DEFAULT bridge and the per-project net was merely SECONDARY. Two
        // consequences made name resolution FAIL on the real workloads even though the network
        // and the DNS aliases existed: (1) the container's `/etc/resolv.conf` pointed at the
        // default-bridge/host resolver, NOT docker's embedded DNS (127.0.0.11); and (2) docker
        // publishes a container into a user-defined network's service discovery ONLY when that
        // net is the container's PRIMARY attachment — a secondary endpoint carrying DNSNames is
        // not enough. Making the per-project net PRIMARY fixes BOTH: embedded DNS in resolv.conf
        // AND SD publication, so a sibling resolves `<workload>:<port>` (the managed-DB DSN is
        // name-based). The per-project net is a non-internal bridge, so egress still NATs out of
        // it — the default bridge is not needed and is intentionally NOT attached (one network
        // per project is also the tenancy boundary: docker's inter-network isolation keeps one
        // project's containers off another's). Published-port + bridge-IP reach are unaffected:
        // port publishing and `container_ip` work on a user-defined bridge exactly as on the
        // default bridge (`container_ip` already falls back from the now-empty top-level
        // `IPAddress` — only set for the default bridge — to the per-project endpoint's IP).
        //
        // The DNS ALIAS is `managed_db_alias(&req.workload)`, NOT the raw workload name (Bug D,
        // Docker 29): a DNS label is capped at 63 octets (RFC 1035), and Docker 29's libnetwork
        // refuses to publish an embedded-DNS service-discovery record for a label over that cap
        // (Docker 28 tolerated it — why this went unseen). A `Single`-isolation managed-DB
        // workload name is `<compute>-<sanitized-ident>` with two 25-char digests ≈ 69 octets, so
        // the raw-name alias silently failed to register on 29 and a sibling got NXDOMAIN. The
        // short, stable alias fits a label and is the SAME string a consumer's DSN host resolves
        // (`NodeTenantSqlResolver::connection_parts` applies the identical `managed_db_alias`), so
        // the two always match. The long container NAME stays (it is identity, never resolved by a
        // sibling once the short alias exists); a short/valid workload name is published unchanged.
        let network = self.ensure_project_network(&req.project).await?;
        host_config.network_mode = Some(network.clone());
        config.host_config = Some(host_config);
        config.networking_config = Some(network_config(
            &network,
            vec![managed_db_alias(&req.workload)],
        ));

        // Best-effort clean of a stale container with the same name, then create.
        let _ = self
            .docker
            .remove_container(
                &name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.clone(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|e| BackendError::Launch(format!("create {name}: {e}")))?;
        self.docker
            .start_container::<String>(&created.id, None)
            .await
            .map_err(|e| BackendError::Launch(format!("start {name}: {e}")))?;

        // Forward the container's stdout/stderr into boatramp observability — the same
        // sink the native container backend uses (tracing `boatramp::guest` +
        // `<data_dir>/compute/logs/<id>.log`), reaching observability parity. A
        // detached background task; it never blocks the launch path and stops when the
        // container exits/removes. The log-file + tracing tag are keyed by the stable
        // boatramp instance id (matching the native backend), not the daemon's id.
        self.spawn_log_forwarder(
            created.id.clone(),
            compute_instance_id(&req.project, &req.workload, req.replica),
            self.build_log_redactor(req),
        );

        // Reachable endpoint: the published host loopback port (default), or the
        // container's bridge IP + in-container port (`Bridge`).
        let (host, endpoint_port) = match self.endpoint {
            // A no-port workload published nothing (see above) — no host port to discover.
            DockerEndpoint::Published if port == 0 => ("127.0.0.1".to_string(), 0),
            DockerEndpoint::Published => (
                "127.0.0.1".to_string(),
                self.published_host_port(&created.id, &port_key).await?,
            ),
            DockerEndpoint::Bridge => (self.container_ip(&created.id).await?, port),
        };
        Ok(Instance {
            handle: InstanceHandle {
                project: req.project.clone(),
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: encode_ref(&name, &host, endpoint_port),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host,
                port: endpoint_port,
            },
        })
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let name = decode_ref(&handle.backend_ref)
            .map(|(n, _, _)| n)
            .unwrap_or_else(|| container_name(&handle.project, &handle.workload, handle.replica));
        // Stop (ignore "already stopped") then force-remove.
        let _ = self
            .docker
            .stop_container(&name, None::<StopContainerOptions>)
            .await;
        self.docker
            .remove_container(
                &name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| BackendError::Stop(format!("remove {name}: {e}")))?;
        // Best-effort GC of the per-project network: `remove_network` fails (ignored) while any
        // sibling is still attached, so this reaps the network only once the LAST of a project's
        // workloads has left — there is no dedicated project-teardown hook on the backend. A later
        // launch re-creates it idempotently. Never fails the stop.
        let _ = self
            .docker
            .remove_network(&project_network_name(&handle.project))
            .await;
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let name = match decode_ref(&handle.backend_ref) {
            Some((n, _, _)) => n,
            None => container_name(&handle.project, &handle.workload, handle.replica),
        };
        let info = match self.docker.inspect_container(&name, None).await {
            Ok(info) => info,
            // Inspect failed (gone / unreachable): not serving.
            Err(_) => return Ok(Health::Unhealthy),
        };
        Ok(health_from_state(info.state.as_ref()))
    }

    async fn needs_redeploy(&self, handle: &InstanceHandle, _spec: &ComputeSpec) -> bool {
        // Auto-heal (Bug A/C): a container whose live PRIMARY network is not this project's
        // per-project net was created by a release before that net became the primary
        // attachment — it is up but cannot resolve siblings by name. Report it as needing a
        // recreate so the reconcile stops + relaunches it (volume-safe), re-running `launch`
        // with the per-project net as primary. A second check (Bug D, below) also recreates a
        // container that is primary on the net but still advertises a STALE DNS alias. Idempotent:
        // a container already primary on the net AND advertising the current alias returns
        // `false`. Inspect failure / gone ⇒ `false` (the normal plan path owns it).
        let name = match decode_ref(&handle.backend_ref) {
            Some((n, _, _)) => n,
            None => container_name(&handle.project, &handle.workload, handle.replica),
        };
        let Ok(info) = self.docker.inspect_container(&name, None).await else {
            return false;
        };
        let project_net = project_network_name(&handle.project);
        let network_mode = info
            .host_config
            .as_ref()
            .and_then(|hc| hc.network_mode.as_deref());
        if !primary_network_is_current(network_mode, &project_net) {
            return true;
        }
        // Auto-heal (Bug D, UPGRADE path): the container is primary on the per-project net but
        // advertises a STALE DNS alias — it was launched before `managed_db_alias` applied (or
        // under a longer workload name), so its `--network-alias` is the OLD value while a
        // consumer now resolves the CURRENT `managed_db_alias(workload)`. Recreate (volume-safe)
        // so the producer relaunches with the current alias; an existing deployment then adopts
        // the <=63-octet alias on upgrade with NO manual recreate. The CONSUMER got recreated on
        // its own spec change (new DSN host), but the producer's spec is unchanged, so without
        // this check the half-applied state (consumer dials the short alias, producer answers only
        // the old long one) persists. A workload whose name already fits a label computes the SAME
        // alias, so this never spuriously recreates it.
        let expected_alias = managed_db_alias(&handle.workload);
        let live_aliases = info
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref())
            .and_then(|nets| nets.get(&project_net))
            .and_then(|ep| ep.aliases.as_deref());
        !container_alias_is_current(live_aliases, &expected_alias)
    }

    /// Re-discover a running container's live published host port (the reconcile's
    /// endpoint re-point — see [`ComputeBackend::observed_endpoint`]). Only the
    /// `Published` mode drifts: docker reassigns the ephemeral host port on every
    /// in-place `--restart` restart, so a crash-looping (e.g. OOM `137`) app is
    /// relaunched under the SAME container name with a NEW host port while the stored
    /// endpoint keeps the dead old one. `Bridge` mode routes to the container's bridge
    /// IP + the fixed in-container port, which an in-place restart preserves, so it does
    /// not drift here (returns `None`). Returns `None` — never a guess — for a container
    /// that is not currently `running` (restarting / exited / gone: it has no live
    /// published port, and its (un)health is the plan path's business), for an inspect
    /// failure, or for a no-port workload (nothing published). Reads the port straight
    /// off the single inspect rather than re-inspecting via `published_host_port`.
    async fn observed_endpoint(&self, handle: &InstanceHandle) -> Option<Endpoint> {
        if self.endpoint != DockerEndpoint::Published {
            return None;
        }
        let name = match decode_ref(&handle.backend_ref) {
            Some((n, _, _)) => n,
            None => container_name(&handle.project, &handle.workload, handle.replica),
        };
        let info = self.docker.inspect_container(&name, None).await.ok()?;
        // Only a genuinely RUNNING container has a live published port to re-read. A
        // restarting/exited/created one momentarily has no (or a torn-down) binding —
        // routing to it is pointless and the normal health→Stop/Launch path owns it.
        if !matches!(
            info.state.as_ref().and_then(|s| s.status),
            Some(ContainerStateStatusEnum::RUNNING)
        ) {
            return None;
        }
        // The workload publishes a single container port; take the first live host-port
        // binding. (A no-port workload has an empty port map → `None`, correctly skipped.)
        let port = info
            .network_settings
            .as_ref()
            .and_then(|ns| ns.ports.as_ref())
            .and_then(|ports| {
                ports
                    .values()
                    .flatten() // Option<Vec<PortBinding>> → the Vecs that are Some
                    .flatten() // Vec<PortBinding> → each PortBinding
                    .find_map(|b| b.host_port.as_ref().and_then(|hp| hp.parse::<u16>().ok()))
            })?;
        Some(Endpoint {
            scheme: Scheme::Http,
            host: "127.0.0.1".to_string(),
            port,
        })
    }

    /// List this backend's persistent volumes (the host-side backing for a spec's
    /// [`VolumeRef`]s), so `GET /api/compute/volumes` can surface a docker-managed
    /// volume for operator reclamation. Only volumes this backend owns are reported —
    /// the `boatramp-` daemon-volume prefix (Named mode) or the entries under
    /// `<data_dir>/compute/volumes/` (Bind mode) — never an unrelated volume on a
    /// shared daemon. The reported `name` is the boatramp volume name (the prefix is
    /// stripped), so it matches the name [`remove_volume`](Self::remove_volume) and the
    /// node volume capability address it by.
    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>, BackendError> {
        match self.volume_mode {
            DockerVolumeMode::Named => {
                let prefix = docker_volume_name(""); // "boatramp-"
                let resp = self
                    .docker
                    .list_volumes(None::<ListVolumesOptions<String>>)
                    .await
                    .map_err(|e| BackendError::Other(format!("list docker volumes: {e}")))?;
                let mut out: Vec<VolumeInfo> = resp
                    .volumes
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|v| {
                        // Only OUR volumes (the `boatramp-` prefix) — strip it back to the
                        // boatramp volume name the caller addresses.
                        let name = v.name.strip_prefix(&prefix)?.to_string();
                        // `usage_data` (hence the real size) is only populated by the daemon
                        // for some requests; report 0 when absent rather than failing the list.
                        let size_bytes = v.usage_data.map(|u| u.size.max(0) as u64).unwrap_or(0);
                        Some(VolumeInfo { name, size_bytes })
                    })
                    .collect();
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            }
            DockerVolumeMode::Bind => {
                let root = self.data_dir.join("compute").join("volumes");
                let mut dir = match tokio::fs::read_dir(&root).await {
                    Ok(d) => d,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(e) => {
                        return Err(BackendError::Other(format!(
                            "read volumes dir {}: {e}",
                            root.display()
                        )));
                    }
                };
                let mut out = Vec::new();
                while let Some(entry) = dir
                    .next_entry()
                    .await
                    .map_err(|e| BackendError::Other(format!("scan volumes dir: {e}")))?
                {
                    let ft = entry
                        .file_type()
                        .await
                        .map_err(|e| BackendError::Other(format!("stat volume entry: {e}")))?;
                    if !ft.is_dir() {
                        continue;
                    }
                    if let Some(name) = entry.file_name().to_str().map(str::to_owned) {
                        // Skip a native-container SCOPED volume dir (`@<scope>`) when the
                        // two backends share a `data_dir` — it is not a docker volume, and
                        // listing it would let the docker `compute volume rm` endpoint
                        // target another backend's PGDATA (Finding 4).
                        if name.starts_with(SCOPE_DIR_PREFIX) {
                            continue;
                        }
                        out.push(VolumeInfo {
                            name,
                            size_bytes: 0,
                        });
                    }
                }
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            }
        }
    }

    /// Remove the backing for persistent volume `name`, returning whether it existed.
    /// Backs `DELETE /api/compute/volumes/{name}` AND the managed-DB drop's volume
    /// reclamation (completing a `db drop database` so a same-name re-provision
    /// `initdb`s afresh against its new credential instead of re-attaching the dropped
    /// DB's stale, old-credential volume). `name` is the boatramp volume name — the
    /// daemon volume is addressed with the `boatramp-` prefix (Named) / the host bind
    /// directory (Bind), so this can only ever touch a volume THIS backend created.
    ///
    /// In **Named** mode `force: false` is deliberate: the daemon refuses (409) to remove
    /// a volume still attached to a container, failing loudly rather than wiping data from
    /// under a live replica; a 404 (already gone) is the idempotent `Ok(false)`. **Bind**
    /// mode is a plain `remove_dir_all` with NO such in-use guard (a bind mount is just a
    /// host path), so it relies on the caller having stopped the workload's container
    /// first — which the drop path does (stop, then reclaim). This is the raw removal; the
    /// "still referenced by a registered workload" refusal lives one layer up in
    /// [`ComputeVolumes`](boatramp_core::compute::ComputeVolumes).
    async fn remove_volume(&self, name: &str) -> Result<bool, BackendError> {
        // Reject a traversing / multi-component name before building any path or daemon
        // volume name from it (mirrors `stage_volumes`' guard; the mount is irrelevant
        // here so a trivially-valid `/` is passed).
        validate_volume(name, "/")?;
        match self.volume_mode {
            DockerVolumeMode::Named => {
                let vol = docker_volume_name(name);
                match self
                    .docker
                    .remove_volume(&vol, Some(RemoveVolumeOptions { force: false }))
                    .await
                {
                    Ok(()) => Ok(true),
                    Err(e) if is_not_found(&e) => Ok(false),
                    Err(e) => Err(BackendError::Other(format!(
                        "remove docker volume {vol}: {e}"
                    ))),
                }
            }
            DockerVolumeMode::Bind => {
                let dir = volume_dir(&self.data_dir, name);
                match tokio::fs::remove_dir_all(&dir).await {
                    Ok(()) => Ok(true),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(BackendError::Other(format!(
                        "remove volume {} dir: {e}",
                        dir.display()
                    ))),
                }
            }
        }
    }

    /// Run a one-shot command **inside** the running container via the Engine
    /// exec API and buffer its output. `argv` is the command + args (no shell);
    /// `stdin`, when present, is written to the command's standard input and the
    /// stream is then half-closed so the command sees EOF. stdout/stderr are
    /// captured to completion, and the command's exit status is read back from
    /// `inspect_exec` after the output stream ends.
    ///
    /// The container name is the one encoded in the handle (falling back to the
    /// deterministic `boatramp-<workload>-<replica>`, mirroring `health`/`stop`).
    async fn exec(
        &self,
        handle: &InstanceHandle,
        argv: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, BackendError> {
        use tokio::io::AsyncWriteExt;

        let name = match decode_ref(&handle.backend_ref) {
            Some((n, _, _)) => n,
            None => container_name(&handle.project, &handle.workload, handle.replica),
        };
        if argv.is_empty() {
            return Err(BackendError::Other("exec: empty argv".into()));
        }
        let created = self
            .docker
            .create_exec(
                &name,
                CreateExecOptions {
                    cmd: Some(argv.to_vec()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    attach_stdin: Some(stdin.is_some()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| BackendError::Other(format!("exec create on {name}: {e}")))?;
        let started = self
            .docker
            .start_exec(&created.id, None)
            .await
            .map_err(|e| BackendError::Other(format!("exec start on {name}: {e}")))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        match started {
            StartExecResults::Attached { mut output, input } => {
                // Feed stdin (if any) and half-close so the command sees EOF, then
                // drain stdout/stderr to completion.
                if let Some(bytes) = stdin {
                    let mut input = input;
                    input.write_all(bytes).await.map_err(|e| {
                        BackendError::Other(format!("exec stdin write on {name}: {e}"))
                    })?;
                    input.flush().await.map_err(|e| {
                        BackendError::Other(format!("exec stdin flush on {name}: {e}"))
                    })?;
                    input.shutdown().await.map_err(|e| {
                        BackendError::Other(format!("exec stdin close on {name}: {e}"))
                    })?;
                } else {
                    // Nothing to send; drop the writer to close the stdin half.
                    drop(input);
                }
                while let Some(chunk) = output.next().await {
                    match chunk
                        .map_err(|e| BackendError::Other(format!("exec output on {name}: {e}")))?
                    {
                        LogOutput::StdOut { message } => stdout.extend_from_slice(&message),
                        // No attached TTY, so `Console` shouldn't appear, but fold it
                        // into stderr defensively if the daemon ever sends it.
                        LogOutput::StdErr { message } | LogOutput::Console { message } => {
                            stderr.extend_from_slice(&message);
                        }
                        LogOutput::StdIn { .. } => {}
                    }
                }
            }
            // We never request `detach`, so a detached result is unexpected; treat it
            // as an empty run and fall through to read the (already-final) status.
            StartExecResults::Detached => {}
        }

        // The exit status is only known after the exec has finished (the output
        // stream has ended). `exit_code` is `Option<i64>`; default a still-unknown
        // status to 0.
        let inspected = self
            .docker
            .inspect_exec(&created.id)
            .await
            .map_err(|e| BackendError::Other(format!("exec inspect on {name}: {e}")))?;
        let exit_code = inspected.exit_code.unwrap_or(0) as i32;

        Ok(ExecOutput {
            exit_code,
            stdout,
            stderr,
        })
    }

    async fn run_ephemeral(
        &self,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        mut stdin: Option<&mut (dyn futures::io::AsyncRead + Send + Unpin)>,
        stdout: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
    ) -> Result<i32, BackendError> {
        // `input` (bollard's stdin writer) is a tokio writer; the caller's `stdin`
        // reader + `stdout` sink are std-agnostic `futures` streams. All the extension
        // traits are in scope.
        use futures::io::AsyncReadExt as FuturesReadExt;
        use futures::io::AsyncWriteExt as FuturesWriteExt;
        use tokio::io::AsyncWriteExt as TokioWriteExt;

        if argv.is_empty() {
            return Err(BackendError::Other("run_ephemeral: empty argv".into()));
        }
        let has_stdin = stdin.is_some();

        // Pull the client image (pg_dump/pg_restore/psql live here). These are public
        // images (pgvector/mysql); a private client image is a documented follow-up —
        // thread the operator auth here when one is wanted. Anonymous for now.
        let reference = self.pull_image(image, None).await?;

        // Hardened one-shot: dropped caps, read-only root, no-new-privileges, PID cap,
        // auto-removed on exit, and NO published port — it only needs network egress to
        // reach the database, which the daemon bridge NATs out of the box.
        let mut host_config = hardened_host_config(512, 1, RestartPolicy::Never, false, &[]);
        host_config.auto_remove = Some(true);

        // CONSUME the reserved per-project-network hint (see `EPHEMERAL_NETWORK_ENV`): a managed-DB
        // export/import client must reach a DB that lives on an isolated per-project network, so the
        // node asks us to join it. Strip the pair from the process env (it must NEVER reach the
        // client) and remember the network to attach to; absent ⇒ the one-shot stays on the daemon
        // default network (an external DSN, reachable via NAT egress), exactly as before.
        let mut env_pairs: Vec<(String, String)> = env.to_vec();
        // Strip EVERY occurrence of the reserved hint (not just the first) so no duplicate pair can
        // ever survive into the client env; the last value wins as the network to join.
        let mut ephemeral_network: Option<String> = None;
        env_pairs.retain(|(k, v)| {
            if k == EPHEMERAL_NETWORK_ENV {
                ephemeral_network = Some(v.clone());
                false
            } else {
                true
            }
        });

        let env_strings: Vec<String> = env_pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
        // No `networking_config` at create: the one-shot comes up on the daemon's DEFAULT network
        // (NAT egress), then — when a per-project network was hinted — is ALSO connected to that
        // network below. Keeping the default attachment is what makes the client reach a managed DB
        // that is NOT on a per-project network (an external DSN, a managed DB launched before the
        // per-project-network change and not yet relaunched, or a colocated test DB on the default
        // bridge) by the host its endpoint reports, exactly as before this backend grew per-project
        // networks.
        let config = Config {
            image: Some(reference),
            cmd: Some(argv.to_vec()),
            env: Some(env_strings),
            host_config: Some(host_config),
            attach_stdin: Some(has_stdin),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            open_stdin: Some(has_stdin),
            stdin_once: Some(has_stdin),
            ..Default::default()
        };

        let name = ephemeral_container_name();
        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.clone(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|e| BackendError::Other(format!("ephemeral create: {e}")))?;

        // DUAL-ATTACH: the one-shot already sits on the daemon default network (above); when the
        // node hinted a per-project network, ALSO connect it there so it can reach a managed DB
        // that lives on that isolated network (the post-relaunch shape — a per-project-network
        // container IP or the DB's workload-name alias over the embedded DNS). Create-if-absent is
        // robust to the network having been reaped between the DB's launch and this one-shot. The
        // client is confined to NO single network: it keeps the default egress AND reaches the
        // target project — which is correct, because the one-shot is boatramp's own operator tool
        // (a fixed pg_dump/pg_restore/psql/mysqldump argv against ONE resolved DB), never guest
        // code, so this is not a guest-tenancy seam; per-project WORKLOAD confinement (the launch
        // path) is unchanged. Connect before start so the interface is present when the client
        // runs; a failure here means the DB is unreachable, so force-remove + surface it.
        if let Some(net) = &ephemeral_network {
            // Create-if-absent with the SAME labels as the launch path (managed + project), so an
            // operator's project-scoped GC/identification finds this network whether a one-shot or
            // a workload launch won the create race. `net` is always `project_network_name(..)`-
            // shaped, so recover the project by stripping the fixed prefix.
            let project = net
                .strip_prefix(PROJECT_NETWORK_PREFIX)
                .unwrap_or(net.as_str());
            let _ = self.ensure_project_network(project).await;
            if let Err(e) = self
                .docker
                .connect_network(
                    net,
                    ConnectNetworkOptions {
                        container: created.id.clone(),
                        endpoint_config: EndpointSettings::default(),
                    },
                )
                .await
            {
                self.force_remove_container(&name).await;
                // Best-effort reap of the network if THIS call just created it (a fresh per-project
                // network with no other endpoints). `remove_network` is a no-op error, ignored, when
                // the network pre-existed and still has workloads attached — so we never tear down a
                // live project network, only our own orphan.
                let _ = self.docker.remove_network(net).await;
                return Err(BackendError::Other(format!(
                    "ephemeral join project network {net}: {e}"
                )));
            }
        }

        // Attach BEFORE start so no output is missed, requesting a live bidirectional
        // stream. If attach (or start, below) fails, the container was CREATED but never
        // ran — `auto_remove` only reaps a container that actually started, so force-
        // remove it here or it leaks and accumulates on repeated daemon errors.
        let attach = match self
            .docker
            .attach_container(
                &created.id,
                Some(AttachContainerOptions::<String> {
                    stdin: Some(has_stdin),
                    stdout: Some(true),
                    stderr: Some(true),
                    stream: Some(true),
                    logs: Some(false),
                    detach_keys: None,
                }),
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                self.force_remove_container(&name).await;
                return Err(BackendError::Other(format!("ephemeral attach: {e}")));
            }
        };
        let mut output = attach.output;
        let mut input = attach.input;

        // The wait stream is lazy — its request is sent on first poll, which happens
        // inside the join below, concurrently with the drain and BEFORE the
        // auto-removed container can vanish, so the exit code is never lost to the race.
        let mut wait = Box::pin(
            self.docker
                .wait_container(&created.id, None::<WaitContainerOptions<String>>),
        );

        if let Err(e) = self
            .docker
            .start_container::<String>(&created.id, None)
            .await
        {
            self.force_remove_container(&name).await;
            return Err(BackendError::Other(format!("ephemeral start: {e}")));
        }

        // Feed stdin, stream stdout to the sink, and await the exit code — all
        // concurrently, bounded by a backstop timeout. Feeding stdin alongside the
        // drain avoids a full-pipe deadlock on a large piped restore.
        let mut stderr_buf: Vec<u8> = Vec::new();
        let run = async {
            let writer = async {
                if let Some(reader) = stdin.as_mut() {
                    // STREAM stdin in: read a chunk, write it, repeat — never buffer
                    // the (multi-GB) restore payload whole. Symmetric with stdout.
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let n = reader.read(&mut buf).await.map_err(|e| {
                            BackendError::Other(format!("ephemeral stdin read: {e}"))
                        })?;
                        if n == 0 {
                            break;
                        }
                        input.write_all(&buf[..n]).await.map_err(|e| {
                            BackendError::Other(format!("ephemeral stdin write: {e}"))
                        })?;
                    }
                    input
                        .flush()
                        .await
                        .map_err(|e| BackendError::Other(format!("ephemeral stdin flush: {e}")))?;
                }
                // Half-close stdin so the command sees EOF (also when there was none).
                input
                    .shutdown()
                    .await
                    .map_err(|e| BackendError::Other(format!("ephemeral stdin close: {e}")))?;
                Ok::<(), BackendError>(())
            };
            let reader = async {
                while let Some(chunk) = output.next().await {
                    match chunk
                        .map_err(|e| BackendError::Other(format!("ephemeral output: {e}")))?
                    {
                        // TRUE streaming: write each stdout chunk straight to the sink,
                        // never buffering the (multi-GB) payload in memory.
                        LogOutput::StdOut { message } => {
                            stdout.write_all(&message).await.map_err(|e| {
                                BackendError::Other(format!("ephemeral sink write: {e}"))
                            })?;
                        }
                        LogOutput::StdErr { message } | LogOutput::Console { message } => {
                            if stderr_buf.len() < EPHEMERAL_STDERR_CAP {
                                let take =
                                    (EPHEMERAL_STDERR_CAP - stderr_buf.len()).min(message.len());
                                stderr_buf.extend_from_slice(&message[..take]);
                            }
                        }
                        LogOutput::StdIn { .. } => {}
                    }
                }
                stdout
                    .flush()
                    .await
                    .map_err(|e| BackendError::Other(format!("ephemeral sink flush: {e}")))?;
                Ok::<(), BackendError>(())
            };
            let waiter = async {
                match wait.next().await {
                    Some(Ok(resp)) => Ok::<i32, BackendError>(resp.status_code as i32),
                    // bollard maps a NON-ZERO exit to this error — it is a legitimate
                    // exit code (e.g. pg_restore flagging a failed object), returned as-is.
                    Some(Err(bollard::errors::Error::DockerContainerWaitError {
                        code, ..
                    })) => Ok(code as i32),
                    Some(Err(e)) => Err(BackendError::Other(format!("ephemeral wait: {e}"))),
                    None => Ok(0),
                }
            };
            let (w, r, code) = tokio::join!(writer, reader, waiter);
            w?;
            r?;
            code
        };

        let outcome = tokio::time::timeout(self.ephemeral_timeout, run).await;

        // Cleanup: auto_remove should already reap it, but kill-on-timeout +
        // best-effort force-remove guarantee no leaked container or host-port/PID hold.
        if outcome.is_err() {
            let _ = self
                .docker
                .kill_container(&name, None::<KillContainerOptions<String>>)
                .await;
        }
        self.force_remove_container(&name).await;

        match outcome {
            Err(_) => Err(BackendError::Other(format!(
                "ephemeral run timed out after {}s (killed)",
                self.ephemeral_timeout.as_secs()
            ))),
            Ok(Ok(code)) => Ok(code),
            Ok(Err(e)) if stderr_buf.is_empty() => Err(e),
            Ok(Err(e)) => {
                // A bounded stderr tail aids diagnosis. The credential rode in `env`,
                // not in a string, so it cannot reach here — but run the tail through
                // the DSN redactor anyway (defense-in-depth) so a client tool that ever
                // echoed a connection string could not leak it into this error.
                let tail = boatramp_core::redact::redact_dsn(&String::from_utf8_lossy(&stderr_buf));
                Err(BackendError::Other(format!("{e}; stderr: {tail}")))
            }
        }
    }

    async fn replica_direct_host(&self, handle: &InstanceHandle) -> Option<String> {
        // The container name is encoded in the handle ref (fallback to the deterministic
        // name); `container_ip` resolves its bridge IP from an inspect. A sibling
        // ephemeral client on the same daemon bridge reaches that IP directly, even when
        // the operator endpoint is a host-loopback publish (`Published` mode).
        let name = decode_ref(&handle.backend_ref)
            .map(|(n, _, _)| n)
            .unwrap_or_else(|| container_name(&handle.project, &handle.workload, handle.replica));
        self.container_ip(&name).await.ok()
    }
}

/// The generous DEFAULT wall-clock backstop for a single `run_ephemeral` invocation
/// (overridable via [`DockerBackend::with_ephemeral_timeout`]). The real
/// "unreachable DSN" hang is bounded far tighter by the client's own connect timeout
/// (the driver sets `connect_timeout` in the DSN), so this exists only to guarantee a
/// wedged daemon / stuck stream can never pin a container (and the host port/PID budget)
/// forever. Deliberately large so a legitimate multi-hour dump of a big database is not
/// killed mid-flight.
const EPHEMERAL_RUN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// Cap on captured stderr from an ephemeral run (diagnostics only — stdout is the
/// streamed payload). Bounds memory if a failing client floods stderr.
const EPHEMERAL_STDERR_CAP: usize = 64 * 1024;

/// A monotonic suffix so two concurrent ephemeral runs never collide on a container
/// name (the daemon rejects a duplicate name). Combined with the process-start nanos.
static EPHEMERAL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Guest-log forwarding (observability parity with the native container backend)
// ---------------------------------------------------------------------------

/// In-memory bytes buffered per stream between the Docker frame demux and the shared
/// line pump. A full buffer back-pressures the frame reader (then the daemon),
/// bounding memory without dropping lines.
const LOG_DUPLEX_CAP: usize = 64 * 1024;

/// Max CONSECUTIVE rapid reconnect attempts after a transient attach/stream error
/// before the forwarder ends cleanly. Bounded so a flapping daemon can never spin the
/// forwarder; reset after a pass that streamed for [`LOG_RECONNECT_BUDGET_RESET`].
const LOG_MAX_RECONNECTS: u32 = 5;

/// A follow pass that streamed at least this long before a transient error was a
/// healthy connection (not rapid flapping), so the reconnect budget is reset — only a
/// genuine burst of back-to-back failures exhausts [`LOG_MAX_RECONNECTS`].
const LOG_RECONNECT_BUDGET_RESET: std::time::Duration = std::time::Duration::from_secs(30);

/// Why an attach/follow pass returned.
enum FollowOutcome {
    /// The attach stream ended normally (container stopped/removed) — stop.
    Ended,
    /// A transient attach/stream error — reconnect if the container is still running.
    Transient,
}

/// Whether `container_id` is still present + running on the daemon. Decides whether a
/// dropped attach stream means "container gone" (stop) or "transient disconnect".
async fn container_is_running(docker: &Docker, container_id: &str) -> bool {
    match docker.inspect_container(container_id, None).await {
        Ok(info) => info.state.and_then(|s| s.running).unwrap_or(false),
        Err(_) => false,
    }
}

/// The background guest-log forwarder: own one rotating writer for the container's
/// whole life and (re)attach to its stdout/stderr, demuxing the multiplexed Docker
/// frame stream into the shared bounded sink. Best-effort + resilient: a failed logs
/// dir create or a gone container ends it cleanly; a transient daemon disconnect
/// reconnects with capped backoff. Never panics, never busy-loops.
async fn forward_container_logs(
    docker: Docker,
    docker_container_id: String,
    log_id: String,
    logs_dir: PathBuf,
    redactor: Option<std::sync::Arc<boatramp_guestlog::Redactor>>,
) {
    if let Err(e) = tokio::fs::create_dir_all(&logs_dir).await {
        // Operator-facing diagnostic on the module target (NOT the guest stream, and
        // without the daemon socket); no guest logs captured, container unaffected.
        tracing::debug!(
            container = %log_id,
            error = %e,
            "docker guest-log forward: cannot create logs dir; skipping capture"
        );
        return;
    }
    let path = boatramp_guestlog::log_path(&logs_dir, &log_id);
    let (tx, rx) = tokio::sync::mpsc::channel(boatramp_guestlog::CHANNEL_CAP);
    // One rotating writer owns the file across reconnects (appending); it logs its own
    // warn if it dies on an IO error (never silent).
    let writer = tokio::spawn(boatramp_guestlog::run_file_writer(
        path,
        rx,
        boatramp_guestlog::DEFAULT_FILE_CAP_BYTES,
        log_id.clone(),
    ));

    // The reconnect budget counts CONSECUTIVE rapid blips, not a container's lifetime:
    // an attach pass that streamed for a real interval resets it, so only genuine rapid
    // flapping exhausts the cap. The running-check + capped backoff still prevent a
    // busy-loop.
    let mut attempt: u32 = 0;
    loop {
        // Replay the container's existing output only on the FIRST attach (the
        // container is started just before the forwarder spawns). A reconnect follows
        // live only, so a transient blip does not re-dump the whole backlog.
        let replay_backlog = attempt == 0;
        let pass_started = std::time::Instant::now();
        match attach_and_forward(
            &docker,
            &docker_container_id,
            &log_id,
            &tx,
            replay_backlog,
            redactor.clone(),
        )
        .await
        {
            FollowOutcome::Ended => break,
            FollowOutcome::Transient => {
                // A pass that streamed for a while was a healthy connection, not rapid
                // flapping — forgive the earlier blips so the budget bounds only a burst.
                if pass_started.elapsed() >= LOG_RECONNECT_BUDGET_RESET {
                    attempt = 0;
                }
                attempt += 1;
                if attempt > LOG_MAX_RECONNECTS
                    || !container_is_running(&docker, &docker_container_id).await
                {
                    break;
                }
                // Capped exponential backoff so a flapping daemon never busy-loops.
                let backoff = std::time::Duration::from_millis(100u64 << u32::min(attempt, 6));
                tokio::time::sleep(backoff).await;
            }
        }
    }
    drop(tx); // close the channel → the writer drains + flushes + exits
    let _ = writer.await; // run_file_writer already logged any IO error
}

/// Attach to a container's stdout/stderr and forward one follow pass through the sink.
async fn attach_and_forward(
    docker: &Docker,
    docker_container_id: &str,
    log_id: &str,
    tx: &tokio::sync::mpsc::Sender<boatramp_guestlog::GuestLine>,
    replay_backlog: bool,
    redactor: Option<std::sync::Arc<boatramp_guestlog::Redactor>>,
) -> FollowOutcome {
    let attach = match docker
        .attach_container(
            docker_container_id,
            Some(AttachContainerOptions::<String> {
                stdin: Some(false),
                stdout: Some(true),
                stderr: Some(true),
                stream: Some(true),
                logs: Some(replay_backlog),
                detach_keys: None,
            }),
        )
        .await
    {
        Ok(a) => a,
        Err(_e) => {
            // Never echo the daemon socket/url into a log; a plain diagnostic only.
            tracing::debug!(container = %log_id, "docker guest-log forward: attach failed");
            return FollowOutcome::Transient;
        }
    };
    forward_frame_stream(attach.output, log_id, tx, redactor).await
}

/// Demux a multiplexed Docker attach frame stream into per-stream byte pipes and
/// reuse the shared [`boatramp_guestlog::pump`] (line-splitting + per-line cap +
/// sanitize + tracing) on each, feeding the shared writer `tx`. Pure over the frame
/// stream, so it is unit-tested with a synthetic `LogOutput` stream (no daemon).
async fn forward_frame_stream<S>(
    mut output: S,
    log_id: &str,
    tx: &tokio::sync::mpsc::Sender<boatramp_guestlog::GuestLine>,
    redactor: Option<std::sync::Arc<boatramp_guestlog::Redactor>>,
) -> FollowOutcome
where
    S: futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    // One in-memory pipe per stream: the read half (as AsyncBufRead) is drained by
    // the shared pump; the write half receives the demuxed frame payloads.
    let (mut out_w, out_r) = tokio::io::duplex(LOG_DUPLEX_CAP);
    let (mut err_w, err_r) = tokio::io::duplex(LOG_DUPLEX_CAP);
    // `keep_draining = false`: the REMOTE path has no local guest pipe to protect (the
    // reader is an in-memory duplex fed from the attach stream), so the pump may stop
    // once the writer is gone and let the forwarder wind down.
    let (id_out, tx_out, r_out) = (log_id.to_string(), tx.clone(), redactor.clone());
    let p_out = tokio::spawn(async move {
        boatramp_guestlog::pump(
            tokio::io::BufReader::new(out_r),
            &id_out,
            "stdout",
            tx_out,
            false,
            r_out,
        )
        .await
    });
    let (id_err, tx_err) = (log_id.to_string(), tx.clone());
    let p_err = tokio::spawn(async move {
        boatramp_guestlog::pump(
            tokio::io::BufReader::new(err_r),
            &id_err,
            "stderr",
            tx_err,
            false,
            redactor,
        )
        .await
    });

    let mut outcome = FollowOutcome::Ended;
    while let Some(frame) = output.next().await {
        match frame {
            Ok(LogOutput::StdOut { message }) => {
                // A write error means the stdout pump ended (writer gone); stop.
                if out_w.write_all(&message).await.is_err() {
                    break;
                }
            }
            Ok(LogOutput::StdErr { message }) | Ok(LogOutput::Console { message }) => {
                if err_w.write_all(&message).await.is_err() {
                    break;
                }
            }
            Ok(LogOutput::StdIn { .. }) => {}
            Err(_e) => {
                tracing::debug!(
                    container = %log_id,
                    "docker guest-log forward: attach stream error"
                );
                outcome = FollowOutcome::Transient;
                break;
            }
        }
    }
    // Close the write halves → the pumps see EOF, drain any buffered partial line, and
    // finish. `tx` stays open (owned by the caller) so the writer persists across a
    // reconnect.
    drop(out_w);
    drop(err_w);
    let _ = p_out.await;
    let _ = p_err.await;
    outcome
}

/// A unique, daemon-safe container name for a one-shot ephemeral run.
fn ephemeral_container_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = EPHEMERAL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("boatramp-ephemeral-{nanos}-{seq}")
}

impl DockerBackend {
    /// Best-effort force-remove a container by name (ignores "no such container"). Used
    /// to reap an ephemeral container on every exit path — including a created-but-never-
    /// started one that `auto_remove` would NOT reap.
    async fn force_remove_container(&self, name: &str) {
        let _ = self
            .docker
            .remove_container(
                name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    /// Pull `reference` from its registry (reused by `materialize` and the one-shot
    /// `run_ephemeral` client pull) and return the fully-qualified reference actually
    /// pulled.
    ///
    /// Split the reference into `from_image` + `tag`, defaulting an untagged reference
    /// to `:latest`. Without a tag the daemon's `fromImage=<name>` (no `tag`) pulls
    /// **every** tag of the repo — slow, and 501s on any repo that still carries an
    /// ancient v1-manifest tag. A digest-pinned reference is passed whole (no tag).
    async fn pull_image(
        &self,
        reference: &str,
        auth: Option<&RegistryAuth>,
    ) -> Result<String, BackendError> {
        let (from_image, tag) = image_pull_target(reference);
        let options = CreateImageOptions {
            from_image: from_image.clone(),
            tag: tag.clone(),
            ..Default::default()
        };
        // When a credential was resolved (a private image), pass it as bollard's
        // `X-Registry-Auth`; `None` ⇒ an anonymous pull. The credential lives only in
        // this transient `DockerCredentials` (a `RegistryAuth` with redacting `Debug`),
        // never in the error path below — a failed pull surfaces the daemon's status
        // message, never the token.
        let credentials = auth.map(docker_credentials);
        let mut pull = self.docker.create_image(Some(options), None, credentials);
        while let Some(step) = pull.next().await {
            // NB: `e` is the daemon's pull error (an HTTP status / manifest message),
            // which never carries the submitted credential — safe to surface + redacted
            // of any DSN shape by the shared redactor as defense-in-depth.
            step.map_err(|e| {
                BackendError::Materialize(boatramp_core::redact::redact_dsn(&format!(
                    "pull {reference}: {e}"
                )))
            })?;
        }
        Ok(if tag.is_empty() {
            reference.to_string()
        } else {
            format!("{from_image}:{tag}")
        })
    }

    /// Whether `reference` is already present in the daemon's **local image store** — a
    /// successful `inspect_image` (by name:tag or digest) means a launch can use it without
    /// a registry pull. Any inspect error (a 404 "no such image", or a daemon hiccup) is
    /// treated as "not present", so the caller falls back to a pull under `IfNotPresent` and
    /// fails closed under `Never` — never a false "present". This is the `IfNotPresent` /
    /// `Never` arm of [`materialize`](DockerBackend::materialize); see [`PullPolicy`] for the
    /// shared-store tenancy caveat that keeps `Always` the default.
    async fn image_present(&self, reference: &str) -> bool {
        self.docker.inspect_image(reference).await.is_ok()
    }

    /// The container's primary IPv4 address (the default bridge, or the first
    /// network it's attached to).
    async fn container_ip(&self, id: &str) -> Result<String, BackendError> {
        let info = self
            .docker
            .inspect_container(id, None)
            .await
            .map_err(|e| BackendError::Launch(format!("inspect {id}: {e}")))?;
        let networks = info
            .network_settings
            .ok_or_else(|| BackendError::Launch("container has no network settings".into()))?;
        // Prefer the top-level address, else the first non-empty network IP.
        if let Some(ip) = networks.ip_address.filter(|s| !s.is_empty()) {
            return Ok(ip);
        }
        if let Some(nets) = networks.networks {
            for net in nets.values() {
                if let Some(ip) = net.ip_address.as_ref().filter(|s| !s.is_empty()) {
                    return Ok(ip.clone());
                }
            }
        }
        Err(BackendError::Launch("container has no IP address".into()))
    }

    /// The host port Docker assigned to a published container port (`<port>/tcp`),
    /// read back from the container's network settings after start.
    async fn published_host_port(&self, id: &str, port_key: &str) -> Result<u16, BackendError> {
        let info = self
            .docker
            .inspect_container(id, None)
            .await
            .map_err(|e| BackendError::Launch(format!("inspect {id}: {e}")))?;
        info.network_settings
            .and_then(|ns| ns.ports)
            .and_then(|mut ports| ports.remove(port_key).flatten())
            .and_then(|bindings| bindings.into_iter().next())
            .and_then(|b| b.host_port)
            .and_then(|hp| hp.parse::<u16>().ok())
            .ok_or_else(|| {
                BackendError::Launch(format!("no published host port for {port_key} on {id}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::{Arc, Mutex, OnceLock};

    // --- guest-log forwarding: the demux wiring over a synthetic frame stream ---

    /// A synthetic multiplexed attach stream (always-`Ok` frames), like bollard's.
    fn frame_stream(
        frames: Vec<LogOutput>,
    ) -> impl futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Unpin {
        futures::stream::iter(frames.into_iter().map(Ok))
    }

    /// A `MakeWriter` over a shared buffer so a `tracing` fmt subscriber's output can
    /// be asserted. Installed ONCE as the global default so events from the pump's
    /// spawned tasks (any thread) are captured.
    #[derive(Clone)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CaptureWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    static TRACING_CAPTURE: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    fn install_tracing_capture() -> Arc<Mutex<Vec<u8>>> {
        TRACING_CAPTURE
            .get_or_init(|| {
                let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
                let w = buf.clone();
                let subscriber = tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::DEBUG)
                    .with_writer(move || CaptureWriter(w.clone()))
                    .finish();
                let _ = tracing::subscriber::set_global_default(subscriber);
                buf
            })
            .clone()
    }

    async fn spawn_writer(
        path: std::path::PathBuf,
    ) -> (
        tokio::sync::mpsc::Sender<boatramp_guestlog::GuestLine>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(boatramp_guestlog::CHANNEL_CAP);
        let writer = tokio::spawn(boatramp_guestlog::write_lines_rotating(
            path,
            rx,
            boatramp_guestlog::DEFAULT_FILE_CAP_BYTES,
        ));
        (tx, writer)
    }

    /// The forwarder reassembles lines across frame boundaries, routes each stream to
    /// its own tag, folds `Console` into stderr, and writes exactly one physical line
    /// per logical line — the core demux contract (mutating any of these turns it RED).
    #[tokio::test]
    async fn forward_frame_stream_demuxes_both_streams_into_the_shared_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = boatramp_guestlog::log_path(dir.path(), "demux-0");
        let (tx, writer) = spawn_writer(path.clone()).await;
        // A stdout line is split mid-word across two frames, with a stderr frame
        // interleaved between them.
        let stream = frame_stream(vec![
            LogOutput::StdOut {
                message: Bytes::from_static(b"app star"),
            },
            LogOutput::StdErr {
                message: Bytes::from_static(b"warn-1\n"),
            },
            LogOutput::StdOut {
                message: Bytes::from_static(b"ted\napp ready\n"),
            },
            LogOutput::Console {
                message: Bytes::from_static(b"console-line\n"),
            },
        ]);
        let _ = forward_frame_stream(stream, "demux-0", &tx, None).await;
        drop(tx);
        writer.await.unwrap().unwrap();

        let s = std::fs::read_to_string(&path).unwrap();
        assert!(
            s.contains("stdout: app started\n"),
            "stdout line reassembled across frames: {s}"
        );
        assert!(s.contains("stdout: app ready\n"), "{s}");
        assert!(s.contains("stderr: warn-1\n"), "{s}");
        assert!(
            s.contains("stderr: console-line\n"),
            "Console folds into stderr: {s}"
        );
        assert_eq!(
            s.lines().count(),
            4,
            "one physical line per logical line: {s}"
        );
    }

    /// A single huge no-newline frame must not grow the file/memory without bound: it
    /// is capped to ONE truncated line by the shared sink's per-line cap.
    #[tokio::test]
    async fn forward_frame_stream_caps_a_no_newline_flood() {
        let dir = tempfile::tempdir().unwrap();
        let path = boatramp_guestlog::log_path(dir.path(), "flood-0");
        let (tx, writer) = spawn_writer(path.clone()).await;
        let mut flood = vec![b'A'; boatramp_guestlog::MAX_LINE_BYTES * 8];
        flood.push(b'\n'); // close the line so it flushes
        let stream = frame_stream(vec![LogOutput::StdOut {
            message: Bytes::from(flood),
        }]);
        let _ = forward_frame_stream(stream, "flood-0", &tx, None).await;
        drop(tx);
        writer.await.unwrap().unwrap();

        let s = std::fs::read_to_string(&path).unwrap();
        assert_eq!(s.lines().count(), 1, "the whole flood is ONE capped line");
        let physical = s.lines().next().unwrap();
        assert!(
            physical.len() < boatramp_guestlog::MAX_LINE_BYTES * 2,
            "line bounded by the per-line cap (got {} for an {}-byte flood)",
            physical.len(),
            boatramp_guestlog::MAX_LINE_BYTES * 8
        );
    }

    /// Each forwarded line is ALSO mirrored to structured `tracing` on the
    /// `boatramp::guest` target, tagged with the container id + stream — the other half
    /// of sink parity with the native backend.
    #[tokio::test]
    async fn forward_frame_stream_mirrors_lines_to_tracing() {
        let buf = install_tracing_capture();
        let dir = tempfile::tempdir().unwrap();
        let path = boatramp_guestlog::log_path(dir.path(), "tracing-0");
        let (tx, writer) = spawn_writer(path.clone()).await;
        let marker = "GUESTLOG_TRACE_MARK_42";
        let stream = frame_stream(vec![LogOutput::StdOut {
            message: Bytes::from(format!("{marker}\n").into_bytes()),
        }]);
        // forward_frame_stream awaits its pump tasks, so every `tracing::info!` has
        // fired (synchronously into the fmt subscriber) by the time it returns.
        let _ = forward_frame_stream(stream, "tracing-0", &tx, None).await;
        drop(tx);
        writer.await.unwrap().unwrap();

        let logged = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
        assert!(
            logged.contains(marker),
            "line mirrored to tracing: {logged}"
        );
        assert!(logged.contains("boatramp::guest"), "guest target: {logged}");
        assert!(
            logged.contains("tracing-0"),
            "container tag present: {logged}"
        );
        assert!(logged.contains("stdout"), "stream tag present: {logged}");
    }

    /// Guest-log secret redaction binds in the docker forwarder's demux path: a secret
    /// value supplied to the forwarder (the per-launch redaction set) is replaced with the
    /// placeholder in BOTH the per-container FILE and the `boatramp::guest` tracing stream,
    /// while a benign line is untouched. Mutation-sensitive: dropping the redactor (the
    /// opt-out / a removed redact step) leaves the secret in both → the `!contains` RED.
    #[tokio::test]
    async fn forward_frame_stream_redacts_a_secret_in_both_file_and_tracing() {
        let buf = install_tracing_capture();
        let dir = tempfile::tempdir().unwrap();
        let path = boatramp_guestlog::log_path(dir.path(), "redact-fwd-0");
        let (tx, writer) = spawn_writer(path.clone()).await;
        // A unique, long secret value (≥ the min-length floor) carried in the per-launch set.
        let secret = "postgres://u:P%40ss_FWD_UNIQ_c0ffee99@bramp-db-z.flycast:5432/app";
        let redactor = boatramp_guestlog::Redactor::build([secret]).expect("qualifies");
        let stream = frame_stream(vec![
            LogOutput::StdOut {
                message: Bytes::from(format!("DATABASE_URL={secret}\n").into_bytes()),
            },
            LogOutput::StdErr {
                message: Bytes::from_static(b"benign stderr line\n"),
            },
        ]);
        let _ = forward_frame_stream(stream, "redact-fwd-0", &tx, Some(redactor)).await;
        drop(tx);
        writer.await.unwrap().unwrap();

        let file = std::fs::read_to_string(&path).unwrap();
        assert!(
            !file.contains(secret),
            "secret leaked into the file: {file}"
        );
        assert!(
            file.contains(boatramp_guestlog::REDACTED_PLACEHOLDER),
            "file missing the placeholder: {file}"
        );
        assert!(
            file.contains("benign stderr line"),
            "benign line survives: {file}"
        );

        let logged = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
        assert!(
            !logged.contains(secret),
            "secret leaked into tracing: {logged}"
        );
        assert!(
            logged.contains(boatramp_guestlog::REDACTED_PLACEHOLDER),
            "tracing missing the placeholder: {logged}"
        );
    }

    /// The two-tier opt-out, wired through the docker backend's `build_log_redactor` (v0.70.0).
    /// Mirror of the native container backend's binding: the per-project opt-out flag on the
    /// request + the two node-global flags reach `boatramp_guestlog::should_redact` (whose full
    /// matrix is unit-tested in the guestlog crate), proving the docker path is CONNECTED too —
    /// including that an admitted opt-out disables redaction for only the opted-out request.
    #[test]
    fn build_log_redactor_honors_the_two_tier_opt_out() {
        // `with_client` connects lazily (no daemon needed to construct the backend).
        let backend = || DockerBackend::with_client(Docker::connect_with_defaults().unwrap());
        let req = |project_opt_out: bool| {
            let mut redaction = boatramp_core::compute::RedactionSet::new();
            redaction.push("postgres://u:P%40ss_FWD_UNIQ_dd11@bramp-db.flycast:5432/app".into());
            redaction.set_project_opt_out(project_opt_out);
            LaunchRequest {
                project: "proj".into(),
                workload: "w".into(),
                replica: 0,
                spec: ComputeSpec::builder(RootSource::Image("img:latest".into()), 1, 128, 0)
                    .build(),
                artifact: Artifact::Image {
                    reference: "img:latest".into(),
                },
                redaction,
                priority_class: None,
            }
        };

        // Default posture (redact on, admission off): opt-out IGNORED → redactor built either way.
        assert!(backend().build_log_redactor(&req(false)).is_some());
        assert!(
            backend().build_log_redactor(&req(true)).is_some(),
            "opt-out ignored unless the node admits per-project overrides"
        );

        // Admission on: the opt-out is honored for the opted-out request ONLY.
        let admit = backend().with_per_project_redaction_override(true);
        assert!(
            admit.build_log_redactor(&req(false)).is_some(),
            "a project that did not opt out still redacts on an admitting node"
        );
        assert!(
            admit.build_log_redactor(&req(true)).is_none(),
            "an admitted per-project opt-out disables redaction for that project"
        );

        // Node default off: never redact.
        let off = backend().with_guest_log_redaction(false);
        assert!(off.build_log_redactor(&req(false)).is_none());
    }

    /// Build a `ContainerState` with a given `Status` (+ optional running bool / health),
    /// the shape `inspect` returns, for the pure health-mapping tests.
    fn state(
        status: Option<ContainerStateStatusEnum>,
        running: Option<bool>,
        health: Option<HealthStatusEnum>,
    ) -> ContainerState {
        ContainerState {
            status,
            running,
            health: health.map(|status| bollard::models::Health {
                status: Some(status),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Bug B: health reflects the ACTUAL container state. A crash-looping container
    /// (`Status: "restarting"`, kept alive in place by its restart policy) must report
    /// `Unhealthy`, NOT the masked `Healthy` the old `Running`-bool-only check produced —
    /// so `compute status` surfaces a crash loop instead of a dead workload reading "up".
    #[test]
    fn health_maps_restarting_and_exited_to_unhealthy() {
        use ContainerStateStatusEnum::*;
        // The bug: a restart loop. `Running` can even be momentarily true mid-restart.
        assert_eq!(
            health_from_state(Some(&state(Some(RESTARTING), Some(true), None))),
            Health::Unhealthy,
            "a restarting (crash-looping) container is NOT healthy"
        );
        assert_eq!(
            health_from_state(Some(&state(Some(EXITED), Some(false), None))),
            Health::Unhealthy
        );
        assert_eq!(
            health_from_state(Some(&state(Some(DEAD), Some(false), None))),
            Health::Unhealthy
        );
        assert_eq!(
            health_from_state(Some(&state(Some(CREATED), Some(false), None))),
            Health::Unhealthy
        );
        // A paused container reports Running=true but is not serving — Status rules.
        assert_eq!(
            health_from_state(Some(&state(Some(PAUSED), Some(true), None))),
            Health::Unhealthy
        );
    }

    /// Bug B: only a genuinely running container (healthcheck not reporting unhealthy) is
    /// `Healthy`; a declared healthcheck that has gone unhealthy overrides a bare running,
    /// while a `starting` healthcheck does not (runner-level health is "process up").
    #[test]
    fn health_maps_running_respecting_the_healthcheck() {
        use ContainerStateStatusEnum::RUNNING;
        assert_eq!(
            health_from_state(Some(&state(Some(RUNNING), Some(true), None))),
            Health::Healthy,
            "a plain running container with no healthcheck is healthy"
        );
        assert_eq!(
            health_from_state(Some(&state(
                Some(RUNNING),
                Some(true),
                Some(HealthStatusEnum::STARTING)
            ))),
            Health::Healthy,
            "a still-starting healthcheck does not fail runner-level health"
        );
        assert_eq!(
            health_from_state(Some(&state(
                Some(RUNNING),
                Some(true),
                Some(HealthStatusEnum::UNHEALTHY)
            ))),
            Health::Unhealthy,
            "an app declaring itself unhealthy overrides a bare running"
        );
        // Older daemon (no Status string): fall back to the Running bool.
        assert_eq!(
            health_from_state(Some(&state(None, Some(true), None))),
            Health::Healthy
        );
        assert_eq!(
            health_from_state(Some(&state(None, Some(false), None))),
            Health::Unhealthy
        );
        // No State at all (gone / unreachable): unhealthy.
        assert_eq!(health_from_state(None), Health::Unhealthy);
    }

    /// Bug A/C auto-heal idempotency: only a container already on its per-project net as
    /// PRIMARY is current; a bridge/default/absent primary is stale (→ recreate).
    #[test]
    fn primary_network_current_only_when_it_is_the_project_net() {
        let expected = project_network_name("acme"); // "boatramp-net-acme"
        assert!(primary_network_is_current(Some(&expected), &expected));
        // Pre-fix shapes a v0.55.0/earlier container would report:
        assert!(!primary_network_is_current(Some("bridge"), &expected));
        assert!(!primary_network_is_current(Some("default"), &expected));
        assert!(!primary_network_is_current(Some(""), &expected));
        assert!(!primary_network_is_current(None, &expected));
        // A DIFFERENT project's net is also not current (never cross-heal).
        assert!(!primary_network_is_current(
            Some("boatramp-net-other"),
            &expected
        ));
    }

    /// Bug D upgrade-path auto-heal idempotency: a container is "alias-current" only when it
    /// advertises the CURRENT `managed_db_alias(workload)` on its net. A pre-fix container still
    /// carrying its OLD (long) `--network-alias` is stale (→ recreate so the producer re-aliases),
    /// while a short-named workload computes the SAME alias and is never spuriously recreated.
    #[test]
    fn container_alias_current_only_when_it_advertises_the_current_managed_db_alias() {
        // A long (>63-octet) managed-DB workload name whose current alias is the short hash.
        let workload = "bramp-db-0xk8mhgah7gfb4e2ivmj05ixx-simertec-stg_backoffice_db_0123456789";
        assert!(workload.len() > 63, "fixture must exceed the DNS label cap");
        let current = managed_db_alias(workload); // the <=63 alias `launch` now publishes
        assert!(current.len() <= 63);
        assert_ne!(current, workload);
        // Current alias present among the live aliases (Docker also lists the short id) → current.
        let live_current = vec!["0123456789ab".to_string(), current.clone()];
        assert!(container_alias_is_current(Some(&live_current), &current));
        // Pre-fix container: only the OLD raw (long) workload-name alias is published → stale.
        let live_old = vec![workload.to_string()];
        assert!(!container_alias_is_current(Some(&live_old), &current));
        // No aliases / empty ⇒ stale (recreate), matching the net-mismatch heal.
        assert!(!container_alias_is_current(None, &current));
        assert!(!container_alias_is_current(Some(&[]), &current));
        // A short workload name maps to itself, so a container carrying it is current.
        let short_alias = managed_db_alias("pg");
        assert_eq!(short_alias, "pg");
        assert!(container_alias_is_current(
            Some(&["pg".to_string()]),
            &short_alias
        ));
    }

    #[test]
    fn docker_credentials_maps_registry_auth_and_never_leaks_the_secret() {
        // The resolved credential maps 1:1 to bollard's basic-auth fields…
        let auth = RegistryAuth {
            username: "robot".into(),
            password: "sup3r-s3cret-token".into(),
            serveraddress: "ghcr.io".into(),
        };
        let dc = docker_credentials(&auth);
        assert_eq!(dc.username.as_deref(), Some("robot"));
        assert_eq!(dc.password.as_deref(), Some("sup3r-s3cret-token"));
        assert_eq!(dc.serveraddress.as_deref(), Some("ghcr.io"));
        assert!(dc.auth.is_none() && dc.identitytoken.is_none());

        // …and the SOURCE credential type redacts its password under `{:?}` (the shape a
        // careless log/tracing/error takes), so the token can never reach a diagnostic
        // via the backend. Mutating `RegistryAuth`'s Debug to print the password turns
        // this RED (defense-in-depth over the core redaction test).
        let dbg = format!("{auth:?}");
        assert!(
            !dbg.contains("sup3r-s3cret-token"),
            "token leaked via Debug: {dbg}"
        );
    }

    #[test]
    fn image_pull_target_defaults_untagged_to_latest() {
        // Bare name -> latest (the papercut fix: no more all-tags pull).
        assert_eq!(
            image_pull_target("alpine"),
            ("alpine".into(), "latest".into())
        );
        assert_eq!(
            image_pull_target("ghcr.io/owner/app"),
            ("ghcr.io/owner/app".into(), "latest".into())
        );
        // Explicit tag is preserved.
        assert_eq!(
            image_pull_target("nginx:1.27"),
            ("nginx".into(), "1.27".into())
        );
        // A registry host:port is NOT mistaken for a tag.
        assert_eq!(
            image_pull_target("localhost:5000/app"),
            ("localhost:5000/app".into(), "latest".into())
        );
        assert_eq!(
            image_pull_target("localhost:5000/app:v2"),
            ("localhost:5000/app".into(), "v2".into())
        );
        // A digest-pinned reference is passed whole, no tag.
        let d = "alpine@sha256:abc123";
        assert_eq!(image_pull_target(d), (d.into(), String::new()));
    }

    #[test]
    fn pull_action_default_always_pulls_even_when_present() {
        // The safe default re-pulls regardless of what the shared local store holds, so a
        // locally-cached `name:tag` can never shadow the registry (the tenancy guarantee).
        assert_eq!(pull_action(PullPolicy::Always, true), PullAction::Pull);
        assert_eq!(pull_action(PullPolicy::Always, false), PullAction::Pull);
    }

    #[test]
    fn pull_action_if_not_present_reuses_a_local_image() {
        // The item-#3 capability: a locally-present image (a `docker load`'d tarball) is
        // used WITHOUT a registry round-trip; an absent one still pulls.
        assert_eq!(
            pull_action(PullPolicy::IfNotPresent, true),
            PullAction::UseLocal
        );
        assert_eq!(
            pull_action(PullPolicy::IfNotPresent, false),
            PullAction::Pull
        );
    }

    #[test]
    fn pull_action_never_requires_a_local_image() {
        // `Never` reuses a present image and fails (never pulls) when absent — the
        // air-gapped posture.
        assert_eq!(pull_action(PullPolicy::Never, true), PullAction::UseLocal);
        assert_eq!(
            pull_action(PullPolicy::Never, false),
            PullAction::FailAbsent
        );
    }

    #[test]
    fn local_reuse_refused_only_under_multi_tenant() {
        // F1: a reuse policy is refused when reuse is not allowed (multi-tenant guard) and
        // honored (not refused) when allowed (single-tenant). `Always` is never a reuse, so
        // it is never refused under either posture.
        assert!(local_reuse_refused(PullPolicy::IfNotPresent, false));
        assert!(local_reuse_refused(PullPolicy::Never, false));
        assert!(!local_reuse_refused(PullPolicy::IfNotPresent, true));
        assert!(!local_reuse_refused(PullPolicy::Never, true));
        assert!(!local_reuse_refused(PullPolicy::Always, false));
        assert!(!local_reuse_refused(PullPolicy::Always, true));
    }

    #[tokio::test]
    async fn materialize_refuses_local_reuse_under_multi_tenant_and_admits_it_single_tenant() {
        let docker = Docker::connect_with_defaults().unwrap();
        let spec = |policy: PullPolicy| {
            ComputeSpec::builder(RootSource::Image("acme/app:local".into()), 1, 128, 0)
                .pull_policy(policy)
                .build()
        };

        // Multi-tenant (reuse NOT allowed, the default): `if-not-present` is REFUSED with the
        // posture error, before any daemon round-trip.
        let mt = DockerBackend::with_client(docker.clone());
        let err = mt
            .materialize("p", "w", &spec(PullPolicy::IfNotPresent), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BackendError::Materialize(m) if m.contains("multi-tenant posture")),
            "expected a multi-tenant posture refusal, got {err:?}"
        );

        // Single-tenant (reuse allowed): the posture gate PASSES — `never` then reaches the
        // local-store decision and (no daemon/image here) fails with the distinct
        // "not present / pull_policy=never" error, proving reuse was admitted, not refused.
        let st = DockerBackend::with_client(docker).with_local_image_reuse_allowed(true);
        let err = st
            .materialize("p", "w", &spec(PullPolicy::Never), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BackendError::Materialize(m)
                if m.contains("not present") && !m.contains("multi-tenant posture")),
            "expected the admitted `never`-absent error, got {err:?}"
        );
    }

    #[test]
    fn docker_endpoint_defaults_to_published_and_parses_lowercase() {
        // Default is the portable, host-reachable mode.
        assert_eq!(DockerEndpoint::default(), DockerEndpoint::Published);
        // Config deserializes the lowercase names.
        assert_eq!(
            serde_json::from_str::<DockerEndpoint>("\"published\"").unwrap(),
            DockerEndpoint::Published
        );
        assert_eq!(
            serde_json::from_str::<DockerEndpoint>("\"bridge\"").unwrap(),
            DockerEndpoint::Bridge
        );
    }

    #[test]
    fn name_and_ref_round_trip() {
        // Default project keeps the bare name (byte-identical to pre-v0.3.12);
        // a non-default project qualifies it so two projects' `web/0` never collide.
        assert_eq!(container_name("default", "web", 0), "boatramp-web-0");
        assert_eq!(container_name("acme", "web", 0), "boatramp-acme-web-0");
        assert_ne!(
            container_name("acme", "web", 0),
            container_name("beta", "web", 0)
        );
        let r = encode_ref("boatramp-web-0", "172.17.0.3", 8080);
        assert_eq!(r, "boatramp-web-0@172.17.0.3:8080");
        assert_eq!(
            decode_ref(&r),
            Some(("boatramp-web-0".to_string(), "172.17.0.3".to_string(), 8080))
        );
        assert_eq!(decode_ref("garbage"), None);
    }

    #[test]
    fn host_config_is_hardened_by_default() {
        let hc = hardened_host_config(256, 2, RestartPolicy::Never, false, &[]);
        // Resource limits still applied.
        assert_eq!(hc.memory, Some(256 * 1024 * 1024));
        assert_eq!(hc.nano_cpus, Some(2_000_000_000));
        assert_eq!(hc.pids_limit, Some(MAX_PIDS));
        // Hardening: no escalation, no caps, read-only rootfs.
        assert_eq!(
            hc.security_opt.as_deref(),
            Some(["no-new-privileges:true".to_string()].as_slice())
        );
        assert_eq!(hc.cap_drop.as_deref(), Some(["ALL".to_string()].as_slice()));
        // No capabilities added back by default.
        assert_eq!(hc.cap_add, None);
        assert_eq!(hc.readonly_rootfs, Some(true));
        // A read-only rootfs stays usable via small noexec/nosuid scratch mounts.
        let tmpfs = hc.tmpfs.expect("tmpfs mounts for a read-only rootfs");
        assert!(tmpfs.get("/tmp").is_some_and(|o| o.contains("noexec")));
        // /run must be world-writable + sticky (mode=1777): Docker defaults a bare
        // /run tmpfs to 0755 root:root, which a non-root image (e.g. a stock Postgres
        // creating /var/run/postgresql for its socket) cannot write. Regression guard.
        assert!(tmpfs.get("/run").is_some_and(|o| o.contains("mode=1777")));
        assert!(tmpfs.get("/tmp").is_some_and(|o| o.contains("mode=1777")));
        // At least one vCPU even when the spec asks for zero.
        assert_eq!(
            hardened_host_config(64, 0, RestartPolicy::Never, false, &[]).nano_cpus,
            Some(1_000_000_000)
        );
    }

    #[test]
    fn writable_root_relaxes_only_the_read_only_root() {
        let hc = hardened_host_config(256, 2, RestartPolicy::Never, true, &[]);
        // The one relaxation.
        assert_eq!(hc.readonly_rootfs, Some(false));
        // Every other hardening still applies.
        assert_eq!(
            hc.security_opt.as_deref(),
            Some(["no-new-privileges:true".to_string()].as_slice())
        );
        assert_eq!(hc.cap_drop.as_deref(), Some(["ALL".to_string()].as_slice()));
        assert_eq!(hc.cap_add, None);
        assert_eq!(hc.pids_limit, Some(MAX_PIDS));
    }

    #[test]
    fn cap_add_adds_back_only_the_allowlist() {
        let caps = ["CHOWN".to_string(), "SETUID".to_string()];
        let hc = hardened_host_config(256, 2, RestartPolicy::Never, false, &caps);
        // The allowlist is added back on top of the retained drop-ALL.
        assert_eq!(hc.cap_drop.as_deref(), Some(["ALL".to_string()].as_slice()));
        assert_eq!(hc.cap_add.as_deref(), Some(caps.as_slice()));
        // Adding caps does not relax any other hardening.
        assert_eq!(
            hc.security_opt.as_deref(),
            Some(["no-new-privileges:true".to_string()].as_slice())
        );
        assert_eq!(hc.readonly_rootfs, Some(true));
    }

    #[test]
    fn writable_root_is_off_by_default_on_the_backend() {
        // A backend built without the posture opt-in refuses to honor writable_root.
        let docker = Docker::connect_with_defaults().unwrap();
        let backend = DockerBackend::with_client(docker);
        assert!(!backend.writable_root_allowed);
        assert!(
            backend
                .with_writable_root_allowed(true)
                .writable_root_allowed,
            "the single-tenant posture opts in"
        );
    }

    #[test]
    fn parse_uid_gid_handles_uid_and_uid_gid() {
        assert_eq!(parse_uid_gid("999"), Some((999, 999)));
        assert_eq!(parse_uid_gid("1000:1001"), Some((1000, 1001)));
        // A non-numeric user (an image username) is left to Docker to resolve.
        assert_eq!(parse_uid_gid("postgres"), None);
        assert_eq!(parse_uid_gid("999:abc"), None);
    }

    #[test]
    fn cap_add_is_off_by_default_on_the_backend() {
        // Without the posture opt-in the backend keeps every capability dropped.
        let docker = Docker::connect_with_defaults().unwrap();
        let backend = DockerBackend::with_client(docker);
        assert!(!backend.cap_add_allowed);
        assert!(
            backend.with_cap_add_allowed(true).cap_add_allowed,
            "the single-tenant posture opts in"
        );
    }

    #[test]
    fn named_volume_mode_builds_a_prefixed_daemon_volume_mount() {
        let vol = VolumeRef::new("/data", "db", 64);
        let m = volume_mount(&vol, DockerVolumeMode::Named, Path::new("/srv/data"));
        assert_eq!(m.typ, Some(MountTypeEnum::VOLUME));
        // Prefixed so it never clobbers an unrelated volume on a shared daemon.
        assert_eq!(m.source.as_deref(), Some("boatramp-db"));
        assert_eq!(m.target.as_deref(), Some("/data"));
        assert_eq!(m.read_only, Some(false), "a persistent volume is writable");
    }

    #[test]
    fn bind_volume_mode_builds_a_host_path_mount() {
        let vol = VolumeRef::new("/data", "db", 64);
        let m = volume_mount(&vol, DockerVolumeMode::Bind, Path::new("/srv/data"));
        assert_eq!(m.typ, Some(MountTypeEnum::BIND));
        assert_eq!(m.source.as_deref(), Some("/srv/data/compute/volumes/db"));
        assert_eq!(m.target.as_deref(), Some("/data"));
        assert_eq!(m.read_only, Some(false));
    }

    #[test]
    fn validate_volume_rejects_traversal_in_name_and_mount() {
        assert!(validate_volume("db", "/data").is_ok());
        assert!(validate_volume("cache-1", "/var/lib/app").is_ok());
        // A name must be a single path component.
        assert!(validate_volume("../etc", "/data").is_err());
        assert!(validate_volume("a/b", "/data").is_err());
        // A mount must be absolute with no `..`.
        assert!(validate_volume("db", "relative").is_err());
        assert!(validate_volume("db", "/data/../etc").is_err());
    }

    #[tokio::test]
    async fn remove_volume_rejects_a_traversing_name() {
        // Security: the destructive volume-removal path must reject a multi-component /
        // traversing name BEFORE it builds any daemon volume name or host path from it,
        // so it can only ever target a volume THIS backend named. `validate_volume` runs
        // first, so this fails without ever reaching the daemon (no live docker needed).
        let docker = Docker::connect_with_defaults().unwrap();
        let named = DockerBackend::with_client(docker);
        assert!(named.remove_volume("../etc").await.is_err());
        assert!(named.remove_volume("a/b").await.is_err());
        assert!(named.remove_volume("/abs").await.is_err());
        // DiD (Finding 4): a native-container SCOPED volume dir (`@<scope>`) is never a
        // docker volume — docker must refuse to address one even when the `data_dir` is
        // shared, so it can't `remove_dir_all` another backend's PGDATA.
        assert!(named.remove_volume("@acme@pg-x").await.is_err());
        // Same guards in Bind mode (the host-path removal), all before touching the fs.
        let docker2 = Docker::connect_with_defaults().unwrap();
        let bind = DockerBackend::with_client(docker2).with_volume_mode(DockerVolumeMode::Bind);
        assert!(bind.remove_volume("..").await.is_err());
        assert!(bind.remove_volume("x/y").await.is_err());
        assert!(bind.remove_volume("@acme@pg-x").await.is_err());
    }

    #[tokio::test]
    async fn bind_mode_lists_and_removes_only_its_own_volumes() {
        // The Bind-mode volume lifecycle end to end on the filesystem (no daemon): a
        // staged volume dir is listed, removed (reports it existed), and removing it
        // again reports it is gone — the idempotent `db drop database` reclaim shape.
        let data = tempfile::tempdir().unwrap();
        let docker = Docker::connect_with_defaults().unwrap();
        let backend = DockerBackend::with_client(docker)
            .with_volume_mode(DockerVolumeMode::Bind)
            .with_data_dir(data.path());

        // Nothing staged yet ⇒ empty list.
        assert!(backend.list_volumes().await.unwrap().is_empty());

        // Stage two managed-DB data volumes (what a `launch` creates for a Single DB), plus
        // a native-container SCOPED volume dir (`@<scope>`) as if the two backends shared
        // this `data_dir` — docker must IGNORE the latter (Finding 4).
        let vols = data.path().join("compute").join("volumes");
        tokio::fs::create_dir_all(vols.join("bramp-db-acme-app"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vols.join("bramp-db-acme-other"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vols.join("@acme@bramp-db-acme-app"))
            .await
            .unwrap();

        let listed: Vec<String> = backend
            .list_volumes()
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.name)
            .collect();
        assert_eq!(
            listed,
            vec!["bramp-db-acme-app", "bramp-db-acme-other"],
            "a native-container `@<scope>` dir is not a docker volume and must be excluded"
        );

        // Drop ONE volume: it existed, and only it is removed (the sibling survives — the
        // per-(project,workload) scope: a drop never touches another DB's data).
        assert!(backend.remove_volume("bramp-db-acme-app").await.unwrap());
        assert!(!vols.join("bramp-db-acme-app").exists());
        assert!(
            vols.join("bramp-db-acme-other").exists(),
            "dropping one managed DB must not remove a sibling's volume"
        );
        // The native scoped dir is untouched (docker refuses the `@` name outright).
        assert!(
            backend
                .remove_volume("@acme@bramp-db-acme-app")
                .await
                .is_err()
        );
        assert!(
            vols.join("@acme@bramp-db-acme-app").exists(),
            "docker must never remove a native-container scoped volume dir"
        );

        // Idempotent: removing the now-absent volume reports `false`, never an error.
        assert!(!backend.remove_volume("bramp-db-acme-app").await.unwrap());
    }

    #[test]
    fn volume_mode_defaults_to_named_and_parses_lowercase() {
        assert_eq!(DockerVolumeMode::default(), DockerVolumeMode::Named);
        assert_eq!(
            serde_json::from_str::<DockerVolumeMode>("\"named\"").unwrap(),
            DockerVolumeMode::Named
        );
        assert_eq!(
            serde_json::from_str::<DockerVolumeMode>("\"bind\"").unwrap(),
            DockerVolumeMode::Bind
        );
    }

    #[test]
    fn ephemeral_container_name_is_unique_and_prefixed() {
        let a = ephemeral_container_name();
        let b = ephemeral_container_name();
        // Prefixed so it never collides with a workload container (`boatramp-<id>`)
        // and is recognizable as a one-shot.
        assert!(a.starts_with("boatramp-ephemeral-"), "got {a}");
        assert!(b.starts_with("boatramp-ephemeral-"), "got {b}");
        // The monotonic sequence guarantees two back-to-back names never collide, even
        // within the same nanosecond — the daemon rejects a duplicate name.
        assert_ne!(a, b);
    }

    #[test]
    fn project_network_name_is_deterministic_per_project_and_isolates() {
        // Deterministic + prefixed so it never clobbers an unrelated network on a shared daemon.
        assert_eq!(project_network_name("acme"), "boatramp-net-acme");
        assert_eq!(project_network_name("acme"), project_network_name("acme"));
        // The reserved default (and an empty id) share the one `default` network — still its OWN
        // isolated network, never a shared node-wide one.
        assert_eq!(project_network_name("default"), "boatramp-net-default");
        assert_eq!(project_network_name(""), "boatramp-net-default");
        // DISTINCT projects get DISTINCT networks — the tenancy boundary a single shared network
        // would destroy. Regression guard for cross-project isolation.
        assert_ne!(
            project_network_name("acme"),
            project_network_name("beta"),
            "two projects must never share a network"
        );
        assert_ne!(
            project_network_name("acme"),
            project_network_name("default")
        );
    }

    #[test]
    fn project_bridge_name_is_scoped_bounded_and_deterministic() {
        let acme = project_bridge_name(&project_network_name("acme"));
        // Scoped to the boatramp prefix the firewall trusts — NOT docker's `br-<hash>`.
        assert!(
            acme.starts_with(PROJECT_BRIDGE_PREFIX),
            "{acme} must carry the boatramp bridge prefix"
        );
        assert!(
            !acme.starts_with("br-"),
            "{acme} must not look like a docker default bridge"
        );
        // Within the Linux IFNAMSIZ budget (15 bytes), for EVERY project — including a max-length
        // 63-byte slug, which cannot go into an ifname verbatim.
        let long = "a".repeat(63);
        for net in [
            project_network_name("acme"),
            project_network_name("default"),
            project_network_name(&long),
        ] {
            let bridge = project_bridge_name(&net);
            assert!(
                bridge.len() <= MAX_IFNAME_LEN,
                "{bridge} ({} bytes) exceeds IFNAMSIZ {MAX_IFNAME_LEN}",
                bridge.len()
            );
            // Name-safe for a Linux interface: ASCII, no `/` or whitespace.
            assert!(
                bridge
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "{bridge} must be interface-name-safe"
            );
        }
        // Deterministic: the same project always derives the same bridge (create-if-absent + the
        // export/import one-shot must converge on ONE bridge across restarts).
        assert_eq!(acme, project_bridge_name(&project_network_name("acme")));
        // Distinct projects get distinct bridges (no accidental sharing under the hash).
        assert_ne!(acme, project_bridge_name(&project_network_name("beta")));
        assert_ne!(
            project_bridge_name(&project_network_name("default")),
            project_bridge_name(&project_network_name("acme"))
        );
        // The docker bridge prefix is DISJOINT from the native-container/firecracker `br-boatramp`
        // bridge, so the firewall can match the two with separate, non-overlapping patterns and a
        // boatramp-scoped match never degrades to the broad `br-+`.
        assert!(!"br-boatramp".starts_with(PROJECT_BRIDGE_PREFIX));
    }

    /// Build a `Network` inspect result with a given bridge driver-opt and attachment set, for the
    /// `classify_project_network` detect/guard tests. `bridge: None` ⇒ no `com.docker.network.
    /// bridge.name` opt (a legacy auto-generated `br-<hash>` — docker does not report it). `containers:
    /// None` ⇒ the `Containers` field is absent (emptiness indeterminable); `Some(n)` ⇒ a map with
    /// `n` attached entries.
    fn net_with(bridge: Option<&str>, containers: Option<usize>) -> Network {
        use bollard::models::NetworkContainer;
        Network {
            options: bridge.map(|b| HashMap::from([(BRIDGE_NAME_OPT.to_string(), b.to_string())])),
            containers: containers.map(|n| {
                (0..n)
                    .map(|i| (format!("container{i}"), NetworkContainer::default()))
                    .collect()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn classify_project_network_detects_scoped_vs_unscoped_and_guards_on_emptiness() {
        let net = project_network_name("acme");
        let scoped = project_bridge_name(&net);

        // SCOPED: the opt equals the expected scoped bridge → keep, regardless of attachment (a
        // scoped network is never rebuilt).
        for containers in [None, Some(0), Some(3)] {
            assert_eq!(
                classify_project_network(&net_with(Some(&scoped), containers), &scoped),
                ProjectNetworkBridge::Scoped,
                "a bridge equal to the scoped name is always kept"
            );
        }

        // UNSCOPED + EMPTY → safe to recreate scoped. Covers BOTH shapes of "not scoped":
        //   (a) no bridge opt at all — docker's legacy auto-generated `br-<hash>` (the reap-race
        //       defect's exact on-wire state), and
        //   (b) an opt present but set to some OTHER value.
        assert_eq!(
            classify_project_network(&net_with(None, Some(0)), &scoped),
            ProjectNetworkBridge::UnscopedEmpty,
            "a legacy br-<hash> (no opt) with no attached container is the safe-upgrade case"
        );
        assert_eq!(
            classify_project_network(&net_with(Some("br-deadbeef"), Some(0)), &scoped),
            ProjectNetworkBridge::UnscopedEmpty,
            "a differing bridge value with no attached container is also upgradable"
        );

        // UNSCOPED + OCCUPIED → leave untouched (never sever a live endpoint).
        assert_eq!(
            classify_project_network(&net_with(None, Some(1)), &scoped),
            ProjectNetworkBridge::UnscopedOccupied,
            "a legacy bridge with a live attached container must be left intact"
        );
        assert_eq!(
            classify_project_network(&net_with(None, Some(5)), &scoped),
            ProjectNetworkBridge::UnscopedOccupied
        );

        // UNSCOPED + INDETERMINATE (Containers absent) → fail safe, leave untouched.
        assert_eq!(
            classify_project_network(&net_with(None, None), &scoped),
            ProjectNetworkBridge::UnscopedUnknown,
            "emptiness that cannot be determined must NOT be torn down (fail safe)"
        );

        // The scoped bridge is per-project: `acme`'s scoped name is NOT `beta`'s, so inspecting
        // `beta`'s (empty, legacy) network against `acme`'s expected bridge classifies as a
        // regular unscoped-empty — detection keys on the project's OWN expected bridge, never a
        // cross-project one.
        let beta = project_network_name("beta");
        let beta_scoped = project_bridge_name(&beta);
        assert_ne!(scoped, beta_scoped);
        assert_eq!(
            classify_project_network(&net_with(Some(&beta_scoped), Some(0)), &scoped),
            ProjectNetworkBridge::UnscopedEmpty,
            "another project's scoped bridge is not THIS project's scoped bridge"
        );
    }

    #[test]
    fn project_network_labels_are_the_per_project_isolation_labels() {
        // The recreate path reapplies EXACTLY these labels, so an upgraded network stays the SAME
        // per-project isolated network (managed + the owning project) — only the bridge changes.
        let labels = project_network_labels("acme");
        assert_eq!(
            labels.get("boatramp.managed").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            labels.get("boatramp.project").map(String::as_str),
            Some("acme")
        );
        assert_eq!(
            labels.len(),
            2,
            "exactly the two isolation labels, nothing else"
        );
        // The reserved default project (and an empty id) still carry their own project label — a
        // single-tenant install is its own isolated, labeled network, never an unlabeled shared one.
        assert_eq!(
            project_network_labels("default")
                .get("boatramp.project")
                .map(String::as_str),
            Some("default")
        );
    }

    #[test]
    fn rewrite_shim_host_rewrites_only_bind_local_hosts() {
        // Bind-local hosts a bridged container can't reach the host at → rewritten, port/path kept.
        assert_eq!(
            rewrite_shim_host_for_docker("http://127.0.0.1:8083/claim").as_deref(),
            Some("http://host.docker.internal:8083/claim")
        );
        assert_eq!(
            rewrite_shim_host_for_docker("http://0.0.0.0:8084").as_deref(),
            Some("http://host.docker.internal:8084")
        );
        assert_eq!(
            rewrite_shim_host_for_docker("http://localhost:8085/b/x/y?z=1").as_deref(),
            Some("http://host.docker.internal:8085/b/x/y?z=1")
        );
        assert_eq!(
            rewrite_shim_host_for_docker("http://[::1]:8086/").as_deref(),
            Some("http://host.docker.internal:8086/")
        );
        // 127.0.0.0/8 (not just .0.1).
        assert_eq!(
            rewrite_shim_host_for_docker("http://127.9.9.9:9/p").as_deref(),
            Some("http://host.docker.internal:9/p")
        );
        // Already-routable hosts are LEFT ALONE: an explicit host-gateway IP, a managed-DB DNS
        // alias (reached over the per-project net), an external FQDN. This is what protects a
        // managed-database DSN and an external endpoint from being clobbered.
        assert_eq!(
            rewrite_shim_host_for_docker("http://172.17.0.1:8083/claim"),
            None
        );
        assert_eq!(
            rewrite_shim_host_for_docker("postgres://cmp-pg-ab12:5432/app"),
            None
        );
        assert_eq!(
            rewrite_shim_host_for_docker("https://db.example.com:5432/app"),
            None
        );
        // No explicit scheme → ambiguous, left alone.
        assert_eq!(rewrite_shim_host_for_docker("127.0.0.1:8083"), None);
    }

    #[test]
    fn docker_binding_reachability_rewrites_shim_urls_and_spares_managed_dsns() {
        use boatramp_core::compute::BindingKind;
        let bind = |kind, url_env: Option<&str>, migration: Option<&str>| {
            ComputeBinding::new(kind)
                .with_url_env(url_env.map(str::to_string))
                .with_migration_url_env(migration.map(str::to_string))
        };
        let mut env = std::collections::BTreeMap::from([
            // A kv/blob/messaging shim bound on loopback — always a shim, always rewritten.
            (
                "BOATRAMP_KV_URL".to_string(),
                "http://127.0.0.1:8084".to_string(),
            ),
            // A sql shim (libsql) bound on loopback — rewritten.
            (
                "BOATRAMP_SQL_URL".to_string(),
                "http://127.0.0.1:8083".to_string(),
            ),
            // A managed-DB DSN (sql binding, co-located pg reached by DNS alias) — NOT a shim,
            // host is a DNS name, MUST survive untouched.
            (
                "MANAGED_DB".to_string(),
                "postgres://cmp-pg-ab12:5432/app".to_string(),
            ),
            // An operator literal that happens to hold a localhost URL but is NOT a binding target
            // — must NOT be rewritten (only declared binding env keys are touched).
            (
                "SOME_LOCAL".to_string(),
                "http://127.0.0.1:9000".to_string(),
            ),
        ]);
        let bindings = [
            bind(BindingKind::Kv, None, None),
            bind(BindingKind::Sql, None, None),
            bind(BindingKind::Sql, Some("MANAGED_DB"), None),
        ];
        let extra = docker_binding_reachability(&mut env, &bindings);
        assert_eq!(env["BOATRAMP_KV_URL"], "http://host.docker.internal:8084");
        assert_eq!(env["BOATRAMP_SQL_URL"], "http://host.docker.internal:8083");
        assert_eq!(env["MANAGED_DB"], "postgres://cmp-pg-ab12:5432/app");
        assert_eq!(env["SOME_LOCAL"], "http://127.0.0.1:9000");
        // Always injects the host-gateway ExtraHost so `host.docker.internal` resolves.
        assert_eq!(extra, vec![HOST_GATEWAY_EXTRA_HOST.to_string()]);
    }

    #[test]
    fn network_config_attaches_with_the_workload_alias() {
        // A workload server is attached with a DNS ALIAS equal to its workload name, so a sibling
        // resolving `<workload>:<port>` over the embedded DNS finds it. One network, keyed exactly.
        let cfg = network_config("boatramp-net-acme", vec!["pg".to_string()]);
        assert_eq!(cfg.endpoints_config.len(), 1);
        let ep = cfg
            .endpoints_config
            .get("boatramp-net-acme")
            .expect("endpoint for the project network");
        assert_eq!(ep.aliases.as_deref(), Some(["pg".to_string()].as_slice()));
    }

    #[test]
    fn network_config_without_aliases_leaves_aliases_unset() {
        // A one-shot client is not a resolvable server: no alias, just membership.
        let cfg = network_config("boatramp-net-acme", Vec::new());
        let ep = cfg.endpoints_config.get("boatramp-net-acme").unwrap();
        assert_eq!(ep.aliases, None);
    }

    /// Bug D (Docker 29 SD registration): the alias `launch` publishes for a workload MUST be a
    /// valid DNS label (≤ 63 octets), or Docker 29's embedded DNS silently drops the record and a
    /// sibling can never resolve it. This is a VERSION-INDEPENDENT guard at the emit site — it
    /// fails on ANY host (no daemon needed), which the live gate on a Docker 28 box could not. A
    /// short workload is published unchanged; a real `Single` managed-DB name (> 63 octets) is
    /// shortened to a valid, stable label that `launch` attaches as the endpoint alias.
    #[test]
    fn launch_alias_is_always_a_valid_dns_label() {
        use boatramp_core::compute::{DNS_LABEL_MAX_LEN, is_valid_dns_label};
        // A short workload name is attached verbatim.
        let short = managed_db_alias("web");
        assert_eq!(short, "web");
        assert!(is_valid_dns_label(&short));

        // The real over-long `Single` managed-DB workload shape `<compute>-<ident>` (two 25-char
        // digests ≈ 69 octets) — the alias `launch` would have published before the fix.
        let h = "abcdefghijklmnopqrstuvwxy";
        let workload = format!("bramp-db-{h}-mailroom_{h}");
        assert!(
            workload.len() > DNS_LABEL_MAX_LEN,
            "fixture must reproduce the > 63-octet failure shape"
        );
        let alias = managed_db_alias(&workload);
        assert!(
            is_valid_dns_label(&alias) && alias.len() <= DNS_LABEL_MAX_LEN,
            "launch must publish a DNS-valid alias, got {alias:?} ({} octets)",
            alias.len()
        );
        // And `network_config` attaches exactly that alias for the endpoint.
        let cfg = network_config("boatramp-net-mailroom", vec![alias.clone()]);
        let ep = cfg.endpoints_config.get("boatramp-net-mailroom").unwrap();
        assert_eq!(ep.aliases.as_deref(), Some([alias].as_slice()));
    }

    #[test]
    fn is_network_conflict_matches_only_409() {
        // 409 ⇒ "already exists" ⇒ the idempotent create-if-absent success path.
        assert!(is_network_conflict(
            &bollard::errors::Error::DockerResponseServerError {
                status_code: 409,
                message: "network already exists".into(),
            }
        ));
        // Any other status is a real error that must surface, not be swallowed.
        assert!(!is_network_conflict(
            &bollard::errors::Error::DockerResponseServerError {
                status_code: 500,
                message: "boom".into(),
            }
        ));
    }

    #[test]
    fn ephemeral_network_env_key_is_stable() {
        // The node sets this exact key (via `boatramp_docker::EPHEMERAL_NETWORK_ENV`); the backend
        // strips + consumes it. A rename on one side without the other silently breaks the managed-
        // DB export/import reach, so pin it.
        assert_eq!(EPHEMERAL_NETWORK_ENV, "BOATRAMP_EPHEMERAL_NETWORK");
    }

    #[test]
    fn restart_policy_maps_to_docker() {
        assert_eq!(
            restart_policy(RestartPolicy::Always).name,
            Some(RestartPolicyNameEnum::ALWAYS)
        );
        assert_eq!(
            restart_policy(RestartPolicy::OnFailure).name,
            Some(RestartPolicyNameEnum::ON_FAILURE)
        );
        assert_eq!(
            restart_policy(RestartPolicy::Never).name,
            Some(RestartPolicyNameEnum::NO)
        );
    }
}
