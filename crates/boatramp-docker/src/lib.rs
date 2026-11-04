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
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, Endpoint, ExecOutput,
    Health, Instance, InstanceHandle, IsolationClass, LaunchRequest, RestartPolicy, RootSource,
    Scheme, VolumeRef, compute_instance_id,
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
    Mount, MountTypeEnum, PortBinding, RestartPolicy as DockerRestartPolicy, RestartPolicyNameEnum,
};
use bollard::network::CreateNetworkOptions;
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

/// Reject a volume whose `name` or `mount` could escape its sandboxed location
/// (mirrors the native-container guard): `name` backs a docker volume / a
/// `<data_dir>/compute/volumes/<name>` bind, so it must be a single normal path
/// component; `mount` is the in-container target, so it must be absolute with no
/// `..`/`.`.
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
    /// Wall-clock backstop for a single [`run_ephemeral`](ComputeBackend::run_ephemeral)
    /// invocation (export/import client run). Generous by default
    /// ([`EPHEMERAL_RUN_TIMEOUT`]); the operator raises it for a very large migration so
    /// the backstop never kills legitimate work (the real unreachable-DSN hang is bounded
    /// far tighter by the client's own connect timeout).
    ephemeral_timeout: std::time::Duration,
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
            ephemeral_timeout: EPHEMERAL_RUN_TIMEOUT,
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
            ephemeral_timeout: EPHEMERAL_RUN_TIMEOUT,
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
    async fn ensure_project_network(&self, project: &str) -> Result<String, BackendError> {
        let name = project_network_name(project);
        self.create_bridge_network(
            &name,
            HashMap::from([
                ("boatramp.managed".to_string(), "true".to_string()),
                ("boatramp.project".to_string(), project.to_string()),
            ]),
        )
        .await?;
        Ok(name)
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

/// Build the [`NetworkingConfig`] attaching a container to `network` with the given DNS `aliases`
/// (the workload name for a server a sibling resolves by name; empty for a one-shot client that
/// only needs to reach peers). Supplying this at container-create means the container joins ONLY
/// this one network — never the shared default bridge — so docker's inter-network isolation is the
/// tenancy boundary (a container can resolve/reach only its own project's peers).
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
        // Authenticate the pull with the host-resolved registry credential (private
        // image), or `None` for a public/anonymous pull. The credential is a sealed
        // secret resolved fail-closed before launch — it never appears in config/argv.
        let reference = self.pull_image(&reference, pull_auth).await?;
        Ok(Artifact::Image { reference })
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
        let env: Vec<String> = req
            .spec
            .env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
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
        if self.endpoint == DockerEndpoint::Published {
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
        let network = self.ensure_project_network(&req.project).await?;
        host_config.network_mode = Some(network.clone());
        config.host_config = Some(host_config);
        config.networking_config = Some(network_config(&network, vec![req.workload.clone()]));

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

        // Reachable endpoint: the published host loopback port (default), or the
        // container's bridge IP + in-container port (`Bridge`).
        let (host, endpoint_port) = match self.endpoint {
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
        // with the per-project net as primary. Idempotent: a container already primary on the
        // net returns `false`. Inspect failure / gone ⇒ `false` (the normal plan path owns it).
        let name = match decode_ref(&handle.backend_ref) {
            Some((n, _, _)) => n,
            None => container_name(&handle.project, &handle.workload, handle.replica),
        };
        let Ok(info) = self.docker.inspect_container(&name, None).await else {
            return false;
        };
        let network_mode = info
            .host_config
            .as_ref()
            .and_then(|hc| hc.network_mode.as_deref());
        !primary_network_is_current(network_mode, &project_network_name(&handle.project))
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
        // Network (Bug C, symmetric with the launch path): when the node hinted a per-project
        // network — a managed DB on an isolated net — make THAT net the one-shot's PRIMARY
        // attachment (`NetworkMode` + an alias-less `networking_config` AT CREATE), so the
        // client's `/etc/resolv.conf` is docker's embedded DNS (127.0.0.11) and it can RESOLVE
        // the DB by its workload-name alias. A mere SECONDARY attach (the old dual-attach, kept
        // on the default bridge as primary) does NOT get embedded DNS, so the name-based DSN
        // never resolved — the exact failure this reverses. The per-project net is a non-internal
        // bridge, so NAT egress still works through it. Absent a hint (an external DSN), NO
        // `networking_config` is set and the one-shot comes up on the daemon's DEFAULT network,
        // reaching the DSN's host by NAT egress — unchanged.
        if let Some(net) = &ephemeral_network {
            // The network must exist before create. `net` is always `project_network_name(..)`-
            // shaped, so recover the project by stripping the fixed prefix (same create-if-absent
            // + labels as the launch path).
            let project = net
                .strip_prefix(PROJECT_NETWORK_PREFIX)
                .unwrap_or(net.as_str());
            if let Err(e) = self.ensure_project_network(project).await {
                return Err(BackendError::Other(format!(
                    "ephemeral ensure project network {net}: {e}"
                )));
            }
            host_config.network_mode = Some(net.clone());
        }

        let mut config = Config {
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
        if let Some(net) = &ephemeral_network {
            // Primary attach at CREATE (no alias — a one-shot client is not a resolvable server;
            // it only needs to RESOLVE the DB, which requires being primary on this net).
            config.networking_config = Some(network_config(net, Vec::new()));
        }

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
        let vol = VolumeRef {
            name: "db".into(),
            mount: "/data".into(),
            size_mib: 64,
        };
        let m = volume_mount(&vol, DockerVolumeMode::Named, Path::new("/srv/data"));
        assert_eq!(m.typ, Some(MountTypeEnum::VOLUME));
        // Prefixed so it never clobbers an unrelated volume on a shared daemon.
        assert_eq!(m.source.as_deref(), Some("boatramp-db"));
        assert_eq!(m.target.as_deref(), Some("/data"));
        assert_eq!(m.read_only, Some(false), "a persistent volume is writable");
    }

    #[test]
    fn bind_volume_mode_builds_a_host_path_mount() {
        let vol = VolumeRef {
            name: "db".into(),
            mount: "/data".into(),
            size_mib: 64,
        };
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
