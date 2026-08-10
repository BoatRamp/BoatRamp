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
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, Endpoint, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest, RestartPolicy, RootSource, Scheme, VolumeRef,
};
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{
    HostConfig, Mount, MountTypeEnum, PortBinding, RestartPolicy as DockerRestartPolicy,
    RestartPolicyNameEnum,
};
use bollard::Docker;
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
        }
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
}

/// Container name for a workload replica (`boatramp-<workload>-<replica>`).
fn container_name(workload: &str, replica: u32) -> String {
    format!("boatramp-{workload}-{replica}")
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
        ("/tmp".to_string(), "rw,noexec,nosuid,size=64m".to_string()),
        ("/run".to_string(), "rw,noexec,nosuid,size=16m".to_string()),
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

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        // The docker backend pulls an OCI **image reference** (registry/repo:tag or a
        // digest); an ext4 rootfs is not runnable here.
        let reference = match &spec.root {
            RootSource::Image(reference) => reference.clone(),
            RootSource::Tar(_) | RootSource::Rootfs(_) => {
                return Err(BackendError::Materialize(
                    "docker backend requires an image reference (RootSource::Image)".into(),
                ))
            }
        };
        // Split the reference into `from_image` + `tag`, defaulting an untagged
        // reference to `:latest`. Without a tag the daemon's `fromImage=<name>` (no
        // `tag`) pulls **every** tag of the repo -- which is slow and 501s on any
        // repo that still has an ancient v1-manifest tag. A digest-pinned reference
        // is passed whole (no tag).
        let (from_image, tag) = image_pull_target(&reference);
        let options = CreateImageOptions {
            from_image: from_image.clone(),
            tag: tag.clone(),
            ..Default::default()
        };
        let mut pull = self.docker.create_image(Some(options), None, None);
        while let Some(step) = pull.next().await {
            step.map_err(|e| BackendError::Materialize(format!("pull {reference}: {e}")))?;
        }
        // Record the fully-qualified reference actually pulled, so `launch` runs the
        // exact tag (not the bare, all-tags-ambiguous name).
        let reference = if tag.is_empty() {
            reference
        } else {
            format!("{from_image}:{tag}")
        };
        Ok(Artifact::Image { reference })
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let reference = match &req.artifact {
            Artifact::Image { reference } => reference.clone(),
            _ => {
                return Err(BackendError::Launch(
                    "docker backend requires an Image artifact".into(),
                ))
            }
        };
        let name = container_name(&req.workload, req.replica);
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
        config.host_config = Some(host_config);

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
            .unwrap_or_else(|| container_name(&handle.workload, handle.replica));
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
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let name = match decode_ref(&handle.backend_ref) {
            Some((n, _, _)) => n,
            None => container_name(&handle.workload, handle.replica),
        };
        let info = match self.docker.inspect_container(&name, None).await {
            Ok(info) => info,
            Err(_) => return Ok(Health::Unhealthy),
        };
        let running = info.state.and_then(|s| s.running).unwrap_or(false);
        Ok(if running {
            Health::Healthy
        } else {
            Health::Unhealthy
        })
    }
}

impl DockerBackend {
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
        assert_eq!(container_name("web", 0), "boatramp-web-0");
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
        assert!(tmpfs.contains_key("/run"));
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
