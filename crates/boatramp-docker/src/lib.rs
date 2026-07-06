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
    InstanceHandle, IsolationClass, LaunchRequest, RestartPolicy, Scheme,
};
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, RestartPolicy as DockerRestartPolicy, RestartPolicyNameEnum};
use bollard::Docker;
use futures::StreamExt;

/// The remote-Docker compute backend: a connected Engine API client.
pub struct DockerBackend {
    docker: Docker,
}

impl DockerBackend {
    /// Connect to the Docker daemon configured by the environment
    /// (`DOCKER_HOST` + TLS/SSH vars, or the platform default socket).
    pub fn connect() -> Result<Self, BackendError> {
        let docker = Docker::connect_with_defaults()
            .map_err(|e| BackendError::Other(format!("connect to docker: {e}")))?;
        Ok(Self { docker })
    }

    /// Wrap an already-connected client (for tests / custom transports).
    pub fn with_client(docker: Docker) -> Self {
        Self { docker }
    }

    /// Whether the daemon answers a `ping` — used to decide whether to register
    /// this backend (a connected client doesn't imply a reachable daemon).
    pub async fn reachable(&self) -> bool {
        self.docker.ping().await.is_ok()
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
fn hardened_host_config(mem_mib: u32, vcpus: u32, restart: RestartPolicy) -> HostConfig {
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
        readonly_rootfs: Some(true),
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
            persistent_volumes: false,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        // For the docker backend the spec's `rootfs` is an OCI **image
        // reference** the daemon can pull (registry/repo:tag or a digest).
        let reference = spec.rootfs.clone();
        let options = CreateImageOptions {
            from_image: reference.clone(),
            ..Default::default()
        };
        let mut pull = self.docker.create_image(Some(options), None, None);
        while let Some(step) = pull.next().await {
            step.map_err(|e| BackendError::Materialize(format!("pull {reference}: {e}")))?;
        }
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
        let host_config = hardened_host_config(req.spec.mem_mib, req.spec.vcpus, req.spec.restart);
        let config = Config {
            image: Some(reference),
            cmd: Some(req.spec.entrypoint.clone()),
            env: Some(env),
            host_config: Some(host_config),
            ..Default::default()
        };

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

        let ip = self.container_ip(&created.id).await?;
        let port = req.spec.port;
        Ok(Instance {
            handle: InstanceHandle {
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: encode_ref(&name, &ip, port),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip,
                port,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let hc = hardened_host_config(256, 2, RestartPolicy::Never);
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
        assert_eq!(hc.readonly_rootfs, Some(true));
        // A read-only rootfs stays usable via small noexec/nosuid scratch mounts.
        let tmpfs = hc.tmpfs.expect("tmpfs mounts for a read-only rootfs");
        assert!(tmpfs.get("/tmp").is_some_and(|o| o.contains("noexec")));
        assert!(tmpfs.contains_key("/run"));
        // At least one vCPU even when the spec asks for zero.
        assert_eq!(
            hardened_host_config(64, 0, RestartPolicy::Never).nano_cpus,
            Some(1_000_000_000)
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
