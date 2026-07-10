//! The `compute` subcommand: define/list/remove Firecracker microVM workloads.
//! The control plane is uniform (runs anywhere); only execution
//! needs a KVM node. `set` takes a rootfs + kernel as a **blob hash, a local
//! file, or a URL** (a file/URL is uploaded for you, like `blob put`); building
//! an `ext4` rootfs from an OCI image is done by `compute build`.

use std::collections::BTreeMap;

use boatramp_core::compute::{
    ComputeSpec, IsolationRequirement, PlacementConstraints, RestartPolicy,
};
use clap::Subcommand;
use serde::Serialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure running a `boatramp compute` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server target from flags/config failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// Serializing a workload to JSON failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Reading/writing a local rootfs file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An `--env` argument was not `K=V`.
    #[error("--env must be K=V, got {0:?}")]
    BadEnv(String),
    /// Building the ext4 rootfs from the OCI image failed.
    #[error("rootfs build failed: {0}")]
    RootfsBuild(String),
}

/// `compute` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp compute`.
#[derive(Debug, clap::Args)]
pub struct ComputeArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: ComputeCommand,
}

#[derive(Debug, Subcommand)]
enum ComputeCommand {
    /// List workloads.
    Ls,
    /// Print one workload's desired state as JSON.
    Get {
        /// Workload name.
        name: String,
    },
    /// Create or update a workload from a rootfs + kernel (blob hash, file, or URL).
    Set {
        /// Workload name.
        name: String,
        /// ext4 rootfs image: a blob hash, a local file, or a URL (file/URL is uploaded).
        #[arg(long)]
        rootfs: String,
        /// vmlinux kernel: a blob hash, a local file, or a URL (file/URL is uploaded).
        #[arg(long)]
        kernel: String,
        /// Virtual CPUs.
        #[arg(long, default_value_t = 1)]
        vcpus: u32,
        /// Guest memory (MiB).
        #[arg(long, default_value_t = 256)]
        mem_mib: u32,
        /// In-guest TCP port the app listens on.
        #[arg(long)]
        port: u16,
        /// Desired replica count.
        #[arg(long, default_value_t = 1)]
        replicas: u32,
        /// In-guest entrypoint argv (repeatable).
        #[arg(long = "entrypoint")]
        entrypoint: Vec<String>,
        /// Environment variable `K=V` (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// Restart policy.
        #[arg(long, value_enum, default_value_t = Restart::Always)]
        restart: Restart,
        /// Snapshot + stop when idle; restore on the next request.
        #[arg(long)]
        scale_to_zero: bool,
        /// Isolation the workload requires (`trusted` allows containers;
        /// `untrusted` forces a microVM / managed platform).
        #[arg(long, value_enum, default_value_t = Isolation::Trusted)]
        isolation: Isolation,
        /// Allowed region (repeatable; empty = any).
        #[arg(long = "region")]
        regions: Vec<String>,
    },
    /// Build an ext4 rootfs from an OCI image, upload it, and set the workload.
    /// Needs the `e2fsprogs` `mke2fs` tool on this host.
    Build {
        /// Workload name.
        name: String,
        /// OCI image reference, e.g. `nginx:1.27` or `ghcr.io/owner/app:tag`.
        #[arg(long)]
        image: String,
        /// vmlinux kernel: a blob hash, a local file, or a URL (provision once, shared).
        #[arg(long)]
        kernel: String,
        /// Size of the ext4 rootfs image (MiB).
        #[arg(long, default_value_t = 1024)]
        size_mib: u64,
        /// In-guest TCP port the app listens on.
        #[arg(long)]
        port: u16,
        /// Virtual CPUs.
        #[arg(long, default_value_t = 1)]
        vcpus: u32,
        /// Guest memory (MiB).
        #[arg(long, default_value_t = 256)]
        mem_mib: u32,
        /// Desired replica count.
        #[arg(long, default_value_t = 1)]
        replicas: u32,
        /// In-guest entrypoint argv (repeatable).
        #[arg(long = "entrypoint")]
        entrypoint: Vec<String>,
        /// Environment variable `K=V` (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// Restart policy.
        #[arg(long, value_enum, default_value_t = Restart::Always)]
        restart: Restart,
        /// Snapshot + stop when idle.
        #[arg(long)]
        scale_to_zero: bool,
        /// Isolation the workload requires (`trusted` allows containers;
        /// `untrusted` forces a microVM / managed platform).
        #[arg(long, value_enum, default_value_t = Isolation::Trusted)]
        isolation: Isolation,
        /// Allowed region (repeatable).
        #[arg(long = "region")]
        regions: Vec<String>,
    },
    /// Remove a workload (its replicas are stopped).
    Rm {
        /// Workload name.
        name: String,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Restart {
    Never,
    OnFailure,
    Always,
}

impl From<Restart> for RestartPolicy {
    fn from(r: Restart) -> Self {
        match r {
            Restart::Never => RestartPolicy::Never,
            Restart::OnFailure => RestartPolicy::OnFailure,
            Restart::Always => RestartPolicy::Always,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Isolation {
    /// Shared-kernel isolation is acceptable (a container is fine).
    Trusted,
    /// Strong isolation required (microVM / managed platform).
    Untrusted,
}

impl From<Isolation> for IsolationRequirement {
    fn from(i: Isolation) -> Self {
        match i {
            Isolation::Trusted => IsolationRequirement::Trusted,
            Isolation::Untrusted => IsolationRequirement::Untrusted,
        }
    }
}

#[derive(Serialize)]
struct PutComputeRequest {
    spec: ComputeSpec,
    replicas: u32,
    placement: PlacementConstraints,
}

/// Entry point for `boatramp compute`.
pub async fn run(args: ComputeArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        ComputeCommand::Ls => {
            let workloads: serde_json::Value = http
                .get(format!("{server}/api/compute"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let arr = workloads.as_array().cloned().unwrap_or_default();
            if arr.is_empty() {
                println!("no workloads");
                return Ok(());
            }
            for w in arr {
                let name = w["name"].as_str().unwrap_or("?");
                let replicas = w["replicas"].as_u64().unwrap_or(0);
                let active = w["active"].as_str().unwrap_or("");
                let short = &active[..active.len().min(12)];
                println!("{name}  replicas={replicas}  active={short}");
            }
        }
        ComputeCommand::Get { name } => {
            let workload: serde_json::Value = http
                .get(format!("{server}/api/compute/{name}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&workload)?);
        }
        ComputeCommand::Set {
            name,
            rootfs,
            kernel,
            vcpus,
            mem_mib,
            port,
            replicas,
            entrypoint,
            env,
            restart,
            scale_to_zero,
            isolation,
            regions,
        } => {
            // `--rootfs` / `--kernel` accept a blob hash, a local file, or a URL.
            let rootfs = client::resolve_artifact(&http, &server, &rootfs).await?;
            let kernel = client::resolve_artifact(&http, &server, &kernel).await?;
            let spec = build_spec(
                rootfs,
                kernel,
                vcpus,
                mem_mib,
                port,
                entrypoint,
                env,
                restart,
                scale_to_zero,
                isolation,
            )?;
            let hash = put_workload(&http, &server, &name, spec, replicas, regions).await?;
            println!("workload {name} set (spec {hash})");
        }
        ComputeCommand::Build {
            name,
            image,
            kernel,
            size_mib,
            port,
            vcpus,
            mem_mib,
            replicas,
            entrypoint,
            env,
            restart,
            scale_to_zero,
            isolation,
            regions,
        } => {
            // Build the ext4 rootfs locally from the OCI image (needs mke2fs).
            // The init that execs the workload is baked in from the entrypoint
            // override (else the image's Entrypoint+Cmd) + the env.
            let env_pairs: Vec<(String, String)> = env
                .iter()
                .map(|pair| {
                    pair.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or_else(|| Error::BadEnv(pair.clone()))
                })
                .collect::<Result<_>>()?;
            let out = std::env::temp_dir().join(format!("boatramp-build-{name}.ext4"));
            eprintln!("building rootfs from {image} (requires e2fsprogs `mke2fs`)…");
            boatramp_firecracker::oci::build_rootfs(
                &image,
                &entrypoint,
                &env_pairs,
                &out,
                size_mib,
                // The CLI doesn't expose volumes yet (the spec sets none here); a
                // workload with volumes baked is the API/project-config path.
                &[],
            )
            .await
            .map_err(|e| Error::RootfsBuild(e.to_string()))?;
            // `--kernel` accepts a blob hash, a local file, or a URL.
            let kernel = client::resolve_artifact(&http, &server, &kernel).await?;
            // Hash + upload the freshly built rootfs as a content-addressed blob.
            let rootfs = client::put_file_blob(&http, &server, &out).await?;
            let _ = std::fs::remove_file(&out);
            eprintln!("rootfs blob {rootfs} uploaded");
            let spec = build_spec(
                rootfs,
                kernel,
                vcpus,
                mem_mib,
                port,
                entrypoint,
                env,
                restart,
                scale_to_zero,
                isolation,
            )?;
            let hash = put_workload(&http, &server, &name, spec, replicas, regions).await?;
            println!("workload {name} built + set (spec {hash})");
        }
        ComputeCommand::Rm { name } => {
            http.delete(format!("{server}/api/compute/{name}"))
                .send()
                .await?
                .error_for_status()?;
            println!("removed {name}");
        }
    }
    Ok(())
}

/// Assemble a [`ComputeSpec`] from CLI fields (parsing `K=V` env pairs).
#[allow(clippy::too_many_arguments)]
fn build_spec(
    rootfs: String,
    kernel: String,
    vcpus: u32,
    mem_mib: u32,
    port: u16,
    entrypoint: Vec<String>,
    env: Vec<String>,
    restart: Restart,
    scale_to_zero: bool,
    isolation: Isolation,
) -> Result<ComputeSpec> {
    let mut env_map = BTreeMap::new();
    for pair in env {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| Error::BadEnv(pair.clone()))?;
        env_map.insert(k.to_string(), v.to_string());
    }
    Ok(ComputeSpec {
        version: boatramp_core::SCHEMA_VERSION,
        rootfs,
        kernel,
        kernel_cmdline: None,
        vcpus,
        mem_mib,
        entrypoint,
        env: env_map,
        port,
        restart: restart.into(),
        scale_to_zero,
        volumes: vec![],
        isolation: isolation.into(),
        prefer_backend: None,
    })
}

/// PUT a workload's desired state; returns the stored spec hash.
async fn put_workload(
    http: &reqwest::Client,
    server: &str,
    name: &str,
    spec: ComputeSpec,
    replicas: u32,
    regions: Vec<String>,
) -> Result<String> {
    let request = PutComputeRequest {
        spec,
        replicas,
        placement: PlacementConstraints {
            regions,
            labels: BTreeMap::new(),
        },
    };
    let resp: serde_json::Value = http
        .put(format!("{server}/api/compute/{name}"))
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp["spec"].as_str().unwrap_or("").to_string())
}
