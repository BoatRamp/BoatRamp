//! The `compute` subcommand: define/list/remove workloads across the compute
//! substrates (micro-VM / container / docker). The control plane is uniform (runs
//! anywhere); only execution needs a capable node. `set` picks the workload's
//! **root-filesystem source** — exactly one of, matched to the target substrate:
//!   * `--image <ref>` — an **OCI image reference** the runtime pulls (docker /
//!     cloudflare); passed through verbatim.
//!   * `--tar <artifact>` — a **tar rootfs archive** the native `container` runtime
//!     stages + unpacks.
//!   * `--rootfs <artifact>` — a **rootfs filesystem image** (a block device; `ext4`
//!     by default, or any filesystem the guest kernel mounts) the `firecracker`
//!     micro-VM stages + attaches.
//!
//! A `--tar`/`--rootfs` artifact is a blob hash, a local file, or a URL (a file/URL is
//! uploaded like `blob put`). `compute build` builds an `ext4` rootfs *from* an OCI
//! image (needs `mke2fs`).

use std::collections::BTreeMap;

use boatramp_core::compute::{
    BindingKind, ComputeBinding, ComputeSpec, IsolationRequirement, PlacementConstraints,
    RestartPolicy, RootSource,
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
    /// The `--image` / `--tar` / `--rootfs` root-filesystem source was not specified
    /// correctly (none, or more than one).
    #[error("{0}")]
    Args(String),
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
        /// An **OCI image reference** (`repo:tag` or a digest) a runtime pulls, e.g.
        /// `pgvector/pgvector:pg16`. For the docker / cloudflare substrates. Passed
        /// through verbatim (not uploaded). Exactly one of --image / --tar / --rootfs.
        #[arg(long, group = "root")]
        image: Option<String>,
        /// A **tar rootfs archive**: a blob hash, a local file, or a URL (file/URL is
        /// uploaded). For the native `container` substrate (staged + unpacked).
        #[arg(long, group = "root")]
        tar: Option<String>,
        /// A **rootfs filesystem image** (a block device — `ext4` by default, or any
        /// filesystem the guest kernel mounts): a blob hash, a local file, or a URL
        /// (file/URL is uploaded). For the `firecracker` micro-VM (staged + attached).
        #[arg(long, group = "root")]
        rootfs: Option<String>,
        /// vmlinux kernel: a blob hash, a local file, or a URL (file/URL is
        /// uploaded). Omit to use the node's configured default kernel. Applies only
        /// to a `--rootfs` (micro-VM) workload.
        #[arg(long)]
        kernel: Option<String>,
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
        /// Allow a writable root filesystem (honored only under the single-tenant
        /// posture; the hardened read-only root is the default). Prefer a persistent
        /// volume for app writes.
        #[arg(long)]
        writable_root: bool,
        /// Add back a Linux capability on the shared-kernel backends (docker / native
        /// container), without the `CAP_` prefix, e.g. `CHOWN` (repeatable). Honored
        /// only under the single-tenant posture. For an image whose entrypoint needs a
        /// capability (a stock database that `chown`s its data dir and drops
        /// privileges). Prefer `--user` + a persistent volume where the image allows.
        #[arg(long = "cap-add")]
        cap_add: Vec<String>,
        /// Run the entrypoint as this user (`uid` or `uid:gid`, numeric) instead of the
        /// backend default, so a stock image can run rootless against a pre-owned
        /// volume — no added capabilities. Honored under any posture.
        #[arg(long)]
        user: Option<String>,
        /// Isolation the workload requires (`trusted` allows containers;
        /// `untrusted` forces a microVM / managed platform).
        #[arg(long, value_enum, default_value_t = Isolation::Trusted)]
        isolation: Isolation,
        /// Allowed region (repeatable; empty = any).
        #[arg(long = "region")]
        regions: Vec<String>,
        /// Managed binding the workload depends on, `<kind>[:<name>]` (repeatable):
        /// `sql` binds the site database, `sql:analytics` a named external DB. The
        /// endpoint URL + token are injected into the guest env (`BOATRAMP_SQL_URL`).
        #[arg(long = "bind")]
        bind: Vec<String>,
    },
    /// Build an ext4 rootfs from an OCI image, upload it, and set the workload.
    /// Needs the `e2fsprogs` `mke2fs` tool on this host.
    Build {
        /// Workload name.
        name: String,
        /// OCI image reference, e.g. `nginx:1.27` or `ghcr.io/owner/app:tag`.
        #[arg(long)]
        image: String,
        /// vmlinux kernel: a blob hash, a local file, or a URL (provision once,
        /// shared). Omit to use the node's configured default kernel.
        #[arg(long)]
        kernel: Option<String>,
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
        /// Allow a writable root filesystem (single-tenant posture only; the
        /// hardened read-only root is the default). Prefer a persistent volume.
        #[arg(long)]
        writable_root: bool,
        /// Add back a Linux capability on the shared-kernel backends, without the
        /// `CAP_` prefix, e.g. `CHOWN` (repeatable). Single-tenant posture only.
        #[arg(long = "cap-add")]
        cap_add: Vec<String>,
        /// Run the entrypoint as this user (`uid` or `uid:gid`, numeric) instead of the
        /// backend default. Lets a stock image run rootless against a pre-owned volume.
        #[arg(long)]
        user: Option<String>,
        /// Isolation the workload requires (`trusted` allows containers;
        /// `untrusted` forces a microVM / managed platform).
        #[arg(long, value_enum, default_value_t = Isolation::Trusted)]
        isolation: Isolation,
        /// Allowed region (repeatable).
        #[arg(long = "region")]
        regions: Vec<String>,
        /// Managed binding, `<kind>[:<name>]` (repeatable) — see `compute set --bind`.
        #[arg(long = "bind")]
        bind: Vec<String>,
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
            Restart::Never => Self::Never,
            Restart::OnFailure => Self::OnFailure,
            Restart::Always => Self::Always,
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
            Isolation::Trusted => Self::Trusted,
            Isolation::Untrusted => Self::Untrusted,
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
    let cp = client::ControlPlane::new(
        server.clone(),
        http.clone(),
        client::resolve_project(config),
    );
    // Honor `--project`: every workload URL is scoped to the collection segment
    // (`compute` for default, else `projects/<proj>/compute`), so `--project` is no
    // longer silently dropped on the write path.
    let seg = client::project_seg(&client::resolve_project(config), "compute");

    match args.command {
        ComputeCommand::Ls => {
            let workloads: serde_json::Value = http
                .get(format!("{server}/api/{seg}"))
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
                .get(format!("{server}/api/{seg}/{name}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&workload)?);
        }
        ComputeCommand::Set {
            name,
            image,
            tar,
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
            writable_root,
            cap_add,
            user,
            isolation,
            regions,
            bind,
        } => {
            // Exactly one of `--image` (an OCI reference, verbatim), `--tar` (a rootfs
            // archive, uploaded), or `--rootfs` (a rootfs filesystem image, uploaded)
            // picks the root-filesystem source. Clap's `root` group enforces at-most-one.
            let root = match (image, tar, rootfs) {
                (Some(i), None, None) => RootSource::Image(i),
                (None, Some(t), None) => RootSource::Tar(cp.resolve_artifact(&t).await?),
                (None, None, Some(r)) => RootSource::Rootfs(cp.resolve_artifact(&r).await?),
                (None, None, None) => {
                    return Err(Error::Args(
                        "one of --image, --tar, or --rootfs is required".into(),
                    ))
                }
                _ => {
                    return Err(Error::Args(
                        "give only one of --image, --tar, or --rootfs".into(),
                    ))
                }
            };
            // `--kernel` accepts a blob hash, a local file, or a URL.
            let kernel = match kernel {
                Some(k) => cp.resolve_artifact(&k).await?,
                None => String::new(), // empty ⇒ the node substitutes its default
            };
            let spec = build_spec(
                root,
                kernel,
                vcpus,
                mem_mib,
                port,
                entrypoint,
                env,
                restart,
                scale_to_zero,
                writable_root,
                cap_add,
                user,
                isolation,
                parse_bindings(&bind)?,
            )?;
            let hash = put_workload(&http, &server, &seg, &name, spec, replicas, regions).await?;
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
            writable_root,
            cap_add,
            user,
            isolation,
            regions,
            bind,
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
            let kernel = match kernel {
                Some(k) => cp.resolve_artifact(&k).await?,
                None => String::new(), // empty ⇒ the node substitutes its default
            };
            // Hash + upload the freshly built rootfs as a content-addressed blob.
            let rootfs = cp.put_file_blob(&out).await?;
            let _ = std::fs::remove_file(&out);
            eprintln!("rootfs blob {rootfs} uploaded");
            let spec = build_spec(
                RootSource::Rootfs(rootfs),
                kernel,
                vcpus,
                mem_mib,
                port,
                entrypoint,
                env,
                restart,
                scale_to_zero,
                writable_root,
                cap_add,
                user,
                isolation,
                parse_bindings(&bind)?,
            )?;
            let hash = put_workload(&http, &server, &seg, &name, spec, replicas, regions).await?;
            println!("workload {name} built + set (spec {hash})");
        }
        ComputeCommand::Rm { name } => {
            http.delete(format!("{server}/api/{seg}/{name}"))
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
    root: RootSource,
    kernel: String,
    vcpus: u32,
    mem_mib: u32,
    port: u16,
    entrypoint: Vec<String>,
    env: Vec<String>,
    restart: Restart,
    scale_to_zero: bool,
    writable_root: bool,
    cap_add: Vec<String>,
    user: Option<String>,
    isolation: Isolation,
    bindings: Vec<ComputeBinding>,
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
        root,
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
        writable_root,
        cap_add,
        user,
        isolation: isolation.into(),
        prefer_backend: None,
        bindings,
    })
}

/// Parse `--bind <kind>[:<name>]` flags into [`ComputeBinding`]s. `sql` binds the
/// site default database; `sql:analytics` binds the named external DB.
fn parse_bindings(flags: &[String]) -> Result<Vec<ComputeBinding>> {
    flags
        .iter()
        .map(|raw| {
            let (kind, name) = raw.split_once(':').unwrap_or((raw.as_str(), ""));
            let kind = match kind {
                "sql" => BindingKind::Sql,
                "kv" => BindingKind::Kv,
                "blob" => BindingKind::Blob,
                "messaging" => BindingKind::Messaging,
                other => return Err(Error::Args(format!("unknown binding kind `{other}`"))),
            };
            Ok(ComputeBinding {
                kind,
                name: name.to_string(),
                url_env: None,
            })
        })
        .collect()
}

/// PUT a workload's desired state; returns the stored spec hash.
async fn put_workload(
    http: &crate::client::ApiClient,
    server: &str,
    seg: &str,
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
        .put(format!("{server}/api/{seg}/{name}"))
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp["spec"].as_str().unwrap_or("").to_string())
}
