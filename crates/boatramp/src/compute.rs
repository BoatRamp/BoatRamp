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
    /// The control-plane returned an error response.
    #[error("{0}")]
    Server(String),
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
        /// Seconds a freshly launched replica has to become healthy before the reconcile
        /// loop treats a still-unhealthy replica as a broken launch to stop + relaunch.
        /// Raise it for a slow-initializing image (a stock database's first `initdb`) so
        /// it isn't killed mid-init. Omit for the default (30).
        #[arg(long)]
        startup_grace_secs: Option<u32>,
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
        /// Seconds a freshly launched replica has to become healthy before it's treated
        /// as a broken launch (see `compute set --startup-grace-secs`). Omit for the
        /// default (30).
        #[arg(long)]
        startup_grace_secs: Option<u32>,
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
    /// Run a command inside a running workload replica (docker-exec style) — e.g.
    /// pipe a SQL file into `psql`, or run `pg_dump`. Requires the server's
    /// `allow_compute_exec` posture; container + docker backends only. The command's
    /// stdout/stderr are printed and this process exits with its exit code.
    Exec {
        /// Workload name.
        name: String,
        /// Feed this process's standard input to the command (pipe a file in).
        #[arg(long)]
        stdin: bool,
        /// The command argv — everything after `--`, e.g. `-- psql -U app -d appdb`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Manage persistent volumes: list them (with in-use / orphaned status) and
    /// reclaim a decommissioned workload's volume. The safe flow is `compute rm
    /// <workload>` first (unregister → the reconcile loop stops it), then
    /// `compute volume rm <name>`.
    #[command(subcommand)]
    Volume(VolumeCommand),
    /// Show observed per-replica runtime state — the reconcile plane's X-ray: stored
    /// health, lifecycle phase, assigned IP:port, age vs startup grace, backend. This
    /// is the record the endpoint resolver reads, so `HEALTHY=false` on a `running`,
    /// endpoint-bearing replica is the "reachable but not served" signature. Node-global
    /// (every tenant on the node); admin-scoped.
    Status {
        /// Show only this workload's replicas (default: every workload).
        workload: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = StatusFormat::Table)]
        format: StatusFormat,
    },
    /// Force one replica's stored health flag — the escape hatch when a recovered
    /// replica is stuck `healthy=false` and the endpoint resolver therefore won't serve
    /// it (the v0.3.12→v0.3.13 class), without waiting for a binary patch. Targets the
    /// `--project` tenant's workload. Node-global; admin-scoped.
    SetHealth {
        /// Workload name.
        workload: String,
        /// Replica ordinal.
        replica: u32,
        /// The health value to persist (`--healthy true` | `--healthy false`).
        #[arg(long, action = clap::ArgAction::Set)]
        healthy: bool,
    },
    /// Inspect the compute IP plane (`ip ls`): every replica's assigned IP, with
    /// duplicate-IP collisions flagged. Node-global; admin-scoped.
    #[command(subcommand)]
    Ip(IpCommand),
    /// Force the reconcile loop to run a convergence pass now (the "kick it" lever for
    /// a workload stuck mid-reconcile) instead of waiting for the next periodic tick.
    /// Fire-and-forget — follow with `compute status` to see the result. Node-global;
    /// admin-scoped.
    Reconcile,
    /// Restart one replica: stop it and let the reconcile loop relaunch a fresh one
    /// (re-running IP allocation) — the live workaround for a wedged replica or a stale
    /// IP assignment. Targets the `--project` tenant's workload. Node-global;
    /// admin-scoped.
    Restart {
        /// Workload name.
        workload: String,
        /// Replica ordinal.
        replica: u32,
    },
    /// Inspect internal service discovery (`dns ls` / `dns resolve <workload>`): the
    /// name → healthy-replica-IP map a co-located guest resolves. Node-global;
    /// admin-scoped.
    #[command(subcommand)]
    Dns(DnsCommand),
    /// Actively probe a workload's replicas from the node — a TCP reachability check
    /// against each replica's endpoint, alongside its stored state. Answers "can the
    /// node actually reach this replica right now?"; `REACHABLE=yes` + `HEALTHY=no` is
    /// the reachable-but-not-served signature. Targets the `--project` tenant's
    /// workload. Node-global; admin-scoped.
    Netdiag {
        /// Workload name.
        workload: String,
    },
}

/// `boatramp compute ip …` — IP-plane diagnostics.
#[derive(Debug, Subcommand)]
enum IpCommand {
    /// List IP assignments (IP / OWNER / HEALTHY), flagging duplicate-IP collisions.
    Ls,
}

/// `boatramp compute dns …` — internal service-discovery diagnostics.
#[derive(Debug, Subcommand)]
enum DnsCommand {
    /// List internal names and the healthy replica IPs each resolves to.
    Ls,
    /// Resolve one workload's internal name (in the `--project` tenant) to its healthy
    /// replica IPs — exactly as a same-project peer's lookup would.
    Resolve {
        /// Workload name.
        workload: String,
    },
}

/// Output format for `compute status`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum StatusFormat {
    /// A plain text table.
    Table,
    /// The raw JSON array of replica views.
    Json,
}

/// `boatramp compute volume …` — persistent-volume management.
#[derive(Debug, Subcommand)]
enum VolumeCommand {
    /// List persistent volumes (NAME / SIZE / IN-USE).
    Ls,
    /// Remove a persistent volume by name. Refused if a registered workload still
    /// references it, unless `--force`.
    Rm {
        /// Volume name.
        name: String,
        /// Remove even when a registered workload's spec still references it (the
        /// disposable-data override). Prefer `compute rm <workload>` first.
        #[arg(long)]
        force: bool,
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
            startup_grace_secs,
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
                startup_grace_secs,
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
            startup_grace_secs,
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
                startup_grace_secs,
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
        ComputeCommand::Exec { name, stdin, argv } => {
            use base64::Engine;
            use std::io::{Read, Write};
            let b64 = base64::engine::general_purpose::STANDARD;
            let stdin_b64 = if stdin {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                Some(b64.encode(&buf))
            } else {
                None
            };
            let body = serde_json::json!({ "argv": argv, "stdin_b64": stdin_b64 });
            let resp = http
                .post(format!("{server}/api/{seg}/{name}/exec"))
                .json(&body)
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "compute exec failed: {status}: {}",
                    text.trim()
                )));
            }
            let out: serde_json::Value = resp.json().await?;
            if let Some(s) = out["stdout_b64"].as_str() {
                std::io::stdout()
                    .write_all(&b64.decode(s).unwrap_or_default())
                    .ok();
            }
            if let Some(s) = out["stderr_b64"].as_str() {
                std::io::stderr()
                    .write_all(&b64.decode(s).unwrap_or_default())
                    .ok();
            }
            // Mirror the command's exit code so scripts see failures.
            let code = out["exit_code"].as_i64().unwrap_or(0);
            if code != 0 {
                std::process::exit(code as i32);
            }
        }
        ComputeCommand::Volume(VolumeCommand::Ls) => {
            let vols: serde_json::Value = http
                .get(format!("{server}/api/{seg}/volumes"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let arr = vols.as_array().cloned().unwrap_or_default();
            if arr.is_empty() {
                println!("no volumes");
                return Ok(());
            }
            let (name_h, size_h, in_use_h) = ("NAME", "SIZE", "IN-USE");
            println!("{name_h:<24}  {size_h:>12}  {in_use_h}");
            for v in arr {
                let name = v["name"].as_str().unwrap_or("?");
                let size = human_size(v["size_bytes"].as_u64().unwrap_or(0));
                let in_use = if v["in_use"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "no"
                };
                println!("{name:<24}  {size:>12}  {in_use}");
            }
        }
        ComputeCommand::Volume(VolumeCommand::Rm { name, force }) => {
            let mut url = format!("{server}/api/{seg}/volumes/{name}");
            if force {
                url.push_str("?force=true");
            }
            let resp = http.delete(url).send().await?;
            match resp.status() {
                s if s.is_success() => println!("removed {name}"),
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(Error::Server(format!("no such volume {name:?}")))
                }
                reqwest::StatusCode::CONFLICT => {
                    return Err(Error::Server(format!(
                        "volume {name:?} in use by a registered workload; `compute rm` it \
                         first, or pass --force"
                    )))
                }
                s => {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(Error::Server(format!(
                        "remove volume failed: {s}: {}",
                        text.trim()
                    )));
                }
            }
        }
        // Node-global operator tools hit the direct `/api/compute/…` maintenance surface
        // (admin-scoped, tenant-agnostic) rather than the project-scoped `seg`.
        ComputeCommand::Status { workload, format } => {
            let mut states: Vec<serde_json::Value> = http
                .get(format!("{server}/api/compute/status"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if let Some(wl) = &workload {
                states.retain(|s| s["workload"].as_str() == Some(wl.as_str()));
            }
            match format {
                StatusFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&states)?);
                }
                StatusFormat::Table => {
                    if states.is_empty() {
                        println!("no replicas");
                        return Ok(());
                    }
                    println!(
                        "{:<28}  {:>3}  {:<7}  {:<21}  {:<7}  {:>6}  BACKEND",
                        "PROJECT/WORKLOAD", "REP", "HEALTHY", "ENDPOINT", "PHASE", "AGE"
                    );
                    for s in &states {
                        let owner = format!(
                            "{}/{}",
                            s["project"].as_str().unwrap_or("?"),
                            s["workload"].as_str().unwrap_or("?")
                        );
                        let rep = s["replica"].as_u64().unwrap_or(0);
                        let healthy = if s["healthy"].as_bool().unwrap_or(false) {
                            "yes"
                        } else {
                            "NO"
                        };
                        let endpoint = format!(
                            "{}:{}",
                            s["host"].as_str().unwrap_or("?"),
                            s["port"].as_u64().unwrap_or(0)
                        );
                        let phase = s["phase"].as_str().unwrap_or("?");
                        let age = match s["age_secs"].as_u64() {
                            Some(a) => format!("{a}s"),
                            None => "-".to_string(),
                        };
                        let backend = s["backend"].as_str().unwrap_or("?");
                        println!(
                            "{owner:<28}  {rep:>3}  {healthy:<7}  {endpoint:<21}  {phase:<7}  {age:>6}  {backend}"
                        );
                    }
                }
            }
        }
        ComputeCommand::SetHealth {
            workload,
            replica,
            healthy,
        } => {
            let body = serde_json::json!({
                "project": client::resolve_project(config),
                "workload": workload,
                "replica": replica,
                "healthy": healthy,
            });
            let resp = http
                .post(format!("{server}/api/compute/maintenance/set-health"))
                .json(&body)
                .send()
                .await?;
            match resp.status() {
                s if s.is_success() => {
                    let view: serde_json::Value = resp.json().await?;
                    println!(
                        "set {}/{} replica {} healthy={}",
                        view["project"].as_str().unwrap_or("?"),
                        view["workload"].as_str().unwrap_or("?"),
                        view["replica"].as_u64().unwrap_or(0),
                        view["healthy"].as_bool().unwrap_or(false)
                    );
                }
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(Error::Server(format!(
                        "no such replica: {workload} #{replica} (in project {:?})",
                        client::resolve_project(config)
                    )))
                }
                s => {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(Error::Server(format!(
                        "set-health failed: {s}: {}",
                        text.trim()
                    )));
                }
            }
        }
        ComputeCommand::Ip(IpCommand::Ls) => {
            let view: serde_json::Value = http
                .get(format!("{server}/api/compute/ipam"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let assignments = view["assignments"].as_array().cloned().unwrap_or_default();
            let dups: Vec<String> = view["duplicates"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if assignments.is_empty() {
                println!("no IP assignments");
                return Ok(());
            }
            println!("{:<16}  {:<30}  {:<7}  PHASE", "IP", "OWNER", "HEALTHY");
            for a in &assignments {
                let ip = a["ip"].as_str().unwrap_or("?");
                let owner = format!(
                    "{}/{}#{}",
                    a["project"].as_str().unwrap_or("?"),
                    a["workload"].as_str().unwrap_or("?"),
                    a["replica"].as_u64().unwrap_or(0)
                );
                let healthy = if a["healthy"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "NO"
                };
                let phase = a["phase"].as_str().unwrap_or("?");
                let flag = if dups.iter().any(|d| d == ip) {
                    "  <-- COLLISION"
                } else {
                    ""
                };
                println!("{ip:<16}  {owner:<30}  {healthy:<7}  {phase}{flag}");
            }
            if !dups.is_empty() {
                println!(
                    "\n{} duplicate IP(s) detected: {}",
                    dups.len(),
                    dups.join(", ")
                );
            }
        }
        ComputeCommand::Reconcile => {
            let resp = http
                .post(format!("{server}/api/compute/reconcile"))
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                println!("reconcile pass requested; run `boatramp compute status` for the result");
            } else {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "reconcile request failed: {status}: {}",
                    text.trim()
                )));
            }
        }
        ComputeCommand::Restart { workload, replica } => {
            let body = serde_json::json!({
                "project": client::resolve_project(config),
                "workload": workload,
                "replica": replica,
            });
            let resp = http
                .post(format!("{server}/api/compute/maintenance/restart"))
                .json(&body)
                .send()
                .await?;
            match resp.status() {
                s if s.is_success() => {
                    println!("restarted {workload} replica {replica}; reconcile will relaunch it");
                }
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(Error::Server(format!(
                        "no such replica: {workload} #{replica} (in project {:?})",
                        client::resolve_project(config)
                    )))
                }
                s => {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(Error::Server(format!(
                        "restart failed: {s}: {}",
                        text.trim()
                    )));
                }
            }
        }
        ComputeCommand::Dns(DnsCommand::Ls) => {
            let entries: Vec<serde_json::Value> = http
                .get(format!("{server}/api/compute/dns"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if entries.is_empty() {
                println!("no internal names");
                return Ok(());
            }
            println!("{:<32}  {:>4}  HEALTHY ADDRS", "NAME", "REPS");
            for e in &entries {
                let name = e["name"].as_str().unwrap_or("?");
                let reps = e["replicas"].as_u64().unwrap_or(0);
                let addrs: Vec<&str> = e["addrs"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let shown = if addrs.is_empty() {
                    "(none — unresolved)".to_string()
                } else {
                    addrs.join(", ")
                };
                println!("{name:<32}  {reps:>4}  {shown}");
            }
        }
        ComputeCommand::Dns(DnsCommand::Resolve { workload }) => {
            let body = serde_json::json!({
                "project": client::resolve_project(config),
                "workload": workload,
            });
            let e: serde_json::Value = http
                .post(format!("{server}/api/compute/dns/resolve"))
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let name = e["name"].as_str().unwrap_or("?");
            let addrs: Vec<&str> = e["addrs"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            if addrs.is_empty() {
                println!("{name} resolves to nothing (no healthy replica)");
            } else {
                println!("{name} -> {}", addrs.join(", "));
            }
        }
        ComputeCommand::Netdiag { workload } => {
            let body = serde_json::json!({
                "project": client::resolve_project(config),
                "workload": workload,
            });
            let replicas: Vec<serde_json::Value> = http
                .post(format!("{server}/api/compute/maintenance/netdiag"))
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if replicas.is_empty() {
                println!("no replicas for {workload}");
                return Ok(());
            }
            println!(
                "{:>3}  {:<21}  {:<9}  {:<7}  {:<7}  BACKEND",
                "REP", "ENDPOINT", "REACHABLE", "HEALTHY", "PHASE"
            );
            for r in &replicas {
                let rep = r["replica"].as_u64().unwrap_or(0);
                let endpoint = r["endpoint"].as_str().unwrap_or("?");
                let reachable = if r["tcp_reachable"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "NO"
                };
                let healthy = if r["healthy"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "NO"
                };
                let phase = r["phase"].as_str().unwrap_or("?");
                let backend = r["backend"].as_str().unwrap_or("?");
                println!(
                    "{rep:>3}  {endpoint:<21}  {reachable:<9}  {healthy:<7}  {phase:<7}  {backend}"
                );
            }
        }
    }
    Ok(())
}

/// Render a byte count as a compact human-readable size for the `volume ls` table.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
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
    startup_grace_secs: Option<u32>,
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
        // Omitted ⇒ the generic spec default (30). An operator raises it for a
        // slow-initializing image.
        startup_grace_secs: startup_grace_secs
            .unwrap_or_else(boatramp_core::compute::default_startup_grace_secs),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal top-level parser mirroring `main`'s `compute` arm, so the
    /// `compute volume …` surface can be arg-parsed in isolation.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Compute(ComputeArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<ComputeCommand, clap::Error> {
        let cli = Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))?;
        let Cmd::Compute(args) = cli.cmd;
        Ok(args.command)
    }

    #[test]
    fn compute_volume_ls_and_rm_parse() {
        assert!(matches!(
            parse(&["compute", "volume", "ls"]),
            Ok(ComputeCommand::Volume(VolumeCommand::Ls))
        ));
        // `rm <name>` defaults to no force.
        match parse(&["compute", "volume", "rm", "data"]) {
            Ok(ComputeCommand::Volume(VolumeCommand::Rm { name, force })) => {
                assert_eq!(name, "data");
                assert!(!force);
            }
            other => panic!("expected volume rm, got {other:?}"),
        }
        // `--force` flips the override.
        match parse(&["compute", "volume", "rm", "data", "--force"]) {
            Ok(ComputeCommand::Volume(VolumeCommand::Rm { name, force })) => {
                assert_eq!(name, "data");
                assert!(force);
            }
            other => panic!("expected forced volume rm, got {other:?}"),
        }
        // `rm` requires a name.
        assert!(parse(&["compute", "volume", "rm"]).is_err());
    }

    #[test]
    fn compute_set_startup_grace_parses_and_defaults() {
        // `--startup-grace-secs 45` parses into the field and flows into the spec.
        match parse(&[
            "compute",
            "set",
            "db",
            "--image",
            "pgvector/pgvector:pg16",
            "--port",
            "5432",
            "--startup-grace-secs",
            "45",
        ]) {
            Ok(ComputeCommand::Set {
                startup_grace_secs, ..
            }) => assert_eq!(startup_grace_secs, Some(45)),
            other => panic!("expected compute set, got {other:?}"),
        }
        // Omitted ⇒ None ⇒ the generic spec default (30) in `build_spec`.
        match parse(&[
            "compute",
            "set",
            "db",
            "--image",
            "pgvector/pgvector:pg16",
            "--port",
            "5432",
        ]) {
            Ok(ComputeCommand::Set {
                startup_grace_secs, ..
            }) => assert_eq!(startup_grace_secs, None),
            other => panic!("expected compute set, got {other:?}"),
        }

        // The Some(45) value lands in the built spec; None yields the default (30).
        let with = build_spec(
            RootSource::Image("img".into()),
            String::new(),
            1,
            256,
            5432,
            vec![],
            vec![],
            Restart::Always,
            false,
            Some(45),
            false,
            vec![],
            None,
            Isolation::Trusted,
            vec![],
        )
        .unwrap();
        assert_eq!(with.startup_grace_secs, 45);
        let dflt = build_spec(
            RootSource::Image("img".into()),
            String::new(),
            1,
            256,
            5432,
            vec![],
            vec![],
            Restart::Always,
            false,
            None,
            false,
            vec![],
            None,
            Isolation::Trusted,
            vec![],
        )
        .unwrap();
        assert_eq!(dflt.startup_grace_secs, 30);
    }

    #[test]
    fn human_size_scales_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
