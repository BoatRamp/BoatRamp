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
        /// `sql` binds the site database, `sql:analytics` a named external DB; `blob`
        /// binds the site blob store, `blob:assets` one named container; `messaging` binds
        /// the project bus — BOTH halves, publish AND consume (claim/ack/nack) — `messaging:
        /// deliver` one topic. The endpoint URL + token are injected into the guest env
        /// (`BOATRAMP_SQL_URL` / `BOATRAMP_BLOB_URL` / `BOATRAMP_MESSAGING_URL`). NOTE: a bare
        /// `blob` (no `:<name>`) is SITE-WIDE — the workload can read/write EVERY container in
        /// its site's `hblob/{site}/` space; use `blob:<name>` to confine it. Likewise a bare
        /// `messaging` is PROJECT-BUS-WIDE (any topic under `{project}/bus/`, for both publish
        /// and claim); use `messaging:<topic>` to confine it to one topic.
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
    /// Mint a blob-shim credential for a NON-managed local process (dev/CI) and print it
    /// as env — the blob analogue of `DATABASE_URL`. The process then reads/writes the
    /// SAME `--site` blob namespace a managed workload (or a `wasi:blobstore` handler) for
    /// that site sees, so a handler↔native-worker shared-blob round-trip can be exercised
    /// offline. Requires the server's `allow_dev_blob_bind` posture (on by default only in
    /// `dev`); System·Admin. Example:
    /// `eval "$(boatramp compute bind-blob --site mailroom --export)"`.
    BindBlob {
        /// The site (the workload identity) whose blob namespace to bind.
        #[arg(long)]
        site: String,
        /// Confine the credential to one container (`--bind blob:<container>`); omit for a
        /// site-wide credential.
        #[arg(long)]
        container: Option<String>,
        /// The project owning the blob namespace (default `default`).
        #[arg(long)]
        project: Option<String>,
        /// Prefix each line with `export ` so the output is `eval`-able in a shell.
        #[arg(long)]
        export: bool,
    },
    /// Mint a messaging-shim credential for a NON-managed local process (dev/CI) and print it as
    /// env — the messaging analogue of `bind-blob` (#07) / `DATABASE_URL`. The credential covers
    /// BOTH halves of the SAME `{project}/bus/<topic>` project bus a managed `--bind messaging`
    /// workload (or a `wasi:messaging` handler) for that project reaches: the process can publish
    /// AND claim/ack/nack, so either a native-producer → consumer-function, or a function-producer
    /// → native-consumer, bus round-trip can be exercised offline. Requires the server's
    /// `allow_dev_messaging_bind` posture (on by default only in `dev`); System·Admin.
    /// Example: `eval "$(boatramp compute bind-messaging --topic deliver --export)"`.
    BindMessaging {
        /// Confine the credential to one topic (`--bind messaging:<topic>`); omit for a
        /// project-bus-wide credential (any topic under `{project}/bus/`).
        #[arg(long)]
        topic: Option<String>,
        /// The project owning the bus (default `default`).
        #[arg(long)]
        project: Option<String>,
        /// Prefix each line with `export ` so the output is `eval`-able in a shell.
        #[arg(long)]
        export: bool,
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
    /// Reap stuck ORPHANED compute replicas — a replica with NO desired workload AND no
    /// live container that the reconcile plane ignores (it converges only against desired
    /// workloads). DESTRUCTIVE + node-global; admin-scoped. **Dry-run by default**: it
    /// reports what it WOULD reap and changes nothing unless `--execute` is passed. Fail-
    /// closed — it never reaps a replica that is live or part of a desired spec, even one
    /// you name explicitly. Name a `<workload>` + `--replica` to target one; omit both to
    /// scan every project.
    Reap {
        /// Reap only this workload's replica (requires `--replica`). Omit to scan all.
        workload: Option<String>,
        /// Replica ordinal (with `<workload>`).
        #[arg(long)]
        replica: Option<u32>,
        /// Actually reap. Without this the command is a dry-run (report only).
        #[arg(long)]
        execute: bool,
        /// Also delete the orphan's persistent volume staging (e.g. a stranded managed-PG
        /// PGDATA). Off by default — the record + container are reaped but data preserved.
        #[arg(long)]
        reclaim_volumes: bool,
        /// Minimum orphan age (seconds) required before acting. Default 0 for an explicit
        /// target (the no-desired-workload + container-gone checks are the real guarantee).
        #[arg(long)]
        grace_secs: Option<u64>,
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

/// The result of a `boatramp compute` subcommand, rendered by [`crate::output`].
///
/// Each variant carries the facts a JSON consumer reads; [`render_human`](crate::output::Rendered::render_human)
/// reproduces the text the command historically printed (including the list/status tables). `compute
/// get` renders its workload as pretty JSON (its historical human view); `--output-format json`
/// renders the typed shape below for every subcommand.
///
/// `compute exec` is a raw stdout/stderr passthrough with exit-code mirroring and does NOT appear
/// here — see the `Exec` arm of [`run`].
#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ComputeOutput {
    /// `compute ls` — the workloads (as returned by the control plane).
    Ls { workloads: Vec<serde_json::Value> },
    /// `compute get` — one workload's desired state.
    Get { workload: serde_json::Value },
    /// `compute set` — the workload was created/updated.
    Set { name: String, spec: String },
    /// `compute build` — the rootfs was built, uploaded, and the workload set.
    Build { name: String, spec: String },
    /// `compute rm` — the workload was removed.
    Rm { name: String },
    /// `compute bind-blob` — the injected blob-shim env (as `K=V` pairs).
    BindBlob {
        /// Whether `--export` was requested (prefixes each human line with `export `).
        #[serde(skip)]
        export: bool,
        /// The env pairs to inject.
        env: Vec<(String, String)>,
    },
    /// `compute bind-messaging` — the injected messaging-shim env (as `K=V` pairs).
    BindMessaging {
        /// Whether `--export` was requested (prefixes each human line with `export `).
        #[serde(skip)]
        export: bool,
        /// The env pairs to inject.
        env: Vec<(String, String)>,
    },
    /// `compute volume ls` — the persistent volumes.
    VolumeLs { volumes: Vec<serde_json::Value> },
    /// `compute volume rm` — the volume was removed.
    VolumeRm { name: String },
    /// `compute status` — observed per-replica runtime state. The human view is a table;
    /// `--output-format json` serializes `states` structurally.
    Status {
        /// The replica views (optionally filtered to one workload).
        states: Vec<serde_json::Value>,
    },
    /// `compute set-health` — a replica's stored health flag was forced.
    SetHealth {
        project: String,
        workload: String,
        replica: u64,
        healthy: bool,
    },
    /// `compute ip ls` — the IP-plane assignments, with duplicate collisions flagged.
    IpLs {
        assignments: Vec<serde_json::Value>,
        duplicates: Vec<String>,
    },
    /// `compute reconcile` — a convergence pass was requested.
    Reconcile,
    /// `compute restart` — a replica was stopped for the reconcile loop to relaunch.
    Restart { workload: String, replica: u32 },
    /// `compute dns ls` — the internal name → healthy-replica-IP map.
    DnsLs { entries: Vec<serde_json::Value> },
    /// `compute dns resolve` — one workload's internal name resolution.
    DnsResolve { name: String, addrs: Vec<String> },
    /// `compute netdiag` — active per-replica TCP reachability probe results.
    Netdiag {
        workload: String,
        replicas: Vec<serde_json::Value>,
    },
    /// `compute reap` — the orphan-reaper report (dry-run or executed).
    Reap {
        /// Whether this was a dry-run (report-only).
        dry_run: bool,
        /// The per-orphan entries (`orphan`, `disposition`, `volume_reclaimed`).
        entries: Vec<serde_json::Value>,
    },
}

impl crate::output::Rendered for ComputeOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Ls { workloads } => write_ls(workloads, w),
            Self::Get { workload } => writeln!(
                w,
                "{}",
                serde_json::to_string_pretty(workload).map_err(std::io::Error::other)?
            ),
            Self::Set { name, spec } => writeln!(w, "workload {name} set (spec {spec})"),
            Self::Build { name, spec } => {
                writeln!(w, "workload {name} built + set (spec {spec})")
            }
            Self::Rm { name } => writeln!(w, "removed {name}"),
            Self::BindBlob { export, env } | Self::BindMessaging { export, env } => {
                let prefix = if *export { "export " } else { "" };
                for (k, v) in env {
                    writeln!(w, "{prefix}{k}={v}")?;
                }
                Ok(())
            }
            Self::VolumeLs { volumes } => write_volume_ls(volumes, w),
            Self::VolumeRm { name } => writeln!(w, "removed {name}"),
            Self::Status { states } => write_status(states, w),
            Self::SetHealth {
                project,
                workload,
                replica,
                healthy,
            } => writeln!(
                w,
                "set {project}/{workload} replica {replica} healthy={healthy}"
            ),
            Self::IpLs {
                assignments,
                duplicates,
            } => write_ip_ls(assignments, duplicates, w),
            Self::Reconcile => writeln!(
                w,
                "reconcile pass requested; run `boatramp compute status` for the result"
            ),
            Self::Restart { workload, replica } => {
                writeln!(
                    w,
                    "restarted {workload} replica {replica}; reconcile will relaunch it"
                )
            }
            Self::DnsLs { entries } => write_dns_ls(entries, w),
            Self::DnsResolve { name, addrs } => {
                if addrs.is_empty() {
                    writeln!(w, "{name} resolves to nothing (no healthy replica)")
                } else {
                    writeln!(w, "{name} -> {}", addrs.join(", "))
                }
            }
            Self::Netdiag { workload, replicas } => write_netdiag(workload, replicas, w),
            Self::Reap { dry_run, entries } => write_reap(*dry_run, entries, w),
        }
    }
}

/// Render the `compute reap` report.
fn write_reap(
    dry_run: bool,
    entries: &[serde_json::Value],
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if dry_run {
        writeln!(w, "DRY-RUN (nothing was reaped — pass --execute to act)")?;
    }
    if entries.is_empty() {
        return writeln!(w, "no orphaned replicas");
    }
    for e in entries {
        let o = &e["orphan"];
        let owner = format!(
            "{}/{}/{}",
            o["project"].as_str().unwrap_or("?"),
            o["workload"].as_str().unwrap_or("?"),
            o["replica"].as_u64().unwrap_or(0)
        );
        // `disposition` is a snake_case-tagged enum: "would_reap" / "reaped" /
        // { "skipped": { "reason": ... } }.
        let disp = &e["disposition"];
        let (verb, detail) = if disp == "would_reap" {
            ("WOULD REAP".to_string(), String::new())
        } else if disp == "reaped" {
            let vol = if e["volume_reclaimed"].as_bool().unwrap_or(false) {
                " (+ volume reclaimed)"
            } else {
                ""
            };
            ("REAPED".to_string(), vol.to_string())
        } else if let Some(reason) = disp["skipped"]["reason"].as_str() {
            ("skipped".to_string(), format!(": {reason}"))
        } else {
            ("?".to_string(), String::new())
        };
        writeln!(w, "{owner}  {verb}{detail}")?;
    }
    Ok(())
}

/// Render the `compute ls` listing.
fn write_ls(workloads: &[serde_json::Value], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    if workloads.is_empty() {
        return writeln!(w, "no workloads");
    }
    for wl in workloads {
        let name = wl["name"].as_str().unwrap_or("?");
        let replicas = wl["replicas"].as_u64().unwrap_or(0);
        let active = wl["active"].as_str().unwrap_or("");
        let short = &active[..active.len().min(12)];
        writeln!(w, "{name}  replicas={replicas}  active={short}")?;
    }
    Ok(())
}

/// Render the `compute volume ls` table.
fn write_volume_ls(
    volumes: &[serde_json::Value],
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if volumes.is_empty() {
        return writeln!(w, "no volumes");
    }
    let (name_h, size_h, in_use_h) = ("NAME", "SIZE", "IN-USE");
    writeln!(w, "{name_h:<24}  {size_h:>12}  {in_use_h}")?;
    for v in volumes {
        let name = v["name"].as_str().unwrap_or("?");
        let size = human_size(v["size_bytes"].as_u64().unwrap_or(0));
        let in_use = if v["in_use"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        writeln!(w, "{name:<24}  {size:>12}  {in_use}")?;
    }
    Ok(())
}

/// Render the `compute status` table.
fn write_status(states: &[serde_json::Value], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    if states.is_empty() {
        return writeln!(w, "no replicas");
    }
    writeln!(
        w,
        "{:<28}  {:>3}  {:<7}  {:<21}  {:<7}  {:>6}  BACKEND",
        "PROJECT/WORKLOAD", "REP", "HEALTHY", "ENDPOINT", "PHASE", "AGE"
    )?;
    for s in states {
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
        writeln!(
            w,
            "{owner:<28}  {rep:>3}  {healthy:<7}  {endpoint:<21}  {phase:<7}  {age:>6}  {backend}"
        )?;
    }
    Ok(())
}

/// Render the `compute ip ls` table, flagging duplicate-IP collisions.
fn write_ip_ls(
    assignments: &[serde_json::Value],
    duplicates: &[String],
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if assignments.is_empty() {
        return writeln!(w, "no IP assignments");
    }
    writeln!(w, "{:<16}  {:<30}  {:<7}  PHASE", "IP", "OWNER", "HEALTHY")?;
    for a in assignments {
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
        let flag = if duplicates.iter().any(|d| d == ip) {
            "  <-- COLLISION"
        } else {
            ""
        };
        writeln!(w, "{ip:<16}  {owner:<30}  {healthy:<7}  {phase}{flag}")?;
    }
    if !duplicates.is_empty() {
        writeln!(
            w,
            "\n{} duplicate IP(s) detected: {}",
            duplicates.len(),
            duplicates.join(", ")
        )?;
    }
    Ok(())
}

/// Render the `compute dns ls` table.
fn write_dns_ls(entries: &[serde_json::Value], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    if entries.is_empty() {
        return writeln!(w, "no internal names");
    }
    writeln!(w, "{:<32}  {:>4}  HEALTHY ADDRS", "NAME", "REPS")?;
    for e in entries {
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
        writeln!(w, "{name:<32}  {reps:>4}  {shown}")?;
    }
    Ok(())
}

/// Render the `compute netdiag` table.
fn write_netdiag(
    workload: &str,
    replicas: &[serde_json::Value],
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if replicas.is_empty() {
        return writeln!(w, "no replicas for {workload}");
    }
    writeln!(
        w,
        "{:>3}  {:<21}  {:<9}  {:<7}  {:<7}  BACKEND",
        "REP", "ENDPOINT", "REACHABLE", "HEALTHY", "PHASE"
    )?;
    for r in replicas {
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
        writeln!(
            w,
            "{rep:>3}  {endpoint:<21}  {reachable:<9}  {healthy:<7}  {phase:<7}  {backend}"
        )?;
    }
    Ok(())
}

/// Entry point for `boatramp compute`.
pub async fn run(args: ComputeArgs, config: &ProjectConfig) -> Result<ComputeOutput> {
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

    let out = match args.command {
        ComputeCommand::Ls => {
            let workloads: serde_json::Value = http
                .get(format!("{server}/api/{seg}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let arr = workloads.as_array().cloned().unwrap_or_default();
            ComputeOutput::Ls { workloads: arr }
        }
        ComputeCommand::Get { name } => {
            let workload: serde_json::Value = http
                .get(format!("{server}/api/{seg}/{name}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            ComputeOutput::Get { workload }
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
                    ));
                }
                _ => {
                    return Err(Error::Args(
                        "give only one of --image, --tar, or --rootfs".into(),
                    ));
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
            ComputeOutput::Set { name, spec: hash }
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
            // Build progress → tracing (diagnostic/stderr); the result is the set-workload line.
            tracing::info!("building rootfs from {image} (requires e2fsprogs `mke2fs`)…");
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
            tracing::info!("rootfs blob {rootfs} uploaded");
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
            ComputeOutput::Build { name, spec: hash }
        }
        ComputeCommand::Rm { name } => {
            http.delete(format!("{server}/api/{seg}/{name}"))
                .send()
                .await?
                .error_for_status()?;
            ComputeOutput::Rm { name }
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
            // RAW PASSTHROUGH: the child's stdout/stderr are DATA — write the decoded bytes straight
            // through, never JSON-wrapped/base64'd, and mirror the child exit code. This leaf command
            // exits directly (it does NOT route through `output::emit`), so the raw byte stream is
            // never polluted by a trailing result object in either output mode.
            let mut so = std::io::stdout();
            if let Some(s) = out["stdout_b64"].as_str() {
                so.write_all(&b64.decode(s).unwrap_or_default()).ok();
            }
            let mut se = std::io::stderr();
            if let Some(s) = out["stderr_b64"].as_str() {
                se.write_all(&b64.decode(s).unwrap_or_default()).ok();
            }
            let _ = so.flush();
            let _ = se.flush();
            let code = out["exit_code"].as_i64().unwrap_or(0);
            // Tail expression (no `;`) so the arm's type is `!`, coercing to `ComputeOutput`.
            std::process::exit(code as i32)
        }
        ComputeCommand::BindBlob {
            site,
            container,
            project,
            export,
        } => {
            let body = serde_json::json!({
                "site": site,
                "container": container,
                "project": project,
            });
            // Node-global endpoint (System·Admin); the blob-namespace project is carried in
            // the BODY, not the path.
            let resp = http
                .post(format!("{server}/api/compute/dev-bind-blob"))
                .json(&body)
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "compute bind-blob failed: {status}: {}",
                    text.trim()
                )));
            }
            let out: serde_json::Value = resp.json().await?;
            let mut env = Vec::new();
            for pair in out["env"].as_array().into_iter().flatten() {
                if let (Some(k), Some(v)) = (pair[0].as_str(), pair[1].as_str()) {
                    env.push((k.to_string(), v.to_string()));
                }
            }
            ComputeOutput::BindBlob { export, env }
        }
        ComputeCommand::BindMessaging {
            topic,
            project,
            export,
        } => {
            let body = serde_json::json!({
                "topic": topic,
                "project": project,
            });
            // Node-global endpoint (System·Admin); the bus-namespace project is carried in the
            // BODY, not the path.
            let resp = http
                .post(format!("{server}/api/compute/dev-bind-messaging"))
                .json(&body)
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "compute bind-messaging failed: {status}: {}",
                    text.trim()
                )));
            }
            let out: serde_json::Value = resp.json().await?;
            let mut env = Vec::new();
            for pair in out["env"].as_array().into_iter().flatten() {
                if let (Some(k), Some(v)) = (pair[0].as_str(), pair[1].as_str()) {
                    env.push((k.to_string(), v.to_string()));
                }
            }
            ComputeOutput::BindMessaging { export, env }
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
            ComputeOutput::VolumeLs { volumes: arr }
        }
        ComputeCommand::Volume(VolumeCommand::Rm { name, force }) => {
            let mut url = format!("{server}/api/{seg}/volumes/{name}");
            if force {
                url.push_str("?force=true");
            }
            let resp = http.delete(url).send().await?;
            match resp.status() {
                s if s.is_success() => ComputeOutput::VolumeRm { name },
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(Error::Server(format!("no such volume {name:?}")));
                }
                reqwest::StatusCode::CONFLICT => {
                    return Err(Error::Server(format!(
                        "volume {name:?} in use by a registered workload; `compute rm` it \
                         first, or pass --force"
                    )));
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
        ComputeCommand::Status { workload } => {
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
            ComputeOutput::Status { states }
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
                    ComputeOutput::SetHealth {
                        project: view["project"].as_str().unwrap_or("?").to_string(),
                        workload: view["workload"].as_str().unwrap_or("?").to_string(),
                        replica: view["replica"].as_u64().unwrap_or(0),
                        healthy: view["healthy"].as_bool().unwrap_or(false),
                    }
                }
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(Error::Server(format!(
                        "no such replica: {workload} #{replica} (in project {:?})",
                        client::resolve_project(config)
                    )));
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
            ComputeOutput::IpLs {
                assignments,
                duplicates: dups,
            }
        }
        ComputeCommand::Reconcile => {
            let resp = http
                .post(format!("{server}/api/compute/reconcile"))
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                ComputeOutput::Reconcile
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
                s if s.is_success() => ComputeOutput::Restart { workload, replica },
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(Error::Server(format!(
                        "no such replica: {workload} #{replica} (in project {:?})",
                        client::resolve_project(config)
                    )));
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
            ComputeOutput::DnsLs { entries }
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
            let name = e["name"].as_str().unwrap_or("?").to_string();
            let addrs: Vec<String> = e["addrs"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            ComputeOutput::DnsResolve { name, addrs }
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
            ComputeOutput::Netdiag { workload, replicas }
        }
        ComputeCommand::Reap {
            workload,
            replica,
            execute,
            reclaim_volumes,
            grace_secs,
        } => {
            // A targeted reap needs workload + replica (project from --project); omit both
            // to scan every project. A partial target is refused by the server.
            let mut body = serde_json::Map::new();
            body.insert("dry_run".into(), serde_json::json!(!execute));
            body.insert("reclaim_volumes".into(), serde_json::json!(reclaim_volumes));
            if let Some(g) = grace_secs {
                body.insert("grace_secs".into(), serde_json::json!(g));
            }
            if let Some(wl) = &workload {
                let Some(rep) = replica else {
                    return Err(Error::Server(
                        "a targeted reap needs --replica with the workload (or omit both to \
                         scan every project)"
                            .to_string(),
                    ));
                };
                body.insert(
                    "project".into(),
                    serde_json::json!(client::resolve_project(config)),
                );
                body.insert("workload".into(), serde_json::json!(wl));
                body.insert("replica".into(), serde_json::json!(rep));
            }
            let resp = http
                .post(format!("{server}/api/compute/maintenance/reap"))
                .json(&serde_json::Value::Object(body))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "reap failed: {status}: {}",
                    text.trim()
                )));
            }
            let report: serde_json::Value = resp.json().await?;
            ComputeOutput::Reap {
                dry_run: report["dry_run"].as_bool().unwrap_or(true),
                entries: report["entries"].as_array().cloned().unwrap_or_default(),
            }
        }
    };
    Ok(out)
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
        post_launch: Vec::new(),
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
