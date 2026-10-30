//! boatramp — a self-hosted, streaming-first alternative to Vercel.
//!
//! A single binary with these subcommands:
//! - `serve`       — run the HTTP server + publishing API.
//! - `sync`        — (optionally build, then) publish a folder as a new
//!   immutable deployment and atomically switch the site to it.
//! - `build`       — run the configured build command only.
//! - `validate`    — parse and check a `project.cfg` (its `routing` section).
//! - `deployments` — list a site's deployment history.
//! - `rollback`    — re-activate the previous (or a specific) deployment.
//! - `status`      — show a site's current deployment.
//! - `domain`      — attach/detach hostnames to a site (virtualhost routing).
//! - `alias`       — manage named pointers (staging, previews) to deployments.
//! - `access`      — configure visitor access control (basic auth, IP, rate).
//! - `token`       — manage control-plane API tokens.
//! - `logs`        — tail a site's captured guest stdout/stderr.
//! - `stats`       — show a site's handler invocation/consumer/stream stats.
//! - `prune`       — delete orphan deployments and unreferenced blobs.
//! - `scrub`       — verify stored blobs still hash to their keys (integrity).

// Optional jemalloc global allocator, selected at build time. The default build uses
// the system allocator (glibc `malloc` on the gnu target, musl `malloc` on the musl
// target); the fully-static musl image enables `jemalloc` because musl's own malloc
// scales poorly under concurrent, allocation-heavy load (benchmarked ~14× slower).
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;

mod access;
#[cfg(feature = "acme-dns")]
mod acme_dns;
mod alias;
mod apply;
mod apply_migrate;
mod authcmd;
mod blob;
mod build;
mod bundle;
mod capabilities;
mod client;
#[cfg(feature = "cluster")]
mod cloudflare;
mod cluster;
#[cfg(all(feature = "cluster", feature = "acme-dns"))]
mod cluster_tls;
mod completions;
mod compose;
mod compression;
mod compute;
// `boatramp connect <svc>` — the overlay service tunneler's one-shot dial + stdio splice
// (overlay-service-tunneler plan R1), for `ssh ProxyCommand`/scripting.
#[cfg(feature = "overlay")]
mod connect;
mod db;
/// On-demand per-SNI TLS issuance at scale (cap-req 03): the allowlist-gated, single-flight,
/// cluster-aware issuer + the resolve-None-retry SNI resolver. Gated on `cluster` too: issuance uses
/// the replicated cert store + the leader gate, and the only wiring is the cluster acme-dns serve path
/// (single-node on-demand is a follow-up).
#[cfg(all(feature = "acme-dns", feature = "cluster"))]
mod on_demand_tls;
// `boatramp kv repair`: offline WAL-tail repair for the SlateDB control-plane store.
// Gated on `slatedb` (it operates on the SlateDB store).
#[cfg(feature = "slatedb")]
mod kv;
mod sql;
// The config model moved to `boatramp-node` (library); re-export it under the
// binary's `crate::config` so existing call sites are unchanged.
pub use boatramp_node::config;
mod config_cmd;
mod dlq;
#[cfg(feature = "acme-dns")]
mod dns;
mod domains;
mod error;
mod function;
mod gateway;
mod graphql;
mod handler_validate;
mod handlers;
mod queue;
mod workflow;
// Joiner-side dynamic cluster join (CJ-2/CJ-3): the ticket codec, root-anchored
// verification, founding decision, and `join_cluster` orchestration wired into
// the cluster runtime's join-at-startup path (`run_cluster`).
#[cfg(feature = "email")]
mod email;
#[cfg(feature = "overlay")]
mod expose;
#[cfg(feature = "overlay")]
mod forward;
#[cfg(feature = "cluster")]
mod join;
mod logs;
mod manage;
#[cfg(feature = "mcp")]
mod mcp;
mod migrate;
#[cfg(feature = "operator")]
mod operator;
mod output;
#[cfg(feature = "overlay")]
mod overlay;
mod project;
mod project_migrate;
mod project_repair;
mod project_tenant_secrets;
mod secrets;
mod security;
mod security_headers;
mod serve;
mod sync;
mod tenancy;
mod token;
// `boatramp tunnel` — the overlay service tunneler's SOCKS5 (+ optional HTTP CONNECT) daemon
// (overlay-service-tunneler plan R1): reach overlay services by name, unprivileged.
#[cfg(feature = "overlay")]
mod tunnel;
mod version;

use error::CliError;

#[derive(Debug, Parser)]
#[command(name = "boatramp", version, about, long_about = None)]
struct Cli {
    /// Path to the config file. Defaults to `project.cfg` for the project
    /// commands and `boatramp.cfg` for `serve`.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Target project for site-scoped commands (default `default`;
    /// falls back to `[publish].project`; env `BOATRAMP_PROJECT`).
    #[arg(long, global = true, env = "BOATRAMP_PROJECT")]
    project: Option<String>,

    /// How to render command results: `human` (default) or `json`. Applies to every subcommand.
    #[arg(
        long = "output-format",
        global = true,
        value_enum,
        env = "BOATRAMP_OUTPUT_FORMAT",
        default_value_t = output::OutputMode::Human
    )]
    output_format: output::OutputMode,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
// The CLI command enum is parsed once; the size difference between variants
// (the `Serve` args struct is the largest) does not matter here.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run the HTTP server and publishing API.
    Serve(serve::ServeArgs),
    /// Forward a local port to an in-cluster target over the overlay fabric —
    /// relay-blind, capability-gated, `ssh -L`-shaped (requires `--features overlay`).
    #[cfg(feature = "overlay")]
    Forward(forward::ForwardArgs),
    /// Publish a LOCAL service INTO the cluster overlay (the reverse of `forward`) — the exposer
    /// dials the relay outbound and holds it open, so a cluster-side `boatramp forward svc/<name>`
    /// reaches a NAT'd local service, relay-blind and capability-gated (requires `--features overlay`).
    #[cfg(feature = "overlay")]
    Expose(expose::ExposeArgs),
    /// Admin tooling for the overlay forward-flow: mint a dial capability and emit a one-flag
    /// forward ticket (`overlay grant`) for `boatramp forward --ticket` (requires `--features overlay`).
    #[cfg(feature = "overlay")]
    Overlay(overlay::OverlayArgs),
    /// Reach overlay services BY NAME: a SOCKS5 (+ optional HTTP CONNECT) proxy daemon over the
    /// shared tunnel core (overlay-service-tunneler plan R1; requires `--features overlay`).
    #[cfg(feature = "overlay")]
    Tunnel(tunnel::TunnelArgs),
    /// One-shot dial + stdio splice to a single overlay service — for `ssh ProxyCommand`/scripting
    /// (requires `--features overlay`).
    #[cfg(feature = "overlay")]
    Connect(connect::ConnectArgs),
    /// Build (optional) and publish a folder as a new atomic deployment.
    Sync(sync::SyncArgs),
    /// Reconcile a whole project (sites + functions + compute) to a declarative
    /// manifest (`apply.cfg`); `--dry-run` prints the plan.
    Apply(apply::ApplyArgs),
    /// Run the configured build command only.
    Build(build::BuildArgs),
    /// Bundle JS/TS (Rolldown) + CSS (lightningcss) in-process (`bundler` feature).
    Bundle(bundle::BundleArgs),
    /// Fuse an edge handler component with plugin components into one linked
    /// component (`--edge a.wasm --plugin b.wasm -o fused.wasm`).
    Compose(compose::ComposeArgs),
    /// Parse and check a `project.cfg` (its `routing` section).
    Validate(build::ValidateArgs),
    /// Print the capability surface this host implements (the `boatramp:handlers`
    /// package version + the imports a deploy may declare).
    Capabilities(capabilities::CapabilitiesArgs),
    /// Report the boatramp version — this binary's (default), or a running daemon's
    /// (`--server <url>` / `--remote`, an operator-only `system·read` query).
    Version(version::VersionArgs),
    /// List a site's deployment history.
    Deployments(manage::DeploymentsArgs),
    /// Inspect the functions a site runs (its handlers/consumers/crons as functions).
    Function(function::FunctionArgs),
    /// Define + run declarative function workflows (FA-6 orchestration).
    Workflow(workflow::WorkflowArgs),
    /// Roll back to the previous (or a specific) deployment.
    Rollback(manage::RollbackArgs),
    /// Show a site's current deployment (id, age, size).
    Status(manage::StatusArgs),
    /// Attach/detach hostnames to a site (virtualhost routing).
    Domain(domains::DomainArgs),
    /// Manage named pointers (staging, previews) to deployments.
    Alias(alias::AliasArgs),
    /// Configure visitor access control (basic auth, IP rules, rate limit).
    Access(access::AccessArgs),
    /// Manage a site's handler policy (enable/disable, import allowlist, caps).
    Handlers(handlers::HandlersArgs),
    /// Manage a project's GraphQL admin (persisted-op safelist + federation subgraphs).
    Graphql(graphql::GraphqlArgs),
    /// Configure on-the-fly response compression for a site.
    Compression(compression::CompressionArgs),
    /// Configure a site's response security headers (HTTPS redirect, HSTS, CSP, frame-options).
    SecurityHeaders(security_headers::SecurityHeadersArgs),
    /// Manage control-plane API tokens.
    Token(token::TokenArgs),
    /// Manage a project's internal, sealed secret store (`secrets set|ls|rm|rotate`).
    Secrets(secrets::SecretsArgs),
    /// Manage a project's tenancy schema — the per-table tenant-key map that scopes
    /// guest queries (`tenancy show|apply <file>|clear`), and dry-run a `token`-source
    /// claim transform locally (`tenancy test-extract`).
    Tenancy(tenancy::TenancyArgs),
    /// Manage a project's SMTP delivery profiles (`email set|ls|show|rm`).
    #[cfg(feature = "email")]
    Email(email::EmailArgs),
    /// Operate a self-hosted cluster's mesh membership (mint join tokens).
    Cluster(cluster::ClusterArgs),
    /// Inspect the operator security posture (`security explain`).
    Security(security::SecurityArgs),
    /// Generate / inspect the control-plane root key for authz.
    Auth(authcmd::AuthArgs),
    /// Publish a private service through the edge (reverse-proxy gateway).
    Gateway(gateway::GatewayArgs),
    /// Manage Firecracker microVM compute workloads.
    Compute(compute::ComputeArgs),
    /// Operator SQL to a managed database: apply a migration script or run a query.
    Sql(sql::SqlArgs),
    /// Inspect a project's declared managed databases (read-only: `db ls|get|status`).
    /// Declaring/provisioning is done via the manifest `databases:` block (`boatramp
    /// apply`) — there is deliberately no `db create`.
    Db(db::DbArgs),
    /// Maintain the control-plane SlateDB store (`kv repair` — recover a torn WAL tail after a
    /// crash/snapshot; dry-run by default, `--apply` to perform it).
    #[cfg(feature = "slatedb")]
    Kv(kv::KvArgs),
    /// Upload a file as a content-addressed blob (e.g. a microVM kernel).
    Blob(blob::BlobArgs),
    /// Read/change the dynamic daemon config (get/set/rollback/apply, no restart).
    Config(config_cmd::ConfigArgs),
    /// Migrate a pre-0.2.0 control-plane store to the project-scoped layout
    /// (`--dry-run` to preview; `--stage`/`--finalize` for a soak window).
    Migrate(migrate::MigrateArgs),
    /// Manage projects — the owning Workspace above sites/functions/compute
    /// (`project create|ls|show|rm`).
    Project(project::ProjectArgs),
    /// Configure DNS + issue wildcard preview certs (requires `--features acme-dns`).
    #[cfg(feature = "acme-dns")]
    Dns(dns::DnsArgs),
    /// Tail a site's captured guest stdout/stderr (`--follow` to keep polling).
    Logs(logs::LogsArgs),
    /// Show a site's handler invocation stats, consumer lag, and dead letters.
    Stats(logs::StatsArgs),
    /// Purge or redrive a consumer topic's dead-letter queue.
    Dlq(dlq::DlqArgs),
    /// Inspect a consumer topic's live work-queue (peek without consuming).
    Queue(queue::QueueArgs),
    /// Delete orphan deployments and unreferenced blobs (--dry-run to only report).
    Prune(manage::PruneArgs),
    /// Verify every stored blob still hashes to its key (integrity scrub).
    Scrub(manage::ScrubArgs),
    /// Show cluster-managed certificate status (domain + expiry).
    CertStatus(manage::CertStatusArgs),
    /// Print a shell-completion script (`boatramp completions bash`).
    Completions {
        /// Target shell: `bash`, `zsh`, `fish`, `powershell`, or `elvish`.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Render the man page to stdout (`boatramp man > boatramp.1`).
    Man,
    /// Generate (and optionally apply) a Cloudflare deployment — boatramp's
    /// cluster mode on CF Containers + an edge Worker.
    #[cfg(feature = "cluster")]
    Cloudflare(cloudflare::CloudflareArgs),
    /// Kubernetes operator: run the controller or emit CRDs/install manifests
    /// (`operator run` / `operator crds` / `operator manifests`).
    #[cfg(feature = "operator")]
    Operator(operator::OperatorArgs),
    /// Model Context Protocol server: drive one or more instances from an agent
    /// (`mcp` / `mcp serve` over stdio; `mcp setup add/list/remove`).
    #[cfg(feature = "mcp")]
    Mcp(mcp::McpArgs),
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // Render the error and its `source()` chain (the per-command enums
            // are `#[error(transparent)]`, so this surfaces the underlying cause).
            eprintln!("error: {err}");
            let mut source = std::error::Error::source(&err);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    // A re-exec'd `boatramp __sandbox` is the native container backend's self-jail
    // worker. Handle it *before* building the Tokio runtime: the worker `fork`s,
    // which is unsafe once a multi-threaded runtime is up (sibling threads vanish
    // in the child while possibly holding locks). At this point we're still
    // single-threaded.
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("__sandbox") {
        return run_sandbox();
    }
    // A re-exec'd `boatramp __vmm-run <json>` is the embedded VMM backend's jailed
    // per-VM worker: it builds + runs one microVM in this (separate-address-space)
    // process, then drops caps + installs seccomp. No Tokio runtime needed. The
    // embedded VMM is x86_64-KVM-only, so this worker exists only there (boatramp
    // still builds + runs on linux/aarch64 — e.g. Graviton/Ampere k8s nodes —
    // without the embedded compute backend).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::env::args().nth(1).as_deref()
        == Some(boatramp_firecracker::embedded_backend::VMM_RUN_SUBCOMMAND)
    {
        return run_vmm_worker(std::env::args().nth(2));
    }
    // A re-exec'd `boatramp __vz-run <json>` is the macOS-native VMM backend's
    // per-VM worker: it builds + runs one Linux microVM via Virtualization.framework
    // in this process, owning the VZVirtualMachine on a dedicated DispatchQueue. No
    // Tokio runtime needed. macOS-only (the backend is registered only there).
    #[cfg(target_os = "macos")]
    if std::env::args().nth(1).as_deref() == Some(boatramp_vz::VZ_RUN_SUBCOMMAND) {
        return run_vz_worker(std::env::args().nth(2));
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?
        .block_on(async_main())
}

/// The container self-jail worker (`boatramp __sandbox`): read a [`SandboxPlan`]
/// as JSON on stdin, apply it (namespaces/mounts/`pivot_root`/cgroups/seccomp/
/// drop-privileges), and `execve` the entrypoint. Never returns on success in
/// the forked child; the parent exits with the child's status.
#[cfg(target_os = "linux")]
fn run_sandbox() -> Result<(), CliError> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::new(stdin.lock());

    // Line 1: the SandboxPlan as JSON.
    let mut plan_line = String::new();
    reader
        .read_line(&mut plan_line)
        .map_err(CliError::SandboxPlanRead)?;
    let plan: boatramp_container::SandboxPlan =
        serde_json::from_str(plan_line.trim()).map_err(CliError::SandboxPlanParse)?;

    // Set up the cgroup + namespaces (we're now in our own netns).
    boatramp_container::worker::prepare(&plan).map_err(CliError::SandboxPrepare)?;

    // Network handshake: tell the launcher we've unshared (so it can move the
    // veth peer into our netns + configure eth0), then block for its "go".
    {
        let mut out = std::io::stdout().lock();
        out.write_all(b"ready\n")
            .and_then(|()| out.flush())
            .map_err(CliError::SandboxReady)?;
    }
    let mut go = String::new();
    reader.read_line(&mut go).map_err(CliError::SandboxGo)?;
    if go.trim() != "go" {
        return Err(CliError::SandboxHandshake { got: go });
    }

    // Fork the container init, jail it, and exec the entrypoint.
    let code = boatramp_container::worker::jail_and_run(&plan).map_err(CliError::SandboxWorker)?;
    std::process::exit(code);
}

/// The embedded VMM backend's jailed per-VM worker (`boatramp __vmm-run <json>`):
/// build + run one microVM in this process (separate address space), then drop
/// caps + install seccomp. Runs until the guest exits or the process is killed
/// (the backend's `stop` SIGKILLs it). `json` is the [`WorkerConfig`]. x86_64-only
/// (the embedded VMM is KVM-x86-specific).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_vmm_worker(json: Option<String>) -> Result<(), CliError> {
    use boatramp_firecracker::embedded_backend::{WorkerConfig, run_jailed_worker};
    let json = json.ok_or(CliError::VmmMissingConfig)?;
    let cfg: WorkerConfig = serde_json::from_str(&json).map_err(CliError::VmmConfigParse)?;
    run_jailed_worker(cfg).map_err(CliError::VmmWorker)?;
    Ok(())
}

/// The macOS-native VMM backend's per-VM worker (`boatramp __vz-run <json>`):
/// build + run one Linux microVM via Virtualization.framework in this process
/// (owning the `VZVirtualMachine` on a dedicated `DispatchQueue`). Runs until the
/// guest stops or the parent closes stdin (the control channel). `json` is the
/// [`boatramp_vz::WorkerConfig`]. macOS-only (Virtualization.framework).
#[cfg(target_os = "macos")]
fn run_vz_worker(json: Option<String>) -> Result<(), CliError> {
    let json = json.ok_or(CliError::VzMissingConfig)?;
    let cfg: boatramp_vz::WorkerConfig =
        serde_json::from_str(&json).map_err(CliError::VzConfigParse)?;
    boatramp_vz::vm::run_worker(cfg).map_err(CliError::VzWorker)?;
    Ok(())
}

/// Build the serve flag layer (the config pipeline's top layer): a `{BOATRAMP_<NAME>:
/// raw-value}` map of the serve args the operator set ON THE COMMAND LINE. The env name comes
/// from each arg's own clap definition (`Arg::get_env`), and only `ValueSource::CommandLine`
/// args are included — env-sourced values (the pipeline's env overlay handles those) and
/// defaults are excluded, so a defaulted `--blobs fs` never enters the layer. Keys the config
/// overlay doesn't recognise (runtime/selector flags like `--tls`, `--kv`, the cluster-action
/// flags) are mapped here but ignored by the overlay, so they never reach the config.
fn serve_cli_flags(matches: &clap::ArgMatches) -> std::collections::BTreeMap<String, String> {
    use clap::parser::ValueSource;
    let mut out = std::collections::BTreeMap::new();
    let Some(sub) = matches.subcommand_matches("serve") else {
        return out;
    };
    let cmd = Cli::command();
    let Some(serve_def) = cmd.find_subcommand("serve") else {
        return out;
    };
    for arg in serve_def.get_arguments() {
        let Some(env) = arg.get_env() else {
            continue; // only env-named args map to a config field
        };
        let id = arg.get_id().as_str();
        if sub.value_source(id) != Some(ValueSource::CommandLine) {
            continue; // env / default sourced → not an explicit CLI flag
        }
        // A value arg yields its raw token; a set boolean flag (ArgAction::SetTrue) has no
        // raw value, so record "true" — the overlay/extract coerces it.
        let value = sub
            .get_raw(id)
            .and_then(|mut vs| vs.next())
            .and_then(|o| o.to_str().map(str::to_string))
            .unwrap_or_else(|| "true".to_string());
        out.insert(env.to_string_lossy().into_owned(), value);
    }
    out
}

async fn async_main() -> Result<(), CliError> {
    // Structured logs (incl. the `boatramp::access` line) go to STDERR — explicitly, because
    // `tracing_subscriber::fmt()` otherwise defaults to stdout, which would co-mingle diagnostics with
    // (and corrupt the JSON of) a command's result on stdout. Set `BOATRAMP_LOG_FORMAT=json` for a
    // machine-readable JSON sink.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("boatramp=info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    let json = std::env::var("BOATRAMP_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }

    // Parse via ArgMatches (not `Cli::parse()`) so the serve flag layer can read each arg's
    // `ValueSource` (CommandLine vs env vs default). `from_arg_matches` on clap's OWN matches
    // is infallible — it is exactly what `Cli::parse()` does internally.
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches)
        .expect("clap re-derive from its own validated matches is infallible");

    // `completions` / `man` are pure generators over the command tree — no config,
    // no network. Handle them before any config load.
    match cli.command {
        Command::Completions { shell } => {
            completions::completions(shell);
            return Ok(());
        }
        Command::Man => {
            completions::man().map_err(CliError::Man)?;
            return Ok(());
        }
        _ => {}
    }

    // `serve` reads the server daemon config (`boatramp.cfg`); every other
    // command reads the project config (`project.cfg`). The two have distinct
    // shapes, so the right one is loaded per command rather than globally.
    if matches!(cli.command, Command::Serve(_)) {
        let path = cli.config.unwrap_or_else(|| PathBuf::from("boatramp.cfg"));
        let Command::Serve(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        // The config is resolved by the ONE pipeline (defaults → file → env → explicit CLI
        // flags). The flag layer is built from the serve subcommand's
        // `ValueSource::CommandLine` args (so a defaulted `--blobs fs` is absent and can't
        // clobber file/env — subsuming the old `--blobs` `var_os` probe). `--format` selects
        // the file decoder (RON/JSON).
        let config =
            config::ServerConfig::load_with_flags(&path, args.format, &serve_cli_flags(&matches))?;
        serve::run(args, &config, &path).await?;
        return Ok(());
    }

    // `forward` is a long-running overlay client-edge (like `serve`). Explicit-flag / `--ticket`
    // forwards consult no config; the self-serve `forward svc/<name>` path reads the project config
    // (server URL + token) to resolve via the control plane — so load it best-effort (a missing
    // `project.cfg` is fine for the explicit paths).
    #[cfg(feature = "overlay")]
    if matches!(cli.command, Command::Forward(_)) {
        let path = cli
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from("project.cfg"));
        let Command::Forward(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        let config = config::ProjectConfig::load(&path, None).unwrap_or_default();
        forward::run(args, &config).await?;
        return Ok(());
    }

    // `expose` is a long-running overlay reverse-ingress (like `forward`). The explicit-flag /
    // `--ticket` paths carry everything; the self-serve `expose <local> as svc/<name>` path reads the
    // project config (server URL + token) to resolve + mint over the control plane — so load it
    // best-effort (a missing `project.cfg` is fine for the explicit paths).
    #[cfg(feature = "overlay")]
    if matches!(cli.command, Command::Expose(_)) {
        let path = cli
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from("project.cfg"));
        let Command::Expose(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        let config = config::ProjectConfig::load(&path, None).unwrap_or_default();
        expose::run(args, &config).await?;
        return Ok(());
    }

    // `tunnel` is a long-running SOCKS5 (+ optional HTTP CONNECT) daemon over the overlay service
    // tunneler's shared core (like `forward`/`expose`) — self-serve only, so it always reads the
    // project config (server URL + token) to resolve + mint over the control plane.
    #[cfg(feature = "overlay")]
    if matches!(cli.command, Command::Tunnel(_)) {
        let path = cli
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from("project.cfg"));
        let Command::Tunnel(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        let config = config::ProjectConfig::load(&path, None).unwrap_or_default();
        tunnel::run(args, &config).await?;
        return Ok(());
    }

    // `connect` is the one-shot stdio-splice analog of `tunnel` — same self-serve control-plane
    // wiring, a single dial instead of a daemon.
    #[cfg(feature = "overlay")]
    if matches!(cli.command, Command::Connect(_)) {
        let path = cli
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from("project.cfg"));
        let Command::Connect(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        let config = config::ProjectConfig::load(&path, None).unwrap_or_default();
        connect::run(args, &config).await?;
        return Ok(());
    }

    // `security` also reads the server daemon config (`boatramp.cfg`), like
    // `serve`, since the posture lives there — not in the project config.
    if matches!(cli.command, Command::Security(_)) {
        let path = cli.config.unwrap_or_else(|| PathBuf::from("boatramp.cfg"));
        // No `--format` on `security`; auto-detect by extension (`.json` ⇒ JSON).
        let config = config::ServerConfig::load(&path, None)?;
        let Command::Security(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        output::emit(cli.output_format, &security::run(args, &config)?)?;
        return Ok(());
    }

    // `migrate` operates on the same control-plane store `serve` opens, so it reads
    // the server daemon config (`boatramp.cfg`) — not the project config.
    if matches!(cli.command, Command::Migrate(_)) {
        let path = cli.config.unwrap_or_else(|| PathBuf::from("boatramp.cfg"));
        // No `--format` on `migrate`; auto-detect by extension (`.json` ⇒ JSON).
        let config = config::ServerConfig::load(&path, None)?;
        let Command::Migrate(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        output::emit(cli.output_format, &migrate::run(args, &config).await?)?;
        return Ok(());
    }

    // `operator` talks to the Kubernetes API (or just emits manifests) — it needs
    // neither the project nor the server config.
    #[cfg(feature = "operator")]
    if matches!(cli.command, Command::Operator(_)) {
        let Command::Operator(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        output::emit(cli.output_format, &operator::run(args).await?)?;
        return Ok(());
    }

    // `mcp` speaks the Model Context Protocol (stdio) or edits its own instance
    // registry (`~/.config/boatramp/mcp.toml`) — it needs neither project nor
    // server config, so handle it before loading `project.cfg`.
    #[cfg(feature = "mcp")]
    if matches!(cli.command, Command::Mcp(_)) {
        let Command::Mcp(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        mcp::run(args).await?;
        return Ok(());
    }

    // `kv repair` operates directly on the on-disk / R2 SlateDB store via `--data-dir` /
    // `--kv-s3` flags — it needs NEITHER the project nor the server config, so handle it before
    // loading `project.cfg` (a store whose repair is needed may predate any valid config).
    #[cfg(feature = "slatedb")]
    if matches!(cli.command, Command::Kv(_)) {
        let Command::Kv(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        output::emit(cli.output_format, &kv::run(args).await?)?;
        return Ok(());
    }

    let path = cli.config.unwrap_or_else(|| PathBuf::from("project.cfg"));
    // The project config (`project.cfg`) auto-detects RON vs JSON by extension;
    // there is no top-level `--format` (it is scoped to `apply` / `serve`).
    let mut config = config::ProjectConfig::load(&path, None)?;
    // The global `--project` / `BOATRAMP_PROJECT` flag wins over `[publish].project`
    // in the config file; unset leaves the config value (or the `default` project).
    if let Some(project) = cli.project.clone() {
        config.publish.project = Some(project);
    }

    // Each arm propagates its module's typed error into `CliError` via `?`; the
    // `#[from]` impls on `CliError` make every command's error a single dispatch.
    // A converted command returns a typed result that `output::emit` renders once here (human
    // text or JSON, per `--output-format`); arms not yet migrated still print internally.
    let mode = cli.output_format;
    match cli.command {
        Command::Serve(_) => unreachable!("handled above"),
        #[cfg(feature = "overlay")]
        Command::Forward(_) => unreachable!("handled above"),
        #[cfg(feature = "overlay")]
        Command::Expose(_) => unreachable!("handled above"),
        #[cfg(feature = "overlay")]
        Command::Tunnel(_) => unreachable!("handled above"),
        #[cfg(feature = "overlay")]
        Command::Connect(_) => unreachable!("handled above"),
        Command::Security(_) => unreachable!("handled above"),
        Command::Migrate(_) => unreachable!("handled above"),
        #[cfg(feature = "operator")]
        Command::Operator(_) => unreachable!("handled above"),
        #[cfg(feature = "mcp")]
        Command::Mcp(_) => unreachable!("handled above"),
        #[cfg(feature = "slatedb")]
        Command::Kv(_) => unreachable!("handled above"),
        Command::Completions { .. } | Command::Man => unreachable!("handled above"),
        Command::Sync(args) => output::emit(mode, &sync::run(args, &config).await?)?,
        Command::Apply(args) => output::emit(mode, &apply::run(args, &config).await?)?,
        Command::Build(args) => output::emit(mode, &build::run(args, &config).await?)?,
        Command::Bundle(args) => output::emit(mode, &bundle::run(args, &config).await?)?,
        Command::Compose(args) => output::emit(mode, &compose::run(args)?)?,
        Command::Validate(args) => output::emit(mode, &build::validate(args)?)?,
        Command::Capabilities(args) => output::emit(mode, &capabilities::run(args, mode))?,
        Command::Version(args) => output::emit(mode, &version::run(args, &config).await?)?,
        Command::Deployments(args) => output::emit(mode, &manage::list(args, &config).await?)?,
        Command::Function(args) => output::emit(mode, &function::run(args, &config).await?)?,
        Command::Workflow(args) => output::emit(mode, &workflow::run(args, &config).await?)?,
        Command::Rollback(args) => output::emit(mode, &manage::rollback(args, &config).await?)?,
        Command::Status(args) => output::emit(mode, &manage::status(args, &config).await?)?,
        Command::Domain(args) => output::emit(mode, &domains::run(args, &config).await?)?,
        Command::Alias(args) => output::emit(mode, &alias::run(args, &config).await?)?,
        Command::Project(args) => output::emit(mode, &project::run(args, &config, mode).await?)?,
        Command::Access(args) => output::emit(mode, &access::run(args, &config).await?)?,
        Command::Handlers(args) => output::emit(mode, &handlers::run(args, &config).await?)?,
        Command::Compression(args) => output::emit(mode, &compression::run(args, &config).await?)?,
        Command::SecurityHeaders(args) => {
            output::emit(mode, &security_headers::run(args, &config).await?)?;
        }
        Command::Graphql(args) => output::emit(mode, &graphql::run(args, &config).await?)?,
        Command::Token(args) => output::emit(mode, &token::run(args, &config).await?)?,
        #[cfg(feature = "overlay")]
        Command::Overlay(args) => output::emit(mode, &overlay::run(args, &config).await?)?,
        Command::Secrets(args) => output::emit(mode, &secrets::run(args, &config).await?)?,
        Command::Tenancy(args) => output::emit(mode, &tenancy::run(args, &config).await?)?,
        #[cfg(feature = "email")]
        Command::Email(args) => output::emit(mode, &email::run(args, &config).await?)?,
        Command::Cluster(args) => output::emit(mode, &cluster::run(args, &config).await?)?,
        Command::Auth(args) => output::emit(mode, &authcmd::run(args, &config).await?)?,
        Command::Gateway(args) => output::emit(mode, &gateway::run(args, &config).await?)?,
        Command::Compute(args) => output::emit(mode, &compute::run(args, &config).await?)?,
        Command::Sql(args) => output::emit(mode, &sql::run(args, &config).await?)?,
        Command::Db(args) => output::emit(mode, &db::run(args, &config).await?)?,
        Command::Blob(args) => output::emit(mode, &blob::run(args, &config).await?)?,
        Command::Config(args) => output::emit(mode, &config_cmd::run(args, &config).await?)?,
        #[cfg(feature = "acme-dns")]
        Command::Dns(args) => output::emit(mode, &dns::run(args, &config).await?)?,
        Command::Logs(args) => output::emit(mode, &logs::run(args, &config).await?)?,
        Command::Stats(args) => output::emit(mode, &logs::stats(args, &config).await?)?,
        Command::Dlq(args) => output::emit(mode, &dlq::run(args, &config).await?)?,
        Command::Queue(args) => output::emit(mode, &queue::run(args, &config).await?)?,
        Command::Prune(args) => output::emit(mode, &manage::prune(args, &config).await?)?,
        Command::Scrub(args) => output::emit(mode, &manage::scrub(args, &config).await?)?,
        Command::CertStatus(args) => {
            output::emit(mode, &manage::cert_status(args, &config).await?)?;
        }
        #[cfg(feature = "cluster")]
        Command::Cloudflare(args) => output::emit(mode, &cloudflare::run(args, &config).await?)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    /// The whole CLI tree is structurally valid — in particular the new `version` SUBCOMMAND
    /// coexists with clap's built-in `--version` FLAG (`#[command(version)]`): both are valid, and
    /// `boatramp version` runs the subcommand while `boatramp --version` prints the flag. `debug_assert`
    /// is clap's own tree validator (it panics on a conflict/ambiguity), so this fails loudly if the
    /// subcommand ever collides with the flag or an arg is misdeclared.
    #[test]
    fn cli_tree_is_valid() {
        Cli::command().debug_assert();
    }
}
