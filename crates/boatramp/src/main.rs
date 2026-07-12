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

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

mod access;
#[cfg(feature = "acme-dns")]
mod acme_dns;
mod alias;
mod authcmd;
mod blob;
mod build;
mod bundle;
mod client;
#[cfg(feature = "cluster")]
mod cloudflare;
mod cluster;
#[cfg(all(feature = "cluster", feature = "acme-dns"))]
mod cluster_tls;
mod completions;
mod compute;
mod config;
mod config_cmd;
mod dlq;
#[cfg(feature = "acme-dns")]
mod dns;
mod domains;
mod error;
mod gateway;
mod handler_validate;
// Joiner-side dynamic cluster join (CJ-2). The orchestration is wired into the
// cluster runtime's join-at-startup path in CJ-3; the ticket codec + root-anchored
// verification it exposes are unit-tested standalone. `allow(dead_code)` until the
// startup wiring lands.
#[cfg(feature = "cluster")]
#[allow(dead_code)]
mod join;
mod logs;
mod manage;
#[cfg(feature = "operator")]
mod operator;
mod security;
mod serve;
mod sync;
mod token;

use error::CliError;

#[derive(Debug, Parser)]
#[command(name = "boatramp", version, about, long_about = None)]
struct Cli {
    /// Path to the config file. Defaults to `project.cfg` for the project
    /// commands and `boatramp.cfg` for `serve`.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

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
    /// Build (optional) and publish a folder as a new atomic deployment.
    Sync(sync::SyncArgs),
    /// Run the configured build command only.
    Build(build::BuildArgs),
    /// Bundle JS/TS (Rolldown) + CSS (lightningcss) in-process (`bundler` feature).
    Bundle(bundle::BundleArgs),
    /// Parse and check a `project.cfg` (its `routing` section).
    Validate(build::ValidateArgs),
    /// List a site's deployment history.
    Deployments(manage::DeploymentsArgs),
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
    /// Manage control-plane API tokens.
    Token(token::TokenArgs),
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
    /// Upload a file as a content-addressed blob (e.g. a microVM kernel).
    Blob(blob::BlobArgs),
    /// Read/change the dynamic daemon config (get/set/rollback/apply, no restart).
    Config(config_cmd::ConfigArgs),
    /// Configure DNS + issue wildcard preview certs (requires `--features acme-dns`).
    #[cfg(feature = "acme-dns")]
    Dns(dns::DnsArgs),
    /// Tail a site's captured guest stdout/stderr (`--follow` to keep polling).
    Logs(logs::LogsArgs),
    /// Show a site's handler invocation stats, consumer lag, and dead letters.
    Stats(logs::StatsArgs),
    /// Purge or redrive a consumer topic's dead-letter queue.
    Dlq(dlq::DlqArgs),
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
    use boatramp_firecracker::embedded_backend::{run_jailed_worker, WorkerConfig};
    let json = json.ok_or(CliError::VmmMissingConfig)?;
    let cfg: WorkerConfig = serde_json::from_str(&json).map_err(CliError::VmmConfigParse)?;
    run_jailed_worker(cfg).map_err(CliError::VmmWorker)?;
    Ok(())
}

async fn async_main() -> Result<(), CliError> {
    // Structured logs (incl. the `boatramp::access` line) go to stderr; set
    // `BOATRAMP_LOG_FORMAT=json` for a machine-readable JSON sink.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("boatramp=info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let json = std::env::var("BOATRAMP_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }

    let cli = Cli::parse();

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
        let config = config::ServerConfig::load(&path)?;
        let Command::Serve(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        serve::run(args, &config).await?;
        return Ok(());
    }

    // `security` also reads the server daemon config (`boatramp.cfg`), like
    // `serve`, since the posture lives there — not in the project config.
    if matches!(cli.command, Command::Security(_)) {
        let path = cli.config.unwrap_or_else(|| PathBuf::from("boatramp.cfg"));
        let config = config::ServerConfig::load(&path)?;
        let Command::Security(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        security::run(args, &config)?;
        return Ok(());
    }

    // `operator` talks to the Kubernetes API (or just emits manifests) — it needs
    // neither the project nor the server config.
    #[cfg(feature = "operator")]
    if matches!(cli.command, Command::Operator(_)) {
        let Command::Operator(args) = cli.command else {
            unreachable!("guarded by matches! above")
        };
        operator::run(args).await?;
        return Ok(());
    }

    let path = cli.config.unwrap_or_else(|| PathBuf::from("project.cfg"));
    let config = config::ProjectConfig::load(&path)?;

    // Each arm propagates its module's typed error into `CliError` via `?`; the
    // `#[from]` impls on `CliError` make every command's error a single dispatch.
    match cli.command {
        Command::Serve(_) => unreachable!("handled above"),
        Command::Security(_) => unreachable!("handled above"),
        #[cfg(feature = "operator")]
        Command::Operator(_) => unreachable!("handled above"),
        Command::Completions { .. } | Command::Man => unreachable!("handled above"),
        Command::Sync(args) => sync::run(args, &config).await?,
        Command::Build(args) => build::run(args, &config).await?,
        Command::Bundle(args) => bundle::run(args, &config).await?,
        Command::Validate(args) => build::validate(args)?,
        Command::Deployments(args) => manage::list(args, &config).await?,
        Command::Rollback(args) => manage::rollback(args, &config).await?,
        Command::Status(args) => manage::status(args, &config).await?,
        Command::Domain(args) => domains::run(args, &config).await?,
        Command::Alias(args) => alias::run(args, &config).await?,
        Command::Access(args) => access::run(args, &config).await?,
        Command::Token(args) => token::run(args, &config).await?,
        Command::Cluster(args) => cluster::run(args, &config).await?,
        Command::Auth(args) => authcmd::run(args, &config).await?,
        Command::Gateway(args) => gateway::run(args, &config).await?,
        Command::Compute(args) => compute::run(args, &config).await?,
        Command::Blob(args) => blob::run(args, &config).await?,
        Command::Config(args) => config_cmd::run(args, &config).await?,
        #[cfg(feature = "acme-dns")]
        Command::Dns(args) => dns::run(args, &config).await?,
        Command::Logs(args) => logs::run(args, &config).await?,
        Command::Stats(args) => logs::stats(args, &config).await?,
        Command::Dlq(args) => dlq::run(args, &config).await?,
        Command::Prune(args) => manage::prune(args, &config).await?,
        Command::Scrub(args) => manage::scrub(args, &config).await?,
        Command::CertStatus(args) => manage::cert_status(args, &config).await?,
        #[cfg(feature = "cluster")]
        Command::Cloudflare(args) => cloudflare::run(args, &config).await?,
    }
    Ok(())
}
