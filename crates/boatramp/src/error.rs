//! The CLI's top-level error type.
//!
//! `boatramp` decomposes its errors per command module (`serve::Error`,
//! `sync::Error`, …, each a focused `thiserror` enum). [`CliError`] is the thin
//! aggregator that `#[from]`s each so the dispatch in `main` can propagate any of
//! them with `?`. It carries no logic of its own: every command variant is
//! `#[error(transparent)]` and delegates Display + `source()` to the module error
//! it wraps. The exceptions are the handful of variants for the re-exec'd worker
//! entrypoints (`__sandbox`, `__vmm-run`), whose failures originate in `main`
//! itself rather than in a command module.

/// Any failure surfaced by the `boatramp` CLI. `main` renders it (Display plus
/// the `source()` chain) to stderr and exits non-zero.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Loading or parsing the project (`project.cfg`) or server (`boatramp.cfg`)
    /// config file.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The `serve` command.
    #[error(transparent)]
    Serve(#[from] crate::serve::Error),
    /// The `sync` command.
    #[error(transparent)]
    Sync(#[from] crate::sync::Error),
    /// The `build` / `validate` commands.
    #[error(transparent)]
    Build(#[from] crate::build::Error),
    /// The `bundle` command.
    #[error(transparent)]
    Bundle(#[from] crate::bundle::Error),
    /// The deployment-management commands (`deployments`, `rollback`, `status`,
    /// `prune`, `scrub`, `cert-status`).
    #[error(transparent)]
    Manage(#[from] crate::manage::Error),
    /// The `domain` command.
    #[error(transparent)]
    Domains(#[from] crate::domains::Error),
    /// The `alias` command.
    #[error(transparent)]
    Alias(#[from] crate::alias::Error),
    /// The `access` command.
    #[error(transparent)]
    Access(#[from] crate::access::Error),
    /// The `token` command.
    #[error(transparent)]
    Token(#[from] crate::token::Error),
    /// The `cluster` command.
    #[error(transparent)]
    Cluster(#[from] crate::cluster::Error),
    /// The `security` command.
    #[error(transparent)]
    Security(#[from] crate::security::Error),
    /// The `auth` command.
    #[error(transparent)]
    Auth(#[from] crate::authcmd::Error),
    /// The `gateway` command.
    #[error(transparent)]
    Gateway(#[from] crate::gateway::Error),
    /// The `compute` command.
    #[error(transparent)]
    Compute(#[from] crate::compute::Error),
    /// The `logs` / `stats` commands.
    #[error(transparent)]
    Logs(#[from] crate::logs::Error),
    /// The `dlq` command.
    #[error(transparent)]
    Dlq(#[from] crate::dlq::Error),
    /// The `dns` command (requires `--features acme-dns`).
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    Dns(#[from] crate::dns::Error),
    /// The `cloudflare` command (requires `--features cluster`).
    #[cfg(feature = "cluster")]
    #[error(transparent)]
    Cloudflare(#[from] crate::cloudflare::Error),

    /// Building the multi-threaded async (Tokio) runtime.
    #[error("building async runtime: {0}")]
    Runtime(#[source] std::io::Error),

    /// The `man` command: writing the rendered man page to stdout failed.
    #[error("rendering man page: {0}")]
    Man(#[source] std::io::Error),

    // ---- re-exec'd worker entrypoints (Linux only) ----
    // These run before/instead of the Tokio runtime and originate in `main`, so
    // they carry their own typed variants rather than wrapping a command module.
    /// `__sandbox`: reading the `SandboxPlan` JSON line from stdin.
    #[cfg(target_os = "linux")]
    #[error("reading sandbox plan: {0}")]
    SandboxPlanRead(#[source] std::io::Error),
    /// `__sandbox`: the stdin line did not parse as a `SandboxPlan`.
    #[cfg(target_os = "linux")]
    #[error("invalid sandbox plan: {0}")]
    SandboxPlanParse(#[source] serde_json::Error),
    /// `__sandbox`: setting up the cgroup + namespaces failed.
    #[cfg(target_os = "linux")]
    #[error("sandbox prepare: {0}")]
    SandboxPrepare(#[source] boatramp_container::worker::WorkerError),
    /// `__sandbox`: writing the `ready` handshake line to stdout failed.
    #[cfg(target_os = "linux")]
    #[error("sandbox ready signal: {0}")]
    SandboxReady(#[source] std::io::Error),
    /// `__sandbox`: reading the launcher's `go` handshake line failed.
    #[cfg(target_os = "linux")]
    #[error("sandbox go signal: {0}")]
    SandboxGo(#[source] std::io::Error),
    /// `__sandbox`: the launcher sent something other than `go`.
    #[cfg(target_os = "linux")]
    #[error("sandbox handshake aborted (expected 'go', got {got:?})")]
    SandboxHandshake { got: String },
    /// `__sandbox`: forking/jailing the container init and exec'ing failed.
    #[cfg(target_os = "linux")]
    #[error("sandbox worker: {0}")]
    SandboxWorker(#[source] boatramp_container::worker::WorkerError),
    /// `__vmm-run`: the config JSON argument was missing.
    #[cfg(target_os = "linux")]
    #[error("__vmm-run: missing config argument")]
    VmmMissingConfig,
    /// `__vmm-run`: the config argument did not parse as a `WorkerConfig`.
    #[cfg(target_os = "linux")]
    #[error("__vmm-run: invalid config: {0}")]
    VmmConfigParse(#[source] serde_json::Error),
    /// `__vmm-run`: building/booting/jailing the microVM failed. The embedded VMM
    /// worker reports failures as a `String` at this process boundary; carried
    /// verbatim (this is not a stringly-typed catch-all — it is the one foreign
    /// API whose error type is `String`).
    #[cfg(target_os = "linux")]
    #[error("vmm worker: {0}")]
    VmmWorker(String),
}

// `CliError`'s largest variant is `Serve(serve::Error)`, kept small by boxing
// serve::Error's openraft-backed bootstrap variant (see `serve::Error::Bootstrap`).
// Guard it so a future variant can't silently reintroduce `result_large_err` — and
// the blanket `#[allow]`s it would need — on the cold CLI dispatch path in `main`.
#[cfg(feature = "cluster")]
const _: () = assert!(std::mem::size_of::<CliError>() <= 128);
