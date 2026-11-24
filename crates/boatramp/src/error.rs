//! The CLI's top-level error type.
//!
//! `boatramp` decomposes its errors per command module (`serve::Error`,
//! `sync::Error`, …, each a focused `thiserror` enum). [`CliError`] is the thin
//! aggregator that `#[from]`s each so the dispatch in `main` can propagate any of
//! them with `?`. It carries no logic of its own: every command variant is
//! `#[error(transparent)]` and delegates Display + `source()` to the module error
//! it wraps — including the `__sandbox` worker, whose handshake now lives in
//! `boatramp_container` (`RunSandboxError`) so an embedder of the container backend
//! can reuse it. The exceptions are the variants for the re-exec'd VMM worker
//! entrypoints (`__vmm-run`, `__vz-run`), whose `String`-typed failures originate
//! at that process boundary rather than in a command module.

/// Any failure surfaced by the `boatramp` CLI. `main` renders it (Display plus
/// the `source()` chain) to stderr and exits non-zero.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Rendering a command's result to stdout (`crate::output::emit`) — e.g. a broken pipe.
    #[error("writing output: {0}")]
    Output(#[from] std::io::Error),
    /// Loading or parsing the project (`project.cfg`) or server (`boatramp.cfg`)
    /// config file.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The `serve` command.
    #[error(transparent)]
    Serve(#[from] crate::serve::Error),
    /// The `forward` command (overlay client-edge).
    #[cfg(feature = "overlay")]
    #[error(transparent)]
    Forward(#[from] crate::forward::ForwardError),
    /// The `expose` command (overlay reverse-ingress).
    #[cfg(feature = "overlay")]
    #[error(transparent)]
    Expose(#[from] crate::expose::ExposeError),
    /// The `overlay` command group (admin-side grant/ticket).
    #[cfg(feature = "overlay")]
    #[error(transparent)]
    Overlay(#[from] crate::overlay::Error),
    /// The `tunnel` AND `connect` commands (overlay service tunneler) — both share the one
    /// `TunnelCmdError` vocabulary (same control-plane wiring, a different front-end), so `?` from
    /// either command dispatch converts through this single variant.
    #[cfg(feature = "overlay")]
    #[error(transparent)]
    Tunnel(#[from] crate::tunnel::TunnelCmdError),
    /// The `sync` command.
    #[error(transparent)]
    Sync(#[from] crate::sync::Error),
    /// The `apply` command.
    #[error(transparent)]
    Apply(#[from] crate::apply::Error),
    /// The `build` / `validate` commands.
    #[error(transparent)]
    Build(#[from] crate::build::Error),
    /// The `bundle` command.
    #[error(transparent)]
    Bundle(#[from] crate::bundle::Error),
    /// The `compose` command.
    #[error(transparent)]
    Compose(#[from] crate::compose::Error),
    /// The deployment-management commands (`deployments`, `rollback`, `status`,
    /// `prune`, `scrub`, `cert-status`).
    #[error(transparent)]
    Manage(#[from] crate::manage::Error),
    /// The `function` command.
    #[error(transparent)]
    Function(#[from] crate::function::FunctionError),
    /// The `workflow` command.
    #[error(transparent)]
    Workflow(#[from] crate::workflow::WorkflowError),
    /// The `domain` command.
    #[error(transparent)]
    Domains(#[from] crate::domains::Error),
    /// The `alias` command.
    #[error(transparent)]
    Alias(#[from] crate::alias::Error),
    /// The `access` command.
    #[error(transparent)]
    Access(#[from] crate::access::Error),
    /// The `handlers` command.
    #[error(transparent)]
    Handlers(#[from] crate::handlers::Error),
    /// The `compression` command.
    #[error(transparent)]
    Compression(#[from] crate::compression::Error),
    /// The `security-headers` command.
    #[error(transparent)]
    SecurityHeaders(#[from] crate::security_headers::Error),
    /// The `graphql` command.
    #[error(transparent)]
    Graphql(#[from] crate::graphql::Error),
    /// The `token` command.
    #[error(transparent)]
    Token(#[from] crate::token::Error),
    /// The `secrets` command.
    #[error(transparent)]
    Secrets(#[from] crate::secrets::Error),
    /// The `tenancy` command.
    #[error(transparent)]
    Tenancy(#[from] crate::tenancy::Error),
    /// The `email` command.
    #[cfg(feature = "email")]
    #[error(transparent)]
    Email(#[from] crate::email::Error),
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
    /// The `sql` command.
    #[error(transparent)]
    Sql(#[from] crate::sql::Error),
    /// The `db` command (read-only declared-database inspection).
    #[error(transparent)]
    Db(#[from] crate::db::Error),
    /// The `kv` command (control-plane SlateDB store maintenance — `kv repair`).
    #[cfg(feature = "slatedb")]
    #[error(transparent)]
    Kv(#[from] crate::kv::Error),
    /// The `blob` command.
    #[error(transparent)]
    Blob(#[from] crate::blob::Error),
    /// The `version` command (remote `--server` query).
    #[error(transparent)]
    Version(#[from] crate::version::Error),
    /// The `config` command.
    #[error(transparent)]
    ConfigCmd(#[from] crate::config_cmd::Error),
    /// The `migrate` command.
    #[error(transparent)]
    Migrate(#[from] crate::migrate::Error),
    /// The `project` command.
    #[error(transparent)]
    Project(#[from] crate::project::Error),
    /// The `logs` / `stats` commands.
    #[error(transparent)]
    Logs(#[from] crate::logs::Error),
    /// The `dlq` command.
    #[error(transparent)]
    Dlq(#[from] crate::dlq::Error),
    /// The `queue` command.
    #[error(transparent)]
    Queue(#[from] crate::queue::Error),
    /// The `dns` command (requires `--features acme-dns`).
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    Dns(#[from] crate::dns::Error),
    /// The `cloudflare` command (requires `--features cluster`).
    #[cfg(feature = "cluster")]
    #[error(transparent)]
    Cloudflare(#[from] crate::cloudflare::Error),
    /// The `operator` command (requires `--features operator`).
    #[cfg(feature = "operator")]
    #[error(transparent)]
    Operator(#[from] crate::operator::Error),
    /// The `mcp` command (requires `--features mcp`).
    #[cfg(feature = "mcp")]
    #[error(transparent)]
    Mcp(#[from] crate::mcp::Error),

    /// Building the multi-threaded async (Tokio) runtime.
    #[error("building async runtime: {0}")]
    Runtime(#[source] std::io::Error),

    /// The `man` command: writing the rendered man page to stdout failed.
    #[error("rendering man page: {0}")]
    Man(#[source] std::io::Error),

    // ---- re-exec'd worker entrypoints (Linux only) ----
    // These run before/instead of the Tokio runtime, dispatched straight from
    // `main`. `__sandbox` now delegates to `boatramp_container`'s `RunSandboxError`
    // (so an embedder of the container backend reuses the same handshake); the VMM
    // workers still carry their own typed variants for the `String` boundary.
    /// `__sandbox`: the container self-jail worker's re-exec handshake (reading /
    /// parsing the plan, the `ready`/`go` exchange, or applying the plan) failed.
    /// The whole sequence lives in `boatramp_container` so an embedder of the
    /// container backend can reuse it; its typed error carries Display + `source()`
    /// here transparently, so the rendered message is unchanged from when the
    /// handshake lived in `main`.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Sandbox(#[from] boatramp_container::worker::RunSandboxError),
    /// `__vmm-run`: reading the `WorkerConfig` line from stdin failed, or it did not
    /// parse as a `WorkerConfig` (U18 — the config is delivered over stdin, off argv).
    /// The worker reports this as a `String` at the process boundary (read + parse are
    /// one step), carried verbatim.
    #[cfg(target_os = "linux")]
    #[error("__vmm-run: invalid config: {0}")]
    VmmConfigParse(String),
    /// `__vmm-run`: building/booting/jailing the microVM failed. The embedded VMM
    /// worker reports failures as a `String` at this process boundary; carried
    /// verbatim (this is not a stringly-typed catch-all — it is the one foreign
    /// API whose error type is `String`).
    #[cfg(target_os = "linux")]
    #[error("vmm worker: {0}")]
    VmmWorker(String),
    /// `__vz-run`: the config JSON argument was missing.
    #[cfg(target_os = "macos")]
    #[error("__vz-run: missing config argument")]
    VzMissingConfig,
    /// `__vz-run`: the config argument did not parse as a `WorkerConfig`.
    #[cfg(target_os = "macos")]
    #[error("__vz-run: invalid config: {0}")]
    VzConfigParse(#[source] serde_json::Error),
    /// `__vz-run`: building/booting the macOS microVM failed. The
    /// Virtualization.framework worker reports failures as a `String` at this
    /// process boundary; carried verbatim (the one foreign API whose error type is
    /// `String`, like the KVM `VmmWorker`).
    #[cfg(target_os = "macos")]
    #[error("vz worker: {0}")]
    VzWorker(String),
}

// `CliError`'s largest variant is `Serve(serve::Error)`, kept small because its openraft-backed
// bootstrap error is boxed (now inside `boatramp_node::Error::Bootstrap`, reached via
// `serve::Error::Assembly`). Guard it so a future variant can't silently reintroduce
// `result_large_err` — and the blanket `#[allow]`s it would need — on the cold CLI dispatch path
// in `main`.
#[cfg(feature = "cluster")]
const _: () = assert!(std::mem::size_of::<CliError>() <= 128);
