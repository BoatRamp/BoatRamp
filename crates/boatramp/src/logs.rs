//! The `logs` subcommand: tail a site's captured guest stdout/stderr.
//! One-shot by default; `--follow` polls for new lines.

use std::time::Duration;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `logs` / `stats` subcommands.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Serializing the handler stats to JSON failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// `logs` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp logs`.
#[derive(Debug, clap::Args)]
pub struct LogsArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site whose guest logs to tail (overrides [deploy].site). Mutually exclusive
    /// with `--function`.
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    /// Function whose captured guest stdout/stderr to tail — a standalone component
    /// (GraphQL subgraph, auth function, worker) invoked via `emit::invoke`. Its
    /// `println!`/`eprintln!` output is otherwise unreadable. Scoped to `--project`;
    /// takes precedence over `--site`.
    #[arg(long)]
    function: Option<String>,

    /// Only show one stream: `stdout` or `stderr`.
    #[arg(long)]
    stream: Option<String>,

    /// Number of recent lines to show.
    #[arg(long, default_value_t = 200)]
    limit: usize,

    /// Keep polling for new lines (like `tail -f`).
    #[arg(long, short)]
    follow: bool,
}

/// What `logs` is tailing: a site's or a function's captured guest output. Both read
/// the same control-plane log store; only the endpoint differs.
enum Target {
    Site(String),
    Function(String),
}

/// One fetch against the control plane for either target — so the initial pull and the
/// `--follow` poll share exactly one code path.
async fn fetch(
    cp: &client::ControlPlane,
    target: &Target,
    limit: usize,
    after: u64,
    stream: Option<&str>,
) -> Result<client::LogsResponse> {
    Ok(match target {
        Target::Site(site) => cp.fetch_logs(site, limit, after, stream).await?,
        Target::Function(function) => {
            cp.fetch_function_logs(function, limit, after, stream)
                .await?
        }
    })
}

/// The result of a bounded `boatramp logs` tail: the captured guest log lines (DATA).
/// Reuses the wire [`client::LogsResponse`] (`{entries, dropped}`) so a JSON consumer
/// reads the lines structurally.
///
/// The `--follow` mode is an *unbounded* streaming tail and does not produce this value:
/// it renders lines to stdout as they arrive (see [`run`]).
#[derive(Debug, serde::Serialize)]
#[serde(transparent)]
pub struct LogsOutput {
    response: client::LogsResponse,
}

impl crate::output::Rendered for LogsOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        for entry in &self.response.entries {
            writeln!(w, "[{}] {}", entry.stream, entry.line)?;
        }
        Ok(())
    }
}

/// Entry point for `boatramp logs`.
///
/// A bounded tail (no `--follow`) returns the fetched lines as the typed result, which
/// [`crate::output`] renders once. `--follow` is a continuous streaming-DATA case that the
/// single-`emit` result model does not fit, so that branch renders lines to stdout directly
/// as they arrive and never returns `Ok` (it loops until interrupted or a fetch errors).
pub async fn run(args: LogsArgs, config: &ProjectConfig) -> Result<LogsOutput> {
    let stream = args.stream.as_deref();
    let http = client::http_client(client::token(config).as_deref());
    let project = client::resolve_project(config);

    // A `--function` selector takes precedence over the (env/config-backed) `--site`,
    // so `BOATRAMP_SITE` in the environment never blocks tailing a function.
    let (cp, target) = if let Some(function) = args.function {
        let server = client::resolve_server(args.server, config)?;
        (
            client::ControlPlane::new(server, http, project),
            Target::Function(function),
        )
    } else {
        let (server, site) = client::resolve_target(args.server, args.site, config)?;
        (
            client::ControlPlane::new(server, http, project),
            Target::Site(site),
        )
    };

    // Initial fetch: the most recent `limit` lines.
    let first = fetch(&cp, &target, args.limit, 0, stream).await?;

    if !args.follow {
        // Bounded tail: the lines ARE the result. The rate-cap drop notice is a
        // diagnostic (was stderr) → tracing; the count also rides the JSON shape.
        if first.dropped > 0 {
            tracing::warn!(
                "(\u{2026} {} line(s) dropped by the rate cap)",
                first.dropped
            );
        }
        return Ok(LogsOutput { response: first });
    }

    // Follow: an unbounded streaming tail. Render lines to stdout as they arrive (the
    // single-`emit` model does not fit a never-ending stream) and never return `Ok`.
    let mut cursor = first.entries.last().map(|e| e.seq).unwrap_or(0);
    for entry in &first.entries {
        print_line(entry);
    }
    if first.dropped > 0 {
        tracing::warn!(
            "(\u{2026} {} line(s) dropped by the rate cap)",
            first.dropped
        );
    }
    // Poll for lines newer than the cursor (a stable monotonic seq, so no duplicates
    // and no gaps across polls).
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let next = fetch(&cp, &target, args.limit.max(1000), cursor, stream).await?;
        for entry in &next.entries {
            print_line(entry);
            cursor = cursor.max(entry.seq);
        }
    }
}

fn print_line(entry: &client::LogEntry) {
    println!("[{}] {}", entry.stream, entry.line);
}

/// Arguments for `boatramp stats`.
#[derive(Debug, clap::Args)]
pub struct StatsArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site whose handler stats to show (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    /// Show the NODE-global wasm instance-lifecycle + memory stats instead of a site's handler stats:
    /// per-lane warm-hit / cold-miss / eviction / instantiation counts + compile & instantiate
    /// durations, the resident (warm) component set vs capacity, in-flight vs ceiling, and process RSS
    /// vs the per-instance limit. Read-only; needs a `System·Read` (operator/admin) token. No `--site`
    /// is required (the engine is shared node-wide).
    #[arg(long)]
    instances: bool,
}

/// The result of `boatramp stats`: the stats document (DATA). Serializes transparently as
/// the stats object itself, so a JSON consumer reads it unwrapped; the human view is the same
/// pretty-printed JSON the command historically emitted.
#[derive(Debug, serde::Serialize)]
#[serde(transparent)]
pub struct StatsOutput {
    stats: serde_json::Value,
}

impl crate::output::Rendered for StatsOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&self.stats).map_err(std::io::Error::other)?
        )
    }
}

/// Entry point for `boatramp stats`: a site's operator handler stats —
/// per-`(trigger, route)` invocation counters, consumer backlog/dead-letters, and live stream
/// connections — OR, with `--instances`, the node-global wasm instance-lifecycle + memory stats.
pub async fn stats(args: StatsArgs, config: &ProjectConfig) -> Result<StatsOutput> {
    // The instance stats are node-global, so they need only a server + token, not a resolved site.
    if args.instances {
        let server = client::resolve_server(args.server, config)?;
        let cp = client::ControlPlane::new(
            server,
            client::http_client(client::token(config).as_deref()),
            client::resolve_project(config),
        );
        let stats = cp.fetch_instance_stats().await?;
        return Ok(StatsOutput { stats });
    }
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let stats = cp.fetch_handler_stats(&site).await?;
    Ok(StatsOutput { stats })
}
