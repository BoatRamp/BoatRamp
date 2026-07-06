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

    /// Site whose guest logs to tail (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

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

/// Entry point for `boatramp logs`.
pub async fn run(args: LogsArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let stream = args.stream.as_deref();

    // Initial fetch: the most recent `limit` lines.
    let first = client::fetch_logs(&http, &server, &site, args.limit, 0, stream).await?;
    let mut cursor = first.entries.last().map(|e| e.seq).unwrap_or(0);
    for entry in &first.entries {
        print_line(entry);
    }
    if first.dropped > 0 {
        eprintln!(
            "(\u{2026} {} line(s) dropped by the rate cap)",
            first.dropped
        );
    }
    if !args.follow {
        return Ok(());
    }

    // Follow: poll for lines newer than the cursor (a stable monotonic seq, so
    // no duplicates and no gaps across polls).
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let next =
            client::fetch_logs(&http, &server, &site, args.limit.max(1000), cursor, stream).await?;
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
}

/// Entry point for `boatramp stats`: the site's operator handler stats —
/// per-`(trigger, route)` invocation counters, consumer backlog/dead-letters,
/// and live stream connections.
pub async fn stats(args: StatsArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let stats = client::fetch_handler_stats(&http, &server, &site).await?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}
