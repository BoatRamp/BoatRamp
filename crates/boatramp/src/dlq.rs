//! `boatramp dlq` — manage a consumer topic's **dead-letter queue**.
//! Dead-lettered messages (those that exhausted `max_attempts`) are retained
//! until cleared; this command is how an operator clears or replays them.
//!
//! - `purge` drops them (records + payloads), reclaiming the space.
//! - `redrive` requeues them onto the live topic with a fresh attempt count, so
//!   consumers retry them once the cause of failure is fixed.
//!
//! Both go through `POST /api/sites/<site>/_boatramp/dlq` (site·write); the topic
//! is namespaced to the site server-side, so a token can only touch its own
//! site's queues.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `dlq` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// `dlq` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp dlq`.
#[derive(Debug, clap::Args)]
pub struct DlqArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,
    /// Site whose queues to manage (overrides [deploy].site).
    #[arg(long, global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: DlqCommand,
}

#[derive(Debug, Subcommand)]
enum DlqCommand {
    /// Drop a topic's dead-lettered messages (records + payloads).
    Purge {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Requeue a topic's dead-lettered messages with a fresh attempt count.
    Redrive {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
}

/// Entry point for `boatramp dlq`.
pub async fn run(args: DlqArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());

    let (action, topic, alias) = match &args.command {
        DlqCommand::Purge { topic, alias } => ("purge", topic, alias),
        DlqCommand::Redrive { topic, alias } => ("redrive", topic, alias),
    };
    let affected =
        client::operate_dlq(&http, &server, &site, topic, alias.as_deref(), action).await?;
    println!("{action}: {affected} dead-lettered message(s) on topic {topic:?}");
    Ok(())
}
