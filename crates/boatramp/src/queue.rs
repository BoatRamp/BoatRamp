//! `boatramp queue` — inspect a consumer topic's **live** work-queue (as opposed to
//! its dead-letter store, which `boatramp dlq` manages).
//!
//! - `peek` shows the head of the queue (id, attempts, leased/claimable, payload)
//!   WITHOUT consuming — no lease is taken and no delivery attempt is charged.
//!
//! Reads go through `GET /api/sites/<site>/_boatramp/queue/peek`; the topic is
//! namespaced to the site server-side, so a token can only inspect its own site's
//! queues.

use clap::Subcommand;

use crate::client::{self, GroupEntry, QueuePeekEntry};
use crate::config::ProjectConfig;

/// A failure in the `queue` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// `queue` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp queue`.
#[derive(Debug, clap::Args)]
pub struct QueueArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,
    /// Site whose queues to inspect (overrides [deploy].site).
    #[arg(long, global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: QueueCommand,
}

#[derive(Debug, Subcommand)]
enum QueueCommand {
    /// Inspect the head of a topic's live work-queue without consuming.
    Peek {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
        /// How many messages to peek (delivery order). Server-capped.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// List a topic's consumer groups (cursor, in-flight, lag).
    Groups {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Reset a consumer group's cursor (re-consume from earliest, or skip to latest).
    GroupReset {
        /// Consumer topic.
        topic: String,
        /// The group to reset.
        group: String,
        /// Skip to the head instead of re-consuming the whole backlog.
        #[arg(long, conflicts_with = "earliest")]
        latest: bool,
        /// Re-consume the whole retained backlog (the default).
        #[arg(long)]
        earliest: bool,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Delete a consumer group (its state + its dead-letters).
    GroupDelete {
        /// Consumer topic.
        topic: String,
        /// The group to delete.
        group: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
}

/// Entry point for `boatramp queue`.
pub async fn run(args: QueueArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    match &args.command {
        QueueCommand::Peek {
            topic,
            alias,
            limit,
        } => {
            let msgs = cp
                .peek_queue(&site, topic, alias.as_deref(), *limit)
                .await?;
            print_peek(topic, &msgs);
        }
        QueueCommand::Groups { topic, alias } => {
            let groups = cp.list_groups(&site, topic, alias.as_deref()).await?;
            print_groups(topic, &groups);
        }
        QueueCommand::GroupReset {
            topic,
            group,
            latest,
            earliest: _,
            alias,
        } => {
            // Default is earliest (re-consume); --latest skips to the head.
            let start = if *latest { "latest" } else { "earliest" };
            cp.group_op(&site, topic, alias.as_deref(), group, "reset", Some(start))
                .await?;
            println!("reset group {group:?} on topic {topic:?} to {start}");
        }
        QueueCommand::GroupDelete {
            topic,
            group,
            alias,
        } => {
            cp.group_op(&site, topic, alias.as_deref(), group, "delete", None)
                .await?;
            println!("deleted group {group:?} on topic {topic:?}");
        }
    }
    Ok(())
}

/// Print a topic's consumer groups (name · in-flight · lag · cursor).
fn print_groups(topic: &str, groups: &[GroupEntry]) {
    if groups.is_empty() {
        println!("no consumer groups on topic {topic:?}");
        return;
    }
    for g in groups {
        println!(
            "{}  in_flight={}  lag={}  hwm={}",
            g.group, g.in_flight, g.lag, g.hwm
        );
    }
    println!("{} group(s) on {topic:?}", groups.len());
}

/// Print the peeked head of the queue, decoding each payload as UTF-8 when possible.
fn print_peek(topic: &str, msgs: &[QueuePeekEntry]) {
    use base64::Engine as _;
    if msgs.is_empty() {
        println!("no messages queued on topic {topic:?}");
        return;
    }
    for m in msgs {
        let state = if m.leased { "leased" } else { "claimable" };
        let ctx = if m.signed_context_present { " ctx" } else { "" };
        let preview = match base64::engine::general_purpose::STANDARD.decode(&m.payload_b64) {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(text) if text.chars().count() <= 120 => text.to_string(),
                Ok(text) => {
                    let head: String = text.chars().take(120).collect();
                    format!("{head}… ({} bytes)", bytes.len())
                }
                Err(_) => format!("<{} bytes binary>", bytes.len()),
            },
            Err(_) => "<undecodable>".to_string(),
        };
        println!("{}  {state}{ctx}  attempts={}  {preview}", m.id, m.attempts);
    }
    println!("{} message(s) at the head of {topic:?}", msgs.len());
}
