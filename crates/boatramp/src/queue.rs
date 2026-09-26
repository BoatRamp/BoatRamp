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

use crate::client::{self, GroupEntry, OpScope, QueuePeekEntry};
use crate::config::ProjectConfig;

/// A failure in the `queue` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// `--alias` was combined with `--bus` (the shared project bus is not per-deployment).
    #[error(
        "--alias cannot be combined with --bus: the shared project bus has no background-alias scope"
    )]
    AliasWithBus,
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
    /// Target the SHARED PROJECT BUS (`{project}/bus/{topic}`, the destination of a
    /// `bus:<topic>` publish, common to every site in the project) instead of a single
    /// site's queues. Authorized project-wide: reads need `Project·Read`, the destructive
    /// ops (group reset/delete, pause) need `Project·Admin`. Incompatible with `--alias`.
    #[arg(long, global = true)]
    bus: bool,

    #[command(subcommand)]
    command: QueueCommand,
}

/// Build the [`OpScope`] a `queue` op targets: the shared project bus under `--bus`
/// (rejecting a nonsensical `--alias`), else the site (with any background-alias).
fn queue_scope<'a>(bus: bool, site: &'a str, alias: Option<&'a str>) -> Result<OpScope<'a>> {
    if bus {
        if alias.is_some() {
            return Err(Error::AliasWithBus);
        }
        Ok(OpScope::Bus)
    } else {
        Ok(OpScope::site_alias(site, alias))
    }
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
    /// Replay a GROUPED topic's retained history from an offset, without consuming (no lease, no
    /// attempt, no group cursor touched). Work-queue topics delete on ack — use `peek` there.
    Replay {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Exclusive start offset — a prior message id; omit to replay from the beginning.
        #[arg(long)]
        after: Option<String>,
        /// How many messages to replay (publish order). Server-capped.
        #[arg(long)]
        limit: Option<usize>,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
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
    /// Pause a topic — suppress delivery (publish + in-flight ack/nack keep flowing).
    Pause {
        /// Consumer topic.
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Resume a paused topic.
    Resume {
        /// Consumer topic.
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Set a per-topic operator flow-control policy (v0.4.24). Omit a flag to leave that axis
    /// uncapped. `--max-unflushed` is single-node only (inert on a cluster).
    Policy {
        /// Consumer topic.
        topic: String,
        /// Reject a publish once the backlog is at/above this (fail-closed). Omit = unbounded.
        #[arg(long)]
        max_depth: Option<usize>,
        /// Per-node publish rate cap (messages/sec, best-effort token bucket). Omit = unlimited.
        #[arg(long)]
        max_rate: Option<u32>,
        /// Per-topic relaxed-durability budget override (single-node only). Omit = node default.
        #[arg(long)]
        max_unflushed: Option<usize>,
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
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            let msgs = cp.peek_queue(scope, topic, *limit).await?;
            print_peek(topic, &msgs);
        }
        QueueCommand::Replay {
            topic,
            after,
            limit,
            alias,
        } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            let (msgs, next_after) = cp
                .replay_queue(scope, topic, after.as_deref(), *limit)
                .await?;
            print_replay(topic, &msgs, next_after.as_deref());
        }
        QueueCommand::Groups { topic, alias } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            let groups = cp.list_groups(scope, topic).await?;
            print_groups(topic, &groups);
        }
        QueueCommand::GroupReset {
            topic,
            group,
            latest,
            earliest: _,
            alias,
        } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            // Default is earliest (re-consume); --latest skips to the head.
            let start = if *latest { "latest" } else { "earliest" };
            cp.group_op(scope, topic, group, "reset", Some(start))
                .await?;
            println!("reset group {group:?} on topic {topic:?} to {start}");
        }
        QueueCommand::GroupDelete {
            topic,
            group,
            alias,
        } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.group_op(scope, topic, group, "delete", None).await?;
            println!("deleted group {group:?} on topic {topic:?}");
        }
        QueueCommand::Pause { topic, alias } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.pause_queue(scope, topic, true).await?;
            println!("paused topic {topic:?} (delivery suppressed; publish still flows)");
        }
        QueueCommand::Resume { topic, alias } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.pause_queue(scope, topic, false).await?;
            println!("resumed topic {topic:?}");
        }
        QueueCommand::Policy {
            topic,
            max_depth,
            max_rate,
            max_unflushed,
            alias,
        } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.set_topic_policy(scope, topic, *max_depth, *max_rate, *max_unflushed)
                .await?;
            let fmt = |v: Option<usize>| v.map_or_else(|| "-".to_string(), |n| n.to_string());
            println!(
                "set policy on topic {topic:?}: max_depth={} max_rate={} max_unflushed={}",
                fmt(*max_depth),
                max_rate.map_or_else(|| "-".to_string(), |n| n.to_string()),
                fmt(*max_unflushed),
            );
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

/// Decode a base64 payload to a short UTF-8 preview (or a binary/undecodable marker).
fn payload_preview(payload_b64: &str) -> String {
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(payload_b64) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text) if text.chars().count() <= 120 => text.to_string(),
            Ok(text) => {
                let head: String = text.chars().take(120).collect();
                format!("{head}… ({} bytes)", bytes.len())
            }
            Err(_) => format!("<{} bytes binary>", bytes.len()),
        },
        Err(_) => "<undecodable>".to_string(),
    }
}

/// Print the peeked head of the queue, decoding each payload as UTF-8 when possible.
fn print_peek(topic: &str, msgs: &[QueuePeekEntry]) {
    if msgs.is_empty() {
        println!("no messages queued on topic {topic:?}");
        return;
    }
    for m in msgs {
        let state = if m.leased { "leased" } else { "claimable" };
        let ctx = if m.signed_context_present { " ctx" } else { "" };
        let preview = payload_preview(&m.payload_b64);
        println!("{}  {state}{ctx}  attempts={}  {preview}", m.id, m.attempts);
    }
    println!("{} message(s) at the head of {topic:?}", msgs.len());
}

/// Print a replayed slice of a grouped topic's retained history (publish order). Unlike `peek`, these
/// are history entries — no lease/attempt state — so print just the id, context flag, and payload; a
/// `next_after` cursor (when present) tells the operator how to page forward.
fn print_replay(topic: &str, msgs: &[QueuePeekEntry], next_after: Option<&str>) {
    if msgs.is_empty() {
        println!("no retained history on topic {topic:?} (grouped-only; empty past the offset)");
        return;
    }
    for m in msgs {
        let ctx = if m.signed_context_present { " ctx" } else { "" };
        let preview = payload_preview(&m.payload_b64);
        println!("{}{ctx}  {preview}", m.id);
    }
    match next_after {
        Some(after) => println!(
            "{} message(s) from {topic:?}; page on with --after {after}",
            msgs.len()
        ),
        None => println!("{} message(s) from {topic:?}", msgs.len()),
    }
}
