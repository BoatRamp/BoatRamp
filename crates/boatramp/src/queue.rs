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

/// Serializable projection of a [`QueuePeekEntry`] for typed JSON output (the wire
/// struct is deserialize-only). Fields mirror it 1:1.
#[derive(Debug, serde::Serialize)]
pub struct QueuePeekEntryView {
    pub id: String,
    pub attempts: u32,
    pub leased: bool,
    pub signed_context_present: bool,
    pub payload_b64: String,
}

impl From<QueuePeekEntry> for QueuePeekEntryView {
    fn from(m: QueuePeekEntry) -> Self {
        Self {
            id: m.id,
            attempts: m.attempts,
            leased: m.leased,
            signed_context_present: m.signed_context_present,
            payload_b64: m.payload_b64,
        }
    }
}

/// Serializable projection of a [`GroupEntry`] for typed JSON output (the wire
/// struct is deserialize-only). Fields mirror it 1:1.
#[derive(Debug, serde::Serialize)]
pub struct GroupEntryView {
    pub group: String,
    pub hwm: String,
    pub in_flight: usize,
    pub lag: usize,
}

impl From<GroupEntry> for GroupEntryView {
    fn from(g: GroupEntry) -> Self {
        Self {
            group: g.group,
            hwm: g.hwm,
            in_flight: g.in_flight,
            lag: g.lag,
        }
    }
}

/// The result of a `queue` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum QueueOutput {
    /// `queue peek` — the head of a topic's live work-queue.
    Peek {
        topic: String,
        messages: Vec<QueuePeekEntryView>,
    },
    /// `queue replay` — a slice of a grouped topic's retained history.
    Replay {
        topic: String,
        messages: Vec<QueuePeekEntryView>,
        next_after: Option<String>,
    },
    /// `queue groups` — a topic's consumer groups.
    Groups {
        topic: String,
        groups: Vec<GroupEntryView>,
    },
    /// `queue group-reset` — a group's cursor was reset.
    GroupReset {
        topic: String,
        group: String,
        start: String,
    },
    /// `queue group-delete` — a group was deleted.
    GroupDelete { topic: String, group: String },
    /// `queue pause` — a topic's delivery was paused.
    Paused { topic: String },
    /// `queue resume` — a paused topic was resumed.
    Resumed { topic: String },
    /// `queue policy` — a topic's flow-control policy was set.
    Policy {
        topic: String,
        max_depth: Option<usize>,
        max_rate: Option<u32>,
        max_unflushed: Option<usize>,
    },
}

impl crate::output::Rendered for QueueOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Peek { topic, messages } => write_peek(w, topic, messages),
            Self::Replay {
                topic,
                messages,
                next_after,
            } => write_replay(w, topic, messages, next_after.as_deref()),
            Self::Groups { topic, groups } => write_groups(w, topic, groups),
            Self::GroupReset {
                topic,
                group,
                start,
            } => writeln!(w, "reset group {group:?} on topic {topic:?} to {start}"),
            Self::GroupDelete { topic, group } => {
                writeln!(w, "deleted group {group:?} on topic {topic:?}")
            }
            Self::Paused { topic } => {
                writeln!(
                    w,
                    "paused topic {topic:?} (delivery suppressed; publish still flows)"
                )
            }
            Self::Resumed { topic } => writeln!(w, "resumed topic {topic:?}"),
            Self::Policy {
                topic,
                max_depth,
                max_rate,
                max_unflushed,
            } => {
                let fmt = |v: Option<usize>| v.map_or_else(|| "-".to_string(), |n| n.to_string());
                writeln!(
                    w,
                    "set policy on topic {topic:?}: max_depth={} max_rate={} max_unflushed={}",
                    fmt(*max_depth),
                    max_rate.map_or_else(|| "-".to_string(), |n| n.to_string()),
                    fmt(*max_unflushed),
                )
            }
        }
    }
}

/// Entry point for `boatramp queue`.
pub async fn run(args: QueueArgs, config: &ProjectConfig) -> Result<QueueOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let out = match &args.command {
        QueueCommand::Peek {
            topic,
            alias,
            limit,
        } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            let msgs = cp.peek_queue(scope, topic, *limit).await?;
            QueueOutput::Peek {
                topic: topic.clone(),
                messages: msgs.into_iter().map(QueuePeekEntryView::from).collect(),
            }
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
            QueueOutput::Replay {
                topic: topic.clone(),
                messages: msgs.into_iter().map(QueuePeekEntryView::from).collect(),
                next_after,
            }
        }
        QueueCommand::Groups { topic, alias } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            let groups = cp.list_groups(scope, topic).await?;
            QueueOutput::Groups {
                topic: topic.clone(),
                groups: groups.into_iter().map(GroupEntryView::from).collect(),
            }
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
            QueueOutput::GroupReset {
                topic: topic.clone(),
                group: group.clone(),
                start: start.to_string(),
            }
        }
        QueueCommand::GroupDelete {
            topic,
            group,
            alias,
        } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.group_op(scope, topic, group, "delete", None).await?;
            QueueOutput::GroupDelete {
                topic: topic.clone(),
                group: group.clone(),
            }
        }
        QueueCommand::Pause { topic, alias } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.pause_queue(scope, topic, true).await?;
            QueueOutput::Paused {
                topic: topic.clone(),
            }
        }
        QueueCommand::Resume { topic, alias } => {
            let scope = queue_scope(args.bus, &site, alias.as_deref())?;
            cp.pause_queue(scope, topic, false).await?;
            QueueOutput::Resumed {
                topic: topic.clone(),
            }
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
            QueueOutput::Policy {
                topic: topic.clone(),
                max_depth: *max_depth,
                max_rate: *max_rate,
                max_unflushed: *max_unflushed,
            }
        }
    };
    Ok(out)
}

/// Write a topic's consumer groups (name · in-flight · lag · cursor).
fn write_groups(
    w: &mut dyn std::io::Write,
    topic: &str,
    groups: &[GroupEntryView],
) -> std::io::Result<()> {
    if groups.is_empty() {
        return writeln!(w, "no consumer groups on topic {topic:?}");
    }
    for g in groups {
        writeln!(
            w,
            "{}  in_flight={}  lag={}  hwm={}",
            g.group, g.in_flight, g.lag, g.hwm
        )?;
    }
    writeln!(w, "{} group(s) on {topic:?}", groups.len())
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

/// Write the peeked head of the queue, decoding each payload as UTF-8 when possible.
fn write_peek(
    w: &mut dyn std::io::Write,
    topic: &str,
    msgs: &[QueuePeekEntryView],
) -> std::io::Result<()> {
    if msgs.is_empty() {
        return writeln!(w, "no messages queued on topic {topic:?}");
    }
    for m in msgs {
        let state = if m.leased { "leased" } else { "claimable" };
        let ctx = if m.signed_context_present { " ctx" } else { "" };
        let preview = payload_preview(&m.payload_b64);
        writeln!(
            w,
            "{}  {state}{ctx}  attempts={}  {preview}",
            m.id, m.attempts
        )?;
    }
    writeln!(w, "{} message(s) at the head of {topic:?}", msgs.len())
}

/// Write a replayed slice of a grouped topic's retained history (publish order). Unlike `peek`, these
/// are history entries — no lease/attempt state — so print just the id, context flag, and payload; a
/// `next_after` cursor (when present) tells the operator how to page forward.
fn write_replay(
    w: &mut dyn std::io::Write,
    topic: &str,
    msgs: &[QueuePeekEntryView],
    next_after: Option<&str>,
) -> std::io::Result<()> {
    if msgs.is_empty() {
        return writeln!(
            w,
            "no retained history on topic {topic:?} (grouped-only; empty past the offset)"
        );
    }
    for m in msgs {
        let ctx = if m.signed_context_present { " ctx" } else { "" };
        let preview = payload_preview(&m.payload_b64);
        writeln!(w, "{}{ctx}  {preview}", m.id)?;
    }
    match next_after {
        Some(after) => writeln!(
            w,
            "{} message(s) from {topic:?}; page on with --after {after}",
            msgs.len()
        ),
        None => writeln!(w, "{} message(s) from {topic:?}", msgs.len()),
    }
}
