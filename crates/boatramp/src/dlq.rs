//! `boatramp dlq` — inspect and manage a consumer topic's **dead-letter queue**.
//! Dead-lettered messages (those that exhausted `max_attempts`) are retained
//! until cleared; this command inspects, replays, or drops them.
//!
//! - `ls` lists the dead-letters (metadata: id, attempts, last_error) — read-only.
//! - `show` prints one dead-letter in full, including its payload.
//! - `redrive` requeues them onto the live topic with a fresh attempt count.
//! - `discard` drops only the matching ones; `purge` drops them all.
//!
//! `redrive`/`discard`/`purge` accept an AND-composed filter (`--id` / `--older-than`
//! / `--match` on the host `last_error` / `--limit`), a `--dry-run` preview, and a
//! `--yes` confirmation for a filter-less (whole-DLQ) mutation. Reads go through
//! `GET` and mutations through `POST /api/sites/<site>/_boatramp/dlq`; the topic is
//! namespaced to the site server-side, so a token can only touch its own site's
//! queues.

use clap::Subcommand;

use crate::client::{self, DlqEntry, DlqFilter, OpScope};
use crate::config::ProjectConfig;

/// A failure in the `dlq` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A whole-DLQ mutation was refused without `--yes`.
    #[error(
        "refusing to {action} the ENTIRE dead-letter queue for topic {topic:?} without --yes (or narrow it with --id/--older-than/--match)"
    )]
    ConfirmRequired { action: String, topic: String },
    /// `--alias` was combined with `--bus` (the shared project bus is not per-deployment).
    #[error(
        "--alias cannot be combined with --bus: the shared project bus has no background-alias scope"
    )]
    AliasWithBus,
}

/// `dlq` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Shared filter flags for the mutating + listing subcommands.
#[derive(Debug, clap::Args)]
struct FilterFlags {
    /// Only the dead-letter with this exact message id.
    #[arg(long)]
    id: Option<String>,
    /// Only a specific lane: a consumer group name (omit for the work-queue lane; unset = all lanes).
    #[arg(long)]
    group: Option<String>,
    /// Only messages older than this many milliseconds (age from the message's own id).
    #[arg(long)]
    older_than_ms: Option<u64>,
    /// Only messages whose host `last_error` contains this substring.
    #[arg(long = "match")]
    match_last_error: Option<String>,
    /// Cap the number listed / acted on.
    #[arg(long)]
    limit: Option<usize>,
}

impl FilterFlags {
    fn to_filter(&self) -> DlqFilter {
        DlqFilter {
            id: self.id.clone(),
            group: self.group.clone(),
            older_than_ms: self.older_than_ms,
            match_last_error: self.match_last_error.clone(),
            limit: self.limit,
        }
    }

    fn is_empty(&self) -> bool {
        self.id.is_none()
            && self.group.is_none()
            && self.older_than_ms.is_none()
            && self.match_last_error.is_none()
            && self.limit.is_none()
    }
}

/// Arguments for `boatramp dlq`.
#[derive(Debug, clap::Args)]
pub struct DlqArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,
    /// Site whose queues to manage (overrides [deploy].site).
    #[arg(long, global = true)]
    site: Option<String>,
    /// Target the SHARED PROJECT BUS's dead-letters (`{project}/bus/{topic}`, common to
    /// every site in the project) instead of a single site's DLQ. Authorized project-wide:
    /// `ls`/`show` need `Project·Read`, and the destructive ops (`redrive`/`discard`/`purge`)
    /// need `Project·Admin`. Incompatible with `--alias`.
    #[arg(long, global = true)]
    bus: bool,

    #[command(subcommand)]
    command: DlqCommand,
}

/// Build the [`OpScope`] a `dlq` op targets: the shared project bus under `--bus`
/// (rejecting a nonsensical `--alias`), else the site (with any background-alias).
fn dlq_scope<'a>(bus: bool, site: &'a str, alias: Option<&'a str>) -> Result<OpScope<'a>> {
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
enum DlqCommand {
    /// List a topic's dead-lettered messages (metadata only).
    Ls {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
        #[command(flatten)]
        filter: FilterFlags,
    },
    /// Show one dead-lettered message in full (including its payload).
    Show {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// The message id to show.
        id: String,
        /// Consumer group lane (omit for the work-queue lane).
        #[arg(long)]
        group: Option<String>,
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
        #[command(flatten)]
        filter: FilterFlags,
        /// Preview the matching set without redriving.
        #[arg(long)]
        dry_run: bool,
        /// Confirm a filter-less (whole-DLQ) redrive.
        #[arg(long)]
        yes: bool,
    },
    /// Drop only the matching dead-lettered messages (records + payloads).
    Discard {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
        #[command(flatten)]
        filter: FilterFlags,
        /// Preview the matching set without discarding.
        #[arg(long)]
        dry_run: bool,
        /// Confirm a filter-less (whole-DLQ) discard.
        #[arg(long)]
        yes: bool,
    },
    /// Drop ALL of a topic's dead-lettered messages (records + payloads).
    Purge {
        /// Consumer topic (as declared in the deploy config).
        topic: String,
        /// Background-alias scope (`{site}/{alias}`); omit for the live site.
        #[arg(long)]
        alias: Option<String>,
        /// Confirm dropping the whole dead-letter queue.
        #[arg(long)]
        yes: bool,
    },
}

/// Entry point for `boatramp dlq`.
pub async fn run(args: DlqArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );

    match &args.command {
        DlqCommand::Ls {
            topic,
            alias,
            filter,
        } => {
            let scope = dlq_scope(args.bus, &site, alias.as_deref())?;
            let entries = cp
                .list_dlq(scope, topic, false, &filter.to_filter())
                .await?;
            print_list(topic, &entries);
        }
        DlqCommand::Show {
            topic,
            id,
            group,
            alias,
        } => {
            let scope = dlq_scope(args.bus, &site, alias.as_deref())?;
            let filter = DlqFilter {
                id: Some(id.clone()),
                group: group.clone(),
                ..Default::default()
            };
            let entries = cp.list_dlq(scope, topic, true, &filter).await?;
            match entries.into_iter().next() {
                Some(entry) => print_show(&entry),
                None => println!("no dead-letter {id:?} on topic {topic:?}"),
            }
        }
        DlqCommand::Redrive {
            topic,
            alias,
            filter,
            dry_run,
            yes,
        } => {
            let scope = dlq_scope(args.bus, &site, alias.as_deref())?;
            mutate(
                &cp,
                scope,
                Mutation {
                    action: "redrive",
                    topic,
                    filter,
                    dry_run: *dry_run,
                    yes: *yes,
                },
            )
            .await?;
        }
        DlqCommand::Discard {
            topic,
            alias,
            filter,
            dry_run,
            yes,
        } => {
            let scope = dlq_scope(args.bus, &site, alias.as_deref())?;
            mutate(
                &cp,
                scope,
                Mutation {
                    action: "discard",
                    topic,
                    filter,
                    dry_run: *dry_run,
                    yes: *yes,
                },
            )
            .await?;
        }
        DlqCommand::Purge { topic, alias, yes } => {
            let scope = dlq_scope(args.bus, &site, alias.as_deref())?;
            let empty = FilterFlags {
                id: None,
                group: None,
                older_than_ms: None,
                match_last_error: None,
                limit: None,
            };
            mutate(
                &cp,
                scope,
                Mutation {
                    action: "purge",
                    topic,
                    filter: &empty,
                    dry_run: false,
                    yes: *yes,
                },
            )
            .await?;
        }
    }
    Ok(())
}

/// One mutating `dlq` invocation (bundles the per-command flags).
struct Mutation<'a> {
    action: &'a str,
    topic: &'a str,
    filter: &'a FilterFlags,
    dry_run: bool,
    yes: bool,
}

/// Run a mutating op with the shared dry-run + whole-DLQ confirmation policy.
async fn mutate(cp: &client::ControlPlane, scope: OpScope<'_>, m: Mutation<'_>) -> Result<()> {
    // A filter-less mutation touches the WHOLE queue — require an explicit --yes (unless it's a
    // preview). A filtered op is already narrowed, so it proceeds.
    if !m.dry_run && m.filter.is_empty() && !m.yes {
        return Err(Error::ConfirmRequired {
            action: m.action.to_string(),
            topic: m.topic.to_string(),
        });
    }
    let (affected, matched) = cp
        .operate_dlq(scope, m.topic, m.action, &m.filter.to_filter(), m.dry_run)
        .await?;
    if m.dry_run {
        println!(
            "dry-run: {} would affect {affected} dead-letter(s) on topic {:?}:",
            m.action, m.topic
        );
        print_list(m.topic, &matched);
    } else {
        println!(
            "{}: {affected} dead-lettered message(s) on topic {:?}",
            m.action, m.topic
        );
    }
    Ok(())
}

/// Print a metadata listing (id · lane · attempts · last_error).
fn print_list(topic: &str, entries: &[DlqEntry]) {
    if entries.is_empty() {
        println!("no dead-letters on topic {topic:?}");
        return;
    }
    for e in entries {
        let lane = if e.group.is_empty() {
            "work-queue".to_string()
        } else {
            format!("group:{}", e.group)
        };
        let reason = e.last_error.as_deref().unwrap_or("-");
        println!(
            "{}  {lane}  attempts={}  last_error={reason}",
            e.id, e.attempts
        );
    }
    println!("{} dead-letter(s)", entries.len());
}

/// Print one dead-letter in full, decoding its payload as UTF-8 when possible.
fn print_show(entry: &DlqEntry) {
    use base64::Engine as _;
    let lane = if entry.group.is_empty() {
        "work-queue".to_string()
    } else {
        format!("group:{}", entry.group)
    };
    println!("id:             {}", entry.id);
    println!("lane:           {lane}");
    println!("attempts:       {}", entry.attempts);
    println!(
        "last_error:     {}",
        entry.last_error.as_deref().unwrap_or("-")
    );
    println!(
        "signed_context: {}",
        if entry.signed_context_present {
            "present"
        } else {
            "none"
        }
    );
    match &entry.payload_b64 {
        Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(text) => println!("payload ({} bytes):\n{text}", bytes.len()),
                Err(_) => println!("payload: {} bytes (binary)", bytes.len()),
            },
            Err(_) => println!("payload: <undecodable>"),
        },
        None => println!("payload: <not loaded>"),
    }
}
