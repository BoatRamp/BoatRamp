//! The `deployments` (history) and `rollback` subcommands.

use std::time::{SystemTime, UNIX_EPOCH};

use boatramp_core::cert::CertStatus;
use boatramp_core::deploy::{DeployMeta, DeploymentList, GcReport, ScrubReport};

use crate::client;
use crate::config::ProjectConfig;

/// A failure running a deployment-management subcommand (deployments, rollback,
/// status, prune, scrub, cert-status).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server/site target or a control-plane call failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// Reading the confirmation prompt from stdin/stderr failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// `rollback --to` matched no deployment.
    #[error("no deployment matching {0}")]
    NoDeploymentMatching(String),
    /// `rollback` with no previous deployment to fall back to.
    #[error("no previous deployment to roll back to")]
    NoPreviousDeployment,
    /// The integrity scrub found corrupt or unreadable blobs.
    #[error("{checked} blob(s) checked: {mismatched} corrupted, {unreadable} unreadable")]
    ScrubFailed {
        checked: usize,
        mismatched: usize,
        unreadable: usize,
    },
}

/// `manage` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp deployments`.
#[derive(Debug, clap::Args)]
pub struct DeploymentsArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,

    /// Site to inspect (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE")]
    site: Option<String>,

    /// Maximum number of deployments to show.
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

/// List a site's deployment history (most recent first; `*` marks current).
pub async fn list(args: DeploymentsArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let list = client::fetch_deployments(&http, &server, &site).await?;

    if list.deployments.is_empty() {
        println!("no deployments for {site}");
        return Ok(());
    }
    for entry in list.deployments.iter().take(args.limit) {
        let marker = if list.current.as_deref() == Some(entry.id.as_str()) {
            "*"
        } else {
            " "
        };
        let detail = entry.meta.as_ref().map(meta_summary).unwrap_or_default();
        println!("{marker} {}  {}{detail}", short(&entry.id), ago(entry.at));
    }
    Ok(())
}

/// A compact one-line provenance summary:
/// ` — <message> [<tag>] (<branch>@<sha7>) <k=v …>`.
fn meta_summary(meta: &DeployMeta) -> String {
    let mut parts = Vec::new();
    if let Some(message) = meta.message.as_deref().filter(|m| !m.is_empty()) {
        parts.push(message.to_string());
    }
    if let Some(tag) = meta.tag.as_deref().filter(|t| !t.is_empty()) {
        parts.push(format!("[{tag}]"));
    }
    let mut origin = String::new();
    if let Some(branch) = &meta.branch {
        origin.push_str(branch);
    }
    if let Some(source) = &meta.source {
        let sha = &source[..source.len().min(7)];
        if origin.is_empty() {
            origin = sha.to_string();
        } else {
            origin = format!("{origin}@{sha}");
        }
    }
    if !origin.is_empty() {
        parts.push(format!("({origin})"));
    }
    if !meta.tags.is_empty() {
        parts.push(
            meta.tags
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  — {}", parts.join(" "))
    }
}

/// Arguments for `boatramp rollback`.
#[derive(Debug, clap::Args)]
pub struct RollbackArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,

    /// Site to roll back (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE")]
    site: Option<String>,

    /// Deployment id (or unique prefix) to activate. Defaults to the previous one.
    #[arg(long)]
    to: Option<String>,
}

/// Roll a site back to its previous deployment, or to a specific id.
pub async fn rollback(args: RollbackArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let list = client::fetch_deployments(&http, &server, &site).await?;

    let target = match &args.to {
        Some(wanted) => {
            resolve_id(&list, wanted).ok_or_else(|| Error::NoDeploymentMatching(wanted.clone()))?
        }
        None => previous(&list).ok_or(Error::NoPreviousDeployment)?,
    };

    client::activate(&http, &server, &site, &target).await?;
    println!("rolled back {site} -> {target}");
    Ok(())
}

/// Arguments for `boatramp status`.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,

    /// Site to inspect (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE")]
    site: Option<String>,
}

/// Show a site's current deployment: id, age, and size.
pub async fn status(args: StatusArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let list = client::fetch_deployments(&http, &server, &site).await?;

    let Some(current) = list.current.clone() else {
        println!("{site}: no active deployment");
        return Ok(());
    };

    let manifest = client::fetch_manifest(&http, &server, &site, &current).await?;
    let files = manifest.files.len();
    let bytes: u64 = manifest.files.values().map(|entry| entry.size).sum();
    let current_entry = list.deployments.iter().find(|entry| entry.id == current);
    let age = current_entry.map(|entry| ago(entry.at));
    let meta = current_entry.and_then(|entry| entry.meta.as_ref());

    println!("{site}");
    println!("  deployment  {}", short(&current));
    println!("  activated   {}", age.as_deref().unwrap_or("unknown"));
    println!("  content     {files} file(s), {}", human_bytes(bytes));
    println!("  history     {} deployment(s)", list.deployments.len());
    if let Some(meta) = meta {
        if let Some(message) = meta.message.as_deref().filter(|m| !m.is_empty()) {
            println!("  message     {message}");
        }
        match (&meta.branch, &meta.source) {
            (Some(branch), Some(source)) => {
                println!("  source      {branch}@{}", &source[..source.len().min(12)]);
            }
            (None, Some(source)) => println!("  source      {}", &source[..source.len().min(12)]),
            (Some(branch), None) => println!("  source      {branch}"),
            (None, None) => {}
        }
        if let Some(author) = meta.author.as_deref().filter(|a| !a.is_empty()) {
            println!("  author      {author}");
        }
        if let Some(tag) = meta.tag.as_deref().filter(|t| !t.is_empty()) {
            println!("  release     {tag}");
        }
        if !meta.tags.is_empty() {
            let kv = meta
                .tags
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  tags        {kv}");
        }
    }
    Ok(())
}

/// Arguments for `boatramp prune`.
#[derive(Debug, clap::Args)]
pub struct PruneArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,

    /// Only report what would be removed; do not delete anything.
    #[arg(long)]
    dry_run: bool,

    /// Delete without asking for confirmation.
    #[arg(long, short = 'y')]
    yes: bool,

    /// Keep at most this many most-recent deployments per site (retention).
    #[arg(long)]
    keep_last: Option<usize>,

    /// Also keep any deployment activated within this many seconds.
    #[arg(long)]
    keep_age: Option<u64>,

    /// Safety window (seconds): never collect a deployment first seen this
    /// recently, so a prune can't race an in-flight deploy (default 3600).
    #[arg(long)]
    grace: Option<u64>,
}

impl PruneArgs {
    /// Query params mirroring the server's `PruneQuery`.
    fn query(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        if let Some(n) = self.keep_last {
            q.push(("keep_last", n.to_string()));
        }
        if let Some(secs) = self.keep_age {
            q.push(("keep_age", secs.to_string()));
        }
        if let Some(secs) = self.grace {
            q.push(("grace", secs.to_string()));
        }
        q
    }
}

/// Delete orphan deployments and unreferenced blobs.
///
/// Previews with a safe GET, then (unless `--yes`) asks for confirmation before
/// committing the deletion with a POST. `--dry-run` only reports.
pub async fn prune(args: PruneArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server.clone(), config)?;
    let http = client::http_client(client::token(config).as_deref());
    let url = format!("{server}/api/prune");
    let query = args.query();

    // Preview with a safe, read-only GET.
    let report: GcReport = http
        .get(&url)
        .query(&query)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if report.manifests_removed == 0 && report.blobs_removed == 0 {
        println!("nothing to prune");
        return Ok(());
    }

    print_report(&report, "reclaimable");

    if args.dry_run {
        println!("run `boatramp prune` to delete");
        return Ok(());
    }

    if !args.yes {
        let prompt = format!(
            "delete {} manifest(s) and {} blob(s) ({})? [y/N] ",
            report.manifests_removed,
            report.blobs_removed,
            human_bytes(report.bytes_reclaimed),
        );
        if !confirm(&prompt)? {
            println!("aborted");
            return Ok(());
        }
    }

    // Commit the deletion.
    let deleted: GcReport = http
        .post(&url)
        .query(&query)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    print_report(&deleted, "removed");
    Ok(())
}

/// Print a prune/GC report: an outcome line plus the totals.
fn print_report(report: &GcReport, verb: &str) {
    println!(
        "{} orphan manifest(s), {} blob(s) {verb} ({})",
        report.manifests_removed,
        report.blobs_removed,
        human_bytes(report.bytes_reclaimed),
    );
    println!(
        "  ({} blob(s), {} manifest(s) total)",
        report.blobs_total, report.manifests_total
    );
}

/// Arguments for `boatramp scrub`.
#[derive(Debug, clap::Args)]
pub struct ScrubArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,
}

/// Verify every stored blob still hashes to its key (integrity scrub).
/// Read-only; exits non-zero if any corruption or unreadable blob is found, so
/// it slots into a cron/healthcheck.
pub async fn scrub(args: ScrubArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let report: ScrubReport = http
        .post(format!("{server}/api/scrub"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if report.is_clean() {
        println!("{} blob(s) verified, all intact", report.checked);
        return Ok(());
    }
    for m in &report.mismatched {
        println!(
            "CORRUPT    {} (expected {}, got {})",
            m.key, m.expected, m.actual
        );
    }
    for e in &report.errors {
        println!("UNREADABLE {} ({})", e.key, e.error);
    }
    Err(Error::ScrubFailed {
        checked: report.checked,
        mismatched: report.mismatched.len(),
        unreadable: report.errors.len(),
    })
}

/// Arguments for `boatramp cert-status`.
#[derive(Debug, clap::Args)]
pub struct CertStatusArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,
}

/// Show cluster-managed certificate status (domain + expiry). Empty when certs
/// live in a file cache (single-node `--tls acme`) rather than the control plane.
pub async fn cert_status(args: CertStatusArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let certs: Vec<CertStatus> = http
        .get(format!("{server}/api/certs"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if certs.is_empty() {
        println!("no cluster-managed certificates");
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for cert in certs {
        let remaining = cert.not_after_unix.saturating_sub(now);
        let days = remaining / 86_400;
        let state = if cert.not_after_unix <= now {
            "EXPIRED".to_string()
        } else {
            format!("{days}d left")
        };
        println!("{}  ({state})", cert.domain);
    }
    Ok(())
}

/// Prompt on stderr and read a yes/no answer from stdin. EOF counts as "no".
fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// The deployment activated just before the current one.
fn previous(list: &DeploymentList) -> Option<String> {
    let current = list.current.as_deref()?;
    let pos = list.deployments.iter().position(|e| e.id == current)?;
    list.deployments.get(pos + 1).map(|e| e.id.clone())
}

/// Resolve a full id, a unique history prefix, or a full 64-hex id.
fn resolve_id(list: &DeploymentList, wanted: &str) -> Option<String> {
    if list.deployments.iter().any(|e| e.id == wanted) {
        return Some(wanted.to_string());
    }
    let mut matches = list.deployments.iter().filter(|e| e.id.starts_with(wanted));
    if let Some(first) = matches.next() {
        return matches.next().is_none().then(|| first.id.clone());
    }
    // Not in history: accept a full content id and let the server validate it.
    if wanted.len() == 64 && wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(wanted.to_string());
    }
    None
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// Render a unix timestamp as a coarse "N{s,m,h,d} ago".
fn ago(at: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = now.saturating_sub(at);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3_600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3_600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// Render a byte count as a human-readable size.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}
