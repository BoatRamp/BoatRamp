//! The `deployments` (history) and `rollback` subcommands.

use std::time::{SystemTime, UNIX_EPOCH};

use boatramp_core::cert::CertStatus;
use boatramp_core::deploy::{DeployMeta, DeploymentList, GcReport, HistoryEntry, ScrubReport};

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

/// `boatramp deployments`: a site's deployment history (the listed items).
#[derive(Debug, serde::Serialize)]
pub struct DeploymentsOutput {
    /// The site inspected.
    site: String,
    /// The currently-active deployment id, if any (marks the `*` row).
    current: Option<String>,
    /// Total deployments in history (before the `--limit` cap).
    total: usize,
    /// The deployments shown (most recent first, capped at `--limit`).
    deployments: Vec<HistoryEntry>,
}

impl crate::output::Rendered for DeploymentsOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.total == 0 {
            return writeln!(w, "no deployments for {}", self.site);
        }
        for entry in &self.deployments {
            let marker = if self.current.as_deref() == Some(entry.id.as_str()) {
                "*"
            } else {
                " "
            };
            let detail = entry.meta.as_ref().map(meta_summary).unwrap_or_default();
            writeln!(
                w,
                "{marker} {}  {}{detail}",
                short(&entry.id),
                ago(entry.at)
            )?;
        }
        Ok(())
    }
}

/// `boatramp rollback`: the site was activated at a target deployment.
#[derive(Debug, serde::Serialize)]
pub struct RollbackOutput {
    site: String,
    target: String,
}

impl crate::output::Rendered for RollbackOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(w, "rolled back {} -> {}", self.site, self.target)
    }
}

/// `boatramp status`: a site's current deployment (or none).
// The `Current` variant carries the full deployment detail + metadata; larger than the no-deployment
// ack, but a short-lived build-then-emit value, so an allow over boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum StatusOutput {
    /// The site has no active deployment.
    NoDeployment { site: String },
    /// The site's current deployment and its provenance.
    Current {
        site: String,
        /// Full current deployment id (rendered short).
        deployment: String,
        /// Coarse age of the activation (`None` ⇒ "unknown").
        activated: Option<String>,
        /// File count in the current manifest.
        files: usize,
        /// Total content bytes.
        bytes: u64,
        /// Number of deployments in history.
        history: usize,
        /// Deploy provenance, if recorded.
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<DeployMeta>,
    },
}

impl crate::output::Rendered for StatusOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::NoDeployment { site } => writeln!(w, "{site}: no active deployment"),
            Self::Current {
                site,
                deployment,
                activated,
                files,
                bytes,
                history,
                meta,
            } => {
                writeln!(w, "{site}")?;
                writeln!(w, "  deployment  {}", short(deployment))?;
                writeln!(
                    w,
                    "  activated   {}",
                    activated.as_deref().unwrap_or("unknown")
                )?;
                writeln!(w, "  content     {files} file(s), {}", human_bytes(*bytes))?;
                writeln!(w, "  history     {history} deployment(s)")?;
                if let Some(meta) = meta {
                    if let Some(message) = meta.message.as_deref().filter(|m| !m.is_empty()) {
                        writeln!(w, "  message     {message}")?;
                    }
                    match (&meta.branch, &meta.source) {
                        (Some(branch), Some(source)) => {
                            writeln!(
                                w,
                                "  source      {branch}@{}",
                                &source[..source.len().min(12)]
                            )?;
                        }
                        (None, Some(source)) => {
                            writeln!(w, "  source      {}", &source[..source.len().min(12)])?;
                        }
                        (Some(branch), None) => writeln!(w, "  source      {branch}")?,
                        (None, None) => {}
                    }
                    if let Some(author) = meta.author.as_deref().filter(|a| !a.is_empty()) {
                        writeln!(w, "  author      {author}")?;
                    }
                    if let Some(tag) = meta.tag.as_deref().filter(|t| !t.is_empty()) {
                        writeln!(w, "  release     {tag}")?;
                    }
                    if !meta.tags.is_empty() {
                        let kv = meta
                            .tags
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        writeln!(w, "  tags        {kv}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// `boatramp prune`: the garbage-collection outcome.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PruneOutput {
    /// Nothing was reclaimable.
    NothingToPrune,
    /// `--dry-run`: the reclaimable report (printed before this verdict).
    DryRun { report: GcReport },
    /// The operator declined at the confirmation prompt.
    Aborted { report: GcReport },
    /// Deletion was committed; `report` is what was removed.
    Pruned { report: GcReport },
}

impl crate::output::Rendered for PruneOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::NothingToPrune => writeln!(w, "nothing to prune"),
            Self::DryRun { .. } => writeln!(w, "run `boatramp prune` to delete"),
            Self::Aborted { .. } => writeln!(w, "aborted"),
            Self::Pruned { report } => write_gc_report(report, "removed", w),
        }
    }
}

/// `boatramp scrub`: every blob verified intact. A scrub that finds corruption
/// prints the per-blob findings and returns [`Error::ScrubFailed`] instead.
#[derive(Debug, serde::Serialize)]
pub struct ScrubOutput {
    /// Blobs checked (all intact).
    checked: usize,
}

impl crate::output::Rendered for ScrubOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(w, "{} blob(s) verified, all intact", self.checked)
    }
}

/// `boatramp cert-status`: cluster-managed certificates.
#[derive(Debug, serde::Serialize)]
pub struct CertStatusOutput {
    certs: Vec<CertStatus>,
}

impl crate::output::Rendered for CertStatusOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.certs.is_empty() {
            return writeln!(w, "no cluster-managed certificates");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for cert in &self.certs {
            let remaining = cert.not_after_unix.saturating_sub(now);
            let days = remaining / 86_400;
            let state = if cert.not_after_unix <= now {
                "EXPIRED".to_string()
            } else {
                format!("{days}d left")
            };
            writeln!(w, "{}  ({state})", cert.domain)?;
        }
        Ok(())
    }
}

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
pub async fn list(args: DeploymentsArgs, config: &ProjectConfig) -> Result<DeploymentsOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let list = cp.fetch_deployments(&site).await?;

    let total = list.deployments.len();
    let current = list.current;
    let deployments = list.deployments.into_iter().take(args.limit).collect();
    Ok(DeploymentsOutput {
        site,
        current,
        total,
        deployments,
    })
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
pub async fn rollback(args: RollbackArgs, config: &ProjectConfig) -> Result<RollbackOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let list = cp.fetch_deployments(&site).await?;

    let target = match &args.to {
        Some(wanted) => {
            resolve_id(&list, wanted).ok_or_else(|| Error::NoDeploymentMatching(wanted.clone()))?
        }
        None => previous(&list).ok_or(Error::NoPreviousDeployment)?,
    };

    cp.activate(&site, &target).await?;
    Ok(RollbackOutput { site, target })
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
pub async fn status(args: StatusArgs, config: &ProjectConfig) -> Result<StatusOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let list = cp.fetch_deployments(&site).await?;

    let Some(current) = list.current.clone() else {
        return Ok(StatusOutput::NoDeployment { site });
    };

    let manifest = cp.fetch_manifest(&site, &current).await?;
    let files = manifest.files.len();
    let bytes: u64 = manifest.files.values().map(|entry| entry.size).sum();
    let current_entry = list.deployments.iter().find(|entry| entry.id == current);
    let activated = current_entry.map(|entry| ago(entry.at));
    let meta = current_entry.and_then(|entry| entry.meta.clone());
    let history = list.deployments.len();

    Ok(StatusOutput::Current {
        site,
        deployment: current,
        activated,
        files,
        bytes,
        history,
        meta,
    })
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
pub async fn prune(args: PruneArgs, config: &ProjectConfig) -> Result<PruneOutput> {
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
        return Ok(PruneOutput::NothingToPrune);
    }

    // The reclaimable preview is shown live — it is the context the operator reads
    // before answering the confirmation prompt (and the body of a `--dry-run`); the
    // terminal verdict is the typed result rendered by `output::emit`.
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        write_gc_report(&report, "reclaimable", &mut out)?;
        out.flush()?;
    }

    if args.dry_run {
        return Ok(PruneOutput::DryRun { report });
    }

    if !args.yes {
        let prompt = format!(
            "delete {} manifest(s) and {} blob(s) ({})? [y/N] ",
            report.manifests_removed,
            report.blobs_removed,
            human_bytes(report.bytes_reclaimed),
        );
        if !confirm(&prompt)? {
            return Ok(PruneOutput::Aborted { report });
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
    Ok(PruneOutput::Pruned { report: deleted })
}

/// Write a prune/GC report: an outcome line plus the totals.
fn write_gc_report(
    report: &GcReport,
    verb: &str,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    writeln!(
        w,
        "{} orphan manifest(s), {} blob(s) {verb} ({})",
        report.manifests_removed,
        report.blobs_removed,
        human_bytes(report.bytes_reclaimed),
    )?;
    writeln!(
        w,
        "  ({} blob(s), {} manifest(s) total)",
        report.blobs_total, report.manifests_total
    )?;
    Ok(())
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
pub async fn scrub(args: ScrubArgs, config: &ProjectConfig) -> Result<ScrubOutput> {
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
        return Ok(ScrubOutput {
            checked: report.checked,
        });
    }
    // Corruption/unreadable blobs found: show each finding, then fail non-zero (the
    // scrub's exit code is the signal for a cron/healthcheck). The per-blob detail is
    // on the error path, so it is written here rather than through `output::emit`.
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        for m in &report.mismatched {
            writeln!(
                out,
                "CORRUPT    {} (expected {}, got {})",
                m.key, m.expected, m.actual
            )?;
        }
        for e in &report.errors {
            writeln!(out, "UNREADABLE {} ({})", e.key, e.error)?;
        }
        out.flush()?;
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
pub async fn cert_status(args: CertStatusArgs, config: &ProjectConfig) -> Result<CertStatusOutput> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let certs: Vec<CertStatus> = http
        .get(format!("{server}/api/certs"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(CertStatusOutput { certs })
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
