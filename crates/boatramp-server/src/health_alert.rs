//! The node/system-health **alerting loop** (node-health-alerting Stage 2): a
//! daemon-side, LEADER-GATED periodic evaluator that emits an alert when a health
//! signal crosses a threshold and a RESOLVE when it clears, delivering over an operator
//! webhook and/or email. Built ON the Stage-1 observability (the `/data` statvfs read,
//! the managed-SQL replica health that the reconcile plane persists) + the Stage-2
//! orphaned-replica reaper.
//!
//! Placement: this lives in `boatramp-server` so it can reach the shared SSRF guard
//! ([`crate::ssrf`]) + the mail path (`boatramp-handlers`), and is spawned from
//! `boatramp_node::assemble` exactly like [`spawn_compute_reconcile`](crate::spawn_compute_reconcile)
//! — a detached, leader-gated `tokio::time::interval` loop whose `JoinHandle` is kept
//! alive in `RunningNode::reconcile`.
//!
//! Three signals (each a gap behind the motivating incident):
//! 1. `/data` filesystem fullness — `used_pct` vs operator warn/critical thresholds;
//! 2. managed-SQL / desired-compute replica health — a replica that SHOULD be serving is
//!    `HEALTHY=NO` past a grace window;
//! 3. orphaned compute replicas — no desired workload + no live container (the reaper's
//!    non-destructive `scan`).
//!
//! Secrets discipline: the webhook URL is resolved from the SEALED secret store at send
//! time (never plaintext config), held only in a redacting newtype, and its egress goes
//! through the SSRF floor; the SMTP password is sealed in the email profile. No secret is
//! ever logged.

use std::collections::HashMap;
use std::sync::Arc;

use boatramp_core::compute::{ComputeReaper, ReapOptions, ReapTarget, ReplicaPhase};
use boatramp_core::deploy::DeployStore;
use boatramp_core::email_config::EmailProfileStore;
use boatramp_core::health_alert::{
    AlertEvent, AlertEventKind, AlertSeverity, AlertsConfig, WebhookConfig, signal,
};
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;

use crate::CronLeaderGate;

// ---------------------------------------------------------------------------
// Mutation-verified gate seams (node-health-alerting Stage 2). Each helper is
// compiled IN only under `cfg(test)` (this crate's own gate tests) or the matching
// `health-alert-*-gate-mutation` feature (a downstream gate lane), and is ARMED only
// when `BOATRAMP_HEALTHALERT_MUTATION` names it — so `--all-features` with the env unset
// behaves normally (the gate stays green), and the gate test sets the env to prove the
// check is load-bearing (RED). In a shipped build the env read is compiled OUT entirely.
// This mirrors `boatramp_core::crownjewel::cas_mutation_active`.
// ---------------------------------------------------------------------------

/// Whether the SSRF-floor BYPASS mutation is armed (the webhook then accepts any target,
/// so the webhook-SSRF gate goes RED). Always `false` in a shipped build.
fn ssrf_bypass_active() -> bool {
    #[cfg(any(test, feature = "health-alert-ssrf-gate-mutation"))]
    {
        std::env::var("BOATRAMP_HEALTHALERT_MUTATION").as_deref() == Ok("ssrf_bypass")
    }
    #[cfg(not(any(test, feature = "health-alert-ssrf-gate-mutation")))]
    {
        false
    }
}

/// Whether the de-dup DISABLE mutation is armed (the reconciler re-alerts every tick, so
/// the de-dup gate goes RED). Always `false` in a shipped build.
fn dedupe_off_active() -> bool {
    #[cfg(any(test, feature = "health-alert-dedupe-mutation"))]
    {
        std::env::var("BOATRAMP_HEALTHALERT_MUTATION").as_deref() == Ok("dedupe_off")
    }
    #[cfg(not(any(test, feature = "health-alert-dedupe-mutation")))]
    {
        false
    }
}

/// Whether the sealed-URL Debug-LEAK mutation is armed (the newtype then prints its URL,
/// so the redaction gate goes RED). Always `false` in a shipped build.
fn sealed_leak_active() -> bool {
    #[cfg(any(test, feature = "health-alert-sealed-gate-mutation"))]
    {
        std::env::var("BOATRAMP_HEALTHALERT_MUTATION").as_deref() == Ok("sealed_leak")
    }
    #[cfg(not(any(test, feature = "health-alert-sealed-gate-mutation")))]
    {
        false
    }
}

/// A resolved webhook URL, held ONLY in this redacting newtype so a stray `{:?}` / log
/// can never leak it. Mirrors the `SealedS3Credential` custom-`Debug` pattern (never
/// `#[derive(Debug)]`): the plaintext is a private field behind a method.
#[derive(Clone)]
pub(crate) struct SealedWebhookUrl(String);

impl SealedWebhookUrl {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SealedWebhookUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The GATE SEAM: when the sealed-leak mutation is armed the newtype prints its
        // URL, so the redaction gate goes RED — proving the redaction is load-bearing.
        // Dormant everywhere else (and compiled out of a shipped build).
        if sealed_leak_active() {
            return write!(f, "SealedWebhookUrl({})", self.0);
        }
        f.debug_struct("SealedWebhookUrl")
            .field("url", &"<redacted>")
            .finish()
    }
}

/// One currently-firing condition, before de-dup. Pure data.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FiringCondition {
    pub signal: &'static str,
    pub subject: String,
    pub severity: AlertSeverity,
    pub current_value: f64,
    pub threshold: f64,
    pub message: String,
}

type AlertKey = (String, String);

/// The de-dup + resolve state the loop carries across ticks. In-memory + leader-local:
/// on a leadership change the new leader re-evaluates and may re-alert an already-open
/// condition once — a deliberate, documented trade-off (a duplicate alert is far cheaper
/// than a missed one, and the in-memory map avoids a shared-state dependency).
#[derive(Default)]
pub(crate) struct AlertState {
    /// Open conditions keyed by `(signal, subject)` → the severity + threshold last
    /// alerted at (threshold echoed on the resolve event).
    active: HashMap<AlertKey, (AlertSeverity, f64)>,
    /// When each currently-unhealthy desired replica was FIRST observed unhealthy, so
    /// the managed-SQL grace window is a real "unhealthy FOR n seconds" and not merely
    /// replica age. Cleared when the replica recovers / disappears.
    unhealthy_since: HashMap<AlertKey, u64>,
}

impl AlertState {
    /// Compute the managed-SQL / desired-compute replica-health firing set, maintaining
    /// the unhealthy-since map. A replica fires iff it has a DESIRED workload (so it is
    /// supposed to be serving), is `phase == Running`, is `!healthy`, and has been
    /// unhealthy for at least `grace_secs`. Recovered / vanished replicas are pruned from
    /// the map so a later relapse starts a fresh grace.
    pub(crate) fn managed_sql_firing(
        &mut self,
        replicas: &[ReplicaHealth],
        desired: &std::collections::BTreeSet<(String, String)>,
        grace_secs: u64,
        now: u64,
    ) -> Vec<FiringCondition> {
        let mut firing = Vec::new();
        // The set of currently-unhealthy desired-replica keys this tick, to prune the rest.
        let mut seen_unhealthy = std::collections::BTreeSet::new();
        for r in replicas {
            let is_desired = desired.contains(&(r.project.clone(), r.workload.clone()));
            let unhealthy = r.phase_running && !r.healthy;
            if !(is_desired && unhealthy) {
                continue;
            }
            let key = (
                signal::MANAGED_SQL_REPLICA.to_string(),
                format!("{}/{}/{}", r.project, r.workload, r.replica),
            );
            seen_unhealthy.insert(key.clone());
            let since = *self.unhealthy_since.entry(key.clone()).or_insert(now);
            let unhealthy_for = now.saturating_sub(since);
            if unhealthy_for >= grace_secs {
                firing.push(FiringCondition {
                    signal: signal::MANAGED_SQL_REPLICA,
                    subject: key.1.clone(),
                    severity: AlertSeverity::Critical,
                    current_value: unhealthy_for as f64,
                    threshold: grace_secs as f64,
                    message: format!(
                        "replica {}/{}/{} HEALTHY=NO for {unhealthy_for}s",
                        r.project, r.workload, r.replica
                    ),
                });
            }
        }
        // Prune replicas that recovered / vanished so their grace restarts next failure.
        self.unhealthy_since
            .retain(|k, _| seen_unhealthy.contains(k));
        firing
    }

    /// Reconcile the current firing set against the open-condition set, returning the
    /// events to deliver: an **alert** for each newly-firing or escalated condition, a
    /// **resolve** for each open condition no longer firing. De-dup: a condition already
    /// open at the SAME severity emits NOTHING (the "don't re-alert every tick" rule).
    pub(crate) fn reconcile(
        &mut self,
        firing: &[FiringCondition],
        now: u64,
        node: &str,
    ) -> Vec<AlertEvent> {
        let mut events = Vec::new();
        let firing_keys: std::collections::BTreeSet<AlertKey> = firing
            .iter()
            .map(|f| (f.signal.to_string(), f.subject.clone()))
            .collect();

        for f in firing {
            let key = (f.signal.to_string(), f.subject.clone());
            let prev = self.active.get(&key).map(|(s, _)| *s);
            // The GATE SEAM: when the de-dup mutation is armed every tick re-alerts, so
            // the de-dup gate goes RED — proving the de-dup check is load-bearing. Dormant
            // everywhere else.
            let changed = dedupe_off_active() || prev != Some(f.severity);
            if changed {
                events.push(AlertEvent {
                    signal: f.signal.to_string(),
                    event: AlertEventKind::Alert,
                    severity: f.severity,
                    subject: Some(f.subject.clone()),
                    current_value: f.current_value,
                    threshold: f.threshold,
                    node: node.to_string(),
                    timestamp: now,
                    message: Some(f.message.clone()),
                });
            }
            self.active.insert(key, (f.severity, f.threshold));
        }

        let cleared: Vec<AlertKey> = self
            .active
            .keys()
            .filter(|k| !firing_keys.contains(*k))
            .cloned()
            .collect();
        for key in cleared {
            let (severity, threshold) = self.active.remove(&key).expect("key just listed");
            events.push(AlertEvent {
                signal: key.0.clone(),
                event: AlertEventKind::Resolve,
                severity,
                subject: Some(key.1.clone()),
                current_value: 0.0,
                threshold,
                node: node.to_string(),
                timestamp: now,
                message: Some("condition cleared".to_string()),
            });
        }
        events
    }

    /// Roll back the open-condition entry for an ALERT whose delivery wholly failed, so
    /// it re-fires (and re-delivers) on the next tick rather than being silently swallowed
    /// — reliability without per-tick spam once a delivery succeeds.
    pub(crate) fn mark_undelivered(&mut self, signal: &str, subject: &str) {
        self.active
            .remove(&(signal.to_string(), subject.to_string()));
    }
}

/// A minimal, test-friendly projection of one replica's health the managed-SQL signal
/// needs (decoupled from the full `ObservedInstance`).
#[derive(Debug, Clone)]
pub(crate) struct ReplicaHealth {
    pub project: String,
    pub workload: String,
    pub replica: u32,
    pub phase_running: bool,
    pub healthy: bool,
}

/// The handles the alerting loop needs. Assembled once at node startup.
pub struct HealthAlertDeps {
    /// The control-plane store (managed-SQL health + desired-workload reads).
    pub deploy: DeployStore,
    /// The orphan reaper (non-destructive `scan` for the orphan signal + opt-in reap).
    pub reaper: Arc<dyn ComputeReaper>,
    /// The sealed secret store the webhook URL is resolved from. `None` ⇒ no `[secrets]`
    /// envelope → the webhook channel fails closed.
    pub secret_store: Option<Arc<SecretStore>>,
    /// The email-profile store (SMTP password sealed in the profile). `None` ⇒ the email
    /// channel is unavailable.
    pub email_profile_store: Option<Arc<EmailProfileStore>>,
    /// The node's data directory, for the `/data` statvfs read (works on a lean node —
    /// not handler-runtime gated).
    pub data_dir: std::path::PathBuf,
    /// A stable label identifying this node in alert events (e.g. `node-<id>`).
    pub node_label: String,
    /// Whether the SMTP relay may be a private address (the mail path's own SSRF relax).
    pub allow_private_relay: bool,
}

/// Read `/data` fullness (`used_pct = (total − free)/total`) via POSIX `libc::statvfs`.
/// `None` off-unix or on ANY error — never panics. Non-handler-gated so a lean node's
/// alerting loop still sees the disk signal (the Stage-2 `data_dir`-via-options intent).
#[cfg(unix)]
pub(crate) fn data_used_pct(dir: &std::path::Path) -> Option<f64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: a zeroed `statvfs` is a valid initial state; `path` is a valid NUL-terminated
    // C string; `statvfs` only reads `path` and writes `stat`.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize as u64;
    let total = frsize.checked_mul(stat.f_blocks as u64)?;
    let free = frsize.checked_mul(stat.f_bfree as u64)?;
    if total == 0 {
        return Some(0.0);
    }
    let used = total.saturating_sub(free);
    Some(used as f64 / total as f64 * 100.0)
}

#[cfg(not(unix))]
pub(crate) fn data_used_pct(_dir: &std::path::Path) -> Option<f64> {
    None
}

/// The disk firing condition, if `/data` is over a threshold. Critical wins over warn.
pub(crate) fn disk_firing(cfg: &AlertsConfig, used_pct: f64) -> Option<FiringCondition> {
    if !cfg.disk.enabled() {
        return None;
    }
    let (severity, threshold) = if used_pct >= cfg.disk.critical_pct() {
        (AlertSeverity::Critical, cfg.disk.critical_pct())
    } else if used_pct >= cfg.disk.warn_pct() {
        (AlertSeverity::Warning, cfg.disk.warn_pct())
    } else {
        return None;
    };
    Some(FiringCondition {
        signal: signal::DISK,
        subject: "/data".to_string(),
        severity,
        current_value: (used_pct * 100.0).round() / 100.0,
        threshold,
        message: format!("/data is {:.2}% full", used_pct),
    })
}

/// Resolve the sealed webhook URL (`boatramp:<name>` ref) to plaintext, held only in the
/// redacting newtype. Fail-closed: no secret store (no `[secrets]` envelope), a missing
/// secret, or a non-UTF-8 value all return `Err` — never a plaintext fallback. Mirrors
/// the S3-credential `boatramp:` arm.
async fn resolve_webhook_url(
    secret_store: Option<&SecretStore>,
    cfg: &WebhookConfig,
) -> Result<SealedWebhookUrl, String> {
    let secret_ref = cfg
        .url_secret_ref()
        .ok_or_else(|| "webhook url_secret not configured".to_string())?;
    // Only the `boatramp:<name>` sealed-store scheme is accepted here (a node/operator
    // secret under the reserved `default` project, exactly as the S3 credential is).
    let name = secret_ref.strip_prefix("boatramp:").ok_or_else(|| {
        "webhook url_secret must be a 'boatramp:<name>' sealed reference".to_string()
    })?;
    let store = secret_store.ok_or_else(|| {
        "no [secrets] envelope configured — the webhook URL cannot be unsealed".to_string()
    })?;
    match store.get(ProjectRef::DEFAULT, name).await {
        Ok(Some(bytes)) => {
            let url = String::from_utf8(bytes)
                .map_err(|_| "webhook URL secret is not valid UTF-8".to_string())?;
            if url.trim().is_empty() {
                return Err("webhook URL secret is empty".to_string());
            }
            Ok(SealedWebhookUrl(url.trim().to_string()))
        }
        Ok(None) => Err(format!(
            "webhook URL secret {name:?} not found in the sealed store"
        )),
        Err(e) => Err(format!("webhook URL secret resolve failed: {e}")),
    }
}

/// Deliver one event to the webhook: unseal the URL, run it through the SSRF floor
/// ([`crate::ssrf::resolve_pin`] — https-only, userinfo-rejected, `is_global_ip` required
/// unless the operator set `allow_private`), pin the resolved address, and POST the JSON.
/// The URL is NEVER logged (held in [`SealedWebhookUrl`]); only a redacted outcome is.
async fn deliver_webhook(
    secret_store: Option<&SecretStore>,
    cfg: &WebhookConfig,
    event: &AlertEvent,
) -> Result<(), String> {
    let url = resolve_webhook_url(secret_store, cfg).await?;

    // The GATE SEAM: when the SSRF-bypass mutation is armed the floor is dropped (every
    // target is allowed), so the webhook-SSRF gate goes RED — proving the floor is
    // load-bearing. Dormant everywhere else: the operator's `allow_private` is the only
    // relaxation in a real build.
    let allow_non_global = cfg.allow_private || ssrf_bypass_active();

    let (host, addr) = crate::ssrf::resolve_pin(url.as_str(), allow_non_global, false)
        .await
        .ok_or_else(|| {
            // No URL in the message — only the SSRF verdict.
            "webhook target refused by the SSRF floor (not https, userinfo, or a \
             non-global address without allow_private)"
                .to_string()
        })?;
    let client = crate::ssrf::pinned_client(&host, addr, true)
        .ok_or_else(|| "failed to build the pinned webhook client".to_string())?;
    let resp = client
        .post(url.as_str())
        .json(event)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("webhook POST failed: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("webhook returned HTTP {}", resp.status()))
    }
}

/// Deliver one event by email via boatramp's existing mail path. The SMTP password is
/// unsealed inside `EmailProfileStore::get`; nothing secret is logged. Only with the
/// `email` feature; otherwise a no-op that reports the channel unavailable.
#[cfg(feature = "email")]
async fn deliver_email(
    deps: &HealthAlertDeps,
    cfg: &AlertsConfig,
    event: &AlertEvent,
) -> Result<(), String> {
    use boatramp_handlers::{LettreBackend, OutboundEmail, SmtpBackend};
    let Some(store) = deps.email_profile_store.as_ref() else {
        return Err("no email-profile store configured".to_string());
    };
    let profile_name = cfg
        .email
        .profile_name()
        .ok_or_else(|| "email profile not configured".to_string())?;
    let project = cfg.email.project().to_string();
    let profile = store
        .get(ProjectRef::new(&project), profile_name)
        .await
        .map_err(|e| format!("email profile resolve failed: {e}"))?
        .ok_or_else(|| {
            format!("email profile {profile_name:?} not found in project {project:?}")
        })?;
    let body = serde_json::to_string_pretty(event).unwrap_or_else(|_| event.summary());
    let msg = OutboundEmail {
        project,
        profile: profile_name.to_string(),
        to: cfg.email.to.clone(),
        cc: Vec::new(),
        bcc: Vec::new(),
        from: profile.from.clone(),
        reply_to: None,
        subject: format!("boatramp node-health: {}", event.summary()),
        text: Some(body),
        html: None,
        durable: false,
    };
    let backend = LettreBackend::new(deps.allow_private_relay);
    backend
        .send(&profile, &msg)
        .await
        .map_err(|e| format!("email send failed: {e}"))
}

#[cfg(not(feature = "email"))]
async fn deliver_email(
    _deps: &HealthAlertDeps,
    _cfg: &AlertsConfig,
    _event: &AlertEvent,
) -> Result<(), String> {
    Err("email delivery not available in this build (email feature off)".to_string())
}

/// Deliver one event to every CONFIGURED channel. Returns whether at least one channel
/// accepted it (or none is configured — nothing to retry). A per-channel failure is
/// logged WITHOUT the secret/URL.
async fn deliver_event(deps: &HealthAlertDeps, cfg: &AlertsConfig, event: &AlertEvent) -> bool {
    let mut any_channel = false;
    let mut any_ok = false;
    if cfg.webhook.is_configured() {
        any_channel = true;
        match deliver_webhook(deps.secret_store.as_deref(), &cfg.webhook, event).await {
            Ok(()) => any_ok = true,
            Err(e) => {
                tracing::warn!(signal = %event.signal, error = %e, "node-health alert: webhook delivery failed");
            }
        }
    }
    if cfg.email.is_configured() {
        any_channel = true;
        match deliver_email(deps, cfg, event).await {
            Ok(()) => any_ok = true,
            Err(e) => {
                tracing::warn!(signal = %event.signal, error = %e, "node-health alert: email delivery failed");
            }
        }
    }
    // No channel configured ⇒ nothing to deliver; treat as "handled" so the loop doesn't
    // spin re-firing (the startup wiring already warned about the missing channel).
    any_ok || !any_channel
}

/// Run ONE evaluation + delivery pass (factored out of the loop so it is directly
/// testable with a fake clock). Reads the three signals, reconciles against the de-dup
/// state, delivers the resulting alert/resolve events, rolls back any ALERT whose
/// delivery wholly failed, and runs the opt-in reaper. Returns the number of events
/// emitted (for logging/tests).
async fn run_pass(
    deps: &HealthAlertDeps,
    cfg: &AlertsConfig,
    state: &mut AlertState,
    now: u64,
) -> usize {
    let mut firing: Vec<FiringCondition> = Vec::new();

    // Signal 1: /data fullness.
    if let Some(pct) = data_used_pct(&deps.data_dir)
        && let Some(f) = disk_firing(cfg, pct)
    {
        firing.push(f);
    }

    // Signals 2 + 3 both need the replica inventory. Read it once.
    let replicas = match deps.deploy.list_all_replica_states().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "node-health alert: replica state read failed");
            Vec::new()
        }
    };

    // Signal 2: managed-SQL / desired-compute replica health.
    if cfg.managed_sql.enabled() && !replicas.is_empty() {
        let desired: std::collections::BTreeSet<(String, String)> =
            match deps.deploy.list_compute_workloads_all().await {
                Ok(ws) => ws.into_iter().map(|(p, w)| (p, w.name)).collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "node-health alert: desired-workload read failed");
                    std::collections::BTreeSet::new()
                }
            };
        let projected: Vec<ReplicaHealth> = replicas
            .iter()
            .map(|o| ReplicaHealth {
                project: o.handle.project.clone(),
                workload: o.handle.workload.clone(),
                replica: o.handle.replica,
                phase_running: o.phase == ReplicaPhase::Running,
                healthy: o.healthy,
            })
            .collect();
        firing.extend(state.managed_sql_firing(
            &projected,
            &desired,
            cfg.managed_sql.grace_secs(),
            now,
        ));
    }

    // Signal 3: orphaned replicas (non-destructive scan).
    if cfg.orphan.enabled() {
        match deps.reaper.scan(cfg.orphan.grace_secs()).await {
            Ok(orphans) => {
                for o in orphans {
                    firing.push(FiringCondition {
                        signal: signal::ORPHAN_REPLICA,
                        subject: format!("{}/{}/{}", o.project, o.workload, o.replica),
                        severity: AlertSeverity::Warning,
                        current_value: o.age_secs.unwrap_or_default() as f64,
                        threshold: cfg.orphan.grace_secs() as f64,
                        message: format!(
                            "orphaned replica {}/{}/{} (no desired workload, container gone)",
                            o.project, o.workload, o.replica
                        ),
                    });
                }
            }
            Err(e) => tracing::warn!(error = %e, "node-health alert: orphan scan failed"),
        }
    }

    let events = state.reconcile(&firing, now, &deps.node_label);
    let emitted = events.len();
    for event in &events {
        let delivered = deliver_event(deps, cfg, event).await;
        // An ALERT that reached no channel is rolled back so it re-fires next tick
        // (reliability); a resolve that failed is let go (a missed resolve is low-harm
        // and re-resolving a cleared condition it never alerted would be noise).
        if !delivered
            && event.event == AlertEventKind::Alert
            && let Some(subject) = event.subject.as_deref()
        {
            state.mark_undelivered(&event.signal, subject);
        }
    }

    // Opt-in reaper: only when enabled. The orphan grace already fired an ALERT above,
    // so by the time the reaper (with its longer grace) acts, an operator was paged. The
    // reaper re-derives orphan-ness fail-closed per replica; dry-run (the default) only
    // reports.
    if cfg.reaper.enabled() {
        let grace = cfg.reaper.grace_secs().max(cfg.orphan.grace_secs());
        match deps
            .reaper
            .reap(ReapOptions {
                target: ReapTarget::All,
                grace_secs: grace,
                dry_run: cfg.reaper.dry_run(),
                reclaim_volumes: cfg.reaper.reclaim_volumes,
            })
            .await
        {
            Ok(report) => {
                let n = report.admitted().count();
                if n > 0 {
                    tracing::warn!(
                        dry_run = report.dry_run,
                        count = n,
                        "node-health alert: orphan reaper pass"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "node-health alert: reaper pass failed"),
        }
    }

    emitted
}

/// Spawn the leader-gated node/system-health alerting loop. A detached
/// `tokio::time::interval` that, on the leader only, evaluates the signals and delivers
/// alert/resolve events each tick. Returns the `JoinHandle` for `RunningNode::reconcile`
/// (it runs for the process life, aborting only if an embedder drops it). The subsystem
/// is OFF unless `cfg.enabled`; the caller only spawns it when enabled.
pub fn spawn_health_alert_loop(
    deps: HealthAlertDeps,
    cfg: AlertsConfig,
    is_leader: CronLeaderGate,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cfg.interval());
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick so the first evaluation waits a full period.
        interval.tick().await;
        let mut state = AlertState::default();
        if !cfg.any_channel_configured() {
            tracing::warn!(
                "node-health alerting is enabled but NO delivery channel is configured \
                 (set [serve.alerts.webhook] and/or [serve.alerts.email])"
            );
        }
        loop {
            interval.tick().await;
            if !is_leader() {
                continue;
            }
            let now = boatramp_core::time::now_unix();
            let _ = run_pass(&deps, &cfg, &mut state, now).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::health_alert::{DiskAlertConfig, ManagedSqlAlertConfig};

    fn disk_cfg(warn: f64, crit: f64) -> AlertsConfig {
        AlertsConfig {
            enabled: true,
            disk: DiskAlertConfig {
                enabled: Some(true),
                warn_pct: Some(warn),
                critical_pct: Some(crit),
            },
            ..Default::default()
        }
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn disk_threshold_cross_then_resolve() {
        let cfg = disk_cfg(75.0, 90.0);
        let mut state = AlertState::default();

        // Below warn: nothing fires.
        let firing: Vec<_> = disk_firing(&cfg, 50.0).into_iter().collect();
        let ev = state.reconcile(&firing, 100, "node-0");
        assert!(ev.is_empty(), "below warn: no event");

        // Cross warn: one ALERT, warning severity.
        let firing: Vec<_> = disk_firing(&cfg, 80.0).into_iter().collect();
        let ev = state.reconcile(&firing, 101, "node-0");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].event, AlertEventKind::Alert);
        assert_eq!(ev[0].severity, AlertSeverity::Warning);
        assert_eq!(ev[0].signal, signal::DISK);

        // Clear below warn: one RESOLVE.
        let firing: Vec<_> = disk_firing(&cfg, 10.0).into_iter().collect();
        let ev = state.reconcile(&firing, 103, "node-0");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].event, AlertEventKind::Resolve);
        assert_eq!(ev[0].signal, signal::DISK);
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn warn_escalates_to_critical_then_de_dupes() {
        let cfg = disk_cfg(75.0, 90.0);
        let mut state = AlertState::default();

        // Warn.
        let ev = state.reconcile(
            &disk_firing(&cfg, 80.0).into_iter().collect::<Vec<_>>(),
            1,
            "n",
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].severity, AlertSeverity::Warning);

        // Escalate to critical ⇒ a NEW alert (severity changed).
        let ev = state.reconcile(
            &disk_firing(&cfg, 95.0).into_iter().collect::<Vec<_>>(),
            2,
            "n",
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].severity, AlertSeverity::Critical);

        // Still critical next tick ⇒ DE-DUP: no event.
        let ev = state.reconcile(
            &disk_firing(&cfg, 96.0).into_iter().collect::<Vec<_>>(),
            3,
            "n",
        );
        assert!(
            ev.is_empty(),
            "same-severity re-evaluation must not re-alert"
        );
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn de_dup_holds_across_many_ticks() {
        let cfg = disk_cfg(75.0, 90.0);
        let mut state = AlertState::default();
        let mut total = 0;
        for t in 0..10u64 {
            total += state
                .reconcile(
                    &disk_firing(&cfg, 80.0).into_iter().collect::<Vec<_>>(),
                    t,
                    "n",
                )
                .len();
        }
        // Exactly ONE alert across ten ticks of a sustained condition.
        assert_eq!(total, 1, "a sustained condition must alert exactly once");
    }

    #[test]
    fn managed_sql_grace_then_alert_then_resolve() {
        let mut state = AlertState::default();
        let mut desired = std::collections::BTreeSet::new();
        desired.insert(("default".to_string(), "pg".to_string()));
        let unhealthy = vec![ReplicaHealth {
            project: "default".into(),
            workload: "pg".into(),
            replica: 0,
            phase_running: true,
            healthy: false,
        }];
        let grace = 300;

        // First seen unhealthy at t=1000: within grace ⇒ no firing yet.
        let f = state.managed_sql_firing(&unhealthy, &desired, grace, 1000);
        assert!(f.is_empty(), "within grace: no firing");
        // Still unhealthy at t=1000+grace ⇒ fires.
        let f = state.managed_sql_firing(&unhealthy, &desired, grace, 1000 + grace);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signal, signal::MANAGED_SQL_REPLICA);
        assert_eq!(f[0].severity, AlertSeverity::Critical);

        // Recovered ⇒ no firing, and the unhealthy-since is pruned (a later relapse
        // starts a fresh grace).
        let healthy = vec![ReplicaHealth {
            healthy: true,
            ..unhealthy[0].clone()
        }];
        let f = state.managed_sql_firing(&healthy, &desired, grace, 1000 + grace + 10);
        assert!(f.is_empty());
        // Relapse: grace restarts (not immediately firing again).
        let f = state.managed_sql_firing(&unhealthy, &desired, grace, 1000 + grace + 20);
        assert!(f.is_empty(), "relapse restarts the grace window");
    }

    #[test]
    fn managed_sql_ignores_a_replica_with_no_desired_workload() {
        // A replica with NO desired workload is an ORPHAN, never a managed-SQL-health
        // alert (that partition is what keeps the two signals from double-counting).
        let mut state = AlertState::default();
        let desired = std::collections::BTreeSet::new(); // empty: nothing desired
        let unhealthy = vec![ReplicaHealth {
            project: "default".into(),
            workload: "pg".into(),
            replica: 0,
            phase_running: true,
            healthy: false,
        }];
        let f = state.managed_sql_firing(&unhealthy, &desired, 0, 100);
        assert!(
            f.is_empty(),
            "no desired workload ⇒ not a managed-SQL alert"
        );
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn undelivered_alert_refires_next_tick() {
        let cfg = disk_cfg(75.0, 90.0);
        let mut state = AlertState::default();
        let ev = state.reconcile(
            &disk_firing(&cfg, 80.0).into_iter().collect::<Vec<_>>(),
            1,
            "n",
        );
        assert_eq!(ev.len(), 1, "first alert");
        // Delivery failed ⇒ roll back.
        state.mark_undelivered(signal::DISK, "/data");
        // Next tick: the still-firing condition re-alerts (because it was rolled back).
        let ev = state.reconcile(
            &disk_firing(&cfg, 80.0).into_iter().collect::<Vec<_>>(),
            2,
            "n",
        );
        assert_eq!(ev.len(), 1, "a wholly-undelivered alert re-fires");
    }

    /// A reversible identity-ish test envelope (XOR) so a "sealed" blob differs from the
    /// plaintext yet round-trips — lets a webhook test seal a URL into a real `SecretStore`.
    struct XorEnvelope;
    #[async_trait::async_trait]
    impl boatramp_core::envelope::KeyEnvelope for XorEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(
            &self,
            w: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(w.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    async fn sealed_store_with(name: &str, value: &str) -> Arc<SecretStore> {
        let store = SecretStore::new(
            Arc::new(boatramp_core::kv::MemoryKv::new()),
            Arc::new(XorEnvelope),
        );
        store
            .set(ProjectRef::DEFAULT, name, value.as_bytes())
            .await
            .unwrap();
        Arc::new(store)
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn webhook_url_is_redacted_in_debug() {
        // The sealed webhook URL must never appear in Debug — the single-choke-point
        // redaction (mirrors SealedS3Credential). With the mutation dormant (env unset)
        // the URL is redacted.
        let url = SealedWebhookUrl("https://hooks.example.com/SECRET-TOKEN-123".to_string());
        let dbg = format!("{url:?}");
        assert!(
            !dbg.contains("SECRET-TOKEN-123"),
            "the webhook URL must be redacted in Debug, got {dbg:?}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn sealed_gate_mutation_proves_redaction_is_load_bearing() {
        // Arming the sealed-leak mutation makes Debug print the URL — i.e. the redaction
        // test above would FAIL — proving the redaction is the thing keeping the secret
        // out of logs. (Env-var activated; serialized so no parallel test sees it.)
        // SAFETY: test-only env toggle, immediately cleared; serialized on this key.
        unsafe { std::env::set_var("BOATRAMP_HEALTHALERT_MUTATION", "sealed_leak") };
        let url = SealedWebhookUrl("https://hooks.example.com/SECRET-TOKEN-123".to_string());
        let leaked = format!("{url:?}").contains("SECRET-TOKEN-123");
        unsafe { std::env::remove_var("BOATRAMP_HEALTHALERT_MUTATION") };
        assert!(leaked, "the armed mutation must leak the URL (gate RED)");
    }

    #[test]
    #[serial_test::serial(health_alert_mutation)]
    fn dedupe_gate_mutation_proves_dedup_is_load_bearing() {
        // With the de-dup mutation armed, a sustained condition re-alerts every tick —
        // i.e. `de_dup_holds_across_many_ticks` would FAIL — proving de-dup is real.
        // SAFETY: test-only env toggle, immediately cleared; serialized on this key.
        unsafe { std::env::set_var("BOATRAMP_HEALTHALERT_MUTATION", "dedupe_off") };
        let cfg = disk_cfg(75.0, 90.0);
        let mut state = AlertState::default();
        let mut total = 0;
        for t in 0..5u64 {
            total += state
                .reconcile(
                    &disk_firing(&cfg, 80.0).into_iter().collect::<Vec<_>>(),
                    t,
                    "n",
                )
                .len();
        }
        unsafe { std::env::remove_var("BOATRAMP_HEALTHALERT_MUTATION") };
        assert_eq!(total, 5, "armed mutation re-alerts every tick (gate RED)");
    }

    #[tokio::test]
    #[serial_test::serial(health_alert_mutation)]
    async fn webhook_egress_is_refused_for_a_private_target_by_the_ssrf_floor() {
        // The webhook URL resolves (sealed) to a PRIVATE address; with allow_private=false
        // the SSRF floor must refuse it (an alert webhook can't be pointed at an internal
        // service). IP-literal ⇒ no network needed.
        let store = sealed_store_with("wh", "https://10.0.0.1/hook").await;
        let cfg = WebhookConfig {
            url_secret: Some("boatramp:wh".into()),
            allow_private: false,
        };
        let ev = sample_event();
        let err = deliver_webhook(Some(store.as_ref()), &cfg, &ev)
            .await
            .unwrap_err();
        assert!(
            err.contains("SSRF floor"),
            "a private webhook target must be refused by the SSRF floor, got: {err}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(health_alert_mutation)]
    async fn webhook_allow_private_permits_a_private_target_past_the_floor() {
        // The explicit private-egress posture lets a private target THROUGH the floor
        // (it then fails at connect, not at the floor) — so the floor is the ONLY gate,
        // and it is operator-controlled, not bypassable by default.
        let store = sealed_store_with("wh", "https://10.0.0.1/hook").await;
        let cfg = WebhookConfig {
            url_secret: Some("boatramp:wh".into()),
            allow_private: true,
        };
        let ev = sample_event();
        let err = deliver_webhook(Some(store.as_ref()), &cfg, &ev)
            .await
            .unwrap_err();
        assert!(
            !err.contains("SSRF floor"),
            "allow_private must pass the floor (a later connect error is fine), got: {err}"
        );
    }

    fn sample_event() -> AlertEvent {
        AlertEvent {
            signal: signal::DISK.into(),
            event: AlertEventKind::Alert,
            severity: AlertSeverity::Critical,
            subject: Some("/data".into()),
            current_value: 95.0,
            threshold: 90.0,
            node: "n".into(),
            timestamp: 1,
            message: None,
        }
    }

    #[tokio::test]
    async fn webhook_refused_without_a_secret_store() {
        // No secret store (no [secrets] envelope) ⇒ the webhook URL cannot be unsealed,
        // fail-closed. Never a plaintext fallback.
        let cfg = WebhookConfig {
            url_secret: Some("boatramp:node-alert-webhook".into()),
            allow_private: false,
        };
        let err = resolve_webhook_url(None, &cfg).await.unwrap_err();
        assert!(err.contains("no [secrets] envelope"), "{err}");
    }

    #[tokio::test]
    async fn webhook_rejects_a_non_boatramp_ref() {
        // Only a sealed `boatramp:<name>` ref is accepted — a plaintext URL in config is
        // refused (secrets must be sealed).
        let cfg = WebhookConfig {
            url_secret: Some("https://evil.example.com/x".into()),
            allow_private: false,
        };
        let err = resolve_webhook_url(None, &cfg).await.unwrap_err();
        assert!(err.contains("boatramp:<name>"), "{err}");
    }

    #[test]
    fn disk_signal_respects_enabled_toggle() {
        let mut cfg = disk_cfg(75.0, 90.0);
        cfg.disk.enabled = Some(false);
        assert!(
            disk_firing(&cfg, 99.0).is_none(),
            "disabled disk signal never fires"
        );
    }

    // Keep ManagedSqlAlertConfig referenced so an unused-import lint never masks a drift.
    #[allow(dead_code)]
    fn _assert_ms_cfg(_c: ManagedSqlAlertConfig) {}
}
