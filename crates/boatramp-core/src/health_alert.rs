//! Node / system-health **alerting** configuration + the alert domain types
//! (node-health-alerting request, Stage 2).
//!
//! Stage 1 (v0.24.0) shipped the read-only observability trio (`/data` statvfs on
//! `/api/instance-stats` + `/api/node-health`, managed-SQL health reads, the effective
//! blob-backend log fix). Stage 2 is the DAEMON-SIDE, LEADER-GATED alerting facility
//! built ON that: a periodic evaluation loop that emits an alert when a health signal
//! crosses a threshold and a RESOLVE when it clears, delivering over an operator
//! webhook and/or email, plus a destructive orphaned-compute-replica reaper.
//!
//! This module is the **wasm-clean, IO-free core**: the declarative `[serve.alerts]`
//! config (parsed by figment in `boatramp-node::config`, consistent with the existing
//! config precedence) and the pure alert-event domain types the delivery channels
//! serialize. The evaluation loop, the de-dup state, the sealed-secret webhook/email
//! channels, and the SSRF floor all live in `boatramp-server` (which can reach the
//! shared SSRF guard + the mail path); the reaper primitive lives in
//! `boatramp-node`/`boatramp-container` (the compute plane). Keeping the vocabulary
//! here means the server, the node, and the CLI cannot drift on it.
//!
//! Secrets discipline: a delivery channel's secret (the webhook URL, the SMTP
//! password) is a SEALED-store *reference* here (never a plaintext value), resolved
//! server-side at send time exactly as the AWS/S3 credential is — so the plaintext
//! never lands in a config file, a manifest, a log, or an API response.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default evaluation cadence when `[serve.alerts] interval_secs` is unset.
pub const DEFAULT_ALERT_INTERVAL_SECS: u64 = 60;
/// Floor on the evaluation cadence — a sub-5s loop would hammer the managed-SQL /
/// compute status reads for no operational gain. An operator value below this is
/// clamped up (never silently disabled).
pub const MIN_ALERT_INTERVAL_SECS: u64 = 5;

/// Default `/data` **warn** threshold (percent used). The disk-full incident that
/// motivated the ask would have fired this days early.
pub const DEFAULT_DISK_WARN_PCT: f64 = 75.0;
/// Default `/data` **critical** threshold (percent used).
pub const DEFAULT_DISK_CRITICAL_PCT: f64 = 90.0;

/// Default grace before a managed-SQL / desired-compute replica that is
/// `HEALTHY=NO` is alerted — long enough to ride out a brief restart, short enough
/// that "the database is down" pages promptly.
pub const DEFAULT_MANAGED_SQL_GRACE_SECS: u64 = 300;

/// Default minimum age before an ORPHANED replica is *alerted on* (a replica with no
/// desired workload + no live container). Orphans are, by definition, long-lived
/// strays, so this is deliberately patient.
pub const DEFAULT_ORPHAN_GRACE_SECS: u64 = 86_400;

/// Default minimum age before the destructive REAPER will act on an orphan — a full
/// week. Strictly ≥ the orphan *alert* grace: an operator is paged well before
/// anything is destroyed. A wrong reap destroys a running workload, so the reaper
/// errs hard toward waiting.
pub const DEFAULT_REAPER_GRACE_SECS: u64 = 604_800;

/// Compile-time invariant: the reaper's default grace is never shorter than the orphan
/// ALERT grace, so by the time the reaper acts an operator has already been paged. A
/// future edit that inverts the two defaults fails the build here.
const _: () = assert!(DEFAULT_REAPER_GRACE_SECS >= DEFAULT_ORPHAN_GRACE_SECS);

/// The `[serve.alerts]` block — the declarative, operator-set alerting config. The
/// whole subsystem is **off by default** (`enabled: false`); thresholds, cadence,
/// delivery channels and the reaper are all operator-set, never hardcoded. All
/// sub-blocks use the `#[serde(default, deny_unknown_fields)]` all-optional shape
/// (the `KvConfig` house pattern) so a typo'd knob fails loud and no `base_seed`
/// entry is needed for an env-only override.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertsConfig {
    /// Master switch for the whole alerting subsystem. `false` (default) ⇒ the
    /// leader-gated evaluation loop is never spawned.
    pub enabled: bool,
    /// Evaluation cadence in seconds. Absent ⇒ [`DEFAULT_ALERT_INTERVAL_SECS`];
    /// clamped up to [`MIN_ALERT_INTERVAL_SECS`].
    pub interval_secs: Option<u64>,
    /// `/data` filesystem-fullness signal (the incident signal).
    pub disk: DiskAlertConfig,
    /// Managed-SQL / desired-compute replica-health signal.
    pub managed_sql: ManagedSqlAlertConfig,
    /// Orphaned-compute-replica signal.
    pub orphan: OrphanAlertConfig,
    /// The DESTRUCTIVE orphan-replica reaper (opt-in; dry-run by default).
    pub reaper: ReaperConfig,
    /// Outbound-webhook delivery (the URL is a sealed-secret reference).
    pub webhook: WebhookConfig,
    /// Email delivery via boatramp's existing mail path (the SMTP password is sealed
    /// in the referenced email profile).
    pub email: EmailAlertConfig,
}

impl AlertsConfig {
    /// The resolved evaluation cadence (default applied, floored).
    #[must_use]
    pub fn interval(&self) -> Duration {
        let secs = self
            .interval_secs
            .unwrap_or(DEFAULT_ALERT_INTERVAL_SECS)
            .max(MIN_ALERT_INTERVAL_SECS);
        Duration::from_secs(secs)
    }

    /// Whether at least one delivery channel is configured. With none configured the
    /// loop still *evaluates* (so a misconfiguration is visible in the logs/metrics)
    /// but there is nowhere to deliver — the startup wiring warns.
    #[must_use]
    pub fn any_channel_configured(&self) -> bool {
        self.webhook.is_configured() || self.email.is_configured()
    }
}

/// `/data` fullness thresholds. `used_pct = (total − free)/total` (how full the disk
/// is — not df's reserved-block Use%), the same figure Stage 1 exposes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiskAlertConfig {
    /// Signal on/off. Absent ⇒ on (the disk signal is the whole point of the ask).
    pub enabled: Option<bool>,
    /// Warn at/above this percent-used. Absent ⇒ [`DEFAULT_DISK_WARN_PCT`].
    pub warn_pct: Option<f64>,
    /// Critical at/above this percent-used. Absent ⇒ [`DEFAULT_DISK_CRITICAL_PCT`].
    pub critical_pct: Option<f64>,
}

impl DiskAlertConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
    #[must_use]
    pub fn warn_pct(&self) -> f64 {
        self.warn_pct.unwrap_or(DEFAULT_DISK_WARN_PCT)
    }
    #[must_use]
    pub fn critical_pct(&self) -> f64 {
        self.critical_pct.unwrap_or(DEFAULT_DISK_CRITICAL_PCT)
    }
}

/// Managed-SQL / desired-compute replica health. Alerts when a replica that HAS a
/// desired workload (so it is supposed to be serving) is `phase=running` + `HEALTHY=NO`
/// for longer than the grace window — the "the database is down" page the incident
/// never got. (A replica with NO desired workload is an orphan, handled by the orphan
/// signal, never here.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagedSqlAlertConfig {
    /// Signal on/off. Absent ⇒ on.
    pub enabled: Option<bool>,
    /// Grace in seconds a replica may be unhealthy before alerting. Absent ⇒
    /// [`DEFAULT_MANAGED_SQL_GRACE_SECS`].
    pub grace_secs: Option<u64>,
}

impl ManagedSqlAlertConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
    #[must_use]
    pub fn grace_secs(&self) -> u64 {
        self.grace_secs.unwrap_or(DEFAULT_MANAGED_SQL_GRACE_SECS)
    }
}

/// Orphaned-compute-replica signal: a replica with NO desired workload AND no live
/// container, past the grace window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OrphanAlertConfig {
    /// Signal on/off. Absent ⇒ on.
    pub enabled: Option<bool>,
    /// Minimum orphan age (seconds) before alerting. Absent ⇒
    /// [`DEFAULT_ORPHAN_GRACE_SECS`].
    pub grace_secs: Option<u64>,
}

impl OrphanAlertConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
    #[must_use]
    pub fn grace_secs(&self) -> u64 {
        self.grace_secs.unwrap_or(DEFAULT_ORPHAN_GRACE_SECS)
    }
}

/// The DESTRUCTIVE orphan-replica reaper. Destroying a replica record (and optionally
/// freeing its `/data` staging) is irreversible, so the reaper is conservative by
/// construction:
/// - **opt-in** (`enabled: false` by default — the loop never reaps unless turned on);
/// - **dry-run by default** (`dry_run` absent ⇒ `true`: it logs/alerts what it WOULD
///   reap but changes nothing, until the operator explicitly sets `dry_run: false`);
/// - **grace-gated** ([`grace_secs`](Self::grace_secs) ≥ the orphan alert grace);
/// - **PGDATA-preserving** (`reclaim_volumes: false` by default — it frees the replica
///   record + tears down the dead container, but does NOT delete the volume staging
///   unless the operator opts in).
///
/// The reaper NEVER reaps a replica that has a desired workload or a live container
/// (re-checked at the moment of the reap, fail-closed) — only a genuinely orphaned one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReaperConfig {
    /// Master switch for the reaper. `false` (default) ⇒ orphans are still ALERTED on
    /// (the orphan signal) but never reaped.
    pub enabled: bool,
    /// When `true` (the default — absent ⇒ `true`) the reaper only REPORTS what it
    /// would reap (and alerts) without destroying anything. Set `false` to actually
    /// reap.
    pub dry_run: Option<bool>,
    /// Minimum orphan age (seconds) the reaper requires before acting. Absent ⇒
    /// [`DEFAULT_REAPER_GRACE_SECS`]. Effectively clamped up to the orphan ALERT grace
    /// by the loop so a reap is always preceded by a page.
    pub grace_secs: Option<u64>,
    /// Also delete the orphan's persistent VOLUME staging (e.g. a stranded managed-PG
    /// PGDATA) to reclaim `/data`. `false` (default) ⇒ the record + container are
    /// reaped but the volume is preserved (the report notes what WOULD be freed).
    pub reclaim_volumes: bool,
}

impl ReaperConfig {
    /// Whether the reaper actually acts (its master switch). Dry-run is a separate axis.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// Dry-run mode — **defaults to `true`** (report-only) when unset. The reaper only
    /// mutates when explicitly set `false`.
    #[must_use]
    pub fn dry_run(&self) -> bool {
        self.dry_run.unwrap_or(true)
    }
    #[must_use]
    pub fn grace_secs(&self) -> u64 {
        self.grace_secs.unwrap_or(DEFAULT_REAPER_GRACE_SECS)
    }
}

/// Outbound-webhook delivery. The URL is a **sealed-secret reference** — ONLY the
/// `boatramp:<name>` scheme (a node/operator secret under the reserved `default` project),
/// never a plaintext URL and never a host-env (`env:`/bare) ref, resolved server-side at
/// send time exactly as the S3 credential is. The egress goes through the shared SSRF guard
/// and the `is_global_ip` floor; reaching a PRIVATE address requires the explicit
/// `allow_private` posture (so an alert webhook can't be turned into an SSRF oracle against
/// internal services).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookConfig {
    /// A sealed-secret reference resolving to the operator webhook URL. Absent/empty ⇒
    /// the webhook channel is off.
    pub url_secret: Option<String>,
    /// Permit the webhook to resolve to a PRIVATE / non-globally-routable address
    /// (relax the SSRF floor). `false` (default) ⇒ a private target is refused
    /// fail-closed.
    pub allow_private: bool,
}

impl WebhookConfig {
    /// Whether the webhook channel is configured (a non-empty secret reference).
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.url_secret
            .as_deref()
            .map(str::trim)
            .is_some_and(|r| !r.is_empty())
    }
    /// The trimmed secret reference, if configured.
    #[must_use]
    pub fn url_secret_ref(&self) -> Option<&str> {
        self.url_secret
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
    }
}

/// Email delivery via boatramp's existing mail path. Email profiles are per-project
/// (`project/<proj>/email/<name>`) with the SMTP password envelope-sealed in the
/// profile record — so the alert email config just names the project + profile +
/// recipients; the password is never in this config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmailAlertConfig {
    /// The project owning the email profile. Absent ⇒ the reserved `default` project
    /// (where node/operator resources live, mirroring the S3 credential scope).
    pub project: Option<String>,
    /// The email-profile name to send through. Absent/empty ⇒ the email channel is off.
    pub profile: Option<String>,
    /// Recipient addresses. Empty ⇒ the email channel is off.
    #[serde(default)]
    pub to: Vec<String>,
}

impl EmailAlertConfig {
    /// Whether the email channel is configured (a profile name + at least one recipient).
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.profile_name().is_some() && !self.to.is_empty()
    }
    /// The project scope for the email profile (defaults to `default`).
    #[must_use]
    pub fn project(&self) -> &str {
        self.project
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .unwrap_or(crate::project::DEFAULT_PROJECT)
    }
    /// The trimmed profile name, if configured.
    #[must_use]
    pub fn profile_name(&self) -> Option<&str> {
        self.profile
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Alert domain types — the vocabulary the delivery channels serialize.
// ---------------------------------------------------------------------------

/// Severity of a crossed threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// A warn-level threshold crossed.
    Warning,
    /// A critical-level threshold crossed.
    Critical,
}

impl AlertSeverity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Whether an event opens (alert) or closes (resolve) a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertEventKind {
    /// A threshold was crossed (the condition opened / escalated).
    Alert,
    /// A previously-alerted condition cleared.
    Resolve,
}

impl AlertEventKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Resolve => "resolve",
        }
    }
}

/// Which health signal an event is about. Stringly on the wire (`signal` field) so an
/// operator's webhook consumer is forward-compatible with new signals.
pub mod signal {
    /// `/data` filesystem fullness.
    pub const DISK: &str = "disk";
    /// A managed-SQL / desired-compute replica is unhealthy past grace.
    pub const MANAGED_SQL_REPLICA: &str = "managed_sql_replica";
    /// An orphaned compute replica (no desired workload + no live container).
    pub const ORPHAN_REPLICA: &str = "orphan_replica";
}

/// One alert / resolve event, serialized to the webhook body and the email. The shape
/// the design specified: `{signal, severity, current_value, threshold, node, timestamp}`
/// plus the `event` (alert|resolve) discriminator and an optional `subject` (e.g. the
/// `project/workload/replica` a per-replica signal is about) + human `message`.
///
/// It carries **no secret** — never the webhook URL, never a credential — so it is safe
/// to serialize and (at most) log at debug.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    /// The signal (`disk` / `managed_sql_replica` / `orphan_replica`).
    pub signal: String,
    /// `alert` or `resolve`.
    pub event: AlertEventKind,
    /// Severity of the crossed threshold.
    pub severity: AlertSeverity,
    /// The specific subject within the signal, when per-instance (e.g.
    /// `"default/pg/0"` for a replica, `"/data"` for the disk). Absent for a
    /// node-scalar signal with a single subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The observed value that triggered the event (percent-used for disk, seconds
    /// unhealthy/orphaned for a replica).
    pub current_value: f64,
    /// The threshold the value crossed.
    pub threshold: f64,
    /// The node this event came from (the node id / hostname), so a fleet operator
    /// can attribute it.
    pub node: String,
    /// Unix seconds when the event was emitted.
    pub timestamp: u64,
    /// A short human-readable description, safe to surface (carries no secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl AlertEvent {
    /// A stable one-line summary for an email subject / log line. Carries no secret.
    #[must_use]
    pub fn summary(&self) -> String {
        let subject = self.subject.as_deref().unwrap_or("");
        match self.event {
            AlertEventKind::Alert => format!(
                "[{}] {} {}{}",
                self.severity.as_str(),
                self.signal,
                if subject.is_empty() {
                    String::new()
                } else {
                    format!("{subject} ")
                },
                self.message.as_deref().unwrap_or("threshold crossed"),
            ),
            AlertEventKind::Resolve => format!(
                "[resolved] {} {}{}",
                self.signal,
                if subject.is_empty() {
                    String::new()
                } else {
                    format!("{subject} ")
                },
                self.message.as_deref().unwrap_or("cleared"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let c = AlertsConfig::default();
        assert!(!c.enabled, "the whole subsystem is off by default");
        assert!(!c.reaper.enabled(), "the reaper is opt-in");
        assert!(
            c.reaper.dry_run(),
            "the reaper defaults to dry-run (report-only)"
        );
        assert!(
            !c.reaper.reclaim_volumes,
            "volume reclamation (PGDATA delete) is off by default"
        );
        assert!(
            !c.any_channel_configured(),
            "no delivery channel by default"
        );
        // Thresholds + graces apply their documented defaults.
        assert_eq!(c.disk.warn_pct(), DEFAULT_DISK_WARN_PCT);
        assert_eq!(c.disk.critical_pct(), DEFAULT_DISK_CRITICAL_PCT);
        assert_eq!(c.managed_sql.grace_secs(), DEFAULT_MANAGED_SQL_GRACE_SECS);
        assert_eq!(c.orphan.grace_secs(), DEFAULT_ORPHAN_GRACE_SECS);
        assert_eq!(c.reaper.grace_secs(), DEFAULT_REAPER_GRACE_SECS);
        assert_eq!(
            c.interval(),
            Duration::from_secs(DEFAULT_ALERT_INTERVAL_SECS)
        );
    }

    #[test]
    fn interval_is_floored() {
        let c = AlertsConfig {
            interval_secs: Some(1),
            ..Default::default()
        };
        assert_eq!(c.interval(), Duration::from_secs(MIN_ALERT_INTERVAL_SECS));
    }

    #[test]
    fn channels_report_configured_only_when_complete() {
        let mut c = AlertsConfig::default();
        assert!(!c.webhook.is_configured());
        c.webhook.url_secret = Some("  ".into());
        assert!(
            !c.webhook.is_configured(),
            "whitespace ref is not configured"
        );
        c.webhook.url_secret = Some("boatramp:node-alert-webhook".into());
        assert!(c.webhook.is_configured());

        assert!(!c.email.is_configured());
        c.email.profile = Some("alerts".into());
        assert!(
            !c.email.is_configured(),
            "profile without a recipient is off"
        );
        c.email.to = vec!["ops@example.com".into()];
        assert!(c.email.is_configured());
        assert_eq!(c.email.project(), crate::project::DEFAULT_PROJECT);
    }

    #[test]
    fn event_serializes_the_specified_shape_without_secrets() {
        let ev = AlertEvent {
            signal: signal::DISK.into(),
            event: AlertEventKind::Alert,
            severity: AlertSeverity::Critical,
            subject: Some("/data".into()),
            current_value: 92.5,
            threshold: 90.0,
            node: "node-0".into(),
            timestamp: 1_700_000_000,
            message: Some("/data is 92.5% full".into()),
        };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["signal"], "disk");
        assert_eq!(v["event"], "alert");
        assert_eq!(v["severity"], "critical");
        assert_eq!(v["current_value"], 92.5);
        assert_eq!(v["threshold"], 90.0);
        assert_eq!(v["node"], "node-0");
        assert_eq!(v["timestamp"], 1_700_000_000u64);
    }

    #[test]
    fn deny_unknown_fields_rejects_a_typod_knob() {
        // A misspelled nested knob must fail loud, not be silently ignored.
        let typo = serde_json::json!({ "enabled": true, "disk": { "warn_pctt": 50.0 } });
        assert!(
            serde_json::from_value::<AlertsConfig>(typo).is_err(),
            "a typo'd nested knob (warn_pctt) must be rejected by deny_unknown_fields"
        );
        // The correct spelling parses and applies.
        let ok = serde_json::json!({ "enabled": true, "disk": { "warn_pct": 50.0 } });
        let c: AlertsConfig = serde_json::from_value(ok).unwrap();
        assert_eq!(c.disk.warn_pct(), 50.0);
    }
}
