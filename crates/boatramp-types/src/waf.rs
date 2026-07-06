//! A small, fully-configurable web-application firewall for the visitor
//! access-control stage. Two independent features, each with its
//! own enable flag and tunables so an operator turns on exactly what they want:
//!
//! * **User-agent rules** — a regex deny-list (any match blocks) and an optional
//!   regex allow-list (when non-empty, the UA must match one or it's blocked).
//! * **Anomaly scoring** — sums points for configurable signals (empty
//!   User-Agent, missing Accept, suspicious path substrings) and blocks when the
//!   total reaches a threshold.
//!
//! Everything is **off by default** (an unset/`enabled = false` feature never
//! blocks), and the decision logic is pure so it is unit-tested without a
//! server. The server maps a [`WafVerdict::Block`] to `403`.

use serde::{Deserialize, Serialize};

/// The firewall config (a sub-policy of `AccessConfig`). Both features default
/// off, so the whole WAF is inert until configured.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafConfig {
    /// User-agent allow/deny rules.
    pub user_agent: UserAgentRules,
    /// Heuristic anomaly scoring.
    pub anomaly: AnomalyRules,
}

impl WafConfig {
    /// Whether any WAF feature is enabled (fast pre-check for the hot path).
    pub fn is_enabled(&self) -> bool {
        self.user_agent.enabled || self.anomaly.enabled
    }
}

/// Regex-based user-agent filtering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserAgentRules {
    /// Master toggle for UA filtering.
    pub enabled: bool,
    /// Regexes that block when the `User-Agent` matches any of them.
    pub deny: Vec<String>,
    /// Regexes for an allow-list: when non-empty, a UA matching none is blocked.
    pub allow: Vec<String>,
}

/// Heuristic anomaly scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnomalyRules {
    /// Master toggle for anomaly scoring.
    pub enabled: bool,
    /// Block when the summed score reaches this (min 1).
    pub threshold: u32,
    /// Add a point when the `User-Agent` is missing or empty.
    pub score_empty_user_agent: bool,
    /// Add a point when the `Accept` header is absent.
    pub score_missing_accept: bool,
    /// Path substrings that each add [`suspicious_path_score`] points when the
    /// request path contains them (e.g. `/.env`, `/.git/`, `/wp-login`).
    ///
    /// [`suspicious_path_score`]: Self::suspicious_path_score
    pub suspicious_paths: Vec<String>,
    /// Points a suspicious-path hit contributes (min 1; default 1).
    pub suspicious_path_score: u32,
}

impl Default for AnomalyRules {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 1,
            score_empty_user_agent: false,
            score_missing_accept: false,
            suspicious_paths: Vec::new(),
            suspicious_path_score: 1,
        }
    }
}

/// The request signals the WAF inspects.
#[derive(Debug, Clone, Copy)]
pub struct WafRequest<'a> {
    /// The `User-Agent` header, if present.
    pub user_agent: Option<&'a str>,
    /// The `Accept` header, if present.
    pub accept: Option<&'a str>,
    /// The (normalized) request path.
    pub path: &'a str,
}

/// The WAF's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafVerdict {
    /// Allow the request through.
    Allow,
    /// Block with a short, operator-facing reason (logged; not sent verbatim).
    Block(String),
}

/// Evaluate `req` against `config`. A disabled feature contributes nothing.
/// Invalid regexes are ignored (they never match), so a typo can't wedge the
/// site open or shut by accident.
pub fn evaluate(config: &WafConfig, req: &WafRequest<'_>) -> WafVerdict {
    if config.user_agent.enabled {
        if let Some(reason) = evaluate_user_agent(&config.user_agent, req.user_agent) {
            return WafVerdict::Block(reason);
        }
    }
    if config.anomaly.enabled {
        if let Some(reason) = evaluate_anomaly(&config.anomaly, req) {
            return WafVerdict::Block(reason);
        }
    }
    WafVerdict::Allow
}

fn matches_any(patterns: &[String], haystack: &str) -> bool {
    patterns.iter().any(|pat| {
        regex::Regex::new(pat)
            .map(|re| re.is_match(haystack))
            .unwrap_or(false)
    })
}

fn evaluate_user_agent(rules: &UserAgentRules, user_agent: Option<&str>) -> Option<String> {
    let ua = user_agent.unwrap_or("");
    if matches_any(&rules.deny, ua) {
        return Some("user-agent matched a deny rule".to_string());
    }
    if !rules.allow.is_empty() && !matches_any(&rules.allow, ua) {
        return Some("user-agent not on the allow-list".to_string());
    }
    None
}

fn evaluate_anomaly(rules: &AnomalyRules, req: &WafRequest<'_>) -> Option<String> {
    let mut score = 0u32;
    if rules.score_empty_user_agent && req.user_agent.map(str::trim).unwrap_or("").is_empty() {
        score += 1;
    }
    if rules.score_missing_accept && req.accept.is_none() {
        score += 1;
    }
    if !rules.suspicious_paths.is_empty() {
        let weight = rules.suspicious_path_score.max(1);
        for needle in &rules.suspicious_paths {
            if req.path.contains(needle.as_str()) {
                score += weight;
            }
        }
    }
    let threshold = rules.threshold.max(1);
    (score >= threshold).then(|| format!("anomaly score {score} >= threshold {threshold}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(ua: Option<&'a str>, accept: Option<&'a str>, path: &'a str) -> WafRequest<'a> {
        WafRequest {
            user_agent: ua,
            accept,
            path,
        }
    }

    #[test]
    fn disabled_waf_allows_everything() {
        let cfg = WafConfig::default();
        assert!(!cfg.is_enabled());
        assert_eq!(evaluate(&cfg, &req(None, None, "/.env")), WafVerdict::Allow);
    }

    #[test]
    fn ua_denylist_blocks_match_only() {
        let cfg = WafConfig {
            user_agent: UserAgentRules {
                enabled: true,
                deny: vec!["(?i)badbot".into()],
                allow: Vec::new(),
            },
            ..Default::default()
        };
        assert!(matches!(
            evaluate(&cfg, &req(Some("Mozilla BadBot/1.0"), None, "/")),
            WafVerdict::Block(_)
        ));
        assert_eq!(
            evaluate(&cfg, &req(Some("Mozilla/5.0"), None, "/")),
            WafVerdict::Allow
        );
    }

    #[test]
    fn ua_allowlist_blocks_non_matches() {
        let cfg = WafConfig {
            user_agent: UserAgentRules {
                enabled: true,
                deny: Vec::new(),
                allow: vec!["GoodClient".into()],
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate(&cfg, &req(Some("GoodClient/2"), None, "/")),
            WafVerdict::Allow
        );
        assert!(matches!(
            evaluate(&cfg, &req(Some("anything-else"), None, "/")),
            WafVerdict::Block(_)
        ));
    }

    #[test]
    fn anomaly_sums_signals_to_threshold() {
        let cfg = WafConfig {
            anomaly: AnomalyRules {
                enabled: true,
                threshold: 2,
                score_empty_user_agent: true,
                score_missing_accept: true,
                suspicious_paths: vec!["/.env".into()],
                suspicious_path_score: 1,
            },
            ..Default::default()
        };
        // Empty UA (+1) + missing Accept (+1) = 2 ≥ 2 → block.
        assert!(matches!(
            evaluate(&cfg, &req(None, None, "/")),
            WafVerdict::Block(_)
        ));
        // Only missing Accept (+1) = 1 < 2 → allow.
        assert_eq!(
            evaluate(&cfg, &req(Some("UA"), None, "/")),
            WafVerdict::Allow
        );
        // Suspicious path (+1) + missing Accept (+1) = 2 → block.
        assert!(matches!(
            evaluate(&cfg, &req(Some("UA"), None, "/.env")),
            WafVerdict::Block(_)
        ));
    }

    #[test]
    fn features_are_independent() {
        // UA off, anomaly on: a denied-looking UA passes (UA feature disabled).
        let cfg = WafConfig {
            user_agent: UserAgentRules {
                enabled: false,
                deny: vec!["BadBot".into()],
                ..Default::default()
            },
            anomaly: AnomalyRules {
                enabled: true,
                threshold: 1,
                score_empty_user_agent: true,
                ..Default::default()
            },
        };
        assert_eq!(
            evaluate(&cfg, &req(Some("BadBot"), Some("*/*"), "/")),
            WafVerdict::Allow,
            "UA rules disabled → not enforced"
        );
        assert!(
            matches!(
                evaluate(&cfg, &req(None, Some("*/*"), "/")),
                WafVerdict::Block(_)
            ),
            "anomaly still fires on empty UA"
        );
    }

    #[test]
    fn invalid_regex_is_ignored_not_fatal() {
        let cfg = WafConfig {
            user_agent: UserAgentRules {
                enabled: true,
                deny: vec!["(unclosed".into()],
                allow: Vec::new(),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate(&cfg, &req(Some("anything"), None, "/")),
            WafVerdict::Allow
        );
    }
}
