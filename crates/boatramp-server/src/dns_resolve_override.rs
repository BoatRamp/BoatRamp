//! DEV/TEST resolver override for the guest consumer-lane `dns-resolve` capability (mailroom cap-req
//! #21 residual). Pure config data + a process-wide install hook so a node can inject a STATIC
//! host→records answer — the hook for a hermetic / fully-offline direct-MX relay proof — or point the
//! consumer-lane resolver at a custom upstream nameserver instead of the host's `/etc/resolv.conf`.
//!
//! This module is ALWAYS compiled (the config type rides in `[handlers]`, which is parsed in every
//! build so config files stay portable), but the hickory wiring that CONSULTS the installed override
//! lives in [`crate::dns_resolve`] (behind the `tcp-egress` feature). OFF by default: an ABSENT (or
//! empty) override leaves the resolver on the system resolver, byte-for-byte unchanged — production is
//! unaffected.
//!
//! # Why node-global, and why it is NOT a tenancy bypass
//! The resolver is built ONCE process-wide and shared by every guest invocation granted `dns-resolve`
//! (DNS is global; one cached resolver is correct), so the override is necessarily node-scoped. It is
//! an OPERATOR/serve knob — a `boatramp.cfg` `[handlers]` field — never a guest/project `project.cfg`
//! knob, so a guest can NEVER set its own resolver override. And the override only chooses WHICH
//! answers the shared resolver returns; those answers still pass, unchanged, through the
//! per-invocation grant + egress posture + SSRF floor in [`boatramp_handlers::DnsResolveHost`] (a
//! static private/loopback address is still dropped unless the operator also set
//! `allow_guest_private_egress`). So the override can be neither a cross-tenant escalation nor a
//! private-IP SSRF oracle — it is strictly a dev/test ergonomics knob for the resolver boundary.

use std::net::IpAddr;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// `[handlers.dns_resolve_override]` — a DEV/TEST override of the consumer-lane DNS resolver. Leave it
/// ABSENT in production (the system resolver is used). See the module docs for the security model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsResolveOverrideConfig {
    /// Static host→records answers, consulted FIRST. A hit returns WITHOUT touching the network, which
    /// is what makes a fully-offline direct-MX relay proof possible. Empty ⇒ no static answers (only a
    /// custom `upstream`, if set, changes behavior).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<StaticRecord>,
    /// Optional custom UPSTREAM resolver `host:port` (e.g. `127.0.0.1:5353`) used, INSTEAD of the
    /// system resolver, for any name the static map does not answer. Absent ⇒ the system resolver
    /// (`/etc/resolv.conf`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// One static override entry: a name and the records it answers with. Only ADDRESS + MX records are
/// supported — the consumer-lane `DnsResolver` capability exposes exactly `resolve-addr` and
/// `resolve-mx` (there is no `resolve-txt`), so TXT (and other record types) are deliberately omitted;
/// a record type is added here only if/when the capability gains a lookup for it. `addrs` serves the
/// A/AAAA (`resolve-addr`) lookup — v4 entries are A records, v6 are AAAA, exactly as the consumer lane
/// returns them combined — and `mx` serves the `resolve-mx` lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaticRecord {
    /// The host/domain this entry answers (matched case-insensitively, trailing dot ignored).
    pub name: String,
    /// A/AAAA answers for `name` (the `resolve-addr` lookup). An IPv4 is an A record, an IPv6 an AAAA.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<IpAddr>,
    /// MX answers for `name` (the `resolve-mx` lookup), ascending preference is applied by the resolver.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mx: Vec<StaticMx>,
}

/// One static MX record (preference + mail-exchange host).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaticMx {
    /// Delivery preference (lower is tried first).
    pub preference: u16,
    /// The mail-exchange host.
    pub exchange: String,
}

impl DnsResolveOverrideConfig {
    /// An override with neither static records nor a custom upstream changes nothing — treated as
    /// absent so the default (system-resolver) path stays byte-for-byte unchanged.
    pub(crate) fn is_active(&self) -> bool {
        !self.records.is_empty() || self.upstream.is_some()
    }
}

/// The process-wide installed override, seeded ONCE at node startup. `None` (never installed, or
/// installed empty) ⇒ the default system resolver.
static INSTALLED: OnceLock<Option<DnsResolveOverrideConfig>> = OnceLock::new();

/// Install the operator-configured resolver override ONCE at node startup, BEFORE the shared resolver
/// is first built (every guest invocation builds it lazily, so startup always wins the race). First
/// install wins; a later install is ignored with a warn (the resolver is a process-wide singleton).
/// Installing `None` (or an empty override) is a no-op for behavior — the system resolver is used.
pub fn install_override(cfg: Option<DnsResolveOverrideConfig>) {
    let active = cfg
        .as_ref()
        .is_some_and(DnsResolveOverrideConfig::is_active);
    if INSTALLED.set(cfg).is_err() {
        tracing::warn!(
            "dns-resolve override install ignored: the shared resolver override was already installed"
        );
        return;
    }
    if active {
        tracing::warn!(
            "dns-resolve: DEV/TEST resolver OVERRIDE is ACTIVE ([handlers.dns_resolve_override] \
             configures static records and/or a custom upstream). This is a dev/test knob — leave it \
             unset in production so the system resolver (/etc/resolv.conf) is used."
        );
    }
}

/// The installed, ACTIVE override, if any (an empty override reads as absent). Consulted by the
/// `tcp-egress` resolver builder only.
#[cfg(feature = "tcp-egress")]
pub(crate) fn installed_override() -> Option<&'static DnsResolveOverrideConfig> {
    INSTALLED
        .get()
        .and_then(Option::as_ref)
        .filter(|cfg| cfg.is_active())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_override_is_inactive() {
        assert!(!DnsResolveOverrideConfig::default().is_active());
        let only_records = DnsResolveOverrideConfig {
            records: vec![StaticRecord {
                name: "example.com".into(),
                addrs: vec!["93.184.216.34".parse().unwrap()],
                ..Default::default()
            }],
            upstream: None,
        };
        assert!(only_records.is_active());
        let only_upstream = DnsResolveOverrideConfig {
            records: vec![],
            upstream: Some("127.0.0.1:5353".into()),
        };
        assert!(only_upstream.is_active());
    }
}
