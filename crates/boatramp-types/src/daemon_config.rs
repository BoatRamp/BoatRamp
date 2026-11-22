//! Dynamic daemon configuration — the *operational* subset of `boatramp.cfg`
//! promoted into the control-plane KV tier, Raft-replicated, and changeable at
//! runtime without a restart. See `PLAN-dynamic-config`.
//!
//! **Security boundary (structural):** trust anchors (root key/signer, TLS key)
//! and *trust-relaxing* posture knobs are deliberately NOT fields here — they
//! stay in the static file, host-access-gated. What is here is safe to make
//! dynamic under two rules enforced by [`DaemonConfig::validate`] and
//! [`DaemonConfig::resolve`]:
//!
//! - **numeric caps are clamped by a static ceiling** (`0` = unlimited, and
//!   unlimited is only reachable dynamically if the static ceiling is also `0`);
//! - **posture knobs are tighten-only** — a dynamic override may move a knob only
//!   toward the safe value; a loosening value is rejected at write time.

use serde::{Deserialize, Serialize};

use crate::security::SecurityPosture;

/// A microVM kernel selection: a content-hash pin, verified before boot, with an
/// optional detached signature checked against the static kernel-signing keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRef {
    /// Where the kernel comes from: a content-addressed blob hash (or a ref a
    /// higher layer resolved to one).
    pub source: String,
    /// The expected SHA-256 of the kernel bytes. The runtime fetches, hashes, and
    /// **refuses to boot on mismatch** (verify-before-boot).
    pub sha256: String,
    /// Detached signature (hex) over [`sha256`](Self::sha256), verified against a
    /// static `[compute] kernel_signing_pubkeys`. Required under the strict
    /// (multi-tenant) posture; optional under single-tenant/dev. `None` = unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Fleet-wide compute defaults (each `None` = defer to the file baseline).
///
/// `#[non_exhaustive]`: this operator-config record grows new fleet knobs over time, so
/// downstream crates build it via [`ComputeDefaults::new`] + the `with_*` setters rather than
/// a struct literal — a later knob is then an additive, non-breaking field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ComputeDefaults {
    /// Kernel used when a workload's [`ComputeSpec`](crate::compute::ComputeSpec)
    /// omits its own. Changing this retargets the default for **new** microVMs and
    /// reboots; in-flight guests keep their kernel until they cycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_kernel: Option<KernelRef>,
    /// Advertised schedulable vCPUs (overrides `[compute].vcpus`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u32>,
    /// Advertised schedulable memory MiB (overrides `[compute].mem_mib`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mib: Option<u32>,
}

impl ComputeDefaults {
    /// The all-defer defaults (every field `None` ⇒ the file baseline). The supported
    /// constructor now that `ComputeDefaults` is `#[non_exhaustive]`; set a field with the
    /// chainable `with_*` setters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default microVM kernel (`None` ⇒ defer to the file baseline).
    #[must_use]
    pub fn with_default_kernel(mut self, default_kernel: Option<KernelRef>) -> Self {
        self.default_kernel = default_kernel;
        self
    }

    /// Set the advertised schedulable vCPUs (`None` ⇒ defer to `[compute].vcpus`).
    #[must_use]
    pub fn with_vcpus(mut self, vcpus: Option<u32>) -> Self {
        self.vcpus = vcpus;
        self
    }

    /// Set the advertised schedulable memory MiB (`None` ⇒ defer to `[compute].mem_mib`).
    #[must_use]
    pub fn with_mem_mib(mut self, mem_mib: Option<u32>) -> Self {
        self.mem_mib = mem_mib;
        self
    }
}

/// Dynamic overrides for the embedded web console mount (`[serve.console]`). Each
/// `None` defers to the file baseline. Making this dynamic lets an operator turn
/// the console on/off (or move its host/path) fleet-wide with one API write, no
/// restart. It is a safe operational toggle, not a trust relaxation: the console
/// is a static, secret-free SPA and the control-plane API it drives stays
/// token-gated regardless — enabling the mount grants no privilege.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleSettings {
    /// Serve the console at all (overrides `[serve.console] enabled`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Host(s) the console answers on: `*` (any), an exact host, or `*.suffix`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// URL path prefix it mounts at (default `/_console`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Tighten-only overrides for the trust-relaxing posture knobs. A field may only
/// carry the **safe** value; a loosening value is rejected by
/// [`DaemonConfig::validate`]. This lets an operator harden a running fleet (e.g.
/// during an incident) via one Raft write, while loosening always requires the
/// static file + a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PostureTighten {
    /// Safe = `true` (require an OIDC audience).
    pub oidc_require_audience: Option<bool>,
    /// Safe = `false` (fail closed on a rate-limit KV error).
    pub ratelimit_fail_open: Option<bool>,
    /// Safe = `false`.
    pub allow_unauthenticated_public_bind: Option<bool>,
    /// Safe = `false`.
    pub allow_site_private_upstreams: Option<bool>,
    /// Safe = `false`.
    pub allow_site_unix_upstreams: Option<bool>,
    /// Safe = `false`.
    pub allow_shared_kernel_compute: Option<bool>,
    /// Safe = `false`.
    pub domain_verify_allow_private: Option<bool>,
    /// Safe = `false`.
    pub allow_implicit_routing: Option<bool>,
}

/// The dynamic daemon config, stored at `daemonconfig/<hash>` and pointed to by
/// `daemon/current`. Every field is optional: `None` defers to the file baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    pub version: u32,
    /// Catch-all site for an unmatched `Host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_site: Option<String>,
    /// Require a token to view deployment previews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protect_previews: Option<bool>,
    /// Blob-upload cap (bytes; `0` = unlimited). Clamped by the static ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_upload_bytes: Option<u64>,
    /// Abort an upload idle this many seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_idle_timeout_secs: Option<u64>,
    /// Cap on simultaneous uploads. Clamped by the static ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_uploads: Option<u64>,
    /// Rate-limit cluster-wide via the KV instead of per-node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_rate_limit: Option<bool>,
    /// Fleet compute defaults (default kernel, advertised capacity).
    #[serde(default, skip_serializing_if = "ComputeDefaults::is_empty")]
    pub compute: ComputeDefaults,
    /// Embedded web console overrides (enable/host/path).
    #[serde(default, skip_serializing_if = "ConsoleSettings::is_empty")]
    pub console: ConsoleSettings,
    /// HTTP `/mcp` endpoint override (a live on/off kill-switch).
    #[serde(default, skip_serializing_if = "McpSettings::is_empty")]
    pub mcp: McpSettings,
    /// Tighten-only posture overrides.
    #[serde(default, skip_serializing_if = "PostureTighten::is_empty")]
    pub posture: PostureTighten,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            default_site: None,
            protect_previews: None,
            max_upload_bytes: None,
            upload_idle_timeout_secs: None,
            max_concurrent_uploads: None,
            cluster_rate_limit: None,
            compute: ComputeDefaults::default(),
            console: ConsoleSettings::default(),
            mcp: McpSettings::default(),
            posture: PostureTighten::default(),
        }
    }
}

/// The file-derived baseline + static ceilings the dynamic config layers over.
/// Supplied by `serve` from the resolved `boatramp.cfg`. Byte/count caps use the
/// convention `0` = unlimited; a ceiling of `0` means "no ceiling".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigBaseline {
    pub default_site: Option<String>,
    pub protect_previews: bool,
    pub max_upload_bytes: u64,
    pub upload_idle_timeout_secs: Option<u64>,
    pub max_concurrent_uploads: Option<u64>,
    pub cluster_rate_limit: bool,
    pub compute_vcpus: u32,
    pub compute_mem_mib: u32,
    /// Console mount baseline from `[serve.console]` (enabled/host/path).
    pub console_enabled: bool,
    pub console_host: Option<String>,
    pub console_path: Option<String>,
    /// Static ceiling for `max_upload_bytes` (`0` = no ceiling).
    pub max_upload_ceiling: u64,
    /// Static ceiling for `max_concurrent_uploads` (`None` = no ceiling).
    pub max_concurrent_uploads_ceiling: Option<u64>,
    /// The file-resolved posture; a dynamic override may only tighten it.
    pub posture: SecurityPosture,
}

/// The validate-relevant slice of the [`ConfigBaseline`] — the static numeric
/// ceilings a dynamic-config **write** is checked against. Serializable so a
/// client (the `boatramp config set`/`apply` path) can fetch it from
/// `GET /api/daemon/config` and run the **same** [`DaemonConfig::validate_limits`]
/// at *set* time, turning a would-be apply-time `400` into a clean, early,
/// explained refusal.
///
/// These ceilings are the only baseline-dependent inputs to validation: the
/// posture tighten-only ratchet needs no baseline — a loosening value is unsafe
/// *regardless* of the server's posture — so advertising the ceilings is all a
/// caller needs to pre-validate the full write. The upload ceiling is
/// posture-derived (it is the file posture's `max_upload_bytes`), which is why
/// the client cannot know it without this plumbing. Byte/count caps use the
/// convention `0`/`None` = unlimited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigLimits {
    /// Static ceiling for `max_upload_bytes` (`0` = no ceiling).
    pub max_upload_ceiling: u64,
    /// Static ceiling for `max_concurrent_uploads` (`None` = no ceiling).
    pub max_concurrent_uploads_ceiling: Option<u64>,
}

impl Default for ConfigLimits {
    /// No ceilings. A caller that lacks the real limits — e.g. an older server that
    /// doesn't advertise them yet — thus never *wrongly* refuses a write client-side;
    /// the server's own [`DaemonConfig::validate`] stays the authority.
    fn default() -> Self {
        Self {
            max_upload_ceiling: 0,
            max_concurrent_uploads_ceiling: None,
        }
    }
}

impl ConfigBaseline {
    /// The validate-relevant ceilings as a serializable view the server can
    /// advertise and a client can pre-validate against (see [`ConfigLimits`]).
    pub fn limits(&self) -> ConfigLimits {
        ConfigLimits {
            max_upload_ceiling: self.max_upload_ceiling,
            max_concurrent_uploads_ceiling: self.max_concurrent_uploads_ceiling,
        }
    }
}

/// The resolved, effective config the server actually runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfig {
    pub default_site: Option<String>,
    pub protect_previews: bool,
    pub max_upload_bytes: u64,
    pub upload_idle_timeout_secs: Option<u64>,
    pub max_concurrent_uploads: Option<u64>,
    pub cluster_rate_limit: bool,
    pub compute_vcpus: u32,
    pub compute_mem_mib: u32,
    pub default_kernel: Option<KernelRef>,
    /// Resolved console mount: whether to serve it, and where.
    pub console_enabled: bool,
    pub console_host: Option<String>,
    pub console_path: Option<String>,
    /// Whether to serve the HTTP `/mcp` endpoint (default on).
    pub mcp_enabled: bool,
    pub posture: SecurityPosture,
}

impl ComputeDefaults {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl ConsoleSettings {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Dynamic override for the in-`serve` HTTP MCP endpoint (`/mcp`). A live
/// operational kill-switch: set `enabled = false` to stop serving `/mcp`
/// fleet-wide with no restart (a security lever, not a trust relaxation — the
/// stdio transport is unaffected). Defaults to on.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpSettings {
    /// Serve the HTTP `/mcp` endpoint at all. `None`/unset ⇒ on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl McpSettings {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl PostureTighten {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Apply the tighten-only overrides to `p`, ignoring any loosening value
    /// (loosening is rejected earlier by [`DaemonConfig::validate`]; this is the
    /// defensive belt so a bad stored config can never *loosen* at read time).
    fn apply(&self, mut p: SecurityPosture) -> SecurityPosture {
        if self.oidc_require_audience == Some(true) {
            p.oidc_require_audience = true;
        }
        if self.ratelimit_fail_open == Some(false) {
            p.ratelimit_fail_open = false;
        }
        if self.allow_unauthenticated_public_bind == Some(false) {
            p.allow_unauthenticated_public_bind = false;
        }
        if self.allow_site_private_upstreams == Some(false) {
            p.allow_site_private_upstreams = false;
        }
        if self.allow_site_unix_upstreams == Some(false) {
            p.allow_site_unix_upstreams = false;
        }
        if self.allow_shared_kernel_compute == Some(false) {
            p.allow_shared_kernel_compute = false;
        }
        if self.domain_verify_allow_private == Some(false) {
            p.domain_verify_allow_private = false;
        }
        if self.allow_implicit_routing == Some(false) {
            p.allow_implicit_routing = false;
        }
        p
    }

    /// Names of any knob set to its *unsafe* (loosening) value — a write carrying
    /// any of these must be rejected.
    fn loosening(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.oidc_require_audience == Some(false) {
            out.push("oidc_require_audience");
        }
        if self.ratelimit_fail_open == Some(true) {
            out.push("ratelimit_fail_open");
        }
        for (v, name) in [
            (
                self.allow_unauthenticated_public_bind,
                "allow_unauthenticated_public_bind",
            ),
            (
                self.allow_site_private_upstreams,
                "allow_site_private_upstreams",
            ),
            (self.allow_site_unix_upstreams, "allow_site_unix_upstreams"),
            (
                self.allow_shared_kernel_compute,
                "allow_shared_kernel_compute",
            ),
            (
                self.domain_verify_allow_private,
                "domain_verify_allow_private",
            ),
            (self.allow_implicit_routing, "allow_implicit_routing"),
        ] {
            if v == Some(true) {
                out.push(name);
            }
        }
        out
    }
}

/// Clamp a cap `v` to a static `ceiling` (`0` = unlimited on both). Unlimited
/// (`0`) is only reachable when the ceiling is also unlimited.
fn clamp_cap(v: u64, ceiling: u64) -> u64 {
    if ceiling == 0 {
        v
    } else if v == 0 || v > ceiling {
        ceiling
    } else {
        v
    }
}

impl DaemonConfig {
    /// Resolve `file baseline ⊕ dynamic overrides` into the effective config,
    /// clamping caps to the static ceilings and applying tighten-only posture
    /// overrides. Defensive: never produces a value looser than the baseline.
    pub fn resolve(&self, base: &ConfigBaseline) -> EffectiveConfig {
        let max_upload_bytes = clamp_cap(
            self.max_upload_bytes.unwrap_or(base.max_upload_bytes),
            base.max_upload_ceiling,
        );
        let max_concurrent_uploads = match (
            self.max_concurrent_uploads.or(base.max_concurrent_uploads),
            base.max_concurrent_uploads_ceiling,
        ) {
            (Some(v), Some(c)) => Some(v.min(c)),
            (v, _) => v,
        };
        EffectiveConfig {
            default_site: self
                .default_site
                .clone()
                .or_else(|| base.default_site.clone()),
            protect_previews: self.protect_previews.unwrap_or(base.protect_previews),
            max_upload_bytes,
            upload_idle_timeout_secs: self
                .upload_idle_timeout_secs
                .or(base.upload_idle_timeout_secs),
            max_concurrent_uploads,
            cluster_rate_limit: self.cluster_rate_limit.unwrap_or(base.cluster_rate_limit),
            compute_vcpus: self.compute.vcpus.unwrap_or(base.compute_vcpus),
            compute_mem_mib: self.compute.mem_mib.unwrap_or(base.compute_mem_mib),
            default_kernel: self.compute.default_kernel.clone(),
            console_enabled: self.console.enabled.unwrap_or(base.console_enabled),
            console_host: self
                .console
                .host
                .clone()
                .or_else(|| base.console_host.clone()),
            console_path: self
                .console
                .path
                .clone()
                .or_else(|| base.console_path.clone()),
            // On unless explicitly disabled; the endpoint is compile-gated by the
            // `mcp` feature and defaults on there, so no baseline field is needed.
            mcp_enabled: self.mcp.enabled.unwrap_or(true),
            posture: self.posture.apply(base.posture),
        }
    }

    /// Validate a proposed dynamic config against the baseline for the **write**
    /// path (leader-side, before Raft commit): reject a wrong schema version, a
    /// cap above its static ceiling, or a loosening posture override. Thin wrapper
    /// over [`validate_limits`](Self::validate_limits) — the one validation body —
    /// passing the baseline's [`ConfigLimits`].
    pub fn validate(&self, base: &ConfigBaseline) -> Result<(), String> {
        self.validate_limits(&base.limits())
    }

    /// The write-path validation against just the static [`ConfigLimits`] (plus the
    /// baseline-independent tighten-only posture ratchet): reject a wrong schema
    /// version, a cap above its static ceiling, or a loosening posture override.
    ///
    /// This is the shared validator the server runs (via [`validate`](Self::validate))
    /// AND the CLI runs at *set* time — the client fetches the server's advertised
    /// [`ConfigLimits`] and calls this to refuse a loosening or over-ceiling write
    /// cleanly and early, instead of surfacing the identical late apply-time `400`.
    pub fn validate_limits(&self, limits: &ConfigLimits) -> Result<(), String> {
        if self.version != crate::SCHEMA_VERSION {
            return Err(format!(
                "unsupported daemon-config version {} (expected {})",
                self.version,
                crate::SCHEMA_VERSION
            ));
        }
        if let Some(v) = self.max_upload_bytes
            && exceeds_ceiling(v, limits.max_upload_ceiling)
        {
            return Err(format!(
                "max_upload_bytes {v} exceeds the static ceiling {}",
                limits.max_upload_ceiling
            ));
        }
        if let (Some(v), Some(c)) = (
            self.max_concurrent_uploads,
            limits.max_concurrent_uploads_ceiling,
        ) && v > c
        {
            return Err(format!(
                "max_concurrent_uploads {v} exceeds the static ceiling {c}"
            ));
        }
        let loosening = self.posture.loosening();
        if !loosening.is_empty() {
            return Err(format!(
                "posture overrides are tighten-only; these would loosen and must be set \
                 in boatramp.cfg + restart instead: {}",
                loosening.join(", ")
            ));
        }
        Ok(())
    }
}

/// Whether cap `v` exceeds `ceiling` (`0` = unlimited). Unlimited (`0`) exceeds
/// any finite ceiling.
fn exceeds_ceiling(v: u64, ceiling: u64) -> bool {
    ceiling != 0 && (v == 0 || v > ceiling)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityProfile;

    fn baseline() -> ConfigBaseline {
        ConfigBaseline {
            default_site: Some("fallback".into()),
            protect_previews: false,
            max_upload_bytes: 10,
            upload_idle_timeout_secs: None,
            max_concurrent_uploads: None,
            cluster_rate_limit: false,
            compute_vcpus: 4,
            compute_mem_mib: 1024,
            console_enabled: false,
            console_host: None,
            console_path: None,
            max_upload_ceiling: 100,
            max_concurrent_uploads_ceiling: Some(8),
            posture: SecurityProfile::MultiTenant.preset(),
        }
    }

    #[test]
    fn compute_defaults_builder_matches_the_literal() {
        // The builder produces the same value a struct literal would (still legal in-crate;
        // `#[non_exhaustive]` only blocks the literal in downstream crates).
        let built = ComputeDefaults::new()
            .with_vcpus(Some(8))
            .with_mem_mib(Some(2048));
        let literal = ComputeDefaults {
            default_kernel: None,
            vcpus: Some(8),
            mem_mib: Some(2048),
        };
        assert_eq!(built, literal);
        // The empty builder is the all-defer default.
        assert_eq!(ComputeDefaults::new(), ComputeDefaults::default());
    }

    #[test]
    fn empty_config_defers_to_baseline() {
        let eff = DaemonConfig::default().resolve(&baseline());
        assert_eq!(eff.default_site.as_deref(), Some("fallback"));
        assert_eq!(eff.max_upload_bytes, 10);
        assert!(!eff.protect_previews);
        assert_eq!(eff.compute_vcpus, 4);
        assert!(eff.default_kernel.is_none());
    }

    #[test]
    fn override_within_ceiling_wins() {
        let cfg = DaemonConfig {
            default_site: Some("blog".into()),
            protect_previews: Some(true),
            max_upload_bytes: Some(50),
            ..Default::default()
        };
        assert!(cfg.validate(&baseline()).is_ok());
        let eff = cfg.resolve(&baseline());
        assert_eq!(eff.default_site.as_deref(), Some("blog"));
        assert!(eff.protect_previews);
        assert_eq!(eff.max_upload_bytes, 50);
    }

    #[test]
    fn cap_over_ceiling_is_rejected_and_clamped() {
        let cfg = DaemonConfig {
            max_upload_bytes: Some(1000),
            ..Default::default()
        };
        // Write path rejects it…
        assert!(cfg.validate(&baseline()).is_err());
        // …and resolve clamps defensively to the ceiling.
        assert_eq!(cfg.resolve(&baseline()).max_upload_bytes, 100);
        // Unlimited (0) is also over a finite ceiling.
        let unlimited = DaemonConfig {
            max_upload_bytes: Some(0),
            ..Default::default()
        };
        assert!(unlimited.validate(&baseline()).is_err());
        assert_eq!(unlimited.resolve(&baseline()).max_upload_bytes, 100);
    }

    #[test]
    fn posture_tighten_only() {
        // Tightening is allowed and applied.
        let tighten = DaemonConfig {
            posture: PostureTighten {
                ratelimit_fail_open: Some(false),
                oidc_require_audience: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        // MultiTenant already has these at the safe value; use a dev baseline to see effect.
        let mut base = baseline();
        base.posture = SecurityProfile::Dev.preset();
        assert!(base.posture.ratelimit_fail_open);
        assert!(!base.posture.oidc_require_audience);
        assert!(tighten.validate(&base).is_ok());
        let eff = tighten.resolve(&base);
        assert!(!eff.posture.ratelimit_fail_open, "tightened to fail-closed");
        assert!(
            eff.posture.oidc_require_audience,
            "tightened to require audience"
        );

        // Loosening is rejected at validate and ignored at resolve.
        let loosen = DaemonConfig {
            posture: PostureTighten {
                allow_shared_kernel_compute: Some(true),
                ratelimit_fail_open: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let strict = baseline(); // MultiTenant: both already false
        assert!(loosen.validate(&strict).is_err());
        let eff = loosen.resolve(&strict);
        assert!(
            !eff.posture.allow_shared_kernel_compute,
            "loosening ignored at resolve"
        );
        assert!(!eff.posture.ratelimit_fail_open);
    }

    #[test]
    fn console_override_toggles_and_defers() {
        // Empty defers to the (disabled) baseline.
        let eff = DaemonConfig::default().resolve(&baseline());
        assert!(!eff.console_enabled);
        assert!(eff.console_host.is_none());

        // A dynamic override enables it (and can move host/path) without a restart.
        let cfg = DaemonConfig {
            console: ConsoleSettings {
                enabled: Some(true),
                host: Some("console.example.com".into()),
                path: Some("/admin".into()),
            },
            ..Default::default()
        };
        assert!(cfg.validate(&baseline()).is_ok());
        let eff = cfg.resolve(&baseline());
        assert!(eff.console_enabled);
        assert_eq!(eff.console_host.as_deref(), Some("console.example.com"));
        assert_eq!(eff.console_path.as_deref(), Some("/admin"));

        // With a file baseline that enabled it, an explicit `false` turns it off.
        let mut base = baseline();
        base.console_enabled = true;
        base.console_path = Some("/_console".into());
        let off = DaemonConfig {
            console: ConsoleSettings {
                enabled: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };
        let eff = off.resolve(&base);
        assert!(!eff.console_enabled);
        // Unset host/path still defer to the baseline.
        assert_eq!(eff.console_path.as_deref(), Some("/_console"));
    }

    #[test]
    fn mcp_enabled_defaults_on_and_toggles_off() {
        let base = baseline();
        // Unset ⇒ the HTTP `/mcp` endpoint is on.
        assert!(DaemonConfig::default().resolve(&base).mcp_enabled);
        // An explicit dynamic disable turns it off (the runtime kill-switch).
        let off = DaemonConfig {
            mcp: McpSettings {
                enabled: Some(false),
            },
            ..Default::default()
        };
        assert!(!off.resolve(&base).mcp_enabled);
    }

    #[test]
    fn json_round_trips_and_rejects_unknown_fields() {
        let cfg = DaemonConfig {
            default_site: Some("x".into()),
            compute: ComputeDefaults {
                default_kernel: Some(KernelRef {
                    source: "abc".into(),
                    sha256: "def".into(),
                    sig: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_vec(&cfg).unwrap();
        let back: DaemonConfig = serde_json::from_slice(&json).unwrap();
        assert_eq!(cfg, back);
        assert!(serde_json::from_slice::<DaemonConfig>(br#"{"nope":1}"#).is_err());
    }

    #[test]
    fn baseline_limits_carry_the_posture_derived_ceilings() {
        // The upload ceiling is the file posture's upload cap, so `limits()` differs
        // per posture — exactly the value a client can't know without plumbing.
        let mut base = baseline();
        base.max_upload_ceiling = 4096;
        base.max_concurrent_uploads_ceiling = Some(8);
        let limits = base.limits();
        assert_eq!(limits.max_upload_ceiling, 4096);
        assert_eq!(limits.max_concurrent_uploads_ceiling, Some(8));
        // A strict (multi-tenant) posture's upload cap flows through to the ceiling.
        let strict = ConfigBaseline {
            max_upload_ceiling: SecurityProfile::MultiTenant.preset().max_upload_bytes,
            ..baseline()
        };
        assert_eq!(
            strict.limits().max_upload_ceiling,
            SecurityProfile::MultiTenant.preset().max_upload_bytes
        );
    }

    #[test]
    fn config_limits_json_round_trips_and_defaults_to_unlimited() {
        let limits = ConfigLimits {
            max_upload_ceiling: 100,
            max_concurrent_uploads_ceiling: Some(8),
        };
        let json = serde_json::to_vec(&limits).unwrap();
        assert_eq!(
            serde_json::from_slice::<ConfigLimits>(&json).unwrap(),
            limits
        );
        // An older server advertises no `limits`: a missing field defaults to no
        // ceiling, so a client never wrongly refuses on the ceiling checks.
        let empty: ConfigLimits = serde_json::from_slice(b"{}").unwrap();
        assert_eq!(empty, ConfigLimits::default());
        assert_eq!(empty.max_upload_ceiling, 0);
        assert!(empty.max_concurrent_uploads_ceiling.is_none());
    }

    #[test]
    fn validate_limits_matches_validate_and_catches_each_case() {
        let base = baseline();
        let limits = base.limits();
        // `validate` delegates to `validate_limits` — identical verdicts.
        let over = DaemonConfig {
            max_upload_bytes: Some(1000), // ceiling is 100
            ..Default::default()
        };
        assert!(over.validate(&base).is_err());
        assert!(over.validate_limits(&limits).is_err());
        assert!(
            over.validate_limits(&limits)
                .unwrap_err()
                .contains("exceeds the static ceiling")
        );
        // A loosening posture override is caught with no baseline knowledge at all
        // (the tighten-only ratchet is posture-independent).
        let loosen = DaemonConfig {
            posture: PostureTighten {
                ratelimit_fail_open: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = loosen
            .validate_limits(&ConfigLimits::default())
            .unwrap_err();
        assert!(err.contains("tighten-only"), "{err}");
        assert!(err.contains("ratelimit_fail_open"), "{err}");
        // A valid write passes both.
        let ok = DaemonConfig {
            max_upload_bytes: Some(50),
            protect_previews: Some(true),
            ..Default::default()
        };
        assert!(ok.validate(&base).is_ok());
        assert!(ok.validate_limits(&limits).is_ok());
    }
}
