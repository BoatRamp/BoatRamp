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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
    /// Static ceiling for `max_upload_bytes` (`0` = no ceiling).
    pub max_upload_ceiling: u64,
    /// Static ceiling for `max_concurrent_uploads` (`None` = no ceiling).
    pub max_concurrent_uploads_ceiling: Option<u64>,
    /// The file-resolved posture; a dynamic override may only tighten it.
    pub posture: SecurityPosture,
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
    pub posture: SecurityPosture,
}

impl ComputeDefaults {
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
            posture: self.posture.apply(base.posture),
        }
    }

    /// Validate a proposed dynamic config against the baseline for the **write**
    /// path (leader-side, before Raft commit): reject a wrong schema version, a
    /// cap above its static ceiling, or a loosening posture override.
    pub fn validate(&self, base: &ConfigBaseline) -> Result<(), String> {
        if self.version != crate::SCHEMA_VERSION {
            return Err(format!(
                "unsupported daemon-config version {} (expected {})",
                self.version,
                crate::SCHEMA_VERSION
            ));
        }
        if let Some(v) = self.max_upload_bytes {
            if exceeds_ceiling(v, base.max_upload_ceiling) {
                return Err(format!(
                    "max_upload_bytes {v} exceeds the static ceiling {}",
                    base.max_upload_ceiling
                ));
            }
        }
        if let (Some(v), Some(c)) = (
            self.max_concurrent_uploads,
            base.max_concurrent_uploads_ceiling,
        ) {
            if v > c {
                return Err(format!(
                    "max_concurrent_uploads {v} exceeds the static ceiling {c}"
                ));
            }
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
            max_upload_ceiling: 100,
            max_concurrent_uploads_ceiling: Some(8),
            posture: SecurityProfile::MultiTenant.preset(),
        }
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
}
