//! Operator-scoped **security posture** (the unifying mechanism for the
//! security hardening). A single resolved set of trust knobs that the server,
//! gateway, handler runtime, and compute scheduler all consult, so the trust
//! model is decided once by the operator rather than scattered across defaults.
//!
//! The model is **"default untrusted, easily configured via profiles"**:
//!
//! - A [`SecurityProfile`] preset picks a coherent default for every knob —
//!   `multi-tenant` (strict; the default), `single-tenant` (relaxed, but still
//!   authenticated, for a single operator who owns every site), or `dev`
//!   (loopback-loose for local development).
//! - **Individual knobs are the source of truth; profiles are sugar.** Any knob
//!   set in [`SecurityConfig::overrides`] wins over the selected profile, and an
//!   operator can define their own named profiles under
//!   [`SecurityConfig::profiles`].
//! - The posture lives **only** in the server daemon config (`boatramp.cfg`),
//!   never in site config — so a `site-write` principal can never define or
//!   relax it. That invariant is structural, not enforced here.
//!
//! [`SecurityConfig::resolve`] folds (profile preset → overrides) into a concrete
//! [`SecurityPosture`]; [`SecurityConfig::explain`] renders the resolved posture
//! with each knob's source for `boatramp security explain`.
//!
//! Byte-cap knobs use the convention **`0` = unlimited**.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;

/// Multi-tenant default blob-upload cap (100 MiB).
const MT_MAX_UPLOAD: u64 = 100 * 1024 * 1024;
/// Multi-tenant default handler blobstore host read/copy cap (64 MiB).
const MT_MAX_BLOB: u64 = 64 * 1024 * 1024;
/// Multi-tenant default Wasm component blob cap (64 MiB).
const MT_MAX_COMPONENT: u64 = 64 * 1024 * 1024;
/// Single-tenant upload cap (1 GiB) — looser, single operator owns every site.
const ST_MAX_UPLOAD: u64 = 1024 * 1024 * 1024;
/// Single-tenant handler blobstore cap (256 MiB).
const ST_MAX_BLOB: u64 = 256 * 1024 * 1024;
/// Single-tenant component cap (128 MiB).
const ST_MAX_COMPONENT: u64 = 128 * 1024 * 1024;

/// A failure resolving the `[security]` configuration.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// The selected `profile` is neither a built-in nor a key under `profiles`.
    #[error(
        "unknown security profile {0:?} (built-ins: multi-tenant, single-tenant, dev; \
         or define it under `security.profiles`)"
    )]
    UnknownProfile(String),
}

/// Built-in posture presets. The default is [`SecurityProfile::MultiTenant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Strict: untrusted site writers + untrusted network. The default.
    MultiTenant,
    /// Relaxed for a single operator who owns every site (still authenticated).
    SingleTenant,
    /// Loopback-loose local development (auth optional, caps off).
    Dev,
}

impl SecurityProfile {
    /// Map a profile name to a built-in, if it is one.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "multi-tenant" => Some(Self::MultiTenant),
            "single-tenant" => Some(Self::SingleTenant),
            "dev" => Some(Self::Dev),
            _ => None,
        }
    }

    /// The canonical name of this built-in profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultiTenant => "multi-tenant",
            Self::SingleTenant => "single-tenant",
            Self::Dev => "dev",
        }
    }

    /// The fully-resolved posture this preset implies (before overrides).
    pub fn preset(self) -> SecurityPosture {
        match self {
            Self::MultiTenant => SecurityPosture {
                allow_unauthenticated_public_bind: false,
                max_upload_bytes: MT_MAX_UPLOAD,
                allow_site_unix_upstreams: false,
                allow_site_private_upstreams: false,
                max_handler_blob_bytes: MT_MAX_BLOB,
                max_component_bytes: MT_MAX_COMPONENT,
                oidc_require_audience: true,
                domain_verify_allow_private: false,
                domain_verify_self_serve: true,
                allow_shared_kernel_compute: false,
                ratelimit_fail_open: false,
                allow_implicit_routing: false,
            },
            Self::SingleTenant => SecurityPosture {
                allow_unauthenticated_public_bind: false,
                max_upload_bytes: ST_MAX_UPLOAD,
                allow_site_unix_upstreams: true,
                allow_site_private_upstreams: true,
                max_handler_blob_bytes: ST_MAX_BLOB,
                max_component_bytes: ST_MAX_COMPONENT,
                oidc_require_audience: true,
                domain_verify_allow_private: true,
                domain_verify_self_serve: true,
                allow_shared_kernel_compute: true,
                ratelimit_fail_open: false,
                allow_implicit_routing: true,
            },
            Self::Dev => SecurityPosture {
                allow_unauthenticated_public_bind: true,
                max_upload_bytes: 0,
                allow_site_unix_upstreams: true,
                allow_site_private_upstreams: true,
                max_handler_blob_bytes: 0,
                max_component_bytes: 0,
                oidc_require_audience: false,
                domain_verify_allow_private: true,
                domain_verify_self_serve: true,
                allow_shared_kernel_compute: true,
                ratelimit_fail_open: true,
                allow_implicit_routing: true,
            },
        }
    }
}

/// Individual posture-knob overrides — every field optional, `Some` wins over the
/// profile preset (knobs are the source of truth). Used both as the top-level
/// [`SecurityConfig::overrides`] and as each custom [`SecurityConfig::profiles`]
/// entry (applied over the strict `multi-tenant` baseline). Byte caps: `0` =
/// unlimited.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PostureOverrides {
    /// Permit binding a non-loopback address with control-plane auth disabled.
    pub allow_unauthenticated_public_bind: Option<bool>,
    /// Default blob-upload cap in bytes (`0` = unlimited).
    pub max_upload_bytes: Option<u64>,
    /// Permit site-declared `unix:` gateway upstreams (operator-declared always ok).
    pub allow_site_unix_upstreams: Option<bool>,
    /// Permit site-declared gateway upstreams resolving to private/loopback IPs.
    pub allow_site_private_upstreams: Option<bool>,
    /// Cap on handler blobstore host reads/ranges/copies in bytes (`0` = unlimited).
    pub max_handler_blob_bytes: Option<u64>,
    /// Cap on a Wasm component blob in bytes (`0` = unlimited).
    pub max_component_bytes: Option<u64>,
    /// Require an OIDC audience when OIDC is enabled.
    pub oidc_require_audience: Option<bool>,
    /// Permit HTTP domain-verification probes to private/loopback/metadata hosts.
    pub domain_verify_allow_private: Option<bool>,
    /// Serve pending HTTP ownership challenges at
    /// `/.well-known/boatramp-domain-verification/<token>` directly from the edge
    /// (before host routing), so a host pointed at this server verifies itself
    /// without a prior deploy — the fix for the domain-attach chicken-and-egg. On
    /// by default in every profile (it only ever returns a random token to a host
    /// with a matching pending challenge); an operator can disable it to require
    /// out-of-band token placement instead.
    pub domain_verify_self_serve: Option<bool>,
    /// Permit scheduling untrusted workloads onto shared-kernel compute backends.
    pub allow_shared_kernel_compute: Option<bool>,
    /// Fail **open** (allow) instead of closed when the rate-limit KV is unreadable.
    pub ratelimit_fail_open: Option<bool>,
    /// Serve a site at root for an unmatched `Host` **without** an explicit domain
    /// registration — either by first host label (`<site>.localhost`) or, when
    /// exactly one site is served, as the sole site. A dev/single-operator
    /// convenience; off under `multi-tenant` so a public host can never
    /// implicitly resolve to a site. A loopback bind enables it regardless.
    pub allow_implicit_routing: Option<bool>,
}

/// The raw `[security]` config section as written in `boatramp.cfg` (RON).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Selected profile: a built-in (`multi-tenant` / `single-tenant` / `dev`) or
    /// a name defined under [`profiles`](Self::profiles). Default `multi-tenant`.
    pub profile: Option<String>,
    /// Operator-defined custom profiles: name → overrides over the strict baseline.
    pub profiles: BTreeMap<String, PostureOverrides>,
    /// Individual knob overrides applied over the selected profile (these win).
    pub overrides: PostureOverrides,
}

impl SecurityConfig {
    /// The base posture for a profile name: a built-in preset, or a custom profile
    /// (its overrides applied over the strict `multi-tenant` baseline).
    fn base_for(&self, name: &str) -> Result<SecurityPosture, SecurityError> {
        if let Some(builtin) = SecurityProfile::from_name(name) {
            Ok(builtin.preset())
        } else if let Some(custom) = self.profiles.get(name) {
            Ok(apply(SecurityProfile::MultiTenant.preset(), custom))
        } else {
            Err(SecurityError::UnknownProfile(name.to_string()))
        }
    }

    /// Resolve the configured profile + overrides into a concrete posture.
    pub fn resolve(&self) -> Result<SecurityPosture, SecurityError> {
        let name = self.profile.as_deref().unwrap_or("multi-tenant");
        Ok(apply(self.base_for(name)?, &self.overrides))
    }

    /// Render the resolved posture with each knob's value and source (the profile
    /// preset vs an explicit override), for `boatramp security explain`.
    pub fn explain(&self) -> Result<String, SecurityError> {
        let name = self.profile.as_deref().unwrap_or("multi-tenant");
        let p = self.resolve()?;
        let o = &self.overrides;
        let mut out = String::new();
        let _ = writeln!(out, "security profile: {name}");
        let mut row = |label: &str, value: String, overridden: bool| {
            let src = if overridden { "override" } else { "profile" };
            let _ = writeln!(out, "  {label:<34} {value:<12} ({src})");
        };
        row(
            "allow_unauthenticated_public_bind",
            p.allow_unauthenticated_public_bind.to_string(),
            o.allow_unauthenticated_public_bind.is_some(),
        );
        row(
            "max_upload_bytes",
            fmt_cap(p.max_upload_bytes),
            o.max_upload_bytes.is_some(),
        );
        row(
            "allow_site_unix_upstreams",
            p.allow_site_unix_upstreams.to_string(),
            o.allow_site_unix_upstreams.is_some(),
        );
        row(
            "allow_site_private_upstreams",
            p.allow_site_private_upstreams.to_string(),
            o.allow_site_private_upstreams.is_some(),
        );
        row(
            "max_handler_blob_bytes",
            fmt_cap(p.max_handler_blob_bytes),
            o.max_handler_blob_bytes.is_some(),
        );
        row(
            "max_component_bytes",
            fmt_cap(p.max_component_bytes),
            o.max_component_bytes.is_some(),
        );
        row(
            "oidc_require_audience",
            p.oidc_require_audience.to_string(),
            o.oidc_require_audience.is_some(),
        );
        row(
            "domain_verify_allow_private",
            p.domain_verify_allow_private.to_string(),
            o.domain_verify_allow_private.is_some(),
        );
        row(
            "domain_verify_self_serve",
            p.domain_verify_self_serve.to_string(),
            o.domain_verify_self_serve.is_some(),
        );
        row(
            "allow_shared_kernel_compute",
            p.allow_shared_kernel_compute.to_string(),
            o.allow_shared_kernel_compute.is_some(),
        );
        row(
            "ratelimit_fail_open",
            p.ratelimit_fail_open.to_string(),
            o.ratelimit_fail_open.is_some(),
        );
        row(
            "allow_implicit_routing",
            p.allow_implicit_routing.to_string(),
            o.allow_implicit_routing.is_some(),
        );
        Ok(out)
    }
}

/// The **resolved** security posture: every knob a concrete value. [`Default`] is
/// the strict `multi-tenant` preset, so a server with no `[security]` section —
/// and any code path that defaults this — is locked down. Byte caps: `0` =
/// unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPosture {
    /// Permit binding a non-loopback address with control-plane auth disabled.
    pub allow_unauthenticated_public_bind: bool,
    /// Default blob-upload cap in bytes, `0` = unlimited.
    pub max_upload_bytes: u64,
    /// Permit site-declared `unix:` gateway upstreams.
    pub allow_site_unix_upstreams: bool,
    /// Permit site-declared gateway upstreams to private/loopback IPs.
    pub allow_site_private_upstreams: bool,
    /// Cap on handler blobstore host reads/ranges/copies, `0` = unlimited.
    pub max_handler_blob_bytes: u64,
    /// Cap on a Wasm component blob, `0` = unlimited.
    pub max_component_bytes: u64,
    /// Require an OIDC audience when OIDC is enabled.
    pub oidc_require_audience: bool,
    /// Permit HTTP domain-verification probes to private hosts.
    pub domain_verify_allow_private: bool,
    /// Serve pending HTTP ownership challenges from the edge before host routing
    /// (the domain-attach chicken-and-egg fix).
    pub domain_verify_self_serve: bool,
    /// Permit untrusted workloads on shared-kernel compute backends.
    pub allow_shared_kernel_compute: bool,
    /// Fail open instead of closed on rate-limit KV errors.
    pub ratelimit_fail_open: bool,
    /// Resolve an unmatched `Host` to a site without an explicit domain
    /// registration (first-label `<site>.host` or the sole served site). Off
    /// under `multi-tenant`; a loopback bind enables it regardless.
    pub allow_implicit_routing: bool,
}

impl Default for SecurityPosture {
    fn default() -> Self {
        SecurityProfile::MultiTenant.preset()
    }
}

/// Apply a set of overrides over a base posture (each `Some` field wins).
fn apply(mut base: SecurityPosture, o: &PostureOverrides) -> SecurityPosture {
    if let Some(v) = o.allow_unauthenticated_public_bind {
        base.allow_unauthenticated_public_bind = v;
    }
    if let Some(v) = o.max_upload_bytes {
        base.max_upload_bytes = v;
    }
    if let Some(v) = o.allow_site_unix_upstreams {
        base.allow_site_unix_upstreams = v;
    }
    if let Some(v) = o.allow_site_private_upstreams {
        base.allow_site_private_upstreams = v;
    }
    if let Some(v) = o.max_handler_blob_bytes {
        base.max_handler_blob_bytes = v;
    }
    if let Some(v) = o.max_component_bytes {
        base.max_component_bytes = v;
    }
    if let Some(v) = o.oidc_require_audience {
        base.oidc_require_audience = v;
    }
    if let Some(v) = o.domain_verify_allow_private {
        base.domain_verify_allow_private = v;
    }
    if let Some(v) = o.domain_verify_self_serve {
        base.domain_verify_self_serve = v;
    }
    if let Some(v) = o.allow_shared_kernel_compute {
        base.allow_shared_kernel_compute = v;
    }
    if let Some(v) = o.ratelimit_fail_open {
        base.ratelimit_fail_open = v;
    }
    if let Some(v) = o.allow_implicit_routing {
        base.allow_implicit_routing = v;
    }
    base
}

/// Render a byte cap for `explain` (`0` shows as `unlimited`).
fn fmt_cap(bytes: u64) -> String {
    if bytes == 0 {
        "unlimited".to_string()
    } else {
        bytes.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_posture_is_multi_tenant_strict() {
        let p = SecurityPosture::default();
        assert_eq!(p, SecurityProfile::MultiTenant.preset());
        assert!(!p.allow_unauthenticated_public_bind);
        assert!(!p.allow_site_unix_upstreams);
        assert!(!p.allow_site_private_upstreams);
        assert!(p.oidc_require_audience);
        assert!(!p.domain_verify_allow_private);
        assert!(p.domain_verify_self_serve);
        assert!(!p.allow_shared_kernel_compute);
        assert!(!p.ratelimit_fail_open);
        assert!(!p.allow_implicit_routing);
        assert_eq!(p.max_upload_bytes, MT_MAX_UPLOAD);
    }

    #[test]
    fn empty_config_resolves_to_multi_tenant() {
        let resolved = SecurityConfig::default().resolve().unwrap();
        assert_eq!(resolved, SecurityProfile::MultiTenant.preset());
    }

    #[test]
    fn dev_profile_is_loose() {
        let cfg = SecurityConfig {
            profile: Some("dev".into()),
            ..Default::default()
        };
        let p = cfg.resolve().unwrap();
        assert!(p.allow_unauthenticated_public_bind);
        assert!(!p.oidc_require_audience);
        assert_eq!(p.max_upload_bytes, 0); // unlimited
        assert!(p.ratelimit_fail_open);
        assert!(p.allow_implicit_routing);
    }

    #[test]
    fn override_beats_profile() {
        // `dev` disables OIDC audience; an explicit override re-requires it.
        let cfg = SecurityConfig {
            profile: Some("dev".into()),
            overrides: PostureOverrides {
                oidc_require_audience: Some(true),
                max_upload_bytes: Some(123),
                ..Default::default()
            },
            ..Default::default()
        };
        let p = cfg.resolve().unwrap();
        assert!(
            p.oidc_require_audience,
            "override must win over the profile"
        );
        assert_eq!(p.max_upload_bytes, 123);
        // A non-overridden knob still follows the dev preset.
        assert!(p.allow_unauthenticated_public_bind);
    }

    #[test]
    fn custom_profile_layers_over_multi_tenant_baseline() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "ci".to_string(),
            PostureOverrides {
                allow_unauthenticated_public_bind: Some(true),
                ..Default::default()
            },
        );
        let cfg = SecurityConfig {
            profile: Some("ci".into()),
            profiles,
            ..Default::default()
        };
        let p = cfg.resolve().unwrap();
        // The custom knob is set...
        assert!(p.allow_unauthenticated_public_bind);
        // ...but everything else stays at the strict multi-tenant baseline.
        assert!(!p.allow_site_private_upstreams);
        assert!(p.oidc_require_audience);
    }

    #[test]
    fn unknown_profile_errors() {
        let cfg = SecurityConfig {
            profile: Some("nope".into()),
            ..Default::default()
        };
        assert!(matches!(
            cfg.resolve(),
            Err(SecurityError::UnknownProfile(name)) if name == "nope"
        ));
    }

    #[test]
    fn explain_marks_value_source() {
        let cfg = SecurityConfig {
            profile: Some("multi-tenant".into()),
            overrides: PostureOverrides {
                max_upload_bytes: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let text = cfg.explain().unwrap();
        assert!(text.contains("security profile: multi-tenant"));
        // The overridden knob is marked (override) and 0 renders as unlimited.
        assert!(text.lines().any(|l| l.contains("max_upload_bytes")
            && l.contains("unlimited")
            && l.contains("override")));
        // A non-overridden knob is marked (profile).
        assert!(text
            .lines()
            .any(|l| l.contains("oidc_require_audience") && l.contains("profile")));
    }
}
