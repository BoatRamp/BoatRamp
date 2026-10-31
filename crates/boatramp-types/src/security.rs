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

use serde::{Deserialize, Serialize};

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

impl std::fmt::Display for SecurityProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SecurityProfile {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| SecurityError::UnknownProfile(s.to_string()))
    }
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
                allow_guest_private_egress: false,
                allow_guest_self_egress: true,
                allow_guest_egress_extra_ca: false,
                allow_guest_tcp_egress: false,
                allow_guest_tcp_listener: false,
                allow_guest_dns_publish: false,
                // A multi-tenant guest may NOT delegate a sub-zone NS to any nameserver (MEDIUM-3).
                guest_dns_publish_ns: GuestDnsPublishNs::None,
                max_handler_blob_bytes: MT_MAX_BLOB,
                max_component_bytes: MT_MAX_COMPONENT,
                oidc_require_audience: true,
                domain_verify_allow_private: false,
                domain_verify_self_serve: true,
                allow_shared_kernel_compute: false,
                allow_compute_exec: false,
                allow_dev_blob_bind: false,
                allow_dev_messaging_bind: false,
                ratelimit_fail_open: false,
                allow_implicit_routing: false,
                require_pop: false,
                require_domain_verification: true,
                allow_env_secret_refs: false,
                allow_guest_email: false,
                allow_guest_mint_capability: false,
                max_guest_capability_ttl_secs: 900,
                allow_guest_admin_domains: false,
                allow_guest_admin_email: false,
                allow_guest_admin_site: false,
                allow_guest_admin_secrets: false,
                require_tenancy_declaration: true,
                allow_cross_tenant_db: false,
            },
            Self::SingleTenant => SecurityPosture {
                allow_unauthenticated_public_bind: false,
                max_upload_bytes: ST_MAX_UPLOAD,
                allow_site_unix_upstreams: true,
                allow_site_private_upstreams: true,
                allow_guest_private_egress: true,
                allow_guest_self_egress: true,
                allow_guest_egress_extra_ca: true,
                allow_guest_tcp_egress: true,
                allow_guest_tcp_listener: true,
                // A new, security-sensitive zone-write surface: OFF even on single-tenant until the
                // operator opts in explicitly (its Security review gates the broader default).
                allow_guest_dns_publish: false,
                // A single operator who owns every site may delegate a sub-zone NS, but only to a
                // nameserver on the per-grant allowlist (never an arbitrary target) — MEDIUM-3.
                guest_dns_publish_ns: GuestDnsPublishNs::Allowlist,
                max_handler_blob_bytes: ST_MAX_BLOB,
                max_component_bytes: ST_MAX_COMPONENT,
                oidc_require_audience: true,
                domain_verify_allow_private: true,
                domain_verify_self_serve: true,
                allow_shared_kernel_compute: true,
                allow_compute_exec: false,
                allow_dev_blob_bind: false,
                allow_dev_messaging_bind: false,
                ratelimit_fail_open: false,
                allow_implicit_routing: true,
                require_pop: false,
                require_domain_verification: true,
                allow_env_secret_refs: true,
                allow_guest_email: true,
                allow_guest_mint_capability: true,
                max_guest_capability_ttl_secs: 3600,
                allow_guest_admin_domains: true,
                allow_guest_admin_email: true,
                allow_guest_admin_site: true,
                allow_guest_admin_secrets: true,
                require_tenancy_declaration: false,
                allow_cross_tenant_db: true,
            },
            Self::Dev => SecurityPosture {
                allow_unauthenticated_public_bind: true,
                max_upload_bytes: 0,
                allow_site_unix_upstreams: true,
                allow_site_private_upstreams: true,
                allow_guest_private_egress: true,
                allow_guest_self_egress: true,
                allow_guest_egress_extra_ca: true,
                allow_guest_tcp_egress: true,
                allow_guest_tcp_listener: true,
                // Off even under dev — a guest `dns-publish` would mutate REAL external DNS (the
                // provider credential is real); an operator opts in explicitly.
                allow_guest_dns_publish: false,
                // Dev is loopback-loose: once an operator opts `dns-publish` on, a sub-zone NS may
                // delegate to any target (MEDIUM-3). The apex-NS guardrail still applies.
                guest_dns_publish_ns: GuestDnsPublishNs::Any,
                max_handler_blob_bytes: 0,
                max_component_bytes: 0,
                oidc_require_audience: false,
                domain_verify_allow_private: true,
                domain_verify_self_serve: true,
                allow_shared_kernel_compute: true,
                allow_compute_exec: true,
                allow_dev_blob_bind: true,
                allow_dev_messaging_bind: true,
                ratelimit_fail_open: true,
                allow_implicit_routing: true,
                require_pop: false,
                // Dev serves arbitrary test hosts locally; the gate is off.
                require_domain_verification: false,
                allow_env_secret_refs: true,
                allow_guest_email: true,
                allow_guest_mint_capability: true,
                max_guest_capability_ttl_secs: 3600,
                allow_guest_admin_domains: true,
                allow_guest_admin_email: true,
                allow_guest_admin_site: true,
                allow_guest_admin_secrets: true,
                require_tenancy_declaration: false,
                allow_cross_tenant_db: true,
            },
        }
    }
}

/// Operator posture (Security review MEDIUM-3, cap-req #24) governing whether a granted guest may
/// WRITE a **(non-apex) sub-zone `NS`** record via `dns-publish` — a record that delegates that
/// subtree to an ARBITRARY nameserver, a persistent, post-revocation, unaudited authority handoff.
/// The apex `NS` is ALWAYS refused by the central `validate_writable` guardrail regardless of this
/// knob; this knob gates only the sub-zone delegation. It is an NS-SPECIFIC constraint layered ON TOP
/// of the per-grant own-name writable-zone allowlist (which is unchanged — still own-name-only): the
/// own-name allowlist authorizes WHERE the NS record lives, this knob authorizes the NS record's rdata
/// TARGET nameserver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestDnsPublishNs {
    /// Delegate a sub-zone to ANY nameserver target (the pre-MEDIUM-3 behavior). The `dev` default.
    Any,
    /// NEVER delegate a sub-zone `NS` — a multi-tenant guest may not hand off a subtree at all. The
    /// `multi-tenant` default, and the fail-closed [`Default`].
    #[default]
    None,
    /// Delegate only to an operator-sanctioned nameserver in the per-grant
    /// [`dns_publish_ns_targets`](crate::config::HandlerConfig::dns_publish_ns_targets) allowlist
    /// (**empty ⇒ deny-all**, fail-closed). The `single-tenant` default.
    Allowlist,
}

impl GuestDnsPublishNs {
    /// The canonical token for `security explain`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::None => "none",
            Self::Allowlist => "allowlist",
        }
    }
}

/// Individual posture-knob overrides — every field optional, `Some` wins over the
/// profile preset (knobs are the source of truth). Used both as the top-level
/// [`SecurityConfig::overrides`] and as each custom [`SecurityConfig::profiles`]
/// entry (applied over the strict `multi-tenant` baseline). Byte caps: `0` =
/// unlimited.
// `Serialize` (alongside `Deserialize`) lets a test enumerate every field name to assert each has a
// `BOATRAMP_SECURITY_*` env mapping — the guard against silently forgetting an env knob (the exact
// gap v0.4.18 closed). Serializing is otherwise unused; `None` fields render as null.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
    /// Permit a guest handler's outbound `wasi:http` to reach private/loopback IPs.
    pub allow_guest_private_egress: Option<bool>,
    /// Permit a guest handler's outbound `wasi:http` to reach this instance's own serve socket.
    pub allow_guest_self_egress: Option<bool>,
    /// Permit a guest handler's outbound `wasi:http` TLS client to trust an operator-supplied EXTRA
    /// CA (`guest_egress_extra_ca_file`), on top of the webpki roots — a dev/single-tenant lever for
    /// a hermetic HTTPS test double. Verification is still fully performed; this only widens the CA
    /// set. Off (and refused) under `multi-tenant`. No effect unless a CA file is also configured.
    pub allow_guest_egress_extra_ca: Option<bool>,
    /// Permit a guest handler's gated `wasi:sockets` capability to open an outbound TCP `connect`.
    /// Off under `multi-tenant`; on under `single-tenant`/`dev`. See
    /// [`SecurityPosture::allow_guest_tcp_egress`].
    pub allow_guest_tcp_egress: Option<bool>,
    /// Permit host-owned inbound-TCP **listeners** to dispatch an accepted connection to a guest.
    /// Off under `multi-tenant`; on under `single-tenant`/`dev`. Independent of
    /// `allow_guest_tcp_egress` (inbound ≠ outbound). See
    /// [`SecurityPosture::allow_guest_tcp_listener`].
    pub allow_guest_tcp_listener: Option<bool>,
    /// Permit a **guest**'s `dns-publish` capability to WRITE DNS records through a host-held provider
    /// credential (cap-req #24). **Off** in every built-in profile — a new, security-sensitive
    /// zone-write surface; an operator opts in explicitly. Independent of the egress knobs (DNS write
    /// is a distinct authority). See [`SecurityPosture::allow_guest_dns_publish`].
    pub allow_guest_dns_publish: Option<bool>,
    /// Posture for a guest's **sub-zone `NS` delegation** via `dns-publish` (Security review MEDIUM-3):
    /// `none` (refuse all sub-zone NS), `allowlist` (only an NS target on the per-grant
    /// `dns_publish_ns_targets` allowlist), or `any` (today's behavior). See
    /// [`SecurityPosture::guest_dns_publish_ns`].
    pub guest_dns_publish_ns: Option<GuestDnsPublishNs>,
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
    /// Permit `boatramp compute exec` — running a command inside a running workload
    /// (docker-exec style). Arbitrary code execution in the workload, so **off** in
    /// every profile but `dev`; an operator opts in for migrations/backups/debug.
    pub allow_compute_exec: Option<bool>,
    /// Permit `boatramp compute bind-blob` — minting a blob-shim `BOATRAMP_BLOB_URL` +
    /// token for a **non-managed** local process (a dev/CI test-harness affordance so a
    /// locally-run native binary shares a site's blob namespace, the blob analogue of
    /// pointing a process at `DATABASE_URL`). It hands a site-scoped credential to a
    /// process OUTSIDE the sandboxed-workload model, so **off** in every profile but
    /// `dev`; a single-tenant CI node opts in explicitly.
    pub allow_dev_blob_bind: Option<bool>,
    /// Permit `boatramp compute bind-messaging` — minting a messaging-shim
    /// `BOATRAMP_MESSAGING_URL` + token for a **non-managed** local process (a dev/CI
    /// test-harness affordance so a locally-run native binary publishes to AND consumes
    /// (claim/ack/nack) a project's `{project}/bus/<topic>` bus, the messaging analogue of
    /// `DATABASE_URL`). It hands a project-bus-scoped credential to a process OUTSIDE the
    /// sandboxed-workload model, so **off** in every profile but `dev`; a single-tenant CI node
    /// opts in explicitly. The direct analogue of [`Self::allow_dev_blob_bind`].
    pub allow_dev_messaging_bind: Option<bool>,
    /// Fail **open** (allow) instead of closed when the rate-limit KV is unreadable.
    pub ratelimit_fail_open: Option<bool>,
    /// Serve a site at root for an unmatched `Host` **without** an explicit domain
    /// registration — either by first host label (`<site>.localhost`) or, when
    /// exactly one site is served, as the sole site. A dev/single-operator
    /// convenience; off under `multi-tenant` so a public host can never
    /// implicitly resolve to a site. A loopback bind enables it regardless.
    pub allow_implicit_routing: Option<bool>,
    /// Require **every** control-plane token to carry a holder key (`cnf`) and to
    /// present a valid per-request proof-of-possession (DPoP-style). Off by default
    /// (a `cnf` token *always* requires a proof regardless — this knob additionally
    /// bans plain bearer tokens fleet-wide, so a leaked bearer alone is inert).
    pub require_pop: Option<bool>,
    /// Refuse to serve a non-local `Host` that isn't a verified, attached
    /// virtualhost (serve the pending page instead). On under multi-/single-tenant.
    /// Setting `false` here (file + restart) disables the gate fleet-wide; a single
    /// host is excluded instead with an admin `domain add <host> --unverified`.
    pub require_domain_verification: Option<bool>,
    /// Permit a site handler's `[handlers].secrets` / a function's `secrets` map to
    /// name a **bare** / `env:`-scheme reference into the serve process's own
    /// environment. Such a reference reads the *operator's* namespace, so it is only
    /// safe when the config author IS the operator. On under `single-tenant`/`dev`;
    /// **off** under `multi-tenant`, where an untrusted tenant authors the map and a
    /// permitted bare ref would let them exfiltrate any host env var (another
    /// tenant's DB password, a cloud key) into their guest.
    pub allow_env_secret_refs: Option<bool>,
    /// Permit a guest handler/function's `email` capability to send. Off under
    /// `multi-tenant`; on under `single-tenant`/`dev`.
    pub allow_guest_email: Option<bool>,
    /// Permit a guest's `capability` capability to MINT fleet-signed target-capability tokens
    /// (PLAN-delegable-capabilities). Off under `multi-tenant`; on under `single-tenant`/`dev`.
    pub allow_guest_mint_capability: Option<bool>,
    /// The operator's ceiling on the TTL (seconds) a guest-minted capability may request (R5). A
    /// mint requesting more is clamped to this value.
    pub max_guest_capability_ttl_secs: Option<u64>,
    /// Permit a guest's `admin` capability to manage the project's domains.
    pub allow_guest_admin_domains: Option<bool>,
    /// Permit a guest's `admin` capability to manage the project's SMTP email profiles.
    pub allow_guest_admin_email: Option<bool>,
    /// Permit a guest's `admin` capability to write the project's site config + aliases.
    pub allow_guest_admin_site: Option<bool>,
    /// Permit a guest's `admin` capability to write the project's sealed secrets.
    pub allow_guest_admin_secrets: Option<bool>,
    /// Require an explicit in-site tenancy decision from sql/orm importers.
    pub require_tenancy_declaration: Option<bool>,
    /// Permit an in-site tenancy grant to reach across tenants (`all`).
    pub allow_cross_tenant_db: Option<bool>,
}

/// A **per-project** override (Gap 4a) of the tenancy/capability posture sub-knobs, from
/// `[security.projects.<project>]` in `boatramp.cfg`. ONLY these four knobs are per-project; the
/// rest of the posture (egress, upload caps, domain verification, …) stays fleet-wide node policy.
///
/// A per-project override tunes only that project's OWN in-project tenancy strictness + its guests'
/// capability-mint ceiling. It can never widen reach into **another** project — cross-project
/// isolation is structural (project = database), not a posture knob. So one serve process can host a
/// strict-isolation project alongside a looser one on a shared, multi-project machine.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectPostureOverride {
    /// Override [`SecurityPosture::require_tenancy_declaration`] for this project.
    pub require_tenancy_declaration: Option<bool>,
    /// Override [`SecurityPosture::allow_cross_tenant_db`] for this project.
    pub allow_cross_tenant_db: Option<bool>,
    /// Override [`SecurityPosture::allow_guest_mint_capability`] for this project.
    pub allow_guest_mint_capability: Option<bool>,
    /// Override [`SecurityPosture::max_guest_capability_ttl_secs`] for this project.
    pub max_guest_capability_ttl_secs: Option<u64>,
}

/// The resolved per-project tenancy/capability knobs (base posture ⊕ an optional project override),
/// consulted at each in-project enforcement point (tenancy declaration, cross-tenant `all`, guest
/// capability minting). Cheap `Copy` so it can be looked up per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedProjectTenancy {
    /// Whether a sql/orm importer in this project must declare an explicit tenancy decision.
    pub require_tenancy_declaration: bool,
    /// Whether an `all` in-site grant may reach across sub-tenants within this project's database.
    pub allow_cross_tenant_db: bool,
    /// `Some(ttl)` ⇒ guest capability minting is enabled for this project, clamped to `ttl` seconds;
    /// `None` ⇒ minting disabled (a guest `mint` is `access-denied`).
    pub capability_max_ttl_secs: Option<u64>,
}

/// The raw `[security]` config section as written in `boatramp.cfg` (RON).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Selected profile: a built-in (`multi-tenant` / `single-tenant` / `dev`) or
    /// a name defined under [`profiles`](Self::profiles). Default `multi-tenant`.
    pub profile: Option<String>,
    /// Operator-defined custom profiles: name → overrides over the strict baseline.
    pub profiles: BTreeMap<String, PostureOverrides>,
    /// Individual knob overrides applied over the selected profile (these win).
    pub overrides: PostureOverrides,
    /// **Per-project** overrides (Gap 4a) of the tenancy/capability sub-knobs — project name →
    /// override. Layered over the resolved fleet posture for that project only; every other project
    /// (and every non-tenancy knob) uses the fleet posture. Lets a shared, multi-project serve
    /// process run e.g. a strict-isolation production project alongside a looser preview project.
    pub projects: BTreeMap<String, ProjectPostureOverride>,
    /// **Node-absolute egress-host allowlist for the PROJECT gateway tier** (two-tier gateway /
    /// cap-req 0.37.0) — the global admin's floor. When non-empty, a `project.cfg`-declared gateway
    /// upstream with a RAW target (not its own compute, not a shared-site grant) may only reach a host
    /// matching one of these globs, on TOP of the public-only IP bright line and the site operator's
    /// `GatewaySiteCaps.project_egress_hosts`. A site operator can only NARROW within this, never widen
    /// past it. Empty (default) ⇒ no node-level host restriction (the IP bright line + any site
    /// allowlist still apply). Globs match as [`crate::gateway::gateway_host_matches`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_egress_allow: Vec<String>,
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
            "allow_guest_private_egress",
            p.allow_guest_private_egress.to_string(),
            o.allow_guest_private_egress.is_some(),
        );
        row(
            "allow_guest_self_egress",
            p.allow_guest_self_egress.to_string(),
            o.allow_guest_self_egress.is_some(),
        );
        row(
            "allow_guest_egress_extra_ca",
            p.allow_guest_egress_extra_ca.to_string(),
            o.allow_guest_egress_extra_ca.is_some(),
        );
        row(
            "allow_guest_tcp_egress",
            p.allow_guest_tcp_egress.to_string(),
            o.allow_guest_tcp_egress.is_some(),
        );
        row(
            "allow_guest_tcp_listener",
            p.allow_guest_tcp_listener.to_string(),
            o.allow_guest_tcp_listener.is_some(),
        );
        row(
            "allow_guest_dns_publish",
            p.allow_guest_dns_publish.to_string(),
            o.allow_guest_dns_publish.is_some(),
        );
        row(
            "guest_dns_publish_ns",
            p.guest_dns_publish_ns.as_str().to_string(),
            o.guest_dns_publish_ns.is_some(),
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
            "allow_compute_exec",
            p.allow_compute_exec.to_string(),
            o.allow_compute_exec.is_some(),
        );
        row(
            "allow_dev_blob_bind",
            p.allow_dev_blob_bind.to_string(),
            o.allow_dev_blob_bind.is_some(),
        );
        row(
            "allow_dev_messaging_bind",
            p.allow_dev_messaging_bind.to_string(),
            o.allow_dev_messaging_bind.is_some(),
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
        row(
            "require_pop",
            p.require_pop.to_string(),
            o.require_pop.is_some(),
        );
        row(
            "allow_env_secret_refs",
            p.allow_env_secret_refs.to_string(),
            o.allow_env_secret_refs.is_some(),
        );
        row(
            "allow_guest_email",
            p.allow_guest_email.to_string(),
            o.allow_guest_email.is_some(),
        );
        row(
            "allow_guest_mint_capability",
            p.allow_guest_mint_capability.to_string(),
            o.allow_guest_mint_capability.is_some(),
        );
        row(
            "max_guest_capability_ttl_secs",
            p.max_guest_capability_ttl_secs.to_string(),
            o.max_guest_capability_ttl_secs.is_some(),
        );
        row(
            "allow_guest_admin_domains",
            p.allow_guest_admin_domains.to_string(),
            o.allow_guest_admin_domains.is_some(),
        );
        row(
            "allow_guest_admin_email",
            p.allow_guest_admin_email.to_string(),
            o.allow_guest_admin_email.is_some(),
        );
        row(
            "allow_guest_admin_site",
            p.allow_guest_admin_site.to_string(),
            o.allow_guest_admin_site.is_some(),
        );
        row(
            "allow_guest_admin_secrets",
            p.allow_guest_admin_secrets.to_string(),
            o.allow_guest_admin_secrets.is_some(),
        );
        row(
            "require_tenancy_declaration",
            p.require_tenancy_declaration.to_string(),
            o.require_tenancy_declaration.is_some(),
        );
        row(
            "allow_cross_tenant_db",
            p.allow_cross_tenant_db.to_string(),
            o.allow_cross_tenant_db.is_some(),
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
    /// Permit a **guest** handler's outbound `wasi:http` to reach a private/loopback/
    /// link-local address. Off under `multi-tenant` (the SSRF default — a guest can only
    /// reach globally-routable hosts); on under `single-tenant`/`dev`. This is the guest
    /// egress analog of [`allow_site_private_upstreams`](Self::allow_site_private_upstreams)
    /// (which gates *operator-declared* gateway upstreams, a different path). It does **not**
    /// cover a guest calling its own site — that is served in-process, host-asserted, and is
    /// never treated as private egress.
    pub allow_guest_private_egress: bool,
    /// Permit a **guest** handler's outbound `wasi:http` to reach **this instance's own HTTP
    /// serve socket** (loopback / the bind address on the serve port) even when
    /// [`allow_guest_private_egress`](Self::allow_guest_private_egress) is off. A much tighter
    /// grant than opening the whole private range: the only reachable internal target is
    /// boatramp's own front door, which re-enters the full pipeline (host routing, visitor
    /// auth, rate-limit, DV) — so a guest reaches only what any anonymous client could. A
    /// self-recursion is bounded by a process-stamped depth cap. **On** by default in every
    /// posture. (For depth-capped, allowlisted function-to-function calls, prefer the `invoke`
    /// binding, which is unaffected by any egress knob.)
    pub allow_guest_self_egress: bool,
    /// Whether a guest's outbound `wasi:http` TLS client trusts an operator-supplied EXTRA CA
    /// (`guest_egress_extra_ca_file`) on top of the webpki roots. Off under `multi-tenant`; a
    /// trusted single-tenant/dev fleet may opt in (e.g. to reach a hermetic HTTPS test double under
    /// a test CA). Verification is still fully performed — this only widens the accepted CA set.
    pub allow_guest_egress_extra_ca: bool,
    /// Permit a **guest** handler's gated `wasi:sockets` capability to open an **outbound TCP
    /// `connect`** (`PLAN-handler-tcp-egress`). Off under `multi-tenant` (the deny-by-default: with
    /// this off the engine installs NO permissive `socket_addr_check`, so the socket host's deny-all
    /// default stands and every connect fails closed at RUNTIME — the capability is NOT refused at
    /// deploy in this stage); on under `single-tenant`/`dev`. This is only the posture gate — a
    /// granted handler still reaches
    /// ONLY its per-handler [`egress_allowlist`](crate::config::HandlerConfig::egress_allowlist)
    /// (empty ⇒ nothing), only `connect` (never `bind`/`listen` — inbound stays the container/
    /// microVM model), and even an allowlisted target is held to the `is_global_ip` SSRF floor
    /// unless [`allow_guest_private_egress`](Self::allow_guest_private_egress) is separately on. Any
    /// single wiring omission fails CLOSED.
    pub allow_guest_tcp_egress: bool,
    /// Permit host-owned inbound-TCP **listeners** (`[serve.listeners.<name>]`) to dispatch an
    /// accepted connection to a guest `tcp-connection-handler` (`PLAN-handler-tcp-inbound`). Off under
    /// `multi-tenant` (deny-by-default: a new, unproven surface — an untrusted site writer would
    /// process arbitrary inbound bytes with no HTTP framing / WAF / visitor-auth, even though the HOST
    /// owns the socket); on under `single-tenant`/`dev` (the operator owns every site, parity with
    /// `allow_guest_tcp_egress`). INDEPENDENT of `allow_guest_tcp_egress` (inbound ≠ outbound
    /// authority). This is ONLY the posture gate: the operator must ALSO declare the listener in
    /// `[serve.listeners.<name>]`, and the guest is handed only the accepted connection's `wasi:io`
    /// streams — it NEVER receives `wasi:sockets` (bind/listen/connect stay host-side). Off ⇒ the
    /// serve accept loop never binds AND [`dispatch_tcp_connection`] refuses; any single wiring
    /// omission fails CLOSED.
    pub allow_guest_tcp_listener: bool,
    /// Permit a **guest**'s `dns-publish` capability to WRITE DNS records (cap-req #24): the guest
    /// NAMES a zone/record and the host performs the mutation through an operator-configured, host-held
    /// `DnsProvider` credential (the guest never holds a zone-write token). `false` (the default in
    /// EVERY built-in profile) makes the `DnsPublishHost` binding fail-closed to `access-denied` for
    /// every call, regardless of grant or per-grant writable-zone allowlist. `true` lets a granted
    /// component mutate within its allowlist (own-name only, never the rdata target), still bounded by
    /// the per-invocation publish budget and the central `validate_writable` guardrail (apex-NS /
    /// supported-kind / malformed-rdata refusal). A new, security-sensitive write surface, so OFF by
    /// default even on `single-tenant`/`dev` — an operator opts in explicitly. INDEPENDENT of every
    /// egress knob (DNS write is a distinct authority). Any single wiring omission fails CLOSED.
    pub allow_guest_dns_publish: bool,
    /// The posture governing a guest's **sub-zone `NS` delegation** via `dns-publish` (Security review
    /// MEDIUM-3, cap-req #24). A sub-zone NS hands a subtree to an arbitrary nameserver — a persistent,
    /// post-revocation, unaudited authority handoff — so it is gated SEPARATELY from the own-name
    /// writable-zone allowlist: [`GuestDnsPublishNs::None`] refuses every sub-zone NS;
    /// [`GuestDnsPublishNs::Allowlist`] permits only an NS whose rdata TARGET nameserver matches the
    /// per-grant `dns_publish_ns_targets` allowlist (empty ⇒ deny-all); [`GuestDnsPublishNs::Any`] is
    /// the pre-MEDIUM-3 behavior. Defaults: `none` (multi-tenant), `allowlist` (single-tenant), `any`
    /// (dev). Applies ONLY to a non-apex NS — the apex NS is always refused by the central guardrail —
    /// and ONLY to the NS record type; every other record (A/MX/CNAME/…) is unaffected and still gated
    /// solely by the own-name allowlist.
    pub guest_dns_publish_ns: GuestDnsPublishNs,
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
    /// Permit `boatramp compute exec` (run a command inside a running workload).
    pub allow_compute_exec: bool,
    /// Permit `boatramp compute bind-blob` (mint a blob-shim URL + token for a
    /// non-managed local process — a dev/CI affordance; off outside `dev`).
    pub allow_dev_blob_bind: bool,
    /// Permit `boatramp compute bind-messaging` (mint a messaging-shim URL + token for a
    /// non-managed local process — a dev/CI affordance; off outside `dev`).
    pub allow_dev_messaging_bind: bool,
    /// Fail open instead of closed on rate-limit KV errors.
    pub ratelimit_fail_open: bool,
    /// Resolve an unmatched `Host` to a site without an explicit domain
    /// registration (first-label `<site>.host` or the sole served site). Off
    /// under `multi-tenant`; a loopback bind enables it regardless.
    pub allow_implicit_routing: bool,
    /// Require every control-plane token to be `cnf`-bound and PoP-proven
    /// (fleet-wide holder-key enforcement). Off by default.
    pub require_pop: bool,
    /// Refuse to serve a **non-local** `Host` that is not a verified, attached
    /// virtualhost — the request gets the "verification pending" holding page
    /// instead of any `default_site`/implicit fallback. On under multi-/single-
    /// tenant; off under `dev`. Local hosts (`localhost`/`*.localhost`/`*.local`/
    /// IP literals) always serve. An operator disables it globally in
    /// `[security]`, or excludes one host with an admin `domain add --unverified`.
    pub require_domain_verification: bool,
    /// Permit a site handler's / function's `secrets` map to resolve a **bare** or
    /// `env:`-scheme reference against the serve process's own environment. That
    /// namespace is the *operator's*, so a bare ref is only safe when the config
    /// author IS the operator: on under `single-tenant`/`dev`, **off** under
    /// `multi-tenant`. When off, `resolve_secret_env` refuses such a ref (fail-closed)
    /// instead of injecting the host value, so an untrusted tenant can't name an
    /// arbitrary host env var to exfiltrate it across the tenant boundary.
    pub allow_env_secret_refs: bool,
    /// Permit a **guest** handler/function's `email` capability to actually send
    /// (bind the `send` verb). Off under `multi-tenant` — an untrusted tenant can't
    /// use the shared node's SMTP egress until the operator opts in — and on under
    /// `single-tenant`/`dev`. Independent of the guest-HTTP egress knobs: email is a
    /// host-mediated SMTP connection whose credentials the guest never sees (a
    /// separate path), so it is gated separately. When off, the binding is absent
    /// and `send` returns `access-denied`. The SMTP relay host is additionally held
    /// to the SSRF rule (a private/loopback relay is refused unless
    /// [`allow_guest_private_egress`](Self::allow_guest_private_egress) is on).
    pub allow_guest_email: bool,
    /// Permit a **guest**'s `capability` capability to MINT fleet-signed target-capability tokens
    /// (`boatramp:handlers/capability`, PLAN-delegable-capabilities). A minted token is bounded:
    /// its audience is host-forced to the guest's OWN project (never redeemable elsewhere), its TTL
    /// is clamped to [`max_guest_capability_ttl_secs`](Self::max_guest_capability_ttl_secs), and its
    /// power is fully gated at redeem by the operator's target-eligible route config (a token is inert
    /// anywhere no matching `via:[capability]` route is opened). Off under `multi-tenant` (an untrusted
    /// tenant can't mint); on under `single-tenant`/`dev`. When off, the binding is absent and `mint`
    /// returns `access-denied`.
    pub allow_guest_mint_capability: bool,
    /// The operator's ceiling (seconds) on a guest-minted capability's TTL (R5). A `mint` requesting a
    /// larger TTL is clamped to this; `0` disables minting (any request is refused). Defaults to 1h.
    pub max_guest_capability_ttl_secs: u64,
    /// Permit a **guest**'s `admin` capability to manage the project's **domains** (add /
    /// verify / attach-verified / remove) via `boatramp:handlers/admin`. Off under
    /// `multi-tenant`, on under `single-tenant`/`dev`. Per-surface + operator-set (a tenant
    /// can't turn it on via site config); domain attach still runs the real ownership probe,
    /// and there is no guest path to the unverified-attach admin route.
    pub allow_guest_admin_domains: bool,
    /// Permit a guest's `admin` capability to manage the project's **SMTP email profiles**
    /// (set / delete). Passwords stay sealed and are never returned to the guest.
    pub allow_guest_admin_email: bool,
    /// Permit a guest's `admin` capability to write **site config + aliases** (routing,
    /// headers, cache). A config write can't attach an unverified domain (the verified-domain
    /// guard is shared with the HTTP path).
    pub allow_guest_admin_site: bool,
    /// Permit a guest's `admin` capability to write the project's **sealed secrets** (set /
    /// rotate / delete — write-only, redacted). The most sensitive surface: an operator can
    /// withhold it while still allowing domains/email/site self-service.
    pub allow_guest_admin_secrets: bool,
    /// Require an **explicit in-site tenancy decision** (Dimension 0) from any site/function that
    /// imports `sql`/`orm`: it must declare either `tenancy: disabled` (deliberately plain) or a
    /// `scoped` config. On under `multi-tenant` — so running a query unscoped on an
    /// untrusted-tenant fleet is a reviewed choice, never an accidental omission — and **off**
    /// under `single-tenant`/`dev` (one operator; *undeclared* silently means plain). When on, an
    /// undeclared sql/orm importer is refused at activation.
    pub require_tenancy_declaration: bool,
    /// Permit an in-site tenancy grant to reach **across tenants** (`read`/`write: all`) — the
    /// operator ceiling on the cross-tenant mode. **Off** under `multi-tenant` (an `all` grant is
    /// refused until the operator opts in) and on under `single-tenant`/`dev`. Independent of the
    /// per-function grant: even a function that declares `all` is capped to `own` (its resolved
    /// tenant) while this is off, so a compromised/misconfigured tenant can't read the fleet.
    pub allow_cross_tenant_db: bool,
}

impl Default for SecurityPosture {
    fn default() -> Self {
        SecurityProfile::MultiTenant.preset()
    }
}

impl SecurityPosture {
    /// The base (no per-project override) resolved tenancy/capability knobs for this posture.
    pub fn base_project_tenancy(&self) -> ResolvedProjectTenancy {
        ResolvedProjectTenancy {
            require_tenancy_declaration: self.require_tenancy_declaration,
            allow_cross_tenant_db: self.allow_cross_tenant_db,
            capability_max_ttl_secs: (self.allow_guest_mint_capability
                && self.max_guest_capability_ttl_secs > 0)
                .then_some(self.max_guest_capability_ttl_secs),
        }
    }

    /// Apply a [`ProjectPostureOverride`] over this posture's base tenancy knobs (Gap 4a). Each
    /// `Some` field of the override wins; the rest fall through to the fleet posture. Only affects
    /// this project's own in-project tenancy + capability-mint ceiling — never cross-project reach.
    pub fn project_tenancy(&self, ovr: &ProjectPostureOverride) -> ResolvedProjectTenancy {
        let mint = ovr
            .allow_guest_mint_capability
            .unwrap_or(self.allow_guest_mint_capability);
        let ttl = ovr
            .max_guest_capability_ttl_secs
            .unwrap_or(self.max_guest_capability_ttl_secs);
        ResolvedProjectTenancy {
            require_tenancy_declaration: ovr
                .require_tenancy_declaration
                .unwrap_or(self.require_tenancy_declaration),
            allow_cross_tenant_db: ovr
                .allow_cross_tenant_db
                .unwrap_or(self.allow_cross_tenant_db),
            capability_max_ttl_secs: (mint && ttl > 0).then_some(ttl),
        }
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
    if let Some(v) = o.allow_guest_private_egress {
        base.allow_guest_private_egress = v;
    }
    if let Some(v) = o.allow_guest_self_egress {
        base.allow_guest_self_egress = v;
    }
    if let Some(v) = o.allow_guest_egress_extra_ca {
        base.allow_guest_egress_extra_ca = v;
    }
    if let Some(v) = o.allow_guest_tcp_egress {
        base.allow_guest_tcp_egress = v;
    }
    if let Some(v) = o.allow_guest_tcp_listener {
        base.allow_guest_tcp_listener = v;
    }
    if let Some(v) = o.allow_guest_dns_publish {
        base.allow_guest_dns_publish = v;
    }
    if let Some(v) = o.guest_dns_publish_ns {
        base.guest_dns_publish_ns = v;
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
    if let Some(v) = o.allow_compute_exec {
        base.allow_compute_exec = v;
    }
    if let Some(v) = o.allow_dev_blob_bind {
        base.allow_dev_blob_bind = v;
    }
    if let Some(v) = o.allow_dev_messaging_bind {
        base.allow_dev_messaging_bind = v;
    }
    if let Some(v) = o.ratelimit_fail_open {
        base.ratelimit_fail_open = v;
    }
    if let Some(v) = o.allow_implicit_routing {
        base.allow_implicit_routing = v;
    }
    if let Some(v) = o.require_pop {
        base.require_pop = v;
    }
    if let Some(v) = o.require_domain_verification {
        base.require_domain_verification = v;
    }
    if let Some(v) = o.allow_env_secret_refs {
        base.allow_env_secret_refs = v;
    }
    if let Some(v) = o.allow_guest_email {
        base.allow_guest_email = v;
    }
    if let Some(v) = o.allow_guest_mint_capability {
        base.allow_guest_mint_capability = v;
    }
    if let Some(v) = o.max_guest_capability_ttl_secs {
        base.max_guest_capability_ttl_secs = v;
    }
    if let Some(v) = o.allow_guest_admin_domains {
        base.allow_guest_admin_domains = v;
    }
    if let Some(v) = o.allow_guest_admin_email {
        base.allow_guest_admin_email = v;
    }
    if let Some(v) = o.allow_guest_admin_site {
        base.allow_guest_admin_site = v;
    }
    if let Some(v) = o.allow_guest_admin_secrets {
        base.allow_guest_admin_secrets = v;
    }
    if let Some(v) = o.require_tenancy_declaration {
        base.require_tenancy_declaration = v;
    }
    if let Some(v) = o.allow_cross_tenant_db {
        base.allow_cross_tenant_db = v;
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
    fn per_project_override_tunes_only_the_named_project() {
        // Base: strict multi-tenant (declaration required, no cross-tenant, no guest mint).
        let base = SecurityProfile::MultiTenant.preset();
        let b = base.base_project_tenancy();
        assert!(b.require_tenancy_declaration);
        assert!(!b.allow_cross_tenant_db);
        assert_eq!(b.capability_max_ttl_secs, None);

        // A project override permits the `all` twins + guest capability minting WHILE keeping
        // strict declaration — the three knobs compose (Gap 4.3).
        let ovr = ProjectPostureOverride {
            require_tenancy_declaration: None, // inherit (stays true)
            allow_cross_tenant_db: Some(true),
            allow_guest_mint_capability: Some(true),
            max_guest_capability_ttl_secs: Some(1800),
        };
        let r = base.project_tenancy(&ovr);
        assert!(r.require_tenancy_declaration); // inherited strict
        assert!(r.allow_cross_tenant_db); // opted in
        assert_eq!(r.capability_max_ttl_secs, Some(1800)); // minting enabled + clamped

        // Minting stays OFF when only a TTL is given without enabling the knob.
        let ttl_only = ProjectPostureOverride {
            max_guest_capability_ttl_secs: Some(3600),
            ..Default::default()
        };
        assert_eq!(
            base.project_tenancy(&ttl_only).capability_max_ttl_secs,
            None
        );

        // A tighter project override (disable minting the base had enabled) also holds.
        let looser = SecurityProfile::SingleTenant.preset();
        assert!(
            looser
                .base_project_tenancy()
                .capability_max_ttl_secs
                .is_some()
        );
        let tighten = ProjectPostureOverride {
            allow_guest_mint_capability: Some(false),
            ..Default::default()
        };
        assert_eq!(
            looser.project_tenancy(&tighten).capability_max_ttl_secs,
            None
        );
    }

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
        assert!(!p.require_pop);
        // Bare/`env:` secret refs read the operator namespace → off under multi-tenant.
        assert!(!p.allow_env_secret_refs);
        assert_eq!(p.max_upload_bytes, MT_MAX_UPLOAD);
    }

    #[test]
    fn allow_env_secret_refs_follows_the_trust_model() {
        // Multi-tenant: untrusted config authors, so a bare host-env secret ref is off.
        assert!(!SecurityProfile::MultiTenant.preset().allow_env_secret_refs);
        // Single-tenant / dev: the operator owns every config, so it is on.
        assert!(SecurityProfile::SingleTenant.preset().allow_env_secret_refs);
        assert!(SecurityProfile::Dev.preset().allow_env_secret_refs);
        // An explicit override wins over the profile (e.g. re-enable under multi-tenant).
        let cfg = SecurityConfig {
            overrides: PostureOverrides {
                allow_env_secret_refs: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let p = cfg.resolve().unwrap();
        assert!(p.allow_env_secret_refs);
        assert!(
            cfg.explain()
                .unwrap()
                .lines()
                .any(|l| l.contains("allow_env_secret_refs")
                    && l.contains("true")
                    && l.contains("override"))
        );
    }

    #[test]
    fn allow_guest_email_follows_the_trust_model() {
        // Multi-tenant: untrusted tenants can't use the shared SMTP egress by default.
        assert!(!SecurityProfile::MultiTenant.preset().allow_guest_email);
        // Single-tenant / dev: the operator owns everything, so it is on.
        assert!(SecurityProfile::SingleTenant.preset().allow_guest_email);
        assert!(SecurityProfile::Dev.preset().allow_guest_email);
        // An explicit override wins (opt a multi-tenant fleet in).
        let cfg = SecurityConfig {
            overrides: PostureOverrides {
                allow_guest_email: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg.resolve().unwrap().allow_guest_email);
        assert!(
            cfg.explain()
                .unwrap()
                .lines()
                .any(|l| l.contains("allow_guest_email")
                    && l.contains("true")
                    && l.contains("override"))
        );
    }

    #[test]
    fn guest_dns_publish_ns_posture_defaults_per_profile() {
        // The MEDIUM-3 defaults: multi-tenant refuses all sub-zone NS; single-tenant allows only an
        // allowlisted NS target; dev allows any (the pre-MEDIUM-3 behavior).
        assert_eq!(
            SecurityProfile::MultiTenant.preset().guest_dns_publish_ns,
            GuestDnsPublishNs::None
        );
        assert_eq!(
            SecurityProfile::SingleTenant.preset().guest_dns_publish_ns,
            GuestDnsPublishNs::Allowlist
        );
        assert_eq!(
            SecurityProfile::Dev.preset().guest_dns_publish_ns,
            GuestDnsPublishNs::Any
        );
        // The fail-closed default (no config at all) is the most restrictive: `none`.
        assert_eq!(
            SecurityPosture::default().guest_dns_publish_ns,
            GuestDnsPublishNs::None
        );
        assert_eq!(GuestDnsPublishNs::default(), GuestDnsPublishNs::None);
        // An explicit override wins over the profile and is attributed in `explain`.
        let cfg = SecurityConfig {
            profile: Some("multi-tenant".into()),
            overrides: PostureOverrides {
                guest_dns_publish_ns: Some(GuestDnsPublishNs::Allowlist),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.resolve().unwrap().guest_dns_publish_ns,
            GuestDnsPublishNs::Allowlist
        );
        assert!(
            cfg.explain()
                .unwrap()
                .lines()
                .any(|l| l.contains("guest_dns_publish_ns")
                    && l.contains("allowlist")
                    && l.contains("override"))
        );
    }

    #[test]
    fn allow_guest_admin_is_per_surface_and_follows_the_trust_model() {
        // All four surfaces off under multi-tenant, on under single-tenant/dev.
        let mt = SecurityProfile::MultiTenant.preset();
        assert!(
            !mt.allow_guest_admin_domains
                && !mt.allow_guest_admin_email
                && !mt.allow_guest_admin_site
                && !mt.allow_guest_admin_secrets
        );
        let st = SecurityProfile::SingleTenant.preset();
        assert!(
            st.allow_guest_admin_domains
                && st.allow_guest_admin_email
                && st.allow_guest_admin_site
                && st.allow_guest_admin_secrets
        );
        // Per-surface override: an operator enables domains fleet-wide but keeps the sensitive
        // secrets surface OFF — the whole point of per-surface knobs.
        let cfg = SecurityConfig {
            overrides: PostureOverrides {
                allow_guest_admin_domains: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let p = cfg.resolve().unwrap();
        assert!(p.allow_guest_admin_domains);
        assert!(!p.allow_guest_admin_secrets, "other surfaces stay off");
        assert!(
            cfg.explain()
                .unwrap()
                .lines()
                .any(|l| l.contains("allow_guest_admin_domains")
                    && l.contains("true")
                    && l.contains("override"))
        );
    }

    #[test]
    fn tenancy_knobs_follow_the_trust_model() {
        // Multi-tenant demands an explicit tenancy decision and forbids cross-tenant `all`.
        let mt = SecurityProfile::MultiTenant.preset();
        assert!(mt.require_tenancy_declaration);
        assert!(!mt.allow_cross_tenant_db);
        // Single-tenant / dev: one operator — undeclared is fine, cross-tenant is allowed.
        for p in [
            SecurityProfile::SingleTenant.preset(),
            SecurityProfile::Dev.preset(),
        ] {
            assert!(!p.require_tenancy_declaration);
            assert!(p.allow_cross_tenant_db);
        }
        // An operator can open cross-tenant on a multi-tenant fleet explicitly.
        let cfg = SecurityConfig {
            overrides: PostureOverrides {
                allow_cross_tenant_db: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let p = cfg.resolve().unwrap();
        assert!(p.allow_cross_tenant_db);
        assert!(
            p.require_tenancy_declaration,
            "the declaration gate stays on"
        );
        assert!(
            cfg.explain()
                .unwrap()
                .lines()
                .any(|l| l.contains("allow_cross_tenant_db")
                    && l.contains("true")
                    && l.contains("override"))
        );
    }

    #[test]
    fn require_pop_defaults_off_everywhere_and_overrides() {
        // Off in every built-in preset (per-token opt-in is issuing a `cnf` token).
        for profile in [
            SecurityProfile::MultiTenant,
            SecurityProfile::SingleTenant,
            SecurityProfile::Dev,
        ] {
            assert!(!profile.preset().require_pop, "{}", profile.as_str());
        }
        // An explicit override turns fleet-wide enforcement on.
        let cfg = SecurityConfig {
            overrides: PostureOverrides {
                require_pop: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg.resolve().unwrap().require_pop);
        assert!(
            cfg.explain()
                .unwrap()
                .lines()
                .any(|l| l.contains("require_pop") && l.contains("true") && l.contains("override"))
        );
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
        assert!(
            text.lines()
                .any(|l| l.contains("oidc_require_audience") && l.contains("profile"))
        );
    }
}
