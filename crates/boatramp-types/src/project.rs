//! Projects (= Uchron **Workspaces**): the owning boundary for a set of sites,
//! functions, and compute workloads, plus shared config/secrets. A Project is
//! content-addressed and atomically activated exactly like a site deployment — an
//! immutable `projectver/<hash>` spec body, a mutable `projectmeta/<name>` pointer, and
//! a bounded history ring for rollback — so the CLI, control plane, and store agree on
//! one wire shape.
//!
//! Every site/function/compute resource lives under the `project/<name>/…` key prefix
//! (see [`resource_prefix`]) — that prefix *is* the authoritative membership statement,
//! and it is what every guard consults (e.g. `delete_project` refuses a non-empty
//! project by scanning the prefix).
//!
//! A global reverse index `owner/<kind>/<name>` → project (see [`owner_key`]) is
//! **built once by the migration** as a derived lookup hint. It is **not** currently
//! maintained on create/delete, and no code consults it for an authorization or
//! uniqueness decision — so it can drift and must **not** be treated as an enforced
//! single-membership guard. Make it a maintained derived index (written/deleted in the
//! same batch as each resource) before relying on it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::manifest::sha256_hex;

/// The reserved project every pre-project resource migrates into, and the default a
/// CLI user who never names a project targets. This is the **only** place the literal
/// is written (everything else references this constant).
pub const DEFAULT_PROJECT: &str = "default";

/// The reserved real name of the **default SQL database binding** — the binding a
/// guest opens as `sql.open("")` and an operator/CLI addresses as `--db default`.
///
/// Historically the default binding was keyed by the *empty string* (`""`), which is
/// not a valid URL path segment (it collapses `/api/sql//exec` to a `//` and cannot be
/// typed on the CLI). As of v0.5.0 the config `DEFAULT` env token and the CLI `--db`
/// default both resolve to this reserved name, so every db-name ingress carries a
/// non-empty, path-segment-safe identifier that passes
/// [`validate_resource_name`]`("database", …)`. The guest-facing empty-name contract
/// (`sql.open("")` = the default DB) is preserved by aliasing `""` ⇄ this name at the
/// backend-resolution boundary, so no guest change is required. This is the **only**
/// place the literal is written.
pub const DEFAULT_DB_NAME: &str = "default";

/// The one-line cure appended to an **empty** (`""`) db-name rejection, at every
/// surface that screens a db name (the CLI `--db`, the control-plane `{db}` body).
/// The empty name is the single most common v0.5.0 upgrade snag — the legacy default
/// binding was keyed by the empty string — so the rejection points straight at the
/// new name instead of leaving the operator to guess. Kept next to [`DEFAULT_DB_NAME`]
/// so the two never drift.
pub const EMPTY_DB_NAME_CURE: &str =
    "the default database is now named `default` — use `--db default`";

/// The one-line cure appended to a **non-conforming resource name** rejection at every
/// operator / CLI / config-load surface (never on a guest path). v0.7.0 tightened the
/// resource-name rule from a path-traversal denylist to a strict slug allowlist
/// ([`is_valid_resource_slug`]), so a name that used to load (e.g. `${PROJECT}`) is now
/// refused; this points the operator straight at the discovery + fix flow instead of
/// leaving them to guess. Kept next to [`EMPTY_DB_NAME_CURE`] so the two never drift.
pub const INVALID_NAME_CURE: &str = "this identifier is no longer accepted (v0.7.0 tightened name validation); run \
     'boatramp project doctor' to list non-conforming names and their fix";

/// Maximum length, in bytes, of a project/site/function/compute/workflow name.
/// Matches the tightest SQL identifier limit (Postgres `NAMEDATALEN - 1 = 63`)
/// so a name can be folded into a per-tenant database identifier without forcing
/// pathological truncation. Longer than any realistic human-chosen name.
///
/// Defined here (the lowest crate) so the slug rule ([`is_valid_resource_slug`]) can
/// reference it and both `boatramp-core`'s `validate_resource_name` and
/// `boatramp-types`'s authz-match backstop share the one bound. Re-exported from
/// `boatramp_core::project` (via `pub use boatramp_types::project::*`).
pub const MAX_RESOURCE_NAME_LEN: usize = 63;

/// The positive-rule reason for any name that is not a valid slug — a single
/// human-readable statement of the whole allowlist. Shared by
/// `boatramp_core::project::validate_resource_name` and the operator-facing surfaces.
pub const INVALID_NAME_REASON: &str = "must be a valid slug: start and end with a letter or digit; interior may add '_', '-'; 1-63 bytes";

/// The v0.7.0 **ASCII strict single-label slug** predicate: `true` IFF `value`
/// matches `^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$` and is 1–[`MAX_RESOURCE_NAME_LEN`]
/// bytes.
///
/// This is the one canonical resource-identifier rule, defined in the lowest crate so
/// every layer shares it with no drift:
/// - `boatramp_core::project::validate_resource_name` wraps it with the `kind`/`reason`
///   error struct at every operator / control-plane / URL-path ingress;
/// - the authz-match backstop (`authz::target_matches`) uses it directly to fail closed
///   on a non-conforming token target that predates this change or was minted offline.
///
/// **Enforced with a byte loop** (`value.bytes()` + [`u8::is_ascii_alphanumeric`]),
/// NOT `char::is_alphanumeric` — a Unicode homoglyph (`аcme` Cyrillic, `acme１`
/// fullwidth, `café`) has non-ASCII bytes (each `>= 0x80`), so it fails the
/// byte-alphanumeric test and can never impersonate an ASCII slug. First AND last byte
/// must be ASCII-alphanumeric; interior bytes may additionally be `_`/`-`; a
/// single-char name must be alphanumeric. Mirror of `cedar.rs::is_safe_ident`.
pub fn is_valid_resource_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_RESOURCE_NAME_LEN {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        let first_or_last = i == 0 || i == bytes.len() - 1;
        let ok = if first_or_last {
            b.is_ascii_alphanumeric()
        } else {
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Whether a **token role target** conforms to the v0.7.0 grammar and every segment is
/// a valid slug: a bare `<project>`, a `<project>/<site>`, or a project wildcard
/// `<project>/*`. Exactly one `/` is permitted (and only as the segment separator or
/// the wildcard delimiter); every non-wildcard segment must satisfy
/// [`is_valid_resource_slug`].
///
/// This is the **fail-closed authz-match backstop** predicate (audit A8): a token role
/// scope is `<role>:<target>`, and the `<target>` string contains a `/` for site /
/// wildcard scopes, so it must NOT be run through [`is_valid_resource_slug`] whole
/// (that rejects `/`). The four mint feeders reject a non-conforming target at issue
/// time, but a token minted before v0.7.0 — or offline — carries an unvalidated target;
/// `authz::target_matches` calls this so such a target matches NOTHING.
pub fn is_conforming_role_target(target: &str) -> bool {
    match target.split_once('/') {
        // A project wildcard `<project>/*`: the project segment must be a valid slug.
        Some((project, "*")) => is_valid_resource_slug(project),
        // A `<project>/<site>`: both segments valid slugs, and no further `/`.
        Some((project, site)) => {
            !site.contains('/') && is_valid_resource_slug(project) && is_valid_resource_slug(site)
        }
        // A bare `<project>`: a valid slug.
        None => is_valid_resource_slug(target),
    }
}

/// KV prefix for the mutable pointer `projectmeta/<name>` → active spec hash.
pub const POINTER_PREFIX: &str = "projectmeta/";
/// KV prefix for the immutable, content-addressed project spec body.
pub const SPEC_PREFIX: &str = "projectver/";
/// KV prefix for the global reverse ownership index `owner/<kind>/<name>` → project.
pub const OWNER_PREFIX: &str = "owner/";

/// The mutable pointer key for a project (→ its active spec hash).
pub fn pointer_key(project: &str) -> String {
    format!("{POINTER_PREFIX}{project}")
}

/// The immutable spec-body key for a content hash.
pub fn spec_key(hash: &str) -> String {
    format!("{SPEC_PREFIX}{hash}")
}

/// The rollback-history key for a project.
pub fn history_key(project: &str) -> String {
    format!("project-history/{project}")
}

/// The prefix under which **all** of a project's owned resources live (sites,
/// functions, compute, …). A single-project sweep is `list_prefix(resource_prefix(p))`.
pub fn resource_prefix(project: &str) -> String {
    format!("project/{project}/")
}

/// The reverse-index key naming which project owns `<kind>/<name>` (see [`owner_kind`]).
pub fn owner_key(kind: &str, name: &str) -> String {
    format!("{OWNER_PREFIX}{kind}/{name}")
}

/// The resource kinds recorded in the reverse ownership index.
pub mod owner_kind {
    /// A site.
    pub const SITE: &str = "site";
    /// A function.
    pub const FUNCTION: &str = "function";
    /// A compute workload.
    pub const COMPUTE: &str = "compute";
}

/// Human-facing project metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectMeta {
    /// Display name (defaults to the slug).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display: String,
    /// Free-text description.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Arbitrary labels.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Project-level shared defaults its sites/functions/compute inherit unless overridden.
/// Kept small; grows as needs surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfig {
    /// Default region for the project's compute/replicas (FA-8); `None` = agnostic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// An immutable, content-addressed project version — the analogue of a site deployment
/// manifest. Stored at `projectver/<hash>`; the mutable `projectmeta/<name>` points at
/// the active one (atomic activation + rollback, same model as a site).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Pinned schema discriminant (`v1`).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// The project's slug — its stable identity (unique, immutable, no `/`).
    pub name: String,
    /// Creation time (unix secs).
    pub created_at: u64,
    /// Human metadata.
    #[serde(default)]
    pub meta: ProjectMeta,
    /// Shared defaults.
    #[serde(default)]
    pub config: ProjectConfig,
    /// Hash of the project's sealed shared-secrets body (content-addressed like
    /// `siteconfig`); `None` ⇒ no shared secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_ref: Option<String>,
}

impl Project {
    /// The content hash of this project version — its `projectver/<hash>` id. Computed
    /// over canonical JSON so identical projects dedupe (like a deployment id).
    pub fn id(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("Project serializes");
        sha256_hex(&canonical)
    }
}

/// The owner recorded in a **global** domain-routing index value (`domain/<host>`,
/// `wildcard/<suffix>`, `httpchallenge/<host>/<token>`). Serializes as `{project,
/// site}`; a **bare string** deserializes as `(DEFAULT_PROJECT, <string>)` so a
/// not-yet-migrated (layout-1) index still reads correctly while the migration runs.
///
/// Note the two host-normalization schemes that key into this shared value type:
/// `domain/`/`wildcard/` keys canonicalize the host via `Host::routing_key`, while
/// `httpchallenge/`/`domainverify/` keys use `Host::verification`. They must not be
/// crossed — a lookup keyed under one normalization must be read under the same one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainOwner {
    /// The owning project.
    pub project: String,
    /// The site within the project.
    pub site: String,
    /// An opaque per-domain **tenant context tag** — the value the host binds as the in-site
    /// tenant when a function/site resolves "own" via [`crate::tenancy::TenantSource::Domain`]
    /// (storefronts: 1 domain : 1 tenant). Set at domain attach via the domain admin API;
    /// wildcards/aliases inherit the base's tag. `None` ⇒ this domain carries no tenant context
    /// (a domain source then fails closed). Omitted from the serialized form when absent, so a
    /// pre-existing `{project, site}` value still reads (and round-trips) unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

impl DomainOwner {
    /// A `(project, site)` owner with no tenant context tag.
    pub fn new(project: impl Into<String>, site: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            site: site.into(),
            context: None,
        }
    }

    /// Attach an opaque tenant context tag (the [`TenantSource::Domain`](crate::tenancy::TenantSource::Domain)
    /// value). An empty tag is treated as none.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        let c = context.into();
        self.context = (!c.is_empty()).then_some(c);
        self
    }

    /// Whether two owners are the **same owner** — `(project, site)` only. The `context` tag is
    /// per-host *metadata* the same owner attaches, NOT part of ownership, so it must never gate
    /// claimability: a host that gains a context tag would otherwise conflict with *itself* the
    /// moment its stored index value carries the tag but a claim-check passes a bare owner (the
    /// v0.4.22 cooperative-apply 409 regression). Use this for every hijack/claim comparison; keep
    /// full [`PartialEq`] (context included) for exact value round-trip checks.
    #[must_use]
    pub fn same_owner(&self, other: &Self) -> bool {
        self.project == other.project && self.site == other.site
    }

    /// The canonical stored form of a domain-index value: the `{project, site}`
    /// JSON object.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("DomainOwner serializes")
    }

    /// Read a domain-index value, tolerant of **three** on-disk forms so a reader
    /// never breaks mid-migration:
    /// 1. the current `{project, site}` JSON object;
    /// 2. a JSON bare string `"blog"` → `(default, "blog")`;
    /// 3. a **raw, unquoted** site name `blog` (the pre-0.2.0 layout, written as
    ///    `site.as_bytes()` — not valid JSON) → `(default, "blog")`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if let Ok(owner) = serde_json::from_slice::<Self>(bytes) {
            return owner;
        }
        // Legacy layout-1 value: the bare site name stored as raw bytes.
        Self::new(DEFAULT_PROJECT, String::from_utf8_lossy(bytes).into_owned())
    }
}

impl<'de> Deserialize<'de> for DomainOwner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            /// Layout 1: a bare site name.
            Bare(String),
            /// Layout 2: `{project, site}` (+ optional `context`, appended in v0.4.0).
            Full {
                project: String,
                site: String,
                #[serde(default)]
                context: Option<String>,
            },
        }
        Ok(match Raw::deserialize(deserializer)? {
            Raw::Bare(site) => Self {
                project: DEFAULT_PROJECT.to_string(),
                site,
                context: None,
            },
            Raw::Full {
                project,
                site,
                context,
            } => Self {
                project,
                site,
                context,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Project {
        Project {
            version: crate::SCHEMA_VERSION,
            name: "acme".into(),
            created_at: 1_700_000_000,
            meta: ProjectMeta {
                display: "Acme Corp".into(),
                ..Default::default()
            },
            config: ProjectConfig {
                region: Some("eu-west".into()),
            },
            secrets_ref: None,
        }
    }

    #[test]
    fn project_id_is_stable_and_content_addressed() {
        let a = sample();
        let mut b = sample();
        assert_eq!(a.id(), b.id(), "identical projects share an id");
        b.name = "other".into();
        assert_ne!(a.id(), b.id(), "a changed field changes the id");
        assert_eq!(a.id().len(), 64);
    }

    #[test]
    fn key_builders() {
        assert_eq!(pointer_key("acme"), "projectmeta/acme");
        assert_eq!(spec_key("deadbeef"), "projectver/deadbeef");
        assert_eq!(history_key("acme"), "project-history/acme");
        assert_eq!(resource_prefix("acme"), "project/acme/");
        assert_eq!(owner_key(owner_kind::SITE, "blog"), "owner/site/blog");
    }

    #[test]
    fn domain_owner_reads_bare_and_full() {
        // Layout 1: a bare string → the default project.
        let bare: DomainOwner = serde_json::from_str("\"blog\"").unwrap();
        assert_eq!(bare, DomainOwner::new(DEFAULT_PROJECT, "blog"));
        // Layout 2: a {project, site} object, verbatim.
        let full: DomainOwner =
            serde_json::from_str(r#"{"project":"acme","site":"shop"}"#).unwrap();
        assert_eq!(full, DomainOwner::new("acme", "shop"));
        // Serializes as the object form + round-trips.
        let round: DomainOwner =
            serde_json::from_slice(&serde_json::to_vec(&full).unwrap()).unwrap();
        assert_eq!(round, full);
    }

    #[test]
    fn domain_owner_from_bytes_tolerates_all_layouts() {
        // Current object form round-trips.
        let owner = DomainOwner::new("acme", "shop");
        assert_eq!(DomainOwner::from_bytes(&owner.to_bytes()), owner);
        // JSON bare string → default project.
        assert_eq!(
            DomainOwner::from_bytes(b"\"blog\""),
            DomainOwner::new(DEFAULT_PROJECT, "blog")
        );
        // Pre-0.2.0 raw (unquoted) site name, not valid JSON → default project.
        assert_eq!(
            DomainOwner::from_bytes(b"blog"),
            DomainOwner::new(DEFAULT_PROJECT, "blog")
        );
        // A raw site name that looks like a JSON scalar still reads as a site name.
        assert_eq!(
            DomainOwner::from_bytes(b"123"),
            DomainOwner::new(DEFAULT_PROJECT, "123")
        );
    }

    #[test]
    fn domain_owner_context_tag_round_trips_and_stays_back_compatible() {
        // A pre-v0.4.0 value with no context reads with context None and re-serializes WITHOUT a
        // context key (so it stays byte-compatible with old readers).
        let legacy: DomainOwner =
            serde_json::from_str(r#"{"project":"acme","site":"shop"}"#).unwrap();
        assert_eq!(legacy.context, None);
        assert_eq!(
            String::from_utf8(legacy.to_bytes()).unwrap(),
            r#"{"project":"acme","site":"shop"}"#
        );
        // A tagged value round-trips the tenant context.
        let tagged = DomainOwner::new("acme", "shop").with_context("acme-store");
        assert_eq!(tagged.context.as_deref(), Some("acme-store"));
        assert_eq!(DomainOwner::from_bytes(&tagged.to_bytes()), tagged);
        // An empty tag is treated as none (never binds an empty-string tenant).
        assert_eq!(
            DomainOwner::new("acme", "shop").with_context("").context,
            None
        );
    }
}
