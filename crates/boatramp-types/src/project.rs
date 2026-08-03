//! Projects (= Uchron **Workspaces**): the owning boundary for a set of sites,
//! functions, and compute workloads, plus shared config/secrets. A Project is
//! content-addressed and atomically activated exactly like a site deployment — an
//! immutable `projectver/<hash>` spec body, a mutable `projectmeta/<name>` pointer, and
//! a bounded history ring for rollback — so the CLI, control plane, and store agree on
//! one wire shape.
//!
//! Every site/function/compute resource lives under the `project/<name>/…` key prefix
//! (see [`resource_prefix`]) — that prefix *is* the authoritative membership statement.
//! A global reverse index `owner/<kind>/<name>` → project (see [`owner_key`]) is a
//! derived accelerator + the single-membership guard.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::manifest::sha256_hex;

/// The reserved project every pre-project resource migrates into, and the default a
/// CLI user who never names a project targets. This is the **only** place the literal
/// is written (everything else references this constant).
pub const DEFAULT_PROJECT: &str = "default";

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainOwner {
    /// The owning project.
    pub project: String,
    /// The site within the project.
    pub site: String,
}

impl DomainOwner {
    /// A `(project, site)` owner.
    pub fn new(project: impl Into<String>, site: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            site: site.into(),
        }
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
            /// Layout 2: `{project, site}`.
            Full { project: String, site: String },
        }
        Ok(match Raw::deserialize(deserializer)? {
            Raw::Bare(site) => Self {
                project: DEFAULT_PROJECT.to_string(),
                site,
            },
            Raw::Full { project, site } => Self { project, site },
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
}
