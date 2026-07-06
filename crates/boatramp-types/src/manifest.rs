//! The deployment **manifest** — the immutable, content-addressed description of
//! a site's files + deploy config at a point in time. It's the wire format the
//! server writes, the CLI reads, and the edge Worker parses to route, so it
//! lives in `boatramp-types` (one definition, no drift) and is wasm-clean.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::DeployConfig;
use crate::error::ConfigError;
use crate::file::FileEntry;

/// An immutable description of a site's files at a point in time.
///
/// Serialized deterministically (paths are a sorted [`BTreeMap`]) so identical
/// content always produces the same [`Manifest::id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`] (see its docs).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Site-relative path (e.g. `index.html`) → file entry.
    pub files: BTreeMap<String, FileEntry>,
    /// Deploy-scoped configuration (the `routing` section of `project.cfg`);
    /// part of the manifest, so routing/headers/cache roll back atomically with
    /// the content.
    #[serde(default)]
    pub config: DeployConfig,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            files: BTreeMap::new(),
            config: DeployConfig::default(),
        }
    }
}

impl Manifest {
    /// Canonical JSON encoding (stable key order).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        serde_json::to_vec(self).map_err(|err| ConfigError::parse(err.to_string()))
    }

    /// Parse from canonical JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        serde_json::from_slice(bytes).map_err(|err| ConfigError::parse(err.to_string()))
    }

    /// The deployment id: SHA-256 (hex) of the canonical encoding.
    pub fn id(&self) -> Result<String, ConfigError> {
        Ok(sha256_hex(&self.to_bytes()?))
    }

    /// The distinct blob hashes this manifest references, including the
    /// precompressed variant blobs (so GC never reclaims a referenced variant).
    pub fn blob_hashes(&self) -> BTreeSet<String> {
        let mut hashes = BTreeSet::new();
        for entry in self.files.values() {
            hashes.insert(entry.hash.clone());
            for variant in entry.variants.values() {
                hashes.insert(variant.hash.clone());
            }
        }
        hashes
    }
}

/// SHA-256 of `data`, hex-encoded.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
