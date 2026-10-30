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

    /// Every blob hash this manifest references paired with the DECLARED byte size recorded for it
    /// (a file entry and each precompressed variant), including variants. This is the size the
    /// serve path emits as `Content-Length`, so a blob whose stored object is shorter than its
    /// declared size would stream a truncated/hung response — the declared≠stored class `blob
    /// verify` detects (PLAN-clone-robustness #3). A hash that appears more than once (shared
    /// content) keeps its first declared size; the sizes agree when the content is identical.
    pub fn blob_sizes(&self) -> std::collections::BTreeMap<String, u64> {
        let mut sizes = std::collections::BTreeMap::new();
        for entry in self.files.values() {
            sizes.entry(entry.hash.clone()).or_insert(entry.size);
            for variant in entry.variants.values() {
                sizes.entry(variant.hash.clone()).or_insert(variant.size);
            }
        }
        sizes
    }
}

/// SHA-256 of `data`, hex-encoded.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{FileEntry, Variant};

    #[test]
    fn blob_sizes_pairs_every_hash_with_its_declared_size_incl_variants() {
        let mut m = Manifest::default();
        let mut variants = BTreeMap::new();
        variants.insert(
            "br".to_string(),
            Variant {
                hash: "varhash".to_string(),
                size: 100,
            },
        );
        m.files.insert(
            "index.html".to_string(),
            FileEntry {
                hash: "filehash".to_string(),
                size: 4096,
                content_type: Some("text/html".to_string()),
                variants,
            },
        );
        let sizes = m.blob_sizes();
        assert_eq!(sizes.get("filehash"), Some(&4096), "the file entry's declared size");
        assert_eq!(sizes.get("varhash"), Some(&100), "a variant's declared size too");
        // Same keyset as blob_hashes (so the size map covers exactly the referenced blobs).
        let hashes = m.blob_hashes();
        assert_eq!(sizes.keys().cloned().collect::<BTreeSet<_>>(), hashes);
    }
}
