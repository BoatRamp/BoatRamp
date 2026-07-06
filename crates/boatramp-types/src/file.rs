//! A deployment's per-file descriptor and its precompressed variants — the
//! immutable, content-addressed file metadata shared by routing and the wire
//! format. Lives here (not in `boatramp-core::deploy`) so the edge Worker and
//! the web console can parse manifests and route without pulling the full
//! `DeployStore`/IO stack.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One file within a deployment manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// SHA-256 (hex) of the file's identity (uncompressed) contents — its blob key.
    pub hash: String,
    /// Size of the identity representation in bytes.
    pub size: u64,
    /// MIME content type, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Precompressed alternates by `Content-Encoding` token (`br`, `gzip`),
    /// produced at `sync`. Each is a separate content-addressed blob the server
    /// may serve when the client accepts that encoding.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variants: BTreeMap<String, Variant>,
}

/// A precompressed alternate representation of a [`FileEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variant {
    /// SHA-256 (hex) of the compressed bytes — its blob key.
    pub hash: String,
    /// Size of the compressed representation in bytes.
    pub size: u64,
}
