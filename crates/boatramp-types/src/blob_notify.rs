//! Ledger + operator tiers for **cloud blob-change notification auto-provisioning**
//! (PLAN-faas FA-5b2). The [`Storage::watch`](crate) seam (FA-5b1) works
//! zero-config on the filesystem via inotify/FSEvents; cloud object stores need a
//! native notification pipeline (S3→SQS, GCS→Pub/Sub, Azure→Event Grid). Rather
//! than make the operator hand-wire it, boatramp provisions it — "auto-DNS, but for
//! object-store events" — recording what it created in this ledger so it can be
//! **retracted** on trigger/site removal (mirrors the [`ManagedDns`](crate::dns_managed)
//! pattern). This module is the wasm-clean serde surface; the provisioning IO lives
//! behind `boatramp_core::blob_provision::WatchProvider`.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// How boatramp obtains the cloud notification pipeline for a blob-change trigger.
/// The tiers preserve the "conceptually clear / no surprises" guarantee: boatramp
/// either has a working watch or clearly refuses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisionTier {
    /// Print the exact provider setup (queue policy + notification config) to apply
    /// — no credentials, nothing mutated. The safe default recipe mode.
    DryRun,
    /// Create + reconcile + retract the pipeline (needs elevated cloud creds).
    Provision,
    /// The operator pre-wired the pipeline; boatramp only verifies + consumes.
    VerifyOnly,
    /// No pipeline + no provisioning creds ⇒ refuse activation (fail-closed).
    #[default]
    Refuse,
}

/// One cloud resource boatramp created (a queue, a topic, a subscription, a bucket
/// notification entry) — recorded so it can be retracted. `kind` is a
/// provider-defined token (e.g. `sqs-queue`, `bucket-notification`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResource {
    /// Provider-defined resource kind.
    pub kind: String,
    /// The resource id / ARN / name (what retraction deletes).
    pub id: String,
}

impl ManagedResource {
    /// A resource record.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// The notification pipeline boatramp provisioned for one `(function, prefix)`, so
/// it can be retracted on trigger/site removal. Keyed under
/// [`blobnotify_key`]. Mirrors [`ManagedDns`](crate::dns_managed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagedNotification {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    pub version: u32,
    /// The function whose blob-change trigger this backs.
    pub function: String,
    /// The watched blobstore prefix.
    pub prefix: String,
    /// The provider that owns the resources (`s3` / `gcs` / `azure`), so a
    /// retraction rebuilds the same one.
    pub provider: String,
    /// The resources to delete when the trigger is retracted.
    pub resources: Vec<ManagedResource>,
    /// Unix seconds the ledger entry was last written.
    pub updated_at_unix: u64,
}

impl Default for ManagedNotification {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            function: String::new(),
            prefix: String::new(),
            provider: String::new(),
            resources: Vec::new(),
            updated_at_unix: 0,
        }
    }
}

impl ManagedNotification {
    /// A ledger entry for `(function, prefix)` provisioned by `provider`.
    pub fn new(
        function: &str,
        prefix: &str,
        provider: &str,
        resources: Vec<ManagedResource>,
        now_unix: u64,
    ) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            function: function.to_string(),
            prefix: prefix.to_string(),
            provider: provider.to_string(),
            resources,
            updated_at_unix: now_unix,
        }
    }

    /// Serialize to the stored JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, ConfigError> {
        serde_json::to_vec(self).map_err(|err| ConfigError::parse(err.to_string()))
    }

    /// Parse from stored JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        serde_json::from_slice(bytes).map_err(|err| ConfigError::parse(err.to_string()))
    }
}

/// A key-safe slug of a watched prefix (non-alphanumerics → `-`, collapsed), so a
/// `uploads/2024/` prefix maps to a stable ledger key suffix.
pub fn prefix_slug(prefix: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in prefix.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "root".to_string()
    } else {
        trimmed.to_string()
    }
}

/// KV key for the notification ledger of `(function, prefix)`.
pub fn blobnotify_key(function: &str, prefix: &str) -> String {
    format!("blobnotify/{function}/{}", prefix_slug(prefix))
}

/// The KV key prefix for a function's notification ledgers (for enumeration).
pub fn blobnotify_function_prefix(function: &str) -> String {
    format!("blobnotify/{function}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_and_keyspace_are_stable() {
        assert_eq!(prefix_slug("uploads/2024/"), "uploads-2024");
        assert_eq!(prefix_slug("/"), "root");
        assert_eq!(prefix_slug(""), "root");
        assert_eq!(
            blobnotify_key("ingest", "uploads/"),
            "blobnotify/ingest/uploads"
        );
        assert_eq!(blobnotify_function_prefix("ingest"), "blobnotify/ingest/");
    }

    #[test]
    fn ledger_round_trips() {
        let led = ManagedNotification::new(
            "ingest",
            "uploads/",
            "s3",
            vec![
                ManagedResource::new("sqs-queue", "arn:aws:sqs:…:boatramp-ingest"),
                ManagedResource::new("bucket-notification", "boatramp-ingest-uploads"),
            ],
            42,
        );
        let bytes = led.to_json().unwrap();
        assert_eq!(ManagedNotification::from_json(&bytes).unwrap(), led);
        assert!(String::from_utf8_lossy(&bytes).contains("\"provider\":\"s3\""));
    }

    #[test]
    fn tier_defaults_to_refuse() {
        assert_eq!(ProvisionTier::default(), ProvisionTier::Refuse);
        // Wire form is kebab-case + stable.
        let json = serde_json::to_string(&ProvisionTier::VerifyOnly).unwrap();
        assert_eq!(json, "\"verify-only\"");
    }
}
