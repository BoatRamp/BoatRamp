//! Concrete **Azure Event Grid → Storage Queue** blob-change notification provider
//! and consumer (PLAN-storage-backends S4; unblocks FA-5b2 Azure) — the Azure
//! counterpart to [`s3_notify`](crate::s3_notify)/[`gcs_notify`](crate::gcs_notify).
//!
//! Two halves:
//! - **Provisioning** ([`AzureWatchProvider`]): creates/verifies/retracts the
//!   **Storage Queue** (shared account-key auth). The **Event Grid subscription**
//!   that routes `Microsoft.Storage.Blob*` events into the queue is a management-
//!   plane (ARM / Azure AD) resource outside the account-key auth model boatramp
//!   holds, so it is a documented one-time operator step — [`recipe`](AzureWatchProvider::recipe)
//!   prints the exact `az eventgrid` command. (Same honest boundary as the GCS
//!   service-agent IAM grant.)
//! - **Consuming** ([`azure_watch_stream`], wired into
//!   [`AzureStorage::watch`](crate::azure::AzureStorage)): polls the queue, parses
//!   the Event Grid event into [`BlobChange`]s, and deletes (acks) each message.
//!
//! The pure helpers (queue naming, the Event Grid event parse, subject→key, event-
//! type mapping, base64/raw body decode) are unit-tested natively; the SDK-calling
//! methods run against real Azure behind the `#[ignore]`d live seam.

use std::collections::VecDeque;

use async_trait::async_trait;
use azure_core::error::ErrorKind;
use azure_core::StatusCode;
use azure_storage_queues::prelude::{QueueClient, QueueServiceClient};
use azure_storage_queues::PopReceipt;
use base64::Engine;
use boatramp_core::blob_notify::{prefix_slug, ManagedResource};
use boatramp_core::blob_provision::{ProvisionError, WatchProvider};
use boatramp_core::{BlobChange, BlobChangeKind, ChangeStream};
use futures::StreamExt;

// ===========================================================================
// Pure helpers (natively unit-tested; no SDK, no IO)
// ===========================================================================

/// The Storage Queue name backing a watched storage prefix. Deterministic so the
/// provider (which creates it) and the consumer (which polls it) agree. Azure queue
/// names are lowercase alphanumeric + single dashes, 3–63 chars; the prefix slug
/// fits, and an over-long name truncates with a stable hash suffix.
pub(crate) fn queue_name(storage_prefix: &str) -> String {
    let base = format!("boatramp-{}", prefix_slug(storage_prefix));
    if base.len() <= 63 {
        return base;
    }
    let suffix = format!("-{:08x}", fnv1a(storage_prefix));
    format!("{}{}", &base[..63 - suffix.len()], suffix)
}

fn fnv1a(s: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in s.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Map an Event Grid `eventType` to a [`BlobChangeKind`].
fn eventgrid_kind(event_type: &str) -> Option<BlobChangeKind> {
    match event_type {
        "Microsoft.Storage.BlobCreated" => Some(BlobChangeKind::Created),
        "Microsoft.Storage.BlobDeleted" => Some(BlobChangeKind::Removed),
        _ => None,
    }
}

/// Extract the blob key from an Event Grid `subject`
/// (`/blobServices/default/containers/<container>/blobs/<key>` → `<key>`, which is
/// the storage key since a blob's name *is* its key).
fn subject_to_key(subject: &str) -> Option<String> {
    subject
        .split_once("/blobs/")
        .map(|(_, key)| key.to_string())
}

/// Decode a queue message body to JSON text: Event Grid may base64-encode its
/// Storage Queue delivery, so try base64 first (accepting it only if it decodes to
/// JSON-looking UTF-8), else use the body as-is.
fn decode_body(body: &str) -> String {
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(body.trim()) {
        if let Ok(text) = String::from_utf8(bytes) {
            let trimmed = text.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return text;
            }
        }
    }
    body.to_string()
}

/// Parse a Storage Queue message body — one or a batch of Event Grid events — into
/// the changes it carries. Unmapped events / non-JSON bodies yield nothing.
pub(crate) fn parse_eventgrid_event(body: &str) -> Vec<BlobChange> {
    let json = decode_body(body);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else {
        return Vec::new();
    };
    let events = match value {
        serde_json::Value::Array(events) => events,
        other => vec![other],
    };
    let mut out = Vec::new();
    for event in events {
        let Some(kind) = event
            .get("eventType")
            .and_then(|t| t.as_str())
            .and_then(eventgrid_kind)
        else {
            continue;
        };
        let Some(key) = event
            .get("subject")
            .and_then(|s| s.as_str())
            .and_then(subject_to_key)
        else {
            continue;
        };
        out.push(BlobChange { key, kind });
    }
    out
}

// ===========================================================================
// Provider (control plane)
// ===========================================================================

/// Provisions + retracts the Storage Queue half of the Azure notification pipeline
/// for one storage account. The Event Grid subscription is an operator step (see
/// the module docs + [`recipe`](AzureWatchProvider::recipe)).
#[derive(Clone)]
pub struct AzureWatchProvider {
    queues: QueueServiceClient,
    account: String,
    container: String,
}

impl AzureWatchProvider {
    /// Build a provider from a Storage Queue service client, the storage account
    /// name, and the container whose blob events feed the pipeline.
    pub fn new(
        queues: QueueServiceClient,
        account: impl Into<String>,
        container: impl Into<String>,
    ) -> Self {
        Self {
            queues,
            account: account.into(),
            container: container.into(),
        }
    }
}

#[async_trait]
impl WatchProvider for AzureWatchProvider {
    fn name(&self) -> &str {
        "azure"
    }

    fn recipe(&self, prefix: &str) -> String {
        let queue = queue_name(prefix);
        format!(
            "Azure Event Grid → Storage Queue blob-change pipeline for account \
             {account:?}, container {container:?}, prefix {prefix:?}:\n  \
             1. Create Storage Queue {queue:?} in the account.\n  \
             2. Create an Event Grid event subscription on the storage account \
             (management-plane / Azure AD auth — a one-time operator step):\n     \
             az eventgrid event-subscription create --name boatramp-{queue} \
             --source-resource-id <storage-account-resource-id> \
             --endpoint-type storagequeue \
             --endpoint /queueServices/default/queues/{queue} \
             --included-event-types Microsoft.Storage.BlobCreated \
             Microsoft.Storage.BlobDeleted \
             --subject-begins-with /blobServices/default/containers/{container}/blobs/{prefix}\n\
             boatramp then polls + deletes messages from the queue and enqueues one \
             invocation per change.",
            account = self.account,
            container = self.container,
        )
    }

    async fn provision(&self, prefix: &str) -> Result<Vec<ManagedResource>, ProvisionError> {
        let name = queue_name(prefix);
        let queue = self.queues.queue_client(&name);
        // Idempotent: an existing queue with no metadata create returns success; a
        // conflicting one (409) is treated as already-present.
        match queue.create().await {
            Ok(_) => {}
            Err(err) if is_conflict(&err) => {}
            Err(err) => return Err(az_err(err)),
        }
        Ok(vec![ManagedResource::new("storage-queue", name)])
    }

    async fn verify(&self, prefix: &str) -> Result<bool, ProvisionError> {
        // No side-effect-free existence probe is exposed; a zero-message peek
        // succeeds iff the queue exists (it neither reads nor hides a message).
        let queue = self.queues.queue_client(queue_name(prefix));
        match queue.get_messages().number_of_messages(0u8).await {
            Ok(_) => Ok(true),
            Err(err) if is_not_found(&err) => Ok(false),
            Err(err) => Err(az_err(err)),
        }
    }

    async fn retract(&self, resources: &[ManagedResource]) -> Result<(), ProvisionError> {
        if let Some(queue) = resources.iter().find(|r| r.kind == "storage-queue") {
            // Best-effort: a missing queue is not an error.
            let _ = self.queues.queue_client(&queue.id).delete().await;
        }
        Ok(())
    }
}

// ===========================================================================
// Consumer (data plane)
// ===========================================================================

/// Poll `queue`, yielding a [`BlobChange`] per Event Grid event under `prefix`.
/// Each message is deleted (acked) once its events are queued for delivery. A
/// receive error ends the stream — the scheduler's watcher reconcile respawns it.
pub(crate) fn azure_watch_stream(queue: QueueClient, prefix: String) -> ChangeStream {
    let state = (queue, prefix, VecDeque::<BlobChange>::new());
    futures::stream::unfold(state, |(queue, prefix, mut pending)| async move {
        loop {
            if let Some(change) = pending.pop_front() {
                return Some((change, (queue, prefix, pending)));
            }
            let response = match queue.get_messages().number_of_messages(10u8).await {
                Ok(response) => response,
                Err(_) => return None, // transient — reconcile respawns the watcher
            };
            for message in response.messages {
                let changes = parse_eventgrid_event(&message.message_text);
                // Ack: delete by pop receipt so the message does not redeliver.
                let receipt = PopReceipt::new(message.message_id, message.pop_receipt);
                let _ = queue.pop_receipt_client(receipt).delete().await;
                for change in changes {
                    if change.key.starts_with(&prefix) {
                        pending.push_back(change);
                    }
                }
            }
        }
    })
    .boxed()
}

// ===========================================================================
// Error mapping
// ===========================================================================

fn is_not_found(err: &azure_core::Error) -> bool {
    matches!(err.kind(), ErrorKind::HttpResponse { status, .. } if *status == StatusCode::NotFound)
}

fn is_conflict(err: &azure_core::Error) -> bool {
    matches!(err.kind(), ErrorKind::HttpResponse { status, .. } if *status == StatusCode::Conflict)
}

fn az_err(err: azure_core::Error) -> ProvisionError {
    ProvisionError::Backend(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_name_is_deterministic_and_bounded() {
        assert_eq!(
            queue_name("hblob/fn/ingest/uploads/"),
            "boatramp-hblob-fn-ingest-uploads"
        );
        let long = format!("hblob/fn/{}/", "a".repeat(200));
        let name = queue_name(&long);
        assert!(
            name.len() <= 63,
            "queue name {name:?} exceeds the Azure limit"
        );
        assert_eq!(name, queue_name(&long), "deterministic");
    }

    #[test]
    fn event_types_map_and_subject_extracts_key() {
        assert_eq!(
            eventgrid_kind("Microsoft.Storage.BlobCreated"),
            Some(BlobChangeKind::Created)
        );
        assert_eq!(
            eventgrid_kind("Microsoft.Storage.BlobDeleted"),
            Some(BlobChangeKind::Removed)
        );
        assert_eq!(eventgrid_kind("Microsoft.Storage.BlobTierChanged"), None);
        assert_eq!(
            subject_to_key("/blobServices/default/containers/data/blobs/hblob/fn/x/up/a.txt"),
            Some("hblob/fn/x/up/a.txt".to_string())
        );
        assert_eq!(
            subject_to_key("/no/blobs/here-marker"),
            Some("here-marker".to_string())
        );
        assert_eq!(subject_to_key("/containers/data"), None);
    }

    #[test]
    fn parses_a_raw_json_event() {
        let body = r#"{
            "eventType": "Microsoft.Storage.BlobCreated",
            "subject": "/blobServices/default/containers/data/blobs/hblob/fn/ingest/uploads/report.json",
            "data": {"url": "https://acct.blob.core.windows.net/data/hblob/fn/ingest/uploads/report.json"}
        }"#;
        let changes = parse_eventgrid_event(body);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key, "hblob/fn/ingest/uploads/report.json");
        assert_eq!(changes[0].kind, BlobChangeKind::Created);
    }

    #[test]
    fn parses_a_base64_batch_and_ignores_unmapped() {
        let inner = r#"[
            {"eventType":"Microsoft.Storage.BlobDeleted",
             "subject":"/blobServices/default/containers/data/blobs/up/gone.bin"},
            {"eventType":"Microsoft.Storage.BlobTierChanged",
             "subject":"/blobServices/default/containers/data/blobs/up/tiered.bin"}
        ]"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
        let changes = parse_eventgrid_event(&b64);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, BlobChangeKind::Removed);
        assert_eq!(changes[0].key, "up/gone.bin");
        // Garbage / non-JSON yields nothing.
        assert!(parse_eventgrid_event("not json at all").is_empty());
    }
}
