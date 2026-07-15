//! Concrete **GCS → Pub/Sub** blob-change notification provider + consumer
//! (PLAN-storage-backends S3; unblocks FA-5b2 GCS). The GCS counterpart to
//! [`s3_notify`](crate::s3_notify): it provisions the native GCS event pipeline
//! (a Pub/Sub topic + subscription + a bucket `notificationConfig`) so a
//! `Blob { prefix }` trigger fires for **any** writer, and consumes the
//! subscription to yield [`BlobChange`]s.
//!
//! Two halves:
//! - **Provisioning** ([`GcsWatchProvider`]): creates/verifies/retracts the topic,
//!   subscription, and bucket notification (idempotent).
//! - **Consuming** ([`gcs_watch_stream`], wired into
//!   [`GcsStorage::watch`](crate::gcs::GcsStorage)): pulls the subscription, parses
//!   the GCS notification into [`BlobChange`]s, and acks.
//!
//! The pure helpers (topic/subscription naming, the notification-attribute parse,
//! event-type mapping) are unit-tested natively; the SDK-calling methods are
//! exercised against real GCP behind the `#[ignore]`d live seam (Pub/Sub +
//! bucket-notification provisioning have no emulator).
//!
//! **Operator prerequisite:** the GCS service agent
//! (`service-<project-number>@gs-project-accounts.iam.gserviceaccount.com`) needs
//! `roles/pubsub.publisher` on the topic (a one-time IAM grant the Pub/Sub SDK does
//! not expose); [`GcsWatchProvider::recipe`] spells it out.

use std::collections::{HashMap, VecDeque};

use async_trait::async_trait;
use boatramp_core::blob_notify::{prefix_slug, ManagedResource};
use boatramp_core::blob_provision::{ProvisionError, WatchProvider};
use boatramp_core::{BlobChange, BlobChangeKind, ChangeStream};
use futures::StreamExt;

use google_cloud_pubsub::client::Client as PubsubClient;
use google_cloud_pubsub::subscription::{Subscription, SubscriptionConfig};
use google_cloud_storage::client::Client as GcsClient;
use google_cloud_storage::http::notifications::delete::DeleteNotificationRequest;
use google_cloud_storage::http::notifications::insert::{
    InsertNotificationRequest, NotificationCreationConfig,
};
use google_cloud_storage::http::notifications::list::ListNotificationsRequest;
use google_cloud_storage::http::notifications::{EventType, PayloadFormat};

// ===========================================================================
// Pure helpers (natively unit-tested; no SDK, no IO)
// ===========================================================================

/// The Pub/Sub topic name backing a watched storage prefix. Deterministic so the
/// provider (which creates it) and the consumer (which pulls its subscription)
/// agree without a lookup table.
pub(crate) fn topic_name(storage_prefix: &str) -> String {
    format!("boatramp-{}", prefix_slug(storage_prefix))
}

/// The Pub/Sub subscription name backing a watched storage prefix.
pub(crate) fn subscription_name(storage_prefix: &str) -> String {
    format!("boatramp-{}-sub", prefix_slug(storage_prefix))
}

/// The full Pub/Sub topic resource name a GCS `notificationConfig` requires.
pub(crate) fn topic_resource(project: &str, topic: &str) -> String {
    format!("//pubsub.googleapis.com/projects/{project}/topics/{topic}")
}

/// Map a GCS notification `eventType` attribute to a [`BlobChangeKind`].
fn event_type_to_kind(event_type: &str) -> Option<BlobChangeKind> {
    match event_type {
        "OBJECT_FINALIZE" => Some(BlobChangeKind::Created),
        "OBJECT_DELETE" => Some(BlobChangeKind::Removed),
        "OBJECT_METADATA_UPDATE" => Some(BlobChangeKind::Modified),
        "OBJECT_ARCHIVE" => Some(BlobChangeKind::Removed),
        _ => None,
    }
}

/// Parse a GCS Pub/Sub notification into the change it carries. GCS puts the event
/// type + object id in the message **attributes** (present regardless of payload
/// format); object names are not URL-encoded. Unknown/unmapped events yield `None`.
pub(crate) fn parse_gcs_notification(attributes: &HashMap<String, String>) -> Option<BlobChange> {
    let kind = event_type_to_kind(attributes.get("eventType")?.as_str())?;
    let key = attributes.get("objectId")?.clone();
    Some(BlobChange { key, kind })
}

// ===========================================================================
// Provider (control plane)
// ===========================================================================

/// Provisions + retracts the GCS → Pub/Sub notification pipeline for one bucket.
#[derive(Clone)]
pub struct GcsWatchProvider {
    gcs: GcsClient,
    pubsub: PubsubClient,
    bucket: String,
    project: String,
}

impl GcsWatchProvider {
    /// Build a provider from a GCS client, a Pub/Sub client, the target bucket, and
    /// the GCP project id (for the topic resource + notification config).
    pub fn new(
        gcs: GcsClient,
        pubsub: PubsubClient,
        bucket: impl Into<String>,
        project: impl Into<String>,
    ) -> Self {
        Self {
            gcs,
            pubsub,
            bucket: bucket.into(),
            project: project.into(),
        }
    }
}

#[async_trait]
impl WatchProvider for GcsWatchProvider {
    fn name(&self) -> &str {
        "gcs"
    }

    fn recipe(&self, prefix: &str) -> String {
        let topic = topic_name(prefix);
        let sub = subscription_name(prefix);
        format!(
            "GCS→Pub/Sub blob-change pipeline for bucket {bucket:?}, prefix {prefix:?}:\n  \
             1. Create Pub/Sub topic {topic:?} and subscription {sub:?} in project {project:?}.\n  \
             2. Grant the GCS service agent \
             (service-<project-number>@gs-project-accounts.iam.gserviceaccount.com) \
             roles/pubsub.publisher on the topic.\n  \
             3. Create a bucket notificationConfig on {bucket:?}: topic \
             projects/{project}/topics/{topic}, event types \
             [OBJECT_FINALIZE, OBJECT_DELETE], object_name_prefix {prefix:?}, \
             payload_format JSON_API_V1.\n\
             boatramp then pulls + acks the subscription and enqueues one invocation \
             per change.",
            bucket = self.bucket,
            project = self.project,
        )
    }

    async fn provision(&self, prefix: &str) -> Result<Vec<ManagedResource>, ProvisionError> {
        let topic_id = topic_name(prefix);
        let sub_id = subscription_name(prefix);

        // 1. Topic (idempotent via exists-guard).
        let topic = self.pubsub.topic(&topic_id);
        if !topic.exists(None).await.map_err(ps_err)? {
            topic.create(None, None).await.map_err(ps_err)?;
        }
        let topic_fqn = topic.fully_qualified_name().to_string();

        // 2. Subscription (idempotent).
        let subscription = self.pubsub.subscription(&sub_id);
        if !subscription.exists(None).await.map_err(ps_err)? {
            subscription
                .create(
                    &topic_fqn,
                    SubscriptionConfig {
                        ack_deadline_seconds: 60,
                        ..Default::default()
                    },
                    None,
                )
                .await
                .map_err(ps_err)?;
        }

        // 3. Bucket notificationConfig.
        let notification = self
            .gcs
            .insert_notification(&InsertNotificationRequest {
                bucket: self.bucket.clone(),
                notification: NotificationCreationConfig {
                    topic: topic_resource(&self.project, &topic_id),
                    event_types: Some(vec![EventType::ObjectFinalize, EventType::ObjectDelete]),
                    object_name_prefix: Some(prefix.to_string()),
                    payload_format: PayloadFormat::JsonApiV1,
                    ..Default::default()
                },
            })
            .await
            .map_err(gcs_err)?;

        Ok(vec![
            ManagedResource::new("pubsub-topic", topic_id),
            ManagedResource::new("pubsub-subscription", sub_id),
            ManagedResource::new("bucket-notification", notification.id),
        ])
    }

    async fn verify(&self, prefix: &str) -> Result<bool, ProvisionError> {
        let topic = topic_resource(&self.project, &topic_name(prefix));
        let resp = self
            .gcs
            .list_notifications(&ListNotificationsRequest {
                bucket: self.bucket.clone(),
            })
            .await
            .map_err(gcs_err)?;
        Ok(resp
            .items
            .unwrap_or_default()
            .iter()
            .any(|n| n.topic == topic))
    }

    async fn retract(&self, resources: &[ManagedResource]) -> Result<(), ProvisionError> {
        // Delete the bucket notification, then the subscription, then the topic —
        // best-effort (a missing resource is not an error).
        if let Some(notification) = resources.iter().find(|r| r.kind == "bucket-notification") {
            let _ = self
                .gcs
                .delete_notification(&DeleteNotificationRequest {
                    bucket: self.bucket.clone(),
                    notification: notification.id.clone(),
                })
                .await;
        }
        if let Some(subscription) = resources.iter().find(|r| r.kind == "pubsub-subscription") {
            let _ = self
                .pubsub
                .subscription(&subscription.id)
                .delete(None)
                .await;
        }
        if let Some(topic) = resources.iter().find(|r| r.kind == "pubsub-topic") {
            let _ = self.pubsub.topic(&topic.id).delete(None).await;
        }
        Ok(())
    }
}

// ===========================================================================
// Consumer (data plane)
// ===========================================================================

/// Pull `subscription`, yielding a [`BlobChange`] per GCS notification under
/// `prefix`. Each message is acked once its change is queued for delivery. A pull
/// error ends the stream — the scheduler's watcher reconcile respawns it.
pub(crate) fn gcs_watch_stream(subscription: Subscription, prefix: String) -> ChangeStream {
    let state = (subscription, prefix, VecDeque::<BlobChange>::new());
    futures::stream::unfold(state, |(subscription, prefix, mut pending)| async move {
        loop {
            if let Some(change) = pending.pop_front() {
                return Some((change, (subscription, prefix, pending)));
            }
            let messages = match subscription.pull(10, None).await {
                Ok(messages) => messages,
                Err(_) => return None, // transient — reconcile respawns the watcher
            };
            for message in messages {
                let change = parse_gcs_notification(&message.message.attributes);
                // Ack regardless: an unparseable/irrelevant message must not redeliver.
                let _ = message.ack().await;
                if let Some(change) = change {
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

fn gcs_err(err: google_cloud_storage::http::Error) -> ProvisionError {
    ProvisionError::Backend(err.to_string())
}

/// Map any Pub/Sub SDK error (a gRPC `Status`) to a provisioning error, without
/// naming the gax type (it is not re-exported by the pubsub crate).
fn ps_err<E: std::fmt::Display>(err: E) -> ProvisionError {
    ProvisionError::Backend(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_deterministic() {
        assert_eq!(
            topic_name("hblob/fn/ingest/uploads/"),
            "boatramp-hblob-fn-ingest-uploads"
        );
        assert_eq!(
            subscription_name("hblob/fn/ingest/uploads/"),
            "boatramp-hblob-fn-ingest-uploads-sub"
        );
        assert_eq!(
            topic_resource("my-project", "boatramp-x"),
            "//pubsub.googleapis.com/projects/my-project/topics/boatramp-x"
        );
    }

    #[test]
    fn event_types_map() {
        assert_eq!(
            event_type_to_kind("OBJECT_FINALIZE"),
            Some(BlobChangeKind::Created)
        );
        assert_eq!(
            event_type_to_kind("OBJECT_DELETE"),
            Some(BlobChangeKind::Removed)
        );
        assert_eq!(
            event_type_to_kind("OBJECT_METADATA_UPDATE"),
            Some(BlobChangeKind::Modified)
        );
        assert_eq!(event_type_to_kind("SOMETHING_ELSE"), None);
    }

    #[test]
    fn parses_a_notification_from_attributes() {
        let mut attrs = HashMap::new();
        attrs.insert("eventType".to_string(), "OBJECT_FINALIZE".to_string());
        attrs.insert(
            "objectId".to_string(),
            "hblob/fn/ingest/uploads/report.json".to_string(),
        );
        let change = parse_gcs_notification(&attrs).unwrap();
        assert_eq!(change.key, "hblob/fn/ingest/uploads/report.json");
        assert_eq!(change.kind, BlobChangeKind::Created);
    }

    #[test]
    fn ignores_unknown_or_incomplete_notifications() {
        // Missing objectId.
        let mut attrs = HashMap::new();
        attrs.insert("eventType".to_string(), "OBJECT_FINALIZE".to_string());
        assert!(parse_gcs_notification(&attrs).is_none());
        // Unmapped event.
        let mut attrs = HashMap::new();
        attrs.insert("eventType".to_string(), "OBJECT_ARCHIVE".to_string());
        attrs.insert("objectId".to_string(), "k".to_string());
        // ARCHIVE maps to Removed, so this one is Some — assert an unknown one isn't.
        assert!(parse_gcs_notification(&attrs).is_some());
        let empty = HashMap::new();
        assert!(parse_gcs_notification(&empty).is_none());
    }
}
