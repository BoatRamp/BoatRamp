//! Concrete **S3 → SQS** blob-change notification provider + consumer
//! (PLAN-faas FA-5b2). This is the cloud counterpart to `FsStorage`'s
//! inotify/FSEvents watch: it provisions the native S3 event pipeline
//! (an SQS queue + queue policy + a bucket `QueueConfiguration`) so a
//! `Blob { prefix }` trigger fires for **any** writer, and it consumes that
//! queue to yield [`BlobChange`]s for the same prefix.
//!
//! Two halves, both here:
//! - **Provisioning** ([`S3WatchProvider`], the control-plane side): implements
//!   [`WatchProvider`] with the security-critical **read-merge-write** of the
//!   bucket notification document (S3 allows exactly one notification doc per
//!   bucket, so existing entries are preserved and an overlapping foreign entry
//!   is *refused*, never clobbered).
//! - **Consuming** ([`s3_watch_stream`], the data-plane side, wired into
//!   [`S3Storage::watch`](crate::s3::S3Storage)): long-polls the queue, parses
//!   the S3 event JSON into [`BlobChange`]s, and deletes each message on receipt.
//!
//! The pure helpers (queue naming, the merge/conflict guard, the S3-event JSON
//! parse, the queue policy) are unit-tested natively; the SDK-calling methods are
//! exercised against real AWS behind the `#[ignore]`d live seam.

use std::collections::VecDeque;

use async_trait::async_trait;
use aws_sdk_s3::operation::get_bucket_notification_configuration::GetBucketNotificationConfigurationOutput;
use aws_sdk_s3::types::{
    Event, FilterRule, FilterRuleName, NotificationConfiguration, NotificationConfigurationFilter,
    QueueConfiguration, S3KeyFilter,
};
use aws_sdk_sqs::types::QueueAttributeName;
use boatramp_core::blob_notify::{prefix_slug, ManagedResource};
use boatramp_core::blob_provision::{ProvisionError, WatchProvider};
use boatramp_core::{BlobChange, BlobChangeKind, ChangeStream};
use futures::StreamExt;

// ===========================================================================
// Pure helpers (natively unit-tested; no SDK, no IO)
// ===========================================================================

/// The SQS queue name backing a watched storage prefix. Deterministic so the
/// provider (which creates it) and the consumer (which polls it) agree without a
/// lookup table. SQS queue names allow `[A-Za-z0-9_-]` up to 80 chars; the prefix
/// slug is already alnum+`-`, and an over-long name is truncated with a stable
/// hash suffix to preserve uniqueness.
pub(crate) fn queue_name(storage_prefix: &str) -> String {
    let base = format!("boatramp-{}", prefix_slug(storage_prefix));
    if base.len() <= 80 {
        return base;
    }
    let suffix = format!("-{:08x}", fnv1a(storage_prefix));
    let keep = 80 - suffix.len();
    format!("{}{}", &base[..keep], suffix)
}

/// The stable `Id` of the bucket `QueueConfiguration` boatramp owns for a prefix.
/// Retraction deletes exactly the entry with this id, and re-provisioning replaces
/// it (idempotent).
pub(crate) fn notification_id(storage_prefix: &str) -> String {
    format!("boatramp-{}", prefix_slug(storage_prefix))
}

/// A tiny non-cryptographic hash for deterministic queue-name disambiguation.
fn fnv1a(s: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in s.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// The SQS access policy letting this bucket's S3 events post to the queue —
/// scoped by `SourceArn` (the bucket) and `SourceAccount` so no other bucket or
/// account can send.
pub(crate) fn queue_access_policy(queue_arn: &str, bucket: &str, account_id: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "boatramp-s3-notify",
            "Effect": "Allow",
            "Principal": { "Service": "s3.amazonaws.com" },
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {
                "ArnLike": { "aws:SourceArn": format!("arn:aws:s3:::{bucket}") },
                "StringEquals": { "aws:SourceAccount": account_id }
            }
        }]
    })
    .to_string()
}

/// A flattened view of one existing bucket-notification entry (queue, topic, or
/// lambda), enough to decide whether it collides with the one boatramp wants to
/// add — the input to [`check_merge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NotifyEntry {
    /// The entry's `Id` (empty if S3 assigned none).
    pub id: String,
    /// The entry's key-prefix filter (`""` = whole bucket).
    pub prefix: String,
    /// Whether it subscribes to object-created events.
    pub created: bool,
    /// Whether it subscribes to object-removed events.
    pub removed: bool,
}

/// Two prefixes overlap iff one is a prefix of the other (S3 rejects overlapping
/// filters for the same event type across *all* notification entries).
fn prefixes_overlap(a: &str, b: &str) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// The **read-merge-write conflict guard**. Given the bucket's existing entries,
/// decide whether boatramp may add its own (`our_id`, `our_prefix`, subscribing to
/// both created + removed). Our own prior entry (same id) is ignored — it is
/// replaced. A *foreign* entry that overlaps our prefix for a shared event type is
/// a conflict: S3 would reject the write, and silently clobbering it is unsafe, so
/// we refuse cleanly. Returns `Ok(())` when the merge is safe.
pub(crate) fn check_merge(
    existing: &[NotifyEntry],
    our_id: &str,
    our_prefix: &str,
) -> Result<(), String> {
    for e in existing {
        if e.id == our_id {
            continue; // our own prior entry — replaced in place
        }
        // We register both created + removed, so any foreign entry with either
        // event and an overlapping prefix collides.
        if (e.created || e.removed) && prefixes_overlap(&e.prefix, our_prefix) {
            return Err(format!(
                "a bucket notification (id {:?}, prefix {:?}) already overlaps prefix {:?} \
                 for the same events — refusing to clobber it",
                e.id, e.prefix, our_prefix
            ));
        }
    }
    Ok(())
}

/// Parse one SQS message body — an S3 event notification — into the changes it
/// carries. Unknown shapes (e.g. the `s3:TestEvent` S3 sends on setup) and events
/// we don't map yield nothing. Keys are URL-decoded (S3 percent-encodes them).
pub(crate) fn parse_s3_event(body: &str) -> Vec<BlobChange> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(records) = value.get("Records").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rec in records {
        let Some(name) = rec.get("eventName").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(kind) = event_name_to_kind(name) else {
            continue;
        };
        let Some(key) = rec.pointer("/s3/object/key").and_then(|k| k.as_str()) else {
            continue;
        };
        out.push(BlobChange {
            key: percent_decode(key),
            kind,
        });
    }
    out
}

/// Map an S3 event name to a [`BlobChangeKind`]. S3 cannot distinguish a create
/// from an overwrite (both are `ObjectCreated:*`), so a write is always reported as
/// `Created`; `ObjectRemoved:*` is `Removed`. The name may be prefixed with `s3:`
/// (notification-config form) or not (message form).
fn event_name_to_kind(name: &str) -> Option<BlobChangeKind> {
    let n = name.strip_prefix("s3:").unwrap_or(name);
    if n.starts_with("ObjectCreated") {
        Some(BlobChangeKind::Created)
    } else if n.starts_with("ObjectRemoved") {
        Some(BlobChangeKind::Removed)
    } else {
        None
    }
}

/// Decode an S3 object key from its notification form: `+` → space and `%XX` →
/// byte. Invalid escapes are passed through literally.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ===========================================================================
// Provider (control plane)
// ===========================================================================

/// Provisions + retracts the S3 → SQS notification pipeline for one bucket. Holds
/// its own S3 + SQS clients (they may differ from the data-plane clients) and the
/// account id needed to scope the queue policy.
#[derive(Clone)]
pub struct S3WatchProvider {
    s3: aws_sdk_s3::Client,
    sqs: aws_sdk_sqs::Client,
    bucket: String,
    account_id: String,
}

impl S3WatchProvider {
    /// Build a provider from S3 + SQS clients, the target bucket, and the AWS
    /// account id (used to scope the queue's `SendMessage` policy).
    pub fn new(
        s3: aws_sdk_s3::Client,
        sqs: aws_sdk_sqs::Client,
        bucket: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Self {
        Self {
            s3,
            sqs,
            bucket: bucket.into(),
            account_id: account_id.into(),
        }
    }

    /// Read the bucket's current notification config.
    async fn read_config(
        &self,
    ) -> Result<GetBucketNotificationConfigurationOutput, ProvisionError> {
        self.s3
            .get_bucket_notification_configuration()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(s3_err)
    }

    /// Write a notification config back, preserving every non-queue entry and the
    /// queue entries we do not own.
    async fn write_config(&self, cfg: NotificationConfiguration) -> Result<(), ProvisionError> {
        self.s3
            .put_bucket_notification_configuration()
            .bucket(&self.bucket)
            .notification_configuration(cfg)
            .send()
            .await
            .map_err(s3_err)?;
        Ok(())
    }
}

#[async_trait]
impl WatchProvider for S3WatchProvider {
    fn name(&self) -> &str {
        "s3"
    }

    fn recipe(&self, prefix: &str) -> String {
        let qname = queue_name(prefix);
        let our_id = notification_id(prefix);
        format!(
            "S3→SQS blob-change pipeline for bucket {bucket:?}, prefix {prefix:?}:\n  \
             1. Create SQS queue {qname:?}.\n  \
             2. Set its access policy to allow s3.amazonaws.com (aws:SourceAccount {account:?}, \
             aws:SourceArn arn:aws:s3:::{bucket}) the sqs:SendMessage action.\n  \
             3. PutBucketNotificationConfiguration adding a QueueConfiguration id={our_id:?}, \
             events [s3:ObjectCreated:*, s3:ObjectRemoved:*], filter prefix {prefix:?} — \
             merging with (never replacing) any existing entries.\n\
             boatramp then consumes + deletes messages from the queue and enqueues one \
             invocation per change.",
            bucket = self.bucket,
            account = self.account_id,
        )
    }

    async fn provision(&self, prefix: &str) -> Result<Vec<ManagedResource>, ProvisionError> {
        // 1. Create (or reuse) the queue.
        let qname = queue_name(prefix);
        let created = self
            .sqs
            .create_queue()
            .queue_name(&qname)
            .send()
            .await
            .map_err(sqs_err)?;
        let queue_url = created
            .queue_url()
            .ok_or_else(|| ProvisionError::Backend("SQS did not return a queue url".to_string()))?
            .to_string();

        // 2. Resolve its ARN.
        let attrs = self
            .sqs
            .get_queue_attributes()
            .queue_url(&queue_url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .map_err(sqs_err)?;
        let queue_arn = attrs
            .attributes()
            .and_then(|m| m.get(&QueueAttributeName::QueueArn))
            .cloned()
            .ok_or_else(|| ProvisionError::Backend("SQS did not return a queue ARN".to_string()))?;

        // 3. Grant this bucket permission to post to the queue.
        let policy = queue_access_policy(&queue_arn, &self.bucket, &self.account_id);
        self.sqs
            .set_queue_attributes()
            .queue_url(&queue_url)
            .attributes(QueueAttributeName::Policy, policy)
            .send()
            .await
            .map_err(sqs_err)?;

        // 4. Read-merge-write the bucket notification config, refusing to clobber
        //    a foreign overlapping entry.
        let our_id = notification_id(prefix);
        let existing = self.read_config().await?;
        check_merge(&extract_entries(&existing), &our_id, prefix)
            .map_err(ProvisionError::Conflict)?;
        let merged = build_merged_config(&existing, &our_id, &queue_arn, prefix)?;
        self.write_config(merged).await?;

        Ok(vec![
            ManagedResource::new("sqs-queue", queue_url),
            ManagedResource::new("bucket-notification", our_id),
        ])
    }

    async fn verify(&self, prefix: &str) -> Result<bool, ProvisionError> {
        let our_id = notification_id(prefix);
        let existing = self.read_config().await?;
        Ok(existing
            .queue_configurations()
            .iter()
            .any(|qc| qc.id() == Some(our_id.as_str())))
    }

    async fn retract(&self, resources: &[ManagedResource]) -> Result<(), ProvisionError> {
        // 1. Drop our bucket-notification entry (read-modify-write; leaves foreign
        //    entries untouched).
        if let Some(bn) = resources.iter().find(|r| r.kind == "bucket-notification") {
            let existing = self.read_config().await?;
            let cfg = drop_our_queue_config(&existing, &bn.id);
            self.write_config(cfg).await?;
        }
        // 2. Delete the queue (a missing queue is not an error).
        if let Some(q) = resources.iter().find(|r| r.kind == "sqs-queue") {
            let _ = self.sqs.delete_queue().queue_url(&q.id).send().await;
        }
        Ok(())
    }
}

/// Flatten every existing notification entry (queue/topic/lambda) into the view
/// [`check_merge`] needs.
fn extract_entries(cfg: &GetBucketNotificationConfigurationOutput) -> Vec<NotifyEntry> {
    let mut out = Vec::new();
    for qc in cfg.queue_configurations() {
        out.push(entry_from(qc.id(), qc.filter(), qc.events()));
    }
    for tc in cfg.topic_configurations() {
        out.push(entry_from(tc.id(), tc.filter(), tc.events()));
    }
    for lc in cfg.lambda_function_configurations() {
        out.push(entry_from(lc.id(), lc.filter(), lc.events()));
    }
    out
}

/// Build a [`NotifyEntry`] from an entry's id, filter, and event list.
fn entry_from(
    id: Option<&str>,
    filter: Option<&NotificationConfigurationFilter>,
    events: &[Event],
) -> NotifyEntry {
    let prefix = filter
        .and_then(|f| f.key())
        .map(aws_sdk_s3::types::S3KeyFilter::filter_rules)
        .into_iter()
        .flatten()
        .find(|r| {
            r.name()
                .map(|n| n.as_str().eq_ignore_ascii_case("prefix"))
                .unwrap_or(false)
        })
        .and_then(|r| r.value())
        .unwrap_or("")
        .to_string();
    NotifyEntry {
        id: id.unwrap_or("").to_string(),
        prefix,
        created: events
            .iter()
            .any(|e| e.as_str().starts_with("s3:ObjectCreated")),
        removed: events
            .iter()
            .any(|e| e.as_str().starts_with("s3:ObjectRemoved")),
    }
}

/// The QueueConfiguration boatramp owns for `prefix` (created + removed, prefix
/// filtered, stable id).
fn our_queue_config(
    our_id: &str,
    queue_arn: &str,
    prefix: &str,
) -> Result<QueueConfiguration, ProvisionError> {
    let key = S3KeyFilter::builder()
        .filter_rules(
            FilterRule::builder()
                .name(FilterRuleName::Prefix)
                .value(prefix)
                .build(),
        )
        .build();
    QueueConfiguration::builder()
        .id(our_id)
        .queue_arn(queue_arn)
        .events(Event::from("s3:ObjectCreated:*"))
        .events(Event::from("s3:ObjectRemoved:*"))
        .filter(NotificationConfigurationFilter::builder().key(key).build())
        .build()
        .map_err(|e| ProvisionError::Backend(e.to_string()))
}

/// The merged config to write on provision: our (replaced) queue entry plus every
/// foreign queue/topic/lambda entry, preserved verbatim.
fn build_merged_config(
    existing: &GetBucketNotificationConfigurationOutput,
    our_id: &str,
    queue_arn: &str,
    prefix: &str,
) -> Result<NotificationConfiguration, ProvisionError> {
    let mut queues: Vec<QueueConfiguration> = existing
        .queue_configurations()
        .iter()
        .filter(|qc| qc.id() != Some(our_id))
        .cloned()
        .collect();
    queues.push(our_queue_config(our_id, queue_arn, prefix)?);
    Ok(NotificationConfiguration::builder()
        .set_queue_configurations(Some(queues))
        .set_topic_configurations(Some(existing.topic_configurations().to_vec()))
        .set_lambda_function_configurations(Some(
            existing.lambda_function_configurations().to_vec(),
        ))
        .build())
}

/// The config to write on retract: everything except our own queue entry.
fn drop_our_queue_config(
    existing: &GetBucketNotificationConfigurationOutput,
    our_id: &str,
) -> NotificationConfiguration {
    let queues: Vec<QueueConfiguration> = existing
        .queue_configurations()
        .iter()
        .filter(|qc| qc.id() != Some(our_id))
        .cloned()
        .collect();
    NotificationConfiguration::builder()
        .set_queue_configurations(Some(queues))
        .set_topic_configurations(Some(existing.topic_configurations().to_vec()))
        .set_lambda_function_configurations(Some(
            existing.lambda_function_configurations().to_vec(),
        ))
        .build()
}

// ===========================================================================
// Consumer (data plane)
// ===========================================================================

/// Long-poll `queue_url`, yielding a [`BlobChange`] per S3 event under `prefix`.
/// Each message is deleted (acked) once its events are queued for delivery. A
/// receive error ends the stream — the scheduler's watcher reconcile respawns it.
pub(crate) fn s3_watch_stream(
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
    prefix: String,
) -> ChangeStream {
    let state = (sqs, queue_url, prefix, VecDeque::<BlobChange>::new());
    futures::stream::unfold(state, |(sqs, url, prefix, mut pending)| async move {
        loop {
            if let Some(change) = pending.pop_front() {
                return Some((change, (sqs, url, prefix, pending)));
            }
            let resp = match sqs
                .receive_message()
                .queue_url(&url)
                .max_number_of_messages(10)
                .wait_time_seconds(20)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(_) => return None, // transient — reconcile respawns the watcher
            };
            for msg in resp.messages() {
                let changes = msg.body().map(parse_s3_event).unwrap_or_default();
                // Ack the message: its events are now queued for delivery.
                if let Some(handle) = msg.receipt_handle() {
                    let _ = sqs
                        .delete_message()
                        .queue_url(&url)
                        .receipt_handle(handle)
                        .send()
                        .await;
                }
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

fn s3_err<E, R>(err: aws_sdk_s3::error::SdkError<E, R>) -> ProvisionError
where
    aws_sdk_s3::error::SdkError<E, R>: std::error::Error,
{
    ProvisionError::Backend(aws_sdk_s3::error::DisplayErrorContext(&err).to_string())
}

fn sqs_err<E, R>(err: aws_sdk_sqs::error::SdkError<E, R>) -> ProvisionError
where
    aws_sdk_sqs::error::SdkError<E, R>: std::error::Error,
{
    ProvisionError::Backend(aws_sdk_sqs::error::DisplayErrorContext(&err).to_string())
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
        // Over-long prefixes truncate to ≤80 chars with a stable hash suffix.
        let long = format!("hblob/fn/{}/", "a".repeat(200));
        let name = queue_name(&long);
        assert!(
            name.len() <= 80,
            "queue name {name:?} exceeds the SQS limit"
        );
        assert_eq!(name, queue_name(&long), "must be deterministic");
    }

    #[test]
    fn notification_id_matches_queue_slug() {
        assert_eq!(
            notification_id("hblob/fn/ingest/uploads/"),
            "boatramp-hblob-fn-ingest-uploads"
        );
    }

    #[test]
    fn queue_policy_scopes_to_the_bucket_and_account() {
        let policy = queue_access_policy(
            "arn:aws:sqs:us-east-1:123456789012:boatramp-x",
            "my-bucket",
            "123456789012",
        );
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmt = &v["Statement"][0];
        assert_eq!(stmt["Principal"]["Service"], "s3.amazonaws.com");
        assert_eq!(stmt["Action"], "sqs:SendMessage");
        assert_eq!(
            stmt["Condition"]["ArnLike"]["aws:SourceArn"],
            "arn:aws:s3:::my-bucket"
        );
        assert_eq!(
            stmt["Condition"]["StringEquals"]["aws:SourceAccount"],
            "123456789012"
        );
    }

    fn entry(id: &str, prefix: &str, created: bool, removed: bool) -> NotifyEntry {
        NotifyEntry {
            id: id.to_string(),
            prefix: prefix.to_string(),
            created,
            removed,
        }
    }

    #[test]
    fn merge_allows_disjoint_prefixes_and_replaces_our_own() {
        let existing = vec![
            entry("someone-else", "invoices/", true, false),
            entry("boatramp-x", "uploads/", true, true), // our prior entry
        ];
        // Disjoint foreign prefix + our own id present → safe.
        assert!(check_merge(&existing, "boatramp-x", "uploads/photos/").is_ok());
    }

    #[test]
    fn merge_refuses_a_foreign_overlapping_entry() {
        // A foreign entry watching a parent of our prefix, for a shared event.
        let existing = vec![entry("legacy", "uploads/", true, false)];
        let err = check_merge(&existing, "boatramp-x", "uploads/photos/").unwrap_err();
        assert!(err.contains("refusing to clobber"), "unexpected: {err}");

        // A foreign entry watching a child of our prefix also overlaps.
        let existing = vec![entry("legacy", "uploads/photos/deep/", false, true)];
        assert!(check_merge(&existing, "boatramp-x", "uploads/").is_err());
    }

    #[test]
    fn merge_ignores_foreign_entries_with_no_relevant_events() {
        // Overlapping prefix but no created/removed subscription → no conflict.
        let existing = vec![entry("legacy", "uploads/", false, false)];
        assert!(check_merge(&existing, "boatramp-x", "uploads/").is_ok());
    }

    #[test]
    fn parses_an_s3_event_and_url_decodes_the_key() {
        let body = r#"{
            "Records": [
                {"eventName": "ObjectCreated:Put",
                 "s3": {"object": {"key": "hblob/fn/ingest/uploads/a+b%2Fc.txt"}}},
                {"eventName": "ObjectRemoved:Delete",
                 "s3": {"object": {"key": "hblob/fn/ingest/uploads/gone.bin"}}}
            ]
        }"#;
        let changes = parse_s3_event(body);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].key, "hblob/fn/ingest/uploads/a b/c.txt");
        assert_eq!(changes[0].kind, BlobChangeKind::Created);
        assert_eq!(changes[1].kind, BlobChangeKind::Removed);
    }

    #[test]
    fn ignores_the_s3_test_event_and_unknown_shapes() {
        let test_event = r#"{"Service":"Amazon S3","Event":"s3:TestEvent"}"#;
        assert!(parse_s3_event(test_event).is_empty());
        assert!(parse_s3_event("not json").is_empty());
        assert!(parse_s3_event(r#"{"Records": []}"#).is_empty());
    }

    #[test]
    fn event_names_map_with_or_without_the_s3_prefix() {
        assert_eq!(
            event_name_to_kind("ObjectCreated:CompleteMultipartUpload"),
            Some(BlobChangeKind::Created)
        );
        assert_eq!(
            event_name_to_kind("s3:ObjectRemoved:DeleteMarkerCreated"),
            Some(BlobChangeKind::Removed)
        );
        assert_eq!(event_name_to_kind("s3:ReducedRedundancyLostObject"), None);
    }
}
