//! Live seam for the GCS → Pub/Sub blob-change notification pipeline
//! (PLAN-storage-backends S3 / FA-5b2 GCS). Needs **real GCP** (Pub/Sub +
//! bucket-notification provisioning have no emulator), so it is env-gated and skips
//! cleanly without creds — the pure provisioning logic (naming, notification parse,
//! event mapping) is covered by the unit tests in `gcs_notify`.
//!
//! Run against GCP (a service account allowed to manage Pub/Sub topics/
//! subscriptions + the bucket's notificationConfigs; the GCS service agent needs
//! roles/pubsub.publisher on the topic — see the provider recipe):
//! ```sh
//! GOOGLE_APPLICATION_CREDENTIALS=/path/sa.json \
//! BOATRAMP_TEST_GCS_NOTIFY_BUCKET=my-bucket \
//! BOATRAMP_TEST_GCP_PROJECT=my-project \
//!   cargo test -p boatramp-storage --features gcs --test gcs_notify_live -- --ignored --nocapture
//! ```
#![cfg(feature = "gcs")]

use boatramp_core::blob_provision::WatchProvider;

#[tokio::test]
#[ignore = "needs real GCP (Pub/Sub + a bucket); env-gated"]
async fn gcs_notify_provision_verify_retract_round_trip() {
    let (Ok(bucket), Ok(project)) = (
        std::env::var("BOATRAMP_TEST_GCS_NOTIFY_BUCKET"),
        std::env::var("BOATRAMP_TEST_GCP_PROJECT"),
    ) else {
        eprintln!(
            "skipping: set BOATRAMP_TEST_GCS_NOTIFY_BUCKET + BOATRAMP_TEST_GCP_PROJECT \
             (and GOOGLE_APPLICATION_CREDENTIALS) to run the live GCS→Pub/Sub test"
        );
        return;
    };

    // Reuse the storage backend's notify constructor to build a paired GCS + Pub/Sub
    // provider from Application Default Credentials.
    let (_storage, provider) = boatramp_storage::GcsStorage::connect_with_notify(
        boatramp_storage::GcsOptions {
            bucket,
            endpoint: None,
            anonymous: false,
        },
        project,
    )
    .await
    .expect("connect_with_notify");

    let prefix = "hblob/fn/notify-live-test/uploads/";

    let resources = provider.provision(prefix).await.expect("provision");
    assert!(resources.iter().any(|r| r.kind == "pubsub-topic"));
    assert!(resources.iter().any(|r| r.kind == "pubsub-subscription"));
    assert!(resources.iter().any(|r| r.kind == "bucket-notification"));
    assert!(provider.verify(prefix).await.expect("verify"), "present");

    // Idempotent re-provision.
    let again = provider.provision(prefix).await.expect("re-provision");
    assert_eq!(again.len(), resources.len());

    provider.retract(&resources).await.expect("retract");
    assert!(
        !provider.verify(prefix).await.expect("verify after retract"),
        "gone after retract"
    );
}
