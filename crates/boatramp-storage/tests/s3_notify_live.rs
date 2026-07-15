//! Live seam for the S3 → SQS blob-change notification pipeline (FA-5b2). Unlike
//! the object round-trip, this needs **real AWS** (MinIO does not speak SQS
//! bucket notifications), so it is env-gated and skips cleanly without creds — the
//! pure provisioning logic (merge/conflict/parse/policy) is covered by the unit
//! tests in `s3_notify`.
//!
//! Run against AWS (an IAM identity allowed to create/delete SQS queues, set queue
//! attributes, and Get/Put the bucket notification config):
//! ```sh
//! AWS_REGION=us-east-1 \
//! BOATRAMP_TEST_S3_NOTIFY_BUCKET=my-bucket \
//! BOATRAMP_TEST_AWS_ACCOUNT_ID=123456789012 \
//!   cargo test -p boatramp-storage --features s3 --test s3_notify_live -- --ignored --nocapture
//! ```
#![cfg(feature = "s3")]

use boatramp_core::blob_provision::WatchProvider;
use boatramp_storage::s3_notify::S3WatchProvider;

#[tokio::test]
#[ignore = "needs real AWS (SQS + a bucket); env-gated"]
async fn s3_notify_provision_verify_retract_round_trip() {
    let (Ok(bucket), Ok(account)) = (
        std::env::var("BOATRAMP_TEST_S3_NOTIFY_BUCKET"),
        std::env::var("BOATRAMP_TEST_AWS_ACCOUNT_ID"),
    ) else {
        eprintln!(
            "skipping: set BOATRAMP_TEST_S3_NOTIFY_BUCKET + BOATRAMP_TEST_AWS_ACCOUNT_ID \
             (and AWS_* creds/region) to run the live S3→SQS provisioning test"
        );
        return;
    };

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3 = aws_sdk_s3::Client::new(&config);
    let sqs = aws_sdk_sqs::Client::new(&config);
    let provider = S3WatchProvider::new(s3, sqs, bucket, account);

    let prefix = "hblob/fn/notify-live-test/uploads/";

    // Provision, then verify the pipeline is present.
    let resources = provider.provision(prefix).await.expect("provision");
    assert!(
        resources.iter().any(|r| r.kind == "sqs-queue"),
        "a queue was recorded"
    );
    assert!(
        resources.iter().any(|r| r.kind == "bucket-notification"),
        "the bucket-notification entry was recorded"
    );
    assert!(
        provider.verify(prefix).await.expect("verify"),
        "pipeline present"
    );

    // Provisioning again is idempotent (same resources, no conflict).
    let again = provider
        .provision(prefix)
        .await
        .expect("re-provision idempotent");
    assert_eq!(again.len(), resources.len());

    // Retract removes both the notification entry and the queue.
    provider.retract(&resources).await.expect("retract");
    assert!(
        !provider.verify(prefix).await.expect("verify after retract"),
        "pipeline gone after retract"
    );
}
