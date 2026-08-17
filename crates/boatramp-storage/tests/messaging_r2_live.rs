//! **Live** (ignored): the boatramp messaging fabric ([`LogMessaging`]) running
//! over the exact durable backends the Cloudflare container uses — a SlateDB KV
//! **on R2** and blob storage **on R2** (S3 API). This is the "messaging battery
//! on the Cloudflare backends": publish, the competing-consumer work queue
//! (claim/ack/backlog), and durable **consumer-group fan-out** (two groups each
//! independently see every message), all against real R2 rather than in-memory
//! test doubles.
//!
//! Needs `BR_R2_TEST_BUCKET` + `BR_R2_TEST_ENDPOINT` (+ optional
//! `BR_R2_TEST_REGION`) and ambient `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
//! Run with: `cargo test -p boatramp-storage --features s3,slatedb --test
//! messaging_r2_live -- --ignored --nocapture`.
#![cfg(all(feature = "s3", feature = "slatedb"))]

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::kv::KvStore;
use boatramp_core::messaging::{LogMessaging, Messaging, StartPosition};
use boatramp_core::Storage;
use boatramp_storage::{S3Options, S3Storage, S3StoreConfig, SlateKv};

#[tokio::test]
#[ignore = "needs live R2 (BR_R2_TEST_BUCKET/ENDPOINT + AWS creds)"]
async fn messaging_fabric_over_r2_backends() {
    let Ok(bucket) = std::env::var("BR_R2_TEST_BUCKET") else {
        eprintln!("skipping: BR_R2_TEST_BUCKET not set");
        return;
    };
    let endpoint = std::env::var("BR_R2_TEST_ENDPOINT").ok();
    let region = std::env::var("BR_R2_TEST_REGION").ok();

    let storage: Arc<dyn Storage> = Arc::new(
        S3Storage::connect(S3Options {
            bucket: bucket.clone(),
            endpoint: endpoint.clone(),
            region: region.clone(),
            force_path_style: true,
        })
        .await,
    );
    let kv: Arc<dyn KvStore> = Arc::new(
        SlateKv::open_s3_with_flush(
            &S3StoreConfig {
                bucket,
                endpoint,
                region,
                path_style: true,
            },
            "_kv-msgtest",
            Duration::from_millis(5),
        )
        .await
        .expect("open SlateDB on R2"),
    );

    let mq = LogMessaging::new(storage, kv);
    let lease = Duration::from_secs(30);

    // Work queue (competing consumers): publish two, claim both, ack, backlog → 0.
    let wq = "bus/r2-workqueue";
    // Drain any residue from a prior run so the counts are exact.
    for m in mq.claim(wq, lease, 100, 5).await.unwrap() {
        mq.ack(&m).await.unwrap();
    }
    mq.publish(wq, b"m1").await.unwrap();
    mq.publish(wq, b"m2").await.unwrap();
    let batch = mq.claim(wq, lease, 10, 5).await.unwrap();
    assert_eq!(batch.len(), 2, "work-queue delivered both messages");
    for m in &batch {
        mq.ack(m).await.unwrap();
    }
    assert_eq!(mq.backlog(wq).await.unwrap(), 0, "backlog drains after ack");

    // Consumer-group fan-out: two groups each independently see every message.
    // The fabric shape is "consumers subscribe, then events flow": the first
    // grouped claim registers a group (its durable cursor starts at `Latest`) and
    // turns on retention. The R2 KV persists across runs, so first drain any
    // residue — that also (re)registers each group at the current tip.
    let ft = "bus/r2-fanout";
    for group in ["group-a", "group-b"] {
        loop {
            let claimed = mq
                .claim_grouped(ft, group, StartPosition::Latest, lease, 100, 5)
                .await
                .unwrap();
            if claimed.is_empty() {
                break;
            }
            for m in &claimed {
                mq.ack(m).await.unwrap();
            }
        }
    }
    // Now both groups are registered at the tip; a fresh event fans out to both.
    mq.publish(ft, b"event").await.unwrap();
    let a = mq
        .claim_grouped(ft, "group-a", StartPosition::Latest, lease, 10, 5)
        .await
        .unwrap();
    let b = mq
        .claim_grouped(ft, "group-b", StartPosition::Latest, lease, 10, 5)
        .await
        .unwrap();
    assert_eq!(a.len(), 1, "group-a sees the event");
    assert_eq!(b.len(), 1, "group-b independently sees the same event");
    assert_eq!(a[0].payload, b"event");
    assert_eq!(b[0].payload, b"event");
    mq.ack(&a[0]).await.unwrap();
    mq.ack(&b[0]).await.unwrap();
}
