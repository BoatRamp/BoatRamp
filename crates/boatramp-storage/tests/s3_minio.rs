//! Integration coverage for the S3 `Storage` backend, exercised against a real
//! S3-compatible server (MinIO in CI/dev). Env-gated: it skips cleanly when the
//! endpoint isn't configured, so `cargo test` is green without infrastructure.
//!
//! Run against MinIO:
//! ```sh
//! docker run -d -p 9000:9000 -e MINIO_ROOT_USER=minioadmin \
//!   -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
//! # create the bucket, then:
//! AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_REGION=us-east-1 \
//! BOATRAMP_TEST_S3_ENDPOINT=http://127.0.0.1:9000 BOATRAMP_TEST_S3_BUCKET=boatramp \
//!   cargo test -p boatramp-storage --features s3 -- --nocapture
//! ```
#![cfg(feature = "s3")]

use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use boatramp_storage::{S3Options, S3Storage};
use futures::StreamExt;

const DATA: &[u8] = b"boatramp s3 integration test payload -- range slice me precisely";

fn options() -> Option<S3Options> {
    Some(S3Options {
        bucket: std::env::var("BOATRAMP_TEST_S3_BUCKET").ok()?,
        endpoint: std::env::var("BOATRAMP_TEST_S3_ENDPOINT").ok(),
        region: std::env::var("BOATRAMP_TEST_S3_REGION").ok(),
        // MinIO and most self-hosted gateways require path-style addressing.
        force_path_style: true,
    })
}

async fn collect(mut body: ByteStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.expect("stream chunk"));
    }
    out
}

#[tokio::test]
async fn s3_round_trip_and_range() {
    let Some(options) = options() else {
        eprintln!(
            "skipping S3 test: set BOATRAMP_TEST_S3_ENDPOINT + BOATRAMP_TEST_S3_BUCKET \
             (and AWS_* creds) to run it"
        );
        return;
    };
    let storage = S3Storage::connect(options).await;
    let key = "zz/boatramp-integration-object";

    // put (streamed)
    let body: ByteStream =
        futures::stream::once(async { Ok(bytes::Bytes::from_static(DATA)) }).boxed();
    storage.put(key, body, PutMeta::default()).await.unwrap();

    // head reports the size
    assert_eq!(
        storage.head(key).await.unwrap().size,
        Some(DATA.len() as u64)
    );

    // full get round-trips
    assert_eq!(collect(storage.get(key).await.unwrap().body).await, DATA);

    // bounded range
    let mid = collect(storage.get_range(key, 10, Some(5)).await.unwrap().body).await;
    assert_eq!(mid, &DATA[10..15]);

    // open-ended range (offset to end)
    let offset = DATA.len() as u64 - 6;
    let tail = collect(storage.get_range(key, offset, None).await.unwrap().body).await;
    assert_eq!(tail, &DATA[DATA.len() - 6..]);

    // list sees the object under its prefix
    assert!(storage
        .list("zz/")
        .await
        .unwrap()
        .iter()
        .any(|meta| meta.key == key));

    // delete, then head is NotFound
    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.head(key).await,
        Err(StorageError::NotFound(_))
    ));
}
