//! Integration coverage for the GCS `Storage` backend, exercised against a real
//! GCS JSON API — the `fake-gcs-server` emulator in CI/dev. Env-gated: it skips
//! cleanly when the endpoint isn't configured, so `cargo test` is green without
//! infrastructure.
//!
//! Run against fake-gcs-server:
//! ```sh
//! docker run -d -p 4443:4443 fsouza/fake-gcs-server \
//!   -scheme http -public-host localhost:4443
//! # create the bucket (POST /storage/v1/b?project=test), then:
//! BOATRAMP_TEST_GCS_ENDPOINT=http://localhost:4443 BOATRAMP_TEST_GCS_BUCKET=boatramp \
//!   cargo test -p boatramp-storage --features gcs --test gcs_emulator -- --nocapture
//! ```
#![cfg(feature = "gcs")]

use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use boatramp_storage::{GcsOptions, GcsStorage};
use futures::StreamExt;

const DATA: &[u8] = b"boatramp gcs integration test payload -- range slice me precisely";

fn options() -> Option<GcsOptions> {
    Some(GcsOptions {
        bucket: std::env::var("BOATRAMP_TEST_GCS_BUCKET").ok()?,
        endpoint: std::env::var("BOATRAMP_TEST_GCS_ENDPOINT").ok(),
        // The emulator needs no credentials.
        anonymous: true,
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
async fn gcs_round_trip_and_range() {
    let Some(options) = options() else {
        eprintln!(
            "skipping GCS test: set BOATRAMP_TEST_GCS_ENDPOINT + BOATRAMP_TEST_GCS_BUCKET \
             (a fake-gcs-server emulator) to run it"
        );
        return;
    };
    let storage = GcsStorage::connect(options).await.expect("connect");
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

    // delete, then head is NotFound; a second delete is idempotent
    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.head(key).await,
        Err(StorageError::NotFound(_))
    ));
    storage.delete(key).await.unwrap();
}
