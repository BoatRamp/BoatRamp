//! Integration coverage for the Azure Blob `Storage` backend, exercised against a
//! real Blob endpoint — the **Azurite** emulator in CI/dev. Env-gated: it skips
//! cleanly when not configured, so `cargo test` is green without infrastructure.
//!
//! Run against Azurite:
//! ```sh
//! docker run -d -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
//!   azurite-blob --blobHost 0.0.0.0
//! # create the container against the well-known devstoreaccount1, then:
//! BOATRAMP_TEST_AZURE_CONTAINER=boatramp \
//!   cargo test -p boatramp-storage --features azure --test azure_emulator -- --nocapture
//! ```
#![cfg(feature = "azure")]

use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use boatramp_storage::{AzureOptions, AzureStorage};
use futures::StreamExt;

const DATA: &[u8] = b"boatramp azure integration test payload -- range slice me precisely";

fn options() -> Option<AzureOptions> {
    Some(AzureOptions {
        account: "devstoreaccount1".to_string(),
        container: std::env::var("BOATRAMP_TEST_AZURE_CONTAINER").ok()?,
        access_key: None,
        // The Azurite emulator supplies its own well-known credentials.
        emulator: true,
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
async fn azure_round_trip_and_range() {
    let Some(options) = options() else {
        eprintln!(
            "skipping Azure test: set BOATRAMP_TEST_AZURE_CONTAINER (an Azurite emulator \
             container) to run it"
        );
        return;
    };
    let storage = AzureStorage::connect(options).expect("connect");
    let key = "zz/boatramp-integration-object";

    // put (streamed as blocks)
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
