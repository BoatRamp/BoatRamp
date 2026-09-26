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
    assert!(
        storage
            .list("zz/")
            .await
            .unwrap()
            .iter()
            .any(|meta| meta.key == key)
    );

    // delete, then head is NotFound; a second delete is idempotent
    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.head(key).await,
        Err(StorageError::NotFound(_))
    ));
    storage.delete(key).await.unwrap();
}

/// A 0-byte upload: `put` stages one empty block and commits it. The `commit_block_list` still
/// carries a body (the block-list XML), so its signed Content-Length must match the wire — this
/// exercises the Shared Key content-length stamp on the empty-object path.
#[tokio::test]
async fn azure_zero_byte_round_trip() {
    let Some(options) = options() else {
        eprintln!("skipping Azure test: set BOATRAMP_TEST_AZURE_CONTAINER to run it");
        return;
    };
    let storage = AzureStorage::connect(options).expect("connect");
    let key = "zz/boatramp-zero-byte-object";

    let body: ByteStream = futures::stream::once(async { Ok(bytes::Bytes::new()) }).boxed();
    storage.put(key, body, PutMeta::default()).await.unwrap();

    assert_eq!(storage.head(key).await.unwrap().size, Some(0));
    assert!(
        collect(storage.get(key).await.unwrap().body)
            .await
            .is_empty()
    );

    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.head(key).await,
        Err(StorageError::NotFound(_))
    ));
    storage.delete(key).await.unwrap();
}

/// A multi-block upload (> the 8 MiB block size): `put` stages several blocks, then commits the
/// block list. This is the exact `stage_block` (many) + `commit_block_list` (one) shape that the
/// content-length stamp fix targets — the commit body is the block-list XML, so a blank signed
/// Content-Length would 403.
#[tokio::test]
async fn azure_multi_block_round_trip() {
    let Some(options) = options() else {
        eprintln!("skipping Azure test: set BOATRAMP_TEST_AZURE_CONTAINER to run it");
        return;
    };
    let storage = AzureStorage::connect(options).expect("connect");
    let key = "zz/boatramp-multi-block-object";

    // 20 MiB → three 8 MiB blocks (last partial). A deterministic, non-uniform pattern so a range
    // read can be verified precisely.
    let size = 20 * 1024 * 1024usize;
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let payload = bytes::Bytes::from(data.clone());
    let body: ByteStream = futures::stream::once(async move { Ok(payload) }).boxed();
    storage.put(key, body, PutMeta::default()).await.unwrap();

    assert_eq!(storage.head(key).await.unwrap().size, Some(size as u64));
    // Full round-trip is byte-exact.
    assert_eq!(collect(storage.get(key).await.unwrap().body).await, data);
    // A bounded range that straddles a block boundary (8 MiB) reads correctly.
    let start = 8 * 1024 * 1024 - 3;
    let mid = collect(
        storage
            .get_range(key, start as u64, Some(6))
            .await
            .unwrap()
            .body,
    )
    .await;
    assert_eq!(mid, &data[start..start + 6]);

    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.head(key).await,
        Err(StorageError::NotFound(_))
    ));
    storage.delete(key).await.unwrap();
}
