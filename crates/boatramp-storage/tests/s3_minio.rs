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
        // The ambient AWS env chain (this live test relies on the MinIO/env credentials).
        credential: None,
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
    assert!(
        storage
            .list("zz/")
            .await
            .unwrap()
            .iter()
            .any(|meta| meta.key == key)
    );

    // delete, then head is NotFound
    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.head(key).await,
        Err(StorageError::NotFound(_))
    ));
}

/// DIAGNOSTIC (`--ignored`): does a concurrent burst of small-object GETs through the S3 backend keep
/// per-GET latency flat, or does it balloon (serialize)? This is the `/img` serve leg — the real
/// suspect once `build_bindings` and the pipeline were proven flat. Seeds a ~12 KB object (a webp
/// derivative), warms one connection, then fires N concurrent `get_range` for N in 1..48, printing the
/// per-GET latency distribution + wall-clock. Flat per-GET as N grows ⇒ the client parallelizes fine
/// (any remote slowness is network/TLS); ballooning per-GET ⇒ the client serializes (a pool cap / lock).
/// Point `BOATRAMP_TEST_S3_ENDPOINT` at minio (localhost: isolates the client) or at Tigris (real
/// network). Run with the same env as `s3_round_trip_and_range`, plus ` -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic: concurrent-GET latency vs concurrency"]
async fn s3_concurrency_repro() {
    use std::time::Instant;
    let Some(options) = options() else {
        eprintln!("skip: set BOATRAMP_TEST_S3_ENDPOINT + BOATRAMP_TEST_S3_BUCKET (+ AWS_* creds)");
        return;
    };
    let storage = std::sync::Arc::new(S3Storage::connect(options).await);
    let key = "zz/der-repro-12k.webp";
    let payload = vec![0x42u8; 12 * 1024];
    let seed = payload.clone();
    let body: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from(seed)) }).boxed();
    storage.put(key, body, PutMeta::default()).await.unwrap();
    // Warm one connection (first GET pays TLS/connect).
    let _ = collect(storage.get(key).await.unwrap().body).await;

    println!(
        "\n==== s3_concurrency_repro ({} B object) ====",
        payload.len()
    );
    for n in [1usize, 4, 8, 16, 32, 48] {
        let start = Instant::now();
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let s = storage.clone();
                let k = key.to_string();
                tokio::spawn(async move {
                    let t = Instant::now();
                    let obj = s.get_range(&k, 0, None).await.expect("get_range");
                    let got = collect(obj.body).await;
                    assert_eq!(got.len(), 12 * 1024);
                    t.elapsed().as_secs_f64() * 1000.0
                })
            })
            .collect();
        let mut ms: Vec<f64> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        let wall = start.elapsed().as_secs_f64() * 1000.0;
        ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |q: f64| ms[((ms.len() as f64 - 1.0) * q) as usize];
        println!(
            "N={n:>2}  wall={wall:8.1}ms  per_get[p50={:8.1} p99={:8.1} max={:8.1}] ms",
            p(0.5),
            p(0.99),
            p(1.0),
        );
    }
    storage.delete(key).await.ok();
    println!("==== end ====\n");
}
