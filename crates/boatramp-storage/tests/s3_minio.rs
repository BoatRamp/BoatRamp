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

/// PERF GATE (image-serve-latency Ask 3c — `CONCURRENT-COLD FAN-OUT`): N **concurrent cold** `/img`
/// fetches through the REAL S3 backend must FAN OUT, not serialize at the `aws_sdk_s3` connector.
///
/// This exercises the real op (a real `aws_sdk_s3` client, a real TCP/TLS connection to a real
/// S3-compatible endpoint), never a warm/local micro-bench — the `benchmark-must-exercise-real-path`
/// rule: a localhost MinIO run is a functional + coarse fan-out smoke; the NODE run against Tigris
/// (real cold-connect latency) is AUTHORITATIVE and is where this gate bites.
///
/// **Cold** means the connection pool is EMPTY when the burst fires. The object MUST already exist
/// (seed it out-of-band — the CI tier uploads it with `mc`/`aws` and names it in
/// `BOATRAMP_TEST_S3_COLD_KEY`) so the burst is the FIRST S3 op the process makes; absent that env the
/// test seeds one itself and runs the same fan-out assertion as a warm smoke (clearly logged).
///
/// The fan-out assertion is latency-RATIO based, so it holds regardless of absolute speed: if the
/// connector serialized the N concurrent cold fetches, the last-scheduled request waits behind all the
/// others, so its latency ≈ N × a single op (the max/median ratio ≈ N). Fanned out ⇒ every request
/// pays ~one op (ratio ≈ 1). The gate fails if the max is anywhere near N× the median. Prints the
/// distribution and `CONCURRENT-COLD FAN-OUT OK` ONLY after the assertion holds (anti-silent-skip).
///
/// Run: the same env as `s3_round_trip_and_range`, plus ` -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live S3/MinIO perf gate: concurrent cold fetches must fan out"]
async fn concurrent_cold_fetches_fan_out() {
    use std::sync::Arc;
    use std::time::Instant;

    let Some(options) = options() else {
        eprintln!("skip: set BOATRAMP_TEST_S3_ENDPOINT + BOATRAMP_TEST_S3_BUCKET (+ AWS_* creds)");
        return;
    };
    let storage = Arc::new(S3Storage::connect(options).await);

    // A ~12 KB object — a representative `/img` webp derivative. Prefer a pre-seeded key (so the burst
    // is genuinely COLD — the first op this process makes); else seed one (warm smoke).
    const SIZE: usize = 12 * 1024;
    let (key, cold) = match std::env::var("BOATRAMP_TEST_S3_COLD_KEY").ok() {
        Some(k) => (k, true),
        None => {
            let k = "zz/cold-fanout-12k.webp".to_string();
            let seed = vec![0x42u8; SIZE];
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(seed)) }).boxed();
            storage.put(&k, body, PutMeta::default()).await.unwrap();
            eprintln!(
                "note: BOATRAMP_TEST_S3_COLD_KEY unset — seeded {k} (pool now WARM; this is a smoke run, \
                 not a true cold measurement)"
            );
            (k, false)
        }
    };

    // The burst is the FIRST read (cold pool when `cold`). Each task times ITS OWN get_range: under a
    // serializing connector, tasks complete in sequence so later tasks see a growing latency.
    const N: usize = 16;
    let start = Instant::now();
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let s = storage.clone();
            let k = key.clone();
            tokio::spawn(async move {
                let t = Instant::now();
                let obj = s.get_range(&k, 0, None).await.expect("get_range");
                let got = collect(obj.body).await;
                assert!(!got.is_empty(), "object must exist + be non-empty");
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
    let median = ms[ms.len() / 2].max(0.001);
    let max = *ms.last().unwrap();
    println!(
        "concurrent-cold fan-out: cold={cold} N={N} wall={wall:.1}ms \
         per_get[median={median:.1} max={max:.1} ratio={:.1}x]",
        max / median
    );

    // Fan-out gate. A serializing connector makes `max ≈ N × median`; fanned out makes `max ≈ median`.
    // Require the max well below N× (generous factor + a small absolute slop for near-zero localhost
    // medians), so the gate tolerates localhost scheduling noise yet fails loudly on real serialization.
    let factor = (N as f64 / 2.0).max(4.0);
    assert!(
        max <= median * factor + 5.0,
        "SERIALIZED: max={max:.1}ms ≈ {:.1}× median={median:.1}ms (N={N}) — concurrent cold fetches are \
         NOT fanning out at the aws_sdk_s3 connector",
        max / median
    );
    // And the wall-clock must be well under fully-serial (N × median).
    assert!(
        wall <= median * N as f64 * 0.6 + 10.0,
        "SERIALIZED: wall={wall:.1}ms ≈ serial {:.1}ms (median×N) — not parallelized",
        median * N as f64
    );

    if !cold {
        storage.delete(&key).await.ok();
    }
    // End-of-test success marker — prints ONLY after the fan-out assertions held (CI greps for it +
    // `test result: ok`, so a silent skip can never pass as success).
    println!("CONCURRENT-COLD FAN-OUT OK");
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
