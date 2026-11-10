//! LIVE capability gate for `project sync` BLOB-TRANSFER ROBUSTNESS — the construens cross-node
//! incident, reproduced on OUR OWN rig at the layer where the real run actually failed.
//!
//! The incident: a `project sync --from <url> --include-pg --include-databases --apply` into a FRESH
//! dest requested the full ~42 GB data plane, transferred ~27 GB of blobs, then ABORTED on a single
//! `503 SlowDown` the dest's S3 (Tigris) backend returned under the write storm —
//! `backend error: service error: unhandled error (SlowDown) … status 503 … retryable: true, on key
//! hblob/…jpg`. `project sync` had NO blob-robustness, so one transient fault killed the whole run.
//!
//! The FIX unified `project sync` onto the clone's existing robustness: the data-plane clone now
//! threads `--continue-on-error=backend` (skip-and-record a per-blob backend fault that outlived the
//! S3 backend's own bounded retries) + `--only-blobs` (re-stream exactly the recorded set). This gate
//! proves that robustness WORKS against the REAL fault shape — not an in-process `FaultStorage`, which
//! the prior gates used and which missed the real layer, but a REAL S3-compatible store (MinIO) behind
//! a fault-injecting reverse PROXY that returns a real HTTP `503 SlowDown` on a chosen mid-stream blob,
//! exactly as Tigris did.
//!
//! The dest node writes its blobs through the proxy → the REAL `aws_sdk_s3` client → real HTTP → real
//! `503` → the SDK's real `RetryConfig::standard()` retry → (exhausted) → the restore's
//! `continue_on_error` decision. That is the construens locus, end to end.
//!
//! Three arms, each a release precondition:
//!   A. **MUTATION / baseline (the pre-fix behaviour).** With `continue_on_error = Off` and the
//!      poison ACTIVE, the mid-stream `503` ABORTS the whole restore — the exact construens failure.
//!   B. **RIDE-PAST (the fix).** With `continue_on_error = backend` and the SAME poison active, the
//!      restore RIDES PAST the `503`: it completes WITH the one poisoned blob skipped-and-recorded (a
//!      DISTINCT "completed with N skipped" outcome + a skip manifest), every OTHER blob landed.
//!   C. **REPAIR → ZERO LOSS.** With the poison cleared, an `--only-blobs` repair re-streams exactly
//!      the recorded blob; a DIRECT read-back from MinIO (bypassing the proxy) then proves ALL blobs
//!      are present and byte-for-byte intact — zero loss across the ride-past + repair.
//!
//! Env-gated (skips cleanly when MinIO isn't configured) and `#[ignore]`d; wired into
//! `.github/workflows/capability.yml` as a HARD gate that greps the success marker, so a silent skip
//! or a regression fails the merge. The blob set size is env-tunable
//! (`BOATRAMP_SYNC_GATE_BLOBS` / `BOATRAMP_SYNC_GATE_BLOB_KB`); on the lighthouse rig it is run at the
//! construens-preview scale (hundreds of blobs, GB-ish). Run:
//!   `AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_REGION=us-east-1 \
//!    BOATRAMP_TEST_S3_ENDPOINT=http://127.0.0.1:9000 BOATRAMP_TEST_S3_BUCKET=boatramp \
//!    cargo test -p boatramp-node --features project-export,s3 \
//!      --test sync_blob_robustness_live -- --ignored --nocapture`
#![cfg(all(feature = "project-export", feature = "s3"))]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project_export::{
    BundleScope, ContinueErrorKind, ContinueOnError, ExportOptions, ImportOptions, ManagedRestore,
    ProjectExport,
};
use boatramp_core::{ByteStream, PutMeta, Storage};
use boatramp_node::project_export::NodeProjectExport;
use boatramp_storage::fs::FsStorage;
use boatramp_storage::{S3Options, S3Storage};
use futures::StreamExt;

/// Shared state for the fault-injecting reverse proxy.
struct ProxyState {
    /// The REAL MinIO base the proxy forwards to (e.g. `http://127.0.0.1:9000`).
    minio_base: String,
    /// A substring of the poisoned object's storage key; a WRITE whose path contains it is 503'd.
    poison_key: String,
    /// Whether injection is armed (cleared for the `--only-blobs` repair arm).
    active: AtomicBool,
    /// How many `503`s were injected (asserted > 0, so a key-match typo can't hollow the gate).
    injected: AtomicU64,
    /// The forward client (plain HTTP to MinIO on loopback).
    client: reqwest::Client,
}

/// The reverse-proxy handler: inject a real `503 SlowDown` on a WRITE to the poisoned key (while
/// armed), else transparently forward to MinIO. The incoming `Host` header — which the `aws_sdk_s3`
/// client signed the request against (it points at the PROXY's endpoint) — is forwarded VERBATIM, so
/// MinIO's SigV4 verification recomputes against the same `Host` and the signature matches
/// (path-style addressing, so the bucket is in the path, not the host).
async fn proxy_handler(
    axum::extract::State(st): axum::extract::State<Arc<ProxyState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, StatusCode};

    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = req.headers().clone();
    let body = to_bytes(req.into_body(), usize::MAX)
        .await
        .unwrap_or_default();

    // Inject on a WRITE (multipart create/upload/complete are PUT/POST) to the poisoned key.
    let is_write = matches!(method, Method::PUT | Method::POST);
    if is_write && st.active.load(Ordering::SeqCst) && path_and_query.contains(&st.poison_key) {
        st.injected.fetch_add(1, Ordering::SeqCst);
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message>\
            <Resource>/</Resource><RequestId>fault-proxy</RequestId></Error>";
        return axum::response::Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("content-type", "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    // Forward to MinIO, preserving every signed header (Host included; drop only hop-by-hop).
    let url = format!("{}{}", st.minio_base, path_and_query);
    let mut fwd = st.client.request(method, &url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        fwd = fwd.header(name, value);
    }
    let resp = match fwd.body(body.to_vec()).send().await {
        Ok(r) => r,
        Err(e) => {
            return axum::response::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("proxy forward failed: {e}")))
                .unwrap();
        }
    };
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_body = resp.bytes().await.unwrap_or_default();
    let mut builder = axum::response::Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder.body(Body::from(resp_body)).unwrap()
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            // `content-length` is re-derived from the (fully buffered) body by reqwest on the way out
            // and by axum on the way back, so forwarding the original would risk a double-set / mismatch.
            | "content-length"
    )
}

/// Deterministic blob bytes for index `idx` of `size` bytes — cheap to regenerate for the read-back
/// comparison without holding the whole set in memory.
fn blob_bytes(idx: usize, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    let seed = (idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u64).wrapping_mul(131)) as u8;
    }
    v
}

async fn collect(mut body: ByteStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.expect("stream chunk"));
    }
    out
}

/// Import the (file-backed) bundle into `target` through `drv`, streaming from disk so a GB-scale
/// bundle is never buffered in memory.
async fn import_from_file(
    drv: &NodeProjectExport,
    bundle_path: &std::path::Path,
    target: &str,
    opts: ImportOptions,
) -> Result<
    boatramp_core::project_export::ImportReport,
    boatramp_core::project_export::ProjectExportError,
> {
    use tokio_util::compat::TokioAsyncReadCompatExt;
    let f = tokio::fs::File::open(bundle_path).await.unwrap();
    let mut src = f.compat();
    drv.import(target, &mut src, opts).await
}

fn s3_options(endpoint: String, bucket: String) -> S3Options {
    S3Options {
        bucket,
        endpoint: Some(endpoint),
        region: std::env::var("BOATRAMP_TEST_S3_REGION").ok(),
        force_path_style: true, // MinIO / Tigris path-style addressing
        credential: None,       // the ambient AWS_* chain (the MinIO creds)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live S3/MinIO blob-transfer robustness gate: a mid-transfer 503 must be ridden past"]
async fn sync_blob_transfer_rides_past_a_mid_stream_503_slowdown() {
    let (Ok(endpoint), Ok(bucket)) = (
        std::env::var("BOATRAMP_TEST_S3_ENDPOINT"),
        std::env::var("BOATRAMP_TEST_S3_BUCKET"),
    ) else {
        eprintln!(
            "SKIP: set BOATRAMP_TEST_S3_ENDPOINT + BOATRAMP_TEST_S3_BUCKET (+ AWS_* creds) to run \
             the sync blob-transfer robustness gate"
        );
        return;
    };

    // Blob set size — CI-friendly default; cranked to the construens-preview scale on the rig.
    let n_blobs: usize = std::env::var("BOATRAMP_SYNC_GATE_BLOBS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let blob_kb: usize = std::env::var("BOATRAMP_SYNC_GATE_BLOB_KB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    let blob_size = blob_kb * 1024;
    assert!(n_blobs >= 4, "need a few blobs for a mid-stream fault");
    // The poisoned blob sits MID-stream (export orders by key), so the fault lands partway through —
    // the construens shape (aborted after ~27 of ~42 GB), not on the first object.
    let poison_idx = n_blobs / 2;
    let poison_rel = format!("web/assets/obj_{poison_idx:05}.bin");
    let poison_suffix = format!("/{poison_rel}");

    let uniq = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let src_project = format!("brsync-src-{uniq}");
    let dst_a = format!("brsync-dsta-{uniq}"); // mutation arm (partial, discarded)
    let dst_b = format!("brsync-dstb-{uniq}"); // fix + repair arm (asserted zero-loss)

    println!(
        "sync-blob-robustness gate: {n_blobs} blobs x {blob_kb} KiB (~{} MiB), poison at mid-stream \
         `{poison_rel}` (idx {poison_idx})",
        (n_blobs * blob_size) / (1024 * 1024)
    );

    // --- SOURCE: an FsStorage project seeded with N blobs; export a DataPlane bundle to a FILE
    //     (streamed, so a GB-scale run never buffers the bundle in memory) ------------------------
    let tmp = tempfile::tempdir().unwrap();
    let src_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("src-blobs")));
    let bundle_path = tmp.path().join("bundle.brproj");
    {
        let skv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let sdeploy = DeployStore::new(src_blobs.clone(), skv.clone());
        let swork = tmp.path().join("src-work");
        std::fs::create_dir_all(&swork).unwrap();
        let drv_src = NodeProjectExport::new(
            Default::default(),
            sdeploy,
            skv.clone(),
            src_blobs.clone(),
            swork,
        );
        for idx in 0..n_blobs {
            let key = format!("hblob/{src_project}/web/assets/obj_{idx:05}.bin");
            let bytes = blob_bytes(idx, blob_size);
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            src_blobs
                .put(&key, body, PutMeta { content_type: None })
                .await
                .expect("seed source blob");
        }
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let f = tokio::fs::File::create(&bundle_path).await.unwrap();
        let mut sink = f.compat_write();
        drv_src
            .export(
                &src_project,
                &ExportOptions {
                    scope: BundleScope::DataPlane,
                    managed_restore: ManagedRestore::Overlay,
                    ..Default::default()
                },
                &mut sink,
            )
            .await
            .expect("source DataPlane export");
    }
    let bundle_len = std::fs::metadata(&bundle_path).unwrap().len();
    println!("source exported: bundle {} MiB", bundle_len / (1024 * 1024));

    // --- Stand up the fault-injecting reverse proxy in front of the REAL MinIO -------------------
    let state = Arc::new(ProxyState {
        minio_base: endpoint.trim_end_matches('/').to_string(),
        poison_key: poison_suffix.clone(),
        active: AtomicBool::new(true),
        injected: AtomicU64::new(0),
        client: reqwest::Client::builder()
            .build()
            .expect("proxy forward client"),
    });
    let app = axum::Router::new()
        .fallback(proxy_handler)
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let proxy_endpoint = format!("http://127.0.0.1:{}", proxy_addr.port());
    println!("fault proxy up at {proxy_endpoint} → {endpoint}");

    // A dest driver whose blobs are the REAL S3 backend pointed at the PROXY.
    let make_dest = |endpoint: String| {
        let bucket = bucket.clone();
        let dir = tmp.path().to_path_buf();
        async move {
            let s3: Arc<dyn Storage> =
                Arc::new(S3Storage::connect(s3_options(endpoint, bucket)).await);
            let dkv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let ddeploy = DeployStore::new(s3.clone(), dkv.clone());
            let dwork = dir.join(format!("dst-work-{}", rand_suffix()));
            std::fs::create_dir_all(&dwork).unwrap();
            let drv =
                NodeProjectExport::new(Default::default(), ddeploy, dkv.clone(), s3.clone(), dwork);
            (drv, s3)
        }
    };

    // === ARM A — MUTATION / baseline: the mid-stream 503 ABORTS the whole run (pre-fix shape) ====
    {
        let (drv_a, _s3_a) = make_dest(proxy_endpoint.clone()).await;
        let before = state.injected.load(Ordering::SeqCst);
        let res = import_from_file(
            &drv_a,
            &bundle_path,
            &dst_a,
            ImportOptions {
                apply: true,
                overwrite: true,
                continue_on_error: ContinueOnError::Off,
                ..Default::default()
            },
        )
        .await;
        let injected = state.injected.load(Ordering::SeqCst) - before;
        assert!(
            injected > 0,
            "the proxy must have injected the 503 (key match?)"
        );
        let err = res.expect_err(
            "ARM A: with continue_on_error OFF the mid-stream 503 MUST abort the whole run (the \
             construens failure)",
        );
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("slowdown") || msg.contains("503") || msg.contains("backend"),
            "ARM A: the abort must carry the S3 backend 503 shape, got: {err}"
        );
        println!("ARM A ok: {injected} x 503 injected → run ABORTED (pre-fix baseline): {err}");
    }

    // === ARM B — RIDE-PAST (the fix): continue_on_error=backend SKIPS-and-RECORDS the poisoned ====
    //     blob and completes; every other blob lands.
    let (drv_b, s3_b) = make_dest(proxy_endpoint.clone()).await;
    let report_b = {
        let before = state.injected.load(Ordering::SeqCst);
        let report = import_from_file(
            &drv_b,
            &bundle_path,
            &dst_b,
            ImportOptions {
                apply: true,
                overwrite: true,
                continue_on_error: ContinueOnError::Kinds(BTreeSet::from([
                    ContinueErrorKind::Backend,
                ])),
                ..Default::default()
            },
        )
        .await
        .expect("ARM B: continue_on_error=backend must RIDE PAST the 503 and complete");
        let injected = state.injected.load(Ordering::SeqCst) - before;
        assert!(injected > 0, "ARM B: the proxy must have injected the 503");
        assert!(
            report.completed_with_skips(),
            "ARM B: the ride-past is a DISTINCT 'completed with N skipped' outcome, not a silent OK"
        );
        assert_eq!(
            report.skipped.len(),
            1,
            "exactly the one poisoned blob was skipped"
        );
        let skipped_key = &report.skipped[0].key;
        assert!(
            skipped_key.ends_with(&poison_rel) && report.skipped[0].kind == "backend",
            "ARM B: the skipped blob must be the poisoned key, backend-classified: {:?}",
            report.skipped[0]
        );
        assert_eq!(
            report.blobs as usize,
            n_blobs - 1,
            "ARM B: every blob EXCEPT the poisoned one landed"
        );
        println!(
            "ARM B ok: {injected} x 503 injected → RODE PAST; {} blobs landed, 1 skipped-and-recorded ({})",
            report.blobs, skipped_key
        );
        report
    };
    let skipped_keys: BTreeSet<String> = report_b.skipped.iter().map(|s| s.key.clone()).collect();

    // === ARM C — REPAIR → ZERO LOSS: clear the fault, --only-blobs re-streams the recorded set ====
    state.active.store(false, Ordering::SeqCst);
    {
        let report = import_from_file(
            &drv_b,
            &bundle_path,
            &dst_b,
            ImportOptions {
                apply: true,
                overwrite: true,
                only_blobs: Some(skipped_keys.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("ARM C: the --only-blobs repair must succeed once the fault clears");
        assert_eq!(
            report.blobs as usize, 1,
            "ARM C: the repair re-streamed EXACTLY the one recorded blob"
        );
        assert!(
            report.skipped.is_empty(),
            "ARM C: the repair itself skipped nothing"
        );
        println!("ARM C ok: --only-blobs repair re-streamed the recorded blob");
    }

    // === ZERO-LOSS read-back: DIRECT from MinIO (bypass the proxy) — ALL blobs present + intact ===
    let direct: Arc<dyn Storage> =
        Arc::new(S3Storage::connect(s3_options(endpoint.clone(), bucket.clone())).await);
    let mut verified = 0usize;
    for idx in 0..n_blobs {
        let key = format!("hblob/{dst_b}/web/assets/obj_{idx:05}.bin");
        let got = direct
            .get(&key)
            .await
            .unwrap_or_else(|e| panic!("ZERO-LOSS: blob {key} missing after repair: {e}"));
        let bytes = collect(got.body).await;
        let expect = blob_bytes(idx, blob_size);
        assert_eq!(
            bytes.len(),
            expect.len(),
            "ZERO-LOSS: blob {key} wrong length"
        );
        assert!(bytes == expect, "ZERO-LOSS: blob {key} bytes differ");
        verified += 1;
    }
    assert_eq!(
        verified, n_blobs,
        "every source blob must be present + intact"
    );
    println!(
        "ZERO-LOSS ok: all {n_blobs} blobs present + byte-for-byte intact at the dest (0 lost)"
    );

    // Best-effort cleanup of both dest prefixes (the test bucket is shared/ephemeral).
    for proj in [&dst_a, &dst_b] {
        if let Ok(page) = direct.list(&format!("hblob/{proj}/")).await {
            for meta in page {
                let _ = direct.delete(&meta.key).await;
            }
        }
    }
    let _ = s3_b; // keep the proxy-backed store alive until here

    // End-of-test marker — printed ONLY after ALL arms + the zero-loss read-back held. CI greps it
    // (plus `test result: ok`), so a silent skip or a regression can never pass as success.
    println!("SYNC BLOB ROBUSTNESS 503 RIDE-PAST OK");
}

fn rand_suffix() -> String {
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}_{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::SeqCst)
    )
}
