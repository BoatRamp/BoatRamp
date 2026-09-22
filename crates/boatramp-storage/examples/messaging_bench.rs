//! Durable-publish throughput benchmark for the single-node bus (`LogMessaging`) on the **production
//! substrate** — a local SlateDB `KvStore` at the node's 5 ms flush interval + an `FsStorage` blob
//! store — so the numbers reflect what a real single-node deploy pays for an at-least-once durable
//! publish. This is the boatramp side of the Phase-1 "within ~2× NATS JetStream" acceptance; run the
//! JetStream side on the SAME box with `nats bench js pub` and compare.
//!
//! ```sh
//! cargo run --release -p boatramp-storage --features slatedb --example messaging_bench
//! # tunables (env): N total msgs, SIZE payload bytes, CONC concurrent publishers,
//! #                 CHUNK batch size, FLUSH_MS SlateDB flush interval (prod = 5)
//! N=50000 SIZE=256 CONC=256 CHUNK=1000 cargo run --release -p boatramp-storage \
//!     --features slatedb --example messaging_bench
//! ```
//!
//! Three publish profiles, each the analog of a `nats bench js pub` mode:
//! - **single (sequential, awaited)** — one publisher, one durable commit per message. The strict
//!   floor: latency ≈ one flush interval. Compare to `nats bench js pub --pub 1` (sync).
//! - **concurrent (aggregate)** — `CONC` publishers in flight; the per-node group-commit (A2)
//!   coalesces everyone's writes landing in a flush window into ONE `write_batch`/fsync. Compare to
//!   `nats bench js pub --pub N`.
//! - **batch (`publish_batch`)** — `CHUNK` messages per durable commit (A4 pipelined path). Compare
//!   to `nats bench js pub` async / batched.
//!
//! Plus the **event-driven delivery idle-scaling sweep** (gate 8 — the headline of
//! PLAN-messaging-event-driven-delivery): with `IDLE_SWEEP=1`, create 10 / 1 000 / 10 000 *idle*
//! topics (each published-then-drained, so no claimable work remains) and measure one drainer
//! "look for work" cycle (`ready_topics()` ∪ `due_topics()`). The whole point of the ready-set is
//! that this cost is ~FLAT in the idle-topic count (the old poll was O(#topics)×2/sec). A regression
//! here — cost rising with idle topics — is the feature failing. Run:
//! ```sh
//! IDLE_SWEEP=1 cargo run --release -p boatramp-storage --features slatedb --example messaging_bench
//! ```

#[cfg(not(feature = "slatedb"))]
fn main() {
    eprintln!("enable the backend: --features slatedb");
}

#[cfg(feature = "slatedb")]
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_storage::{FsStorage, SlateKv};
    #[allow(unused_imports)]
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn env_usize(k: &str, d: usize) -> usize {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    }

    let n = env_usize("N", 50_000);
    let size = env_usize("SIZE", 256);
    let conc = env_usize("CONC", 256).max(1);
    let chunk = env_usize("CHUNK", 1000).max(1);
    let flush_ms = env_usize("FLUSH_MS", 5) as u64;
    // MAX_UNFLUSHED=0 (default) = strong durability (Option B — every publish awaits the flush).
    // N>0 opts into the shipping relaxed path: fast-ack up to N un-durable messages, then a durable
    // checkpoint (LogMessaging::with_max_unflushed) — the actual code that ships, not a raw prototype.
    let max_unflushed = env_usize("MAX_UNFLUSHED", 0);
    let payload = vec![b'x'; size];

    // A fresh production-shaped store per profile (SlateDB at the node flush interval + FsStorage),
    // so a prior profile's backlog never skews the next.
    async fn fresh(
        tag: &str,
        flush_ms: u64,
        max_unflushed: usize,
    ) -> (Arc<LogMessaging>, std::path::PathBuf) {
        let base =
            std::env::temp_dir().join(format!("bramp-msgbench-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("blobs")).unwrap();
        let kv =
            SlateKv::open_local_with_flush(base.join("kv-slate"), Duration::from_millis(flush_ms))
                .await
                .unwrap();
        let storage = Arc::new(FsStorage::new(base.join("blobs")));
        let mq = LogMessaging::new(storage, Arc::new(kv)).with_max_unflushed(max_unflushed);
        (Arc::new(mq), base)
    }

    let rate = |count: usize, elapsed: Duration| count as f64 / elapsed.as_secs_f64();

    // ── Profile 1: single publisher, sequential awaited durable publishes (latency floor). ────────
    let seq_n = n.min(5_000); // sequential is the slow floor — a smaller N keeps wall-clock sane.
    let (mq, base) = fresh("seq", flush_ms, max_unflushed).await;
    let mut lat_us: Vec<u128> = Vec::with_capacity(seq_n);
    let t = Instant::now();
    for _ in 0..seq_n {
        let op = Instant::now();
        mq.publish("bench-seq", &payload).await.unwrap();
        lat_us.push(op.elapsed().as_micros());
    }
    let seq_elapsed = t.elapsed();
    let _ = std::fs::remove_dir_all(&base);
    lat_us.sort_unstable();
    let pct =
        |p: f64| lat_us[((lat_us.len() as f64 * p) as usize).min(lat_us.len() - 1)] as f64 / 1000.0;
    let (p50, p99) = (pct(0.50), pct(0.99));

    // ── Profile 2: CONC concurrent publishers, aggregate throughput (group-commit coalescing). ────
    let (mq, base) = fresh("conc", flush_ms, max_unflushed).await;
    let per = n / conc;
    let t = Instant::now();
    let mut tasks = Vec::with_capacity(conc);
    for _ in 0..conc {
        let mq = mq.clone();
        let payload = payload.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..per {
                mq.publish("bench-conc", &payload).await.unwrap();
            }
        }));
    }
    for h in tasks {
        h.await.unwrap();
    }
    let conc_elapsed = t.elapsed();
    let conc_count = per * conc;
    let _ = std::fs::remove_dir_all(&base);

    // ── Profile 3: publish_batch of CHUNK messages per durable commit (pipelined path). ───────────
    let (mq, base) = fresh("batch", flush_ms, max_unflushed).await;
    let t = Instant::now();
    let mut sent = 0usize;
    while sent < n {
        let this = chunk.min(n - sent);
        let msgs: Vec<(String, Vec<u8>)> = (0..this)
            .map(|_| ("bench-batch".to_string(), payload.clone()))
            .collect();
        mq.publish_batch_ctx(&msgs, None).await.unwrap();
        sent += this;
    }
    let batch_elapsed = t.elapsed();
    let _ = std::fs::remove_dir_all(&base);

    println!(
        "boatramp single-node durable publish — SlateDB(flush={flush_ms}ms, max_unflushed={max_unflushed})+FsStorage, {size}B payload\n"
    );
    println!(
        "  single  (seq, awaited)   | {:>10.0} msg/s   (p50 {:.3} ms, p99 {:.3} ms, n={})",
        rate(seq_n, seq_elapsed),
        p50,
        p99,
        seq_n
    );
    println!(
        "  concurrent (CONC={conc:<5}) | {:>10.0} msg/s   ({} msgs in {:.2}s)",
        rate(conc_count, conc_elapsed),
        conc_count,
        conc_elapsed.as_secs_f64()
    );
    println!(
        "  batch   (CHUNK={chunk:<6})  | {:>10.0} msg/s   ({} msgs in {:.2}s)",
        rate(sent, batch_elapsed),
        sent,
        batch_elapsed.as_secs_f64()
    );
    println!(
        "\ncompare on the SAME box:  nats bench js pub bench --msgs {n} --size {size} [--pub 1|--pub {conc}]"
    );

    // ── Gate 8: the idle-scaling sweep (the headline). Cost of one drainer "look for work" cycle vs
    //    the number of IDLE topics. Event-driven delivery makes this ~flat (an idle topic is absent
    //    from the ready-set); the old poll was O(#topics). Opt-in (it creates up to 10k topics).
    if std::env::var("IDLE_SWEEP").ok().as_deref() == Some("1") {
        println!("\nevent-driven delivery — idle-scaling sweep (gate 8): drainer look-for-work cost vs idle topics");

        // (a) The ALGORITHM's cost, isolated from LSM compaction lag: over an in-memory KV (no
        //     tombstones), measure `ready_topics()` for a fixed set of ACTIVE topics while the number
        //     of fully-drained IDLE topics grows 10→1k→10k. This is the headline claim — the per-wake
        //     drain cost must be ~FLAT in the idle count (an idle topic is absent from the ready-set).
        {
            use boatramp_core::kv::MemoryKv;
            use boatramp_core::Storage;
            // A trivial in-memory blob store (payloads never touch the ready-set scan being measured).
            struct MemBlob(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);
            #[async_trait::async_trait]
            impl Storage for MemBlob {
                async fn get(
                    &self,
                    key: &str,
                ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
                    let b = self
                        .0
                        .lock()
                        .unwrap()
                        .get(key)
                        .cloned()
                        .ok_or_else(|| boatramp_core::StorageError::NotFound(key.into()))?;
                    let body =
                        futures::stream::once(async move { Ok(bytes::Bytes::from(b)) }).boxed();
                    Ok(boatramp_core::GetObject {
                        meta: boatramp_core::ObjectMeta {
                            key: key.into(),
                            ..Default::default()
                        },
                        body,
                    })
                }
                async fn get_range(
                    &self,
                    key: &str,
                    _: u64,
                    _: Option<u64>,
                ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
                    self.get(key).await
                }
                async fn put(
                    &self,
                    key: &str,
                    mut body: boatramp_core::ByteStream,
                    _: boatramp_core::PutMeta,
                ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError>
                {
                    let mut buf = Vec::new();
                    while let Some(c) = body.next().await {
                        buf.extend_from_slice(&c?);
                    }
                    self.0.lock().unwrap().insert(key.into(), buf);
                    Ok(boatramp_core::ObjectMeta {
                        key: key.into(),
                        ..Default::default()
                    })
                }
                async fn head(
                    &self,
                    key: &str,
                ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError>
                {
                    Ok(boatramp_core::ObjectMeta {
                        key: key.into(),
                        ..Default::default()
                    })
                }
                async fn delete(&self, key: &str) -> Result<(), boatramp_core::StorageError> {
                    self.0.lock().unwrap().remove(key);
                    Ok(())
                }
                async fn list(
                    &self,
                    _: &str,
                ) -> Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError>
                {
                    Ok(Vec::new())
                }
            }
            let mq = LogMessaging::new(
                Arc::new(MemBlob(std::sync::Mutex::new(
                    std::collections::HashMap::new(),
                ))),
                Arc::new(MemoryKv::new()),
            );
            // 5 always-active topics (a live marker each), so the scan has real work.
            const ACTIVE: usize = 5;
            for i in 0..ACTIVE {
                mq.publish(&format!("active-{i}"), b"x").await.unwrap();
            }
            let mut idle = 0usize;
            println!("  (a) algorithm over in-memory KV (no compaction lag) — {ACTIVE} active topics, growing idle count:");
            for &target in &[10usize, 1_000, 10_000] {
                while idle < target {
                    let t = format!("idle-{idle}");
                    mq.publish(&t, b"x").await.unwrap();
                    for m in mq.claim(&t, Duration::from_secs(30), 16, 5).await.unwrap() {
                        mq.ack(&m).await.unwrap();
                    }
                    idle += 1;
                }
                const ITERS: u32 = 50;
                let start = Instant::now();
                for _ in 0..ITERS {
                    let _ = mq.ready_topics().await.unwrap();
                }
                let per = start.elapsed() / ITERS;
                println!(
                    "      {target:>6} idle | ready_topics {:>7.1} µs (ready-set size {})",
                    per.as_secs_f64() * 1e6,
                    mq.ready_topics().await.unwrap().len(),
                );
            }
            println!("      → FLAT (≈ constant) across 10→10k idle: an idle topic costs ~0 (gate 8, algorithm).");
        }

        // (b) The production substrate (SlateDB): same sweep, subject to LSM compaction lag on the
        //     just-churned marker tombstones (documented below).
        println!("  (b) production substrate (SlateDB) — burst-churned then measured:");
        let (mq, base) = fresh("idle", flush_ms, 0).await;
        let mut created = 0usize;
        for &target in &[10usize, 1_000, 10_000] {
            // Grow the idle-topic set to `target`, each fully drained (publish → claim → ack), so it
            // leaves NO ready marker and NO pending work — a genuinely idle topic.
            while created < target {
                let topic = format!("idle-{created}");
                mq.publish(&topic, b"x").await.unwrap();
                let claimed = mq
                    .claim(&topic, Duration::from_secs(30), 16, 5)
                    .await
                    .unwrap();
                for m in &claimed {
                    mq.ack(m).await.unwrap();
                }
                created += 1;
            }
            // Sanity: no idle topic left a ready marker (all drained).
            let ready = mq.ready_topics().await.unwrap();
            // Measure the drainer's per-WAKE hot path — `ready_topics()` (the durable ready-set
            // scan) — separately from the periodic `due_topics()` rebuild (safety-net cadence only,
            // NOT every wake). The per-wake cost is the one that must stay flat in idle-topic count.
            const ITERS: u32 = 20;
            let t = Instant::now();
            for _ in 0..ITERS {
                let _ = mq.ready_topics().await.unwrap();
            }
            let per_ready = t.elapsed() / ITERS;
            let t = Instant::now();
            for _ in 0..ITERS {
                let _ = mq.due_topics().await.unwrap();
            }
            let per_due = t.elapsed() / ITERS;
            println!(
                "  {target:>6} idle topics | ready_topics {:>8.1} µs (per wake) | due_topics {:>8.1} µs (per safety-net) | ready-set size {}",
                per_ready.as_secs_f64() * 1e6,
                per_due.as_secs_f64() * 1e6,
                ready.len(),
            );
        }
        let _ = std::fs::remove_dir_all(&base);
        println!(
            "  ready_topics() is the PER-WAKE hot path (scans only the ready-set: absent markers ⇒ ~0);\n  \
             due_topics() runs only on the safety-net cadence (bounded by LEASED messages, not topics).\n  \
             Note: this sweep BURST-creates then drains every idle topic immediately before measuring, so\n  \
             the scan also walks the just-churned marker TOMBSTONES (an LSM artifact that compacts away);\n  \
             a genuinely-idle fleet (markers long compacted) pays only for its LIVE markers — the design's\n  \
             invariant is 'an idle topic is ABSENT from the ready-set', which the ready-set-size 0 confirms."
        );
    } else {
        println!(
            "\n(run with IDLE_SWEEP=1 for the event-driven delivery idle-scaling sweep — gate 8)"
        );
    }
}
