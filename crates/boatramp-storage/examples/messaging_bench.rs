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
//! Three profiles, each the analog of a `nats bench js pub` mode:
//! - **single (sequential, awaited)** — one publisher, one durable commit per message. The strict
//!   floor: latency ≈ one flush interval. Compare to `nats bench js pub --pub 1` (sync).
//! - **concurrent (aggregate)** — `CONC` publishers in flight; the per-node group-commit (A2)
//!   coalesces everyone's writes landing in a flush window into ONE `write_batch`/fsync. Compare to
//!   `nats bench js pub --pub N`.
//! - **batch (`publish_batch`)** — `CHUNK` messages per durable commit (A4 pipelined path). Compare
//!   to `nats bench js pub` async / batched.

#[cfg(not(feature = "slatedb"))]
fn main() {
    eprintln!("enable the backend: --features slatedb");
}

#[cfg(feature = "slatedb")]
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_storage::{FsStorage, SlateKv};
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
}
