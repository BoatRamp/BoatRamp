//! Micro-benchmark for the SlateDB `KvStore` backend on the local filesystem,
//! showing how the control-plane tuning pays off. Run in release:
//!
//! ```sh
//! cargo run --release -p boatramp-storage --features slatedb --example kv_bench
//! ```
//!
//! A single awaited `put` costs ~one `flush_interval`, so the three profiles
//! below show the spread boatramp actually cares about:
//!
//! - **default flush (~100 ms)** — the throughput profile the handler store uses.
//! - **low flush (5 ms)** — the control-plane profile: serialized deploy writes
//!   acknowledge ~20x sooner.
//! - **write_batch** — N writes committed in one flush, the cheapest of all when
//!   the writes can be grouped (as deploy metadata is).

#[cfg(not(feature = "slatedb"))]
fn main() {
    eprintln!("enable the backend: --features slatedb");
}

#[cfg(feature = "slatedb")]
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    use boatramp_core::kv::{KvStore, WriteOp};
    use boatramp_storage::SlateKv;
    use std::time::{Duration, Instant};

    const N: usize = 200; // small: each seq put waits a whole flush interval
    let value = vec![b'x'; 128];

    fn key(i: usize) -> String {
        format!("bench/{i:06}")
    }

    async fn fresh(name: &str, flush: Option<Duration>) -> SlateKv {
        let dir = std::env::temp_dir().join(format!("bramp-bench-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        match flush {
            Some(interval) => SlateKv::open_local_with_flush(&dir, interval)
                .await
                .unwrap(),
            None => SlateKv::open_local(&dir).await.unwrap(),
        }
    }

    let value_ref = &value;
    let per = |d: Duration| d.as_secs_f64() * 1e3 / N as f64;

    // Sequential awaited puts at the default (~100 ms) flush interval.
    let kv = fresh("default", None).await;
    let t = Instant::now();
    for i in 0..N {
        kv.put(&key(i), value_ref.to_vec()).await.unwrap();
    }
    let seq_default = t.elapsed();
    kv.close().await.unwrap();

    // Sequential awaited puts at the control-plane (5 ms) flush interval.
    let kv = fresh("low", Some(Duration::from_millis(5))).await;
    let t = Instant::now();
    for i in 0..N {
        kv.put(&key(i), value_ref.to_vec()).await.unwrap();
    }
    let seq_low = t.elapsed();
    kv.close().await.unwrap();

    // All N writes in one batch (one flush), control-plane flush interval.
    let kv = fresh("batch", Some(Duration::from_millis(5))).await;
    let ops: Vec<WriteOp> = (0..N)
        .map(|i| WriteOp::Put(key(i), value_ref.to_vec()))
        .collect();
    let t = Instant::now();
    kv.write_batch(ops).await.unwrap();
    let batch = t.elapsed();
    assert_eq!(kv.list_prefix("bench/").await.unwrap().len(), N);
    kv.close().await.unwrap();

    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("bramp-bench-default"));
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("bramp-bench-low"));
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("bramp-bench-batch"));

    println!("SlateDB local-FS KvStore — N={N} sequential 128-byte puts\n");
    println!(
        "  seq put, default flush (~100ms) | {:>8.2} ms/op",
        per(seq_default)
    );
    println!(
        "  seq put, low flush (5ms)         | {:>8.2} ms/op",
        per(seq_low)
    );
    println!(
        "  write_batch (one flush)          | {:>8.2} ms/op ({:?} total)",
        per(batch),
        batch
    );
    println!(
        "\nnote: a single awaited put costs ~one flush_interval; the control plane\n\
         uses the low interval and groups related writes via write_batch."
    );
}
