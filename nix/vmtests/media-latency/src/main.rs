//! Pool warm-floor benchmark — faithful replica of boatramp-storage's
//! `sql_sqlx::build_pool` (Postgres) pool config, exercising the REAL sqlx 0.8.6
//! pool against a REAL postgres with the REAL drain -> burst pattern.
//!
//! It measures the per-request latency (connection acquire + the real managed-pg
//! transaction) across a concurrent burst that hits a pool which has been left
//! idle long enough to drain, comparing `min_connections = 0` (no warm floor:
//! the pool drains to empty, the burst re-establishes every connection cold) vs
//! `min_connections = MAX` (warm floor: the pool keeps a warm set, the burst
//! acquires warm connections).
//!
//! It isolates the SAME lever the ship change adds (`min_connections`); the query
//! itself is constant across both arms, so the delta is the cold-connect penalty.

use std::time::{Duration, Instant};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Executor, Row};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Build the pool EXACTLY as boatramp's `build_pool` does, plus an explicit
/// `idle_timeout` (boatramp inherits sqlx's 10-min default; the bench compresses
/// it so the drain is observable in seconds — the drained STATE is identical,
/// only the wait is shortened). `max_lifetime` is left at sqlx's 30-min default.
fn build_pool(url: &str, max: u32, min: u32, idle_ms: u64) -> sqlx::PgPool {
    let connect_opts: PgConnectOptions = url
        .parse::<PgConnectOptions>()
        .expect("url parses")
        .log_statements(log::LevelFilter::Off)
        .log_slow_statements(log::LevelFilter::Off, Duration::ZERO);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(min.min(max))
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Some(Duration::from_millis(idle_ms)))
        .connect_lazy_with(connect_opts)
}

/// One real managed-pg request: acquire a pooled connection, open a READ ONLY
/// transaction, set the two RLS GUCs via bound `set_config` (as
/// `sql_compute::apply_session_context` does), run a SELECT, COMMIT.
async fn one_request(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    conn.execute("BEGIN READ ONLY").await?;
    // Bound set_config — the storefront RLS GUC pattern (project + site).
    sqlx::query("SELECT set_config('boatramp.project', $1, true)")
        .bind("acme")
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT set_config('boatramp.site', $1, true)")
        .bind("storefront")
        .execute(&mut *conn)
        .await?;
    let row = sqlx::query("SELECT 1 AS one").fetch_one(&mut *conn).await?;
    let _: i32 = row.try_get("one")?;
    conn.execute("COMMIT").await?;
    Ok(())
}

fn pctile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted_ms.len() as f64 - 1.0)).round() as usize;
    sorted_ms[idx]
}

struct BurstStat {
    floor_after_drain: usize,
    p50: f64,
    p95: f64,
    max: f64,
    errors: usize,
}

async fn drain_then_burst(
    url: &str,
    max: u32,
    min: u32,
    burst: usize,
    idle_ms: u64,
    drain_ms: u64,
) -> BurstStat {
    let pool = build_pool(url, max, min, idle_ms);

    // 1) Warm the pool to its high-water mark (like a prior burst did), so the
    //    reaper then has something to drain.
    {
        let mut handles = Vec::new();
        for _ in 0..max {
            let p = pool.clone();
            handles.push(tokio::spawn(async move {
                let _ = one_request(&p).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    }

    // 2) Idle long enough for the reaper to drain: min=0 -> 0; min=MAX -> MAX.
    tokio::time::sleep(Duration::from_millis(drain_ms)).await;
    let floor_after_drain = pool.num_idle();

    // 3) Fire the concurrent burst; measure acquire+txn per task.
    let t_start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..burst {
        let p = pool.clone();
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let r = one_request(&p).await;
            (t0.elapsed().as_secs_f64() * 1000.0, r.is_err())
        }));
    }
    let mut lat = Vec::with_capacity(burst);
    let mut errors = 0;
    for h in handles {
        let (ms, err) = h.await.expect("task joins");
        if err {
            errors += 1;
        }
        lat.push(ms);
    }
    let _wall = t_start.elapsed();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());

    pool.close().await;

    BurstStat {
        floor_after_drain,
        p50: pctile(&lat, 50.0),
        p95: pctile(&lat, 95.0),
        max: lat.last().copied().unwrap_or(0.0),
        errors,
    }
}

#[tokio::main]
async fn main() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let max = env_u64("MAX", 8) as u32;
    let burst = env_u64("BURST", 48) as usize;
    let idle_ms = env_u64("IDLE_MS", 1500);
    let drain_ms = env_u64("DRAIN_MS", 3000);
    let trials = env_u64("TRIALS", 3) as usize;

    println!(
        "media-latency-driver: max={max} burst={burst} idle_ms={idle_ms} drain_ms={drain_ms} trials={trials}"
    );
    println!(
        "sqlx=0.8.6 (replica of boatramp build_pool); url_tls={}",
        url.contains("sslmode=require") || url.contains("sslmode=verify")
    );
    println!();

    for (label, min) in [
        ("min=0 (no warm floor)", 0u32),
        ("min=MAX (warm floor)", max),
    ] {
        println!("=== {label} ===");
        let mut p50s = Vec::new();
        let mut maxs = Vec::new();
        for t in 0..trials {
            let s = drain_then_burst(&url, max, min, burst, idle_ms, drain_ms).await;
            println!(
                "  trial {t}: floor_after_drain={:>2}  p50={:>8.1}ms  p95={:>8.1}ms  max={:>8.1}ms  errors={}",
                s.floor_after_drain, s.p50, s.p95, s.max, s.errors
            );
            p50s.push(s.p50);
            maxs.push(s.max);
        }
        p50s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        maxs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "  >> median-of-trials  p50={:.1}ms  max={:.1}ms",
            p50s[p50s.len() / 2],
            maxs[maxs.len() / 2]
        );
        println!();
    }
}
