//! Percentile/throughput reduction over a raw latency sample set, plus the results-table printer.
//! No statistics crate — nearest-rank percentiles over a sorted `Vec<f64>` (microseconds) are
//! all a few thousand samples need, and keeping this dependency-free matches the rest of the
//! harness.

#[derive(Clone, Copy, Debug)]
pub struct Percentiles {
    pub p50_us: f64,
    pub p99_us: f64,
    pub mean_us: f64,
    pub min_us: f64,
    pub max_us: f64,
}

/// Nearest-rank percentile (`p` in `[0,1]`) over an UNSORTED sample slice (sorts a local copy).
pub fn summarize(samples_us: &[f64]) -> Percentiles {
    assert!(!samples_us.is_empty(), "summarize called with zero samples");
    let mut sorted = samples_us.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("latency samples are never NaN"));
    let pct = |p: f64| -> f64 {
        let n = sorted.len();
        let idx = ((p * n as f64).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1);
        sorted[idx]
    };
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    Percentiles {
        p50_us: pct(0.50),
        p99_us: pct(0.99),
        mean_us: mean,
        min_us: *sorted.first().unwrap(),
        max_us: *sorted.last().unwrap(),
    }
}

/// Steady-state throughput implied by the warm sample set: requests/sec a SINGLE
/// frontend/backend pair sustains back-to-back (serial round trips, not concurrent — the
/// decision-relevant per-pair crossing rate, matching how a Phase-3 instance pair would run).
pub fn throughput_rps(warm_samples_us: &[f64]) -> f64 {
    let total_us: f64 = warm_samples_us.iter().sum();
    if total_us <= 0.0 {
        return 0.0;
    }
    warm_samples_us.len() as f64 / (total_us / 1_000_000.0)
}

/// One fully-measured (substrate, payload) cell: warm steady-state + cold/spawn cost, reported
/// SEPARATELY per the task spec ("reporting spawn/setup cost separately per substrate").
#[derive(Clone, Debug)]
pub struct Cell {
    pub substrate: String,
    pub payload_label: String,
    pub warm: Option<Percentiles>,
    pub warm_rps: Option<f64>,
    pub warm_iterations: usize,
    pub cold_spawn_us: Option<Percentiles>,
    pub cold_iterations: usize,
    pub note: String,
}

impl Cell {
    pub fn na(substrate: &str, payload_label: &str, reason: &str) -> Self {
        Cell {
            substrate: substrate.to_string(),
            payload_label: payload_label.to_string(),
            warm: None,
            warm_rps: None,
            warm_iterations: 0,
            cold_spawn_us: None,
            cold_iterations: 0,
            note: format!("N/A — {reason}"),
        }
    }
}

/// Full-precision, machine-parseable dump (one CSV row per cell) — the pretty table above elides
/// mean/min/max and sample counts for terminal readability; this is the source of truth for the
/// results writeup.
pub fn print_csv(cells: &[Cell]) {
    println!(
        "substrate,payload,warm_iterations,warm_p50_us,warm_p99_us,warm_mean_us,warm_min_us,warm_max_us,warm_rps,\
         cold_iterations,cold_p50_us,cold_p99_us,cold_mean_us,cold_min_us,cold_max_us,note"
    );
    for c in cells {
        let w = c.warm;
        let cd = c.cold_spawn_us;
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\"{}\"",
            c.substrate,
            c.payload_label,
            c.warm_iterations,
            w.map(|p| format!("{:.2}", p.p50_us)).unwrap_or_default(),
            w.map(|p| format!("{:.2}", p.p99_us)).unwrap_or_default(),
            w.map(|p| format!("{:.2}", p.mean_us)).unwrap_or_default(),
            w.map(|p| format!("{:.2}", p.min_us)).unwrap_or_default(),
            w.map(|p| format!("{:.2}", p.max_us)).unwrap_or_default(),
            c.warm_rps.map(|r| format!("{r:.1}")).unwrap_or_default(),
            c.cold_iterations,
            cd.map(|p| format!("{:.2}", p.p50_us)).unwrap_or_default(),
            cd.map(|p| format!("{:.2}", p.p99_us)).unwrap_or_default(),
            cd.map(|p| format!("{:.2}", p.mean_us)).unwrap_or_default(),
            cd.map(|p| format!("{:.2}", p.min_us)).unwrap_or_default(),
            cd.map(|p| format!("{:.2}", p.max_us)).unwrap_or_default(),
            c.note.replace('"', "'"),
        );
    }
}

pub fn print_table(cells: &[Cell]) {
    println!(
        "{:<22} {:<8} {:>10} {:>10} {:>12} {:>14} {:<40}",
        "substrate", "payload", "warm_p50us", "warm_p99us", "warm_rps", "cold_spawn_us", "note"
    );
    for c in cells {
        let (p50, p99) = match &c.warm {
            Some(p) => (format!("{:.1}", p.p50_us), format!("{:.1}", p.p99_us)),
            None => ("-".into(), "-".into()),
        };
        let rps = match c.warm_rps {
            Some(r) => format!("{r:.0}"),
            None => "-".into(),
        };
        let cold = match &c.cold_spawn_us {
            Some(p) => format!("{:.1}", p.p50_us),
            None => "-".into(),
        };
        println!(
            "{:<22} {:<8} {:>10} {:>10} {:>12} {:>14} {:<40}",
            c.substrate, c.payload_label, p50, p99, rps, cold, c.note
        );
    }
}
