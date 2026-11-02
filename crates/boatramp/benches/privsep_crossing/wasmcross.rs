//! Substrate 5: **wasm (wasmtime linear-memory copy-in/copy-out).** Deliberately bypasses
//! `boatramp-handlers::engine`'s full wasi-http component-model invoke path — that machinery
//! (pooling allocator, AOT artifact cache, wasi-http bindings) answers a different question. The
//! decision-relevant number here is the CROSSING itself: copying a request into the guest's
//! linear memory, calling into it, and copying a response back out — so this builds its own
//! minimal classic (non-component) `wasmtime::Module` directly from WAT.
//!
//! The guest function is intentionally near-trivial (just returns its length argument) — guest
//! COMPUTE is not what's being measured; it exists only so the call isn't optimized away and so
//! the memory region is genuinely touched on both sides of the boundary.

use std::io;
use std::time::Instant;

use wasmtime::{Config, Engine, Instance, Module, Store};

use crate::stats::{self, Percentiles};

const WAT_MODULE: &str = r#"
(module
  (memory (export "memory") 40)
  (func (export "process") (param $ptr i32) (param $len i32) (result i32)
    local.get $len)
)
"#;

pub struct WasmOutcome {
    pub copy_warm: Percentiles,
    pub copy_warm_rps: f64,
    pub copy_warm_iterations: usize,
    pub instantiate_cold: Percentiles,
    pub instantiate_iterations: usize,
}

/// `payload_len` must fit the module's 40-page (2.5 MiB) linear memory — true for every
/// benchmark payload size (max 2 MiB) plus the fixed base offset used below.
pub fn run(
    payload_len: usize,
    copy_iterations: usize,
    instantiate_iterations: usize,
) -> io::Result<WasmOutcome> {
    let engine = Engine::new(&Config::new()).map_err(io::Error::other)?;
    let module = Module::new(&engine, WAT_MODULE).map_err(io::Error::other)?;

    // ---- cold: a FRESH Store+Instance per call (the Engine + compiled Module are shared, as a
    // real deployment would reuse one precompiled artifact across many per-request instances —
    // this isolates the per-request INSTANTIATION cost, the Phase-4-relevant number).
    let mut instantiate_us = Vec::with_capacity(instantiate_iterations.max(1));
    for _ in 0..instantiate_iterations {
        let t0 = Instant::now();
        let mut store = Store::new(&engine, ());
        let _instance = Instance::new(&mut store, &module, &[]).map_err(io::Error::other)?;
        instantiate_us.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
    }

    // ---- warm: one persistent instance, many copy-in -> call -> copy-out round trips ----
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).map_err(io::Error::other)?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| io::Error::other("wasm module did not export \"memory\""))?;
    let process = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "process")
        .map_err(io::Error::other)?;

    let input = vec![0xCDu8; payload_len.max(1)];
    let mut output = vec![0u8; payload_len.max(1)];
    const PTR: i32 = 0;
    let mut copy_us = Vec::with_capacity(copy_iterations);
    for _ in 0..copy_iterations {
        let t0 = Instant::now();
        memory
            .write(&mut store, PTR as usize, &input)
            .map_err(io::Error::other)?;
        let _ = process
            .call(&mut store, (PTR, payload_len as i32))
            .map_err(io::Error::other)?;
        memory
            .read(&store, PTR as usize, &mut output)
            .map_err(io::Error::other)?;
        copy_us.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
    }

    Ok(WasmOutcome {
        copy_warm: stats::summarize(&copy_us),
        copy_warm_rps: stats::throughput_rps(&copy_us),
        copy_warm_iterations: copy_iterations,
        instantiate_cold: stats::summarize(&instantiate_us),
        instantiate_iterations,
    })
}
