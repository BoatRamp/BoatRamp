//! Mutation-sensitive gate for the **static-musl embedded-libsql concurrency fix**
//! (`sql_libsql::local_sql_lock` / `local_exec_lock` / `GuardedConn`).
//!
//! ROOT CAUSE it guards: on the fully-static musl build, concurrent execution of the bundled SQLite
//! across OS threads corrupts process-global memory even though libsql selects the serialized
//! threading mode — a captured core shows the fault in `sqlite3DbMallocRawNN` (a connection's
//! lookaside) on one thread while another is mid-`PRAGMA journal_mode=WAL` journal commit on a
//! DIFFERENT connection. It surfaces as an intermittent `SQLITE_MISUSE` during a run or a SIGSEGV.
//! The fix serializes embedded (local) libsql execution process-wide so no two embedded-SQLite
//! operations ever run at once.
//!
//! This gate drives the exact faulting pattern — 20 OS threads, each a `current_thread` runtime,
//! each looping the full open(WAL)/begin/DDL/insert/commit/read cycle on its OWN local database —
//! at a volume well past where the corruption is near-certain:
//!
//! * NORMAL (the fix in force): the run completes with ZERO libsql errors and prints the marker.
//! * MUTATION (`libsql-execlock-gate-mutation` feature + `BOATRAMP_LIBSQL_EXECLOCK_MUTATE` set): the
//!   exec lock is bypassed, so the run MUST fault — a `SQLITE_MISUSE` (caught here → `panic`) or a
//!   SIGSEGV (crashes the process). Either way the process exits non-zero, proving the serialization
//!   is load-bearing. If NEITHER happens within the budget the gate FAILS loudly (not load-bearing).
//!
//! `#[ignore]`d because it is heavy and (under mutation) deliberately corrupts process memory, so it
//! must run ALONE in its own process; the CI `libsql-exec-serialization` gate runs it isolated, once
//! per mutation state.
#![cfg(feature = "sql")]

use boatramp_core::sql::{SqlBackends, SqlValue};
use boatramp_storage::LibsqlSqlBackends;
use std::sync::Arc;

async fn cycle(dir: std::path::PathBuf, tag: usize) -> Result<(), String> {
    let backends = LibsqlSqlBackends::local(&dir);
    let db = backends
        .database("default", "shop", "")
        .await
        .map_err(|e| format!("database: {e}"))?;
    {
        let mut tx = db.begin().await.map_err(|e| format!("begin: {e}"))?;
        tx.execute(
            "CREATE TABLE orders (id TEXT PRIMARY KEY, tenant_id TEXT, item TEXT)",
            &[],
        )
        .await
        .map_err(|e| format!("ddl: {e}"))?;
        for i in 0..5 {
            tx.execute(
                "INSERT INTO orders (id, tenant_id, item) VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(format!("o{i}")),
                    SqlValue::Text("acme".into()),
                    SqlValue::Text(format!("item{tag}_{i}")),
                ],
            )
            .await
            .map_err(|e| format!("insert: {e}"))?;
        }
        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    }
    {
        let mut tx = db
            .begin_read_only()
            .await
            .map_err(|e| format!("begin_ro: {e}"))?;
        let rows = tx
            .query(
                "SELECT id FROM orders WHERE tenant_id = ?1",
                &[SqlValue::Text("acme".into())],
            )
            .await
            .map_err(|e| format!("query: {e}"))?;
        if rows.rows.len() != 5 {
            return Err(format!("wrong row count {}", rows.rows.len()));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[ignore = "heavy, deliberately-corrupting static-musl libsql concurrency gate; run ALONE in the CI libsql-exec-serialization gate (normal → pass + marker; BOATRAMP_LIBSQL_EXECLOCK_MUTATE → must fault)"]
fn libsql_exec_serialization_gate() {
    let mutate = std::env::var_os("BOATRAMP_LIBSQL_EXECLOCK_MUTATE").is_some();
    let seam_compiled = cfg!(feature = "libsql-execlock-gate-mutation");
    let threads: usize = env_usize("GATE_THREADS", 20);
    // 20 threads x 4000 rounds = 80000 open/begin/DDL/5-insert/commit/read cycles (~0.8M embedded-
    // SQLite ops). The unserialized race is ~1e-4/cycle, so the mutation run's expected fault count
    // is well above 1 (and it breaks on the first fault, so it is fast when the bug reproduces); the
    // NORMAL run executes all cycles serialized and must stay clean.
    let rounds: usize = env_usize("GATE_ROUNDS", 4000);

    let base = std::env::temp_dir().join(format!("br-libsql-execgate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let errors = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let mut handles = Vec::new();
    for t in 0..threads {
        let base = base.clone();
        let errors = errors.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            for r in 0..rounds {
                let dir = base.join(format!("t{t}-r{r}"));
                if let Err(e) = rt.block_on(cycle(dir, t * rounds + r)) {
                    errors.lock().unwrap().push(e);
                }
                // Under the mutation, stop as soon as ANY thread has seen a fault — the bug is
                // reproduced, so there is no need to run the remaining cycles (fast detection).
                if mutate && r % 16 == 0 && !errors.lock().unwrap().is_empty() {
                    break;
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let _ = std::fs::remove_dir_all(&base);
    let errs = errors.lock().unwrap();
    println!(
        "LIBSQL EXEC-SERIALIZATION GATE mutate={mutate} seam_compiled={seam_compiled} \
         threads={threads} rounds={rounds} faults={}",
        errs.len()
    );

    if mutate && seam_compiled {
        // The exec lock was bypassed. Reaching this point at all means the process did NOT SIGSEGV
        // (a SIGSEGV is also a valid, non-zero "mutation detected"). Either way the mutation run is
        // EXPECTED to exit non-zero — the CI gate treats a passing (exit 0) mutation run as proof the
        // serialization is NOT load-bearing. So panic in both branches, distinguished by message:
        // the concurrent workload should have corrupted SQLite (a collected `SQLITE_MISUSE`); zero
        // faults in the whole budget means the gate is not reliably reproducing the race.
        if errs.is_empty() {
            panic!(
                "MUTATION NOT DETECTED: with the exec lock bypassed, {threads}x{rounds} concurrent \
                 libsql cycles produced ZERO faults — raise GATE_ROUNDS (the gate must reliably \
                 reproduce the static-musl race to be load-bearing)"
            );
        }
        panic!(
            "MUTATION DETECTED (gate is load-bearing): {} libsql faults with the exec lock bypassed; \
             first = {}",
            errs.len(),
            errs[0]
        );
    } else {
        // The fix is in force (or the seam is not compiled): the serialized engine must be clean.
        assert!(
            errs.is_empty(),
            "serialized embedded-libsql execution still faulted ({} errors; first = {}) — the \
             static-musl concurrency fix regressed",
            errs.len(),
            errs.first().map(String::as_str).unwrap_or("")
        );
        println!("LIBSQL EXEC-SERIALIZATION GATE OK");
    }
}

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(d)
}
