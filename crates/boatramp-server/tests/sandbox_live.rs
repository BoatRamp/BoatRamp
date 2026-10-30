//! LIVE gate for the whole-process OS sandbox (privsep Phase 0, WS1 — seccomp-bpf + Landlock).
//!
//! It proves, against the REAL kernel, the two security properties WS1 promises — FROM A NON-INSTALLING
//! THREAD (the critical coverage property: the op runs on a thread spawned AFTER the install, exactly
//! like a Tokio worker cloned after the pre-runtime install, so it must inherit the filter + domain) —
//! and MUTATION-VERIFIES them by running the SAME probes with the sandbox OFF and asserting the ops then
//! SUCCEED (so the ON assertions detect a real difference, not a no-op):
//!
//!   (a) **`exec*` is KILLED** by the seccomp filter. A forked child installs the whole-process seccomp
//!       filter on its main thread, spawns a second thread, and that thread `execve`s a `true` binary.
//!       With the filter ON, `execve` hits `SECCOMP_RET_KILL_PROCESS` and the child dies with `SIGSYS`.
//!       With it OFF, `execve` succeeds, the child becomes `true`, and exits `0`.
//!   (b) **A write OUTSIDE the data dir is REFUSED** by Landlock. A forked child installs a Landlock
//!       ruleset (reads+writes confined to a `data_dir`) on its main thread, spawns a second thread, and
//!       that thread tries to create a file OUTSIDE it (must be `EACCES`) and INSIDE it (must succeed).
//!       With Landlock OFF, both succeed.
//!
//! Each probe runs in its OWN `fork`ed child so the filter/ruleset never touches the test process (an
//! `exec` KILL would otherwise take down the harness). The seccomp program + Landlock ruleset are built
//! in the parent; the child applies them and then spawns the probe thread. A real `execve`/`open` is
//! driven — not a mock — so TESTED == ENFORCED.
//!
//! `#[ignore]`d (it forks + installs a whole-process filter): it runs ONLY in the dedicated
//! `sandbox-live` CI step via `--include-ignored`, NEVER in the general `--all-features` suite. The CI
//! step greps the success marker `SANDBOX LIVE OK` + the pass count. Gated on
//! `cfg(all(target_os = "linux", feature = "sandbox"))` — a no-op build elsewhere.

#![cfg(all(target_os = "linux", feature = "sandbox"))]

use std::ffi::CString;
use std::path::PathBuf;

use boatramp_server::sandbox;

// Child exit codes (the probes report via exit code, not stdout, so the CI grep stays unambiguous).
const FS_OUTSIDE_REFUSED_INSIDE_OK: i32 = 21; // Landlock ON: outside refused, inside allowed
const FS_BOTH_OK: i32 = 22; // sandbox OFF (or a hole): both writes succeeded
const FS_UNEXPECTED: i32 = 23; // inside refused and/or an impossible combination
const SELFTEST_INSTALL_FAILED: i32 = 99; // the sandbox install itself errored in the child

fn cstr(s: &str) -> CString {
    CString::new(s).expect("path has no interior NUL")
}

/// Resolve an absolute path to a `true` binary for the exec probe. Searches `$PATH` (so it works on a
/// stock CI runner and on NixOS, where coreutils live in the nix store, not `/bin`), with fallbacks.
fn true_binary() -> String {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("true");
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    for p in [
        "/bin/true",
        "/usr/bin/true",
        "/run/current-system/sw/bin/true",
    ] {
        if std::path::Path::new(p).is_file() {
            return p.to_string();
        }
    }
    panic!("no `true` binary found for the exec probe (searched $PATH + common locations)");
}

/// Reap `pid` and decode its exit code (128 + signal if it was killed).
fn wait_code(pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is a valid out-pointer; blocking wait for the one child.
    let r = unsafe { libc::waitpid(pid, &mut status as *mut libc::c_int, 0) };
    assert_eq!(
        r,
        pid,
        "waitpid() failed: {}",
        std::io::Error::last_os_error()
    );
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

/// Fork a child that (optionally) installs the whole-process seccomp filter on its MAIN thread, then
/// spawns a SECOND thread which `execve`s `true`. The exec therefore runs on a NON-installing thread.
fn probe_exec(install: bool) -> i32 {
    // Build the filter in the PARENT (minimises allocation in the child after fork).
    let prepared = if install {
        Some(sandbox::linux::prepare_seccomp().expect("compile whole-process seccomp filter"))
    } else {
        None
    };
    let true_path = cstr(&true_binary());

    // SAFETY: after fork the child installs the pre-built filter, then runs the probe on a spawned
    // thread. This test binary holds a single test, so no concurrent harness thread is allocating at
    // the fork instant (the malloc-after-fork hazard) — the child's thread spawn is safe.
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "fork() failed: {}",
        std::io::Error::last_os_error()
    );
    if pid == 0 {
        if let Some(p) = prepared.as_ref()
            && p.apply().is_err()
        {
            unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
        }
        // Run the denied op on a thread spawned AFTER the install (it inherits the filter via clone).
        let handle = std::thread::spawn(move || {
            let argv: [*const libc::c_char; 2] = [true_path.as_ptr(), std::ptr::null()];
            let envp: [*const libc::c_char; 1] = [std::ptr::null()];
            // SAFETY: argv/envp are NUL-terminated and outlive the call.
            unsafe {
                libc::execve(true_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            // Reached only if execve was NOT killed/replaced (i.e. a coverage HOLE): report it.
            unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
        });
        // Under ON, the thread's execve is killed (SIGSYS) → the whole process dies before join
        // returns. Under OFF, the thread's execve replaces the whole process image. Either way join
        // never returns normally; the sentinel below is only hit on an unexpected coverage hole.
        let _ = handle.join();
        unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
    }
    wait_code(pid)
}

/// Fork a child that (optionally) installs a Landlock ruleset (reads+writes confined to `data_dir`) on
/// its MAIN thread, then spawns a SECOND thread which tries the OUTSIDE + INSIDE writes.
fn probe_fs(install: bool, data_dir: &str, inside: &CString, outside: &CString) -> i32 {
    let prepared = if install {
        let roots = vec![PathBuf::from(data_dir)];
        Some(sandbox::linux::prepare_landlock(&roots, &roots).expect("build Landlock ruleset"))
    } else {
        None
    };
    let inside = inside.clone();
    let outside = outside.clone();

    // SAFETY: see `probe_exec`.
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "fork() failed: {}",
        std::io::Error::last_os_error()
    );
    if pid == 0 {
        let installed_ok = match prepared {
            Some(p) => p.apply().is_ok(),
            None => true,
        };
        if !installed_ok {
            unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
        }
        // Run the probe on a thread spawned AFTER the install (it inherits the domain via clone).
        let handle = std::thread::spawn(move || {
            let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC;
            // OUTSIDE the data dir — must be refused when Landlock is on.
            let out_fd = unsafe { libc::open(outside.as_ptr(), flags, 0o600) };
            let out_ok = out_fd >= 0;
            if out_fd >= 0 {
                unsafe { libc::close(out_fd) };
            }
            // INSIDE the data dir — must still succeed.
            let in_fd = unsafe { libc::open(inside.as_ptr(), flags, 0o600) };
            let in_ok = in_fd >= 0;
            if in_fd >= 0 {
                unsafe { libc::close(in_fd) };
            }
            let code = match (out_ok, in_ok) {
                (false, true) => FS_OUTSIDE_REFUSED_INSIDE_OK,
                (true, true) => FS_BOTH_OK,
                _ => FS_UNEXPECTED,
            };
            unsafe { libc::_exit(code) };
        });
        let _ = handle.join();
        unsafe { libc::_exit(FS_UNEXPECTED) };
    }
    wait_code(pid)
}

#[test]
#[ignore = "live/privileged OS-sandbox gate: forks children that install seccomp-bpf + Landlock against the real kernel and probe from a non-installing thread; runs ONLY in the dedicated sandbox-live CI step via --include-ignored, not the general --all-features suite"]
fn sandbox_live_blocks_exec_and_out_of_data_dir_writes() {
    // Fail with a clear message on a kernel without Landlock, rather than a confusing assertion
    // mismatch (the CI runner has it; this guards a stray dev box / minimal container).
    let abi = sandbox::linux::landlock_kernel_abi();
    assert!(
        abi > 0,
        "this kernel reports no Landlock support (landlock_create_ruleset ABI probe returned {abi}); \
         the sandbox-live gate needs a Landlock-capable kernel (ubuntu-latest has it)"
    );

    // Scratch layout: a `data` dir (the allowed root) and a sibling `outside` dir (NOT allowed).
    let base = std::env::temp_dir().join(format!("br-sandbox-live-{}", std::process::id()));
    let data_dir = base.join("data");
    let outside = base.join("outside");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let inside_file = data_dir.join("inside.txt");
    let outside_file = outside.join("outside.txt");
    let data_dir_s = data_dir.to_str().expect("utf-8 data dir");
    let inside_c = cstr(inside_file.to_str().expect("utf-8 inside path"));
    let outside_c = cstr(outside_file.to_str().expect("utf-8 outside path"));

    // ---- sandbox ON (enforced on a NON-installing thread) ------------------------------------------
    let exec_on = probe_exec(true);
    assert_eq!(
        exec_on,
        128 + libc::SIGSYS,
        "seccomp ON: execve on a NON-installing thread must be KILLED with SIGSYS (exec* denial + \
         KILL_PROCESS + whole-process coverage); child wait-code was {exec_on} \
         (0 = execve succeeded; {SELFTEST_INSTALL_FAILED} = a coverage hole or install error)"
    );
    let fs_on = probe_fs(true, data_dir_s, &inside_c, &outside_c);
    assert_eq!(
        fs_on, FS_OUTSIDE_REFUSED_INSIDE_OK,
        "Landlock ON: on a NON-installing thread, a write OUTSIDE data_dir must be refused while a \
         write INSIDE succeeds; child exit was {fs_on} ({FS_BOTH_OK} = outside was NOT confined)"
    );

    // Reset the probe files so the OFF run recreates them from scratch.
    let _ = std::fs::remove_file(&inside_file);
    let _ = std::fs::remove_file(&outside_file);

    // ---- sandbox OFF (mutation: prove the ON assertions detect a real difference) ------------------
    let exec_off = probe_exec(false);
    assert_eq!(
        exec_off, 0,
        "sandbox OFF: execve must SUCCEED (the child becomes `true`, exit 0), proving the ON kill is \
         real; child wait-code was {exec_off}"
    );
    let fs_off = probe_fs(false, data_dir_s, &inside_c, &outside_c);
    assert_eq!(
        fs_off, FS_BOTH_OK,
        "sandbox OFF: BOTH the inside and outside writes must succeed, proving the ON refusal is \
         real; child exit was {fs_off}"
    );

    let _ = std::fs::remove_dir_all(&base);

    // The single marker the CI gate greps for — printed ONLY after all four probes held.
    println!(
        "SANDBOX LIVE OK: on a NON-installing thread, seccomp-bpf KILLED exec* (SIGSYS) and Landlock \
         refused a write outside data_dir; with the sandbox OFF both ops succeeded (mutation-verified)."
    );
}
