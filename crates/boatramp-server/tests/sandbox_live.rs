//! LIVE gate for the whole-process OS sandbox (privsep Phase 0, WS1 — seccomp-bpf + Landlock).
//!
//! It proves, against the REAL kernel, the two security properties WS1 promises — and MUTATION-VERIFIES
//! them by running the SAME probes with the sandbox OFF and asserting the ops then SUCCEED (so the ON
//! assertions detect a real difference, not a no-op):
//!
//!   (a) **`exec*` is DENIED** by the seccomp allow-list. A forked child installs the whole-process
//!       seccomp filter, then `execve`s `/bin/true`. With the filter ON, `execve` is refused (`EPERM`)
//!       and the child falls through to `_exit(EXEC_BLOCKED)`. With it OFF, `execve` succeeds, the child
//!       becomes `/bin/true`, and exits `0`.
//!   (b) **A write OUTSIDE the data dir is REFUSED** by Landlock. A forked child installs a Landlock
//!       ruleset confining reads+writes to a `data_dir`, then tries to create a file OUTSIDE it (must be
//!       `EACCES`) and INSIDE it (must succeed). With Landlock OFF, both succeed.
//!
//! Each probe runs in its OWN `fork`ed child so the filter/ruleset never touches the test process, and
//! the child runs ONLY pre-built, async-signal-safe syscalls after the fork (the seccomp program +
//! Landlock ruleset are built in the parent). A real `execve`/`open` is driven — not a mock — so TESTED
//! == ENFORCED.
//!
//! `#[ignore]`d (it forks + installs a whole-process filter): it runs ONLY in the dedicated
//! `sandbox-live` CI step via `--include-ignored`, NEVER in the general `--all-features` suite. The CI
//! step greps the success marker `SANDBOX LIVE OK` + the pass count, so a silent skip/compile-out fails
//! the job. Gated on `cfg(all(target_os = "linux", feature = "sandbox"))` — a no-op build elsewhere.

#![cfg(all(target_os = "linux", feature = "sandbox"))]

use std::ffi::CString;
use std::path::PathBuf;

use boatramp_server::sandbox;

// Child exit codes (the probes report via exit code, not stdout, so the CI grep stays unambiguous).
const EXEC_BLOCKED: i32 = 42; // seccomp refused execve → the child fell through to here
const FS_OUTSIDE_REFUSED_INSIDE_OK: i32 = 21; // Landlock ON: outside refused, inside allowed
const FS_BOTH_OK: i32 = 22; // sandbox OFF (or a hole): both writes succeeded
const FS_UNEXPECTED: i32 = 23; // inside refused and/or an impossible combination
const SELFTEST_INSTALL_FAILED: i32 = 99; // the sandbox install itself errored in the child

fn cstr(s: &str) -> CString {
    CString::new(s).expect("path has no interior NUL")
}

/// Resolve an absolute path to a `true` binary for the exec probe. Searches `$PATH` (so it works on a
/// stock CI runner and on NixOS, where coreutils live in the nix store, not `/bin`), with a few common
/// fallbacks.
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

/// Fork a child that (optionally) installs the whole-process seccomp filter, then `execve`s `/bin/true`.
fn probe_exec(install: bool) -> i32 {
    // Build the filter in the PARENT (no heap allocation in the child after fork).
    let prepared = if install {
        Some(sandbox::linux::prepare_seccomp().expect("compile whole-process seccomp filter"))
    } else {
        None
    };
    let true_path = cstr(&true_binary());
    let argv: [*const libc::c_char; 2] = [true_path.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];

    // SAFETY: after fork the child runs only pre-built, async-signal-safe syscalls, then `_exit`.
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
            // SAFETY: _exit is async-signal-safe and does not return.
            unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
        }
        // SAFETY: argv/envp are NUL-terminated and outlive the call; execve returns only on failure.
        unsafe {
            libc::execve(true_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            // Only reached if execve was refused (seccomp EPERM).
            libc::_exit(EXEC_BLOCKED);
        }
    }
    wait_code(pid)
}

/// Fork a child that (optionally) installs a Landlock ruleset confining reads+writes to `data_dir`,
/// then tries to create a file OUTSIDE it and INSIDE it.
fn probe_fs(install: bool, data_dir: &str, inside: &CString, outside: &CString) -> i32 {
    let prepared = if install {
        let roots = vec![PathBuf::from(data_dir)];
        Some(sandbox::linux::prepare_landlock(&roots, &roots).expect("build Landlock ruleset"))
    } else {
        None
    };

    // SAFETY: the child runs only async-signal-safe syscalls after fork, then `_exit`.
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
    }
    wait_code(pid)
}

#[test]
#[ignore = "live/privileged OS-sandbox gate: forks children that install seccomp-bpf + Landlock against the real kernel; runs ONLY in the dedicated sandbox-live CI step via --include-ignored, not the general --all-features suite"]
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

    // ---- sandbox ON --------------------------------------------------------------------------------
    let exec_on = probe_exec(true);
    assert_eq!(
        exec_on, EXEC_BLOCKED,
        "seccomp ON: execve MUST be refused (exec* denied) — child exit was {exec_on} \
         (0 = execve succeeded; {SELFTEST_INSTALL_FAILED} = install errored)"
    );
    let fs_on = probe_fs(true, data_dir_s, &inside_c, &outside_c);
    assert_eq!(
        fs_on, FS_OUTSIDE_REFUSED_INSIDE_OK,
        "Landlock ON: a write OUTSIDE data_dir MUST be refused while a write INSIDE succeeds — \
         child exit was {fs_on} ({FS_BOTH_OK} = outside was NOT confined)"
    );

    // Reset the probe files so the OFF run recreates them from scratch.
    let _ = std::fs::remove_file(&inside_file);
    let _ = std::fs::remove_file(&outside_file);

    // ---- sandbox OFF (mutation: prove the ON assertions detect a real difference) ------------------
    let exec_off = probe_exec(false);
    assert_eq!(
        exec_off, 0,
        "sandbox OFF: execve MUST succeed (/bin/true exits 0), proving the ON block is real — \
         child exit was {exec_off}"
    );
    let fs_off = probe_fs(false, data_dir_s, &inside_c, &outside_c);
    assert_eq!(
        fs_off, FS_BOTH_OK,
        "sandbox OFF: BOTH the inside and outside writes MUST succeed, proving the ON refusal is \
         real — child exit was {fs_off}"
    );

    let _ = std::fs::remove_dir_all(&base);

    // The single marker the CI gate greps for — printed ONLY after all four probes held.
    println!(
        "SANDBOX LIVE OK: seccomp-bpf denied exec* (EPERM) and Landlock refused a write outside \
         data_dir; with the sandbox OFF both ops succeeded (mutation-verified)."
    );
}
