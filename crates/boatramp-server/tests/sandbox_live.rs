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
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use boatramp_server::sandbox;

// Child exit codes (the probes report via exit code, not stdout, so the CI grep stays unambiguous).
const FS_OUTSIDE_REFUSED_INSIDE_OK: i32 = 21; // Landlock ON: outside refused, inside allowed
const FS_BOTH_OK: i32 = 22; // sandbox OFF (or a hole): both writes succeeded
const FS_UNEXPECTED: i32 = 23; // inside refused and/or an impossible combination
// SERVE smoke (M2): the ALLOW set must pass the REAL serving byte-movers under the filter.
const SERVE_OK: i32 = 31; // sendfile file-body + splice reverse-proxy relay both delivered in full
const SERVE_SENDFILE_FAILED: i32 = 32; // sendfile EPERM'd / short (H1 missing `sendfile`)
const SERVE_SPLICE_FAILED: i32 = 33; // splice EPERM'd / short (H1 missing `splice`)
const SERVE_SETUP_FAILED: i32 = 34; // socket/pipe/file plumbing failed (not a filter verdict)
// Per-capability DERIVED profile (privsep Phase 1 WS-D): a no-listener (storage) profile must EPERM
// `bind` while still allowing `socket` (it has outbound). Mutation-verified with the sandbox OFF.
const DERIVED_BIND_REFUSED: i32 = 41; // derived profile ON: socket allowed, bind EPERM'd (expected)
const DERIVED_BIND_ALLOWED: i32 = 42; // OFF or a hole: bind succeeded
const DERIVED_BIND_SETUP_FAILED: i32 = 43; // socket() itself failed (not the bind verdict)
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

/// Fork a child that (optionally) installs a DERIVED per-capability profile (privsep Phase 1 WS-D) for
/// a no-listener (storage: `backend.*`) instance on its MAIN thread, then on a SECOND (spawned) thread
/// creates a socket (which the derived profile ALLOWS — storage dials outbound) and tries to `bind` it
/// (which the derived profile DENIES — no `listen.*` capability). Proves the derivation's load-bearing
/// denial against the REAL kernel, from a non-installing thread.
fn probe_derived_bind(install: bool) -> i32 {
    use boatramp_core::privsep::{HostAuthority, SandboxPosture};
    use std::collections::BTreeSet;

    let caps: BTreeSet<HostAuthority> = [
        HostAuthority::BackendKv,
        HostAuthority::BackendSql,
        HostAuthority::BackendBlob,
        HostAuthority::BackendMessaging,
    ]
    .into_iter()
    .collect();
    // System read roots + temp only (no listener, no key paths) — a clean no-listener profile.
    // data_dir is a non-temp path: derive_profile refuses a data_dir placed under a shared_temp
    // dir (Security re-review residual #3), and shared_temp defaults include /tmp.
    let inputs = sandbox::SandboxDerivationInputs::for_instance("/var/lib/boatramp-livetest", None);
    let profile = if install {
        Some(
            sandbox::derive_profile(&caps, SandboxPosture::Derived, &inputs)
                .expect("derive a no-listener storage profile"),
        )
    } else {
        None
    };

    // SAFETY: see `probe_exec` — single-test binary, no concurrent harness allocation at fork.
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "fork() failed: {}",
        std::io::Error::last_os_error()
    );
    if pid == 0 {
        if let Some(p) = profile.as_ref()
            && sandbox::linux::install_derived(p).is_err()
        {
            unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
        }
        let handle = std::thread::spawn(move || {
            // `socket` is ALLOWED for a backend instance (it dials its pools outbound).
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                unsafe { libc::_exit(DERIVED_BIND_SETUP_FAILED) };
            }
            // `bind` must be DENIED (no `listen.*`). Bind to an ephemeral loopback port.
            // SAFETY: a zeroed sockaddr_in, filled for AF_INET loopback:0, passed by value size.
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 0; // ephemeral
            addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let r = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            let bind_ok = r == 0;
            unsafe { libc::close(fd) };
            let code = if bind_ok {
                DERIVED_BIND_ALLOWED
            } else {
                DERIVED_BIND_REFUSED
            };
            unsafe { libc::_exit(code) };
        });
        let _ = handle.join();
        unsafe { libc::_exit(DERIVED_BIND_SETUP_FAILED) };
    }
    wait_code(pid)
}

/// `sendfile(2)` the whole `in_fd` to `out_fd`, looping over partial transfers. EPERM (seccomp without
/// H1's `sendfile`) surfaces as an `Err` here.
fn sendfile_all(out_fd: i32, in_fd: i32, count: usize) -> std::io::Result<usize> {
    let mut sent = 0usize;
    let mut offset: libc::off_t = 0;
    while sent < count {
        // SAFETY: valid fds the caller owns; `offset` is a valid out-pointer; `count` bounds the move.
        let n = unsafe { libc::sendfile(out_fd, in_fd, &mut offset, count - sent) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        sent += n as usize;
    }
    Ok(sent)
}

/// `splice(2)` once from `fd_in` into `fd_out` (one of which is a pipe end). Returns bytes moved (0 =
/// EOF). EPERM (seccomp without H1's `splice`) surfaces as an `Err`.
fn splice_once(fd_in: i32, fd_out: i32, len: usize) -> std::io::Result<isize> {
    // SAFETY: valid fds the caller owns; NULL offsets (stream/pipe), no SPLICE_F flags.
    let n = unsafe { libc::splice(fd_in, ptr::null_mut(), fd_out, ptr::null_mut(), len, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n)
}

/// (a) Serve a local-fs file body over a plaintext loopback `TcpStream` via `sendfile` (the exact
/// `boatramp-http` HTTP/1.1 file-body syscall). Returns Ok(true) iff the client receives the full body.
fn sendfile_smoke(body_path: &str) -> std::io::Result<bool> {
    let body = std::fs::read(body_path)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let mut client = TcpStream::connect(addr)?; // loopback connect completes before accept
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (server, _) = listener.accept()?;
    let file = File::open(body_path)?;
    let sent = sendfile_all(server.as_raw_fd(), file.as_raw_fd(), body.len())?;
    if sent != body.len() {
        return Ok(false);
    }
    let mut got = vec![0u8; body.len()];
    client.read_exact(&mut got)?;
    // Keep `server` alive until the client has read (dropping it early could reset the conn).
    drop(server);
    Ok(got == body)
}

/// (b) Relay one plaintext HTTP/1.1 reverse-proxy response upstream→downstream via a pipe + `splice`
/// (the exact `boatramp-server::splice` data-plane pattern). Returns Ok(true) iff the client receives
/// the full response.
fn splice_smoke() -> std::io::Result<bool> {
    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    // Upstream connection: `u_srv` is the upstream server; the front reads from `u_cli`.
    let up = TcpListener::bind("127.0.0.1:0")?;
    let up_addr = up.local_addr()?;
    let u_cli = TcpStream::connect(up_addr)?;
    let (mut u_srv, _) = up.accept()?;
    // Downstream connection: the front writes `d_srv`; the real client reads `d_cli`.
    let down = TcpListener::bind("127.0.0.1:0")?;
    let down_addr = down.local_addr()?;
    let mut d_cli = TcpStream::connect(down_addr)?;
    d_cli.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (d_srv, _) = down.accept()?;

    // The upstream speaks its response, then half-closes so the relay sees EOF after it.
    u_srv.write_all(RESPONSE)?;
    u_srv.shutdown(Shutdown::Write)?;

    // Front relay: u_cli -> pipe -> d_srv via splice, until upstream EOF.
    let mut pipefd = [0 as libc::c_int; 2];
    // SAFETY: valid out array; O_CLOEXEC pipe.
    if unsafe { libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (pr, pw) = (pipefd[0], pipefd[1]);
    let relay = (|| -> std::io::Result<usize> {
        let mut relayed = 0usize;
        loop {
            let n = splice_once(u_cli.as_raw_fd(), pw, 65536)?;
            if n == 0 {
                break; // upstream EOF
            }
            let mut moved: isize = 0;
            while moved < n {
                let m = splice_once(pr, d_srv.as_raw_fd(), (n - moved) as usize)?;
                if m == 0 {
                    break;
                }
                moved += m;
                relayed += m as usize;
            }
        }
        Ok(relayed)
    })();
    // SAFETY: close the pipe ends regardless of the relay outcome.
    unsafe {
        libc::close(pr);
        libc::close(pw);
    }
    let relayed = relay?;
    drop(d_srv); // close downstream so the client sees EOF
    let mut got = Vec::new();
    d_cli.read_to_end(&mut got)?;
    Ok(got == RESPONSE && relayed == RESPONSE.len())
}

/// The serve ops, run on a NON-installing worker thread (symmetric with the deny probes): prove the
/// ALLOW set passes the real serving byte-movers (`sendfile` + `splice`) under the filter.
fn serve_ops(body_path: &str) -> i32 {
    match sendfile_smoke(body_path) {
        Ok(true) => {}
        Ok(false) => return SERVE_SENDFILE_FAILED,
        Err(_) => return SERVE_SENDFILE_FAILED,
    }
    match splice_smoke() {
        Ok(true) => {}
        Ok(false) => return SERVE_SPLICE_FAILED,
        Err(_) => return SERVE_SPLICE_FAILED,
    }
    SERVE_OK
}

/// Fork a child that (optionally) installs the REAL combined `install()` filter on its MAIN thread,
/// then serves a file body (`sendfile`) + relays a reverse-proxy response (`splice`) on a SECOND
/// (spawned) thread. Proves the ALLOW set against the real serving path (H1) and guards the class.
fn probe_serve(install: bool, data_dir: &str) -> i32 {
    let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let body_path = format!("{data_dir}/serve-body.bin");
    if std::fs::write(&body_path, &body).is_err() {
        return SERVE_SETUP_FAILED;
    }
    let policy = sandbox::SandboxPolicy::for_server(data_dir);

    // SAFETY: the child installs the pre-resolved policy, then serves on a spawned thread. Single-test
    // binary ⇒ no concurrent harness allocation at the fork instant.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let _ = std::fs::remove_file(&body_path);
        panic!("fork() failed: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        if install && sandbox::install(&policy).is_err() {
            unsafe { libc::_exit(SELFTEST_INSTALL_FAILED) };
        }
        let path = body_path.clone();
        let code = std::thread::spawn(move || serve_ops(&path))
            .join()
            .unwrap_or(SERVE_SETUP_FAILED);
        unsafe { libc::_exit(code) };
    }
    let code = wait_code(pid);
    let _ = std::fs::remove_file(&body_path);
    code
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

    // ---- SERVE smoke (H1 / M2): prove the ALLOW set passes the real serving byte-movers -------------
    // Under the REAL combined install() filter, on a NON-installing worker thread, serving a file body
    // (sendfile) + relaying a plaintext HTTP/1.1 reverse-proxy response (splice) must BOTH complete. If
    // H1's fd byte-movers were missing from the allow-list, these EPERM mid-response → RED.
    let serve_on = probe_serve(true, data_dir_s);
    assert_eq!(
        serve_on, SERVE_OK,
        "under the REAL combined sandbox filter, sendfile (file body over a plaintext TcpStream) AND \
         splice (plaintext HTTP/1.1 reverse-proxy relay) must both deliver the full payload (H1); child \
         exit was {serve_on} ({SERVE_SENDFILE_FAILED}=sendfile EPERM/short, \
         {SERVE_SPLICE_FAILED}=splice EPERM/short, {SERVE_SETUP_FAILED}=plumbing)"
    );
    // Sanity: the same plumbing without the filter also serves (so SERVE_OK above is about the filter,
    // not a broken harness).
    let serve_off = probe_serve(false, data_dir_s);
    assert_eq!(
        serve_off, SERVE_OK,
        "serve-smoke plumbing sanity WITHOUT the filter; child exit was {serve_off}"
    );

    // ---- DERIVED per-capability profile (privsep Phase 1 WS-D): a no-listener instance's profile -----
    // DENIES `bind` while still ALLOWING `socket`. Proves the per-capability derivation's load-bearing
    // denial against the real kernel, mutation-verified with the profile OFF.
    let bind_on = probe_derived_bind(true);
    assert_eq!(
        bind_on, DERIVED_BIND_REFUSED,
        "derived profile ON (no-listener storage caps): on a NON-installing thread, `socket` is allowed \
         but `bind` must be EPERM'd; child exit was {bind_on} ({DERIVED_BIND_ALLOWED}=bind was NOT \
         denied, {DERIVED_BIND_SETUP_FAILED}=socket() failed)"
    );
    let bind_off = probe_derived_bind(false);
    assert_eq!(
        bind_off, DERIVED_BIND_ALLOWED,
        "derived profile OFF: `bind` must SUCCEED, proving the ON denial is real; child exit was \
         {bind_off}"
    );

    let _ = std::fs::remove_dir_all(&base);

    // The single marker the CI gate greps for — printed ONLY after all probes held.
    println!(
        "SANDBOX LIVE OK: on a NON-installing thread, seccomp-bpf KILLED exec* (SIGSYS) and Landlock \
         refused a write outside data_dir; under the REAL combined filter, sendfile (file body) + \
         splice (reverse-proxy relay) both served in full (H1); a DERIVED no-listener profile EPERM'd \
         `bind` while allowing `socket` (WS-D); and with the sandbox OFF the deny ops all succeeded \
         (mutation-verified)."
    );
}
