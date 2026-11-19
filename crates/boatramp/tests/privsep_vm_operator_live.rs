//! Live end-to-end gate for the scoped privsep VM substrate's **operator supervise-dispatch** (S1 —
//! `crates/boatramp/DESIGN-privsep-phase3-vm-scoped.md`). Unlike `privsep_vm_live.rs` (which calls
//! `launch_frontend_vm` directly, with the byte-relay on an in-root THREAD), this drives the REAL
//! operator path: `boatramp __root` resolves the `[privsep]` topology, binds the privileged listener,
//! boots the microVM guest (`boot_frontend_vm`, NO in-root relay), `fork`+`exec`s a SEPARATE
//! least-authority `__vm-relay` process, runs the relay's POSITIVE readiness handshake (Finding 1),
//! and supervises BOTH the firecracker child and the relay child.
//!
//! It proves three things against the live kernel:
//! 1. **serve** — a client `GET /` flows client → root-bound TCP listener → the separate `__vm-relay`
//!    → vsock → the frontend-in-guest → a real `200` behind the hypervisor wall (`PRIVSEP VM SUPERVISE
//!    SERVE OK`), with the relay's readiness gate having PASSED (`PRIVSEP VM RELAY READY`);
//! 2. **relay death ⇒ FailNodeClosed** — SIGKILL the `__vm-relay` child ⇒ the root supervise loop
//!    tears the whole node down and exits non-zero (`PRIVSEP VM RELAY-KILL FAILCLOSED OK`);
//! 3. **guest death ⇒ FailNodeClosed** — a fresh node, SIGKILL the firecracker child ⇒ the root tears
//!    the node down and exits (`PRIVSEP VM FIRECRACKER-KILL FAILCLOSED OK`).
//!
//! LIGHTHOUSE-ONLY (needs `/dev/kvm` + firecracker + a Landlock-V5 guest kernel + the non-PIE shim + a
//! musl static-PIE `boatramp` AND root — the relay inherits `CAP_SYS_ADMIN` from the privileged root
//! to enter its netns/mount-ns). `#[ignore]`d and driven by
//! `docs/privsep-vm-scoped-repro/run-operator.sh`, which builds the assets, sets the
//! `BOATRAMP_PRIVSEP_VM_*` + `BOATRAMP_PRIVSEP_VM_ROOT_BIN` env, and runs it with `--ignored` under
//! `sudo`. It is NOT a GitHub-hosted-CI merge gate (no `/dev/kvm`); the evidence is the lighthouse run.
#![cfg(all(target_os = "linux", feature = "sandbox"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Which supervised child to SIGKILL to prove `FailNodeClosed` tears the node down.
#[derive(Clone, Copy)]
enum KillTarget {
    Relay,
    Firecracker,
}

#[test]
#[ignore = "live: operator supervise-dispatch boots a firecracker microVM (needs /dev/kvm + root + a \
            Landlock-V5 guest kernel + the non-PIE shim + a musl static-PIE boatramp); run via \
            docs/privsep-vm-scoped-repro/run-operator.sh"]
fn privsep_vm_operator_dispatch_serves_then_failnodeclosed_on_either_child_death() {
    let Ok(root_bin) = std::env::var("BOATRAMP_PRIVSEP_VM_ROOT_BIN") else {
        eprintln!(
            "SKIP: set BOATRAMP_PRIVSEP_VM_ROOT_BIN (the musl static-PIE boatramp run as `__root`) + \
             the BOATRAMP_PRIVSEP_VM_* assets; run docs/privsep-vm-scoped-repro/run-operator.sh on \
             lighthouse under sudo"
        );
        return;
    };
    for k in [
        "BOATRAMP_PRIVSEP_VM_FIRECRACKER",
        "BOATRAMP_PRIVSEP_VM_KERNEL",
        "BOATRAMP_PRIVSEP_VM_KERNEL_SHA256",
        "BOATRAMP_PRIVSEP_VM_SHIM",
    ] {
        if std::env::var(k).is_err() {
            eprintln!("SKIP: VM asset env {k} not set — run the repro driver");
            return;
        }
    }

    // Phase 1: serve end-to-end, then SIGKILL the relay child ⇒ the node must tear down FailNodeClosed.
    run_once(&root_bin, KillTarget::Relay);
    println!("PRIVSEP VM SUPERVISE SERVE OK");
    println!("PRIVSEP VM RELAY-KILL FAILCLOSED OK");

    // Phase 2: a FRESH node, SIGKILL the firecracker child ⇒ the node must tear down FailNodeClosed.
    run_once(&root_bin, KillTarget::Firecracker);
    println!("PRIVSEP VM FIRECRACKER-KILL FAILCLOSED OK");
}

/// Boot one operator node, prove it serves a 200, then SIGKILL `target` and assert the root exits
/// (FailNodeClosed). Panics (with the captured root log + guest console) on any failure.
fn run_once(root_bin: &str, target: KillTarget) {
    // Root the node dirs under `/var/lib` (root-owned, mode 0755), NOT `$CARGO_TARGET_TMPDIR` under the
    // repo: the privsep instances drop ALL capabilities (incl. CAP_DAC_OVERRIDE) in their `pre_exec`,
    // so as uid 0 they cannot TRAVERSE a 0700 `/home/<user>` to read the shared config — exactly as a
    // production root deploy keeps its config + data_dir on a root-traversable path, never under a
    // user's home. `/var/lib` is also NOT a base read-only root (`/usr`,`/bin`,…,`/run`,`/var/run`) —
    // so an instance's RW state-dir grant under data_dir does not collide with a parent RO grant — and
    // NOT a shared-temp dir (`/tmp`/`/var/tmp`/`$TMPDIR`), so `derive_profile` accepts a data_dir there.
    // The gate runs under sudo, so creating under `/var/lib` is fine.
    let tmp = PathBuf::from("/var/lib").join(format!(
        "boatramp-privsep-vm-op-{}-{}",
        std::process::id(),
        match target {
            KillTarget::Relay => "relay",
            KillTarget::Firecracker => "fc",
        }
    ));
    let _ = std::fs::remove_dir_all(&tmp); // a stale dir from a prior run
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");
    let log_path = tmp.join("root.log");

    // A valid 4-instance composition for the OPERATOR path. Exactly ONE serve.addr binder — the scoped
    // VM `edge` frontend, which holds BOTH serve.addr-binding listeners (`listen.public-tls` +
    // `listen.http-parse`), is key-free (the lint's P3), and serves self-contained behind the
    // hypervisor wall. The other instances are LINKLESS, hold only non-serve.addr authorities, and PARK
    // (hold their authority inert) — present so the composition-closure lint's union == ALL passes
    // without a second serve.addr bind. No crown jewel co-resides a listener/exec/control surface.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                substrate: Vm,
                links: [],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay", "listen.s3ingress",
                    "listen.inbound-tcp", "listen.gateway", "exec.wasmtime", "acme.dns-control",
                ],
                sandbox: Derived,
                links: [],
            ),
            "ops": (
                capabilities: ["exec.compute", "control.admin-api"],
                sandbox: Derived,
                links: [],
            ),
            "core": (
                capabilities: [
                    "secrets.sealer", "token.signer", "image.signer", "overlay.dial-signer",
                    "s3ingress.root", "cluster.join-signer",
                    "backend.kv", "backend.sql", "backend.blob", "backend.messaging",
                ],
                sandbox: Derived,
                links: [],
            ),
        }},
        links: {{}},
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the privsep config");

    let log = std::fs::File::create(&log_path).expect("create the root log");
    let log2 = log.try_clone().expect("clone the root log handle");
    let mut root = Command::new(root_bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .spawn()
        .expect("spawn `boatramp __root` (the operator supervisor)");

    // 1. Wait for the node to SERVE a 200 (cold boot: firecracker + ~185 MB cpio unpack + static-PIE
    //    self-reloc + the guest's Enforced profile + vsock bind + the relay's readiness handshake).
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        if Instant::now() > deadline {
            let log = read_log(&log_path);
            let _ = root.kill();
            let _ = root.wait();
            dump_guest_console(&data_dir);
            panic!("the operator VM node did not serve a 200 within 150s\n---root log---\n{log}");
        }
        if let Ok(Some(status)) = root.try_wait() {
            let log = read_log(&log_path);
            dump_guest_console(&data_dir);
            panic!(
                "`boatramp __root` exited early ({status}) before serving — the operator VM dispatch \
                 failed to stand up\n---root log---\n{log}"
            );
        }
        if let Ok(resp) = try_http_get(port)
            && resp.contains("200")
            && resp.contains("boatramp privsep VM static-parser frontend")
        {
            break; // served a real 200 from the VM guest over the separate relay
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // 2. The relay's POSITIVE readiness gate must have passed before it accepted our client.
    let log = read_log(&log_path);
    assert!(
        log.contains("PRIVSEP VM RELAY READY"),
        "the relay's readiness handshake must have PASSED before serving (Finding 1)\n---log---\n{log}"
    );
    assert!(
        log.contains("scoped VM frontend dispatched"),
        "the operator supervise-dispatch log line must be present\n---log---\n{log}"
    );

    // 3. Extract the two supervised child PIDs from the dispatch log line
    //    (`... fc_pid=<N> relay_pid=<M> ...`) and SIGKILL the chosen one.
    let fc_pid = extract_pid(&log, "fc_pid=").expect("fc_pid in the dispatch log line");
    let relay_pid = extract_pid(&log, "relay_pid=").expect("relay_pid in the dispatch log line");
    let (victim, which) = match target {
        KillTarget::Relay => (relay_pid, "__vm-relay"),
        KillTarget::Firecracker => (fc_pid, "firecracker guest"),
    };
    // SAFETY: kill(2) takes two scalars; the test runs as root and the victim is a child of our root.
    let rc = unsafe { libc::kill(victim as libc::pid_t, libc::SIGKILL) };
    assert_eq!(
        rc, 0,
        "SIGKILL of the {which} child (pid {victim}) must succeed"
    );

    // 4. The root's supervise loop must detect the child's death and tear the WHOLE node down
    //    (FailNodeClosed) — it exits within a short deadline (the loop polls every 200 ms).
    let td_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match root.try_wait() {
            Ok(Some(_status)) => break, // the root exited — FailNodeClosed tore the node down
            Ok(None) => {
                if Instant::now() > td_deadline {
                    let log = read_log(&log_path);
                    let _ = root.kill();
                    let _ = root.wait();
                    panic!(
                        "killing the {which} child (pid {victim}) did NOT tear the node down within \
                         30s — the operator supervise loop failed to FailNodeClosed\n---log---\n{log}"
                    );
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("waiting on the root after killing {which}: {e}"),
        }
    }
    // The root exited (non-zero FailNodeClosed). Belt-and-suspenders: reap any stragglers.
    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Grab a free loopback port (bind :0, read it back, release it). A small race, fine for a live gate.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// One blocking HTTP/1.1 GET to the node's public addr, returning the raw response or an error.
fn try_http_get(port: u16) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: op-gate\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

/// Parse `<key><digits>` out of the root log (tracing's `key=value` field format). The log is
/// ANSI-stripped first (see `read_log`), so `fc_pid=` / `relay_pid=` are contiguous — the tracing
/// formatter otherwise wraps the `=` in SGR colour codes (`fc_pid\x1b[0m\x1b[2m=`), which would break a
/// literal substring search.
fn extract_pid(log: &str, key: &str) -> Option<u32> {
    let idx = log.find(key)? + key.len();
    let digits: String = log[idx..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Read the root log, STRIPPING ANSI/SGR escape sequences — the node's tracing emits colour codes even
/// to a non-tty file sink, which would split `key=value` fields (e.g. `fc_pid=`) across escapes.
fn read_log(path: &Path) -> String {
    strip_ansi(&std::fs::read_to_string(path).unwrap_or_default())
}

/// Remove ANSI CSI escape sequences (`\x1b[ … <final-byte>`), leaving plain text.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC [ <params> <final>. The CSI introducer `[` (0x5B) is itself inside the final-byte
            // range (0x40..=0x7E), so it must be SKIPPED first — otherwise the scan stops on `[` and
            // leaves the params (e.g. `3m`) behind.
            let mut first = true;
            for c2 in chars.by_ref() {
                if first {
                    first = false; // the `[` introducer
                } else if ('\u{40}'..='\u{7e}').contains(&c2) {
                    break; // the final byte (e.g. `m`)
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Echo the guest serial console (SHIM-ALIVE / PRIVSEP VM GUEST SERVING / any fatal reason) on failure.
fn dump_guest_console(data_dir: &Path) {
    // The root puts each VM's work dir at `<data_dir>/privsep-vm/<label>/console.log`.
    let console = data_dir.join("privsep-vm").join("edge").join("console.log");
    if let Ok(log) = std::fs::read_to_string(&console) {
        eprintln!("---- guest serial console ({}) ----", console.display());
        eprint!("{log}");
        eprintln!("---- end guest serial console ----");
    }
}
