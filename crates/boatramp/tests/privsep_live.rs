//! Live end-to-end gate for the privsep Phase-1 2-instance composition (WS-C).
//!
//! Proves the WHOLE runtime wiring against the real kernel: the root (`boatramp __root`) resolves
//! the `[privsep]` topology, runs the fail-closed screens + lints, creates a `socketpair(2)` link,
//! binds the privileged public listener, and `fork`+`exec`s two feature-instances — a `listen.*`
//! FRONTEND and a backend+crown-jewel CORE. Each instance installs its per-capability
//! seccomp/Landlock profile and REFUSES to serve unless it reports `Enforced` (fail-closed). The
//! frontend accepts a client TCP connection on its inherited listener fd and splices the accepted
//! client fd to the core over the local link (`SCM_RIGHTS`); the core receives it and serves the
//! request with the hand-rolled HTTP stack. An HTTP client then gets a real `200` response —
//! bytes flowing client → frontend listener fd → SCM_RIGHTS splice → core → HTTP → client, with
//! BOTH instances sandboxed.
//!
//! `#[ignore]`d because it forks the real binary + installs a per-instance sandbox against the live
//! kernel — Linux + the `sandbox` feature only (on any other platform/build the instances
//! fail-closed at the sandbox install, the root exits, and the node never serves). The CI
//! `live gate (privsep)` job runs it with `--include-ignored` and greps the `PRIVSEP LIVE OK`
//! marker + the pass count, so a silent skip / compile-out fails the merge.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use boatramp_core::envelope::KeyEnvelope;
use boatramp_server::envelope::LocalKek;

/// Grab a currently-free loopback port (bind :0, read it back, release it). A small race, fine for
/// a single live gate.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

#[test]
#[ignore = "live: forks boatramp __root + installs the per-instance sandbox + serves end-to-end \
            over a socketpair SCM_RIGHTS splice (Linux + `sandbox` feature); run via \
            --include-ignored in the `live gate (privsep)` job"]
fn privsep_two_instance_composition_serves_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    // Root the node dirs under cargo's integration-test temp (`target/tmp`), NOT the system
    // temp (`/tmp`): a real deployment keeps data_dir on persistent storage, never under a
    // world-writable temp dir — and `derive_profile` fail-closed-refuses a data_dir placed under
    // a `shared_temp` entry (/tmp, /var/tmp, $TMPDIR). `CARGO_TARGET_TMPDIR` is under the repo's
    // target dir, outside those, so the composition stands up as it would in production.
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("boatramp-privsep-live-{}", std::process::id()));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // A minimal, VALID 4-instance composition (passes the closure lint: union == ALL; no crown
    // jewel co-resident with a listener/exec/control surface; grants disjoint; WS-D Finding-2
    // (widened): no public listener co-resides exec.compute / control.admin-api / backend.*):
    //   - `edge`  = the public parse surface (`listen.public-tls` + `listen.http-parse`) — the
    //               FRONTEND (binds serve.addr, splices client fds inward); NO spawn, NO KV;
    //   - `aux`   = the other listeners + `exec.wasmtime` + `acme.dns-control` (neither a Finding-2
    //               forbidden partner; no keys, no backends) — parks;
    //   - `ops`   = `exec.compute` + `control.admin-api` (off every public listener, WS-D Finding-2
    //               widened; no keys, no backends, no listeners) — parks;
    //   - `core`  = every crown jewel + every backend (group A ∪ B; a crown jewel may co-reside
    //               only with A ∪ B) — the serving BACKEND.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
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
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "edge", to: "core", transport: Local) }},
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(20);
    let response = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the privsep node did not serve a response within 20s");
        }
        // Fail-closed: if the root exited, the composition failed to stand up (a sandbox that
        // could not reach `Enforced`, a bad composition, …) — don't keep polling a dead node.
        if let Ok(Some(status)) = root.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the 2-instance composition failed to \
                 stand up (sandbox not Enforced? link/listener wiring?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    // HIGH-1 (final privsep Security re-review) — while the node is STILL serving, probe the
    // cross-instance `/proc/<pid>/mem` wall against the REAL crown-jewel `core` instance: a capless
    // same-uid sibling must be DENIED reading its memory (`PR_SET_DUMPABLE(0)` ⇒ root-owned +
    // `ptrace_may_access`-gated). Capture the verdict NOW (node alive) but assert AFTER teardown so a
    // failure doesn't leak the node. Linux+`sandbox` only — the probe uses `libc::fork` + the sandbox
    // capability primitives, so it is cfg-gated (this test otherwise compiles on every platform).
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    let proc_mem_verdict = probe_cross_instance_proc_mem_wall(&cfg_path);

    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        response.contains("200"),
        "expected a 200 status line from the backend instance, got:\n{response}"
    );
    assert!(
        response.contains("boatramp privsep backend"),
        "expected the backend instance's body marker (proving the SCM_RIGHTS splice reached a \
         sandboxed serving backend), got:\n{response}"
    );

    // HIGH-1 cross-instance `/proc/<pid>/mem` wall: assert the capless sibling was DENIED and emit the
    // `PRIVSEP PROC-MEM WALL OK` marker (mutation-verified — see `assert_proc_mem_wall`). A hard gate:
    // a wall-down verdict, or a probe that could not run (target gone / capdrop failed), FAILS here.
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    assert_proc_mem_wall(proc_mem_verdict);

    // The marker the CI gate greps — only reached after a real 200 came back over the full path.
    println!("PRIVSEP LIVE OK");
}

/// Live end-to-end gate for the privsep **signer-key unlock** (the "KEK-file now" owner decision):
/// a `token.signer` instance obtains its sealed signing key by asking a SEPARATE `secrets.sealer`
/// instance to unseal it over the feature-link, under a root-wired per-link allowlist the sealer
/// enforces fail-closed. Proves the WHOLE unlock path against the real kernel:
///
/// - a 4-instance composition stands up: `edge` (frontend) + `core` (backends) + `sealer`
///   (`secrets.sealer`, holding the `[secrets]` KEK) + `signer` (`token.signer`, its key NOT on its
///   own disk), with a `to-signer` link between the sealer and the signer;
/// - the root resolves the topology, runs the sealed-signer composition-closure lint, wires the
///   sealer's unseal allowlist (`to-signer` → the configured `key_ref`), and fork+execs all four,
///   each installing its per-capability `Enforced` sandbox;
/// - the signer asks the sealer over the link to unseal its key; the sealer (enforcing the
///   allowlist) reads the KEK-sealed key FILE behind its OWN Landlock grant, unwraps it with the
///   `[secrets]` KEK, and returns the plaintext; the signer loads it and runs a sign+verify
///   self-test — if ANY of that fails it exits and, under `FailNodeClosed`, the ROOT tears the whole
///   node down. So the node serving a real `200` over the independent `edge`→`core` path PROVES the
///   signer unlocked + verified its key end-to-end (a failed unlock would have killed the node).
///
/// `#[ignore]`d like the composition gate above (forks + sandboxes against the live kernel); the CI
/// `live gate (privsep)` job runs it with `--include-ignored` and greps the `PRIVSEP SIGNER UNSEAL
/// LIVE OK` marker + the signer's own `PRIVSEP SIGNER UNSEAL OK`.
#[test]
#[ignore = "live: forks boatramp __root for a 4-instance sealer+signer composition; the signer \
            unseals its key over the feature-link + self-tests it, then the node serves end-to-end \
            (Linux + `sandbox`); run via --include-ignored in the `live gate (privsep)` job"]
fn privsep_sealer_signer_unseal_serves_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("boatramp-privsep-unseal-{}", std::process::id()));
    let data_dir = tmp.join("data");
    let secrets_dir = data_dir.join("secrets");
    std::fs::create_dir_all(&secrets_dir).expect("create the node data + secrets dirs");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // Pre-seal the signer key exactly as the running sealer will read it: a `[secrets]` local KEK
    // file + the signer key spec sealed (KEK-wrapped) to a blob file. Any 32 bytes is a valid
    // ed25519 seed, so a fixed spec is a real, loadable key. (A real deploy would seal via the
    // `[secrets]` tooling; here the test is the producer so it is self-contained.)
    let kek_file = secrets_dir.join("kek");
    let sealed_file = secrets_dir.join("signer.sealed");
    let signer_spec = format!("ed25519:{}", "11".repeat(32)); // 32-byte seed in hex
    {
        // `load_or_generate` creates the KEK file `0600` (the SAME file the sealer loads at boot).
        let kek = LocalKek::load_or_generate(&kek_file).expect("create the [secrets] KEK file");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime to drive the async wrap");
        let sealed = rt
            .block_on(kek.wrap(signer_spec.as_bytes()))
            .expect("seal the signer key with the KEK");
        std::fs::write(&sealed_file, &sealed).expect("write the sealed signer-key blob");
    }

    // A VALID 6-instance composition (passes the closure lint + the sealed-signer closure lint;
    // WS-D Finding-2 widened: no public listener co-resides exec.compute / control / backend.*):
    //   - `edge`   = the public parse surface (`listen.public-tls` + `listen.http-parse`) — FRONTEND;
    //   - `aux`    = the other listeners + `exec.wasmtime` + `acme.dns-control` (parks);
    //   - `ops`    = `exec.compute` + `control.admin-api` (off every public listener; parks);
    //   - `core`   = the four backends (B) — the serving BACKEND (edge splices client fds here);
    //   - `sealer` = secrets.sealer + the OTHER crown jewels (A∖{token.signer}) — holds the KEK,
    //                serves unseal on `to-signer`;
    //   - `signer` = token.signer alone (A) — asks the sealer to unseal its key over `to-signer`.
    let cfg = format!(
        r#"(
    serve: (
        addr: "127.0.0.1:{port}",
        data_dir: "{data_dir}",
        signer: Sealed(key_ref: "path:{sealed}"),
    ),
    secrets: ( envelope: "local", kek_file: "{kek}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
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
                capabilities: ["backend.kv", "backend.sql", "backend.blob", "backend.messaging"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "sealer": (
                capabilities: [
                    "secrets.sealer", "image.signer", "overlay.dial-signer",
                    "s3ingress.root", "cluster.join-signer",
                ],
                sandbox: Derived,
                links: ["to-signer"],
            ),
            "signer": (
                capabilities: ["token.signer"],
                sandbox: Derived,
                links: ["to-signer"],
            ),
        }},
        links: {{
            "to-core":   (from: "edge",   to: "core",   transport: Local),
            "to-signer": (from: "sealer", to: "signer", transport: Local),
        }},
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
        sealed = sealed_file.display(),
        kek = kek_file.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    let response = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the privsep sealer+signer node did not serve a response within 25s");
        }
        // Fail-closed: if the root exited, the composition failed to stand up — most tellingly, the
        // signer failed to unseal/verify its key (FailNodeClosed tears the node down).
        if let Ok(Some(status)) = root.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the sealer+signer composition failed \
                 to stand up (signer could not unseal/verify its key? sandbox not Enforced?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        response.contains("200"),
        "expected a 200 status line (the node stood up ⇒ the signer unlocked its key), got:\n{response}"
    );
    assert!(
        response.contains("boatramp privsep backend"),
        "expected the backend body marker, got:\n{response}"
    );

    // The marker the CI gate greps — reached only after a real 200 came back, which under
    // FailNodeClosed requires the signer to have unsealed + verified its key over the link.
    println!("PRIVSEP SIGNER UNSEAL LIVE OK");
}

/// Live end-to-end gate for the privsep **frontend authority-inversion** composition (Phase-3 —
/// "the most-exposed holds the least"). Unlike the mechanism-proof `edge` demo (which piles every
/// listener + both exec + both control onto one instance), the `frontend` here holds ONLY the
/// most-exposed parsers it must — `listen.public-tls` + `listen.http-parse` + `exec.wasmtime` — with
/// NO keys, NO backend creds, NO control surface, NO `exec.compute`: a parser RCE on the inverted
/// frontend reaches none of those. It relays inward over the `local` splice to a `core` holding the
/// crown jewels + backends; the other listeners + `exec.compute` + control live on a separate `aux`.
///
/// This is the composition the whole program exists for, and it also exercises the Phase-3
/// operator-selectable SUBSTRATE field: `frontend` is pinned to `substrate: OsProcess` (the wired
/// default backend) explicitly, proving the new config vocabulary parses + stands up end-to-end.
///
/// Proves (against the live kernel, all four instances sandboxed `Enforced`): a client `GET /`
/// flows client → frontend listener fd → SCM_RIGHTS splice → core → hand-rolled HTTP → a real 200.
///
/// `#[ignore]`d like the gates above (forks + sandboxes against the live kernel); the CI
/// `live gate (privsep)` job runs it via `--include-ignored` and greps the
/// `PRIVSEP FRONTEND INVERSION LIVE OK` marker + the pass count.
#[test]
#[ignore = "live: forks boatramp __root for the frontend-inversion composition (frontend holds only \
            public-tls + http-parse + exec.wasmtime, substrate OsProcess; relays inward to a crown+backend \
            core) + serves end-to-end (Linux + `sandbox`); run via --include-ignored in the \
            `live gate (privsep)` job"]
fn privsep_frontend_inversion_serves_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("boatramp-privsep-frontend-{}", std::process::id()));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // The frontend-inversion composition (union == ALL; no crown co-resident with a listener/exec/
    // control surface; grants disjoint; no F8 warning):
    //   - `frontend` = ONLY listen.public-tls + listen.http-parse + exec.wasmtime (no keys, no
    //                  backends, no control, no exec.compute) — the INVERTED frontend. Pinned to the
    //                  OsProcess substrate explicitly. Binds serve.addr, splices client fds to core.
    //   - `aux`      = the OTHER listeners + acme.dns-control (C∖{public-tls,http-parse} ∪ acme) —
    //                  no keys, no backends. Parks (Phase 1 binds only the public listener).
    //   - `ops`      = exec.compute + control.admin-api (off every public listener, WS-D Finding-2
    //                  widened) — no keys, no backends, no listeners. Parks; closes the union.
    //   - `core`     = every crown jewel + every backend (A ∪ B) — the serving BACKEND.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "frontend": (
                capabilities: ["listen.public-tls", "listen.http-parse", "exec.wasmtime"],
                sandbox: Derived,
                substrate: OsProcess,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay", "listen.s3ingress",
                    "listen.inbound-tcp", "listen.gateway",
                    "acme.dns-control",
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
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "frontend", to: "core", transport: Local, purpose: Relay) }},
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(20);
    let response = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the frontend-inversion node did not serve a response within 20s");
        }
        if let Ok(Some(status)) = root.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the frontend-inversion composition \
                 failed to stand up (sandbox not Enforced? link/listener wiring? substrate?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        response.contains("200"),
        "expected a 200 from the core backend over the inverted-frontend splice, got:\n{response}"
    );
    assert!(
        response.contains("boatramp privsep backend"),
        "expected the backend body marker (the SCM_RIGHTS splice reached the sandboxed core), got:\n{response}"
    );

    // The marker the CI gate greps — only reached after a real 200 came back over the full inverted path.
    println!("PRIVSEP FRONTEND INVERSION LIVE OK");
}

/// Live end-to-end gate for the privsep **per-tenant wasm instantiation** (Phase-4 WS-C + WS-D): a
/// `[privsep]` composition with a `lifecycle: PerTenantTemplate` instance actually SERVES — one
/// isolated `{exec.wasmtime}` OS process per project (tenant), instantiated on demand by the
/// non-public per-tenant SUPERVISOR and wired to it over a lazily-created `socketpair`.
///
/// Composition (WS-D Finding-2 split): `parser` (listen.public-tls + listen.http-parse ONLY — the
/// public parse surface, NO spawn/KV) forwards client fds + the peeked Host inward; `supervisor`
/// (backend.kv + exec.compute — non-public, binds no listener, the sole KV opener) re-resolves
/// Host→project + instantiates + relays per tenant; `tenant-wasm` (the per-tenant template, NOT
/// boot-forked); `core` (crown jewels + the other backends); `aux` (the other listeners + control).
/// The test PRE-SEEDS the control-plane KV with TWO `domain/<host>` → `(project, site)` mappings,
/// then CLOSES it before the node opens it as the sole writer.
///
/// Drives TWO hosts (`tenant-a.test` → project `acme`, `tenant-b.test` → project `globex`): the
/// parser peeks each Host (Stage-0, MSG_PEEK — consuming nothing) and forwards the client fd inward;
/// the supervisor re-resolves the Host, instantiates that tenant's `exec.wasmtime` instance (lazy
/// socketpair + fork via the root's OWN primitive, scope wired via `BOATRAMP_PRIVSEP_TENANT_SCOPE`,
/// NO secret inherited), and relays the client fd. Each per-tenant
/// backend establishes its UNFORGEABLE wired identity (fail-closed) and serves a body keyed by its
/// scope — so the TWO hosts return TWO DISTINCT bodies (`project=acme` vs `project=globex`), proving
/// two distinct per-tenant instances. Greps the `PRIVSEP PER-TENANT OK` marker.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]`: it forks the real binary +
/// installs per-instance sandboxes against the live kernel, so it compiles + runs ONLY on Linux with
/// the `sandbox` feature. The CI `live gate (privsep)` job runs it via `--include-ignored` and greps
/// the marker + the pass count.
///
/// NOTE (WS-D): the non-public SUPERVISOR (`exec.compute`) forks the per-tenant children, so its
/// derived seccomp/Landlock profile permits `fork`/`execve` of its OWN binary (execute-pinned,
/// never the writable `kv-slate` — `sandbox::derive_seccomp_allowlist` + the Landlock execute-pin
/// grant `exec.compute` holders this; the public `parser` holds no `exec.compute`, so its `execve`
/// stays seccomp-killed — the Finding-2 wall). The SUPERVISOR holds `backend.kv` (its `kv-slate`
/// grant), NOT the parser.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a per-tenant template composition; the parser peeks two \
            Hosts + forwards inward, the supervisor instantiates two per-tenant exec.wasmtime \
            instances (lazy socketpair + root fork+exec, scope-wired) + serves two distinct scoped \
            bodies (Linux + `sandbox`); run via --include-ignored in the `live gate (privsep)` job"]
fn privsep_per_tenant_serves_end_to_end() {
    use boatramp_core::kv::KvOpenPolicy;
    use boatramp_core::project::DomainOwner;
    use boatramp_node::backends::{KvBackend, build_kv};

    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-per-tenant-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // PRE-SEED the control-plane KV with two host→(project, site) domain mappings, exactly as the
    // running supervisor will read them (`domain/<canon-host>` → DomainOwner JSON), then CLOSE it so
    // the node opens the SAME SlateDB store as its sole writer (no concurrent open — the supervisor
    // is the only `backend.kv` holder). Done in a dedicated current-thread runtime, mirroring the
    // unseal gate's pre-seal.
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime to seed the control-plane KV");
        rt.block_on(async {
            let kv = build_kv(
                KvBackend::Slatedb,
                &data_dir,
                None,
                KvOpenPolicy::SelfHeal,
                None,
            )
            .await
            .expect("open the control-plane KV to seed domains");
            kv.put(
                "domain/tenant-a.test",
                DomainOwner::new("acme", "shop").to_bytes(),
            )
            .await
            .expect("seed tenant-a → acme");
            kv.put(
                "domain/tenant-b.test",
                DomainOwner::new("globex", "shop").to_bytes(),
            )
            .await
            .expect("seed tenant-b → globex");
            // Flush + close so the store's lock is released before the node opens it.
            kv.close().await.expect("close the seeded control-plane KV");
        });
    }

    // The per-tenant composition (union == ALL; no crown co-resident with a listener/exec/control;
    // exec.wasmtime lives ONLY on the per-tenant template), with the public parser DE-COUPLED from
    // spawn + KV (WS-D Finding-2):
    //   - `parser`     = listen.public-tls + listen.http-parse ONLY — the public parse surface, holds
    //                    NO backend.kv / exec.compute; it peeks Host + forwards client fds inward;
    //   - `supervisor` = backend.kv + exec.compute + control.admin-api (non-public, binds no
    //                    listener) — RE-resolves Host→project (sole KV opener), instantiates + relays
    //                    per tenant, and holds the control-plane mutation surface off every public
    //                    listener (WS-D Finding-2 widened);
    //   - `tenant-wasm` = ONLY exec.wasmtime, `lifecycle: PerTenantTemplate` — NOT boot-forked;
    //   - `core`        = every crown jewel + the other backends (A ∪ B∖{kv});
    //   - `aux`         = the other listeners + acme (closes the union).
    //   - `parser-sup`  = the parser→supervisor Relay link (client fds + peeked Host ride inward);
    //   - `to-tenant`   = the supervisor↔template Relay link (socketpaired per tenant at instantiation).
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "parser": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["parser-sup"],
            ),
            "supervisor": (
                capabilities: ["backend.kv", "exec.compute", "control.admin-api"],
                sandbox: Derived,
                links: ["parser-sup", "to-tenant"],
            ),
            "tenant-wasm": (
                capabilities: ["exec.wasmtime"],
                lifecycle: PerTenantTemplate,
                sandbox: Derived,
                links: ["to-tenant"],
            ),
            "core": (
                capabilities: [
                    "secrets.sealer", "token.signer", "image.signer", "overlay.dial-signer",
                    "s3ingress.root", "cluster.join-signer",
                    "backend.sql", "backend.blob", "backend.messaging",
                ],
                sandbox: Derived,
                links: [],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay", "listen.s3ingress",
                    "listen.inbound-tcp", "listen.gateway",
                    "acme.dns-control",
                ],
                sandbox: Derived,
                links: [],
            ),
        }},
        links: {{
            "parser-sup": (from: "parser", to: "supervisor", transport: Local, purpose: Relay),
            "to-tenant": (from: "supervisor", to: "tenant-wasm", transport: Local, purpose: Relay),
        }},
        per_tenant: ( idle_eviction_secs: 300, max_instances: 64 ),
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    // Drive the TWO hosts; each must return a body naming ITS OWN project (two distinct instances).
    let want = [
        ("tenant-a.test", "project=acme"),
        ("tenant-b.test", "project=globex"),
    ];
    let mut got: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
    loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the per-tenant node did not serve both tenants within 25s; got: {got:?}");
        }
        if let Ok(Some(status)) = root.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the per-tenant composition failed to \
                 stand up (sandbox not Enforced? the supervisor could not open the KV or fork a \
                 per-tenant instance? the parser↔supervisor / supervisor↔template link wiring?)"
            );
        }
        for (host, marker) in want {
            if got.contains_key(host) {
                continue;
            }
            if let Ok(resp) = try_http_get_host(&addr, host)
                && resp.contains("200")
                && resp.contains(marker)
            {
                got.insert(host, resp);
            }
        }
        if got.len() == want.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    // Two DISTINCT per-tenant bodies ⇒ two DISTINCT per-tenant instances, each scoped by its own
    // unforgeable wired identity (artifact #2). Spoof-proof: the project came from the routed Host,
    // never a guest field.
    let a = &got["tenant-a.test"];
    let b = &got["tenant-b.test"];
    assert!(
        a.contains("project=acme") && b.contains("project=globex"),
        "each Host must route to its OWN tenant's scoped instance; a={a}\nb={b}"
    );
    assert!(
        a.contains("boatramp privsep per-tenant backend")
            && b.contains("boatramp privsep per-tenant backend"),
        "both responses must come from the per-tenant backend handler"
    );

    // The marker the CI gate greps — only reached after BOTH tenants served a distinct scoped body,
    // which under fail-closed semantics requires two per-tenant instances to have established their
    // wired identities and served scope-keyed.
    println!("PRIVSEP PER-TENANT OK");
}

/// Live gate for the Phase-3 **`substrate: container`** spawn backend — now WIRED on the SIMPLE model
/// (design-note Option C, owner-approved; see `crates/boatramp/DESIGN-privsep-phase3-container.md`).
/// Forks `boatramp __root` against the known-valid frontend-inversion topology (union == `all`, grants
/// disjoint, no crown co-resident with a listener/exec/control surface) whose serving `core` is pinned
/// `substrate: container`. The root does the SAME fork+exec the OsProcess path does, with the `core`
/// child additionally `unshare`ing the mount/ipc/uts/cgroup namespaces in its `pre_exec` (no
/// `pivot_root`, no new net namespace — the per-capability Landlock profile stays the FS wall).
///
/// Proves end-to-end, against the live kernel: a client `GET /` flows client → `frontend` listener fd
/// → SCM_RIGHTS splice → the NAMESPACE/CGROUP-CONFINED `core` → hand-rolled HTTP → a real 200. Under
/// `FailNodeClosed` + the confined instance's OWN fail-closed self-check
/// (`verify_container_namespaces_unshared` — the container instance refuses to serve unless it
/// confirms it entered fresh mount/ipc/uts/cgroup namespaces distinct from the root supervisor's), a
/// 200 coming back PROVES: `core` forked+exec'd the own binary INTO the unshared namespaces, installed
/// its nested per-capability sandbox `Enforced`, and served its slice — a sibling reached it over the
/// cross-namespace socketpair (which works because an `AF_UNIX` socketpair end is a plain open fd on
/// the one shared kernel — design §2a). Exactly the shape of the signer-unseal gate: the 200 is the
/// proof because a failure at any step would have torn the node down.
///
/// **Root required.** The simple model unshares WITHOUT a user namespace, so the root supervisor needs
/// `CAP_SYS_ADMIN` (the normal privsep posture — it binds privileged listeners). This gate runs the
/// NODE under `sudo -n` when the harness itself is unprivileged (CI `runner`, lighthouse `jwk` — both
/// have passwordless sudo), keeping the test harness unprivileged; it talks to the node only over
/// loopback HTTP. If the root cannot unshare (no `CAP_SYS_ADMIN`, or a kernel without namespaces) the
/// spawn fails and the node fail-closes — never a silent downgrade to an unconfined OS process.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]` like the other live gates.
/// The CI `live gate (privsep)` job runs it via `--include-ignored` and greps the
/// `PRIVSEP CONTAINER SUBSTRATE OK` marker + the pass count, so a silent skip / compile-out — or a
/// regression that drops the namespace wall — fails the merge.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root (as root, via sudo -n, for CAP_SYS_ADMIN) for a composition \
            whose serving core is pinned `substrate: container`; the core unshares NS/IPC/UTS/\
            CGROUP, self-confirms the namespaces, installs its Enforced sandbox, and serves end-to-end \
            over the cross-namespace splice (Linux + `sandbox`); run via --include-ignored in the \
            `live gate (privsep)` job"]
fn privsep_container_substrate_serves_end_to_end() {
    let src_bin = env!("CARGO_BIN_EXE_boatramp");
    let as_root = process_is_root();

    // The node + EVERY instance now runs with ZERO capabilities (Finding 2), and the container
    // substrate requires the node to be root. A capless root process is subject to normal DAC and
    // holds no CAP_DAC_READ_SEARCH, so it cannot traverse an unprivileged user's `0700` home — which
    // is exactly where this harness's build tree (and `CARGO_TARGET_TMPDIR`) lives on a dev box. In
    // PRODUCTION a root node owns a world-traversable data dir (e.g. under `/var/lib`), so this is a
    // gate artifact. Mirror production: stage the node tree (config, data dir, and a hardlink of the
    // binary) under a world-traversable, root-owned base so the capless-root instances can reach it
    // WITHOUT crossing the owner's home. (NOT under /tmp|/var/tmp|$TMPDIR — `derive_profile` refuses a
    // data dir there.) The hardlink shares the built binary's inode (no multi-GB copy) and gives the
    // instances a reachable `current_exe()` for the Landlock execute-pin + any re-exec.
    let base = std::path::PathBuf::from(format!(
        "/var/lib/boatramp-privsep-container-{}",
        std::process::id()
    ));
    let node_bin = base.join("boatramp");
    let data_dir = base.join("data");
    let cfg_path = base.join("boatramp.cfg");
    let tmp = base.clone();
    stage_root_reachable_gate(src_bin, &base, &data_dir, &node_bin, as_root);
    let bin = node_bin.to_str().expect("node bin path is utf-8");
    let port = free_port();

    // The known-valid frontend-inversion topology (union == ALL; grants disjoint; no crown co-resident
    // with a listener/exec/control surface — so it clears every pre-supervise gate), with the one
    // change under test: the serving `core` is pinned to the now-WIRED `substrate: container`. `core`
    // holds the backends + crown jewels and serves the 200; `frontend` (OsProcess) binds the listener
    // and splices the accepted client fd to `core` over the `local` socketpair that crosses `core`'s
    // namespace boundary.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "frontend": (
                capabilities: ["listen.public-tls", "listen.http-parse", "exec.wasmtime"],
                sandbox: Derived,
                substrate: OsProcess,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay", "listen.s3ingress",
                    "listen.inbound-tcp", "listen.gateway",
                    "acme.dns-control",
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
                substrate: Container,
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "frontend", to: "core", transport: Local, purpose: Relay) }},
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the privsep config");

    // The container substrate unshares WITHOUT a user namespace ⇒ the node needs CAP_SYS_ADMIN. Run it
    // as root: directly if the harness is already root, else under passwordless `sudo -n` (keeping the
    // harness itself unprivileged). The node's unique config path is the teardown token.
    let mut cmd = if as_root {
        Command::new(bin)
    } else {
        // `sudo -n` (non-interactive, passwordless): fail rather than block if no sudo. We do NOT ask
        // sudo to preserve env (strict sudoers can refuse `--preserve-env`), so the node logs at its
        // default level — enough for a failure to surface on the inherited stderr; the gate asserts on
        // the HTTP 200, not on logs.
        let mut c = Command::new("sudo");
        c.arg("-n").arg(bin);
        c
    };
    let mut root = cmd
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root` (via sudo -n when unprivileged)");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    let response = loop {
        if Instant::now() > deadline {
            teardown_container_gate(&cfg_path, &mut root, &tmp, as_root);
            panic!(
                "the container-substrate node did not serve a response within 25s (unshare refused \
                 for lack of CAP_SYS_ADMIN? the namespace self-check fail-closed? sudo -n unavailable?)"
            );
        }
        // Fail-closed: if the node exited, the composition failed to stand up — most tellingly here,
        // the `unshare` failed (no CAP_SYS_ADMIN) or the container instance's namespace self-check
        // refused (FailNodeClosed). Don't keep polling a dead node.
        if let Ok(Some(status)) = root.try_wait() {
            teardown_container_gate(&cfg_path, &mut root, &tmp, as_root);
            panic!(
                "`boatramp __root` exited early ({status}) — the container-substrate composition \
                 failed to stand up (unshare refused for lack of CAP_SYS_ADMIN? namespace self-check \
                 fail-closed? sandbox not Enforced? link/listener wiring?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    // Finding 2 PROBE: while the node is still alive, read the container core's capability sets from
    // /proc to confirm the pre_exec capability drop took effect — a served instance must hold ZERO
    // capabilities (⇒ definitely no CAP_SYS_ADMIN), closing the retained-root metadata-tamper / kill
    // primitives. The core runs as root (the node is root), so the probe reads /proc as root.
    let core_caps = read_container_core_caps(&cfg_path, as_root);

    teardown_container_gate(&cfg_path, &mut root, &tmp, as_root);

    assert!(
        response.contains("200"),
        "expected a 200 from the namespace/cgroup-confined core over the splice, got:\n{response}"
    );
    assert!(
        response.contains("boatramp privsep backend"),
        "expected the backend body marker (proving the SCM_RIGHTS splice reached the CONFINED core, \
         which under its namespace self-check + FailNodeClosed means it served from inside the \
         unshared namespaces), got:\n{response}"
    );

    // Finding 2 assertion: the served container core holds ZERO capabilities (CapEff/CapPrm/CapBnd
    // all 0). Zero effective/permitted caps ⇒ no CAP_SYS_ADMIN and none of the retained-root
    // primitives; a clean bounding set means no execve can regain one.
    assert!(
        core_caps.contains("PID="),
        "could not locate the container `core` process to probe its capabilities (Finding 2); \
         got:\n{core_caps}"
    );
    for field in ["CapEff:", "CapPrm:", "CapBnd:"] {
        let val = core_caps
            .lines()
            .find(|l| l.starts_with(field))
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("<missing>");
        assert_eq!(
            val, "0000000000000000",
            "served container core must hold ZERO {field} capabilities (Finding 2 cap drop) — a \
             non-zero value means it retained uid-0 caps (metadata-tamper / kill primitives); \
             got:\n{core_caps}"
        );
    }

    // The marker the CI gate greps — reached only after a real 200 came back over the full path to a
    // container-substrate instance that self-confirmed its fresh namespaces (else FailNodeClosed)
    // AND was probed to hold zero capabilities.
    println!("PRIVSEP CONTAINER SUBSTRATE OK");
}

/// Read the container `core` instance's capability sets (CapEff/CapPrm/CapBnd) from `/proc`, for the
/// Finding-2 zero-caps probe. Finds the process whose cmdline is `... __instance core --config
/// <cfg_path>` (unique to this gate's node) and prints its `PID=` + `Cap*:` lines. The node runs as
/// root, so the scan runs as root (directly when the harness is root, else via `sudo -n`).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn read_container_core_caps(cfg_path: &std::path::Path, as_root: bool) -> String {
    let token = format!("__instance core --config {}", cfg_path.display());
    // Scan /proc, NUL-translate each cmdline, match our unique token, emit PID + Cap* lines.
    let script = format!(
        "for p in /proc/[0-9]*; do c=$(tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null); \
         case \"$c\" in *'{token}'*) echo \"PID=${{p##*/}}\"; \
         grep -E '^Cap(Inh|Prm|Eff|Bnd):' \"$p/status\" 2>/dev/null; break;; esac; done"
    );
    let mut cmd = if as_root {
        Command::new("sh")
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg("sh");
        c
    };
    cmd.arg("-c").arg(&script);
    match cmd.output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => format!("(capability probe failed to run: {e})"),
    }
}

/// Whether THIS test process is running with effective uid 0 (read from `/proc/self/status`, so no
/// `libc` dependency). Used by the container-substrate gate to decide whether the node must be
/// launched under `sudo -n` to obtain the `CAP_SYS_ADMIN` the simple-model `unshare` needs.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn process_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                // `Uid:` line is `Uid:\t<real>\t<effective>\t<saved>\t<fs>`; the effective uid is 2nd.
                .and_then(|l| l.split_whitespace().nth(2).map(|u| u == "0"))
        })
        .unwrap_or(false)
}

/// Stage the container-gate node tree under a world-traversable, root-owned base so the
/// capless-root instances (Finding 2 drops ALL caps) can reach the config/data/binary WITHOUT
/// crossing the owner's `0700` home (where `CARGO_TARGET_TMPDIR` lives). Creates `<base>` +
/// `<base>/data` mode 0777 (root-owned so the harness can still drop the config in and the
/// capless-root node can create its state), and HARDLINKS the built binary to `<node_bin>` (same
/// inode — no multi-GB copy; falls back to a copy across filesystems). Runs as root (directly when
/// the harness is already root, else via `sudo -n`). Panics with the command output on failure — the
/// gate cannot run without it. `/var/lib` is deliberately NOT under /tmp|/var/tmp|$TMPDIR (which
/// `derive_profile` refuses for a data dir) and its ancestors are world-traversable.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn stage_root_reachable_gate(
    src_bin: &str,
    base: &std::path::Path,
    data_dir: &std::path::Path,
    node_bin: &std::path::Path,
    as_root: bool,
) {
    let script = format!(
        "set -e; install -d -m 0777 '{base}' '{data}'; \
         (ln '{src}' '{node}' 2>/dev/null || cp '{src}' '{node}'); chmod 0755 '{node}'",
        base = base.display(),
        data = data_dir.display(),
        src = src_bin,
        node = node_bin.display(),
    );
    let mut cmd = if as_root {
        Command::new("sh")
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg("sh");
        c
    };
    let out = cmd
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run the container-gate staging command");
    assert!(
        out.status.success(),
        "failed to stage the root-reachable container-gate base {} (is passwordless sudo + /var/lib \
         available?):\nstdout: {}\nstderr: {}",
        base.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Tear down the container-substrate node tree (root supervisor + every `__instance`) and remove its
/// scratch dir. SIGKILL-ing the direct child would orphan a `sudo`-launched node (SIGKILL cannot be
/// forwarded), so FIRST `pkill -TERM` the whole tree by its unique config path (as root when the node
/// was sudo-launched, so it can signal the root-owned processes); the SIGTERM tears the node down
/// (FailNodeClosed), then reap the direct child and remove the (possibly root-owned) scratch dir.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn teardown_container_gate(
    cfg_path: &std::path::Path,
    child: &mut std::process::Child,
    tmp: &std::path::Path,
    as_root: bool,
) {
    let token = cfg_path.display().to_string();
    let mut pk = if as_root {
        Command::new("pkill")
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg("pkill");
        c
    };
    let _ = pk.arg("-TERM").arg("-f").arg(&token).status();
    // Give the SIGTERM a moment to tear the tree down (FailNodeClosed), then reap the direct child.
    std::thread::sleep(Duration::from_millis(200));
    let _ = child.kill();
    let _ = child.wait();
    if std::fs::remove_dir_all(tmp).is_err() && !as_root {
        let _ = Command::new("sudo")
            .arg("-n")
            .arg("rm")
            .arg("-rf")
            .arg(tmp)
            .status();
    }
}

/// One blocking HTTP/1.1 `GET /` to `addr` with an explicit `Host`, returning the raw response text
/// (the router routes on this Host).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn try_http_get_host(addr: &str, host: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// One blocking HTTP/1.1 `GET /` with `Connection: close`, returning the raw response text.
fn try_http_get(addr: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// One blocking HTTP/1.1 `PUT /` (a mutating method, empty body) with `Connection: close`, returning
/// the raw response text. Used by the P5-3 write-plane gate to drive a control-plane MUTATION request
/// through the node app router (which decomposes it into its authorize + write sub-ops).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn try_http_put(addr: &str, host: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(
        format!("PUT / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// One blocking HTTP/1.1 `PUT <path>` carrying the end-principal credential HEADERS the node's own
/// `/api/*` serve path requires (P5-3-serve): `authorization: Bearer <token>`, the per-call
/// `boatramp-privsep-nonce`, and the per-call `boatramp-privsep-pop`. A `None` for a header OMITS it
/// (the missing-PoP negative). `host` is the transport Host (what the PoP binds). Returns the raw
/// response text.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn try_http_put_authed(
    addr: &str,
    path: &str,
    host: &str,
    token: &str,
    nonce: u128,
    pop: Option<&str>,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let pop_line = match pop {
        Some(p) => format!("boatramp-privsep-pop: {p}\r\n"),
        None => String::new(),
    };
    stream.write_all(
        format!(
            "PUT {path} HTTP/1.1\r\nHost: {host}\r\nauthorization: Bearer {token}\r\n\
             boatramp-privsep-nonce: {nonce}\r\n{pop_line}Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// =============================================================================
// MED-1 LIVE GATE — the VM relay's EMPTY-NETWORK-NAMESPACE egress containment.
// =============================================================================
//
// The F1/F2 Security review found that F1 (the relay's Landlock `AccessNet` deny-all-TCP wall) governs
// only TCP: UDP egress (`socket(AF_INET, SOCK_DGRAM)` + `sendto`) stayed open, and the relay's seccomp
// legitimately KEEPS `socket`/`sendto` (name-only filtering). MED-1's fix runs the netless relay in a
// FRESH, EMPTY (loopback-only) network namespace, which has no route anywhere — closing UDP (and TCP,
// raw, abstract-UDS) egress — while the pathname AF_UNIX vsock UDS still dials and the inherited
// root-netns TCP listener still `accept`s (a socket keeps its creation netns).
//
// This gate PROVES all of that against the REAL kernel, using the SAME production primitives the relay
// uses (`sandbox::enter_empty_netns` + `sandbox::drop_all_capabilities` + `derive_relay_profile`), and
// MUTATION-verifies it: a grandchild WITH the netns must find UDP egress DENIED; a grandchild WITHOUT
// it must find the SAME UDP egress SUCCEEDS (so the netns is demonstrably the thing that contains it).
//
// `unshare(CLONE_NEWNET)` needs CAP_SYS_ADMIN, which the relay inherits from the privileged root but a
// unit-test harness lacks. So, exactly like `privsep_container_substrate_serves_end_to_end`, the gate
// gains root via passwordless `sudo -n`: when it is NOT already root it re-execs THIS test under
// `sudo -n` and asserts on the marker the root run prints; when it IS root (the re-exec, or a harness
// already run under sudo on lighthouse) it runs the fork-probe inline. The CI `live gate (privsep)`
// job greps the `PRIVSEP VM RELAY NETNS OK` marker on the outer log.

/// The success marker the CI gate greps (printed on the OUTER process's stdout).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
const NETNS_MARKER: &str = "PRIVSEP VM RELAY NETNS OK";

/// Grandchild probe verdicts (reported via `_exit` code, like `sandbox_live.rs`'s probes).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
mod netns_probe_codes {
    pub const CONTAINED: i32 = 70; // netns ON: UDP egress DENIED, accept+AF_UNIX OK, TCP F1-denied
    pub const UDP_ESCAPED: i32 = 71; // UDP egress SUCCEEDED (the mutation signal / a containment hole)
    pub const UNIX_BLOCKED: i32 = 72; // AF_UNIX dial blocked — the vsock-dial shape would break
    pub const ACCEPT_BLOCKED: i32 = 73; // accept() on the inherited root-netns listener failed
    pub const TCP_ESCAPED: i32 = 74; // TCP egress SUCCEEDED (an F1 hole)
    pub const SETUP_FAILED: i32 = 75; // socket/plumbing failure (not a verdict)
    pub const INSTALL_FAILED: i32 = 76; // the relay profile did not install Enforced
    pub const UNSHARE_FAILED: i32 = 77; // unshare(CLONE_NEWNET) failed (no CAP_SYS_ADMIN?)
    pub const CAPDROP_FAILED: i32 = 78; // drop_all_capabilities failed (load-bearing SECBIT)
}

/// Fork ONE grandchild that stands in for the contained relay: optionally enter the empty netns, drop
/// ALL capabilities, install the relay's Enforced profile, then exercise the relay's four network
/// shapes against the real kernel and `_exit` a [`netns_probe_codes`] verdict. Returns the exit code.
/// The profile is derived in the PARENT (minimising post-fork allocation, as `probe_relay_net` does).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn fork_netns_grandchild(
    netns: bool,
    listener_fd: i32,
    uds_c: &std::ffi::CStr,
    exe: &std::path::Path,
    tcp_port: u16,
) -> i32 {
    use netns_probe_codes as code;

    let uds = std::path::PathBuf::from(uds_c.to_str().expect("utf-8 uds path"));
    let profile = boatramp_server::sandbox::derive_relay_profile(exe, &uds);

    // SAFETY: a single selected test ⇒ no concurrent harness thread allocating at the fork instant
    // (the malloc-after-fork hazard) — the SAME assumption `sandbox_live.rs`'s fork-probes rely on.
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "fork() failed: {}",
        std::io::Error::last_os_error()
    );
    if pid == 0 {
        // ---- the grandchild: set up the relay's containment, then probe egress ----
        // (1) MED-1: enter the empty netns (the production primitive) when this is the ON arm.
        if netns && boatramp_server::sandbox::enter_empty_netns().is_err() {
            unsafe { libc::_exit(code::UNSHARE_FAILED) };
        }
        // (2) INFO: drop ALL capabilities (incl CAP_NET_RAW) — the production primitives, both arms:
        //     the prctl bounding/securebits drop THEN the in-process capset effective-cap clear (the
        //     relay never execs, so the effective set must be cleared here, exactly as the relay does).
        if boatramp_server::sandbox::drop_all_capabilities().is_err()
            || boatramp_server::sandbox::clear_current_capabilities().is_err()
        {
            unsafe { libc::_exit(code::CAPDROP_FAILED) };
        }
        // (3) F1 + the rest: install the relay's Enforced profile (both arms — so the ONLY difference
        //     between ON and OFF is the netns, isolating it as the UDP-egress container).
        match boatramp_server::sandbox::linux::install_derived(&profile) {
            Ok(boatramp_server::sandbox::SandboxStatus::Enforced) => {}
            _ => unsafe { libc::_exit(code::INSTALL_FAILED) },
        }

        // (a) accept() the connection the parent queued on the INHERITED (root-netns) listener fd —
        //     proves a socket keeps its creation netns (the inherited-listener-accept correctness point).
        let afd = unsafe { libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if afd < 0 {
            unsafe { libc::_exit(code::ACCEPT_BLOCKED) };
        }
        unsafe { libc::close(afd) };

        // (b) AF_UNIX connect() to the pathname vsock-UDS shape — must work from inside the netns.
        let ufd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if ufd < 0 {
            unsafe { libc::_exit(code::SETUP_FAILED) };
        }
        // SAFETY: a zeroed sockaddr_un filled with the NUL-terminated pathname.
        let mut uaddr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        uaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = uds_c.to_bytes_with_nul();
        if bytes.len() > uaddr.sun_path.len() {
            unsafe { libc::_exit(code::SETUP_FAILED) };
        }
        for (dst, &b) in uaddr.sun_path.iter_mut().zip(bytes.iter()) {
            *dst = b as libc::c_char;
        }
        let urc = unsafe {
            libc::connect(
                ufd,
                &uaddr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        unsafe { libc::close(ufd) };
        if urc != 0 {
            unsafe { libc::_exit(code::UNIX_BLOCKED) };
        }

        // (c) UDP egress to loopback (the MED-1 pivot): ON ⇒ the empty netns has no route, so sendto
        //     must FAIL (ENETUNREACH); OFF ⇒ the SAME sendto reaches loopback and SUCCEEDS.
        let udp_egressed = {
            let dfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if dfd < 0 {
                unsafe { libc::_exit(code::SETUP_FAILED) };
            }
            // SAFETY: a zeroed sockaddr_in for 127.0.0.1:9 (the discard port) in network byte order.
            let mut daddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            daddr.sin_family = libc::AF_INET as libc::sa_family_t;
            daddr.sin_port = 9u16.to_be();
            daddr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let payload = b"x";
            let n = unsafe {
                libc::sendto(
                    dfd,
                    payload.as_ptr() as *const libc::c_void,
                    payload.len(),
                    0,
                    &daddr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            unsafe { libc::close(dfd) };
            n >= 0
        };

        // (d) TCP egress to the live loopback listener — F1 (Landlock AccessNet) must DENY it in BOTH
        //     arms (the profile is installed in both), so a SUCCESS here is an F1 hole.
        let tcp_egressed = {
            let tfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if tfd < 0 {
                unsafe { libc::_exit(code::SETUP_FAILED) };
            }
            // SAFETY: a zeroed sockaddr_in for 127.0.0.1:tcp_port in network byte order.
            let mut taddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            taddr.sin_family = libc::AF_INET as libc::sa_family_t;
            taddr.sin_port = tcp_port.to_be();
            taddr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let rc = unsafe {
                libc::connect(
                    tfd,
                    &taddr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            unsafe { libc::close(tfd) };
            rc == 0
        };

        if tcp_egressed {
            unsafe { libc::_exit(code::TCP_ESCAPED) };
        }
        if udp_egressed {
            unsafe { libc::_exit(code::UDP_ESCAPED) };
        }
        unsafe { libc::_exit(code::CONTAINED) };
    }
    // ---- the parent: reap the grandchild + decode its exit code ----
    let mut status: libc::c_int = 0;
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

/// Run the MED-1 fork-probe (we already hold CAP_SYS_ADMIN here) and print the marker on success.
/// Mutation-verified: the netns-ON arm must be CONTAINED (UDP denied) and the netns-OFF arm must be
/// UDP_ESCAPED (UDP succeeds) — so the netns is demonstrably the thing containing UDP egress.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn run_relay_netns_probe_and_report() {
    use netns_probe_codes as code;
    use std::os::fd::AsRawFd;

    // The relay's REAL sequence is netns → drop ALL caps → install_derived, so the profile's Landlock
    // PathFd grants are opened by a CAPLESS uid-0 process. In production the binary + the vsock-UDS
    // runtime dir live under world-traversable roots (/usr, /nix/store, the runtime temp dir), so a
    // capless root can O_PATH-open them. This harness, though, lives under a `0700` home that a capless
    // root (no CAP_DAC_READ_SEARCH) cannot traverse — the SAME constraint the container gate handles by
    // staging under world-traversable `/var/lib`. So we give the test's relay profile world-traversable
    // `/tmp` FS grants (a stand-in exe + the real probe UDS); the probe never execs the exe, so any file
    // suffices. This keeps the faithful capdrop-BEFORE-install order while letting the capless grandchild
    // open its grants.
    let exe = std::path::PathBuf::from(format!("/tmp/br-relay-netns-exe-{}", std::process::id()));
    let _ = std::fs::write(&exe, b"stand-in exe for the relay execute-pin grant\n");
    // Root-netns setup, held for the whole probe: a live loopback TCP listener (the inherited-listener
    // shape) + a pathname AF_UNIX listener (the vsock-UDS dial shape).
    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind loopback TCP listener (root netns)");
    let tcp_port = tcp.local_addr().expect("listener addr").port();
    let uds_path =
        std::path::PathBuf::from(format!("/tmp/br-relay-netns-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&uds_path);
    let _uds =
        std::os::unix::net::UnixListener::bind(&uds_path).expect("bind AF_UNIX probe listener");
    let uds_c = std::ffi::CString::new(uds_path.to_str().expect("utf-8 uds path")).expect("no NUL");

    // ON arm: queue a connection for its accept(), then probe WITH the empty netns.
    let client_on = TcpStream::connect(("127.0.0.1", tcp_port)).expect("queue a conn (ON)");
    let code_on = fork_netns_grandchild(true, tcp.as_raw_fd(), &uds_c, &exe, tcp_port);
    drop(client_on);
    // OFF arm (mutation): queue another connection, probe WITHOUT the netns.
    let client_off = TcpStream::connect(("127.0.0.1", tcp_port)).expect("queue a conn (OFF)");
    let code_off = fork_netns_grandchild(false, tcp.as_raw_fd(), &uds_c, &exe, tcp_port);
    drop(client_off);

    let _ = std::fs::remove_file(&uds_path);
    let _ = std::fs::remove_file(&exe);

    assert_eq!(
        code_on,
        code::CONTAINED,
        "with the empty netns, the relay stand-in must find UDP egress DENIED (ENETUNREACH) while \
         accept()ing the inherited root-netns listener and dialing the AF_UNIX vsock-UDS shape, with \
         TCP still F1-denied; grandchild exit was {code_on} ({}=UDP escaped the netns, {}=AF_UNIX dial \
         blocked, {}=inherited-listener accept blocked, {}=TCP escaped F1, {}=setup, {}=profile not \
         Enforced, {}=unshare failed (CAP_SYS_ADMIN?), {}=capdrop failed)",
        code::UDP_ESCAPED,
        code::UNIX_BLOCKED,
        code::ACCEPT_BLOCKED,
        code::TCP_ESCAPED,
        code::SETUP_FAILED,
        code::INSTALL_FAILED,
        code::UNSHARE_FAILED,
        code::CAPDROP_FAILED,
    );
    assert_eq!(
        code_off,
        code::UDP_ESCAPED,
        "MUTATION: WITHOUT the empty-netns step, the SAME UDP sendto to loopback must SUCCEED \
         (F1/Landlock AccessNet governs only TCP, not UDP) — proving the netns is the thing that \
         contains UDP egress, not a broken harness; grandchild exit was {code_off} ({}=still contained \
         without the netns, so the mutation is NOT exercising the real difference)",
        code::CONTAINED,
    );
    println!(
        "{NETNS_MARKER}: the netless VM relay stand-in, inside a FRESH EMPTY (loopback-only) network \
         namespace with ALL capabilities dropped (incl CAP_NET_RAW) and its Enforced least-authority \
         profile installed, DENIED UDP egress to loopback (ENETUNREACH) and kept TCP F1-denied, while \
         still accept()ing the inherited root-netns listener fd and dialing the AF_UNIX vsock-UDS \
         shape; WITHOUT the netns step the SAME UDP egress SUCCEEDED (mutation-verified on the real \
         kernel)."
    );
}

/// MED-1 live gate: the VM relay's empty-network-namespace egress containment (UDP closed, TCP/F1
/// closed, raw/packet closed) while the inherited listener + the AF_UNIX vsock dial still work —
/// mutation-verified (remove the netns ⇒ UDP egress reopens). Self-elevates via `sudo -n` for the
/// CAP_SYS_ADMIN `unshare(CLONE_NEWNET)` needs (the SAME passwordless-sudo pattern the container gate
/// uses); on a box without passwordless sudo it SKIPS with a clear note rather than failing.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live/privileged: proves the VM relay's empty-netns UDP-egress containment against the \
            real kernel (MED-1), mutation-verified; self-elevates via `sudo -n` for CAP_SYS_ADMIN; run \
            via --include-ignored in the `live gate (privsep)` job"]
fn relay_empty_netns_contains_udp_egress() {
    // Already privileged (the sudo re-exec below, or a harness run under sudo on lighthouse): run it.
    if process_is_root() {
        run_relay_netns_probe_and_report();
        return;
    }
    // Unprivileged: re-exec THIS one test under passwordless `sudo -n` to gain CAP_SYS_ADMIN. We do
    // NOT pass env through sudo (strict sudoers scrub it) — the root re-exec detects its own euid.
    let exe = std::env::current_exe().expect("resolve the test binary path for the sudo re-exec");
    let out = match Command::new("sudo")
        .arg("-n")
        .arg(&exe)
        .arg("--ignored")
        .arg("--exact")
        .arg("relay_empty_netns_contains_udp_egress")
        .arg("--nocapture")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "PRIVSEP VM RELAY NETNS SKIPPED: could not invoke `sudo -n` to gain CAP_SYS_ADMIN for \
                 the empty-netns probe ({e}); on CI/lighthouse (passwordless sudo) this runs for real."
            );
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // No passwordless sudoers rule ⇒ a clear SKIP, not a failure (a dev box without it shouldn't red
    // the suite; CI runners + lighthouse DO have it and run the real probe).
    if !stdout.contains(NETNS_MARKER)
        && (stderr.contains("a password is required")
            || stderr.contains("a terminal is required")
            || stderr.contains("sudo: "))
    {
        eprintln!(
            "PRIVSEP VM RELAY NETNS SKIPPED: `sudo -n` could not elevate (no passwordless sudoers?). \
             stderr: {stderr}"
        );
        return;
    }
    assert!(
        stdout.contains(NETNS_MARKER),
        "the root (sudo -n) re-exec of the empty-netns probe did not report success.\nexit: {:?}\n\
         --- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}",
        out.status.code(),
    );
    // Surface the marker on THIS (outer) process's stdout so the CI gate greps it on the outer log.
    println!(
        "{NETNS_MARKER} (via sudo -n re-exec; see the child's probe detail above if captured)"
    );
}

// =============================================================================
// VM RELAY — PATHNAME-AF_UNIX egress containment (INFO-1), a FRESH-EMPTY-netns + MINIMAL mount-ns
// pivot_root. Scoped privsep VM substrate, S1 follow-up from the F1/F2 Security review (2026-11-18).
// =============================================================================
//
// The F1/F2 Security review left one open question: the empty netns (MED-1) closes all IP egress and
// every ABSTRACT-namespace AF_UNIX socket, but a **pathname** AF_UNIX socket is NOT netns-scoped, and
// Landlock's `AccessFs` does not mediate `connect(2)` to a UDS (the relay's dir-grant governs the
// install's O_PATH opens, not the kernel's `unix_find_other` path walk). So: does the relay's narrow
// Landlock FS view (own binary + the one vsock dir) ALSO block an out-of-view pathname-UDS `connect()`
// (e.g. to `/run/docker.sock`, a dbus/systemd/postgres socket) for a local pivot — or is that pivot
// OPEN?
//
// This gate SETTLES it empirically against the real kernel AND proves the fix, in ONE mutation-verified
// probe. BOTH arms hold the netns + the dropped caps + the Enforced relay profile CONSTANT; the ONLY
// difference is the minimal mount-ns (`sandbox::enter_minimal_mount_ns`):
//   • arm A (mount-ns ON  — the production relay's full containment): the out-of-view host UDS must be
//     UNREACHABLE (`connect` DENIED, ENOENT — the pivot_root minimal root holds no host UDS path),
//     while the IN-view vsock dial + the inherited-listener accept still work.
//   • arm B (mount-ns OFF — the MUTATION, = netns + caps + Landlock dir-view ALONE): the SAME out-of-
//     view `connect` must SUCCEED. This is the empirical answer to the open question — the pivot IS
//     open under the Landlock dir-view alone — AND it proves the mount-ns is the load-bearing wall that
//     closes it (not a broken harness).
//
// Reuses the SAME production primitives the relay uses (`enter_empty_netns` + `enter_minimal_mount_ns`
// + `drop_all_capabilities`/`clear_current_capabilities` + `derive_relay_profile`), so the gate and the
// production path can never drift. Self-elevates via passwordless `sudo -n` (the CAP_SYS_ADMIN the
// unshares need); the CI `live gate (privsep)` job greps the `PRIVSEP VM RELAY PATHUDS OK` marker.

/// The success marker the CI gate greps (printed on the OUTER process's stdout).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
const PATHUDS_MARKER: &str = "PRIVSEP VM RELAY PATHUDS OK";

/// Grandchild probe verdicts for the pathname-UDS gate (reported via `_exit`, like the netns gate).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
mod pathuds_probe_codes {
    pub const CONTAINED: i32 = 80; // out-of-view pathname-UDS connect DENIED (the mount-ns closed it)
    pub const ESCAPED: i32 = 81; // out-of-view connect SUCCEEDED (pivot open / the mutation signal)
    pub const UNIX_BLOCKED: i32 = 82; // the IN-view vsock dial failed (the mount-ns broke the legit dial)
    pub const ACCEPT_BLOCKED: i32 = 83; // accept() on the inherited root-netns listener failed
    pub const SETUP_FAILED: i32 = 84; // socket/plumbing failure (not a verdict)
    pub const INSTALL_FAILED: i32 = 85; // the relay profile did not install Enforced
    pub const UNSHARE_FAILED: i32 = 86; // enter_empty_netns failed (no CAP_SYS_ADMIN?)
    pub const MOUNTNS_FAILED: i32 = 87; // enter_minimal_mount_ns failed (the pivot_root wall)
    pub const CAPDROP_FAILED: i32 = 88; // drop/clear capabilities failed
}

/// `connect(2)` a pathname `AF_UNIX` socket; returns whether the connect SUCCEEDED. Shared by the
/// in-view vsock dial and the out-of-view pivot probe (no post-fork allocation — a stack `sockaddr_un`).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn try_connect_pathname_uds(path_c: &std::ffi::CStr) -> bool {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return false;
    }
    // SAFETY: a zeroed sockaddr_un filled with the NUL-terminated pathname (bounds-checked).
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path_c.to_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return false;
    }
    for (dst, &b) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = b as libc::c_char;
    }
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    rc == 0
}

/// Fork ONE grandchild standing in for the contained relay: enter the empty netns, OPTIONALLY enter the
/// minimal mount-ns (`mount_ns`), drop ALL caps, install the Enforced relay profile, then (a) dial the
/// IN-view vsock UDS, (b) accept() the inherited listener, (c) attempt the OUT-of-view pathname-UDS
/// `connect()` — `_exit`ing a [`pathuds_probe_codes`] verdict. The profile is derived in the PARENT.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn fork_pathuds_grandchild(
    mount_ns: bool,
    listener_fd: i32,
    uds: &std::path::Path,
    exe: &std::path::Path,
    out_of_view_c: &std::ffi::CStr,
) -> i32 {
    use pathuds_probe_codes as code;

    let profile = boatramp_server::sandbox::derive_relay_profile(exe, uds);
    let vsock_dir = uds
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| uds.to_path_buf());
    let uds_c = match std::ffi::CString::new(uds.to_str().expect("utf-8 uds path")) {
        Ok(c) => c,
        Err(_) => return code::SETUP_FAILED,
    };

    // SAFETY: a single selected test ⇒ no concurrent harness thread allocating at the fork instant (the
    // SAME assumption the netns gate + `sandbox_live.rs`'s fork-probes rely on).
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "fork() failed: {}",
        std::io::Error::last_os_error()
    );
    if pid == 0 {
        // (1) MED-1 egress wall — the empty netns (the production primitive), in BOTH arms.
        if boatramp_server::sandbox::enter_empty_netns().is_err() {
            unsafe { libc::_exit(code::UNSHARE_FAILED) };
        }
        // (2) INFO-1 — the minimal mount-ns pivot_root, ONLY in arm A (the sole difference between arms).
        if mount_ns && boatramp_server::sandbox::enter_minimal_mount_ns(exe, &vsock_dir).is_err() {
            unsafe { libc::_exit(code::MOUNTNS_FAILED) };
        }
        // (3) INFO — drop ALL capabilities (prctl bounding/securebits THEN the in-process capset clear).
        if boatramp_server::sandbox::drop_all_capabilities().is_err()
            || boatramp_server::sandbox::clear_current_capabilities().is_err()
        {
            unsafe { libc::_exit(code::CAPDROP_FAILED) };
        }
        // (4) Install the relay's Enforced profile (both arms — so the ONLY difference is the mount-ns).
        match boatramp_server::sandbox::linux::install_derived(&profile) {
            Ok(boatramp_server::sandbox::SandboxStatus::Enforced) => {}
            _ => unsafe { libc::_exit(code::INSTALL_FAILED) },
        }

        // (a) IN-view vsock dial — must still work in BOTH arms (arm A binds the vsock dir into the
        //     minimal root). A failure here means the mount-ns broke the legitimate guest dial.
        if !try_connect_pathname_uds(&uds_c) {
            unsafe { libc::_exit(code::UNIX_BLOCKED) };
        }
        // (b) inherited root-netns listener accept() — a socket keeps its creation netns + is fd-based,
        //     so it survives both the netns and the pivot_root.
        let afd = unsafe { libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if afd < 0 {
            unsafe { libc::_exit(code::ACCEPT_BLOCKED) };
        }
        unsafe { libc::close(afd) };

        // (c) THE PROBE: `connect()` an OUT-of-view host pathname-UDS. arm A (mount-ns) ⇒ the path does
        //     not resolve in the minimal root ⇒ DENIED (CONTAINED). arm B (no mount-ns) ⇒ it resolves on
        //     the host tree + is DAC-reachable (root owner) and Landlock does not mediate UDS connect ⇒
        //     SUCCEEDS (ESCAPED) — the empirical "pivot is open under the dir-view alone" signal.
        if try_connect_pathname_uds(out_of_view_c) {
            unsafe { libc::_exit(code::ESCAPED) };
        }
        unsafe { libc::_exit(code::CONTAINED) };
    }
    // ---- the parent: reap the grandchild + decode its exit code ----
    let mut status: libc::c_int = 0;
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

/// Run the INFO-1 fork-probe (we already hold CAP_SYS_ADMIN here) and print the marker on success.
/// Mutation-verified: arm A (mount-ns ON) must be CONTAINED (out-of-view UDS connect DENIED) and arm B
/// (mount-ns OFF) must be ESCAPED (the SAME connect SUCCEEDS) — settling that the pathname-UDS pivot is
/// open under the Landlock dir-view alone, and that the minimal mount-ns is the wall that closes it.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn run_relay_pathuds_probe_and_report() {
    use pathuds_probe_codes as code;
    use std::os::fd::AsRawFd;

    // Stage under root-owned `/run` (a 0755 tmpfs): the capless uid-0 grandchild traverses it as OWNER
    // (no CAP_DAC_READ_SEARCH needed), so the relay profile's PathFd grants (the stand-in exe + the
    // vsock dir) O_PATH-open, mirroring production (`/run/boatramp-vm`, root-owned 0700). A dedicated
    // per-run gate dir holds the exe + the IN-view vsock dir; the OUT-of-view pivot UDS sits directly
    // under `/run` (the realistic `/run/docker.sock`-style host-daemon socket location).
    let gate_dir = std::path::PathBuf::from(format!("/run/br-pathuds-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&gate_dir);
    std::fs::create_dir_all(&gate_dir).expect("create the pathuds gate dir under /run");
    let exe = gate_dir.join("exe");
    std::fs::write(&exe, b"stand-in exe for the relay execute-pin grant\n")
        .expect("write stand-in exe");
    let vsock_dir = gate_dir.join("vsk");
    std::fs::create_dir_all(&vsock_dir).expect("create the in-view vsock dir");
    let uds_path = vsock_dir.join("vsock.sock");
    let _ = std::fs::remove_file(&uds_path);

    // Root-netns setup, held for the whole probe: a live loopback TCP listener (the inherited-listener
    // shape), the IN-view AF_UNIX vsock listener, and the OUT-of-view pivot AF_UNIX listener.
    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind loopback TCP listener (root netns)");
    let tcp_port = tcp.local_addr().expect("listener addr").port();
    let _in_view =
        std::os::unix::net::UnixListener::bind(&uds_path).expect("bind in-view vsock listener");

    let out_of_view =
        std::path::PathBuf::from(format!("/run/br-pathuds-pivot-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&out_of_view);
    let _pivot = std::os::unix::net::UnixListener::bind(&out_of_view)
        .expect("bind the out-of-view pivot UDS (a /run host-socket stand-in)");
    let out_of_view_c =
        std::ffi::CString::new(out_of_view.to_str().expect("utf-8 pivot path")).expect("no NUL");

    // arm A (mount-ns ON): queue a connection for the inherited accept(), then probe WITH the mount-ns.
    let client_on = TcpStream::connect(("127.0.0.1", tcp_port)).expect("queue a conn (arm A)");
    let code_on = fork_pathuds_grandchild(true, tcp.as_raw_fd(), &uds_path, &exe, &out_of_view_c);
    drop(client_on);
    // arm B (mount-ns OFF — the MUTATION): queue another connection, probe WITHOUT the mount-ns.
    let client_off = TcpStream::connect(("127.0.0.1", tcp_port)).expect("queue a conn (arm B)");
    let code_off = fork_pathuds_grandchild(false, tcp.as_raw_fd(), &uds_path, &exe, &out_of_view_c);
    drop(client_off);

    let _ = std::fs::remove_dir_all(&gate_dir);
    let _ = std::fs::remove_file(&out_of_view);

    assert_eq!(
        code_on,
        code::CONTAINED,
        "with the minimal mount-ns, the relay stand-in must find the OUT-of-view host pathname-UDS \
         connect DENIED (the pivot_root minimal root holds no host UDS path) while still dialing the \
         IN-view vsock UDS + accept()ing the inherited listener; grandchild exit was {code_on} \
         ({}=pivot ESCAPED the mount-ns, {}=in-view vsock dial blocked, {}=inherited accept blocked, \
         {}=setup, {}=profile not Enforced, {}=netns unshare failed, {}=mount-ns pivot_root failed, \
         {}=capdrop failed)",
        code::ESCAPED,
        code::UNIX_BLOCKED,
        code::ACCEPT_BLOCKED,
        code::SETUP_FAILED,
        code::INSTALL_FAILED,
        code::UNSHARE_FAILED,
        code::MOUNTNS_FAILED,
        code::CAPDROP_FAILED,
    );
    assert_eq!(
        code_off,
        code::ESCAPED,
        "MUTATION / empirical settlement: WITHOUT the minimal mount-ns step (netns + dropped caps + the \
         Enforced Landlock dir-view ALONE), the SAME out-of-view host pathname-UDS connect must SUCCEED \
         — proving (1) the pathname-UDS pivot IS open under the Landlock dir-view alone (AccessFs does \
         not mediate UDS connect, and pathname UDS are not netns-scoped) and (2) the mount-ns is the \
         thing that closes it, not a broken harness; grandchild exit was {code_off} ({}=still contained \
         without the mount-ns, so the mutation is NOT exercising the real difference)",
        code::CONTAINED,
    );
    println!(
        "{PATHUDS_MARKER}: the netless VM relay stand-in, inside the empty netns with ALL capabilities \
         dropped and its Enforced least-authority profile installed, had its OUT-of-view host pathname-\
         AF_UNIX `connect()` DENIED by the minimal mount-ns pivot_root root (which holds only the own \
         binary + the one vsock dir) while still dialing the IN-view vsock UDS + accept()ing the \
         inherited listener; WITHOUT the mount-ns the SAME connect SUCCEEDED (so the Landlock dir-view \
         alone does NOT close the pathname-UDS pivot — mutation-verified on the real kernel)."
    );
}

/// INFO-1 live gate: the VM relay's minimal mount-ns `pivot_root` closes the PATHNAME-AF_UNIX local-
/// pivot surface (connect to an out-of-view host UDS DENIED) that the empty netns + the Landlock dir-
/// view do NOT — mutation-verified (remove the mount-ns ⇒ the out-of-view connect reopens), which also
/// empirically SETTLES that the pivot is open under the dir-view alone. Self-elevates via `sudo -n` for
/// the CAP_SYS_ADMIN the unshares need; on a box without passwordless sudo it SKIPS with a clear note.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live/privileged: proves the VM relay's minimal mount-ns pathname-UDS-pivot containment \
            against the real kernel (INFO-1), mutation-verified; self-elevates via `sudo -n` for \
            CAP_SYS_ADMIN; run via --include-ignored in the `live gate (privsep)` job"]
fn relay_mount_ns_contains_pathname_uds_pivot() {
    // Already privileged (the sudo re-exec below, or a harness run under sudo on lighthouse): run it.
    if process_is_root() {
        run_relay_pathuds_probe_and_report();
        return;
    }
    // Unprivileged: re-exec THIS one test under passwordless `sudo -n` to gain CAP_SYS_ADMIN.
    let exe = std::env::current_exe().expect("resolve the test binary path for the sudo re-exec");
    let out = match Command::new("sudo")
        .arg("-n")
        .arg(&exe)
        .arg("--ignored")
        .arg("--exact")
        .arg("relay_mount_ns_contains_pathname_uds_pivot")
        .arg("--nocapture")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "PRIVSEP VM RELAY PATHUDS SKIPPED: could not invoke `sudo -n` to gain CAP_SYS_ADMIN for \
                 the mount-ns probe ({e}); on CI/lighthouse (passwordless sudo) this runs for real."
            );
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stdout.contains(PATHUDS_MARKER)
        && (stderr.contains("a password is required")
            || stderr.contains("a terminal is required")
            || stderr.contains("sudo: "))
    {
        eprintln!(
            "PRIVSEP VM RELAY PATHUDS SKIPPED: `sudo -n` could not elevate (no passwordless sudoers?). \
             stderr: {stderr}"
        );
        return;
    }
    assert!(
        stdout.contains(PATHUDS_MARKER),
        "the root (sudo -n) re-exec of the mount-ns pathname-UDS probe did not report success.\nexit: \
         {:?}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}",
        out.status.code(),
    );
    // Surface the marker on THIS (outer) process's stdout so the CI gate greps it on the outer log.
    println!(
        "{PATHUDS_MARKER} (via sudo -n re-exec; see the child's probe detail above if captured)"
    );
}

// =============================================================================
// PHASE-5 P5-2 — node SELF-HOSTING read plane: WIRED LIVE on the lightweight substrates,
//                VM data-holder still REFUSED.
// =============================================================================
//
// Phase-5 ("self-hosting") makes the node serve its OWN serve path UNDER the privsep composition, not
// only guest workloads. P5-2 — the READ-PLANE increment — wires the authority-scoped node app router
// LIVE on the backend serve path: under `node_serve = node-self-host` a `backend.*` data-holder
// instance on a LIGHTWEIGHT, shared-net substrate (`os-process` / `container`) serves the node's own
// READ data plane (classify → authority-scoped route → a real control-plane KV read), replacing the
// Phase-1 `MinimalHandler` stub. The VM data-holder stays REFUSED (design §3a): a `backend.*` on
// `substrate: vm` is refused fail-closed (the structural S2 scope lint `VmInstanceOutsideApprovedScope`
// at `plan_root`, plus the P5-2 defence-in-depth `NodeSelfHostVmDataHolder` gate).
//
// Two gates below, both `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]` and run
// by the CI `live gate (privsep)` job via `--include-ignored`:
//   (A) `privsep_node_self_host_vm_data_holder_refused_end_to_end` (marker
//       `PRIVSEP NODE SELF-HOST VM DATA-HOLDER REFUSED OK`): a node-self-host composition that puts a
//       `backend.*` data-holder on `vm` is REFUSED fail-closed before any spawn, never served.
//   (B) `privsep_node_self_host_read_plane_serves_end_to_end` (marker
//       `PRIVSEP NODE SELF-HOST READ-PLANE OK`): a node-self-host composition with the data-holder on
//       `os-process` serves a REAL read-plane response (the authority-scoped router ran live — the body
//       is the node read-plane result, NOT the `Phase 1 minimal serve` stub).
//   (C) `privsep_node_self_host_write_plane_serves_end_to_end` (marker
//       `PRIVSEP NODE SELF-HOST WRITE-PLANE OK`, P5-3): the node stands up + serves only after `core`'s
//       boot WRITE-plane self-validation mutated the control-plane store (durable put + checkpoint + GC
//       + read-back + delete) under Landlock with NO EACCES; then a client PUT fail-closes `503` via
//       the INFO-2 decomposition (the backend.kv write sub-op is held, the control.admin-api authorize
//       sub-op is unreachable → the WHOLE request fails closed).
//   (D) `privsep_node_self_host_control_mutation_serves_end_to_end` (marker
//       `PRIVSEP NODE SELF-HOST CONTROL-MUTATION OK`, P5-3-serve): a node-self-host composition whose
//       `core` holds BOTH control.admin-api AND backend.kv SERVES an AUTHORIZED client control-plane
//       mutation (a trust-root-signed cnf-bound `publisher@acme/blog` role token + a per-call PoP bound
//       to the mutation) — 200, with the deploy/routing write LANDING under core's backend.kv Landlock
//       profile (a read-plane `GET Host: served.example` then resolves) — while a FORGED principal
//       (token not trust-root-signed) and a MISSING-PoP mutation are BOTH refused fail-closed 503. The
//       client→control-plane-write authz chain (end-principal verification + PoP + default-deny RBAC),
//       the highest-stakes privsep delta — the positive AND the negative.
//
// LIVE-GATE PROVENANCE: these were authored + compile-checked (musl clippy, `-D warnings`) on the
// authoring host; the `backend.kv` control-plane store opening + reading (P5-2, gate B) AND mutating
// (P5-3, gate C) under the derived per-capability Landlock profile is the biggest self-host unknown
// (design §5) and MUST be validated on lighthouse (Linux + `sandbox`) before any cut — a write/
// compaction/GC `EPERM` would FailNodeClosed (gate C's "exited early" panic), which is exactly what the
// live gate exists to surface. Gate C was lighthouse-validated (kernel 6.12.67, Landlock active):
// `instance=core status=Enforced seccomp_allow=193 ro=12 rw=8`, then "control-plane write plane
// self-validated under the backend.kv Landlock/seccomp profile (durable put + checkpoint + GC +
// read-back + delete, no fail-closed EACCES)", then the marker — `test result: ok. 1 passed`.

/// The VM-data-holder refusal marker (mirrors `privsep::NODE_SELF_HOST_VM_DATA_HOLDER_MARKER`; a
/// literal here so a drift in the const is caught by the gate).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
const NODE_SELF_HOST_VM_DATA_HOLDER_MARKER: &str = "PRIVSEP_NODE_SELF_HOST_VM_DATA_HOLDER_REFUSED";

/// (A) Live fail-closed gate for the **P5-2 VM data-holder refusal**: a `node_serve: node-self-host`
/// composition that places a `backend.*` DATA-HOLDER on `substrate: vm` must be REFUSED by the root
/// fail-closed, before any instance is spawned and before anything serves (design §3a — the VM
/// data-holder's egress/secret-blindness problem is the owner-gated P5-5 question). Proves it
/// end-to-end: `boatramp __root` resolves the topology, runs its screens + lints, refuses (the
/// structural S2 scope lint `VmInstanceOutsideApprovedScope` fires at `plan_root` step 2b-vm, ahead of
/// the P5-2 defence-in-depth gate at 2d), and EXITS non-zero, never binding the listener.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]` like the other live gates;
/// the CI `live gate (privsep)` job greps `PRIVSEP NODE SELF-HOST VM DATA-HOLDER REFUSED OK`, so a
/// regression that let a VM data-holder stand up — or a silent skip / compile-out — fails the merge.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a node-self-host composition that puts a backend.* \
            data-holder on `substrate: vm`; the root must refuse fail-closed (the VM data-holder is \
            not a P5-2 shape) and exit non-zero, never serving; run via --include-ignored in the \
            `live gate (privsep)` job"]
fn privsep_node_self_host_vm_data_holder_refused_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-selfhost-vm-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // A valid union==ALL composition (no forbidden co-residency), node-self-host, with the `backend.*`
    // authorities split onto their OWN `data` instance pinned to `substrate: vm` — the ONE thing to
    // refuse. `core` holds the crown jewels only (a valid P1 bundle); `data` holds the backends and is
    // a key-free non-listener VM instance → outside the approved VM scope (refused fail-closed).
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-data"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
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
                ],
                sandbox: Derived,
                links: [],
            ),
            "data": (
                capabilities: [
                    "backend.kv", "backend.sql", "backend.blob", "backend.messaging",
                ],
                sandbox: Derived,
                substrate: Vm,
                links: ["to-data"],
            ),
        }},
        links: {{ "to-data": (from: "edge", to: "data", transport: Local) }},
        node_serve: NodeSelfHost,
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the vm-data-holder privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `boatramp __root`");

    // The root must REFUSE and exit promptly — it never binds the listener, so a GET never connects.
    // Poll for the exit; past the deadline (or on any served 200) fail LOUD.
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Ok(Some(status)) = root.try_wait() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` did not refuse a VM `backend.*` data-holder within 20s — the P5-2 \
                 / S2 VM scope gate regressed (the node must fail closed, not stand up a VM data-holder)"
            );
        }
        if try_http_get(&format!("127.0.0.1:{port}"))
            .map(|r| r.contains("200"))
            .unwrap_or(false)
        {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "a node-self-host composition with a VM `backend.*` data-holder served a 200 — the VM \
                 data-holder MUST be refused fail-closed, never served"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    let mut stderr = String::new();
    if let Some(mut e) = root.stderr.take() {
        let _ = e.read_to_string(&mut stderr);
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !status.success(),
        "the root must EXIT NON-ZERO refusing a VM data-holder (it must not stand the node up), \
         got a success exit.\n--- root stderr ---\n{stderr}"
    );
    // The refusal fires at the structural S2 scope lint (which names the offending VM instance) OR the
    // P5-2 defence-in-depth gate (which carries the marker); accept EITHER, since both are fail-closed
    // refusals of the SAME unsafe VM data-holder shape — what matters is no spawn, no serve.
    assert!(
        stderr.contains("data")
            && (stderr.contains("VM instance")
                || stderr.contains(NODE_SELF_HOST_VM_DATA_HOLDER_MARKER)),
        "the refusal must name the offending VM data-holder (`data`) via the S2 scope lint or the \
         P5-2 {NODE_SELF_HOST_VM_DATA_HOLDER_MARKER} marker, got exit {:?}:\n--- root stderr ---\n{stderr}",
        status.code(),
    );

    // The marker the CI gate greps — reached only after the root refused the VM data-holder fail-closed.
    println!("PRIVSEP NODE SELF-HOST VM DATA-HOLDER REFUSED OK");
}

/// (B) Live SERVE gate for the **P5-2 read plane** on the lightweight `os-process` substrate: a
/// `node_serve: node-self-host` composition whose serving `core` holds `backend.kv` + is on
/// `substrate: os-process` serves a REAL read-plane response. `boatramp __root` stands up the
/// composition (sandbox Enforced in every instance), the `edge` frontend splices the accepted client fd
/// to `core`, and `core`'s authority-scoped node app router CLASSIFIES the GET → `backend.kv` read
/// surface → `Local` → opens + reads the control-plane KV and answers from the READ PLANE (not the
/// Phase-1 stub). The node's KV is empty, so a GET resolves to a `404` from the read plane — which is a
/// REAL read (not a canned 200), proving the router + read serve ran live under the sandbox.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]`; the CI `live gate (privsep)`
/// job greps `PRIVSEP NODE SELF-HOST READ-PLANE OK`. NB the control-plane KV opening under the derived
/// Landlock profile is the biggest live-gated P5-2 unknown (design §5): an `EPERM` here FailNodeCloses
/// (the "exited early" panic below), which is exactly what this gate exists to surface.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a node-self-host composition with a backend.kv \
            data-holder on os-process; the backend's authority-scoped router serves a REAL read-plane \
            response (not the Phase-1 stub) over the splice; run via --include-ignored in the \
            `live gate (privsep)` job"]
fn privsep_node_self_host_read_plane_serves_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-selfhost-serve-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // The SAME known-valid 4-instance composition the 2-instance serve gate uses (edge/aux/ops/core:
    // union == ALL, no forbidden co-residency), with `node_serve: node-self-host` — so `core` (holding
    // backend.kv on the default os-process) serves the node's OWN read plane instead of the stub.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
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
                substrate: OsProcess,
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "edge", to: "core", transport: Local, purpose: Relay) }},
        node_serve: NodeSelfHost,
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the self-host serve privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    let response = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the node-self-host read-plane node did not serve a response within 25s");
        }
        // Fail-closed: if the root exited, the composition failed to stand up — most tellingly here, the
        // control-plane KV would not open under `core`'s Landlock grant (the live-gated P5-2 unknown).
        if let Ok(Some(status)) = root.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the node-self-host read-plane composition \
                 failed to stand up (the backend.kv control-plane KV would not open under the derived \
                 Landlock profile? sandbox not Enforced? link/listener wiring?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    // The authority-scoped node app router ran LIVE: the body is the node READ-PLANE result (a real KV
    // read), NOT the Phase-1 `MinimalHandler` stub. An empty node KV ⇒ a 404 from the read plane.
    assert!(
        response.contains("node-self-host read plane"),
        "expected the node read-plane body (the authority-scoped router served a real read), got:\n{response}"
    );
    assert!(
        !response.contains("Phase 1 minimal serve"),
        "the node-self-host backend must NOT serve the guest-workloads stub body (the router must run \
         live), got:\n{response}"
    );
    assert!(
        response.contains("404") || response.contains("200"),
        "expected a real read-plane status (404 for an empty KV, or 200 if seeded), got:\n{response}"
    );

    // The marker the CI gate greps — only reached after a real read-plane response came back over the
    // full composed, sandboxed path.
    println!("PRIVSEP NODE SELF-HOST READ-PLANE OK");
}

/// (C) Live gate for the **P5-3 control-plane WRITE plane** on the lightweight `os-process` substrate:
/// a `node_serve: node-self-host` composition whose serving `core` holds `backend.kv` STANDS UP AND
/// SERVES — which it can do only after `core`'s boot WRITE-PLANE self-validation
/// (`NodeDataPlane::validate_write_plane`) completed its REAL control-plane store MUTATION round-trip
/// (durable put ×2 + checkpoint + maintenance GC + read-back + durable delete) UNDER `core`'s per-
/// capability Landlock+seccomp profile. **This is the decisive P5-3 proof** the task demands: the
/// write/flush/compaction/GC/manifest object-store paths a READ never touches (P5-2's gate B) complete
/// with NO fail-closed EACCES under real Landlock (kernel 6.12 / ABI V5 on lighthouse). If the sandbox
/// denied a write, `build_self_host_backend_handler` returns `Err` → `core` exits → `FailNodeClosed`
/// tears `__root` down → the "exited early" panic below fires (exactly what this gate surfaces).
///
/// It ALSO proves the serve-seam INFO-2 decomposition: a client `PUT` (a mutation) decomposes into its
/// `{control.admin-api authorize, backend.kv write}` sub-ops; on `core` the `backend.kv` write sub-op
/// is HELD (`Local`) but the `control.admin-api` authorize sub-op is NEITHER held NOR reachable over
/// `core`'s single `to-core` link (it reaches only the key-free `edge` frontend) → the WHOLE request
/// fails closed `503` (never a partial serve of the held write half). The SERVED, authorized mutation
/// (end-principal re-validation + the control.admin-api→crown-jewel relay) is the remaining P5-3 work.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]`; the CI `live gate (privsep)`
/// job greps `PRIVSEP NODE SELF-HOST WRITE-PLANE OK`.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a node-self-host composition with a backend.kv \
            data-holder on os-process; the node stands up only after the boot write-plane self-\
            validation mutates the control-plane store under Landlock, then a client PUT fails closed \
            via the INFO-2 decomposition; run via --include-ignored in the `live gate (privsep)` job"]
fn privsep_node_self_host_write_plane_serves_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-selfhost-write-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // The SAME known-valid 4-instance composition the read-plane gate uses (edge/aux/ops/core: union ==
    // ALL, no forbidden co-residency), with `node_serve: node-self-host` — so `core` (holding backend.kv
    // on os-process) runs the boot WRITE-plane self-validation at stand-up and serves the node's own
    // data plane. (`control.admin-api` stays on `ops`, NOT co-located with `core`'s crown jewels — the
    // crown-jewel-exclusion lint forbids that co-residency — which is exactly why a PUT's authorize
    // sub-op is unreachable from `core` and the whole mutation fails closed.)
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
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
                substrate: OsProcess,
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "edge", to: "core", transport: Local, purpose: Relay) }},
        node_serve: NodeSelfHost,
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the self-host write privsep config");

    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    // Poll a GET until the node serves. The node serves ONLY after `core` built its self-host handler,
    // which runs the boot write-plane self-validation FIRST — so a served response PROVES the real
    // control-plane store MUTATION completed under `core`'s Landlock+seccomp profile with no EACCES.
    let read_resp = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the node-self-host write-plane node did not serve within 25s");
        }
        // Fail-closed: if the root exited, the composition failed to stand up — the load-bearing P5-3
        // case being that the control-plane store MUTATION self-validation hit a fail-closed EACCES
        // under `core`'s derived Landlock profile (a `backend.kv` rw-grant/path mismatch), so
        // `build_self_host_backend_handler` returned `Err` → `core` exited → FailNodeClosed.
        if let Ok(Some(status)) = root.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the node-self-host WRITE-plane composition \
                 failed to stand up (the backend.kv control-plane store MUTATION self-validation would \
                 not complete under the derived Landlock profile? a write/compaction/GC EACCES? sandbox \
                 not Enforced?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    // The node is up (the boot write-plane mutation passed under Landlock) and its read plane answers a
    // real read (an empty KV ⇒ 404 from the read plane, NOT the Phase-1 stub).
    assert!(
        read_resp.contains("node-self-host read plane"),
        "expected the node read-plane body (the node stood up after the boot write-plane validation), \
         got:\n{read_resp}"
    );

    // A client control-plane MUTATION (PUT) decomposes into {control.admin-api authorize, backend.kv
    // write} (INFO-2). On `core` the write sub-op is HELD but the authorize sub-op is unreachable → the
    // WHOLE request fails closed 503, never a partial serve of the held write half.
    let put_resp = try_http_put(&addr, "node.local").expect("issue a control-plane PUT");
    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        put_resp.starts_with("HTTP/1.1 503"),
        "a client control-plane mutation must fail closed (503), got:\n{put_resp}"
    );
    assert!(
        put_resp.contains("control-plane mutation refused")
            && put_resp.contains("authorization")
            && put_resp.contains("control.admin-api"),
        "the 503 must name the unsatisfiable authorization sub-op (INFO-2 decomposition), got:\n{put_resp}"
    );
    assert!(
        !put_resp.contains("Phase 1 minimal serve"),
        "the node-self-host backend must NOT serve the guest-workloads stub, got:\n{put_resp}"
    );

    // The marker the CI gate greps — reached only after the node stood up (its boot write-plane
    // mutation completed under Landlock) AND a client mutation fail-closed via the INFO-2 decomposition.
    println!("PRIVSEP NODE SELF-HOST WRITE-PLANE OK");
}

/// (D) Live gate for **P5-3-serve — the SERVED, AUTHORIZED client control-plane mutation** (the
/// highest-stakes privsep delta: client→control-plane-write authz). This is the DECISIVE proof that the
/// authz chain is correct AND that the authorized write lands UNDER the real `backend.kv` Landlock
/// profile — a host test is a false green for the authz decision.
///
/// A `node_serve: node-self-host` composition where `core` holds BOTH `control.admin-api` AND
/// `backend.kv` (so it serves a mutation's authorize + write sub-ops LOCALLY — the crown jewels live on
/// a separate `jewels` instance, since the crown-jewel-exclusion lint forbids a crown jewel co-residing
/// a control surface), with `serve.auth_root_public_key` set to a key THIS test holds the private half
/// of. Proves BOTH:
/// - **(a) POSITIVE:** an AUTHORIZED `PUT /api/routing/acme/blog/served.example` — a valid cnf-bound
///   `publisher@acme/blog` role token (trust-root-signed) + a per-call PoP bound to the mutation —
///   SERVES (200), and the write LANDS: a follow-up read-plane `GET Host: served.example` resolves (200).
///   The node served it only AFTER `core` verified the end principal (`cose::verify` + PoP), authorized
///   it (default-deny RBAC), and the write completed under `core`'s `backend.kv` Landlock/seccomp wall.
/// - **(b) NEGATIVE:** a FORGED principal (token signed by a non-trust-root key) and a MISSING-PoP
///   mutation are BOTH REFUSED fail-closed (503). The positive AND the negative — the authz decision is
///   only proven by both.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]`; the CI `live gate (privsep)`
/// job greps `PRIVSEP NODE SELF-HOST CONTROL-MUTATION OK`.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a node-self-host control-plane composition; an AUTHORIZED \
            client mutation serves + lands under the backend.kv Landlock profile, a forged / missing-PoP \
            one is refused 503; run via --include-ignored in the `live gate (privsep)` job"]
fn privsep_node_self_host_control_mutation_serves_end_to_end() {
    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{
        AuthorityPopBinding, Claims, KIND_ROLE, LocalSigner, Signer, TokenAlg, mint_authority_pop,
        mint_delegatable,
    };
    use boatramp_server::privsep_authority::{CONTROL_MUTATION_POP_OP, control_mutation_pop_bytes};

    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-selfhost-ctrlmut-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // The control-plane trust root (the test holds the PRIVATE half; the node gets only the PUBLIC half
    // via `serve.auth_root_public_key`) + the end principal's holder key (a frontend relay never holds
    // it). A small current-thread runtime drives the async mints (this is a sync `#[test]`).
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build a current-thread runtime for the mints");
    let root = LocalSigner::generate(TokenAlg::Es256);
    let holder = LocalSigner::generate(TokenAlg::Es256);
    let forger = LocalSigner::generate(TokenAlg::Es256);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let method = "PUT";
    let path = "/api/routing/acme/blog/served.example";
    let transport_host = "node-admin";
    // Mint a cnf-bound role token + a per-call PoP bound to THIS mutation, signed by `signer`.
    let mint = |signer: &LocalSigner, role: GrantedRole, nonce: u128| -> (String, String) {
        rt.block_on(async {
            let claims = Claims {
                roles: vec![role],
                kind: KIND_ROLE.to_string(),
                ttl_secs: Some(300),
                now_unix: now,
            };
            let token = mint_delegatable(&claims, &holder.public_key(), signer)
                .await
                .expect("mint the role token");
            let req_bytes = control_mutation_pop_bytes(method, path, transport_host);
            let binding = AuthorityPopBinding {
                op: CONTROL_MUTATION_POP_OP,
                context_token: &token,
                nonce,
                request_bytes: &req_bytes,
            };
            let pop = mint_authority_pop(&binding, &holder, now)
                .await
                .expect("mint the PoP");
            (token, pop)
        })
    };

    // A VALID composition: `core` holds control.admin-api + backend.* (serves the mutation's sub-ops
    // LOCALLY), the 6 crown jewels live on a separate `jewels` instance (crown-jewel exclusion forbids
    // control+crown co-residency), union == ALL, no forbidden public-listener co-residency.
    let cfg = format!(
        r#"(
    serve: (
        addr: "127.0.0.1:{port}",
        data_dir: "{data_dir}",
        auth_root_public_key: "{root_pub}",
    ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
                ],
                sandbox: Derived,
                links: [],
            ),
            "jewels": (
                capabilities: [
                    "secrets.sealer", "token.signer", "image.signer", "overlay.dial-signer",
                    "s3ingress.root", "cluster.join-signer",
                ],
                sandbox: Derived,
                links: [],
            ),
            "core": (
                capabilities: [
                    "control.admin-api", "exec.compute",
                    "backend.kv", "backend.sql", "backend.blob", "backend.messaging",
                ],
                sandbox: Derived,
                substrate: OsProcess,
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "edge", to: "core", transport: Local, purpose: Relay) }},
        node_serve: NodeSelfHost,
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
        root_pub = root.public_key().to_hex(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the self-host control-mutation privsep config");

    let mut root_proc = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    // Poll until the node serves (a read-plane 404 proves `core` stood up — its boot write-plane
    // self-validation passed under Landlock — and the control plane authorizer was built).
    loop {
        if Instant::now() > deadline {
            let _ = root_proc.kill();
            let _ = root_proc.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the node-self-host control-mutation node did not serve within 25s");
        }
        if let Ok(Some(status)) = root_proc.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the node-self-host control-mutation \
                 composition failed to stand up (sandbox not Enforced? the control plane verifier could \
                 not resolve the trust root? a backend.kv Landlock EACCES?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if resp.contains("node-self-host read plane") => break,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }

    // --- (a) POSITIVE: an authorized publisher@acme/blog serves the mutation (200) + the write lands.
    let (token, pop) = mint(&root, GrantedRole::scoped("publisher", "acme/blog"), 1);
    let served = try_http_put_authed(&addr, path, transport_host, &token, 1, Some(&pop))
        .expect("issue the authorized control-plane PUT");
    // --- read-back: the P5-2 read plane now resolves `served.example` (the write LANDED).
    let read_back = try_http_get_host(&addr, "served.example").expect("read-back GET");

    // --- (b) NEGATIVE 1: a FORGED principal (token signed by a non-trust-root key) ⇒ 503.
    let (ftoken, fpop) = mint(&forger, GrantedRole::scoped("publisher", "acme/blog"), 2);
    let forged = try_http_put_authed(&addr, path, transport_host, &ftoken, 2, Some(&fpop))
        .expect("issue the forged control-plane PUT");

    // --- (b) NEGATIVE 2: a MISSING PoP (no boatramp-privsep-pop header) ⇒ 503 (default-deny).
    let (token3, _pop3) = mint(&root, GrantedRole::scoped("publisher", "acme/blog"), 3);
    let no_pop = try_http_put_authed(&addr, path, transport_host, &token3, 3, None)
        .expect("issue the missing-PoP control-plane PUT");

    let _ = root_proc.kill();
    let _ = root_proc.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    // Assertions AFTER teardown (so a failure never leaks the forked node / tmp dir).
    assert!(
        served.starts_with("HTTP/1.1 200") && served.contains("authorized mutation served"),
        "an AUTHORIZED client mutation must SERVE (200) under the backend.kv Landlock profile, got:\n{served}"
    );
    assert!(
        read_back.starts_with("HTTP/1.1 200") && read_back.contains("resolves"),
        "the authorized write must LAND + be readable via the read plane (GET resolves), got:\n{read_back}"
    );
    assert!(
        forged.starts_with("HTTP/1.1 503") && forged.contains("end-principal verification failed"),
        "a FORGED principal (not trust-root-signed) must be REFUSED 503, got:\n{forged}"
    );
    assert!(
        no_pop.starts_with("HTTP/1.1 503") && no_pop.contains("no end-principal credential"),
        "a MISSING-PoP mutation must be REFUSED 503 (default-deny), got:\n{no_pop}"
    );

    // The marker the CI gate greps — reached ONLY after the AUTHORIZED mutation served + landed under
    // Landlock AND both the forged and missing-PoP mutations were refused fail-closed.
    println!("PRIVSEP NODE SELF-HOST CONTROL-MUTATION OK");
}

/// (E) The P5-4 **cross-instance authorize relay** live gate — the DECISIVE proof of the
/// cross-instance control-plane authz TRUST decision under REAL Landlock. A host test over a socketpair
/// proves the wire protocol + decision logic; only a forked composition on a real Landlock kernel
/// proves the SPLIT holds end-to-end — so this is the authoritative gate ([[ignore-gated-tests-not-evidence]]).
///
/// A `node_serve: node-self-host` composition where `authorize` (`control.admin-api`) is held on a
/// DIFFERENT instance (`control`) than the `backend.kv` write (`core`): `core` (holds `backend.kv` +
/// the other backends + `exec.compute`, NOT `control.admin-api`) receives the client fd from `edge`,
/// decomposes the mutation, and RELAYS the `authorize` sub-op to `control` (holds only
/// `control.admin-api`) over a `control-authorize-serve`-marked link; `control` re-validates the
/// end-principal context + per-call PoP AT THE DESTINATION and answers the `rights_for` DECISION (never
/// a key), and `core` — the revocation-marker authority — enforces revocation + applies the write under
/// its `backend.kv` Landlock profile. Proves:
/// - **(a) POSITIVE:** an AUTHORIZED `PUT /api/routing/acme/blog/served.example` (a valid cnf-bound
///   `publisher@acme/blog` role token + a per-call PoP) SERVES cross-instance (200) and the write LANDS
///   (a follow-up read-plane `GET Host: served.example` resolves). The node served it only after the
///   SEPARATE `control` instance verified + authorized the principal and `core` wrote under Landlock.
/// - **(b) NEGATIVES:** a FORGED principal (non-trust-root key) is refused by the DESTINATION
///   re-validation (no asserted-id trust across the link); a MISSING-PoP mutation is default-denied; and
///   a verbatim REPLAY of the accepted call is refused by the destination's anti-replay. All 503.
///
/// (The "relay to a non-grammar endpoint is refused" negative is a PURE ROUTING decision — proven
/// decisively by the host tests `p5_4_cross_instance_authorize_relay_serves_and_fail_closes` (NEGATIVE
/// 7) + `p5_1_node_router_serves_held_relays_the_rest_refuses_unreachable`; it needs no Landlock, so a
/// host test is not a false green for it.)
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]`; the CI `live gate (privsep)`
/// job greps `PRIVSEP NODE SELF-HOST CROSS-INSTANCE AUTHORIZE OK`.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a node-self-host composition that SPLITS control.admin-api \
            onto a separate instance; an AUTHORIZED client mutation serves cross-instance over the \
            control-authorize relay + lands under the backend.kv Landlock profile, a forged / \
            missing-PoP / replayed one is refused 503; run via --include-ignored in `live gate (privsep)`"]
fn privsep_node_self_host_cross_instance_authorize_serves_end_to_end() {
    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{
        AuthorityPopBinding, Claims, KIND_ROLE, LocalSigner, Signer, TokenAlg, mint_authority_pop,
        mint_delegatable,
    };
    use boatramp_server::privsep_authority::{CONTROL_MUTATION_POP_OP, control_mutation_pop_bytes};

    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-selfhost-xinst-authz-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build a current-thread runtime for the mints");
    let root = LocalSigner::generate(TokenAlg::Es256);
    let holder = LocalSigner::generate(TokenAlg::Es256);
    let forger = LocalSigner::generate(TokenAlg::Es256);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let method = "PUT";
    let path = "/api/routing/acme/blog/served.example";
    let transport_host = "node-admin";
    let mint = |signer: &LocalSigner, role: GrantedRole, nonce: u128| -> (String, String) {
        rt.block_on(async {
            let claims = Claims {
                roles: vec![role],
                kind: KIND_ROLE.to_string(),
                ttl_secs: Some(300),
                now_unix: now,
            };
            let token = mint_delegatable(&claims, &holder.public_key(), signer)
                .await
                .expect("mint the role token");
            let req_bytes = control_mutation_pop_bytes(method, path, transport_host);
            let binding = AuthorityPopBinding {
                op: CONTROL_MUTATION_POP_OP,
                context_token: &token,
                nonce,
                request_bytes: &req_bytes,
            };
            let pop = mint_authority_pop(&binding, &holder, now)
                .await
                .expect("mint the PoP");
            (token, pop)
        })
    };

    // The SPLIT composition: `control` holds ONLY `control.admin-api` (the authorizer); `core` holds
    // `backend.kv` + the other backends + `exec.compute` (the serving writer) and RELAYS the authorize
    // sub-op to `control` over the `control-authorize-serve`-marked `core-to-control` link. `edge` is
    // the public parser frontend; `aux` holds the other listeners + exec.wasmtime + acme; `jewels` holds
    // the 6 crown jewels. union == ALL, no forbidden co-residency, exactly one control.admin-api on the
    // control-authorize link.
    let cfg = format!(
        r#"(
    serve: (
        addr: "127.0.0.1:{port}",
        data_dir: "{data_dir}",
        auth_root_public_key: "{root_pub}",
    ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
                ],
                sandbox: Derived,
                links: [],
            ),
            "jewels": (
                capabilities: [
                    "secrets.sealer", "token.signer", "image.signer", "overlay.dial-signer",
                    "s3ingress.root", "cluster.join-signer",
                ],
                sandbox: Derived,
                links: [],
            ),
            "control": (
                capabilities: ["control.admin-api"],
                sandbox: Derived,
                substrate: OsProcess,
                links: ["core-to-control"],
            ),
            "core": (
                capabilities: [
                    "exec.compute",
                    "backend.kv", "backend.sql", "backend.blob", "backend.messaging",
                ],
                sandbox: Derived,
                substrate: OsProcess,
                links: ["to-core", "core-to-control"],
            ),
        }},
        links: {{
            "to-core": (from: "edge", to: "core", transport: Local, purpose: Relay),
            "core-to-control": (from: "core", to: "control", transport: Local, purpose: ControlAuthorizeServe),
        }},
        node_serve: NodeSelfHost,
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
        root_pub = root.public_key().to_hex(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the cross-instance-authorize privsep config");

    let mut root_proc = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if Instant::now() > deadline {
            let _ = root_proc.kill();
            let _ = root_proc.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!("the node-self-host cross-instance-authorize node did not serve within 25s");
        }
        if let Ok(Some(status)) = root_proc.try_wait() {
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the cross-instance-authorize composition \
                 failed to stand up (sandbox not Enforced? the split `control` verifier could not \
                 resolve the trust root? a backend.kv Landlock EACCES? the control-authorize link not \
                 wired?)"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if resp.contains("node-self-host read plane") => break,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }

    // --- (a) POSITIVE: an authorized publisher@acme/blog serves cross-instance (200) + the write lands.
    let (token, pop) = mint(&root, GrantedRole::scoped("publisher", "acme/blog"), 1);
    let served = try_http_put_authed(&addr, path, transport_host, &token, 1, Some(&pop))
        .expect("issue the authorized cross-instance PUT");
    let read_back = try_http_get_host(&addr, "served.example").expect("read-back GET");

    // --- (b) NEGATIVE 1: a FORGED principal (non-trust-root key) ⇒ the DESTINATION re-validation fails.
    let (ftoken, fpop) = mint(&forger, GrantedRole::scoped("publisher", "acme/blog"), 2);
    let forged = try_http_put_authed(&addr, path, transport_host, &ftoken, 2, Some(&fpop))
        .expect("issue the forged cross-instance PUT");

    // --- (b) NEGATIVE 2: a MISSING PoP ⇒ default-deny (before any relay).
    let (token3, _pop3) = mint(&root, GrantedRole::scoped("publisher", "acme/blog"), 3);
    let no_pop = try_http_put_authed(&addr, path, transport_host, &token3, 3, None)
        .expect("issue the missing-PoP cross-instance PUT");

    // --- (b) NEGATIVE 3: a verbatim REPLAY of the accepted call ⇒ the DESTINATION anti-replay refuses.
    let replay = try_http_put_authed(&addr, path, transport_host, &token, 1, Some(&pop))
        .expect("issue the replayed cross-instance PUT");

    let _ = root_proc.kill();
    let _ = root_proc.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        served.starts_with("HTTP/1.1 200") && served.contains("authorized mutation served"),
        "an AUTHORIZED client mutation must SERVE (200) over the cross-instance authorize relay, got:\n{served}"
    );
    assert!(
        read_back.starts_with("HTTP/1.1 200") && read_back.contains("resolves"),
        "the cross-instance-authorized write must LAND + be readable via the read plane, got:\n{read_back}"
    );
    assert!(
        forged.starts_with("HTTP/1.1 503"),
        "a FORGED principal must be REFUSED 503 (destination re-validation), got:\n{forged}"
    );
    assert!(
        no_pop.starts_with("HTTP/1.1 503") && no_pop.contains("no end-principal credential"),
        "a MISSING-PoP mutation must be REFUSED 503 (default-deny), got:\n{no_pop}"
    );
    assert!(
        replay.starts_with("HTTP/1.1 503") && replay.contains("anti-replay"),
        "a verbatim REPLAY must be REFUSED 503 by the destination anti-replay, got:\n{replay}"
    );

    // The marker the CI gate greps — reached ONLY after the AUTHORIZED cross-instance mutation served +
    // landed under Landlock AND the forged / missing-PoP / replayed mutations were all refused.
    println!("PRIVSEP NODE SELF-HOST CROSS-INSTANCE AUTHORIZE OK");
}

/// (E, P5-4-proper) Live gate for the **node-own wasm EXECUTION ENGINE self-host**: a
/// `node_serve: node-self-host` composition whose `aux` instance HOLDS `exec.wasmtime` — i.e. the node
/// OWNS its wasm execution engine — STANDS UP + SERVES, which it can do only after `aux`'s boot engine
/// self-validation (`HandlerEngine::self_validate_stand_up`) BUILT the wasm engine and COMPILED a
/// component — the cranelift codegen → executable-`mmap(PROT_EXEC)` path a read/write/stub serve never
/// touches — UNDER `aux`'s per-capability Landlock+seccomp profile. **This is the decisive P5-4 proof**
/// the task demands for the engine tier: the JIT compile completes with NO fail-closed EACCES / killed
/// syscall under real Landlock (kernel 6.12 / ABI V5 on lighthouse). If the sandbox killed a syscall
/// cranelift needs (or walled its codegen), `run_node_exec_engine_self_validation` returns `Err` →
/// `aux` exits → `FailNodeClosed` tears `__root` down → the "exited early" panic below fires (exactly
/// what this gate surfaces).
///
/// Two assertions make it decisive, not hollow: (1) the node SERVES a real read-plane response —
/// proving the WHOLE composition (incl. `aux`'s fail-closed engine self-validation) stood up; and (2)
/// `aux`'s engine self-validation SUCCESS log appears in the root's stderr — proving the self-validation
/// RAN + PASSED under the sandbox (a silent skip / compile-out, or a build that never reached the
/// compile, fails assertion 2). The engine self-validation is COMPILE-only; guest EXECUTION under the
/// instance sandbox is separately proven by the per-tenant template gate.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]`; the CI `live gate (privsep)`
/// job greps `PRIVSEP NODE SELF-HOST EXEC-ENGINE OK`.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a node-self-host composition whose aux holds \
            exec.wasmtime; aux's boot engine self-validation must build the wasm engine + compile a \
            component under aux's Landlock/seccomp profile (no fail-closed EACCES) or the node fails \
            closed; run via --include-ignored in the `live gate (privsep)` job"]
fn privsep_node_self_host_exec_engine_serves_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "boatramp-privsep-selfhost-engine-{}",
        std::process::id()
    ));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");
    let stderr_path = tmp.join("root.stderr.log");

    // The SAME known-valid 4-instance composition the read-/write-plane gates use (edge/aux/ops/core:
    // union == ALL, no forbidden co-residency), with `node_serve: node-self-host`. `aux` holds
    // `exec.wasmtime` (+ the other listeners + acme) and NO links → it self-validates the node-own wasm
    // engine at stand-up, then parks holding it inert (the node-own-function SERVE routing is P5-4's
    // surfaced remaining work); `core` (backend.kv on os-process) serves the read plane so the gate can
    // confirm the WHOLE composition — `aux` included — stood up.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.public-tls", "listen.http-parse"],
                sandbox: Derived,
                links: ["to-core"],
            ),
            "aux": (
                capabilities: [
                    "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "acme.dns-control",
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
                substrate: OsProcess,
                links: ["to-core"],
            ),
        }},
        links: {{ "to-core": (from: "edge", to: "core", transport: Local, purpose: Relay) }},
        node_serve: NodeSelfHost,
    ),
)"#,
        port = port,
        data_dir = data_dir.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write the self-host exec-engine privsep config");

    // Redirect the root's stderr to a FILE (not a pipe — a pipe would block the serving root once its
    // buffer filled); the test reads it at the end to assert `aux`'s engine self-validation log.
    let stderr_file = std::fs::File::create(&stderr_path).expect("create the root stderr log");
    let mut root = Command::new(bin)
        .arg("__root")
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "boatramp=info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("spawn `boatramp __root`");

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(25);
    let response = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let log = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "the node-self-host exec-engine node did not serve within 25s\n--- root stderr ---\n{log}"
            );
        }
        // Fail-closed: if the root exited, the composition failed to stand up — most tellingly here,
        // `aux`'s engine self-validation hit a fail-closed EACCES / killed syscall compiling under its
        // Landlock/seccomp profile (the live-gated P5-4 unknown).
        if let Ok(Some(status)) = root.try_wait() {
            let log = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "`boatramp __root` exited early ({status}) — the node-self-host exec-engine composition \
                 failed to stand up (aux's wasm engine would not compile a component under the \
                 exec.wasmtime Landlock/seccomp profile? sandbox not Enforced? the backend.kv KV would \
                 not open?).\n--- root stderr ---\n{log}"
            );
        }
        match try_http_get(&addr) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };

    // `aux` self-validates its engine at stand-up, CONCURRENTLY with `core` coming up — so `core`
    // may serve the read plane (breaking the loop above) a beat BEFORE `aux` flushes its success log.
    // Poll the stderr log for that line (while the root is still alive) up to a short deadline; the
    // self-validation completes in tens of ms (well short of its own 30s probe timeout), so a line
    // still ABSENT here means it genuinely did not complete — a real failure, not a read race. (If the
    // root died meanwhile, assertion (2) surfaces the captured stderr.)
    const ENGINE_OK_LOG: &str =
        "wasm engine self-validated under the exec.wasmtime Landlock/seccomp profile";
    let log_deadline = Instant::now() + Duration::from_secs(10);
    let log = loop {
        let log = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        if log.contains(ENGINE_OK_LOG) || matches!(root.try_wait(), Ok(Some(_))) {
            break log;
        }
        if Instant::now() > log_deadline {
            break log;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let _ = root.kill();
    let _ = root.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    // (1) The node served a REAL read-plane response (the whole composition — `aux` included — stood up).
    assert!(
        response.contains("node-self-host read plane"),
        "expected the node read-plane body (the composition served a real read), got:\n{response}"
    );
    assert!(
        !response.contains("Phase 1 minimal serve"),
        "the node-self-host backend must NOT serve the guest-workloads stub body, got:\n{response}"
    );
    // (2) `aux`'s engine self-validation RAN + PASSED under its sandbox (not a silent skip / compile-out,
    //     not a fail-closed EACCES — which would have exited aux → FailNodeClosed above).
    assert!(
        log.contains(ENGINE_OK_LOG),
        "expected aux's node-own wasm engine self-validation SUCCESS log (proving the engine compiled a \
         component under the exec.wasmtime Landlock/seccomp profile), got root stderr:\n{log}"
    );

    // The marker the CI gate greps — reached only after the node served AND aux's engine self-validation
    // passed under the sandbox.
    println!("PRIVSEP NODE SELF-HOST EXEC-ENGINE OK");
}

// =============================================================================
// HIGH-1 LIVE GATE — the cross-instance `/proc/<pid>/mem` key-disclosure WALL.
// =============================================================================
//
// The final privsep Security re-review found (HIGH-1) that on the same-kernel instance substrates
// (OsProcess default + the Container "simple model") the VFS path to a sibling's `/proc/<pid>/mem` was
// left open: all instances run as the same node uid in the SHARED host pid namespace, `/proc` is
// read-granted in every derived Landlock profile, and `openat`/`pread64` are allowed — so a compromised
// frontend instance could `openat("/proc/<signer-pid>/mem")` + `pread64` a crown-jewel key straight out
// of a holder's mlocked address space, bypassing the ptrace/process_vm_readv seccomp KILL (that VFS read
// issues NO ptrace syscall). The fix: every served instance calls `sandbox::set_process_undumpable()`
// (`prctl(PR_SET_DUMPABLE, 0)`) post-exec, which reparents its `/proc/<pid>/*` to root:root and gates
// them behind `ptrace_may_access` — so a capless same-uid sibling gets `EPERM`/`EACCES`.
//
// This assertion (invoked from `privsep_two_instance_composition_serves_end_to_end`, while that real
// `__root` composition is serving) PROVES the wall against the REAL crown-jewel `core` instance, and is
// MUTATION-verifiable: with the fix present the capless same-uid sibling is DENIED (`PRIVSEP PROC-MEM
// WALL OK`); revert `set_process_undumpable()` and the SAME read SUCCEEDS (the reader reports DISCLOSED
// and the assertion fails), proving the gate has teeth. The CI `live gate (privsep)` job greps the
// marker, so a silent skip / compile-out fails the merge (the "ignore-gated tests != evidence" rule).

/// The success marker the CI `live gate (privsep)` job greps for the HIGH-1 wall.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
const PROC_MEM_WALL_MARKER: &str = "PRIVSEP PROC-MEM WALL OK";

/// The `/proc/sys/kernel/yama/ptrace_scope` sysctl (absent on a kernel built without
/// `CONFIG_SECURITY_YAMA`).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
const PTRACE_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Reader-child verdicts (reported via `_exit`, like the netns/pathuds fork-probes above).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
mod proc_mem_probe_codes {
    pub const WALL_OK: i32 = 60; // the read was DENIED (EPERM/EACCES) — the PR_SET_DUMPABLE(0) wall held
    pub const DISCLOSED: i32 = 61; // the read was ADMITTED (open+read) — the wall is DOWN (mutation signal)
    pub const CAPDROP_FAILED: i32 = 62; // the reader could not shed CAP_SYS_PTRACE (would be a false pass)
    pub const TARGET_GONE: i32 = 63; // `/proc/<pid>/mem` open ENOENT/ESRCH — the core PID vanished (race)
    pub const SETUP_FAILED: i32 = 64; // an unexpected open/read errno (not a verdict)
}

/// The decoded verdict of the cross-instance `/proc/<pid>/mem` probe, captured WHILE the node is still
/// serving but asserted AFTER teardown (so a failure does not leak the node).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
struct ProcMemVerdict {
    code: i32,
    detail: String,
}

/// Find the PID of the privsep instance whose re-exec cmdline carries the unique
/// `__instance <label> --config <cfg_path>` token (the SAME token shape `read_container_core_caps`
/// matches). `cmdline` is `0444`/world-readable even for a non-dumpable target, so the harness (same
/// uid as the instance) can scan it without any capability. Pure-Rust `/proc` walk (no `sudo`).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn find_instance_pid(cfg_path: &std::path::Path, label: &str) -> Option<i32> {
    let token = format!("__instance {label} --config {}", cfg_path.display());
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // `cmdline` args are NUL-separated; translate NUL→space to match the token shape above.
        if let Ok(raw) = std::fs::read(entry.path().join("cmdline")) {
            let joined = String::from_utf8_lossy(&raw).replace('\0', " ");
            if joined.contains(&token) {
                return name.parse::<i32>().ok();
            }
        }
    }
    None
}

/// Best-effort lower `kernel.yama.ptrace_scope` to 0 for the probe window, returning the prior value to
/// restore (`None` ⇒ Yama absent, already 0, or we could not lower it — nothing to restore).
///
/// WHY: with `ptrace_scope >= 1`, Yama INDEPENDENTLY blocks a non-ancestor same-uid reader EVEN when the
/// target is dumpable — which would MASK a revert of the dumpable fix (the gate would stay green with the
/// hole reopened: no teeth). The dumpable fix itself denies REGARDLESS of `ptrace_scope`, so lowering it
/// NEVER changes the fix-present (WALL_OK) result — it only lets the MUTATION demonstrate the disclosure,
/// giving the gate real teeth. Writes the sysctl directly when root, else via passwordless `sudo -n`
/// (CI runners + lighthouse have it). A box without either keeps its current scope: the gate still
/// passes with the fix, but its teeth then hold only where `ptrace_scope` is already 0 or Yama is absent
/// (documented in the mutation-proof recipe).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn lower_ptrace_scope_best_effort() -> Option<String> {
    let prior = std::fs::read_to_string(PTRACE_SCOPE_PATH).ok()?; // None ⇒ Yama absent ⇒ nothing to do
    let prior = prior.trim().to_string();
    if prior == "0" {
        return None; // already permissive — no change, nothing to restore
    }
    if write_ptrace_scope("0") {
        Some(prior)
    } else {
        None
    }
}

/// Restore a `ptrace_scope` value previously lowered by [`lower_ptrace_scope_best_effort`] (best-effort).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn restore_ptrace_scope_best_effort(prior: Option<String>) {
    if let Some(prior) = prior {
        let _ = write_ptrace_scope(&prior);
    }
}

/// Write `value` to the `ptrace_scope` sysctl — directly if root, else via passwordless `sudo -n`.
/// Returns whether the write succeeded.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn write_ptrace_scope(value: &str) -> bool {
    if std::fs::write(PTRACE_SCOPE_PATH, value).is_ok() {
        return true;
    }
    Command::new("sudo")
        .arg("-n")
        .arg("sh")
        .arg("-c")
        .arg(format!("echo {value} > {PTRACE_SCOPE_PATH}"))
        .status()
        .is_ok_and(|s| s.success())
}

/// Fork ONE child that stands in for a COMPROMISED same-uid sibling instance: shed ALL capabilities
/// (so it holds no `CAP_SYS_PTRACE` — the crux, else a full-cap root reader would bypass the dumpable
/// gate and false-pass), then `open("/proc/<target>/mem")` + `pread` and `_exit` a
/// [`proc_mem_probe_codes`] verdict. Returns the child's exit code.
///
/// The child performs NO heap allocation after the fork (the `/proc/<pid>/mem` path is built as a
/// `CString` in the PARENT, and the body is `prctl`/`capset`/`open`/`pread`/`close` syscalls only) — the
/// async-signal-safe discipline the sibling fork-probes rely on, which makes the raw `fork` safe even
/// though this probe (unlike the netns/pathuds ones) runs inline in the possibly-multi-threaded harness.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn fork_proc_mem_reader(target_pid: i32) -> i32 {
    use proc_mem_probe_codes as code;

    // Built BEFORE the fork — no post-fork allocation in the child.
    let mem_path =
        std::ffi::CString::new(format!("/proc/{target_pid}/mem")).expect("no NUL in path");
    let is_root = process_is_root();

    // SAFETY: a single selected live test ⇒ no concurrent harness thread allocating at the fork instant,
    // and the child below only ever calls async-signal-safe syscalls (no malloc) — the SAME assumption
    // the netns/pathuds fork-probes above document.
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "fork() failed: {}",
        std::io::Error::last_os_error()
    );
    if pid == 0 {
        // ---- the reader child: become capless, then attempt the cross-instance read ----
        // Shed capabilities so this reader holds NO CAP_SYS_PTRACE. THE CRUX: a full-cap root reader
        // holds CAP_SYS_PTRACE and would bypass the dumpable gate (the read would succeed even WITH the
        // fix ⇒ a false pass). Mirror a served instance/relay as closely as practical:
        // `drop_all_capabilities()` (SECBIT_NOROOT + empty bounding set) THEN
        // `clear_current_capabilities()` (the in-process effective/permitted clear — this reader never
        // execs, exactly like the relay). `drop_all`'s `PR_SET_SECUREBITS` needs `CAP_SETPCAP`; when the
        // harness is already NON-root it holds none, so tolerate `drop_all`'s failure THERE (the reader
        // is already capless) but ALWAYS require the effective-set clear (which needs no privilege and is
        // the step that actually strips `CAP_SYS_PTRACE` from THIS reader). As root, `drop_all` MUST
        // succeed (CAP_SETPCAP is held), else the reader could retain ptrace authority ⇒ a false pass.
        let drop_all_ok = boatramp_server::sandbox::drop_all_capabilities().is_ok();
        if boatramp_server::sandbox::clear_current_capabilities().is_err() {
            unsafe { libc::_exit(code::CAPDROP_FAILED) };
        }
        if is_root && !drop_all_ok {
            unsafe { libc::_exit(code::CAPDROP_FAILED) };
        }

        // Open the target's `/proc/<pid>/mem`. With the fix (target non-dumpable) the file is
        // root-owned + `ptrace_may_access`-gated, so a capless same-uid sibling is DENIED here with
        // EPERM (ptrace gate) or EACCES (DAC, when the reparented root:root file is unreadable to a
        // non-root reader) — both are the wall.
        let fd = unsafe { libc::open(mem_path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EPERM || e == libc::EACCES {
                unsafe { libc::_exit(code::WALL_OK) };
            }
            if e == libc::ENOENT || e == libc::ESRCH {
                unsafe { libc::_exit(code::TARGET_GONE) };
            }
            unsafe { libc::_exit(code::SETUP_FAILED) };
        }
        // `open` SUCCEEDED ⇒ `ptrace_may_access` ADMITTED this reader at open time. Attempt a read: a
        // read that is denied (EPERM/EACCES) is still the wall; a read that returns bytes — OR fails only
        // for a benign reason such as EIO at an unmapped offset 0 — means the reader has a live handle to
        // the target's address space (it could walk `/proc/<pid>/maps` and pread a mapped key) ⇒ the wall
        // is DOWN (disclosure).
        let mut buf = [0u8; 1];
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, 1, 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::close(fd) };
            if e == libc::EPERM || e == libc::EACCES {
                unsafe { libc::_exit(code::WALL_OK) };
            }
            unsafe { libc::_exit(code::DISCLOSED) };
        }
        unsafe { libc::close(fd) };
        unsafe { libc::_exit(code::DISCLOSED) };
    }
    // ---- the parent: reap the child + decode its exit code ----
    let mut status: libc::c_int = 0;
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

/// Probe the cross-instance `/proc/<pid>/mem` wall against the live crown-jewel `core` instance (HIGH-1).
/// Locates `core`'s PID, neutralizes Yama so the mutation keeps its teeth (see
/// [`lower_ptrace_scope_best_effort`]), forks the capless same-uid reader, restores Yama, and returns the
/// verdict. Call WHILE the node is still serving.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn probe_cross_instance_proc_mem_wall(cfg_path: &std::path::Path) -> ProcMemVerdict {
    use proc_mem_probe_codes as code;

    let core_pid = match find_instance_pid(cfg_path, "core") {
        Some(p) => p,
        None => {
            return ProcMemVerdict {
                code: code::TARGET_GONE,
                detail: "could not locate the serving `core` instance by its \
                         `__instance core --config <cfg>` cmdline token in /proc"
                    .to_string(),
            };
        }
    };

    let prior_scope = lower_ptrace_scope_best_effort();
    let exit_code = fork_proc_mem_reader(core_pid);
    restore_ptrace_scope_best_effort(prior_scope);

    ProcMemVerdict {
        code: exit_code,
        detail: format!("core pid={core_pid}"),
    }
}

/// Assert the HIGH-1 wall held (the capless sibling was DENIED) and emit the CI marker. A hard gate: any
/// non-`WALL_OK` verdict — including a probe that could not run — FAILS rather than silently skip.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn assert_proc_mem_wall(verdict: ProcMemVerdict) {
    use proc_mem_probe_codes as code;
    let ProcMemVerdict { code: got, detail } = verdict;
    assert_eq!(
        got,
        code::WALL_OK,
        "HIGH-1 cross-instance /proc/<pid>/mem wall ({detail}): a CAPLESS same-uid sibling MUST be \
         DENIED (EPERM/EACCES) reading the crown-jewel `core` instance's memory — the \
         PR_SET_DUMPABLE(0) wall. Verdict codes: {disclosed}=DISCLOSED (the wall is DOWN — the open+read \
         was ADMITTED: either the `set_process_undumpable` flip regressed, OR on a reverted-mutation run \
         this is the EXPECTED failure that proves the gate's teeth), {capdrop}=CAPDROP_FAILED (the \
         reader could not shed CAP_SYS_PTRACE ⇒ refused as a would-be false pass), {gone}=TARGET_GONE \
         (the `core` PID was not found ⇒ the probe could not run, so it FAILS rather than silently \
         skip), {setup}=SETUP_FAILED (an unexpected open/read errno).",
        disclosed = code::DISCLOSED,
        capdrop = code::CAPDROP_FAILED,
        gone = code::TARGET_GONE,
        setup = code::SETUP_FAILED,
    );
    // The marker the CI gate greps — reached only after the capless sibling was walled off.
    println!("{PROC_MEM_WALL_MARKER}");
}
