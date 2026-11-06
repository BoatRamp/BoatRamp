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

/// Live gate for the Phase-3 **`substrate: vm`** spawn backend — DESIGN-FIRST, still REFUSED
/// fail-closed (the VM backend is NOT wired; see `crates/boatramp/DESIGN-privsep-phase3-vm.md`).
///
/// A VM has its OWN kernel, so fd-passing cannot cross the boundary: the `local` socketpair link
/// ends, the public listener fd, AND the per-request `SCM_RIGHTS` client-connection splice all need a
/// vsock byte-relay that is not built, and the hosting model (guest kernel + own-binary-as-init) is an
/// unratified owner + Security decision. So the substrate stays refused.
///
/// Forks `boatramp __root` against the known-valid frontend-inversion topology (union == ALL; grants
/// disjoint; no crown co-resident with a listener/exec/control surface — so it clears every
/// pre-supervise lint + screen and REACHES the substrate-dispatch gate) whose serving `core` is pinned
/// `substrate: vm`, and asserts the node **refuses fail-closed end-to-end**: the root exits NON-ZERO
/// at the pre-spawn substrate-dispatch gate (`supervise::run` step 0 → `resolve_spawn_backend`),
/// BEFORE it binds the public listener or spawns any instance, and the port is NEVER served. The "no
/// silent downgrade to an OS process" invariant made observable end-to-end.
///
/// **This gate INVERTS** into a real serve gate once the VM backend is wired: the SAME composition
/// then serves a real 200 from a VM-confined `core` over the vsock relay (marker
/// `PRIVSEP VM SUBSTRATE OK`), at which point it moves to lighthouse (Linux + `/dev/kvm`). Until then
/// the REFUSE assertion is the proof the fail-closed posture holds. The refuse gate needs NEITHER
/// `/dev/kvm` NOR sudo — the refusal fires before any VM boot — so it runs on the ordinary CI runner.
///
/// `#[cfg(all(target_os = "linux", feature = "sandbox"))]` + `#[ignore]` like the other live gates.
/// The CI `live gate (privsep)` job runs it via `--include-ignored` and greps the
/// `PRIVSEP VM SUBSTRATE REFUSED OK` marker + the pass count, so a silent skip / compile-out — or a
/// fail-closed regression that spawns/binds a VM instance despite the unwired backend — fails the
/// merge.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
#[ignore = "live: forks boatramp __root for a composition whose serving core is pinned `substrate: \
            vm`; asserts the node refuses FAIL-CLOSED (exits non-zero at the pre-spawn \
            substrate-dispatch gate, never binds the listener, never serves) — the VM backend is not \
            wired (DESIGN-first, see DESIGN-privsep-phase3-vm.md). Run via --include-ignored in the \
            `live gate (privsep)` job"]
fn privsep_vm_substrate_refuses_fail_closed_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_boatramp");
    // The refusal fires at the pre-spawn substrate-dispatch gate (supervise::run step 0 →
    // resolve_spawn_backend), BEFORE any instance is forked — so (unlike the container SERVE gate)
    // there is no cap-drop/traversal concern and no root/sudo needed. Root the node dirs under cargo's
    // integration-test temp (NOT /tmp — `derive_profile` refuses a data_dir there), like the
    // 2-instance composition gate.
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("boatramp-privsep-vm-refuse-{}", std::process::id()));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let port = free_port();
    let cfg_path = tmp.join("boatramp.cfg");

    // The SAME known-valid frontend-inversion topology the container serve gate uses, with the one
    // change under test: the serving `core` is pinned to the still-REFUSED `substrate: vm`. Chosen so
    // that when the VM backend is wired, this exact composition INVERTS into the serve gate (frontend
    // splices client bytes → vsock relay → a VM-confined `core` returns a 200). `frontend` (OsProcess)
    // binds the listener; `core` holds the backends + crown jewels.
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
                substrate: Vm,
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

    // Fail-closed proof: the node must EXIT (non-zero — the VM substrate refusal) within a few
    // seconds, and must NEVER serve the port. Poll both: a served response AT ANY POINT means the
    // fail-closed posture broke (a VM instance was spawned / the listener was bound despite the unwired
    // backend); otherwise wait for the non-zero exit.
    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(15);
    let exit_status = loop {
        if Instant::now() > deadline {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "the `substrate: vm` node neither refused (exited) nor served within 15s — the \
                 pre-spawn substrate-dispatch refusal did not fire as expected"
            );
        }
        // A served response = the fail-closed posture broke: the unwired VM backend must be refused
        // BEFORE the public listener is bound or any instance spawned.
        if let Ok(resp) = try_http_get(&addr)
            && !resp.is_empty()
        {
            let _ = root.kill();
            let _ = root.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            panic!(
                "the `substrate: vm` node SERVED a response — fail-closed REGRESSION (an unwired VM \
                 substrate must be refused before the listener is bound / any instance is spawned), \
                 got:\n{resp}"
            );
        }
        if let Ok(Some(status)) = root.try_wait() {
            break status;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !exit_status.success(),
        "`boatramp __root` with a `substrate: vm` instance must EXIT NON-ZERO (fail-closed refusal of \
         the unwired VM backend), got a clean exit: {exit_status}"
    );
    // Belt-and-suspenders: after the refusal the public listener must be unbound (connection refused),
    // confirming the refusal fired BEFORE the step-2 listener bind.
    assert!(
        try_http_get(&addr).is_err(),
        "after the fail-closed VM refusal the public listener must be unbound (connection refused) — \
         the refusal must fire before the listener is bound"
    );

    // The marker the CI gate greps — reached only after the node refused the unwired VM substrate
    // fail-closed (exited non-zero, never served). INVERTS to `PRIVSEP VM SUBSTRATE OK` + a real 200
    // when the backend is wired (see `crates/boatramp/DESIGN-privsep-phase3-vm.md` §7).
    println!("PRIVSEP VM SUBSTRATE REFUSED OK");
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
