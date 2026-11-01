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

    // A minimal, VALID 2-instance composition (passes the closure lint: union == ALL; no crown
    // jewel co-resident with a listener/exec/control surface; grants disjoint):
    //   - `edge`  = every listener + both exec + both control (group C ∪ D ∪ E; no keys, no
    //               backends) — the FRONTEND (binds serve.addr, splices client fds inward);
    //   - `core`  = every crown jewel + every backend (group A ∪ B; a crown jewel may co-reside
    //               only with A ∪ B) — the serving BACKEND.
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: [
                    "listen.public-tls", "listen.http-parse", "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "exec.compute",
                    "control.admin-api", "acme.dns-control",
                ],
                sandbox: Derived,
                links: ["to-core"],
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

    // A VALID 4-instance composition (passes the closure lint + the sealed-signer closure lint):
    //   - `edge`   = every listener + both exec + both control (C∪D∪E) — the FRONTEND;
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
                capabilities: [
                    "listen.public-tls", "listen.http-parse", "listen.mail", "listen.overlay",
                    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",
                    "exec.wasmtime", "exec.compute",
                    "control.admin-api", "acme.dns-control",
                ],
                sandbox: Derived,
                links: ["to-core"],
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
