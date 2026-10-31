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
    let tmp = std::env::temp_dir().join(format!("boatramp-privsep-live-{}", std::process::id()));
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
