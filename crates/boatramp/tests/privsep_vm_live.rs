//! Live end-to-end **serve gate** for the scoped privsep VM substrate (firecracker/Linux,
//! static-parser-frontends-only) — the owner-greenlit first cut, `DESIGN-privsep-phase3-vm.md` §1c /
//! the de-risk §1.5 "serve gate's first assertion: boot the literal boatramp static-PIE via the shim
//! to a 200 over vsock".
//!
//! It exercises the REAL Rust host launcher ([`boatramp::privsep_vm::launch_frontend_vm`]): assemble
//! the initramfs (the non-PIE shim as `/init` + the literal static-PIE `boatramp` + the real config +
//! the descriptor), S3-verify + boot a firecracker microVM (kernel + initramfs + vsock, NO net, NO
//! drives), and run the host client-byte relay. Inside the guest, the shim `execve`s
//! `boatramp __vm-guest`, which binds AF_VSOCK, installs its fail-closed `Enforced` profile (S4 — on a
//! Landlock-V5 guest kernel), and serves the relayed client with the REAL `boatramp_http` stack. A
//! plain HTTP client then gets a `200` — bytes flowing client → host TCP listener → vsock relay →
//! guest parse → response, with the frontend behind the hypervisor wall.
//!
//! LIGHTHOUSE-ONLY (needs `/dev/kvm` + firecracker + a Landlock-V5 guest kernel + a NON-PIE shim + a
//! musl static-PIE `boatramp`). `#[ignore]`d and driven by `docs/privsep-vm-scoped-repro/run.sh`,
//! which builds the assets, sets the `BOATRAMP_PRIVSEP_VM_*` env, and runs it with `--ignored`. It is
//! NOT a GitHub-CI gate (GitHub's hosted runners have no `/dev/kvm`); the evidence is the lighthouse
//! run captured in the repro log.
#![cfg(all(target_os = "linux", feature = "sandbox"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The scoped VM serve gate. Requires the `BOATRAMP_PRIVSEP_VM_*` assets env + a musl static-PIE
/// `boatramp` at `BOATRAMP_PRIVSEP_VM_GUEST_BIN` (set by the repro driver). Absent env ⇒ the gate
/// explains the provisioning requirement and SKIPS (it never silently passes).
#[test]
#[ignore = "live: boots a firecracker microVM (needs /dev/kvm + firecracker + a Landlock-V5 guest \
            kernel + the non-PIE shim + a musl static-PIE boatramp); run via the repro driver"]
fn privsep_vm_scoped_frontend_serves_200_over_vsock() {
    let Ok(guest_bin) = std::env::var("BOATRAMP_PRIVSEP_VM_GUEST_BIN") else {
        eprintln!(
            "SKIP: set BOATRAMP_PRIVSEP_VM_GUEST_BIN (the musl static-PIE boatramp) + the \
             BOATRAMP_PRIVSEP_VM_* assets; run docs/privsep-vm-scoped-repro/run.sh on lighthouse"
        );
        return;
    };
    let assets = match boatramp::privsep_vm::VmAssets::from_env() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("SKIP: VM assets not provisioned: {e}");
            return;
        }
    };

    // Root the node dirs under cargo's integration-test temp (NOT the system temp — `derive_profile`
    // fail-closed-refuses a data_dir under a shared-temp entry).
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("boatramp-privsep-vm-live-{}", std::process::id()));
    let data_dir = tmp.join("data");
    std::fs::create_dir_all(&data_dir).expect("create the node data dir");
    let work = tmp.join("vm-work");
    std::fs::create_dir_all(&work).expect("create the vm work dir");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the frontend listener");
    let addr = listener.local_addr().expect("local_addr");
    let port = addr.port();
    let cfg_path = tmp.join("boatramp.cfg");

    // A minimal VALID 4-instance composition (union == ALL; no crown jewel co-resident with a
    // listener/exec/control; LINKLESS — `core` co-resides sealer+signer so no cross-instance key link
    // is needed; the scoped VM `edge` frontend holds ONLY `listen.http-parse`, the pure parse surface,
    // and serves self-contained — no inward §1d link in this cut).
    let cfg = format!(
        r#"(
    serve: ( addr: "127.0.0.1:{port}", data_dir: "{data_dir}" ),
    privsep: (
        instances: {{
            "edge": (
                capabilities: ["listen.http-parse"],
                sandbox: Derived,
                substrate: Vm,
                links: [],
            ),
            "aux": (
                capabilities: [
                    "listen.public-tls", "listen.mail", "listen.overlay",
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

    // Launch the scoped frontend microVM (the REAL Rust host path: cpio + S3-verify + boot + relay).
    let guest_bin_path = Path::new(&guest_bin);
    let mut launch = boatramp::privsep_vm::launch_frontend_vm(
        guest_bin_path,
        "edge",
        &cfg_path,
        listener,
        &assets,
        &work,
        3, // guest CID (0/1/2 reserved)
        boatramp::privsep_vm::DEFAULT_GUEST_VSOCK_PORT,
    )
    .expect("launch the scoped frontend microVM");

    // The guest must boot (firecracker + 185 MB cpio unpack + static-PIE self-reloc + profile install +
    // vsock bind) then serve — a generous deadline. If firecracker EXITS early, dump the serial console.
    let console = work.join("console.log");
    let deadline = Instant::now() + Duration::from_secs(120);
    let response = loop {
        if Instant::now() > deadline {
            dump_console(&console);
            let _ = launch.child.kill();
            let _ = launch.child.wait();
            panic!("the scoped VM frontend did not serve a 200 within 120s");
        }
        if let Ok(Some(status)) = launch.child.try_wait() {
            dump_console(&console);
            panic!("firecracker exited early ({status}) — the guest frontend did not stand up");
        }
        match try_http_get(&addr.to_string()) {
            Ok(resp) if !resp.is_empty() => break resp,
            _ => std::thread::sleep(Duration::from_millis(500)),
        }
    };

    let _ = launch.child.kill();
    let _ = launch.child.wait();
    dump_console(&console);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        response.contains("200"),
        "expected a 200 from the VM frontend over the vsock relay, got:\n{response}"
    );
    assert!(
        response.contains("boatramp privsep VM static-parser frontend"),
        "expected the VM frontend's body marker (proving the real parse ran behind the hypervisor \
         wall), got:\n{response}"
    );

    // The marker the repro driver greps — only reached after a real 200 came back over the full path.
    println!("PRIVSEP VM SCOPED SERVE OK");
}

/// One blocking HTTP/1.1 GET, returning the raw response (status line + headers + body) or an error.
fn try_http_get(addr: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: vm-gate\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

/// Echo the guest serial console to the test output (the markers SHIM-ALIVE / PRIVSEP VM GUEST
/// SERVING / any fatal reason), best-effort.
fn dump_console(console: &Path) {
    if let Ok(log) = std::fs::read_to_string(console) {
        eprintln!("---- guest serial console ({}) ----", console.display());
        eprint!("{log}");
        eprintln!("---- end guest serial console ----");
    }
}
