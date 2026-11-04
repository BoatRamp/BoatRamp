//! Subprocess serve-boot smoke for the `dns-publish` SERVE-INSTALL CALL-SITE (cap-req #25).
//!
//! The in-process serve-path gate (`boatramp-server/tests/dns_publish_serve_wiring_live.rs`) proves
//! the install→dispatch→capture SEAM, but it installs the provider source itself — so it cannot prove
//! that `boatramp serve` actually CALLS `install_dns_publish_source` at boot. That one-line call-site
//! in `serve::run()` is EXACTLY how #24 shipped inert (the call was missing), so it is the failure mode
//! worth a runtime guard, not just builder unit tests + review. This smoke closes that gap: it boots
//! the REAL `boatramp` binary with `--dns-publish-provider manual` and asserts serve emits the install
//! boot marker [`MARKER`] early in `run()`. Delete the call line and the marker never appears ⇒ this
//! gate fails.
//!
//! ROBUST by construction (no cross-process store-seeding flakiness): `install_dns_publish_source`
//! runs in `run()` BEFORE the mode fork / deploy-store seeding, so the marker is the FIRST boot log
//! line (verified: it precedes the KV open). The smoke captures that EARLY stderr line with a bounded
//! deadline and KILLS the process — it never waits for the full node boot, binds nothing meaningful,
//! and seeds no KV/blob store. serve auto-generates its `[secrets]` kek under the throwaway
//! `--data-dir`, so no config file or secret is needed; the marker is reached well before any of that.
//!
//! `#[ignore]`d (boots a real binary). Run via the CI `live-gate-dns-publish-serve-wiring` job or:
//!   `cargo test -p boatramp --features dns-publish,acme-dns --test dns_publish_serve_install_boot -- --ignored --nocapture`

#![cfg(all(feature = "dns-publish", feature = "acme-dns"))]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Emitted ONLY by `boatramp::dns_publish_serve::install_dns_publish_source` when serve installs a
/// provider source — the proof that `run()` reached + executed the install call-site. Kept verbatim in
/// that log message; a rewording that drops this token breaks the gate on purpose.
const MARKER: &str = "DNS-PUBLISH SERVE-INSTALL CALLED";

#[test]
#[ignore = "capability gate: boots the real serve binary; run via ci.yml live-gate-dns-publish-serve-wiring or with --ignored"]
fn serve_boot_calls_install_dns_publish_source() {
    // A throwaway data dir: serve auto-generates its `[secrets]` kek here, but the install marker is
    // emitted BEFORE any store/secret work, so this never fills.
    let dir = std::env::temp_dir().join(format!("br-dns-pub-install-boot-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp data dir");

    // A free loopback port (serve binds late, after the marker; we kill before it matters).
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port();

    let data_dir = dir.to_string_lossy().into_owned();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_boatramp"))
        .args([
            "serve",
            "--tls",
            "off",
            "--addr",
            &addr,
            "--data-dir",
            &data_dir,
            // The fix under test: with a provider configured, run() must CALL install_dns_publish_source.
            "--dns-publish-provider",
            "manual",
            "--dns-publish-zone-root",
            "app.example.com",
        ])
        // The install log is `boatramp::dns::publish` at info, written to STDERR by serve's subscriber.
        .env("RUST_LOG", "boatramp=info")
        .env_remove("BOATRAMP_LOG_FORMAT")
        .current_dir(&dir) // never pick up a stray repo `boatramp.cfg`
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `boatramp serve`");

    // Stream stderr lines to a channel so the main thread waits with a bounded deadline.
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut captured = String::new();
    let mut found = false;
    let mut early_exit = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                let hit = line.contains(MARKER);
                captured.push_str(&line);
                captured.push('\n');
                if hit {
                    found = true;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // If serve died before the marker, stop early (don't burn the whole deadline).
                if let Ok(Some(status)) = child.try_wait() {
                    early_exit = Some(status);
                    while let Ok(line) = rx.try_recv() {
                        if line.contains(MARKER) {
                            found = true;
                        }
                        captured.push_str(&line);
                        captured.push('\n');
                    }
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // ALWAYS tear the process down (success, timeout, or early exit), then join the reader.
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    assert!(
        found,
        "serve did NOT emit the install marker `{MARKER}` within the deadline — `boatramp serve` must \
         CALL install_dns_publish_source at boot (cap-req #25; this is the inert-ship failure mode). \
         early_exit={early_exit:?}; captured serve stderr:\n{captured}"
    );

    println!(
        "DNS-PUBLISH SERVE-INSTALL-BOOT OK: `boatramp serve --dns-publish-provider manual` emitted \
         `{MARKER}` at boot — serve's run() reached + executed the install_dns_publish_source call-site"
    );
}
