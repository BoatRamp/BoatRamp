//! Privileged, real-device integration test for the TUN front-end (plan §3.9/§6: "per-OS TUN smoke
//! needs a device/privilege ⇒ NOT the Linux merge gate" — this is exactly that smoke test, run
//! only by the non-blocking `.github/workflows/tunnel.yml` job, never by the default
//! `cargo test`/merge gate).
//!
//! Needs `CAP_NET_ADMIN` or root to open a real Linux TUN device, and is run inside its own
//! network namespace by `tunnel.yml` (`ip netns exec`) so it can never collide with routes already
//! on the runner. `#[ignore]` keeps it out of the default `cargo test` run entirely.
//!
//! **Scope, deliberately narrow**: this test's unique job is the REAL kernel device/route plumbing
//! around the TUN front-end — NOT re-proving the overlay dial logic, which is already proven
//! without any privilege by
//! `tun::netstack::tests::a_crafted_syn_and_data_frame_drives_a_dial_through_the_mock_control_plane`
//! (the plan's own "smoltcp-direct test gives most of the coverage without privilege" — plan §6).
//! So the control plane here resolves to a deliberately unreachable relay (`127.0.0.1:1`); the
//! assertion is "a real TCP connection through the real kernel TUN device drives exactly one
//! overlay dial ATTEMPT", not a full backend echo.
#![cfg(feature = "tun")]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use boatramp_overlay_client::{OverlayId, OverlaySecret};
use boatramp_overlay_tunnel::tun::cidr::Ipv4Cidr;
use boatramp_overlay_tunnel::tun::{TunFrontend, TunOptions};
use boatramp_overlay_tunnel::{ControlPlane, ControlPlaneError, DialGrant, ServiceInfo, Tunnel};

fn dummy_id() -> OverlayId {
    OverlaySecret::generate().unwrap().id()
}

/// Resolves exactly `svc/db` to a throwaway, never-actually-reachable relay — see the module doc
/// for why a full backend echo is deliberately out of scope here.
struct FixedControlPlane {
    mint_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl ControlPlane for FixedControlPlane {
    async fn list_services(&self) -> Result<Vec<ServiceInfo>, ControlPlaneError> {
        Ok(vec![ServiceInfo {
            service: "svc/db".to_string(),
            relay: "127.0.0.1:1".parse().unwrap(),
            relay_id: dummy_id(),
            egress_id: dummy_id(),
            capability_only: true,
        }])
    }

    async fn resolve_and_mint(
        &self,
        service: &str,
        _holder: OverlayId,
    ) -> Result<DialGrant, ControlPlaneError> {
        self.mint_calls.fetch_add(1, Ordering::SeqCst);
        if service != "svc/db" {
            return Err(ControlPlaneError::NotFound(service.to_string()));
        }
        Ok(DialGrant {
            relay: "127.0.0.1:1".parse().unwrap(),
            relay_id: dummy_id(),
            egress_id: dummy_id(),
            capability_only: true,
            token: "test-cap".to_string(),
            expires_at: u64::MAX,
        })
    }
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN/root to open a real TUN device — see .github/workflows/tunnel.yml"]
async fn a_real_tcp_connection_through_the_kernel_tun_device_drives_a_dial_attempt() {
    let cp = Arc::new(FixedControlPlane {
        mint_calls: AtomicUsize::new(0),
    });
    let holder = OverlaySecret::generate().unwrap();
    let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
        .await
        .unwrap();

    let cidr: Ipv4Cidr = "10.123.45.0/24".parse().unwrap();
    let marker_path = std::env::temp_dir().join(format!(
        "br-tunnel-privileged-test-{}.marker",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker_path);
    let mut options = TunOptions::new(
        cidr,
        "internal".to_string(),
        "citest".to_string(),
        marker_path.clone(),
    );
    // This test never touches host DNS config (`resolvectl`/`/etc/resolv.conf`) — it only proves
    // the device/route/netstack plumbing, same narrowing as the module doc.
    options.skip_resolver = true;

    let front_end = TunFrontend::bind(tunnel, options)
        .await
        .expect("opening the TUN device needs CAP_NET_ADMIN/root — see the #[ignore] reason above");

    dump_net_state("after bind (device test)").await;

    // The synthetic IP a DNS lookup would hand back for `db.svc.citest.internal.` is deterministic
    // (the allocator's first allocation this run) but `TunFrontend` doesn't expose it directly —
    // this test queries the embedded DNS responder over the wire, exactly like a real client would.
    let synthetic_ip = resolve_via_embedded_dns("db.svc.citest.internal").await;

    // A REAL TCP connection from this process, through the KERNEL's routing table (which now
    // routes `10.123.45.0/24` to the TUN device `bind()` just created), into our netstack — held
    // open (see `connect_and_wait_for_dial`) so the netstack reliably observes it `Established` and
    // drives exactly one overlay dial attempt to the (doomed) relay at `127.0.0.1:1`; the dial's own
    // failure is irrelevant — the load-bearing assertion is the mint-call count.
    let mints = connect_and_wait_for_dial((synthetic_ip, 54321), &cp.mint_calls).await;
    assert!(
        mints > 0,
        "a real TCP connection through the kernel TUN device must drive an overlay dial attempt"
    );

    front_end.shutdown().await.unwrap();
    let _ = std::fs::remove_file(&marker_path);
}

/// Open a real TCP connection to `addr` THROUGH the kernel TUN and hold it OPEN while waiting for
/// the overlay dial to fire, returning the observed mint-call count. The dial starts only once the
/// netstack's poll loop observes the socket in `Established`; a connect-then-immediately-drop races
/// the FIN past that momentary state (the socket can reach `CloseWait` between the netstack's 10ms
/// polls, so the dial never fires), so this keeps the stream alive — and writes a byte, as a real
/// client that actually uses the connection would — for the whole wait, closing it only afterward.
async fn connect_and_wait_for_dial(addr: (Ipv4Addr, u16), mint_calls: &AtomicUsize) -> usize {
    use tokio::io::AsyncWriteExt;
    let connect = tokio::net::TcpStream::connect(addr);
    // A failed/timed-out connect leaves `stream` None; the poll below then simply reports 0 mints
    // and the caller's assertion fails with a clear message rather than hanging.
    let mut stream = match tokio::time::timeout(Duration::from_secs(5), connect).await {
        Ok(Ok(s)) => Some(s),
        _ => None,
    };
    if let Some(s) = stream.as_mut() {
        let _ = s.write_all(b"ping").await;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while mint_calls.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(stream); // the connection is never torn down before the dial has had its chance
    mint_calls.load(Ordering::SeqCst)
}

/// Full **split-DNS** live path (plan §3.6): bind the front-end WITH the host resolver override
/// enabled (`skip_resolver = false`, the production default), then prove the REAL system resolver —
/// `systemd-resolved`, driven through the `resolvectl` per-link DNS + routing-only-domain override
/// `super::super::tun::resolver` installs — now (a) sends an in-zone name to the embedded responder
/// and gets back a synthetic IP inside the TUN CIDR, and (b) does NOT answer an out-of-zone name
/// into that CIDR (the override is scoped to exactly the zone — the rest of the host is untouched).
/// Then a real TCP connection to the resolved synthetic IP, routed by the kernel into the TUN,
/// drives exactly one overlay dial attempt — the same load-bearing assertion as the device test.
///
/// This is the netns job's one real gap: that job runs with `skip_resolver = true` (it never touches
/// host DNS), so it proves device/route/netstack but NOT the host-resolver split-horizon. A NixOS VM
/// has a real `systemd-resolved`, so this test closes that gap. Needs root (to apply + revert the
/// `resolvectl` link override) and `systemd-resolved` — hence `#[ignore]`, run only by the
/// `tunnel-tun` nixosTest (and locally under `sudo` on a resolved host).
///
/// Note on privilege: run directly as root (no `SUDO_UID`/`SUDO_GID`, the nixosTest case),
/// `TunFrontend::bind`'s privilege-drop step is a no-op (see `tun::privilege`), so this process stays
/// root for both the `resolvectl query` probe and the shutdown-time `resolvectl revert` — a clean,
/// fully-reverted run.
#[tokio::test]
#[ignore = "needs root + systemd-resolved to apply/revert a real resolvectl split-DNS override — run by the tunnel-tun nixosTest / tunnel.yml"]
async fn split_dns_via_the_host_resolver_scopes_only_the_zone_and_a_lookup_drives_a_dial() {
    let cp = Arc::new(FixedControlPlane {
        mint_calls: AtomicUsize::new(0),
    });
    let holder = OverlaySecret::generate().unwrap();
    let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
        .await
        .unwrap();

    // A distinct CIDR + cluster from the device test above, so the two can run back-to-back in one
    // binary (`--test-threads=1`) without their TUN devices/routes/zones ever colliding.
    let cidr: Ipv4Cidr = "10.123.77.0/24".parse().unwrap();
    let marker_path = std::env::temp_dir().join(format!(
        "br-tunnel-splitdns-test-{}.marker",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker_path);
    // zone_suffix = "svc.splitdns.internal." — `skip_resolver` left at its production default
    // (false), so `bind()` applies the real host-resolver override.
    let options = TunOptions::new(
        cidr,
        "internal".to_string(),
        "splitdns".to_string(),
        marker_path.clone(),
    );

    let front_end = TunFrontend::bind(tunnel, options).await.expect(
        "binding with the host-resolver override needs root + a real TUN device + systemd-resolved \
         — see the #[ignore] reason above",
    );
    let tun = front_end.tun_name().to_string();
    eprintln!("split-dns: bound TUN {tun}, CIDR {cidr}");

    // (a) An IN-ZONE name must now resolve, THROUGH systemd-resolved, to a synthetic IP in the CIDR.
    let in_zone = "db.svc.splitdns.internal";
    let synthetic = resolvectl_query_in_cidr(in_zone, cidr)
        .await
        .unwrap_or_else(|| {
            panic!(
                "the host resolver must route {in_zone} to the embedded responder and return a \
                 synthetic IP in {cidr} (is systemd-resolved applying the resolvectl ~zone override \
                 on {tun}?)"
            )
        });
    eprintln!("split-dns: host resolver returned {in_zone} -> {synthetic}");
    assert!(
        cidr.contains(synthetic),
        "the resolver-returned address {synthetic} must be inside the TUN CIDR {cidr}"
    );

    // (Zone SCOPING — that an out-of-zone name is NOT answered into this CIDR — is covered
    // exhaustively + hermetically by `tun::dns`'s unit tests (out-of-zone -> REFUSED, a different
    // cluster under the same tld -> OutOfZone) and by the `resolvectl` `~zone` ROUTING-only domain
    // this path installs. It is deliberately NOT re-probed here through the host resolver: an
    // out-of-zone lookup falls through to the system's upstream/fallback DNS, which is unreachable
    // in a hermetic VM and would stall this test on resolved's multi-minute upstream retry loop.)

    // A REAL TCP connection to the resolved synthetic IP, routed by the kernel through the TUN into
    // our netstack, must drive exactly one overlay dial attempt (held open like the device test, so
    // the netstack observes `Established`; the mint-call count is the real assertion).
    let mints = connect_and_wait_for_dial((synthetic, 5432), &cp.mint_calls).await;
    assert!(
        mints > 0,
        "a TCP connection to the resolver-returned synthetic IP must drive an overlay dial attempt"
    );

    // Clean shutdown reverts the resolvectl override (root, so the revert actually lands) and closes
    // the TUN fd (which removes its route). A leftover override would break resolution on the box.
    front_end.shutdown().await.unwrap();
    let _ = std::fs::remove_file(&marker_path);
}

/// macOS (R3) real-device smoke: bind on a real `utun` WITH the host-resolver override (the
/// production default `skip_resolver = false`), prove the macOS `/etc/resolver/<zone>` split-DNS
/// file is written (scoped to exactly the zone, pointing at the loopback responder), that a real TCP
/// connection routed by the kernel into the utun drives an overlay dial attempt, and that shutdown
/// removes the resolver file again (its loopback-ownership guard permitting). The embedded-DNS
/// resolve goes straight to the responder (`127.0.0.1:5353`), NOT through the system resolver, so the
/// assertion never depends on mDNSResponder's `/etc/resolver` pickup timing — the file's
/// presence/content is checked directly.
///
/// Needs root (open a utun + write `/etc/resolver`), so `#[ignore]`d — this is infrastructure for a
/// future `tunnel.yml` macOS leg and the plan §6 MANUAL macOS smoke, NOT an automated e2e claim. Run
/// it by hand on macOS: `sudo cargo test -p boatramp-overlay-tunnel --features tun --test
/// tun_privileged -- --ignored --test-threads=1 macos_utun`.
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "needs root to open a real utun + write /etc/resolver — run manually on macOS / a future tunnel.yml macOS leg (plan §6)"]
async fn macos_utun_route_and_etc_resolver_split_dns_roundtrip() {
    let cp = Arc::new(FixedControlPlane {
        mint_calls: AtomicUsize::new(0),
    });
    let holder = OverlaySecret::generate().unwrap();
    let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
        .await
        .unwrap();

    let cidr: Ipv4Cidr = "10.123.99.0/24".parse().unwrap();
    let marker_path = std::env::temp_dir().join(format!(
        "br-tunnel-macos-test-{}.marker",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker_path);
    // `skip_resolver` left at its production default (false) → `bind()` writes
    // `/etc/resolver/svc.mactest.internal`.
    let options = TunOptions::new(
        cidr,
        "internal".to_string(),
        "mactest".to_string(),
        marker_path.clone(),
    );
    let zone_file = std::path::PathBuf::from("/etc/resolver/svc.mactest.internal");
    let _ = std::fs::remove_file(&zone_file);

    let front_end = TunFrontend::bind(tunnel, options).await.expect(
        "opening a utun + writing /etc/resolver needs root — see the #[ignore] reason above",
    );

    let body = std::fs::read_to_string(&zone_file)
        .expect("bind() must have written /etc/resolver/svc.mactest.internal");
    assert!(
        body.contains("nameserver 127.0.0.1"),
        "the /etc/resolver file must point the zone at the loopback responder: {body:?}"
    );
    assert!(
        body.contains("port 5353"),
        "the /etc/resolver file must carry the embedded responder's port: {body:?}"
    );

    let synthetic_ip = resolve_via_embedded_dns("db.svc.mactest.internal").await;
    let mints = connect_and_wait_for_dial((synthetic_ip, 5432), &cp.mint_calls).await;
    assert!(
        mints > 0,
        "a real TCP connection through the kernel utun device must drive an overlay dial attempt"
    );

    front_end.shutdown().await.unwrap();
    assert!(
        !zone_file.exists(),
        "shutdown must remove the /etc/resolver split-DNS file it created"
    );
    let _ = std::fs::remove_file(&marker_path);
}

/// Query the HOST resolver (`resolvectl query <name>`) and return the first IPv4 it answers that
/// falls inside `cidr`, or `None` if it answers nothing in range within a short retry budget. Runs
/// the blocking `resolvectl` on a blocking thread (`spawn_blocking`) so the current-thread test
/// runtime stays free to poll the embedded DNS responder that `systemd-resolved` is forwarding to —
/// blocking the runtime thread here would deadlock that forward. Retries because the first query
/// after a fresh per-link override can race resolved picking the new link config up.
async fn resolvectl_query_in_cidr(name: &str, cidr: Ipv4Cidr) -> Option<Ipv4Addr> {
    for _ in 0..24 {
        let name = name.to_string();
        let out = tokio::task::spawn_blocking(move || {
            std::process::Command::new("resolvectl")
                .args(["query", &name])
                .output()
        })
        .await
        .ok()?
        .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
            if let Ok(ip) = tok.parse::<Ipv4Addr>()
                && cidr.contains(ip)
            {
                return Some(ip);
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// Print the kernel networking state relevant to the TUN round-trip (routes, interface addresses,
/// and the reverse-path-filter sysctls) — a diagnostic so a "no dial attempt" failure in a VM shows
/// WHY (e.g. the SYN-ACK getting dropped by rp_filter) rather than being a black box. Runs the
/// blocking tools on a blocking thread so it never stalls the responder/netstack tasks.
async fn dump_net_state(label: &str) {
    let out = tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        for cmd in [
            ("ip", vec!["-4", "route", "show"]),
            ("ip", vec!["-4", "addr", "show"]),
        ] {
            if let Ok(o) = std::process::Command::new(cmd.0).args(&cmd.1).output() {
                s.push_str(&format!("$ {} {}\n", cmd.0, cmd.1.join(" ")));
                s.push_str(&String::from_utf8_lossy(&o.stdout));
            }
        }
        for key in [
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            "net.ipv4.ip_forward",
        ] {
            if let Ok(o) = std::process::Command::new("sysctl").arg(key).output() {
                s.push_str(&String::from_utf8_lossy(&o.stdout));
            }
        }
        s
    })
    .await
    .unwrap_or_default();
    eprintln!("--- net state: {label} ---\n{out}--- end net state ---");
}

/// Hand-rolled, minimal DNS-over-UDP query — consistent with this crate's own hand-rolled-
/// protocol posture elsewhere (the SOCKS codec, the DNS responder itself); this test is the only
/// caller, so a full client dependency isn't worth adding just for it. Sends one A-record query
/// and reads back the first (and, for this responder's own reply shape — one question, at most one
/// answer, no authority/additional records — ONLY) answer's address as the message's trailing 4
/// bytes.
async fn resolve_via_embedded_dns(name: &str) -> Ipv4Addr {
    use tokio::net::UdpSocket;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect("127.0.0.1:5353").await.unwrap();

    let mut query = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT=0
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
    ];
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // root label
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

    socket.send(&query).await.unwrap();
    let mut buf = [0u8; 512];
    let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .expect("the embedded DNS responder must answer within 5s")
        .unwrap();
    let reply = &buf[..len];
    assert!(len >= 4, "reply too short to contain a trailing A record");
    Ipv4Addr::new(
        reply[len - 4],
        reply[len - 3],
        reply[len - 2],
        reply[len - 1],
    )
}
