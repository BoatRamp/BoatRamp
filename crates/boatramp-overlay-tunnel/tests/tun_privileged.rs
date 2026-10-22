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

    // The synthetic IP a DNS lookup would hand back for `db.svc.citest.internal.` is deterministic
    // (the allocator's first allocation this run) but `TunFrontend` doesn't expose it directly —
    // this test queries the embedded DNS responder over the wire, exactly like a real client would.
    let synthetic_ip = resolve_via_embedded_dns("db.svc.citest.internal").await;

    // A REAL TCP connection from this process, through the KERNEL's routing table (which now
    // routes `10.123.45.0/24` to the TUN device `bind()` just created), into our netstack. The
    // connection attempt's own outcome is secondary — it races the (doomed) overlay dial to
    // `127.0.0.1:1`, which may tear the socket down before or after the local handshake completes
    // — the load-bearing assertion is the polled mint-call count below.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((synthetic_ip, 54321)),
    )
    .await;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while cp.mint_calls.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        cp.mint_calls.load(Ordering::SeqCst) > 0,
        "a real TCP connection through the kernel TUN device must drive an overlay dial attempt"
    );

    front_end.shutdown().await.unwrap();
    let _ = std::fs::remove_file(&marker_path);
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
