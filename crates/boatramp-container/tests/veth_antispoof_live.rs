//! LIVE gate for the native **container** backend's per-veth L2/L3 anti-spoof: proves, on a
//! real kernel with real `nftables`, that (1) the EXACT production `VethNetwork` filtered
//! `host_setup`/`teardown` path is accepted at runtime (create the veth pair, install the
//! per-port `bridge` anti-spoof table on the HOST veth, enslave, then tear it all down), and
//! (2) a counter-instrumented twin of the same ruleset drops every crafted spoof shape
//! (wrong MAC, spoofed source IP, spoofed ARP sender-IP, spoofed ARP sender-HW,
//! non-ARP/non-IPv4 ethertype incl. 802.1Q VLAN and QinQ) injected FROM the container end of
//! the veth, while letting exactly the two legitimate frames (pinned-IP IPv4 + pinned ARP)
//! through.
//!
//! This is the container-veth twin of `boatramp-firecracker`'s `antispoof_live.rs` (the VMM
//! tap gate): the two backends install the SAME ruleset via the SAME shared primitive
//! (`boatramp_firecracker::net::antispoof_install_commands`), just hooked on a `vth-*` host
//! port instead of a `tap-*`. The frame builders below are copied from that test.
//!
//! `#[ignore]`d by default — it needs **root**, `nftables`, `iproute2`, and `CAP_NET_RAW`
//! (an `AF_PACKET` injector). Wired as a HARD success-marker gate on the KVM/sudo capability
//! lane (`.github/workflows/capability.yml`). No KVM, no snapshot — only host L2 plumbing.
//!
//! Run locally on a Linux box:
//! ```text
//! sudo -E cargo test -p boatramp-container --test veth_antispoof_live \
//!   -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::process::Command;
use std::time::{Duration, Instant};

use boatramp_container::VethNetwork;

// The pinned identity under test. The MAC is exactly `IpPool::mac_for(10.0.0.5)` —
// `02:00:<the four IPv4 octets>` — i.e. what the container backend pins on `eth0`.
const TEST_IP: &str = "10.0.0.5";
const TEST_MAC: &str = "02:00:0a:00:00:05";
const PINNED_MAC: [u8; 6] = [0x02, 0x00, 0x0a, 0x00, 0x00, 0x05];
const PINNED_IP: [u8; 4] = [10, 0, 0, 5];
const WRONG_MAC: [u8; 6] = [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef];
const SPOOFED_IP: [u8; 4] = [10, 0, 0, 99];
const BCAST: [u8; 6] = [0xff; 6];

// ≤15-char ifnames. `VM_ID` = `as0` ⇒ host veth `vth-as0`, peer `cth-as0`, and the
// production anti-spoof table is `brl2-vth-as0` (what `VethNetwork::teardown` deletes).
const BRIDGE: &str = "brt-as0";
const VM_ID: &str = "as0";
const HOST_VETH: &str = "vth-as0";
const PEER_VETH: &str = "cth-as0";
// The counter-instrumented twin table used for the behavioural phase (named so its teardown
// is independent of the production `brl2-vth-as0` table).
const TWIN: &str = "brl2test-as0";

/// Run a command, returning (success, combined-output-for-logs).
fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {program} {args:?}: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// Run a command and assert it succeeded.
fn must(program: &str, args: &[&str]) {
    let (ok, text) = run(program, args);
    assert!(ok, "`{program} {}` failed: {text}", args.join(" "));
}

/// Best-effort delete (ignore failure) — pre-clean + teardown of twin resources.
fn best_effort(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}

/// Build an Ethernet frame: dst, src, ethertype, payload. (From `antispoof_live.rs`.)
fn eth(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(dst);
    f.extend_from_slice(src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A minimal (20-byte) IPv4 header with the given source address. (From `antispoof_live.rs`.)
fn ipv4_hdr(saddr: &[u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, // version=4, IHL=5, DSCP/ECN
        0x00, 0x14, // total length = 20
        0x00, 0x00, 0x00, 0x00, // id, flags/frag
        0x40, 0x11, // TTL=64, proto=UDP(17)
        0x00, 0x00, // header checksum (0 — not verified for the match)
    ];
    h.extend_from_slice(saddr); // source address (bytes 12..16)
    h.extend_from_slice(&[10, 0, 0, 1]); // dest address (the gateway)
    h
}

/// A minimal ARP (request) body: sender-HW `sha` + sender-IP `spa`. (From `antispoof_live.rs`.)
fn arp_body(sha: &[u8; 6], spa: &[u8; 4]) -> Vec<u8> {
    let mut b = vec![
        0x00, 0x01, // htype = Ethernet
        0x08, 0x00, // ptype = IPv4
        0x06, 0x04, // hlen=6, plen=4
        0x00, 0x01, // oper = request
    ];
    b.extend_from_slice(sha); // sender hardware address
    b.extend_from_slice(spa); // sender protocol address
    b.extend_from_slice(&[0u8; 6]); // target hardware address
    b.extend_from_slice(&[0u8; 4]); // target protocol address
    b
}

/// Inject a raw Ethernet `frame` out `ifname` (the container end `cth-*`) via an `AF_PACKET`
/// `SOCK_RAW` socket. The frame egresses `cth-*`, arrives at its veth peer `vth-*`, and
/// ingresses the bridge from `iifname vth-*` — exactly where the anti-spoof chain evaluates.
/// This is the veth analogue of writing to the tap fd in `antispoof_live.rs`.
fn inject(ifname: &str, frame: &[u8]) {
    use nix::libc;
    let cname = CString::new(ifname).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    assert!(ifindex != 0, "if_nametoindex({ifname})");
    // SOCK_RAW, protocol 0: send-only (we never receive), frame sent verbatim.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    assert!(
        fd >= 0,
        "AF_PACKET socket: {}",
        std::io::Error::last_os_error()
    );
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&BCAST); // dest for SOCK_RAW; frame carries its own
    let ret = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            std::ptr::addr_of!(sll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    let err = (ret < 0).then(std::io::Error::last_os_error);
    unsafe { libc::close(fd) };
    assert!(err.is_none(), "sendto on {ifname}: {}", err.unwrap());
}

/// Read a named nft counter's packet count (`nft list counter bridge <TWIN> <name>`).
fn counter_packets(name: &str) -> u64 {
    let (ok, text) = run("nft", &["list", "counter", "bridge", TWIN, name]);
    assert!(ok, "read counter {name}: {text}");
    let toks: Vec<&str> = text.split_whitespace().collect();
    let i = toks
        .iter()
        .position(|t| *t == "packets")
        .unwrap_or_else(|| panic!("no `packets` in counter {name}: {text}"));
    toks[i + 1]
        .parse()
        .unwrap_or_else(|e| panic!("bad packet count for {name} ({:?}): {e}", toks[i + 1]))
}

/// Pre-clean any leftovers from a prior crashed run, so the gate is idempotent.
fn pre_clean() {
    best_effort("nft", &["delete", "table", "bridge", TWIN]);
    best_effort("nft", &["delete", "table", "bridge", "brl2-vth-as0"]);
    best_effort("ip", &["link", "del", HOST_VETH]);
    best_effort("ip", &["link", "del", PEER_VETH]);
    best_effort("ip", &["link", "del", BRIDGE]);
}

/// Poll until the host veth's bridge port is forwarding (STP off ⇒ immediate; poll to be
/// robust), up to `budget`.
fn wait_forwarding(port: &str, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let (_ok, text) = run("bridge", &["-j", "link", "show", "dev", port]);
        if text.contains("\"forwarding\"") || text.contains("\"disabled\"") {
            return;
        }
        if Instant::now() >= deadline {
            eprintln!("warning: port {port} not observed FORWARDING within budget: {text}");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root + nftables + CAP_NET_RAW (CI KVM/sudo capability lane)"]
async fn veth_antispoof_accepts_production_rules_and_drops_spoofed_frames() {
    pre_clean();

    // --- the bridge: STP off + forward_delay 0 so the port forwards immediately ---
    must(
        "ip",
        &[
            "link",
            "add",
            BRIDGE,
            "type",
            "bridge",
            "stp_state",
            "0",
            "forward_delay",
            "0",
        ],
    );
    must("ip", &["addr", "add", "10.0.0.1/24", "dev", BRIDGE]);
    must("ip", &["link", "set", BRIDGE, "up"]);

    // === Phase A — runtime-acceptance of the EXACT production filtered veth path ===
    // Build the veth the way the container backend does under the enforced posture, with the
    // per-port anti-spoof filter bound to the pinned (IP, MAC), and run the production
    // `host_setup` (create pair → host up → install nft filter → enslave) + `teardown`
    // (delete table → delete pair), asserting both succeed on this live kernel.
    let prod = VethNetwork::for_vm_filtered(VM_ID, BRIDGE, TEST_IP, TEST_MAC);
    assert_eq!(
        prod.host_veth, HOST_VETH,
        "host veth name must match hardcoded ifnames"
    );
    assert_eq!(
        prod.peer_veth, PEER_VETH,
        "peer veth name must match hardcoded ifnames"
    );
    assert_eq!(prod.filter_table(), "brl2-vth-as0");
    prod.host_setup()
        .await
        .expect("production filtered host_setup accepted on a live kernel");
    prod.teardown()
        .await
        .expect("production teardown accepted on a live kernel");

    // === Phase B — behaviour via a counter-instrumented twin of the SAME ruleset ===
    // Recreate the veth pair directly (the production filter was just torn down): host end on
    // the bridge, peer end up on the host so we can inject from it.
    must(
        "ip",
        &[
            "link", "add", HOST_VETH, "type", "veth", "peer", "name", PEER_VETH,
        ],
    );
    must("ip", &["link", "set", HOST_VETH, "up"]);
    must("ip", &["link", "set", PEER_VETH, "up"]);
    must("ip", &["link", "set", HOST_VETH, "master", BRIDGE]);

    // The twin table mirrors the production `antispoof_install_commands` match-for-match, in
    // the same order, with a NAMED counter on each drop rule plus a trailing accept counter.
    must("nft", &["add", "table", "bridge", TWIN]);
    must(
        "nft",
        &[
            "add",
            "chain",
            "bridge",
            TWIN,
            "as",
            "{ type filter hook prerouting priority -300 ; policy accept ; }",
        ],
    );
    for c in [
        "c_mac",
        "c_arpip",
        "c_arpether",
        "c_ip",
        "c_ether",
        "c_accept",
    ] {
        must("nft", &["add", "counter", "bridge", TWIN, c]);
    }
    let iface = format!("\"{HOST_VETH}\"");
    must(
        "nft",
        &[
            "add", "rule", "bridge", TWIN, "as", "iifname", &iface, "ether", "saddr", "!=",
            TEST_MAC, "counter", "name", "c_mac", "drop",
        ],
    );
    must(
        "nft",
        &[
            "add", "rule", "bridge", TWIN, "as", "iifname", &iface, "arp", "saddr", "ip", "!=",
            TEST_IP, "counter", "name", "c_arpip", "drop",
        ],
    );
    must(
        "nft",
        &[
            "add",
            "rule",
            "bridge",
            TWIN,
            "as",
            "iifname",
            &iface,
            "arp",
            "saddr",
            "ether",
            "!=",
            TEST_MAC,
            "counter",
            "name",
            "c_arpether",
            "drop",
        ],
    );
    must(
        "nft",
        &[
            "add", "rule", "bridge", TWIN, "as", "iifname", &iface, "ip", "saddr", "!=", TEST_IP,
            "counter", "name", "c_ip", "drop",
        ],
    );
    must(
        "nft",
        &[
            "add",
            "rule",
            "bridge",
            TWIN,
            "as",
            "iifname",
            &iface,
            "ether",
            "type",
            "!=",
            "{ arp, ip }",
            "counter",
            "name",
            "c_ether",
            "drop",
        ],
    );
    must(
        "nft",
        &[
            "add", "rule", "bridge", TWIN, "as", "iifname", &iface, "counter", "name", "c_accept",
            "accept",
        ],
    );

    // Cross-check: the production ruleset (what the backend actually installs via the shared
    // primitive) carries the SAME matches, so the twin can't silently drift from it.
    let prod_lines: Vec<String> = prod
        .antispoof_install_commands()
        .iter()
        .map(ToString::to_string)
        .collect();
    for needle in [
        format!("ether saddr != {TEST_MAC} drop"),
        format!("arp saddr ip != {TEST_IP} drop"),
        format!("arp saddr ether != {TEST_MAC} drop"),
        format!("ip saddr != {TEST_IP} drop"),
        "ether type != { arp, ip } drop".to_string(),
    ] {
        assert!(
            prod_lines.iter().any(|l| l.contains(needle.as_str())),
            "production ruleset is missing `{needle}` — the twin has drifted"
        );
    }
    // And the production ruleset hooks the HOST veth, never the container/peer end.
    assert!(
        prod_lines.iter().any(|l| l.contains("\"vth-as0\"")),
        "production ruleset must match iifname vth-as0"
    );
    assert!(
        prod_lines.iter().all(|l| !l.contains("cth-as0")),
        "production ruleset must NOT match the container/peer end"
    );

    wait_forwarding(HOST_VETH, Duration::from_secs(3));

    // --- inject the crafted frames FROM the container end (ingress on iifname vth-as0) ---
    let frames: Vec<(&str, Vec<u8>)> = vec![
        // A: pinned MAC + pinned source IP → ACCEPT.
        (
            "A pinned-IP IPv4",
            eth(&BCAST, &PINNED_MAC, 0x0800, &ipv4_hdr(&PINNED_IP)),
        ),
        // B: wrong source MAC → MAC drop.
        (
            "B wrong-MAC",
            eth(&BCAST, &WRONG_MAC, 0x0800, &ipv4_hdr(&PINNED_IP)),
        ),
        // C: pinned MAC but spoofed source IP → IP drop.
        (
            "C spoofed-IP",
            eth(&BCAST, &PINNED_MAC, 0x0800, &ipv4_hdr(&SPOOFED_IP)),
        ),
        // D: ARP with spoofed sender IP → ARP-IP drop.
        (
            "D spoofed-ARP-ip",
            eth(
                &BCAST,
                &PINNED_MAC,
                0x0806,
                &arp_body(&PINNED_MAC, &SPOOFED_IP),
            ),
        ),
        // E: IPv6 ethertype → ethertype drop.
        ("E IPv6", eth(&BCAST, &PINNED_MAC, 0x86dd, &[0u8; 40])),
        // F: ARP with pinned sender IP + pinned sender HW → ACCEPT.
        (
            "F pinned-ARP",
            eth(
                &BCAST,
                &PINNED_MAC,
                0x0806,
                &arp_body(&PINNED_MAC, &PINNED_IP),
            ),
        ),
        // G: ARP with pinned sender IP but WRONG sender HW → ARP-HW drop.
        (
            "G ARP-wrong-HW",
            eth(
                &BCAST,
                &PINNED_MAC,
                0x0806,
                &arp_body(&WRONG_MAC, &PINNED_IP),
            ),
        ),
        // VLAN (802.1Q): outer ethertype 0x8100 → ethertype drop.
        (
            "VLAN 802.1Q",
            eth(&BCAST, &PINNED_MAC, 0x8100, &{
                let mut v = vec![0x00, 0x64, 0x08, 0x00]; // vid=100, inner=IPv4
                v.extend_from_slice(&ipv4_hdr(&SPOOFED_IP));
                v
            }),
        ),
        // QinQ (802.1ad): outer ethertype 0x88a8 → ethertype drop.
        (
            "QinQ 802.1ad",
            eth(&BCAST, &PINNED_MAC, 0x88a8, &{
                let mut v = vec![0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x08, 0x00];
                v.extend_from_slice(&ipv4_hdr(&SPOOFED_IP));
                v
            }),
        ),
    ];
    for (label, frame) in &frames {
        inject(PEER_VETH, frame);
        eprintln!("injected {label}");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(200));

    // --- assert the per-rule counters + the accept counter ---
    let mac = counter_packets("c_mac");
    let arpip = counter_packets("c_arpip");
    let arpether = counter_packets("c_arpether");
    let ip = counter_packets("c_ip");
    let ether = counter_packets("c_ether");
    let accept = counter_packets("c_accept");
    eprintln!(
        "veth anti-spoof counters: mac={mac} arp_ip={arpip} arp_ether={arpether} ip={ip} \
         ethertype={ether} accept={accept}"
    );

    assert_eq!(
        mac, 1,
        "wrong-MAC frame B must hit the MAC drop exactly once"
    );
    assert_eq!(
        arpip, 1,
        "spoofed-ARP-IP frame D must hit the ARP-IP drop once"
    );
    assert_eq!(
        arpether, 1,
        "ARP-wrong-HW frame G must hit the ARP-HW drop once"
    );
    assert_eq!(ip, 1, "spoofed-source-IP frame C must hit the IP drop once");
    assert_eq!(
        ether, 3,
        "IPv6 + VLAN + QinQ must all hit the ethertype drop"
    );
    // The load-bearing invariant: ONLY the two legitimate frames reach accept.
    assert_eq!(
        accept, 2,
        "exactly two frames (A pinned-IP IPv4 + F pinned ARP) may be accepted; a VLAN/QinQ or \
         any spoof reaching accept is a bypass"
    );

    // --- teardown: the twin + veth pair + bridge; assert the delete commands succeed ---
    must("nft", &["delete", "table", "bridge", TWIN]);
    must("ip", &["link", "del", HOST_VETH]);
    must("ip", &["link", "del", BRIDGE]);

    // SUCCESS MARKER — printed ONLY after every assertion passed. The capability lane greps
    // for this exact line to defeat a silent skip (0 tests run / cfg'd out).
    println!(
        "VETH-ANTISPOOF-LIVE-OK: accept==2, all spoof shapes dropped, production filtered \
         host_setup/teardown accepted"
    );
}
