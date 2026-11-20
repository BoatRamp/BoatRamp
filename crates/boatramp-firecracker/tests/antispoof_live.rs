//! LIVE gate for the per-tap L2/L3 anti-spoof (U16): proves, on a real kernel with
//! real `nftables`, that (1) the EXACT production `TapNetwork` setup/teardown command
//! sequences are accepted at runtime, and (2) a counter-instrumented twin of the same
//! ruleset drops every crafted spoof shape (wrong MAC, spoofed source IP, spoofed ARP
//! sender-IP, spoofed ARP sender-HW, non-ARP/non-IPv4 ethertype incl. 802.1Q VLAN and
//! QinQ) while letting exactly the two legitimate frames (pinned-IP IPv4 + pinned ARP)
//! through.
//!
//! `#[ignore]`d by default — it needs **root**, `nftables`, `iproute2`, and
//! `/dev/net/tun`. Wired as a HARD success-marker gate on the KVM/sudo capability
//! lane (`.github/workflows/capability.yml`), alongside the other live seams. It needs
//! no KVM and no snapshot — only the host L2 plumbing.
//!
//! Run locally on a Linux box:
//! ```text
//! sudo -E cargo test -p boatramp-firecracker --features embedded,backend \
//!   --test antispoof_live -- --ignored --nocapture
//! ```

#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]

use std::io::Write;
use std::process::Command;
use std::time::{Duration, Instant};

use boatramp_firecracker::net::TapNetwork;
use boatramp_firecracker::tap::Tap;

// The pinned identity under test. The MAC is exactly `IpPool::mac_for(10.0.0.5)` —
// `02:00:<the four IPv4 octets>` — i.e. what the embedded backend pins for this IP.
const TEST_IP: &str = "10.0.0.5";
const TEST_MAC: &str = "02:00:0a:00:00:05";
const PINNED_MAC: [u8; 6] = [0x02, 0x00, 0x0a, 0x00, 0x00, 0x05];
const PINNED_IP: [u8; 4] = [10, 0, 0, 5];
const WRONG_MAC: [u8; 6] = [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef];
const SPOOFED_IP: [u8; 4] = [10, 0, 0, 99];
const BCAST: [u8; 6] = [0xff; 6];

// ≤15-char ifnames. `VM_ID` ⇒ tap `tap-as0`, and the production anti-spoof table is
// `brl2-tap-as0` (what `TapNetwork::teardown_commands` deletes).
const BRIDGE: &str = "brt-antispoof0";
const VM_ID: &str = "as0";
const TAP: &str = "tap-as0";
// The counter-instrumented twin table used for the behavioural phase (named so its
// teardown is independent of the production `brl2-*` table).
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

/// Run a command and assert it succeeded (for the runtime-acceptance phase).
fn must(program: &str, args: &[&str]) {
    let (ok, text) = run(program, args);
    assert!(ok, "`{program} {}` failed: {text}", args.join(" "));
}

/// Best-effort delete (ignore failure) — pre-clean + teardown of twin resources.
fn best_effort(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}

/// Build an Ethernet frame: dst, src, ethertype, payload.
fn eth(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(dst);
    f.extend_from_slice(src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A minimal (20-byte) IPv4 header with the given source address (UDP, no payload) —
/// enough for nft's `ip saddr` to read bytes 12–15 of the IP header.
fn ipv4_hdr(saddr: &[u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, // version=4, IHL=5, DSCP/ECN
        0x00, 0x14, // total length = 20
        0x00, 0x00, 0x00, 0x00, // id, flags/frag
        0x40, 0x11, // TTL=64, proto=UDP(17)
        0x00, 0x00, // header checksum (0 — the kernel/nft don't verify for the match)
    ];
    h.extend_from_slice(saddr); // source address (bytes 12..16)
    h.extend_from_slice(&[10, 0, 0, 1]); // dest address (the gateway)
    h
}

/// A minimal ARP (request) body: sender-HW `sha` + sender-IP `spa` are what nft's
/// `arp saddr ether` / `arp saddr ip` read.
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

/// Read a named nft counter's packet count (`nft list counter bridge <TWIN> <name>`).
fn counter_packets(name: &str) -> u64 {
    let (ok, text) = run("nft", &["list", "counter", "bridge", TWIN, name]);
    assert!(ok, "read counter {name}: {text}");
    // Parse "... packets N bytes M ...".
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
    best_effort("nft", &["delete", "table", "bridge", "brl2-tap-as0"]);
    best_effort("ip", &["link", "del", TAP]);
    best_effort("ip", &["link", "del", BRIDGE]);
}

#[test]
#[ignore = "needs root + nftables + /dev/net/tun (CI KVM/sudo capability lane)"]
fn tap_antispoof_accepts_production_rules_and_drops_spoofed_frames() {
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

    // === Phase A — runtime-acceptance of the EXACT production command sequences ===
    // Build the tap the way the embedded backend does, with the per-tap anti-spoof
    // filter bound to the pinned (IP, MAC), and run the production setup sequence,
    // asserting every `ip`/`nft` command exits 0 on this live kernel.
    let prod = TapNetwork::for_vm_filtered(VM_ID, BRIDGE, TEST_IP, TEST_MAC);
    assert_eq!(
        prod.tap_name, TAP,
        "tap name must match the hardcoded ifnames"
    );
    for cmd in prod.setup_commands() {
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        must(&cmd.program, &args);
    }
    // And the production teardown (deletes the `brl2-tap-as0` table + the device).
    for cmd in prod.teardown_commands() {
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        must(&cmd.program, &args);
    }

    // === Phase B — behaviour via a counter-instrumented twin of the SAME ruleset ===
    // Re-create the tap and enslave it (the production filter was just torn down).
    must("ip", &["tuntap", "add", TAP, "mode", "tap"]);
    must("ip", &["link", "set", TAP, "up"]);
    must("ip", &["link", "set", TAP, "master", BRIDGE]);

    // The twin table mirrors `TapNetwork::antispoof_commands` match-for-match, in the
    // same order, with a NAMED counter on each drop rule plus a trailing accept
    // counter. (If the production rule set changes, this twin must change in lockstep;
    // the cross-check below asserts the production commands carry the same matches.)
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
    let iface = format!("\"{TAP}\"");
    // Same matches + order as the production chain.
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

    // Cross-check: the production anti-spoof matches the twin's (so the twin can't
    // silently drift from what the backend actually installs).
    let prod_lines: Vec<String> = prod
        .setup_commands()
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

    // Wait for the tap's bridge port to reach FORWARDING before injecting (STP is off,
    // so this is immediate, but poll to be robust).
    wait_forwarding(TAP, Duration::from_secs(3));

    // --- inject the crafted frames from the tap (ingress on `iifname tap-as0`) ---
    let mut tx = Tap::open(TAP).expect("open tap for injection");
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
        // G: ARP with pinned sender IP but WRONG sender HW → ARP-HW drop (U16 LOW 3a).
        (
            "G ARP-wrong-HW",
            eth(
                &BCAST,
                &PINNED_MAC,
                0x0806,
                &arp_body(&WRONG_MAC, &PINNED_IP),
            ),
        ),
        // VLAN (802.1Q): outer ethertype 0x8100 with a spoofed inner → ethertype drop.
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
        tx.write_all(frame)
            .unwrap_or_else(|e| panic!("inject {label}: {e}"));
        tx.flush().ok();
        std::thread::sleep(Duration::from_millis(50));
    }
    // Let the last frame traverse the hook before reading counters.
    std::thread::sleep(Duration::from_millis(200));

    // --- assert the per-rule counters + the accept counter ---
    let mac = counter_packets("c_mac");
    let arpip = counter_packets("c_arpip");
    let arpether = counter_packets("c_arpether");
    let ip = counter_packets("c_ip");
    let ether = counter_packets("c_ether");
    let accept = counter_packets("c_accept");
    eprintln!(
        "anti-spoof counters: mac={mac} arp_ip={arpip} arp_ether={arpether} ip={ip} \
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
        "IPv6 + VLAN + QinQ (E + VLAN + QinQ) must all hit the ethertype drop"
    );
    // The load-bearing invariant: ONLY the two legitimate frames reach accept.
    assert_eq!(
        accept, 2,
        "exactly two frames (A pinned-IP IPv4 + F pinned ARP) may be accepted; \
         a VLAN/QinQ or any spoof reaching accept is a bypass"
    );

    // --- teardown: the twin + tap + bridge; assert the delete commands succeed ---
    must("nft", &["delete", "table", "bridge", TWIN]);
    must("ip", &["link", "del", TAP]);
    must("ip", &["link", "del", BRIDGE]);

    // SUCCESS MARKER — printed ONLY after every assertion passed. The capability lane
    // greps for this exact line to defeat a silent skip (0 tests run / cfg'd out).
    println!("ANTISPOOF-LIVE-OK: accept==2, all spoof shapes dropped, production ruleset accepted");
}

/// Poll `bridge -j link show dev <tap>` until the port's STP state is `forwarding`
/// (or `disabled`, which a non-STP bridge reports as "no STP"), up to `budget`.
fn wait_forwarding(tap: &str, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let (_ok, text) = run("bridge", &["-j", "link", "show", "dev", tap]);
        // Accept forwarding, or a bridge with STP disabled (the configured case).
        if text.contains("\"forwarding\"") || text.contains("\"disabled\"") {
            return;
        }
        if Instant::now() >= deadline {
            // Don't fail here — STP is off, so forwarding is expected immediately; the
            // injection assertions are the real gate. Log for diagnosis.
            eprintln!("warning: tap {tap} not observed FORWARDING within budget: {text}");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
