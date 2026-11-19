//! Host network plumbing for microVM tap devices.
//!
//! Firecracker attaches a guest NIC to a host **tap** device; boatramp owns the
//! plumbing (no CNI/container runtime). This module builds the exact `ip`/`nft`
//! command sequences — once per node (the bridge + egress NAT) and once per VM
//! (its tap) — plus their teardown. The command *sequences* are pure and
//! unit-tested; **running** them needs root on a Linux host (the KVM seam), via
//! the [`crate::executor::Host`] runner.

/// One host command to run: a `program` and its `args` (e.g. `ip tuntap add …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCommand {
    /// The executable to run (`ip`, `nft`, `sysctl`, …).
    pub program: String,
    /// The arguments, in order.
    pub args: Vec<String>,
}

impl HostCommand {
    /// Build a command from string slices.
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(std::string::ToString::to_string).collect(),
        }
    }
}

/// Render as a shell-ish line for logs/tests (not for execution).
impl std::fmt::Display for HostCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.args.is_empty() {
            f.write_str(&self.program)
        } else {
            write!(f, "{} {}", self.program, self.args.join(" "))
        }
    }
}

/// Node-level networking: the shared bridge every VM tap attaches to, the
/// bridge's gateway address (the `.1` the guests route through), and the egress
/// uplink that guest traffic is NAT-masqueraded out of. Set up once per KVM node
/// (idempotently — the runner tolerates "already exists").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeNetwork {
    /// The bridge name (e.g. `br-boatramp`).
    pub bridge: String,
    /// The bridge's own address in CIDR form (the guests' gateway, e.g.
    /// `10.0.0.1/24`).
    pub gateway_cidr: String,
    /// The host uplink interface guest egress is masqueraded out of (e.g. `eth0`).
    pub uplink: String,
    /// The nftables table name boatramp owns its NAT rules under.
    pub nat_table: String,
}

impl NodeNetwork {
    /// A node network with boatramp's default bridge/NAT-table names.
    pub fn new(gateway_cidr: &str, uplink: &str) -> Self {
        Self {
            bridge: "br-boatramp".to_string(),
            gateway_cidr: gateway_cidr.to_string(),
            uplink: uplink.to_string(),
            nat_table: "boatramp-nat".to_string(),
        }
    }

    /// Commands to bring up the bridge + egress NAT. Idempotent in intent: the
    /// runner ignores "already exists"/"file exists" failures (see
    /// [`crate::executor::SystemHost`]).
    pub fn setup_commands(&self) -> Vec<HostCommand> {
        vec![
            HostCommand::new("ip", &["link", "add", &self.bridge, "type", "bridge"]),
            HostCommand::new(
                "ip",
                &["addr", "add", &self.gateway_cidr, "dev", &self.bridge],
            ),
            HostCommand::new("ip", &["link", "set", &self.bridge, "up"]),
            // Forward between the bridge and the uplink.
            HostCommand::new("sysctl", &["-w", "net.ipv4.ip_forward=1"]),
            // NAT: masquerade guest egress out of the uplink.
            HostCommand::new("nft", &["add", "table", "ip", &self.nat_table]),
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "chain",
                    "ip",
                    &self.nat_table,
                    "postrouting",
                    "{ type nat hook postrouting priority 100 ; }",
                ],
            ),
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip",
                    &self.nat_table,
                    "postrouting",
                    "oifname",
                    &self.uplink,
                    "masquerade",
                ],
            ),
        ]
    }

    /// Commands to remove the NAT table + bridge (node teardown; best-effort).
    pub fn teardown_commands(&self) -> Vec<HostCommand> {
        vec![
            HostCommand::new("nft", &["delete", "table", "ip", &self.nat_table]),
            HostCommand::new("ip", &["link", "del", &self.bridge]),
        ]
    }
}

/// The per-tap L2/L3 **anti-spoof** binding (U16): the single guest IP + MAC a
/// tap is permitted to source traffic as. Installed as a per-tap nftables `bridge`
/// table so a guest cannot impersonate a neighbor at L2 (a forged source MAC — the
/// VMM MAC is the deterministic, *predictable* `02:00:<ip octets>`, so a neighbor's
/// MAC is trivially guessable) or at L3 (a forged source/ARP-sender IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapFilter {
    /// The one IPv4 the tap may source IP + ARP traffic as (dotted-quad string).
    pub guest_ip: String,
    /// The one MAC the tap's frames may carry as `ether saddr` (`aa:bb:…` string).
    pub guest_mac: String,
}

/// One VM's tap device, attached to a (per-node or per-tenant) bridge. A
/// per-tenant bridge name gives L2 isolation between tenants; full netns/VLAN
/// isolation is not yet implemented. When [`filter`](Self::filter) is set, a
/// per-tap nftables anti-spoof binding (IP + MAC) is installed **before** the tap
/// joins the bridge, so a tap whose filter can't be installed never carries traffic
/// (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapNetwork {
    /// The tap device name (e.g. `tap-<vmid>`; keep ≤ 15 chars for the kernel).
    pub tap_name: String,
    /// The bridge this tap is enslaved to (`NodeNetwork::bridge`, or a per-tenant
    /// bridge).
    pub bridge: String,
    /// The per-tap anti-spoof binding (U16), or `None` for the legacy/external
    /// firecracker path that does not pin a guest IP/MAC.
    pub filter: Option<TapFilter>,
}

impl TapNetwork {
    /// Create the tap for VM id `vm_id` on `bridge`, with **no** anti-spoof filter
    /// (the external `VmmBackend`/`executor` path). The tap name is `tap-<vm_id>`,
    /// truncated to the 15-char interface-name limit.
    pub fn for_vm(vm_id: &str, bridge: &str) -> Self {
        Self {
            tap_name: Self::tap_name(vm_id),
            bridge: bridge.to_string(),
            filter: None,
        }
    }

    /// Create the tap for VM id `vm_id` on `bridge` **bound** to `guest_ip` +
    /// `guest_mac` by a per-tap nftables anti-spoof filter (U16): the embedded-VMM
    /// path, where the guest's IP + (deterministic) MAC are known at launch.
    pub fn for_vm_filtered(vm_id: &str, bridge: &str, guest_ip: &str, guest_mac: &str) -> Self {
        Self {
            tap_name: Self::tap_name(vm_id),
            bridge: bridge.to_string(),
            filter: Some(TapFilter {
                guest_ip: guest_ip.to_string(),
                guest_mac: guest_mac.to_string(),
            }),
        }
    }

    /// `tap-<vm_id>`, truncated to the 15-char `IFNAMSIZ` interface-name limit.
    fn tap_name(vm_id: &str) -> String {
        let mut tap_name = format!("tap-{vm_id}");
        tap_name.truncate(15);
        tap_name
    }

    /// The per-tap nftables `bridge`-family table name owning this tap's anti-spoof
    /// rules (`brl2-<tap>`). A table **per tap** (not shared rules) makes teardown a
    /// single atomic `delete table` — no rule-handle bookkeeping. Hyphens are fine
    /// in an nft table name (the node NAT table `boatramp-nat` already uses one).
    fn filter_table(&self) -> String {
        format!("brl2-{}", self.tap_name)
    }

    /// The anti-spoof install commands for `filter`: a dedicated `bridge`-family
    /// table hooked at `prerouting` that **default-drops** any frame from this tap
    /// whose source MAC isn't the pinned MAC, whose IPv4/ARP sender-IP isn't the
    /// pinned IP, whose ARP sender-**hardware** address isn't the pinned MAC, or
    /// whose ethertype is neither ARP nor IPv4. Only correctly-sourced ARP + IPv4
    /// from the pinned MAC leave the port. Empty when there is no filter.
    ///
    /// LOAD-BEARING INVARIANT: the nft-injection surface is closed ONLY because the
    /// tap name is slug-constrained. `tap_name` is `tap-<vm_id>` where `vm_id` is
    /// built from the project/workload, which `boatramp_core`'s `validate_resource_name`
    /// restricts to `[A-Za-z0-9_-]` — so the name interpolated into these `nft` tokens
    /// (and the `brl2-<tap>` table name) can never carry shell/nft metacharacters. If
    /// that validation is ever loosened, this builder MUST escape/validate the name
    /// itself before trusting it in a rule.
    fn antispoof_commands(&self) -> Vec<HostCommand> {
        let Some(f) = &self.filter else {
            return Vec::new();
        };
        let table = self.filter_table();
        // Interface names are quoted (they contain `-`); nft joins argv with spaces
        // and re-lexes, so the literal quotes make `"tap-x"` a single string token.
        let iface = format!("\"{}\"", self.tap_name);
        vec![
            HostCommand::new("nft", &["add", "table", "bridge", &table]),
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "chain",
                    "bridge",
                    &table,
                    "antispoof",
                    "{ type filter hook prerouting priority -300 ; policy accept ; }",
                ],
            ),
            // MAC anti-spoof: drop any frame not sourced from the pinned MAC.
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "rule",
                    "bridge",
                    &table,
                    "antispoof",
                    "iifname",
                    &iface,
                    "ether",
                    "saddr",
                    "!=",
                    &f.guest_mac,
                    "drop",
                ],
            ),
            // ARP anti-spoof: drop an ARP whose sender-protocol-address isn't the IP.
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "rule",
                    "bridge",
                    &table,
                    "antispoof",
                    "iifname",
                    &iface,
                    "arp",
                    "saddr",
                    "ip",
                    "!=",
                    &f.guest_ip,
                    "drop",
                ],
            ),
            // ARP sender-HARDWARE anti-spoof: drop an ARP whose sender MAC isn't the
            // pinned MAC — blocks a gratuitous-ARP self-redirect that forges only the
            // ARP-level hardware address (the frame's `ether saddr` could still be the
            // pinned MAC, so the MAC rule above would not catch it).
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "rule",
                    "bridge",
                    &table,
                    "antispoof",
                    "iifname",
                    &iface,
                    "arp",
                    "saddr",
                    "ether",
                    "!=",
                    &f.guest_mac,
                    "drop",
                ],
            ),
            // IPv4 anti-spoof: drop an IP packet whose source address isn't the IP.
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "rule",
                    "bridge",
                    &table,
                    "antispoof",
                    "iifname",
                    &iface,
                    "ip",
                    "saddr",
                    "!=",
                    &f.guest_ip,
                    "drop",
                ],
            ),
            // Default-drop: anything that is neither ARP nor IPv4 from this tap.
            HostCommand::new(
                "nft",
                &[
                    "add",
                    "rule",
                    "bridge",
                    &table,
                    "antispoof",
                    "iifname",
                    &iface,
                    "ether",
                    "type",
                    "!=",
                    "{ arp, ip }",
                    "drop",
                ],
            ),
        ]
    }

    /// Commands to create the tap, (optionally) install its anti-spoof filter, and
    /// enslave it to the bridge + bring it up.
    ///
    /// **Fail-closed ordering** (U16): with a filter, the tap is created + brought up,
    /// the anti-spoof table is installed, and **only then** is the tap enslaved to the
    /// bridge — so a caller that aborts on the first failing command (`spawn_worker`)
    /// never lets a tap whose filter failed to install carry traffic. The no-filter
    /// (external/legacy) path is byte-identical to before: create → enslave → up.
    pub fn setup_commands(&self) -> Vec<HostCommand> {
        if self.filter.is_none() {
            return vec![
                HostCommand::new("ip", &["tuntap", "add", &self.tap_name, "mode", "tap"]),
                HostCommand::new(
                    "ip",
                    &["link", "set", &self.tap_name, "master", &self.bridge],
                ),
                HostCommand::new("ip", &["link", "set", &self.tap_name, "up"]),
            ];
        }
        let mut cmds = vec![
            HostCommand::new("ip", &["tuntap", "add", &self.tap_name, "mode", "tap"]),
            HostCommand::new("ip", &["link", "set", &self.tap_name, "up"]),
        ];
        cmds.extend(self.antispoof_commands());
        // Enslave LAST: if any anti-spoof command above failed and the caller aborted,
        // the tap is never on the bridge.
        cmds.push(HostCommand::new(
            "ip",
            &["link", "set", &self.tap_name, "master", &self.bridge],
        ));
        cmds
    }

    /// Commands to delete the tap (best-effort; safe to run on a partial setup).
    /// Removes the per-tap anti-spoof table first (if any), then the device.
    pub fn teardown_commands(&self) -> Vec<HostCommand> {
        let mut cmds = Vec::new();
        if self.filter.is_some() {
            cmds.push(HostCommand::new(
                "nft",
                &["delete", "table", "bridge", &self.filter_table()],
            ));
        }
        cmds.push(HostCommand::new("ip", &["link", "del", &self.tap_name]));
        cmds
    }
}

/// Pure boot-sweep selection (U17): from parsed `/proc/<pid>/cmdline` argv vectors,
/// the pids that are embedded-VMM workers — `argv[1] == subcommand` (the `__vmm-run`
/// marker) — excluding `self_pid`. On a fresh node-process boot there are no live
/// workers yet, so every match is a PRIOR-incarnation orphan the boot sweep SIGKILLs
/// before reissuing any IP/MAC (the in-memory registry does not survive a restart).
/// Keeping the selection pure makes the "never kill the wrong process" property
/// host-testable without walking a live `/proc`.
pub fn orphan_vmm_worker_pids(
    entries: &[(u32, Vec<String>)],
    subcommand: &str,
    self_pid: u32,
) -> Vec<u32> {
    entries
        .iter()
        .filter(|(pid, argv)| {
            *pid != self_pid && argv.get(1).map(String::as_str) == Some(subcommand)
        })
        .map(|(pid, _)| *pid)
        .collect()
}

/// Pure boot-sweep selection (U17): the VMM tap interfaces present on the host that
/// are NOT in `live` (the current in-memory registry's tap names). A VMM tap is named
/// `tap-*` (the container backend uses `vth-*`/`cth-*`, never `tap-*`), so the prefix
/// alone selects this backend's devices. On boot `live` is empty, so every `tap-*` is
/// a prior-incarnation orphan whose device + per-tap anti-spoof table must be reclaimed
/// before a new IP/MAC is reissued onto the same L2.
pub fn stale_vmm_taps(ifaces: &[String], live: &std::collections::BTreeSet<String>) -> Vec<String> {
    ifaces
        .iter()
        .filter(|n| n.starts_with("tap-") && !live.contains(*n))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_name_is_derived_and_length_capped() {
        let tap = TapNetwork::for_vm("web-0", "br-boatramp");
        assert_eq!(tap.tap_name, "tap-web-0");
        // Long workload/replica ids are truncated to the 15-char IFNAMSIZ limit.
        let long = TapNetwork::for_vm("a-very-long-workload-name-7", "br-boatramp");
        assert_eq!(long.tap_name.len(), 15);
        assert!(long.tap_name.starts_with("tap-"));
    }

    #[test]
    fn tap_setup_then_teardown_round_trips_the_device() {
        let tap = TapNetwork::for_vm("vm1", "br-boatramp");
        let setup = tap.setup_commands();
        // create → enslave → up.
        assert_eq!(setup[0].to_string(), "ip tuntap add tap-vm1 mode tap");
        assert_eq!(
            setup[1].to_string(),
            "ip link set tap-vm1 master br-boatramp"
        );
        assert_eq!(setup[2].to_string(), "ip link set tap-vm1 up");
        // Teardown deletes the same device.
        let down = tap.teardown_commands();
        assert_eq!(
            down,
            vec![HostCommand::new("ip", &["link", "del", "tap-vm1"])]
        );
    }

    #[test]
    fn node_setup_brings_up_bridge_forwarding_and_nat() {
        let net = NodeNetwork::new("10.0.0.1/24", "eth0");
        let cmds = net.setup_commands();
        let lines: Vec<String> = cmds.iter().map(HostCommand::to_string).collect();
        assert!(lines.contains(&"ip link add br-boatramp type bridge".to_string()));
        assert!(lines.contains(&"ip addr add 10.0.0.1/24 dev br-boatramp".to_string()));
        assert!(lines.contains(&"sysctl -w net.ipv4.ip_forward=1".to_string()));
        // The masquerade rule targets the uplink.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("masquerade") && l.contains("eth0"))
        );
    }

    #[test]
    fn node_teardown_drops_nat_table_and_bridge() {
        let net = NodeNetwork::new("10.0.0.1/24", "eth0");
        let down = net.teardown_commands();
        assert_eq!(down[0].to_string(), "nft delete table ip boatramp-nat");
        assert_eq!(down[1].to_string(), "ip link del br-boatramp");
    }

    // -----------------------------------------------------------------------
    // U16: per-tap anti-spoof. The filtered tap pins exactly one (IP, MAC) and
    // default-drops everything else, and the filter is installed BEFORE the tap
    // joins the bridge (fail-closed).
    // -----------------------------------------------------------------------

    #[test]
    fn unfiltered_tap_setup_is_unchanged() {
        // The external/legacy path (no filter) is byte-identical to before: the
        // executor + external VmmBackend depend on this exact create→enslave→up shape.
        let tap = TapNetwork::for_vm("vm1", "br-boatramp");
        assert!(tap.filter.is_none());
        let lines: Vec<String> = tap
            .setup_commands()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            lines,
            vec![
                "ip tuntap add tap-vm1 mode tap".to_string(),
                "ip link set tap-vm1 master br-boatramp".to_string(),
                "ip link set tap-vm1 up".to_string(),
            ]
        );
        assert_eq!(
            tap.teardown_commands(),
            vec![HostCommand::new("ip", &["link", "del", "tap-vm1"])]
        );
    }

    #[test]
    fn filtered_tap_binds_ip_and_mac_and_default_drops() {
        let tap =
            TapNetwork::for_vm_filtered("web-0", "br-boatramp", "10.0.0.5", "02:00:0a:00:00:05");
        let lines: Vec<String> = tap
            .setup_commands()
            .iter()
            .map(ToString::to_string)
            .collect();

        // Per-tap bridge table, hooked at prerouting.
        assert!(lines.contains(&"nft add table bridge brl2-tap-web-0".to_string()));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("chain bridge brl2-tap-web-0 antispoof")
                    && l.contains("type filter hook prerouting"))
        );
        // MAC anti-spoof bound to the pinned MAC.
        assert!(lines.iter().any(|l| l
            == "nft add rule bridge brl2-tap-web-0 antispoof iifname \"tap-web-0\" \
                ether saddr != 02:00:0a:00:00:05 drop"));
        // IPv4 + ARP anti-spoof bound to the pinned IP.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("arp saddr ip != 10.0.0.5 drop")
                    && l.contains("iifname \"tap-web-0\""))
        );
        assert!(lines.iter().any(
            |l| l.contains("ip saddr != 10.0.0.5 drop") && l.contains("iifname \"tap-web-0\"")
        ));
        // ARP sender-HARDWARE anti-spoof bound to the pinned MAC (gratuitous-ARP
        // self-redirect that forges only the ARP-level HW address).
        assert!(
            lines
                .iter()
                .any(|l| l.contains("arp saddr ether != 02:00:0a:00:00:05 drop")
                    && l.contains("iifname \"tap-web-0\""))
        );
        // Default-drop any non-ARP/non-IPv4 ethertype.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("ether type != { arp, ip } drop"))
        );
    }

    #[test]
    fn orphan_worker_selection_matches_only_vmm_run_and_skips_self() {
        let entries = vec![
            (10u32, vec!["boatramp".into(), "__vmm-run".into()]), // a worker
            (11u32, vec!["boatramp".into(), "serve".into()]),     // the node itself
            (12u32, vec!["boatramp".into(), "__vmm-run".into()]), // another worker
            (13u32, vec!["something-else".into()]),               // unrelated, short argv
            (99u32, vec!["boatramp".into(), "__vmm-run".into()]), // self → must be skipped
        ];
        let got = orphan_vmm_worker_pids(&entries, "__vmm-run", 99);
        assert_eq!(
            got,
            vec![10, 12],
            "only __vmm-run workers, never self or others"
        );
    }

    #[test]
    fn stale_tap_selection_is_tap_prefixed_and_excludes_live() {
        let ifaces = vec![
            "tap-web-0".to_string(),
            "tap-api-1".to_string(),
            "vth-web-0".to_string(),   // a container veth — never a VMM tap
            "cth-web-0".to_string(),   // its peer — never a VMM tap
            "br-boatramp".to_string(), // the bridge itself
            "eth0".to_string(),
        ];
        let live: std::collections::BTreeSet<String> =
            ["tap-api-1".to_string()].into_iter().collect();
        let stale = stale_vmm_taps(&ifaces, &live);
        // Only tap-* that isn't a currently-registered (live) tap.
        assert_eq!(stale, vec!["tap-web-0".to_string()]);
    }

    #[test]
    fn filtered_tap_installs_filter_before_joining_the_bridge() {
        // Fail-closed: the enslave-to-bridge command MUST come after every anti-spoof
        // rule, so a caller that aborts on a failing nft command never puts a tap with
        // a missing/partial filter onto the shared L2.
        let tap =
            TapNetwork::for_vm_filtered("web-0", "br-boatramp", "10.0.0.5", "02:00:0a:00:00:05");
        let lines: Vec<String> = tap
            .setup_commands()
            .iter()
            .map(ToString::to_string)
            .collect();
        let enslave = lines
            .iter()
            .position(|l| l == "ip link set tap-web-0 master br-boatramp")
            .expect("enslave command present");
        let last_drop = lines
            .iter()
            .rposition(|l| l.contains("drop"))
            .expect("at least one drop rule");
        assert!(
            enslave > last_drop,
            "enslave (idx {enslave}) must come after the last anti-spoof drop (idx {last_drop})"
        );
        // Teardown removes the per-tap table before the device.
        let down: Vec<String> = tap
            .teardown_commands()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(down[0], "nft delete table bridge brl2-tap-web-0");
        assert_eq!(down[1], "ip link del tap-web-0");
    }
}
