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
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// Render as a shell-ish line for logs/tests (not for execution).
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
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

/// One VM's tap device, attached to a (per-node or per-tenant) bridge. A
/// per-tenant bridge name gives L2 isolation between tenants; full netns/VLAN
/// isolation is not yet implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapNetwork {
    /// The tap device name (e.g. `tap-<vmid>`; keep ≤ 15 chars for the kernel).
    pub tap_name: String,
    /// The bridge this tap is enslaved to (`NodeNetwork::bridge`, or a per-tenant
    /// bridge).
    pub bridge: String,
}

impl TapNetwork {
    /// Create the tap for VM id `vm_id` on `bridge`. The tap name is
    /// `tap-<vm_id>`, truncated to the 15-char interface-name limit.
    pub fn for_vm(vm_id: &str, bridge: &str) -> Self {
        let mut tap_name = format!("tap-{vm_id}");
        tap_name.truncate(15);
        Self {
            tap_name,
            bridge: bridge.to_string(),
        }
    }

    /// Commands to create the tap, enslave it to the bridge, and bring it up.
    pub fn setup_commands(&self) -> Vec<HostCommand> {
        vec![
            HostCommand::new("ip", &["tuntap", "add", &self.tap_name, "mode", "tap"]),
            HostCommand::new(
                "ip",
                &["link", "set", &self.tap_name, "master", &self.bridge],
            ),
            HostCommand::new("ip", &["link", "set", &self.tap_name, "up"]),
        ]
    }

    /// Commands to delete the tap (best-effort; safe to run on a partial setup).
    pub fn teardown_commands(&self) -> Vec<HostCommand> {
        vec![HostCommand::new("ip", &["link", "del", &self.tap_name])]
    }
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
        assert_eq!(setup[0].display(), "ip tuntap add tap-vm1 mode tap");
        assert_eq!(setup[1].display(), "ip link set tap-vm1 master br-boatramp");
        assert_eq!(setup[2].display(), "ip link set tap-vm1 up");
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
        let lines: Vec<String> = cmds.iter().map(HostCommand::display).collect();
        assert!(lines.contains(&"ip link add br-boatramp type bridge".to_string()));
        assert!(lines.contains(&"ip addr add 10.0.0.1/24 dev br-boatramp".to_string()));
        assert!(lines.contains(&"sysctl -w net.ipv4.ip_forward=1".to_string()));
        // The masquerade rule targets the uplink.
        assert!(lines
            .iter()
            .any(|l| l.contains("masquerade") && l.contains("eth0")));
    }

    #[test]
    fn node_teardown_drops_nat_table_and_bridge() {
        let net = NodeNetwork::new("10.0.0.1/24", "eth0");
        let down = net.teardown_commands();
        assert_eq!(down[0].display(), "nft delete table ip boatramp-nat");
        assert_eq!(down[1].display(), "ip link del br-boatramp");
    }
}
