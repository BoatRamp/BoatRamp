//! The Firecracker machine configuration.
//!
//! Serializes to the JSON Firecracker accepts via `--config-file` (and the same
//! shapes its HTTP API uses): `boot-source`, `drives`, `machine-config`,
//! `network-interfaces`. [`FcMachine::from_spec`] assembles it from a
//! [`ComputeSpec`] plus the host resources the executor allocated (image paths +
//! the tap device). Building this is pure and host-agnostic; only *applying* it
//! (spawning Firecracker) needs KVM.

use boatramp_types::compute::ComputeSpec;
use serde::{Deserialize, Serialize};

/// The kernel + boot args.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootSource {
    /// Host path to the `vmlinux` kernel image.
    pub kernel_image_path: String,
    /// Kernel cmdline.
    pub boot_args: String,
}

/// A block device exposed to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drive {
    /// Firecracker drive id.
    pub drive_id: String,
    /// Host path to the backing image.
    pub path_on_host: String,
    /// Whether this is the guest's root device.
    pub is_root_device: bool,
    /// Whether the guest sees it read-only.
    pub is_read_only: bool,
}

/// vCPU + memory sizing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig {
    /// Virtual CPUs.
    pub vcpu_count: u32,
    /// Memory in MiB.
    pub mem_size_mib: u32,
    /// Simultaneous multithreading (hyperthreading) — off for predictability.
    pub smt: bool,
}

/// A guest network interface backed by a host tap device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Firecracker interface id.
    pub iface_id: String,
    /// The guest's MAC.
    pub guest_mac: String,
    /// The host tap device name.
    pub host_dev_name: String,
}

/// A full Firecracker machine config (the `--config-file` document).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcMachine {
    /// Kernel + cmdline.
    #[serde(rename = "boot-source")]
    pub boot_source: BootSource,
    /// Block devices (root rootfs + ephemeral scratch).
    pub drives: Vec<Drive>,
    /// CPU/memory.
    #[serde(rename = "machine-config")]
    pub machine_config: MachineConfig,
    /// Network interfaces.
    #[serde(rename = "network-interfaces")]
    pub network_interfaces: Vec<NetworkInterface>,
}

/// The host-side resources the executor allocated for one microVM, fed into
/// [`FcMachine::from_spec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineResources {
    /// Host path to the kernel image (resolved from the spec's kernel blob).
    pub kernel_path: String,
    /// Host path to the read-only rootfs image (the spec's rootfs blob).
    pub rootfs_path: String,
    /// Host path to a writable ephemeral scratch image.
    pub scratch_path: String,
    /// The tap device name on the host.
    pub tap_name: String,
    /// The guest MAC (from the IPAM allocation).
    pub guest_mac: String,
    /// The guest IP (informational; configured via the kernel cmdline / init).
    pub guest_ip: String,
}

/// The default kernel cmdline: serial console on, root on the first virtio
/// block device, read-only. The guest IP is appended (`ip=…`) so the init can
/// bring up networking without DHCP.
fn default_cmdline(guest_ip: &str) -> String {
    format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro ip={guest_ip}::{0}:255.255.255.0::eth0:off",
        gateway_ip(guest_ip)
    )
}

/// The conventional gateway for a `/24`: the `.1` of the guest's network.
fn gateway_ip(guest_ip: &str) -> String {
    match guest_ip.rsplit_once('.') {
        Some((net, _)) => format!("{net}.1"),
        None => guest_ip.to_string(),
    }
}

impl FcMachine {
    /// Assemble the machine config for `spec` on the allocated `resources`.
    ///
    /// Drives: the rootfs is the read-only root device; a writable ephemeral
    /// scratch is a second drive. The boot args use the spec's cmdline override
    /// or a sane default that brings up the guest IP.
    pub fn from_spec(spec: &ComputeSpec, resources: &MachineResources) -> Self {
        let boot_args = spec
            .kernel_cmdline
            .clone()
            .unwrap_or_else(|| default_cmdline(&resources.guest_ip));
        FcMachine {
            boot_source: BootSource {
                kernel_image_path: resources.kernel_path.clone(),
                boot_args,
            },
            drives: vec![
                Drive {
                    drive_id: "rootfs".to_string(),
                    path_on_host: resources.rootfs_path.clone(),
                    is_root_device: true,
                    is_read_only: true,
                },
                Drive {
                    drive_id: "scratch".to_string(),
                    path_on_host: resources.scratch_path.clone(),
                    is_root_device: false,
                    is_read_only: false,
                },
            ],
            machine_config: MachineConfig {
                vcpu_count: spec.vcpus.max(1),
                mem_size_mib: spec.mem_mib.max(1),
                smt: false,
            },
            network_interfaces: vec![NetworkInterface {
                iface_id: "eth0".to_string(),
                guest_mac: resources.guest_mac.clone(),
                host_dev_name: resources.tap_name.clone(),
            }],
        }
    }

    /// Render the config as the JSON Firecracker reads from `--config-file`.
    pub fn to_config_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("FcMachine serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_types::compute::RestartPolicy;
    use std::collections::BTreeMap;

    fn spec() -> ComputeSpec {
        ComputeSpec {
            version: 1,
            rootfs: "r".repeat(64),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus: 2,
            mem_mib: 512,
            entrypoint: vec!["/app".into()],
            env: BTreeMap::new(),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: boatramp_types::compute::IsolationRequirement::Trusted,
            prefer_backend: None,
        }
    }

    fn resources() -> MachineResources {
        MachineResources {
            kernel_path: "/var/lib/boatramp/kernels/vmlinux".into(),
            rootfs_path: "/var/lib/boatramp/rootfs/abc.ext4".into(),
            scratch_path: "/var/lib/boatramp/scratch/vm1.ext4".into(),
            tap_name: "tap-vm1".into(),
            guest_mac: "02:00:0a:00:00:05".into(),
            guest_ip: "10.0.0.5".into(),
        }
    }

    #[test]
    fn builds_root_and_scratch_drives() {
        let m = FcMachine::from_spec(&spec(), &resources());
        assert_eq!(m.drives.len(), 2);
        assert!(m.drives[0].is_root_device && m.drives[0].is_read_only);
        assert!(!m.drives[1].is_root_device && !m.drives[1].is_read_only);
        assert_eq!(m.machine_config.vcpu_count, 2);
        assert_eq!(m.network_interfaces[0].host_dev_name, "tap-vm1");
    }

    #[test]
    fn default_cmdline_brings_up_guest_ip_with_dot1_gateway() {
        let m = FcMachine::from_spec(&spec(), &resources());
        assert!(m.boot_source.boot_args.contains("ip=10.0.0.5::10.0.0.1:"));
        assert!(m.boot_source.boot_args.contains("root=/dev/vda ro"));
    }

    #[test]
    fn cmdline_override_is_respected() {
        let mut s = spec();
        s.kernel_cmdline = Some("custom args".into());
        let m = FcMachine::from_spec(&s, &resources());
        assert_eq!(m.boot_source.boot_args, "custom args");
    }

    #[test]
    fn config_json_uses_firecracker_keys() {
        let json = FcMachine::from_spec(&spec(), &resources()).to_config_json();
        for key in [
            "boot-source",
            "machine-config",
            "network-interfaces",
            "kernel_image_path",
            "vcpu_count",
            "host_dev_name",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
    }

    #[test]
    fn vcpu_and_mem_floored_at_one() {
        let mut s = spec();
        s.vcpus = 0;
        s.mem_mib = 0;
        let m = FcMachine::from_spec(&s, &resources());
        assert_eq!(m.machine_config.vcpu_count, 1);
        assert_eq!(m.machine_config.mem_size_mib, 1);
    }
}
