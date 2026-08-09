//! The worker wire types + kernel-cmdline assembly — **pure and cross-platform**
//! (compiles + tests on every host, so the orchestration is validated off macOS).
//!
//! [`WorkerConfig`] is the single JSON argv element handed across the `__vz-run`
//! re-exec boundary (like the KVM backend's `WorkerConfig`), so the backend and
//! the VM host stay in lock-step. The cmdline helpers mirror the firecracker
//! defaults so a rootfs built by `compute build` boots identically on either
//! substrate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Everything the re-exec'd `__vz-run` worker needs to build + run one VM. Passed
/// as a single JSON argv element (no quoting concerns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Host path to the (already-staged) `ext4` rootfs — attached as the guest's
    /// root virtio-block device (`/dev/vda`).
    pub rootfs_path: String,
    /// Host path to the guest `vmlinux` (arm64) — loaded by `VZLinuxBootLoader`.
    pub kernel_path: String,
    /// Kernel cmdline override; `None` ⇒ [`default_cmdline`] (serial console,
    /// `root=/dev/vda ro`, static `ip=`). The runtime-env fragment is always
    /// appended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline_override: Option<String>,
    /// The ` boatramp.env=<hex>` cmdline fragment delivering the workload's
    /// runtime `env` to the guest init (empty ⇒ none). See [`env_cmdline_fragment`].
    #[serde(default)]
    pub env_cmdline: String,
    /// The guest's static IPv4 (kernel `ip=` autoconfig; also derives the MAC).
    pub guest_ip: String,
    /// The vmnet gateway the guest routes through (the `.1` of the subnet).
    pub gateway: String,
    /// Whether the root filesystem is attached read-only. `false` (the hardened
    /// default) mounts `ro`; `true` (single-tenant `writable_root`) mounts `rw`.
    #[serde(default)]
    pub writable_root: bool,
    /// Guest memory (MiB).
    pub mem_mib: u32,
    /// vCPU count.
    pub vcpus: u8,
    /// Persistent volumes attached as writable virtio-block devices
    /// (`/dev/vdb`, `/dev/vdc`, …) after the rootfs, in order.
    #[serde(default)]
    pub volumes: Vec<WorkerVolume>,
    /// **Restore** (scale-to-zero wake): host path to a `saveMachineStateToURL:`
    /// state file. When set, the worker recreates the VM from this `WorkerConfig`
    /// (which must match the one that saved it), `restoreMachineStateFromURL:` +
    /// `resume`s it instead of a fresh boot. `None` ⇒ a normal cold boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_path: Option<String>,
    /// Hex of a `VZGenericMachineIdentifier.dataRepresentation` — the VM's stable
    /// platform identity. VZ requires the identifier on **restore** to match the one
    /// the state was **saved** with, so the backend generates it once at launch and
    /// threads it through launch → snapshot → restore. `None` ⇒ the worker mints a
    /// fresh one (a VM that is never restored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
}

/// One persistent volume as the worker needs it: the (already-created) host image
/// to attach writably + the guest path the init mounts it at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerVolume {
    /// Host path to the volume's ext4 image
    /// (`<data_dir>/compute/volumes/<name>.img`).
    pub image_path: String,
    /// Guest mount point (validated absolute, no `..`).
    pub mount: String,
}

/// The default guest kernel cmdline: serial console, root on the first virtio
/// block device, and the static guest IP via the kernel `ip=` autoconfig
/// (gateway = the vmnet address). `ro` unless `writable_root`.
///
/// Unlike the KVM backend this appends **no** virtio-MMIO `device=` fragments —
/// Virtualization.framework enumerates its virtio devices for the guest (they
/// appear as standard `/dev/vdX`), so only the base cmdline is needed.
pub fn default_cmdline(guest_ip: &str, gateway: &str, writable_root: bool) -> String {
    let root_mode = if writable_root { "rw" } else { "ro" };
    format!(
        "console=hvc0 reboot=k panic=1 root=/dev/vda {root_mode} \
         ip={guest_ip}::{gateway}:255.255.255.0::eth0:off"
    )
}

/// Encode a workload's runtime `env` as a ` boatramp.env=<hex>` kernel-cmdline
/// fragment the guest init (`vminit`) decodes and merges over the baked
/// `/etc/boatramp/env` — the launch-time env channel for microVMs (the rootfs env
/// is baked read-only at `compute build` time). The payload is the hex of the
/// NUL-joined `KEY=VALUE\0…` pairs (hex avoids cmdline quoting); empty env ⇒ empty
/// string.
///
/// Bit-for-bit identical to the firecracker crate's `env_cmdline_fragment`, so
/// the **same guest init** decodes it on either substrate — the uniform-UX
/// invariant. Non-secret env only: the cmdline is world-readable in the guest
/// (`/proc/cmdline`); a secret binding token wants vsock (a later refinement).
pub fn env_cmdline_fragment(env: &BTreeMap<String, String>) -> String {
    if env.is_empty() {
        return String::new();
    }
    let mut blob = Vec::new();
    for (k, v) in env {
        blob.extend_from_slice(k.as_bytes());
        blob.push(b'=');
        blob.extend_from_slice(v.as_bytes());
        blob.push(0);
    }
    let mut hex = String::with_capacity(blob.len() * 2);
    for b in blob {
        hex.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        hex.push(char::from_digit(u32::from(b & 0xf), 16).unwrap());
    }
    format!(" boatramp.env={hex}")
}

/// Assemble the full guest cmdline for `cfg`: the base (override or default) plus
/// the runtime-env fragment. The one place both the worker and the tests agree on
/// the exact string the VM boots with.
pub fn full_cmdline(cfg: &WorkerConfig) -> String {
    let base = cfg
        .cmdline_override
        .clone()
        .unwrap_or_else(|| default_cmdline(&cfg.guest_ip, &cfg.gateway, cfg.writable_root));
    format!("{base}{}", cfg.env_cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cmdline_is_read_only_root_with_static_ip() {
        let c = default_cmdline("10.0.0.5", "10.0.0.1", false);
        assert!(c.contains("root=/dev/vda ro"), "{c}");
        assert!(
            c.contains("ip=10.0.0.5::10.0.0.1:255.255.255.0::eth0:off"),
            "{c}"
        );
        assert!(c.contains("console=hvc0"), "{c}");
    }

    #[test]
    fn writable_root_flips_ro_to_rw() {
        assert!(default_cmdline("10.0.0.5", "10.0.0.1", true).contains("root=/dev/vda rw"));
    }

    #[test]
    fn env_fragment_is_empty_for_empty_env() {
        assert_eq!(env_cmdline_fragment(&BTreeMap::new()), "");
    }

    #[test]
    fn env_fragment_hex_encodes_nul_joined_pairs() {
        // `A=b` → 0x41 0x3d 0x62 0x00 → "413d6200", sorted by key (BTreeMap).
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "b".to_string());
        assert_eq!(env_cmdline_fragment(&env), " boatramp.env=413d6200");
    }

    #[test]
    fn env_fragment_matches_firecracker_encoding_for_two_keys() {
        // Two keys, deterministic order: `X=1\0Y=2\0`.
        let mut env = BTreeMap::new();
        env.insert("X".to_string(), "1".to_string());
        env.insert("Y".to_string(), "2".to_string());
        // X=1\0  → 58 3d 31 00 ; Y=2\0 → 59 3d 32 00
        assert_eq!(env_cmdline_fragment(&env), " boatramp.env=583d3100593d3200");
    }

    #[test]
    fn full_cmdline_appends_env_to_default() {
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "b".to_string());
        let cfg = WorkerConfig {
            rootfs_path: "/x/rootfs.ext4".into(),
            kernel_path: "/x/vmlinux".into(),
            cmdline_override: None,
            env_cmdline: env_cmdline_fragment(&env),
            guest_ip: "10.0.0.5".into(),
            gateway: "10.0.0.1".into(),
            writable_root: false,
            mem_mib: 256,
            vcpus: 1,
            volumes: vec![],
            restore_path: None,
            machine_id: None,
        };
        let full = full_cmdline(&cfg);
        assert!(full.starts_with("console=hvc0"), "{full}");
        assert!(full.ends_with(" boatramp.env=413d6200"), "{full}");
    }

    #[test]
    fn full_cmdline_honors_override() {
        let cfg = WorkerConfig {
            rootfs_path: "/x/rootfs.ext4".into(),
            kernel_path: "/x/vmlinux".into(),
            cmdline_override: Some("custom root=/dev/vda ro".into()),
            env_cmdline: String::new(),
            guest_ip: "10.0.0.5".into(),
            gateway: "10.0.0.1".into(),
            writable_root: false,
            mem_mib: 256,
            vcpus: 1,
            volumes: vec![],
            restore_path: None,
            machine_id: None,
        };
        assert_eq!(full_cmdline(&cfg), "custom root=/dev/vda ro");
    }

    #[test]
    fn worker_config_round_trips_through_json() {
        let cfg = WorkerConfig {
            rootfs_path: "/data/compute/rootfs/abc.ext4".into(),
            kernel_path: "/data/compute/kernels/def".into(),
            cmdline_override: None,
            env_cmdline: " boatramp.env=413d6200".into(),
            guest_ip: "10.0.0.7".into(),
            gateway: "10.0.0.1".into(),
            writable_root: false,
            mem_mib: 512,
            vcpus: 2,
            volumes: vec![WorkerVolume {
                image_path: "/data/compute/volumes/db.img".into(),
                mount: "/data".into(),
            }],
            restore_path: None,
            machine_id: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: WorkerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }
}
